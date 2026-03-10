"""Tests for ELF import library resolution and .so name handling."""

import os
import struct
import tempfile
import unittest

from core.mapping.symbol_resolver import SymbolResolver
from core.models import FunctionNode, LinksToEdge


# ---------------------------------------------------------------------------
# Test _parse_elf_verneed (raw ELF file parser)
# ---------------------------------------------------------------------------
# We import the standalone function (no IDA dependency)
from core.extraction.engine import _parse_elf_verneed, _parse_elf_import_maps


def _build_test_elf_with_verneed(version_entries, is_64=True, include_dynsym=False):
    """Build a minimal ELF binary with .gnu.version_r and .dynstr sections.

    *version_entries* is a list of ``(lib_name, [(version_tag, index), ...])``.

    If *include_dynsym* is True, also creates ``.dynsym`` and ``.gnu.version``
    sections with synthetic symbol entries for testing the full sym_to_lib path.

    Returns the path to a temporary file.
    """
    endian = "<"  # little-endian

    # Build .dynstr
    dynstr = b"\x00"
    str_offsets = {}
    for lib_name, versions in version_entries:
        str_offsets[lib_name] = len(dynstr)
        dynstr += lib_name.encode("utf-8") + b"\x00"
        for tag, _ in versions:
            str_offsets[tag] = len(dynstr)
            dynstr += tag.encode("utf-8") + b"\x00"

    # Build .gnu.version_r
    verneed = bytearray()
    for entry_idx, (lib_name, versions) in enumerate(version_entries):
        is_last_entry = entry_idx == len(version_entries) - 1
        vn_cnt = len(versions)
        vn_file = str_offsets[lib_name]

        # Vernaux entries for this Verneed
        vernaux = bytearray()
        for aux_idx, (tag, ver_idx) in enumerate(versions):
            is_last_aux = aux_idx == len(versions) - 1
            vna_hash = 0
            vna_flags = 0
            vna_other = ver_idx
            vna_name = str_offsets[tag]
            vna_next = 0 if is_last_aux else 16
            vernaux += struct.pack(f"{endian}IHHiI", vna_hash, vna_flags, vna_other, vna_name, vna_next)

        vn_aux = 16  # Vernaux starts right after Verneed header
        vn_next = 0 if is_last_entry else (16 + len(vernaux))
        verneed += struct.pack(f"{endian}HHIiI", 1, vn_cnt, vn_file, vn_aux, vn_next)
        verneed += vernaux

    verneed_data = bytes(verneed)
    dynstr_data = bytes(dynstr)

    # Build section headers
    SHT_STRTAB = 3
    SHT_GNU_VERNEED = 0x6FFFFFFE

    if is_64:
        ehdr_size = 64
        shentsize = 64
    else:
        ehdr_size = 52
        shentsize = 40

    # Sections: [0]=NULL, [1]=.dynstr(STRTAB), [2]=.gnu.version_r(VERNEED), [3]=.shstrtab
    shstrtab = b"\x00.dynstr\x00.gnu.version_r\x00.shstrtab\x00"
    sh_dynstr_name = 1  # offset of ".dynstr" in shstrtab
    sh_verneed_name = 9  # offset of ".gnu.version_r" in shstrtab
    sh_shstrtab_name = 24  # offset of ".shstrtab" in shstrtab

    # File layout: ELF header | dynstr_data | verneed_data | shstrtab | section headers
    dynstr_offset = ehdr_size
    verneed_offset = dynstr_offset + len(dynstr_data)
    shstrtab_offset = verneed_offset + len(verneed_data)
    sh_offset = shstrtab_offset + len(shstrtab)

    def _make_sh_64(name, sh_type, offset, size, link=0):
        # sh_name(4) sh_type(4) sh_flags(8) sh_addr(8) sh_offset(8) sh_size(8) sh_link(4) sh_info(4) sh_addralign(8) sh_entsize(8)
        return struct.pack("<IIQQQQIIqq", name, sh_type, 0, 0, offset, size, link, 0, 1, 0)

    def _make_sh_32(name, sh_type, offset, size, link=0):
        return struct.pack("<IIIIIIIIII", name, sh_type, 0, 0, offset, size, link, 0, 1, 0)

    make_sh = _make_sh_64 if is_64 else _make_sh_32

    sh_null = make_sh(0, 0, 0, 0)
    sh_dynstr = make_sh(sh_dynstr_name, SHT_STRTAB, dynstr_offset, len(dynstr_data))
    sh_verneed = make_sh(sh_verneed_name, SHT_GNU_VERNEED, verneed_offset, len(verneed_data), link=1)
    sh_shstr = make_sh(sh_shstrtab_name, SHT_STRTAB, shstrtab_offset, len(shstrtab))

    sh_table = sh_null + sh_dynstr + sh_verneed + sh_shstr
    e_shnum = 4
    e_shstrndx = 3

    # Build ELF header
    if is_64:
        ehdr = struct.pack(
            "<4sBBBBBxxxxxxx",
            b"\x7fELF", 2, 1, 1, 0, 0,  # EI_CLASS=64, EI_DATA=LE, EI_VERSION
        )
        ehdr += struct.pack("<HHIQQQIHHHHHH",
            2, 62,  # e_type=ET_EXEC, e_machine=EM_X86_64
            1,      # e_version
            0,      # e_entry
            0,      # e_phoff
            sh_offset,  # e_shoff
            0,      # e_flags
            ehdr_size,  # e_ehsize
            0, 0,   # e_phentsize, e_phnum
            shentsize,
            e_shnum,
            e_shstrndx,
        )
    else:
        ehdr = struct.pack(
            "<4sBBBBBxxxxxxx",
            b"\x7fELF", 1, 1, 1, 0, 0,
        )
        ehdr += struct.pack("<HHIIIIIHHHHHH",
            2, 3, 1, 0, 0, sh_offset, 0, ehdr_size, 0, 0, shentsize, e_shnum, e_shstrndx,
        )

    file_data = ehdr + dynstr_data + verneed_data + shstrtab + sh_table

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
    tmp.write(file_data)
    tmp.close()
    return tmp.name


class TestParseElfVerneed(unittest.TestCase):
    """Test the raw ELF .gnu.version_r parser."""

    def test_basic_parsing(self):
        entries = [
            ("libc.so.6", [("GLIBC_2.2.5", 2), ("GLIBC_2.3.4", 3)]),
            ("libssl.so.1.1", [("OPENSSL_1_1_0", 4)]),
        ]
        path = _build_test_elf_with_verneed(entries, is_64=True)
        try:
            result = _parse_elf_verneed(path)
            self.assertEqual(result["GLIBC_2.2.5"], "libc.so.6")
            self.assertEqual(result["GLIBC_2.3.4"], "libc.so.6")
            self.assertEqual(result["OPENSSL_1_1_0"], "libssl.so.1.1")
            self.assertEqual(len(result), 3)
        finally:
            os.unlink(path)

    def test_32bit_elf(self):
        entries = [("libm.so.6", [("GLIBC_2.0", 2)])]
        path = _build_test_elf_with_verneed(entries, is_64=False)
        try:
            result = _parse_elf_verneed(path)
            self.assertEqual(result["GLIBC_2.0"], "libm.so.6")
        finally:
            os.unlink(path)

    def test_non_elf_file(self):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        tmp.write(b"MZ" + b"\x00" * 100)
        tmp.close()
        try:
            result = _parse_elf_verneed(tmp.name)
            self.assertEqual(result, {})
        finally:
            os.unlink(tmp.name)

    def test_resolve_import_module(self):
        """Test _resolve_elf_import_module static method."""
        from core.extraction.engine import ExtractionEngine
        ver_map = {"GLIBC_2.2.5": "libc.so.6", "OPENSSL_1_1_0": "libssl.so.1.1"}
        sym_map = {"deflateInit_": "libz.so.1", "pcre_exec": "libpcre.so.3"}

        # Strategy 1: @@VERSION_TAG
        self.assertEqual(
            ExtractionEngine._resolve_elf_import_module("printf@@GLIBC_2.2.5", "printf", ver_map, sym_map, ".dynsym"),
            "libc.so.6",
        )
        self.assertEqual(
            ExtractionEngine._resolve_elf_import_module("SSL_read@@OPENSSL_1_1_0", "SSL_read", ver_map, sym_map, ".dynsym"),
            "libssl.so.1.1",
        )
        # Strategy 2: sym_to_lib (no version annotation)
        self.assertEqual(
            ExtractionEngine._resolve_elf_import_module("deflateInit_", "deflateInit_", ver_map, sym_map, ".dynsym"),
            "libz.so.1",
        )
        self.assertEqual(
            ExtractionEngine._resolve_elf_import_module("pcre_exec", "pcre_exec", ver_map, sym_map, ".dynsym"),
            "libpcre.so.3",
        )
        # No match at all → fallback
        self.assertEqual(
            ExtractionEngine._resolve_elf_import_module("unknown_func", "unknown_func", ver_map, sym_map, ".dynsym"),
            ".dynsym",
        )
        # Empty name → fallback
        self.assertEqual(
            ExtractionEngine._resolve_elf_import_module("", "", ver_map, sym_map, ".dynsym"),
            ".dynsym",
        )


class TestParseElfImportMaps(unittest.TestCase):
    """Test the full ELF import maps parser (.dynsym + .gnu.version + .gnu.version_r)."""

    def test_full_symbol_resolution(self):
        """Build ELF with all three sections and verify sym_to_lib mapping."""
        # We build a complete ELF with:
        # .dynstr: symbol names + lib names + version tags
        # .dynsym: 3 symbols (null + deflate + printf)
        # .gnu.version: version indices for each symbol
        # .gnu.version_r: version requirements

        path = _build_test_elf_full(
            version_entries=[
                ("libc.so.6", [("GLIBC_2.2.5", 2)]),
                ("libz.so.1", [("ZLIB_1.2.0", 3)]),
            ],
            symbols=[
                # (name, version_index)
                ("deflate", 3),     # maps to ZLIB_1.2.0 → libz.so.1
                ("printf", 2),      # maps to GLIBC_2.2.5 → libc.so.6
                ("unknown", 1),     # VER_NDX_GLOBAL → no mapping
            ],
        )
        try:
            tag_map, sym_map = _parse_elf_import_maps(path)
            # tag_map from .gnu.version_r
            self.assertEqual(tag_map["GLIBC_2.2.5"], "libc.so.6")
            self.assertEqual(tag_map["ZLIB_1.2.0"], "libz.so.1")
            # sym_map from .dynsym + .gnu.version cross-reference
            self.assertEqual(sym_map["deflate"], "libz.so.1")
            self.assertEqual(sym_map["printf"], "libc.so.6")
            # "unknown" has version index 1 (global unversioned) → NOT in sym_map
            self.assertNotIn("unknown", sym_map)
        finally:
            os.unlink(path)


def _build_test_elf_full(version_entries, symbols, is_64=True):
    """Build a complete test ELF with .dynsym, .gnu.version, .gnu.version_r, .dynstr.

    *version_entries*: [(lib_name, [(tag, index), ...]), ...]
    *symbols*: [(name, version_index), ...]  — does NOT include the mandatory null entry
    """
    endian = "<"

    # Build .dynstr
    dynstr = b"\x00"
    str_offsets = {}
    for lib_name, versions in version_entries:
        str_offsets[lib_name] = len(dynstr)
        dynstr += lib_name.encode("utf-8") + b"\x00"
        for tag, _ in versions:
            str_offsets[tag] = len(dynstr)
            dynstr += tag.encode("utf-8") + b"\x00"
    for sym_name, _ in symbols:
        str_offsets[sym_name] = len(dynstr)
        dynstr += sym_name.encode("utf-8") + b"\x00"

    # Build .gnu.version_r
    verneed = bytearray()
    for entry_idx, (lib_name, versions) in enumerate(version_entries):
        is_last = entry_idx == len(version_entries) - 1
        vernaux = bytearray()
        for aux_idx, (tag, ver_idx) in enumerate(versions):
            is_last_aux = aux_idx == len(versions) - 1
            vernaux += struct.pack(f"{endian}IHHiI", 0, 0, ver_idx, str_offsets[tag], 0 if is_last_aux else 16)
        verneed += struct.pack(f"{endian}HHIiI", 1, len(versions), str_offsets[lib_name], 16, 0 if is_last else (16 + len(vernaux)))
        verneed += vernaux
    verneed_data = bytes(verneed)

    # Build .dynsym (null entry + symbol entries)
    if is_64:
        sym_entsize = 24  # Elf64_Sym
        # st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
        dynsym = struct.pack(f"{endian}IBBHQQ", 0, 0, 0, 0, 0, 0)  # null entry
        for sym_name, _ in symbols:
            dynsym += struct.pack(f"{endian}IBBHQQ", str_offsets[sym_name], 0x12, 0, 1, 0, 0)
    else:
        sym_entsize = 16  # Elf32_Sym
        dynsym = struct.pack(f"{endian}IIIBBH", 0, 0, 0, 0, 0, 0)
        for sym_name, _ in symbols:
            dynsym += struct.pack(f"{endian}IIIBBH", str_offsets[sym_name], 0, 0, 0x12, 0, 1)
    dynsym_data = bytes(dynsym)

    # Build .gnu.version (one uint16 per .dynsym entry)
    versym = struct.pack(f"{endian}H", 0)  # null entry version
    for _, ver_idx in symbols:
        versym += struct.pack(f"{endian}H", ver_idx)
    versym_data = bytes(versym)

    # Section layout
    SHT_STRTAB = 3
    SHT_DYNSYM = 11
    SHT_GNU_VERSYM = 0x6FFFFFFF
    SHT_GNU_VERNEED = 0x6FFFFFFE

    ehdr_size = 64 if is_64 else 52
    shentsize = 64 if is_64 else 40

    # Sections: [0]=NULL [1]=.dynstr [2]=.gnu.version_r [3]=.dynsym [4]=.gnu.version [5]=.shstrtab
    shstrtab = b"\x00.dynstr\x00.gnu.version_r\x00.dynsym\x00.gnu.version\x00.shstrtab\x00"
    sh_names = {
        ".dynstr": 1,
        ".gnu.version_r": 9,
        ".dynsym": 24,
        ".gnu.version": 32,
        ".shstrtab": 45,
    }

    dynstr_data_bytes = bytes(dynstr)
    off = ehdr_size
    dynstr_off = off; off += len(dynstr_data_bytes)
    verneed_off = off; off += len(verneed_data)
    dynsym_off = off; off += len(dynsym_data)
    versym_off = off; off += len(versym_data)
    shstrtab_off = off; off += len(shstrtab)
    sh_offset = off

    def _make_sh(name_idx, sh_type, offset, size, link=0, entsize=0):
        if is_64:
            return struct.pack("<IIQQQQIIqq", name_idx, sh_type, 0, 0, offset, size, link, 0, 1, entsize)
        else:
            return struct.pack("<IIIIIIIIII", name_idx, sh_type, 0, 0, offset, size, link, 0, 1, entsize)

    sh_table = (
        _make_sh(0, 0, 0, 0)
        + _make_sh(sh_names[".dynstr"], SHT_STRTAB, dynstr_off, len(dynstr_data_bytes))
        + _make_sh(sh_names[".gnu.version_r"], SHT_GNU_VERNEED, verneed_off, len(verneed_data), link=1)
        + _make_sh(sh_names[".dynsym"], SHT_DYNSYM, dynsym_off, len(dynsym_data), link=1, entsize=sym_entsize)
        + _make_sh(sh_names[".gnu.version"], SHT_GNU_VERSYM, versym_off, len(versym_data))
        + _make_sh(sh_names[".shstrtab"], SHT_STRTAB, shstrtab_off, len(shstrtab))
    )

    e_shnum = 6
    e_shstrndx = 5

    if is_64:
        ehdr = struct.pack("<4sBBBBBxxxxxxx", b"\x7fELF", 2, 1, 1, 0, 0)
        ehdr += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, sh_offset, 0, ehdr_size, 0, 0, shentsize, e_shnum, e_shstrndx)
    else:
        ehdr = struct.pack("<4sBBBBBxxxxxxx", b"\x7fELF", 1, 1, 1, 0, 0)
        ehdr += struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, 0, 0, sh_offset, 0, ehdr_size, 0, 0, shentsize, e_shnum, e_shstrndx)

    file_data = ehdr + dynstr_data_bytes + verneed_data + dynsym_data + versym_data + shstrtab + sh_table

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
    tmp.write(file_data)
    tmp.close()
    return tmp.name


# ---------------------------------------------------------------------------
# SymbolResolver: .so extension handling
# ---------------------------------------------------------------------------


class TestSymbolResolverSoSupport(unittest.TestCase):
    """Test SymbolResolver with ELF shared library names."""

    def _make_func(self, uid, name, func_type="EXPORT", binary_id="bin1"):
        return FunctionNode(
            uid=uid,
            rva=0x1000,
            name=name,
            orig_name=name,
            size=100,
            is_lib=False,
            func_type=func_type,
            binary_id=binary_id,
        )

    def test_build_export_table_so_no_dll_append(self):
        """build_export_table should NOT append .dll to .so names."""
        resolver = SymbolResolver()
        func = self._make_func("uid1", "my_export")
        resolver.build_export_table([func], "libfoo.so.3")
        # Key should use the .so name, not libfoo.so.3.dll
        self.assertIn(("libfoo.so.3", "my_export"), resolver.export_table)
        self.assertNotIn(("libfoo.so.3.dll", "my_export"), resolver.export_table)

    def test_has_binary_extension_so(self):
        self.assertTrue(SymbolResolver._has_binary_extension("libc.so.6"))
        self.assertTrue(SymbolResolver._has_binary_extension("libpthread.so.0"))
        self.assertTrue(SymbolResolver._has_binary_extension("libfoo.so"))
        self.assertFalse(SymbolResolver._has_binary_extension("my_binary"))
        self.assertTrue(SymbolResolver._has_binary_extension("kernel32.dll"))
        self.assertTrue(SymbolResolver._has_binary_extension("app.exe"))
        self.assertTrue(SymbolResolver._has_binary_extension("libfoo.dylib"))

    def test_get_dll_name_variants_so(self):
        resolver = SymbolResolver()
        variants = resolver._get_dll_name_variants("libc.so.6")
        self.assertIn("libc.so.6", variants)
        self.assertIn("libc.so", variants)
        self.assertIn("libc", variants)

    def test_get_dll_name_variants_so_no_version(self):
        resolver = SymbolResolver()
        variants = resolver._get_dll_name_variants("libfoo.so")
        self.assertIn("libfoo.so", variants)
        self.assertIn("libfoo", variants)

    def test_get_dll_name_variants_dll(self):
        """Existing PE behaviour should be preserved."""
        resolver = SymbolResolver()
        variants = resolver._get_dll_name_variants("kernel32.dll")
        self.assertIn("kernel32.dll", variants)
        self.assertIn("kernel32", variants)

    def test_resolve_links_to_with_so_names(self):
        """End-to-end: IMPORT from libc.so.6 matched to EXPORT in libc.so.6."""
        resolver = SymbolResolver()
        export_func = self._make_func("export_uid", "open", func_type="EXPORT")
        resolver.build_export_table([export_func], "libc.so.6")

        edge = LinksToEdge(
            from_id="import_uid",
            to_id="virtual_placeholder",
            dll_name="libc.so.6",
            func_name="open",
        )
        result = resolver.resolve_links_to_edges([edge])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].to_id, "export_uid")

    def test_resolve_links_to_so_variant_matching(self):
        """Import uses 'libc.so' but export binary is 'libc.so.6'."""
        resolver = SymbolResolver()
        export_func = self._make_func("exp1", "read", func_type="EXPORT")
        resolver.build_export_table([export_func], "libc.so.6")

        edge = LinksToEdge(
            from_id="imp1",
            to_id="placeholder",
            dll_name="libc.so",
            func_name="read",
        )
        result = resolver.resolve_links_to_edges([edge])
        # 'libc.so' variant should match the export table keyed on 'libc.so.6'
        # because _get_dll_name_variants("libc.so") includes "libc.so" and
        # the export table also stores under "libc.so.6" whose variant "libc.so" matches.
        # However, the current resolver searches import dll_name variants against
        # export table keys. So: import variant "libc" should also match via
        # export key "libc.so.6" only if we also add the inverse lookup.
        # In practice, both sides generate variants, so at least one should match.
        self.assertEqual(len(result), 1)


class TestSymbolResolverDylibSupport(unittest.TestCase):
    """Test SymbolResolver with macOS .dylib names."""

    def test_get_dll_name_variants_dylib(self):
        resolver = SymbolResolver()
        variants = resolver._get_dll_name_variants("libSystem.B.dylib")
        self.assertIn("libsystem.b.dylib", variants)
        self.assertIn("libsystem.b", variants)
        self.assertIn("libsystem.b.so", variants)


if __name__ == "__main__":
    unittest.main()

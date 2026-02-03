"""Compatibility shim for SymbolResolver."""

from core.mapping.symbol_resolver import SymbolResolver, resolve_symbols  # noqa: F401

__all__ = ["SymbolResolver", "resolve_symbols"]

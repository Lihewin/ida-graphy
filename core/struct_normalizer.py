"""
Structure Name Normalizer Module

This module implements structure name canonicalization to ensure cross-binary
consistency for DataSlot IDs. According to the struct.txt strategy, structure
members with the same normalized name and offset should converge to the same
DataSlot node, enabling cross-binary data flow analysis.

Key Features:
1. Remove common prefixes (struct, class, _, T_)
2. Remove IDA-generated numeric suffixes (e.g., Session_1 -> Session)
3. Normalize case (default: lowercase)
4. Handle struct aliases/mapping

Author: IDA-Graphy Project
Date: 2026-02-02
"""

import re
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class StructNameNormalizer:
    """
    Structure name normalizer with alias mapping support.
    
    This class implements the canonicalization strategy defined in struct.txt:
    - Removes prefixes like "struct ", "class ", "_", "T_"
    - Removes IDA-generated numeric suffixes (e.g., Session_1 -> Session)
    - Normalizes case for consistency
    - Applies user-defined alias mappings
    
    Example:
        >>> normalizer = StructNameNormalizer()
        >>> normalizer.normalize("struct Session_1")
        'session'
        >>> normalizer.add_alias("ProcessObject", "EPROCESS")
        >>> normalizer.normalize("ProcessObject")
        'eprocess'
    """
    
    def __init__(self, 
                 aliases: Optional[Dict[str, str]] = None,
                 case_mode: str = 'lower',
                 aggressive_suffix_removal: bool = True):
        """
        Initialize the normalizer.
        
        Args:
            aliases: Dictionary mapping variant names to canonical names
                     e.g., {"ProcessObject": "EPROCESS", "_EPROCESS": "EPROCESS"}
            case_mode: Case normalization mode:
                       - 'lower': Convert to lowercase (default)
                       - 'upper': Convert to uppercase
                       - 'preserve': Keep original case
            aggressive_suffix_removal: If True, removes all numeric suffixes.
                                       If False, only removes IDA-style suffixes.
        """
        self.aliases = aliases or {}
        self.case_mode = case_mode
        self.aggressive_suffix_removal = aggressive_suffix_removal
        
        # Statistics
        self.stats = {
            'normalized': 0,
            'alias_applied': 0,
            'prefix_removed': 0,
            'suffix_removed': 0
        }
    
    def add_alias(self, variant: str, canonical: str):
        """
        Add a struct name alias mapping.
        
        Args:
            variant: The variant name (e.g., "ProcessObject")
            canonical: The canonical name (e.g., "EPROCESS")
        """
        self.aliases[variant] = canonical
        logger.debug(f"Added alias: {variant} -> {canonical}")
    
    def load_aliases(self, alias_dict: Dict[str, str]):
        """
        Load multiple aliases from a dictionary.
        
        Args:
            alias_dict: Dictionary of variant -> canonical mappings
        """
        self.aliases.update(alias_dict)
        logger.info(f"Loaded {len(alias_dict)} struct aliases")
    
    def normalize(self, struct_name: str) -> str:
        """
        Normalize a structure name.
        
        This is the main entry point for normalization. It applies all
        transformations in the following order:
        1. Remove common prefixes
        2. Check alias mapping (after prefix removal)
        3. Remove numeric suffixes
        4. Clean leading underscores
        5. Apply case normalization
        
        Args:
            struct_name: Raw structure name from IDA
            
        Returns:
            Normalized canonical name
            
        Example:
            >>> normalizer.normalize("struct _Session_1")
            'session'
        """
        if not struct_name:
            return struct_name
        
        original_name = struct_name
        
        # Step 1: Remove common prefixes FIRST
        name = self._remove_prefixes(struct_name)
        
        # Step 2: Apply alias mapping (after prefix removal)
        # This allows "struct ProcessObject" to match the "ProcessObject" alias
        if name in self.aliases:
            name = self.aliases[name]
            self.stats['alias_applied'] += 1
            logger.debug(f"Alias applied: {original_name} -> {name}")
        
        # Step 3: Remove numeric suffixes (IDA collision resolution)
        name = self._remove_suffixes(name)
        
        # Step 4: Clean leading underscores
        name = self._clean_underscores(name)
        
        # Step 5: Apply case normalization
        name = self._normalize_case(name)
        
        self.stats['normalized'] += 1
        
        if name != original_name:
            logger.debug(f"Normalized: {original_name} -> {name}")
        
        return name
    
    def _remove_prefixes(self, name: str) -> str:
        """
        Remove common type prefixes.
        
        Handles:
        - "struct " (with space)
        - "class " (with space)
        - "union " (with space)
        - "enum " (with space)
        - "T_" (Hungarian notation)
        - "tag" (Windows style, e.g., tagWNDCLASS)
        
        Args:
            name: Input name
            
        Returns:
            Name with prefixes removed
        """
        original = name
        
        # Remove keyword prefixes with space
        for prefix in ['struct ', 'class ', 'union ', 'enum ']:
            if name.startswith(prefix):
                name = name[len(prefix):]
                self.stats['prefix_removed'] += 1
                break
        
        # Remove Hungarian notation prefix (T_)
        if name.startswith('T_'):
            name = name[2:]
            self.stats['prefix_removed'] += 1
        
        # Remove Windows "tag" prefix (e.g., tagWNDCLASS -> WNDCLASS)
        if name.startswith('tag') and len(name) > 3 and name[3].isupper():
            name = name[3:]
            self.stats['prefix_removed'] += 1
        
        if name != original:
            logger.debug(f"Prefix removed: {original} -> {name}")
        
        return name
    
    def _remove_suffixes(self, name: str) -> str:
        """
        Remove IDA-generated numeric suffixes.
        
        IDA appends _0, _1, _2 when it encounters type name collisions.
        We need to remove these to merge the same logical structure.
        
        Examples:
            Session_1 -> Session
            _EPROCESS_2 -> _EPROCESS
        
        CAUTION: This might incorrectly remove legitimate suffixes like:
            UTF8_string -> UTF (if aggressive)
            Version_2 -> Version
        
        Args:
            name: Input name
            
        Returns:
            Name with suffixes removed
        """
        original = name
        
        if self.aggressive_suffix_removal:
            # Remove any trailing _digit(s)
            # Pattern: _\d+$ (underscore followed by one or more digits at end)
            name = re.sub(r'_\d+$', '', name)
        else:
            # Only remove single digit suffixes (IDA style)
            # Pattern: _[0-9]$ (underscore followed by single digit at end)
            name = re.sub(r'_[0-9]$', '', name)
        
        if name != original:
            self.stats['suffix_removed'] += 1
            logger.debug(f"Suffix removed: {original} -> {name}")
        
        return name
    
    def _clean_underscores(self, name: str) -> str:
        """
        Clean leading underscores.
        
        Removes leading underscores (common in system types):
            _EPROCESS -> EPROCESS
            __int64 -> int64
        
        Args:
            name: Input name
            
        Returns:
            Name with leading underscores removed
        """
        original = name
        name = name.lstrip('_')
        
        if name != original:
            logger.debug(f"Underscores cleaned: {original} -> {name}")
        
        return name
    
    def _normalize_case(self, name: str) -> str:
        """
        Normalize case according to configuration.
        
        Args:
            name: Input name
            
        Returns:
            Case-normalized name
        """
        if self.case_mode == 'lower':
            return name.lower()
        elif self.case_mode == 'upper':
            return name.upper()
        else:  # preserve
            return name
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get normalization statistics.
        
        Returns:
            Dictionary with statistics counters
        """
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset statistics counters."""
        self.stats = {
            'normalized': 0,
            'alias_applied': 0,
            'prefix_removed': 0,
            'suffix_removed': 0
        }


# ============= Convenience Functions =============

# Global default normalizer instance
_default_normalizer = None


def get_default_normalizer() -> StructNameNormalizer:
    """
    Get the global default normalizer instance.
    
    Returns:
        Global StructNameNormalizer instance
    """
    global _default_normalizer
    if _default_normalizer is None:
        _default_normalizer = StructNameNormalizer()
    return _default_normalizer


def normalize_struct_name(struct_name: str) -> str:
    """
    Normalize a structure name using the default normalizer.
    
    Convenience function for quick normalization.
    
    Args:
        struct_name: Raw structure name
        
    Returns:
        Normalized name
    """
    return get_default_normalizer().normalize(struct_name)


def load_aliases_from_config(alias_dict: Dict[str, str]):
    """
    Load aliases into the global normalizer.
    
    Args:
        alias_dict: Dictionary of variant -> canonical mappings
    """
    get_default_normalizer().load_aliases(alias_dict)


# ============= Testing Examples =============

if __name__ == '__main__':
    # Configure logging for testing
    logging.basicConfig(level=logging.DEBUG)
    
    # Create normalizer
    normalizer = StructNameNormalizer()
    
    # Test cases
    test_cases = [
        "struct Session",
        "class _SessionEntry_1",
        "T_EPROCESS",
        "tagWNDCLASS",
        "_EPROCESS_2",
        "Session_1",
        "__int64",
        "struct _IO_FILE",
        "union _LARGE_INTEGER",
    ]
    
    print("=" * 60)
    print("Structure Name Normalization Tests")
    print("=" * 60)
    print()
    
    for test in test_cases:
        normalized = normalizer.normalize(test)
        print(f"{test:30s} -> {normalized}")
    
    print()
    print("=" * 60)
    print("Testing Alias Mapping")
    print("=" * 60)
    print()
    
    # Add aliases
    normalizer.add_alias("ProcessObject", "EPROCESS")
    normalizer.add_alias("HandleTable", "EPROCESS")
    
    alias_tests = [
        "ProcessObject",
        "HandleTable",
        "struct ProcessObject",  # Should apply normalization first
    ]
    
    for test in alias_tests:
        normalized = normalizer.normalize(test)
        print(f"{test:30s} -> {normalized}")
    
    print()
    print("=" * 60)
    print("Statistics:")
    print("=" * 60)
    stats = normalizer.get_stats()
    for key, value in stats.items():
        print(f"  {key:20s}: {value}")

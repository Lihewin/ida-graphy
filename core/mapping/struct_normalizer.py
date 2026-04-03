"""Structure name normalizer for cross-binary consistency."""

import re
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class StructNameNormalizer:
    """Normalize structure names for stable DataSlot IDs."""

    def __init__(
        self,
        aliases: Optional[Dict[str, str]] = None,
        case_mode: str = "lower",
        aggressive_suffix_removal: bool = True,
    ):
        self.aliases = aliases or {}
        self.case_mode = case_mode
        self.aggressive_suffix_removal = aggressive_suffix_removal
        self.stats = {
            "normalized": 0,
            "alias_applied": 0,
            "prefix_removed": 0,
            "suffix_removed": 0,
        }

    def add_alias(self, variant: str, canonical: str):
        self.aliases[variant] = canonical
        logger.debug("Added alias: %s -> %s", variant, canonical)

    def load_aliases(self, alias_dict: Dict[str, str]):
        self.aliases.update(alias_dict)
        logger.info("Loaded %d struct aliases", len(alias_dict))

    def normalize(self, struct_name: str) -> str:
        if not struct_name:
            return struct_name

        original_name = struct_name
        name = self._remove_prefixes(struct_name)

        if name in self.aliases:
            name = self.aliases[name]
            self.stats["alias_applied"] += 1

        name = self._remove_suffixes(name)
        name = self._clean_underscores(name)
        name = self._normalize_case(name)

        self.stats["normalized"] += 1

        if name != original_name:
            logger.debug("Normalized: %s -> %s", original_name, name)

        return name

    def _remove_prefixes(self, name: str) -> str:
        original = name
        for prefix in ["struct ", "class ", "union ", "enum "]:
            if name.startswith(prefix):
                name = name[len(prefix) :]
                self.stats["prefix_removed"] += 1
                break

        if name.startswith("T_"):
            name = name[2:]
            self.stats["prefix_removed"] += 1

        if name.startswith("tag") and len(name) > 3 and name[3].isupper():
            name = name[3:]
            self.stats["prefix_removed"] += 1

        if name != original:
            logger.debug("Prefix removed: %s -> %s", original, name)

        return name

    def _remove_suffixes(self, name: str) -> str:
        original = name
        if self.aggressive_suffix_removal:
            name = re.sub(r"_\d+$", "", name)
        else:
            name = re.sub(r"_[0-9]$", "", name)

        if name != original:
            self.stats["suffix_removed"] += 1
            logger.debug("Suffix removed: %s -> %s", original, name)

        return name

    def _clean_underscores(self, name: str) -> str:
        original = name
        name = name.lstrip("_")
        if name != original:
            logger.debug("Underscores cleaned: %s -> %s", original, name)
        return name

    def _normalize_case(self, name: str) -> str:
        if self.case_mode == "lower":
            return name.lower()
        if self.case_mode == "upper":
            return name.upper()
        return name

    def get_stats(self) -> Dict[str, int]:
        return self.stats.copy()

    def reset_stats(self):
        self.stats = {
            "normalized": 0,
            "alias_applied": 0,
            "prefix_removed": 0,
            "suffix_removed": 0,
        }


_default_normalizer = None


def get_default_normalizer() -> StructNameNormalizer:
    global _default_normalizer
    if _default_normalizer is None:
        _default_normalizer = StructNameNormalizer()
    return _default_normalizer


def normalize_struct_name(struct_name: str) -> str:
    return get_default_normalizer().normalize(struct_name)


def load_aliases_from_config(alias_dict: Dict[str, str]):
    get_default_normalizer().load_aliases(alias_dict)

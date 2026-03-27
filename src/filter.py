"""Filter stage: classify domains as brand-relevant or irrelevant.

``Filter`` is a stateless utility class.  ``should_process`` applies per-brand
accept/reject keyword rules and returns a boolean.  No Redis, asyncio, or
pipeline-stage inheritance is used — the filter is a pure CPU function called
directly by ``filter_task`` in ``src/flow.py``.
"""

from typing import Iterable, Optional

from .config import CONFIG
from .http_client import HTTPClient


class Filter:
    """Stateless utility that classifies domains as brand-relevant or irrelevant.

    All methods are static — no instance state is required.  ``filter_task``
    in ``src/flow.py`` calls ``should_process`` for each domain and routes
    irrelevant domains to ``Output.write`` immediately.
    """

    @staticmethod
    def matching_brand(domain: str) -> Optional[str]:
        """Return the name of the first brand that accepts this domain, or ``None``.

        A brand accepts a domain when the normalised hostname contains at least
        one of the brand's ``domain_match_keywords`` and none of its
        ``domain_exclude_keywords``.

        Args:
            domain: Raw domain string from the pipeline.

        Returns:
            The ``Brand.name`` of the first matching brand, or ``None`` if no
            brand claims the domain.
        """
        normalized: str = HTTPClient.normalize_host(domain)
        for b in CONFIG.brands:
            if (
                Filter.contains_any(normalized, b.domain_match_keywords)
                and not Filter.contains_any(normalized, b.domain_exclude_keywords)
            ):
                return b.name
        return None

    @staticmethod
    def should_process(domain: str) -> bool:
        """Return ``True`` if any configured brand accepts this domain.

        For each brand, a domain is accepted when it contains at least one of
        the brand's ``domain_match_keywords`` and none of its
        ``domain_exclude_keywords``.  The domain passes if *any* brand accepts
        it.

        Args:
            domain: Raw domain string from the pipeline.

        Returns:
            ``True`` if the domain should proceed to the classification stage.
        """
        return Filter.matching_brand(domain) is not None

    @staticmethod
    def normalize(word: str) -> str:
        """Strip and lowercase a single keyword for case-insensitive matching.

        Args:
            word: Raw keyword string.

        Returns:
            Lowercased and whitespace-stripped keyword.
        """
        return word.strip().lower()

    @staticmethod
    def contains_any(text: str, keywords: Iterable[str]) -> bool:
        """Return ``True`` if ``text`` contains at least one of ``keywords``.

        Args:
            text: Normalised domain or text to search within.
            keywords: Iterable of keyword strings to look for.

        Returns:
            ``True`` if any non-empty, normalised keyword is a substring of
            ``text``.
        """
        if not text or not keywords:
            return False
        return any(nk and nk in text for nk in map(Filter.normalize, keywords))

from .commons import RedisClient, Channel
from .config import CONFIG
from typing import Iterable

class Filter:
    """Domain filtering module that applies brand-specific accept/reject keyword rules."""

    @staticmethod
    async def start(listening_channel: Channel = Channel.FILTER) -> None:
        """Start the filter module by subscribing to the filter channel."""
        async for domain in RedisClient.subscribe(listening_channel):
            channel: Channel = (Channel.PROCESS 
                                if Filter.should_process(domain) 
                                else Channel.IRRELEVANT)
            await RedisClient.publish(channel, domain)

    @staticmethod
    def should_process(domain: str) -> bool:
        """
        Determine if a domain should be processed based on brand-specific keywords.
        
        Logic for each brand:
        1) If domain contains any accept keyword AND not in reject keywords -> True
        2) Otherwise -> False
        
        Returns True if ANY brand accepts the domain.
        """
        normalized_domain: str = Filter.normalize_domain(domain)

        return any(
            Filter.contains_any(normalized_domain, b.domain_accept_keywords)
            and not Filter.contains_any(normalized_domain, b.domain_reject_keywords)
            for b in CONFIG.brands
        )
    
    @staticmethod
    def normalize(word: str) -> str:
        """Normalize a keyword for matching."""
        return word.strip().lower()

    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize a domain for keyword matching."""
        if not domain:
            return ""
        normalized: str = Filter.normalize(domain)
        try:
            normalized: str = normalized.encode("ascii", "ignore").decode("idna") or normalized
        finally:
            return normalized

    @staticmethod
    def contains_any(text: str, keywords: Iterable[str]) -> bool:
        """Check if text contains any of the given keywords."""
        if not text or not keywords:
            return False
        return any(nk and nk in text for nk in map(Filter.normalize, keywords))

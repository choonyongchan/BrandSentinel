"""Output Modules that persist domains routed by final pipeline stages."""

import asyncio
from .commons import Channel, RedisModule


class _BaseDomainOutput(RedisModule):
    """Base class that writes subscribed domains to a file."""

    def __init__(self, listening_channel: Channel, path: str) -> None:
        """Initialize a sink for a specific channel and file path.

        Args:
            listening_channel: Channel to subscribe to.
            path: File path to append domain lines to.
        """
        super().__init__(listening_channel)
        self.path = path

    async def start(self) -> None:
        """Begin consuming and writing domains."""
        await self.subscribe(self.act)

    async def act(self, domain: str) -> None:
        """Append a domain to the sink file asynchronously.

        Args:
            domain: Domain string to write.
        """
        await asyncio.to_thread(self._append_line, domain)
        print(f"Wrote domain '{domain}' to {self.path}")

    def _append_line(self, domain: str) -> None:
        """Blocking file append; run in thread via to_thread.

        Args:
            domain: Domain string to write.
        """
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(domain.strip() + "\n")


class NonScam(_BaseDomainOutput):
    """Writes NON_SCAM domains to a file."""

    def __init__(self, non_scam_path: str = "non_scam.txt") -> None:
        """Initialize NON_SCAM sink.

        Args:
            non_scam_path: Output file path.
        """
        super().__init__(Channel.BENIGN, non_scam_path)


class Inconclusive(_BaseDomainOutput):
    """Writes INCONCLUSIVE domains to a file."""

    def __init__(self, inconclusive_path: str = "inconclusive.txt") -> None:
        """Initialize INCONCLUSIVE sink.

        Args:
            inconclusive_path: Output file path.
        """
        super().__init__(Channel.INCONCLUSIVE, inconclusive_path)


class Scam(_BaseDomainOutput):
    """Writes SCAM domains to a file."""

    def __init__(self, scam_path: str = "scam.txt") -> None:
        """Initialize SCAM sink.

        Args:
            scam_path: Output file path.
        """
        super().__init__(Channel.SCAM, scam_path)
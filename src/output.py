"""Output Modules that persist domains routed by final pipeline stages."""
from .commons import Channel, RedisClient

class Output:
    """Base class that writes subscribed domains to a file."""

    channels: list[Channel] = [Channel.SCAM, Channel.INCONCLUSIVE, Channel.BENIGN, Channel.IRRELEVANT]

    @staticmethod
    async def start(listening_channel: Channel) -> None:
        """Begin consuming and writing domains."""
        path: str = f"{listening_channel.value}.txt"
        async for domain in RedisClient.subscribe(listening_channel):
            with open(path, "a", encoding="utf-8") as f:
                f.write(domain.strip() + "\n")
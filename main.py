"""Async entrypoint that starts outputs, processors, then the ingester."""

import asyncio
import signal
from typing import Sequence, Type

from src.commons import HTTPClient, RedisClient, RedisModule
from src.output import Inconclusive, NonScam, Scam
from src.processor import Processor
from src.ingester import DomainIngester

# Order matters: start subscribers (outputs, processors) before publishers.
OUTPUTS: Sequence[Type[RedisModule]] = (NonScam, Inconclusive, Scam)
PROCESSORS: Sequence[Type[RedisModule]] = (Processor,)


def _install_signal_handlers(shutdown_event: asyncio.Event) -> None:
    """Install SIGINT/SIGTERM handlers to trigger graceful shutdown.

    Args:
        shutdown_event: Event to set when a termination signal is received.
    """
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_event.set)


async def main() -> None:
    """Start the pipeline in stages and wait for shutdown."""
    shutdown = asyncio.Event()
    _install_signal_handlers(shutdown)

    async with asyncio.TaskGroup() as tg:
        # 1) Start outputs (terminal sinks)
        for cls in OUTPUTS:
            tg.create_task(cls().start(), name=f"output:{cls.__name__}")
        await asyncio.sleep(0.1)  # brief time to establish subscriptions

        # 2) Start processors (classification stage)
        for cls in PROCESSORS:
            tg.create_task(cls().start(), name=f"proc:{cls.__name__}")
        await asyncio.sleep(0.1)

        # 3) Finally, publish seed domains
        await DomainIngester().start()

        print("Pipeline running. Press Ctrl+C to stop.")
        await shutdown.wait()
        print("Shutting down...")

    # After TaskGroup exits, subscribers are cancelled; close shared clients.
    await HTTPClient.close()
    await RedisClient.close()
    print("Shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
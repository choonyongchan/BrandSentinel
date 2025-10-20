"""Counter module to track volumes per result channel and report periodically."""
from .commons import Channel, RedisClient
from .config import CONFIG
from typing import Dict

import asyncio

class Counter:
    """Subscribes to result channels and maintains running counts; reports every minute."""

    COUNTS: Dict[Channel, int] = {
        Channel.SCAM: 0,
        Channel.INCONCLUSIVE: 0,
        Channel.BENIGN: 0,
        Channel.IRRELEVANT: 0,
    }
    INTERVAL: int = CONFIG.counter.interval_s

    @staticmethod
    async def count_channel(channel: Channel) -> None:
        """Return the current scam count."""
        async for _ in RedisClient.subscribe(channel):
            Counter.COUNTS[channel] += 1

    @staticmethod
    async def count() -> None:
        """Start count_channel tasks inside a TaskGroup and return the TaskGroup.
        Caller is responsible for exiting the TaskGroup (await tg.__aexit__(None, None, None))
        to cancel/join the tasks when done.
        """
        async with asyncio.TaskGroup() as tg:
            for channel in Counter.COUNTS.keys():
                tg.create_task(Counter.count_channel(channel))

    @staticmethod
    async def report() -> None:
        """Begin consuming and reporting counts."""
        while True:
            total = 0
            message = "[Counter] 1-min update: "
            for channel, count in Counter.COUNTS.items():
                total += count
                message += f"{channel.value}: {count} "
            message += f"total: {total}"
            print(message)
            await asyncio.sleep(Counter.INTERVAL)
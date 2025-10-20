"""Async entrypoint that starts outputs, processors, then the ingester."""

import asyncio

from src.commons import Channel, HTTPClient, RedisClient
from src.output import Output
from src.counter import Counter
from src.filter import Filter
from src.processor import Processor
from src.ingester import Ingester

async def main() -> None:
    """Start the pipeline in stages and wait for shutdown."""
    async with asyncio.TaskGroup() as tg:

        # 0) Start Counter
        tg.create_task(Counter.count(), name="counter")

        # 1) Start outputs (terminal sinks)
        for listening_channel in (Channel.SCAM, Channel.INCONCLUSIVE, Channel.BENIGN):
            tg.create_task(Output.start(listening_channel=listening_channel), name=f"output:{listening_channel.name}")

        # 2) Start processors (classification stage)
        tg.create_task(Processor.start(listening_channel=Channel.PROCESS), name="proc:Filter")
        tg.create_task(Filter.start(listening_channel=Channel.FILTER), name="proc:Filter")
        tg.create_task(Ingester.start(), name="ingester")

        tg.create_task(Counter.report(), name="counter_report")

    try:
        # wait until interrupted (Ctrl-C)
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        print("Shutdown requested (Ctrl-C). Cancelling tasks...")

        # cancel all other running tasks to initiate graceful shutdown
        main_task = asyncio.current_task()
        tasks = []
        for t in tasks:
            t.cancel()

        # give tasks a chance to finish their cancellation handlers
        await asyncio.gather(*tasks, return_exceptions=True)

    # After TaskGroup exits, subscribers are cancelled; close shared clients.
    await HTTPClient.close()
    await RedisClient.close()
    print("Shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
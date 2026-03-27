"""Prefect flow and task definitions for the BrandSentinel pipeline.

Pipeline::

    brandsentinel_pipeline()  @flow — runs indefinitely; no schedule
      │
      ├─ source.run(queue)    asyncio.Task per enabled source (background workers)
      │
      └─ while True:
           await queue.get()            block until ≥1 domain arrives
           drain remaining (non-blocking)
           filter_task(batch)           @task — brand keyword filter
           classify_task(d) fan-out     @task — heuristic engine, one per domain
           output_task(results)         @task — write per-verdict files

No task imports another task or stage module — all wiring lives in this file.

Why ``asyncio.gather`` over ``.submit()`` for classify fan-out:
``.submit()`` dispatches to a thread pool (default ``ThreadPoolTaskRunner``).
Each thread would create its own event loop, breaking the shared
``httpx.AsyncClient`` singleton.  Calling the async ``classify_task`` coroutine
directly with ``asyncio.gather`` keeps everything in the flow's event loop —
the Prefect 3.x recommended pattern for async task fan-out.
"""

import asyncio
from typing import Optional

from prefect import flow, task, get_run_logger

from .ingester import Ingester
from .filter import Filter
from .processor import Processor
from .output import Output
from .verdict import Verdict


@task(name="filter")
def filter_task(domains: list[str]) -> list[tuple[str, str]]:
    """Filter for brand-relevant domains and write irrelevant ones to file.

    Pure CPU work — no I/O except the ``Output.write`` call for irrelevant domains.

    Args:
        domains: Raw domain strings from the queue batch.

    Returns:
        List of ``(domain, brand_name)`` pairs for domains that passed brand
        keyword filtering.
    """
    relevant: list[tuple[str, str]] = []
    irrelevant: list[str] = []
    for d in domains:
        brand = Filter.matching_brand(d)
        if brand is not None:
            relevant.append((d, brand))
        else:
            irrelevant.append(d)
    for d in irrelevant:
        Output.write(d, Verdict.IRRELEVANT)
    get_run_logger().info(
        "filter: %d relevant, %d irrelevant", len(relevant), len(irrelevant)
    )
    return relevant


@task(name="classify", retries=1, retry_delay_seconds=2)
async def classify_task(domain: str, brand: str) -> tuple[str, str, Optional[Verdict]]:
    """Classify one domain through the full heuristic engine.

    This task is the unit of retry: a transient I/O failure retries only this
    domain, leaving all other in-flight domains unaffected.

    Args:
        domain: A brand-relevant domain string from ``filter_task``.
        brand: The brand name that claimed this domain (from ``filter_task``).

    Returns:
        ``(domain, brand, Verdict)`` on success, or ``(domain, brand, None)``
        for whitelisted domains (silently dropped in ``output_task``).
    """
    verdict = await Processor.classify(domain)
    return domain, brand, verdict


@task(name="output")
def output_task(results: list[tuple[str, str, Optional[Verdict]]]) -> None:
    """Write classified domains to per-brand verdict files and log counts.

    Args:
        results: List of ``(domain, brand, Verdict | None)`` triples from
            ``classify_task``.  ``None`` verdict entries (whitelisted domains)
            are silently skipped.
    """
    counts: dict[str, int] = {v.value: 0 for v in Verdict}
    for domain, brand, verdict in results:
        if verdict is None:
            continue
        Output.write(domain, verdict, brand)
        counts[verdict.value] += 1
    get_run_logger().info("output: %s", counts)


@flow(name="brandsentinel_pipeline", log_prints=True)
async def brandsentinel_pipeline() -> None:
    """Streaming DRP pipeline: source workers push into a queue; flow drains and classifies.

    Runs indefinitely.  Each enabled source is started as a background
    ``asyncio.Task``.  The main loop blocks on ``queue.get()`` until at least
    one domain is available, then drains any remaining queued domains and
    processes the full batch through
    ``filter_task → classify_task (fan-out) → output_task``.

    The classify fan-out uses ``asyncio.gather`` so all classify coroutines run
    in the same event loop, allowing the shared ``httpx.AsyncClient`` connection
    pool to be reused across concurrent domain fetches.
    """
    logger = get_run_logger()
    queue: asyncio.Queue[str] = asyncio.Queue()

    sources = Ingester.enabled_sources()
    # Strong references are required: the event loop holds only weak refs to
    # tasks, so an un-referenced task can be GC'd while still pending —
    # producing "Task was destroyed but it is pending!" warnings.
    source_tasks: list[asyncio.Task] = [
        asyncio.create_task(src.run(queue), name=src.key)
        for src in sources
    ]
    logger.info("pipeline: %d source workers started", len(source_tasks))

    try:
        while True:
            domain = await queue.get()
            batch: list[str] = [domain]
            while not queue.empty():
                batch.append(queue.get_nowait())

            logger.info("pipeline: %d domains dequeued", len(batch))

            relevant = filter_task(batch)
            if not relevant:
                continue

            results: list[tuple[str, str, Optional[Verdict]]] = list(
                await asyncio.gather(*(classify_task(d, b) for d, b in relevant))
            )
            output_task(results)
    finally:
        # Cancel source workers and wait for them to finish so the event loop
        # does not emit "Task was destroyed but it is pending!" on shutdown.
        for t in source_tasks:
            t.cancel()
        await asyncio.gather(*source_tasks, return_exceptions=True)

"""Entry point: run the BrandSentinel streaming pipeline.

Startup sequence:
1. Run ``brandsentinel_pipeline`` (blocking; runs indefinitely).
2. On shutdown, close the shared HTTP client.

Run::

    export PREFECT_API_URL=http://localhost:4200/api
    python main.py
"""

import asyncio

from src.flow import brandsentinel_pipeline
from src.http_client import HTTPClient


async def main() -> None:
    """Start the pipeline and block until interrupted."""
    await brandsentinel_pipeline()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        asyncio.run(HTTPClient.close())

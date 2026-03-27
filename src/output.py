"""Output stage: appends classified domains to per-verdict text files.

``Output.write`` is a synchronous static method — no Redis, asyncio, or
pipeline-stage inheritance is used.  The file is opened and closed per call
so no file handle leaks occur between concurrent classify tasks.

Output layout::

    results/
      <brand>/          ← one sub-directory per matched brand
        scam.txt
        inconclusive.txt
        benign.txt
      irrelevant.txt    ← domains that matched no brand (no sub-directory)
"""

import os
from typing import Optional

from .verdict import Verdict

_RESULTS_DIR = "results"


class Output:
    """Appends classified domains to per-brand verdict files under ``results/``.

    Brand-matched domains are written to ``results/<brand>/<verdict>.txt``.
    Domains with no brand match (i.e. ``Verdict.IRRELEVANT``) are written to
    ``results/irrelevant.txt``.

    All methods are static — no instance state is required.  ``output_task``
    and ``filter_task`` in ``src/flow.py`` call ``write`` for each domain.
    """

    @staticmethod
    def write(domain: str, verdict: Verdict, brand: Optional[str] = None) -> None:
        """Append ``domain`` to the appropriate verdict file.

        Brand-matched domains go to ``results/<brand>/<verdict>.txt``.
        Unmatched domains (no brand) go to ``results/<verdict>.txt``.
        The target directory is created automatically if it does not exist.
        File is opened and closed per call so no file handle leaks occur
        between concurrent classify tasks.  Line-buffered mode (``buffering=1``)
        ensures the write is flushed immediately.

        Args:
            domain: The classified domain string.
            verdict: Determines which output file receives the domain.
            brand: Brand name used as the sub-directory.  ``None`` for
                domains with no brand match (e.g. ``Verdict.IRRELEVANT``).
        """
        directory = (
            os.path.join(_RESULTS_DIR, brand) if brand else _RESULTS_DIR
        )
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{verdict.value}.txt")
        with open(path, "a", encoding="utf-8", buffering=1) as f:
            f.write(domain.strip() + "\n")

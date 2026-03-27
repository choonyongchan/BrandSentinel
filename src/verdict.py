"""Verdict enum for domain classification outcomes.

Replaces the routing channels ``SCAM / INCONCLUSIVE / BENIGN / IRRELEVANT``
from the old ``Channel`` enum.  ``FILTER`` and ``PROCESS`` are removed —
they were Redis routing artefacts, not business concepts.

Typical usage::

    from .verdict import Verdict

    verdict = Verdict.SCAM
    path = f"{verdict.value}.txt"  # "scam.txt"
"""

from enum import Enum


class Verdict(Enum):
    """Classification outcome for a single domain.

    Attributes:
        SCAM: Domain is likely a phishing or brand-impersonation threat.
        INCONCLUSIVE: Domain has suspicious signals but insufficient weight to
            confirm as scam.  Warrants manual review.
        BENIGN: Domain is inactive, parked, or carries OV/EV certificate proof
            of legitimate ownership.
        IRRELEVANT: Domain does not match any monitored brand and was dropped
            at the filter stage.
    """

    SCAM = "scam"
    INCONCLUSIVE = "inconclusive"
    BENIGN = "benign"
    IRRELEVANT = "irrelevant"

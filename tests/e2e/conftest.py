"""E2E test fixtures: Prefect test harness for full pipeline runs."""

import pytest


@pytest.fixture(autouse=True, scope="session")
def prefect_test_env():
    """Activate the Prefect in-memory test harness for the full test session.

    Provides an isolated Prefect environment (no external server required)
    so that ``brandsentinel_pipeline`` can be called directly in tests
    without connecting to a live Prefect server.
    """
    from prefect.testing.utilities import prefect_test_harness

    with prefect_test_harness():
        yield

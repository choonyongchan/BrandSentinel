"""Unit tests for src/ingester.py: sources, run() workers, and enqueue deduplication."""

import asyncio
import json
from typing import List
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.http_client import FetchResult
from src.ingester import Ingester


def make_fetch_result(html="", status=200):
    """Return a stub FetchResult for use in ingester tests.

    Args:
        html: Simulated HTTP response body.
        status: Simulated HTTP status code.

    Returns:
        A ``FetchResult`` populated with test values.
    """
    return FetchResult(
        url="http://feed.example.com",
        status=status,
        headers={},
        html=html,
        history=[],
        final_url="http://feed.example.com",
        elapsed_ms=10.0,
    )


def _fast_sleep(monkeypatch):
    """Patch ``asyncio.sleep`` to yield once (via the original) without waiting.

    Stores the original coroutine function before patching so the replacement
    can delegate to it with a zero-second duration (avoiding infinite recursion
    while still giving the event loop a chance to schedule pending tasks).

    Args:
        monkeypatch: The pytest monkeypatch fixture.

    Returns:
        A list that accumulates each ``n`` passed to the patched sleep, allowing
        callers to assert which intervals were requested.
    """
    original_sleep = asyncio.sleep
    calls: List[float] = []

    async def _mock(n):
        calls.append(n)
        await original_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", _mock)
    return calls


# ---------------------------------------------------------------------------
# OpenPhish
# ---------------------------------------------------------------------------

class TestOpenPhish:
    """Tests for OpenPhish.run() async worker."""

    async def test_run_enqueues_normalized_hosts(self, monkeypatch):
        from src.ingester import OpenPhish

        html = "https://phish1.com/path\nhttps://phish2.com\n"
        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=html)),
        )
        _fast_sleep(monkeypatch)

        src_obj = OpenPhish()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert "phish1.com" in results
        assert "phish2.com" in results

    async def test_run_skips_empty_response(self, monkeypatch):
        from src.ingester import OpenPhish

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="")),
        )
        _fast_sleep(monkeypatch)

        src_obj = OpenPhish()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert queue.empty()

    async def test_run_calls_sleep_with_interval(self, monkeypatch):
        from src.ingester import OpenPhish

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="")),
        )
        calls = _fast_sleep(monkeypatch)

        src_obj = OpenPhish(interval_s=99)
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert 99 in calls

    async def test_run_skips_invalid_lines(self, monkeypatch):
        from src.ingester import OpenPhish

        html = "# comment\nnot-a-domain\nvalid.example.com\n"
        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=html)),
        )
        _fast_sleep(monkeypatch)

        src_obj = OpenPhish()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert "valid.example.com" in results
        assert "" not in results


# ---------------------------------------------------------------------------
# PhishTank
# ---------------------------------------------------------------------------

class TestPhishTank:
    """Tests for PhishTank.run() async worker."""

    async def test_run_enqueues_url_field(self, monkeypatch):
        from src.ingester import PhishTank

        data = json.dumps([{"url": "http://evil.com/"}])
        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=data)),
        )
        _fast_sleep(monkeypatch)

        src_obj = PhishTank()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert "evil.com" in results

    async def test_run_skips_invalid_json(self, monkeypatch):
        from src.ingester import PhishTank

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="not json")),
        )
        _fast_sleep(monkeypatch)

        src_obj = PhishTank()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert queue.empty()

    async def test_run_ignores_entries_without_url(self, monkeypatch):
        from src.ingester import PhishTank

        data = json.dumps([{"no_url": True}, {"url": "http://valid.com/"}])
        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=data)),
        )
        _fast_sleep(monkeypatch)

        src_obj = PhishTank()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert "valid.com" in results
        assert len(results) == 1

    async def test_run_deduplicates_within_feed(self, monkeypatch):
        from src.ingester import PhishTank

        data = json.dumps([
            {"url": "http://dup.com/a"},
            {"url": "http://dup.com/b"},
        ])
        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=data)),
        )
        _fast_sleep(monkeypatch)

        src_obj = PhishTank()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert results.count("dup.com") == 1


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------

class TestURLhaus:
    """Tests for URLhaus.run() async worker."""

    async def test_run_skips_comment_lines(self, monkeypatch):
        from src.ingester import URLhaus

        html = "# This is a comment\nhttp://evil.com/\n"
        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=html)),
        )
        _fast_sleep(monkeypatch)

        src_obj = URLhaus()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert "evil.com" in results

    async def test_run_skips_blank_lines(self, monkeypatch):
        from src.ingester import URLhaus

        html = "\n\nhttp://evil.com/\n\n"
        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=html)),
        )
        _fast_sleep(monkeypatch)

        src_obj = URLhaus()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert results == ["evil.com"]

    async def test_run_normalizes_hosts(self, monkeypatch):
        from src.ingester import URLhaus

        html = "https://SCAM.EXAMPLE.COM/path\n"
        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=html)),
        )
        _fast_sleep(monkeypatch)

        src_obj = URLhaus()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert "scam.example.com" in results

    async def test_run_skips_empty_response(self, monkeypatch):
        from src.ingester import URLhaus

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="")),
        )
        _fast_sleep(monkeypatch)

        src_obj = URLhaus()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert queue.empty()


# ---------------------------------------------------------------------------
# _parse_ct_domains helper
# ---------------------------------------------------------------------------

def _make_cert_message(domains: List[str]) -> dict:
    """Build a minimal certstream ``certificate_update`` message dict.

    Args:
        domains: List of domain strings to embed in ``leaf_cert.all_domains``.

    Returns:
        Dict matching the certstream certificate_update JSON structure.
    """
    return {
        "message_type": "certificate_update",
        "data": {"leaf_cert": {"all_domains": domains}},
    }


class TestParseCTDomains:
    """Unit tests for ``CertStream._parse_ct_domains``."""

    def test_returns_domains_for_valid_message(self):
        from src.ingester import CertStream
        result = CertStream._parse_ct_domains(_make_cert_message(["evil.example.com", "www.evil.example.com"]))
        assert result == ["evil.example.com", "www.evil.example.com"]

    def test_strips_wildcard_prefix(self):
        from src.ingester import CertStream
        result = CertStream._parse_ct_domains(_make_cert_message(["*.EVIL.COM"]))
        assert result == ["evil.com"]

    def test_returns_empty_for_heartbeat(self):
        from src.ingester import CertStream
        assert CertStream._parse_ct_domains({"message_type": "heartbeat"}) == []

    def test_returns_empty_for_non_dict(self):
        from src.ingester import CertStream
        assert CertStream._parse_ct_domains(None) == []
        assert CertStream._parse_ct_domains("raw string") == []

    def test_returns_empty_for_missing_leaf_cert(self):
        from src.ingester import CertStream
        msg = {"message_type": "certificate_update", "data": {}}
        assert CertStream._parse_ct_domains(msg) == []

    def test_returns_empty_for_missing_all_domains(self):
        from src.ingester import CertStream
        msg = {"message_type": "certificate_update", "data": {"leaf_cert": {}}}
        assert CertStream._parse_ct_domains(msg) == []

    def test_skips_non_string_entries(self):
        from src.ingester import CertStream
        result = CertStream._parse_ct_domains(_make_cert_message([None, 123, "good.com"]))  # type: ignore[list-item]
        assert result == ["good.com"]


# ---------------------------------------------------------------------------
# CertStream._on_message / _on_error
# ---------------------------------------------------------------------------

class TestCertStreamOnMessage:
    """Tests for ``CertStream._on_message`` and ``CertStream._on_error``."""

    def test_enqueues_domain_via_call_soon_threadsafe(self):
        """Valid certificate_update message → ``call_soon_threadsafe`` called with domain."""
        from src.ingester import CertStream

        cs = CertStream()
        loop_mock = MagicMock()
        queue_mock: asyncio.Queue = asyncio.Queue()
        cs._loop = loop_mock
        cs._queue = queue_mock

        cs._on_message(_make_cert_message(["phish-brand.com"]), context=None)

        loop_mock.call_soon_threadsafe.assert_called_once_with(
            Ingester.enqueue, "phish-brand.com", queue_mock, "certstream"
        )

    def test_ignores_heartbeat(self):
        """Heartbeat message → ``call_soon_threadsafe`` not called."""
        from src.ingester import CertStream

        cs = CertStream()
        loop_mock = MagicMock()
        cs._loop = loop_mock
        cs._queue = asyncio.Queue()

        cs._on_message({"message_type": "heartbeat"}, context=None)

        loop_mock.call_soon_threadsafe.assert_not_called()

    def test_noop_when_loop_not_set(self):
        """``_on_message`` is a no-op when ``_loop`` is ``None``."""
        from src.ingester import CertStream

        cs = CertStream()
        cs._queue = asyncio.Queue()
        # _loop intentionally left as None

        # Should not raise
        cs._on_message(_make_cert_message(["brand.com"]), context=None)

    def test_noop_when_queue_not_set(self):
        """``_on_message`` is a no-op when ``_queue`` is ``None``."""
        from src.ingester import CertStream

        cs = CertStream()
        cs._loop = MagicMock()
        # _queue intentionally left as None

        cs._on_message(_make_cert_message(["brand.com"]), context=None)

        cs._loop.call_soon_threadsafe.assert_not_called()

    def test_on_error_prints_message(self, capsys):
        """``_on_error`` prints the exception without raising."""
        from src.ingester import CertStream

        cs = CertStream()
        cs._on_error(exc=RuntimeError("timeout"))

        captured = capsys.readouterr()
        assert "timeout" in captured.out

    def test_multiple_domains_in_one_message(self):
        """Multiple domains in a single cert event → one ``call_soon_threadsafe`` call per domain."""
        from src.ingester import CertStream

        cs = CertStream()
        loop_mock = MagicMock()
        queue_mock: asyncio.Queue = asyncio.Queue()
        cs._loop = loop_mock
        cs._queue = queue_mock

        cs._on_message(_make_cert_message(["alpha.com", "beta.com"]), context=None)

        assert loop_mock.call_soon_threadsafe.call_count == 2


# ---------------------------------------------------------------------------
# CertStream.run()
# ---------------------------------------------------------------------------

class TestCertStreamRunMethod:
    """Tests for ``CertStream.run()`` — thread startup and state initialisation."""

    async def test_run_stores_loop_and_queue(self, monkeypatch):
        """``run()`` stores the running event loop and queue on the instance."""
        import threading
        from src.ingester import CertStream

        started_events: list = []

        def fake_start(self_thread):
            started_events.append(True)

        monkeypatch.setattr(threading.Thread, "start", fake_start)

        # Prevent the coroutine from suspending forever
        event_mock = MagicMock()
        event_mock.wait = AsyncMock(side_effect=asyncio.CancelledError)
        monkeypatch.setattr("src.ingester.asyncio.Event", lambda: event_mock)

        cs = CertStream()
        queue: asyncio.Queue = asyncio.Queue()

        with pytest.raises(asyncio.CancelledError):
            await cs.run(queue)

        assert cs._loop is asyncio.get_event_loop()
        assert cs._queue is queue

    async def test_run_starts_daemon_thread(self, monkeypatch):
        """``run()`` starts exactly one daemon thread targeting ``_run_listener``."""
        import threading
        from src.ingester import CertStream

        created_threads: list = []
        original_init = threading.Thread.__init__

        def capturing_init(self_thread, **kwargs):
            original_init(self_thread, **kwargs)
            created_threads.append(self_thread)

        monkeypatch.setattr(threading.Thread, "__init__", capturing_init)
        monkeypatch.setattr(threading.Thread, "start", lambda self_thread: None)

        event_mock = MagicMock()
        event_mock.wait = AsyncMock(side_effect=asyncio.CancelledError)
        monkeypatch.setattr("src.ingester.asyncio.Event", lambda: event_mock)

        cs = CertStream()
        queue: asyncio.Queue = asyncio.Queue()

        with pytest.raises(asyncio.CancelledError):
            await cs.run(queue)

        assert len(created_threads) == 1
        assert created_threads[0].daemon is True


# ---------------------------------------------------------------------------
# ManualImport
# ---------------------------------------------------------------------------

class TestManualImport:
    """Tests for ManualImport.run() async worker."""

    async def test_run_enqueues_file_contents(self, tmp_path, monkeypatch):
        from src.ingester import ManualImport

        domains_file = tmp_path / "manual_domains.txt"
        domains_file.write_text("evil.com\nscam.net\n", encoding="utf-8")
        _fast_sleep(monkeypatch)

        mi = ManualImport()
        mi.path = str(domains_file)
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(mi.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert "evil.com" in results
        assert "scam.net" in results

    async def test_run_skips_missing_file(self, tmp_path, monkeypatch):
        from src.ingester import ManualImport

        _fast_sleep(monkeypatch)

        mi = ManualImport()
        mi.path = str(tmp_path / "nonexistent.txt")
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(mi.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert queue.empty()

    async def test_run_skips_already_seen_domains_on_second_cycle(self, tmp_path, monkeypatch):
        from src.ingester import ManualImport

        domains_file = tmp_path / "manual_domains.txt"
        domains_file.write_text("evil.com\n", encoding="utf-8")
        calls = _fast_sleep(monkeypatch)

        mi = ManualImport()
        mi.path = str(domains_file)
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(mi.run(queue))

        # Yield enough times for two full sleep cycles to execute
        for _ in range(4):
            await asyncio.sleep(0)

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        # "evil.com" should only be enqueued once despite two cycles
        assert results.count("evil.com") == 1

    async def test_run_calls_sleep_with_interval(self, tmp_path, monkeypatch):
        from src.ingester import ManualImport

        calls = _fast_sleep(monkeypatch)

        mi = ManualImport(interval_s=42)
        mi.path = str(tmp_path / "nonexistent.txt")
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(mi.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert 42 in calls


# ---------------------------------------------------------------------------
# Ingester.enqueue
# ---------------------------------------------------------------------------

class TestIngesterEnqueue:
    """Tests for Ingester.enqueue static method."""

    def test_new_domain_enqueued_and_visited(self):
        from src.ingester import Ingester, Source

        Source.VISITED_DOMAINS.clear()
        queue: asyncio.Queue = asyncio.Queue()
        Ingester.enqueue("evil.com", queue)
        assert queue.get_nowait() == "evil.com"
        assert "evil.com" in Source.VISITED_DOMAINS

    def test_already_visited_domain_not_enqueued(self):
        from src.ingester import Ingester, Source

        Source.VISITED_DOMAINS.add("evil.com")
        queue: asyncio.Queue = asyncio.Queue()
        Ingester.enqueue("evil.com", queue)
        assert queue.empty()

    def test_empty_string_not_enqueued(self):
        from src.ingester import Ingester, Source

        Source.VISITED_DOMAINS.clear()
        queue: asyncio.Queue = asyncio.Queue()
        Ingester.enqueue("", queue)
        assert queue.empty()

    def test_second_enqueue_of_same_domain_skipped(self):
        from src.ingester import Ingester, Source

        Source.VISITED_DOMAINS.clear()
        queue: asyncio.Queue = asyncio.Queue()
        Ingester.enqueue("evil.com", queue)
        Ingester.enqueue("evil.com", queue)
        assert queue.qsize() == 1

    def test_multiple_distinct_domains_all_enqueued(self):
        from src.ingester import Ingester, Source

        Source.VISITED_DOMAINS.clear()
        queue: asyncio.Queue = asyncio.Queue()
        Ingester.enqueue("evil.com", queue)
        Ingester.enqueue("scam.net", queue)
        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert set(results) == {"evil.com", "scam.net"}


# ---------------------------------------------------------------------------
# Shared helper for plain-text feed sources
# ---------------------------------------------------------------------------

async def _run_once(src_obj, monkeypatch, html: str) -> List[str]:
    """Run a plain-text source worker once and return all enqueued domains.

    Patches ``asyncio.sleep`` to cancel after one cycle, drives the source
    ``run()`` coroutine to completion for a single fetch, and drains the queue.

    Args:
        src_obj: An instantiated ``Source`` subclass to test.
        monkeypatch: The pytest monkeypatch fixture.
        html: Simulated feed response body.

    Returns:
        List of hostname strings that were placed on the queue.
    """
    monkeypatch.setattr(
        "src.http_client.HTTPClient.fetch",
        AsyncMock(return_value=make_fetch_result(html=html)),
    )
    _fast_sleep(monkeypatch)
    queue: asyncio.Queue = asyncio.Queue()
    task = asyncio.create_task(src_obj.run(queue))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    results = []
    while not queue.empty():
        results.append(queue.get_nowait())
    return results


# ---------------------------------------------------------------------------
# CERTPolska
# ---------------------------------------------------------------------------

class TestCERTPolska:
    """Tests for CERTPolska.run() async worker."""

    async def test_enqueues_normalized_hosts(self, monkeypatch):
        """Each hostname line is normalised and enqueued."""
        from src.ingester import CERTPolska

        results = await _run_once(CERTPolska(), monkeypatch, "evil.pl\nphish.com\n")
        assert "evil.pl" in results
        assert "phish.com" in results

    async def test_skips_comment_lines(self, monkeypatch):
        """Lines beginning with ``#`` are discarded."""
        from src.ingester import CERTPolska

        results = await _run_once(CERTPolska(), monkeypatch, "# header\nevil.pl\n")
        assert "evil.pl" in results
        assert not any(r.startswith("#") for r in results)

    async def test_skips_blank_lines(self, monkeypatch):
        """Empty lines produce no queue entries."""
        from src.ingester import CERTPolska

        results = await _run_once(CERTPolska(), monkeypatch, "\n\nevil.pl\n\n")
        assert results == ["evil.pl"]

    async def test_skips_empty_response(self, monkeypatch):
        """An empty HTTP response produces no queue entries."""
        from src.ingester import CERTPolska

        results = await _run_once(CERTPolska(), monkeypatch, "")
        assert results == []

    async def test_calls_sleep_with_interval(self, monkeypatch):
        """``asyncio.sleep`` is called with the configured interval."""
        from src.ingester import CERTPolska

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="")),
        )
        calls = _fast_sleep(monkeypatch)
        src_obj = CERTPolska(interval_s=77)
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert 77 in calls


# ---------------------------------------------------------------------------
# PhishingDatabase
# ---------------------------------------------------------------------------

class TestPhishingDatabase:
    """Tests for PhishingDatabase.run() async worker."""

    async def test_enqueues_active_domains(self, monkeypatch):
        """Domains from the active list are normalised and enqueued."""
        from src.ingester import PhishingDatabase

        results = await _run_once(
            PhishingDatabase(), monkeypatch, "phish-active.com\nscam-live.net\n"
        )
        assert "phish-active.com" in results
        assert "scam-live.net" in results

    async def test_skips_comment_and_blank_lines(self, monkeypatch):
        """Comment and blank lines produce no queue entries."""
        from src.ingester import PhishingDatabase

        results = await _run_once(
            PhishingDatabase(), monkeypatch, "# PyFunceble header\n\nphish.com\n"
        )
        assert results == ["phish.com"]

    async def test_skips_empty_response(self, monkeypatch):
        """An empty HTTP response produces no queue entries."""
        from src.ingester import PhishingDatabase

        results = await _run_once(PhishingDatabase(), monkeypatch, "")
        assert results == []

    async def test_calls_sleep_with_interval(self, monkeypatch):
        """``asyncio.sleep`` is called with the configured interval."""
        from src.ingester import PhishingDatabase

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="")),
        )
        calls = _fast_sleep(monkeypatch)
        src_obj = PhishingDatabase(interval_s=55)
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert 55 in calls


# ---------------------------------------------------------------------------
# PhishingArmy
# ---------------------------------------------------------------------------

class TestPhishingArmy:
    """Tests for PhishingArmy.run() async worker."""

    async def test_enqueues_blocklist_domains(self, monkeypatch):
        """Domains from the extended blocklist are enqueued."""
        from src.ingester import PhishingArmy

        results = await _run_once(PhishingArmy(), monkeypatch, "block1.com\nblock2.net\n")
        assert "block1.com" in results
        assert "block2.net" in results

    async def test_skips_comment_and_blank_lines(self, monkeypatch):
        """Comment and blank lines produce no queue entries."""
        from src.ingester import PhishingArmy

        results = await _run_once(
            PhishingArmy(), monkeypatch, "# Phishing Army blocklist\n\nblock1.com\n"
        )
        assert results == ["block1.com"]

    async def test_skips_empty_response(self, monkeypatch):
        """An empty HTTP response produces no queue entries."""
        from src.ingester import PhishingArmy

        results = await _run_once(PhishingArmy(), monkeypatch, "")
        assert results == []

    async def test_calls_sleep_with_interval(self, monkeypatch):
        """``asyncio.sleep`` is called with the configured interval."""
        from src.ingester import PhishingArmy

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="")),
        )
        calls = _fast_sleep(monkeypatch)
        src_obj = PhishingArmy(interval_s=33)
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert 33 in calls


# ---------------------------------------------------------------------------
# Botvrij
# ---------------------------------------------------------------------------

class TestBotvrij:
    """Tests for Botvrij.run() async worker."""

    async def test_enqueues_raw_ioc_domains(self, monkeypatch):
        """Domains from the raw IOC list are enqueued."""
        from src.ingester import Botvrij

        results = await _run_once(Botvrij(), monkeypatch, "ioc1.nl\nioc2.com\n")
        assert "ioc1.nl" in results
        assert "ioc2.com" in results

    async def test_skips_comment_and_blank_lines(self, monkeypatch):
        """Comment and blank lines produce no queue entries."""
        from src.ingester import Botvrij

        results = await _run_once(Botvrij(), monkeypatch, "# botvrij header\n\nioc1.nl\n")
        assert results == ["ioc1.nl"]

    async def test_skips_empty_response(self, monkeypatch):
        """An empty HTTP response produces no queue entries."""
        from src.ingester import Botvrij

        results = await _run_once(Botvrij(), monkeypatch, "")
        assert results == []

    async def test_calls_sleep_with_interval(self, monkeypatch):
        """``asyncio.sleep`` is called with the configured interval."""
        from src.ingester import Botvrij

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="")),
        )
        calls = _fast_sleep(monkeypatch)
        src_obj = Botvrij(interval_s=22)
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert 22 in calls


# ---------------------------------------------------------------------------
# DigitalSide
# ---------------------------------------------------------------------------

class TestDigitalSide:
    """Tests for DigitalSide.run() async worker."""

    async def test_enqueues_domains_from_primary(self, monkeypatch):
        """Domains are enqueued when the primary endpoint returns content."""
        from src.ingester import DigitalSide

        results = await _run_once(DigitalSide(), monkeypatch, "ds-evil.com\n")
        assert "ds-evil.com" in results

    async def test_falls_back_to_fallback_url_when_primary_empty(self, monkeypatch):
        """Falls back to ``fallback_url`` when the primary returns an empty body."""
        from src.ingester import DigitalSide

        fetch_calls = []

        async def mock_fetch(url):
            fetch_calls.append(url)
            if "osint.digitalside.it" in url:
                return make_fetch_result(html="")
            return make_fetch_result(html="fallback-domain.com\n")

        monkeypatch.setattr("src.http_client.HTTPClient.fetch", mock_fetch)
        _fast_sleep(monkeypatch)

        ds = DigitalSide()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(ds.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())

        assert "fallback-domain.com" in results
        assert any("osint.digitalside.it" in u for u in fetch_calls)
        assert any("githubusercontent.com" in u for u in fetch_calls)

    async def test_skips_comment_and_blank_lines(self, monkeypatch):
        """Comment and blank lines produce no queue entries."""
        from src.ingester import DigitalSide

        results = await _run_once(DigitalSide(), monkeypatch, "# header\n\nds-evil.com\n")
        assert results == ["ds-evil.com"]

    async def test_skips_empty_primary_and_empty_fallback(self, monkeypatch):
        """No queue entries when both primary and fallback return empty content."""
        from src.ingester import DigitalSide

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="")),
        )
        _fast_sleep(monkeypatch)
        ds = DigitalSide()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(ds.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert queue.empty()


# ---------------------------------------------------------------------------
# URLhausCountry
# ---------------------------------------------------------------------------

_CSV_HEADER = "# URLhaus Feed\n"
_CSV_ROW = '"{date}","http://{host}/path","online","malware_download","{host}","1.2.3.4","AS1234","SG"\n'


def _make_urlhaus_csv(*hosts: str) -> str:
    """Build a minimal URLhaus country feed CSV body.

    Args:
        *hosts: Hostnames to embed as URLhaus CSV rows.

    Returns:
        Multi-line string resembling a URLhaus country CSV feed.
    """
    rows = [_CSV_HEADER]
    for h in hosts:
        rows.append(_CSV_ROW.format(date="2026-01-01 00:00:00", host=h))
    return "".join(rows)


class TestURLhausCountry:
    """Tests for URLhausCountry.run() async worker."""

    async def test_enqueues_host_column_from_csv(self, monkeypatch):
        """The ``Host`` column (index 4) of each CSV row is normalised and enqueued."""
        from src.ingester import URLhausCountry

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=_make_urlhaus_csv("evil.sg", "scam.sg"))),
        )
        monkeypatch.setattr(
            "src.ingester.CONFIG.ingester",
            type("I", (), {"urlhaus_country_codes": ["SG"]})(),
        )
        _fast_sleep(monkeypatch)

        src_obj = URLhausCountry()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        results = []
        while not queue.empty():
            results.append(queue.get_nowait())
        assert "evil.sg" in results
        assert "scam.sg" in results

    async def test_skips_comment_rows(self, monkeypatch):
        """Rows whose first field starts with ``#`` are discarded."""
        from src.ingester import URLhausCountry

        csv_body = "# comment row\n"
        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=csv_body)),
        )
        monkeypatch.setattr(
            "src.ingester.CONFIG.ingester",
            type("I", (), {"urlhaus_country_codes": ["SG"]})(),
        )
        _fast_sleep(monkeypatch)

        src_obj = URLhausCountry()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert queue.empty()

    async def test_skips_rows_with_fewer_than_five_columns(self, monkeypatch):
        """Rows with fewer than 5 CSV fields are safely ignored."""
        from src.ingester import URLhausCountry

        csv_body = "only,four,fields,here\n"
        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html=csv_body)),
        )
        monkeypatch.setattr(
            "src.ingester.CONFIG.ingester",
            type("I", (), {"urlhaus_country_codes": ["SG"]})(),
        )
        _fast_sleep(monkeypatch)

        src_obj = URLhausCountry()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert queue.empty()

    async def test_iterates_over_all_country_codes(self, monkeypatch):
        """One HTTP fetch is issued per configured country code."""
        from src.ingester import URLhausCountry

        fetched_urls: List[str] = []

        async def mock_fetch(url):
            fetched_urls.append(url)
            return make_fetch_result(html="")

        monkeypatch.setattr("src.http_client.HTTPClient.fetch", mock_fetch)
        monkeypatch.setattr(
            "src.ingester.CONFIG.ingester",
            type("I", (), {"urlhaus_country_codes": ["SG", "MY", "TH"]})(),
        )
        _fast_sleep(monkeypatch)

        src_obj = URLhausCountry()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert any("SG" in u for u in fetched_urls)
        assert any("MY" in u for u in fetched_urls)
        assert any("TH" in u for u in fetched_urls)

    async def test_skips_country_with_empty_response(self, monkeypatch):
        """An empty response for a given country code produces no queue entries."""
        from src.ingester import URLhausCountry

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="")),
        )
        monkeypatch.setattr(
            "src.ingester.CONFIG.ingester",
            type("I", (), {"urlhaus_country_codes": ["SG"]})(),
        )
        _fast_sleep(monkeypatch)

        src_obj = URLhausCountry()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert queue.empty()

    async def test_calls_sleep_with_interval(self, monkeypatch):
        """``asyncio.sleep`` is called with the configured interval."""
        from src.ingester import URLhausCountry

        monkeypatch.setattr(
            "src.http_client.HTTPClient.fetch",
            AsyncMock(return_value=make_fetch_result(html="")),
        )
        monkeypatch.setattr(
            "src.ingester.CONFIG.ingester",
            type("I", (), {"urlhaus_country_codes": []})(),
        )
        calls = _fast_sleep(monkeypatch)

        src_obj = URLhausCountry(interval_s=66)
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert 66 in calls

    async def test_no_fetches_when_country_codes_empty(self, monkeypatch):
        """No HTTP fetches are made when ``urlhaus_country_codes`` is empty."""
        from src.ingester import URLhausCountry

        fetched_urls: List[str] = []

        async def mock_fetch(url):
            fetched_urls.append(url)
            return make_fetch_result(html="")

        monkeypatch.setattr("src.http_client.HTTPClient.fetch", mock_fetch)
        monkeypatch.setattr(
            "src.ingester.CONFIG.ingester",
            type("I", (), {"urlhaus_country_codes": []})(),
        )
        _fast_sleep(monkeypatch)

        src_obj = URLhausCountry()
        queue: asyncio.Queue = asyncio.Queue()
        task = asyncio.create_task(src_obj.run(queue))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert fetched_urls == []

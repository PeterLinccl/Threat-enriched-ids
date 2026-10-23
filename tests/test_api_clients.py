"""Offline checks for concurrent API lookups and cache behavior."""

import asyncio
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from src.api_clients import ReputationAPIError, lookup_abuseipdb, lookup_virustotal
from src.cache import ReputationCache
from src.dedup import RecentIPTracker
from src.main import process_alert


class FakeResponse:
    def __init__(self, status, payload, entered=None):
        self.status = status
        self.payload = payload
        self.entered = entered

    async def __aenter__(self):
        if self.entered:
            await self.entered()
        return self

    async def __aexit__(self, *args):
        return False

    async def json(self):
        return self.payload


class FakeSession:
    def __init__(self, abuse=(200, None), vt=(200, None), entered=None):
        self.abuse = abuse
        self.vt = vt
        self.entered = entered
        self.calls = []

    def get(self, url, **kwargs):
        provider = "abuseipdb" if "abuseipdb.com" in url else "virustotal"
        self.calls.append((provider, url, kwargs))
        status, payload = self.abuse if provider == "abuseipdb" else self.vt
        return FakeResponse(status, payload, self.entered)


ABUSE = {"data": {"abuseConfidenceScore": 42, "totalReports": 7}}
VT = {"data": {"attributes": {"last_analysis_stats": {
    "malicious": 2, "suspicious": 1, "harmless": 70, "undetected": 10
}}}}
ALERT = {"src_ip": "1.2.3.4", "dest_ip": "10.0.0.5", "signature": "test"}
KEYS = {"abuseipdb": "test-abuse-key", "virustotal": "test-vt-key"}


class APIClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_provider_requests_and_normalized_results(self):
        session = FakeSession(abuse=(200, ABUSE), vt=(200, VT))
        abuse = await lookup_abuseipdb(session, "1.2.3.4", KEYS["abuseipdb"])
        vt = await lookup_virustotal(session, "1.2.3.4", KEYS["virustotal"])
        self.assertEqual(abuse["abuse_confidence_score"], 42)
        self.assertEqual(vt["malicious"], 2)
        self.assertEqual(session.calls[0][2]["params"]["ipAddress"], "1.2.3.4")
        self.assertEqual(session.calls[0][2]["headers"]["Key"], KEYS["abuseipdb"])
        self.assertEqual(session.calls[1][2]["headers"]["x-apikey"], KEYS["virustotal"])

    async def test_invalid_data_is_not_success(self):
        session = FakeSession(abuse=(200, {"data": {"totalReports": 0}}))
        with self.assertRaises(ReputationAPIError):
            await lookup_abuseipdb(session, "1.2.3.4", "test-key")

    async def test_failure_does_not_block_other_provider_and_can_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = ReputationCache(str(Path(directory) / "cache.sqlite3"))
            tracker = RecentIPTracker()
            failed = FakeSession(abuse=(200, ABUSE), vt=(429, {}))
            try:
                with redirect_stdout(io.StringIO()):
                    await process_alert(ALERT, cache, tracker, failed, KEYS)
                self.assertEqual(cache.get("1.2.3.4", "abuseipdb")["total_reports"], 7)
                self.assertIsNone(cache.get("1.2.3.4", "virustotal"))

                retry = FakeSession(abuse=(200, ABUSE), vt=(200, VT))
                with redirect_stdout(io.StringIO()):
                    await process_alert(ALERT, cache, tracker, retry, KEYS)
                self.assertEqual([call[0] for call in retry.calls], ["virustotal"])
                self.assertEqual(cache.get("1.2.3.4", "virustotal")["malicious"], 2)
            finally:
                cache.close()

    async def test_two_missing_providers_run_concurrently(self):
        both_entered = asyncio.Event()
        count = 0

        async def entered():
            nonlocal count
            count += 1
            if count == 2:
                both_entered.set()
            await both_entered.wait()

        with tempfile.TemporaryDirectory() as directory:
            cache = ReputationCache(str(Path(directory) / "cache.sqlite3"))
            session = FakeSession(abuse=(200, ABUSE), vt=(200, VT), entered=entered)
            try:
                with redirect_stdout(io.StringIO()):
                    await asyncio.wait_for(
                        process_alert(ALERT, cache, RecentIPTracker(), session, KEYS),
                        timeout=1,
                    )
                self.assertEqual(count, 2)
            finally:
                cache.close()


if __name__ == "__main__":
    unittest.main()

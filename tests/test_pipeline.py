import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import AsyncMock, patch

import src.main as app
from src.cache import ReputationCache


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_provider_retries_without_repeating_success(self):
        # Read the two identical alerts already in our test file.
        async def sample_lines(path, from_start):
            lines = Path("tests/dedup_demo.json").read_text(
                encoding="utf-8"
            ).splitlines()
            for line in lines:
                yield line

        with tempfile.TemporaryDirectory() as folder:
            db_path = str(Path(folder) / "cache.sqlite3")

            with (
                patch.object(app, "tail_file", sample_lines),
                patch.object(
                    app,
                    "ReputationCache",
                    side_effect=lambda: ReputationCache(db_path),
                ),
                patch.object(
                    app, "lookup_abuseipdb", new_callable=AsyncMock
                ) as abuse,
                patch.object(
                    app, "lookup_virustotal", new_callable=AsyncMock
                ) as vt,
                patch.dict(
                    os.environ,
                    {
                        "ABUSEIPDB_API_KEY": "TEST_KEY",
                        "VIRUSTOTAL_API_KEY": "TEST_KEY",
                    },
                ),
                patch.object(
                    sys, "argv", ["main", "--from-start"]
                ),
                redirect_stdout(io.StringIO()) as output,
            ):
                abuse.return_value = {
                    "provider": "abuseipdb",
                    "ip": "1.2.3.4",
                    "abuse_confidence_score": 42,
                }
                vt.side_effect = [
                    RuntimeError("simulated failure"),
                    {
                        "provider": "virustotal",
                        "ip": "1.2.3.4",
                        "malicious": 2,
                    },
                ]

                await app.main()

            self.assertEqual(abuse.await_count, 1)
            self.assertEqual(vt.await_count, 2)
            self.assertIn("LOOKUP FAILED", output.getvalue())

            cache = ReputationCache(db_path)
            try:
                self.assertIsNotNone(cache.get("1.2.3.4", "abuseipdb"))
                self.assertIsNotNone(cache.get("1.2.3.4", "virustotal"))
            finally:
                cache.close()


if __name__ == "__main__":
    unittest.main()
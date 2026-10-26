import unittest

from src.api_clients import lookup_abuseipdb, lookup_virustotal

class FakeResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self):
        return {
            "data": {
                "abuseConfidenceScore": 42,
                "totalReports": 7,
            }
        }


class FakeSession:
    def get(self, url, **kwargs):
        assert url == "https://api.abuseipdb.com/api/v2/check"
        assert kwargs["params"]["ipAddress"] == "1.2.3.4"
        assert kwargs["headers"]["Key"] == "TEST_KEY"
        return FakeResponse()
    
class FakeVirusTotalResponse(FakeResponse):
    async def json(self):
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 1,
                        "harmless": 70,
                        "undetected": 10,
                    }
                }
            }
        }


class FakeVirusTotalSession:
    def get(self, url, **kwargs):
        assert url == "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"
        assert kwargs["headers"]["x-apikey"] == "TEST_VT_KEY"
        return FakeVirusTotalResponse()

class APIClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_abuseipdb_response(self):
        result = await lookup_abuseipdb(
            FakeSession(), "1.2.3.4", "TEST_KEY"
        )
        self.assertEqual(result["abuse_confidence_score"], 42)
        self.assertEqual(result["total_reports"], 7)

    async def test_virustotal_response(self):
        result = await lookup_virustotal(
            FakeVirusTotalSession(), "1.2.3.4", "TEST_VT_KEY"
        )
        self.assertEqual(result["malicious"], 2)
        self.assertEqual(result["suspicious"], 1)
    

if __name__ == "__main__":
    unittest.main()
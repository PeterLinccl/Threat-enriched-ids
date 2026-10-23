"""Asynchronous IP reputation lookups for the two external providers."""

import asyncio
from urllib.parse import quote

import aiohttp


class ReputationAPIError(Exception):
    """A provider request failed or returned an unusable response."""

    def __init__(self, provider, reason):
        self.provider = provider
        super().__init__(f"{provider}: {reason}")


async def _get_json(session, provider, url, *, headers, params=None):
    try:
        async with session.get(
            url, headers=headers, params=params, allow_redirects=False
        ) as response:
            if response.status != 200:
                # Do not include response bodies, which may contain sensitive data.
                raise ReputationAPIError(provider, f"HTTP {response.status}")
            try:
                body = await response.json()
            except (ValueError, aiohttp.ContentTypeError) as exc:
                raise ReputationAPIError(provider, "invalid JSON response") from exc
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        raise ReputationAPIError(provider, "network error or timeout") from exc

    if not isinstance(body, dict):
        raise ReputationAPIError(provider, "invalid response shape")
    return body


async def lookup_abuseipdb(session, ip, api_key):
    """Return the AbuseIPDB confidence score and recent report count."""
    provider = "abuseipdb"
    body = await _get_json(
        session,
        provider,
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
    )
    data = body.get("data")
    if not isinstance(data, dict):
        raise ReputationAPIError(provider, "missing data")
    score = data.get("abuseConfidenceScore")
    if type(score) is not int or not 0 <= score <= 100:
        raise ReputationAPIError(provider, "invalid confidence score")
    reports = data.get("totalReports", 0)
    if type(reports) is not int or reports < 0:
        raise ReputationAPIError(provider, "invalid report count")
    return {
        "provider": provider,
        "ip": ip,
        "abuse_confidence_score": score,
        "total_reports": reports,
    }


async def lookup_virustotal(session, ip, api_key):
    """Return VirusTotal's detection counts for an IP address."""
    provider = "virustotal"
    body = await _get_json(
        session,
        provider,
        f"https://www.virustotal.com/api/v3/ip_addresses/{quote(ip, safe='')}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    data = body.get("data")
    attributes = data.get("attributes") if isinstance(data, dict) else None
    stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
    if not isinstance(stats, dict) or not stats:
        raise ReputationAPIError(provider, "missing analysis statistics")
    counts = {}
    for category in ("malicious", "suspicious", "harmless", "undetected"):
        count = stats.get(category, 0)
        if type(count) is not int or count < 0:
            raise ReputationAPIError(provider, f"invalid {category} count")
        counts[category] = count
    return {"provider": provider, "ip": ip, **counts}

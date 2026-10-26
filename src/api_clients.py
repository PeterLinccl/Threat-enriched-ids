import aiohttp
from urllib.parse import quote

async def lookup_abuseipdb(
    session: aiohttp.ClientSession, ip: str, api_key: str
) -> dict:
    """Query AbuseIPDB for one IP address."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    # Wait for the HTTP response without blocking other async tasks.
    async with session.get(url, headers=headers, params=params) as response:
        if response.status != 200:
            raise RuntimeError(f"AbuseIPDB returned HTTP {response.status}")
        payload = await response.json()

    # The reputation information is inside the response's "data" field.
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise ValueError("AbuseIPDB response has no data")

    score = data.get("abuseConfidenceScore")
    if type(score) is not int or not 0 <= score <= 100:
        raise ValueError("AbuseIPDB returned an invalid confidence score")

    return {
        "provider": "abuseipdb",
        "ip": ip,
        "abuse_confidence_score": score,
        "total_reports": data.get("totalReports", 0),
    }
async def lookup_virustotal(
    session: aiohttp.ClientSession, ip: str, api_key: str
) -> dict:
    """Query VirusTotal's report for one IP address."""
    encoded_ip = quote(ip, safe="")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{encoded_ip}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    async with session.get(url, headers=headers) as response:
        if response.status != 200:
            raise RuntimeError(f"VirusTotal returned HTTP {response.status}")
        payload = await response.json()

    data = payload.get("data") if isinstance(payload, dict) else None
    attributes = data.get("attributes") if isinstance(data, dict) else None
    stats = (
        attributes.get("last_analysis_stats")
        if isinstance(attributes, dict)
        else None
    )
    if not isinstance(stats, dict) or not stats:
        raise ValueError("VirusTotal response has no analysis statistics")

    counts = {}
    for category in ("malicious", "suspicious", "harmless", "undetected"):
        count = stats.get(category, 0)
        if type(count) is not int or count < 0:
            raise ValueError(f"Invalid VirusTotal {category} count")
        counts[category] = count

    return {"provider": "virustotal", "ip": ip, **counts}
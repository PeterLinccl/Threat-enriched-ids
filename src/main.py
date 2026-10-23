"""Tail Suricata alerts and enrich public IPs with cached reputation data."""

import argparse
import asyncio
import os

import aiohttp

from .api_clients import lookup_abuseipdb, lookup_virustotal
from .cache import ReputationCache
from .dedup import RecentIPTracker
from .ip_filter import get_public_ip
from .parser import parse_alert, tail_file


LOOKUPS = {
    "abuseipdb": lookup_abuseipdb,
    "virustotal": lookup_virustotal,
}
KEY_VARIABLES = {
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
}


async def process_alert(alert, cache, tracker, session, api_keys, *, dry_run=False):
    """Keep the alert and query only missing IP/provider combinations."""
    print(f"ALERT src={alert['src_ip']} sig={alert['signature']}")

    # An alert may have two public IPs, but never query the same IP twice.
    candidate_ips = []
    for field in ("src_ip", "dest_ip"):
        ip = get_public_ip(alert.get(field))
        if ip and ip not in candidate_ips:
            candidate_ips.append(ip)

    pending = []
    for ip in candidate_ips:
        for provider, lookup in LOOKUPS.items():
            cached = cache.get(ip, provider)
            if cached is not None:
                print(f"  CACHE HIT: {ip} / {provider}")
                continue

            print(f"  CACHE MISS: {ip} / {provider}")
            key = (ip, provider)
            if dry_run:
                if tracker.should_lookup(key):
                    print(f"  NEW lookup needed: {ip} / {provider}")
                else:
                    print(f"  DUPLICATE lookup: {ip} / {provider}")
                continue

            api_key = api_keys.get(provider)
            if not api_key:
                print(f"  SKIPPED (missing {KEY_VARIABLES[provider]}): {ip}")
                continue
            if not tracker.should_lookup(key):
                print(f"  DUPLICATE lookup: {ip} / {provider}")
                continue

            # Run all missing provider requests for this alert concurrently.
            pending.append((ip, provider, lookup(session, ip, api_key)))

    if not pending:
        return
    results = await asyncio.gather(*(job[2] for job in pending), return_exceptions=True)
    for (ip, provider, _), result in zip(pending, results):
        if isinstance(result, BaseException):
            tracker.forget((ip, provider))
            if isinstance(result, asyncio.CancelledError):
                raise result
            print(f"  LOOKUP FAILED: {ip} / {provider} ({result})")
            continue
        cache.put(ip, provider, result)
        print(f"  LOOKUP OK: {ip} / {provider} {result}")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default="tests/sample_eve.json")
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument(
        "--dry-run", action="store_true", help="show lookups without using API keys"
    )
    args = parser.parse_args()

    tracker = RecentIPTracker(window_seconds=60)
    cache = ReputationCache()
    api_keys = {provider: os.environ.get(name) for provider, name in KEY_VARIABLES.items()}

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async for line in tail_file(args.log, args.from_start):
                alert = parse_alert(line)
                if alert:
                    await process_alert(
                        alert, cache, tracker, session, api_keys, dry_run=args.dry_run
                    )
    finally:
        cache.close()


if __name__ == "__main__":
    asyncio.run(main())

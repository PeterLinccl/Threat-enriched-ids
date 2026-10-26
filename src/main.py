import asyncio
import argparse
from dotenv import load_dotenv
from .parser import tail_file, parse_alert
from .ip_filter import get_public_ip
from .dedup import RecentIPTracker
from .cache import ReputationCache

import os
import aiohttp

from .api_clients import lookup_abuseipdb, lookup_virustotal


async def main():
    """Read alerts and check which IP reputation results are available."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default="tests/sample_eve.json")
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    tracker = RecentIPTracker(window_seconds=60)
    cache = ReputationCache()
    providers = ("abuseipdb", "virustotal")
    
    load_dotenv()
    api_keys = {
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
    "virustotal": os.getenv("VIRUSTOTAL_API_KEY"),
    }

    lookup_functions = {
    "abuseipdb": lookup_abuseipdb,
    "virustotal": lookup_virustotal,
    }

    session = aiohttp.ClientSession(
    timeout=aiohttp.ClientTimeout(total=10)
    )

    try:
        async for line in tail_file(args.log, args.from_start):
            alert = parse_alert(line)
            if not alert:
                continue

            # Display every alert, including repeated alerts.
            print(f"ALERT src={alert['src_ip']} sig={alert['signature']}")

            candidate_ips = []
            for field in ("src_ip", "dest_ip"):
                ip = get_public_ip(alert.get(field))
                if ip and ip not in candidate_ips:
                    candidate_ips.append(ip)
            pending = []
            for ip in candidate_ips:
                for provider in providers:
                    result = cache.get(ip, provider)

                    if result is not None:
                        print(f"  CACHE HIT: {ip} / {provider}")
                        continue

                    print(f"  CACHE MISS: {ip} / {provider}")
                    key = (ip, provider)

                    if args.dry_run:
                        if tracker.should_lookup(key):
                            print(f"  NEW lookup needed: {ip} / {provider}")
                        else:
                            print(f"  DUPLICATE lookup: {ip} / {provider}")
                        continue

                    if not api_keys[provider]:
                        print(f"  SKIPPED: missing {provider} API key")
                        continue

                        
                    if not tracker.should_lookup(key):
                        print(f"  DUPLICATE lookup: {ip} / {provider}")
                        continue

                    pending.append(
                        (ip, provider, lookup_functions[provider](
                            session, ip, api_keys[provider]
                        ))
                    )
                    
            if pending:
                results = await asyncio.gather(
                    *(job[2] for job in pending),
                    return_exceptions=True,
                )

                for (ip, provider, _), result in zip(pending, results):
                    if isinstance(result, BaseException):
                        tracker.forget((ip, provider))
                        if isinstance(result, asyncio.CancelledError):
                            raise result
                        print(f"  LOOKUP FAILED: {ip} / {provider} ({result})")
                    else:
                        cache.put(ip, provider, result)
                        print(f"  LOOKUP OK: {ip} / {provider} {result}")
    finally:
        # Close the database when the program stops.
        await session.close()
        cache.close()


if __name__ == "__main__":
    asyncio.run(main())
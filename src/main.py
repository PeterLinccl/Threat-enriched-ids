import asyncio
import argparse

from .parser import tail_file, parse_alert
from .ip_filter import get_public_ip
from .dedup import RecentIPTracker
from .cache import ReputationCache


async def main():
    """Read alerts and check which IP reputation results are available."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default="tests/sample_eve.json")
    parser.add_argument("--from-start", action="store_true")
    args = parser.parse_args()

    tracker = RecentIPTracker(window_seconds=60)
    cache = ReputationCache()
    providers = ("abuseipdb", "virustotal")

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

            for ip in candidate_ips:
                missing_providers = []

                # Cache entries are separate for each IP and provider.
                for provider in providers:
                    result = cache.get(ip, provider)
                    if result is None:
                        print(f"  CACHE MISS: {ip} / {provider}")
                        missing_providers.append(provider)
                    else:
                        print(f"  CACHE HIT: {ip} / {provider}")

                # For now, only report which API lookups would be needed.
                if missing_providers:
                    if tracker.should_lookup(ip):
                        print(f"  NEW lookup needed: {ip} / {missing_providers}")
                    else:
                        print(f"  DUPLICATE lookup: {ip}")

    finally:
        # Close the database when the program stops.
        cache.close()


if __name__ == "__main__":
    asyncio.run(main())
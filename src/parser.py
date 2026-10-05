import asyncio
import json
import os


async def tail_file(path: str, from_start: bool = False):
    """Yield existing or newly appended lines from a log file."""
    f = open(path, "r", encoding="utf-8", errors="ignore")

    # Without --from-start, skip existing content and wait for new lines.
    if not from_start:
        f.seek(0, os.SEEK_END)

    while True:
        line = f.readline()

        if not line:
            # Pause briefly when no new line is available.
            await asyncio.sleep(0.2)
            continue

        # Remove the newline before passing the text to parse_alert().
        yield line.strip()


def parse_alert(line: str):
    """Extract the fields needed from one Suricata alert event."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        # Skip lines that are not valid JSON.
        return None

    # EVE also contains DNS and other event types.
    if event.get("event_type") != "alert":
        return None

    # Missing fields become None rather than stopping the parser.
    return {
        "timestamp": event.get("timestamp"),
        "src_ip": event.get("src_ip"),
        "dest_ip": event.get("dest_ip"),
        "signature": event.get("alert", {}).get("signature"),
        "severity": event.get("alert", {}).get("severity"),
    }
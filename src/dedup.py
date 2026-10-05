import time


class RecentIPTracker:
    """Track IPs seen during a short time window."""

    def __init__(self, window_seconds=60):
        self.window_seconds = window_seconds
        self.last_seen = {}

    def should_lookup(self, ip):
        # Monotonic time measures elapsed time even if the system clock changes.
        now = time.monotonic()
        previous = self.last_seen.get(ip)

        if previous is not None and now - previous < self.window_seconds:
            return False

        # Allow a new lookup after the window expires.
        self.last_seen[ip] = now
        return True
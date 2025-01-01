import asyncio
import aiofiles
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging

logger = logging.getLogger(__name__)

class LogParser:
    """Core log parsing and analysis engine."""
    def __init__(self):
        self.attempts = defaultdict(lambda: defaultdict(deque))
        self.pattern = re.compile(
            r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+.*?(?:sshd|sudo|login)\[.*?\].*?(?:Failed|Invalid)\s+(?:password|user).*?user\s+(\S+).*?(?:from\s+(\S+))?'
        )

    async def parse_line(self, line: str) -> dict | None:
        """Parse a single log line."""
        try:
            match = self.pattern.search(line)
            if not match:
                return None
            timestamp_str, user, ip = match.groups()
            timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            return {"timestamp": timestamp, "user": user, "ip": ip}
        except ValueError as e:
            logger.debug(f"Skipping malformed line: {line.strip()} - {e}")
            return None

    async def process_log(self, file_path: str):
        """Read and process log file asynchronously."""
        try:
            async with aiofiles.open(file_path, mode='r') as file:
                async for line in file:
                    parsed = await self.parse_line(line)
                    if parsed:
                        self.attempts[parsed["user"]][parsed["ip"]].append(parsed["timestamp"])
        except FileNotFoundError:
            logger.error(f"Log file {file_path} not found.")
            raise
        except PermissionError:
            logger.error(f"Permission denied: {file_path}")
            raise
        except Exception as e:
            logger.error(f"Error processing log: {e}")
            raise

    def analyze(self, time_window: int = 10, max_attempts: int = 5) -> list:
        """Analyze login attempts for suspicious patterns."""
        suspicious = []
        for user, ip_data in self.attempts.items():
            for ip, timestamps in ip_data.items():
                timestamps = sorted(timestamps)
                # Brute-force detection
                for i in range(len(timestamps) - max_attempts + 1):
                    if timestamps[i + max_attempts - 1] - timestamps[i] <= timedelta(minutes=time_window):
                        suspicious.append({
                            "user": user,
                            "ip": ip,
                            "type": "brute_force",
                            "attempts": len(timestamps[i:i + max_attempts]),
                            "time_range": f"{timestamps[i]} to {timestamps[i + max_attempts - 1]}"
                        })
                # Suspicious time detection
                for ts in timestamps:
                    if 2 <= ts.hour <= 5:
                        suspicious.append({
                            "user": user,
                            "ip": ip,
                            "type": "unusual_time",
                            "attempts": 1,
                            "time_range": f"{ts}"
                        })
        return suspicious

 
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import asyncio
import logging

logger = logging.getLogger(__name__)

class LogMonitor(FileSystemEventHandler):
    """Monitor log files for real-time changes."""
    def __init__(self, callback):
        self.callback = callback

    def on_modified(self, event):
        if not event.is_directory:
            logger.info(f"Log file changed: {event.src_path}")
            asyncio.run(self.callback(event.src_path))

    def start(self, path: str):
        """Start monitoring a log file."""
        observer = Observer()
        observer.schedule(self, path, recursive=False)
        observer.start()
        logger.info(f"Started monitoring: {path}")
        return observer
"""
Assessment scheduler for Perimtr.

Manages cron-like scheduling for recurring assessments.
Uses the `schedule` library for simplicity.
"""

import logging
import time
import threading
from typing import Callable, Optional

import schedule

logger = logging.getLogger("perimtr")


class Scheduler:
    """Manages recurring assessment scheduling."""

    def __init__(self, frequency: str = "weekly"):
        self.frequency = frequency
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def schedule_task(self, task: Callable, frequency: Optional[str] = None):
        """
        Schedule a task to run at the configured frequency.

        Args:
            task: Callable to execute
            frequency: Override frequency (daily, weekly, monthly)
        """
        freq = frequency or self.frequency

        if freq == "daily":
            schedule.every().day.at("02:00").do(task)
            logger.info("Scheduled daily assessment at 02:00")
        elif freq == "weekly":
            schedule.every().monday.at("02:00").do(task)
            logger.info("Scheduled weekly assessment on Mondays at 02:00")
        elif freq == "monthly":
            # schedule lib doesn't have monthly, so we use daily + check
            schedule.every().day.at("02:00").do(self._monthly_wrapper, task)
            logger.info("Scheduled monthly assessment on the 1st at 02:00")
        else:
            logger.warning(f"Unknown frequency '{freq}', defaulting to weekly")
            schedule.every().monday.at("02:00").do(task)

    def start(self):
        """Start the scheduler in a background thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("Scheduler started")

    def stop(self):
        """Stop the scheduler."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        schedule.clear()
        logger.info("Scheduler stopped")

    def _run_loop(self):
        """Background loop that checks and runs pending tasks."""
        while not self._stop_event.is_set():
            schedule.run_pending()
            time.sleep(60)

    @staticmethod
    def _monthly_wrapper(task: Callable):
        """Only run task on the 1st of the month."""
        from datetime import datetime
        if datetime.now().day == 1:
            task()

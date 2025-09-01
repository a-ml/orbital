"""
Schedules and runs the Orbital agent at regular intervals.
This is the main entry point for the automated, recurring SOC process.
"""
import os
import time
import uuid
import asyncio
import schedule

# Import the core runner logic and the shared logger
from projects.orbital.runner import run_agent_session
from projects.orbital.services import logger

SESSION_ID_BASE = os.getenv("ORBITAL_SESSION_ID_BASE", "scheduled_run_")

def run_scheduled_task():
    """
    A synchronous wrapper that prepares and triggers the async agent runner.
    """
    current_time_str = time.strftime("%Y%m%d_%H%M%S")
    unique_id = str(uuid.uuid4())[:8]
    session_id = f"{SESSION_ID_BASE}{current_time_str}_{unique_id}"
    task_input = "Execute security events analysis"

    logger.info("==================================================")
    logger.info(f"Scheduler triggered. Starting job for session: {session_id}")
    logger.info("==================================================")

    try:
        final_response = asyncio.run(run_agent_session(session_id, task_input))
        logger.info(f"Scheduled job for session '{session_id}' completed successfully.")
        logger.info(f"<<< Agent Final Response: {final_response}")
    except Exception:
        logger.error(f"Unhandled exception in scheduled task for session '{session_id}'", exc_info=True)
    finally:
        logger.info("==================================================")
        logger.info(f"Finished scheduled job for session: {session_id}")
        logger.info("==================================================")

if __name__ == "__main__":
    logger.info("Orbital SOC Scheduler starting up...")

    try:
        interval_env = os.getenv("SCHEDULE_INTERVAL_MINUTES", "5")
        interval = int(interval_env)
        if interval <= 0:
            raise ValueError("Interval must be a positive integer.")
    except (ValueError, TypeError):
        logger.warning(f"Invalid SCHEDULE_INTERVAL_MINUTES ('{interval_env}'). Defaulting to 5 minutes.")
        interval = 5

    schedule.every(interval).minutes.do(run_scheduled_task)
    logger.info(f"Task scheduled to run every {interval} minute(s). Next run at: {schedule.next_run}")

    if os.getenv("RUN_ON_STARTUP", "true").lower() == "true":
        logger.info("RUN_ON_STARTUP is true. Performing initial run...")
        run_scheduled_task()
        logger.info(f"Initial run complete. Next scheduled run at: {schedule.next_run}")

    logger.info("Scheduler is now running. Press Ctrl+C to exit.")
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Scheduler stopped by user.")
    finally:
        logger.info("Orbital SOC Scheduler shutting down.")
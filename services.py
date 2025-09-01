"""Centralized setup for ADK services and logging for the Orbital application."""

import logging
import logging.handlers
import sys
import os

from google.adk.sessions import DatabaseSessionService
from google.adk.artifacts import InMemoryArtifactService
from google.adk.memory import InMemoryMemoryService

# --- Log File Configuration ---
LOG_FILE_PATH = os.getenv("ORBITAL_LOG_FILE", "orbital_soc.log")
LOG_FILE_MAX_BYTES = int(os.getenv("ORBITAL_LOG_MAX_BYTES", 10 * 1024 * 1024)) # 10 MB
LOG_FILE_BACKUP_COUNT = int(os.getenv("ORBITAL_LOG_BACKUP_COUNT", 5))

def setup_logging(logger_name: str) -> logging.Logger:
    """Configures and returns a logger instance."""
    logger = logging.getLogger(logger_name)
    if logger.hasHandlers():
        return logger  # Avoid adding duplicate handlers

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    CONSOLE_LOG_LEVEL_STR = os.getenv("CONSOLE_LOG_LEVEL", "INFO").upper()
    console_handler.setLevel(getattr(logging, CONSOLE_LOG_LEVEL_STR, logging.INFO))
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)-8s - %(name)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_FILE_PATH, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUP_COUNT, encoding='utf-8'
        )
        FILE_LOG_LEVEL_STR = os.getenv("FILE_LOG_LEVEL", "DEBUG").upper()
        file_handler.setLevel(getattr(logging, FILE_LOG_LEVEL_STR, logging.DEBUG))
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)-8s - %(name)s - %(module)s.%(funcName)s:%(lineno)d - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        logger.info(f"Logging configured. Console Level: {CONSOLE_LOG_LEVEL_STR}, File Level: {FILE_LOG_LEVEL_STR} at '{LOG_FILE_PATH}'")
    except Exception as e:
        logger.error(f"Failed to set up file logging: {e}. Logging to console only.", exc_info=True)

    return logger

# --- Initialize Logger ---
logger = setup_logging("OrbitalSOC")

# --- Initialize Global Services ---
try:
    # Use InMemory for simplicity, can be swapped with a persistent one
    memory_service = InMemoryMemoryService()
    logger.info("Initialized InMemoryMemoryService.")

    db_url = os.getenv("ORBITAL_DATABASE_URL", "sqlite:///./orbital_soc_data.db")
    if not db_url:
        raise ValueError("ORBITAL_DATABASE_URL is not set or empty.")
    session_service = DatabaseSessionService(db_url=db_url)
    logger.info(f"Initialized DatabaseSessionService with db_url.")

    artifact_service = InMemoryArtifactService()
    logger.info("Initialized InMemoryArtifactService.")

except Exception as e:
    logger.critical(f"Failed to initialize critical ADK services: {e}", exc_info=True)
    sys.exit(1)
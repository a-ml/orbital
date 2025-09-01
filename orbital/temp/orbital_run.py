import asyncio
import logging
import logging.handlers
import sys
import os
# import warnings
import time
import schedule
import uuid

# --- ADK and Google GenAI Imports ---
try:
    from google.adk.sessions import InMemorySessionService, DatabaseSessionService
    from google.adk.artifacts import InMemoryArtifactService
    from google.adk.memory import InMemoryMemoryService
    from google.adk.runners import Runner
    from google.adk.tools import load_memory
    from google.genai import types as GoogleGenAiTypes
except ModuleNotFoundError as e:
    dep_name = str(e).split("'")[-2]
    print(
        f"CRITICAL ERROR: Failed to import '{dep_name}'. Ensure Google ADK and dependencies are installed. "
        "Run: pip install google-adk google-generativeai schedule",
        file=sys.stderr
    )
    sys.exit(1)
except ImportError as e:
    print(f"CRITICAL ERROR: Unexpected import error for ADK/GenAI: {e}", file=sys.stderr)
    sys.exit(1)

# --- Orbital Agent Import ---
try:
    from orbital.agent import soc_manager_agent as main_orbital_agent
except ModuleNotFoundError as e:
    print(
        f"CRITICAL ERROR: Failed to import 'soc_manager_agent' from 'orbital.agent'. "
        f"Check path and package structure. Original error: {e}",
        file=sys.stderr
    )
    sys.exit(1)
except ImportError as e:
    print(f"CRITICAL ERROR: Error importing main agent: {e}", file=sys.stderr)
    sys.exit(1)


# --- Logging and Warnings Configuration ---
# warnings.filterwarnings("ignore")

# --- Log File Configuration ---
LOG_FILE_PATH = os.getenv("ORBITAL_LOG_FILE", "orbital_soc_scheduler.log")
LOG_FILE_MAX_BYTES = int(os.getenv("ORBITAL_LOG_MAX_BYTES", 10 * 1024 * 1024)) # 10 MB
LOG_FILE_BACKUP_COUNT = int(os.getenv("ORBITAL_LOG_BACKUP_COUNT", 5))

# Configure our script's logger
script_logger = logging.getLogger("OrbitalSOCScheduler")
script_logger.setLevel(logging.DEBUG)  # Process all messages from this level upwards
script_logger.propagate = False # Prevent messages from being passed to the root logger's handlers

# Create a console handler (logs to stderr)
console_log_handler = logging.StreamHandler(sys.stderr)
# Set console log level (e.g., INFO for less verbosity on console)
CONSOLE_LOG_LEVEL_STR = os.getenv("CONSOLE_LOG_LEVEL", "INFO").upper()
console_log_level = getattr(logging, CONSOLE_LOG_LEVEL_STR, logging.INFO)
console_log_handler.setLevel(console_log_level)

# Create a formatter and set it for the console handler
console_log_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)-8s - %(name)s - %(message)s', # Adjusted for alignment
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_log_handler.setFormatter(console_log_formatter)
script_logger.addHandler(console_log_handler)

# Create a rotating file handler
try:
    file_log_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE_PATH,
        maxBytes=LOG_FILE_MAX_BYTES,
        backupCount=LOG_FILE_BACKUP_COUNT,
        encoding='utf-8' # Good practice to specify encoding
    )
    # Set file log level (e.g., DEBUG to capture all details in the file)
    FILE_LOG_LEVEL_STR = os.getenv("FILE_LOG_LEVEL", "DEBUG").upper()
    file_log_level = getattr(logging, FILE_LOG_LEVEL_STR, logging.DEBUG)
    file_log_handler.setLevel(file_log_level)

    # Create a more detailed formatter for the file
    file_log_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)-8s - %(name)s - %(module)s.%(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_log_handler.setFormatter(file_log_formatter)
    script_logger.addHandler(file_log_handler)
    script_logger.info(f"Logging to console (level: {CONSOLE_LOG_LEVEL_STR}) and file (level: {FILE_LOG_LEVEL_STR}, path: '{LOG_FILE_PATH}')")
except Exception as e:
    # If file logging setup fails, log to console and continue
    script_logger.error(f"Failed to set up file logging to '{LOG_FILE_PATH}': {e}. Logging to console only.", exc_info=True)


# Optionally, reduce verbosity of other loggers if they are too noisy
# These will also be affected by the root logger's level if not specifically configured.
# It's better to configure them directly if you want fine-grained control.
logging.getLogger("google.adk").setLevel(logging.WARNING)
logging.getLogger("schedule").setLevel(logging.INFO) # 'schedule' logs job runs at INFO
logging.getLogger("httpx").setLevel(logging.WARNING) # httpx can be very verbose at DEBUG
logging.getLogger("httpcore").setLevel(logging.WARNING) # httpcore can be very verbose at DEBUG


# --- Constants for Session Management ---
APP_NAME = "orbital_soc_app"
USER_ID = os.getenv("ORBITAL_USER_ID", "soar_sa")
SESSION_ID_BASE = os.getenv("ORBITAL_SESSION_ID_BASE", "scheduled_run_")

# --- Database URL Configuration ---
try:
    db_url = os.getenv("ORBITAL_DATABASE_URL", "sqlite:///./orbital_soc_data.db")
    if not db_url:
        raise ValueError("ORBITAL_DATABASE_URL environment variable is not set or is empty.")
except ValueError as e:
    # Ensure this critical error is logged if logger is available, and printed if not
    script_logger.error(f"Failed to retrieve ORBITAL_DATABASE_URL: {e}", exc_info=True)
    print(f"CRITICAL ERROR: {e}. ORBITAL_DATABASE_URL must be set.", file=sys.stderr)
    sys.exit(1)

# --- Global Services ---
memory_service = InMemoryMemoryService()
script_logger.info("Initialized InMemoryMemoryService for the application lifetime.")

session_service = DatabaseSessionService(db_url=db_url)
script_logger.info(f"Initialized DatabaseSessionService with db_url for the application lifetime.")

artifact_service = InMemoryArtifactService()
script_logger.info("Initialized InMemoryArtifactService for the application lifetime.")



async def run_agent_with_predefined_input(run_session_id: str):
    """
    Sets up ADK session, runner, and executes the main_orbital_agent
    with a predefined input, iterating through all events.
    Adds the completed session to memory.
    Raises exceptions on critical setup failures.
    """
    predefined_task_input = "Execute security events analysis"
    # Using time.time() makes it easier for log correlation if needed
    current_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    script_logger.info(f"==================================================")
    script_logger.info(f"Starting scheduled SOAR task at {current_timestamp}")
    script_logger.info(f"==================================================")
    script_logger.info(f"Scheduler job triggered. Running agent task with Session ID: {run_session_id}")
    script_logger.info(f"Starting Orbital agent task (Session: {run_session_id}): '{predefined_task_input}'")

    try:
        await session_service.create_session(
            app_name=APP_NAME,
            user_id=USER_ID,
            session_id=run_session_id
        )
        script_logger.debug(f"Session '{run_session_id}' created successfully.")
    except Exception as e:
        script_logger.error(f"Failed to initialize or create session (ID: {run_session_id})", exc_info=True)
        raise

    try:
        runner = Runner(
            agent=main_orbital_agent,
            app_name=APP_NAME,
            session_service=session_service,
            memory_service=memory_service,
            artifact_service=artifact_service
        )
        agent_name = main_orbital_agent.name if hasattr(main_orbital_agent, 'name') else 'soc_manager_agent'
        script_logger.debug(f"ADK Runner created for agent '{agent_name}' with memory service.")
    except Exception as e:
        script_logger.error(f"Failed to create ADK Runner (Session: {run_session_id})", exc_info=True)
        raise

    try:
        content = GoogleGenAiTypes.Content(role='user', parts=[GoogleGenAiTypes.Part(text=predefined_task_input)])
    except Exception as e:
        script_logger.error(f"Failed to create GoogleGenAiTypes.Content (Session: {run_session_id})", exc_info=True)
        raise

    final_response_text = "Agent task initiated, but no textual response was generated."
    last_model_content_event = None

    script_logger.info(f"Executing runner.run_async for User='{USER_ID}', Session='{run_session_id}'...")
    try:
        event_count = 0
        async for event in runner.run_async(user_id=USER_ID, session_id=run_session_id, new_message=content):
            event_count += 1
            event_details_parts = [
                f"Author: {event.author}",
                f"Type: {type(event).__name__}",
                f"Final: {event.is_final_response()}"
            ]
            if event.content:
                 event_details_parts.append(f"Content Role: {event.content.role if event.content.role else 'N/A'}")
                 content_parts_repr = repr(event.content.parts)
                 if len(content_parts_repr) > 200:
                     content_parts_repr = content_parts_repr[:200] + "..."
                 event_details_parts.append(f"Content Parts: {content_parts_repr}")
            if event.actions:
                 actions_repr = repr(event.actions)
                 if len(actions_repr) > 200:
                     actions_repr = actions_repr[:200] + "..."
                 event_details_parts.append(f"Actions: {actions_repr}")
            if hasattr(event, 'get_function_calls') and event.get_function_calls():
                event_details_parts.append(f"FunctionCalls: {repr(event.get_function_calls())}")
            if hasattr(event, 'get_function_responses') and event.get_function_responses():
                event_details_parts.append(f"FunctionResponses: {repr(event.get_function_responses())}")
            if event.error_message:
                 event_details_parts.append(f"Error: {repr(event.error_message)}")

            script_logger.debug(f"  [Event {event_count} Session: {run_session_id}] {', '.join(event_details_parts)}")

            if event.content and event.content.role == 'model' and event.content.parts:
                 if event.content.parts[0].text: # Check for text attribute
                     last_model_content_event = event
                     script_logger.debug(f"    --> Captured latest model content from Event {event_count} (Author: {event.author}, Role: {event.content.role})")

        script_logger.info(f"Finished processing {event_count} events for Session: {run_session_id}")

        if last_model_content_event:
            if last_model_content_event.content and \
               last_model_content_event.content.parts and \
               hasattr(last_model_content_event.content.parts[0], 'text') and \
               last_model_content_event.content.parts[0].text:
                final_response_text = last_model_content_event.content.parts[0].text
                script_logger.info(f"Found final textual response from the last model content event.")
            elif last_model_content_event.actions and \
                 hasattr(last_model_content_event.actions, 'escalate') and \
                 last_model_content_event.actions.escalate is not None:
                escalation_msg = last_model_content_event.actions.escalate
                if not isinstance(escalation_msg, str) and hasattr(last_model_content_event, 'error_message'):
                    escalation_msg = last_model_content_event.error_message
                final_response_text = f"Agent ended with escalation: {escalation_msg or 'No specific message.'}"
                script_logger.warning(f"(Session: {run_session_id}) {final_response_text}")
        elif event_count > 0 and final_response_text == "Agent task initiated, but no textual response was generated.":
            final_response_text = "Agent processed events but did not produce a standard textual final response."
            script_logger.warning(f"(Session: {run_session_id}) {final_response_text}")

    except Exception as e:
        script_logger.error(f"An error occurred during agent execution (Session: {run_session_id})", exc_info=True)
        final_response_text = f"Error during agent execution: {e}"
    finally:
        try:
            script_logger.info(f"Attempting to add session '{run_session_id}' to memory.")
            completed_session = await session_service.get_session(
                app_name=APP_NAME,
                user_id=USER_ID,
                session_id=run_session_id
            )
            if completed_session:
                await memory_service.add_session_to_memory(completed_session)
                script_logger.info(f"Session '{run_session_id}' successfully added to memory.")
            else:
                script_logger.warning(f"Could not retrieve session '{run_session_id}' to add to memory (get_session returned None).")
        except Exception as e:
            script_logger.error(f"Failed to add session '{run_session_id}' to memory", exc_info=True)

    script_logger.info(f"==================================================")
    script_logger.info(f"<<< Agent Final Response (Session: {run_session_id})")
    script_logger.info(f"==================================================")

    indented_final_response = "    " + final_response_text.replace('\n', '\n    ')
    print(f"AGENT_RESPONSE_START", file=sys.stdout)
    print(f"  Session: {run_session_id}", file=sys.stdout)
    print(f"  Response:\n{indented_final_response}", file=sys.stdout)
    print(f"AGENT_RESPONSE_END", file=sys.stdout)
    
    script_logger.info(f"Agent task processing complete for Session: {run_session_id}.")
    return final_response_text


def run_soc_manager_task_job():
    """
    Synchronous wrapper for the async agent task, suitable for the scheduler.
    """
    current_time_str = time.strftime("%Y%m%d_%H%M%S")
    unique_id = str(uuid.uuid4())[:8]
    run_specific_session_id = f"{SESSION_ID_BASE}{current_time_str}_{unique_id}" # Swapped order for better sorting

    try:
        asyncio.run(run_agent_with_predefined_input(run_specific_session_id))
        script_logger.info(f"Successfully completed scheduled job for session {run_specific_session_id}.")
    except Exception as e:
        # Log the full exception details
        script_logger.error(f"Unhandled error during agent task execution for session {run_specific_session_id}", exc_info=True)
        # Output a structured error to stdout as well
        error_type = type(e).__name__
        indented_error_message = f"    Agent task failed to complete for session {run_specific_session_id} due to: {error_type}: {e}".replace('\n', '\n    ')
        print(f"AGENT_RESPONSE_START", file=sys.stdout)
        print(f"  Session: {run_specific_session_id}", file=sys.stdout)
        print(f"  CRITICAL_ERROR:\n{indented_error_message}", file=sys.stdout)
        print(f"AGENT_RESPONSE_END", file=sys.stdout)
        script_logger.info(f"Scheduled job failed for session {run_specific_session_id}.")


if __name__ == "__main__":
    # The script_logger is configured above this point
    script_logger.info("Orbital SOC Scheduler starting up...")

    try:
        schedule_interval_env = os.getenv("SCHEDULE_INTERVAL_MINUTES", "5")
        SCHEDULE_INTERVAL_MINUTES = int(schedule_interval_env)
        if SCHEDULE_INTERVAL_MINUTES <= 0:
             raise ValueError("Interval must be positive.")
    except ValueError:
        script_logger.warning(f"Invalid or non-positive SCHEDULE_INTERVAL_MINUTES ('{schedule_interval_env}'). Defaulting to 5 minutes.")
        SCHEDULE_INTERVAL_MINUTES = 5

    schedule.every(SCHEDULE_INTERVAL_MINUTES).minutes.do(run_soc_manager_task_job)
    next_run_time = schedule.next_run()
    script_logger.info(f"SOC Manager task scheduled to run every {SCHEDULE_INTERVAL_MINUTES} minute(s). Next run: {next_run_time.strftime('%Y-%m-%d %H:%M:%S') if next_run_time else 'N/A'}")

    if os.getenv("RUN_ON_STARTUP", "true").lower() == "true":
         script_logger.info("Performing an initial run on startup...")
         run_soc_manager_task_job()
         next_run_time = schedule.next_run()
         script_logger.info(f"Initial run complete. Next scheduled run: {next_run_time.strftime('%Y-%m-%d %H:%M:%S') if next_run_time else 'N/A'}")

    script_logger.info("Scheduler running. Press Ctrl+C to exit.")
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        script_logger.info("Scheduler stopped by user.")
    except Exception as e: 
        script_logger.error(f"Scheduler encountered an unhandled exception", exc_info=True)
    finally:
        script_logger.info("Orbital SOC Scheduler shutting down.")
        logging.shutdown() 
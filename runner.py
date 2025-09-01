"""
Defines the core execution logic for running the Orbital agent for a single session.
"""
import asyncio
from google.adk.runners import Runner
from google.genai import types as GoogleGenAiTypes

from projects.orbital.services import logger, session_service, memory_service, artifact_service
from projects.orbital.orbital.agent import root_agent as main_orbital_agent

APP_NAME = "orbital_soc_app"
USER_ID = "soar_sa"

async def run_agent_session(session_id: str, task_input: str) -> str:
    """
    Initializes and runs the Orbital agent for a single, complete session,
    and then saves the completed session to memory.
    """
    logger.info(f"Starting Orbital agent task for Session ID: {session_id}")
    final_response = "Agent task initiated, but no final textual response was captured."

    try:
        await session_service.create_session(
            app_name=APP_NAME, user_id=USER_ID, session_id=session_id
        )

        runner = Runner(
            agent=main_orbital_agent,
            app_name=APP_NAME,
            session_service=session_service,
            memory_service=memory_service,  # Ensure memory service is passed
            artifact_service=artifact_service,
        )

        content = GoogleGenAiTypes.Content(role='user', parts=[GoogleGenAiTypes.Part(text=task_input)])

        last_model_content_event = None
        async for event in runner.run_async(user_id=USER_ID, session_id=session_id, new_message=content):
            logger.debug(f"[Event Session: {session_id}] Author: {event.author}, Type: {type(event).__name__}")
            if event.content and event.content.role == 'model':
                last_model_content_event = event

        if last_model_content_event and last_model_content_event.content.parts[0].text:
            final_response = last_model_content_event.content.parts[0].text
            logger.info(f"Agent session '{session_id}' completed with a final response.")
        else:
            logger.warning(f"Agent session '{session_id}' completed, but no final textual response was found.")

    except Exception as e:
        logger.error(f"An error occurred during agent execution for session '{session_id}'", exc_info=True)
        final_response = f"Critical error during agent execution for session {session_id}."

    finally:
        # === THIS IS THE CORRECT IMPLEMENTATION ===
        # After the session run (even if it fails), try to get the session
        # transcript and add it to memory.
        try:
            logger.info(f"Attempting to add session '{session_id}' to memory.")
            completed_session = await session_service.get_session(
                app_name=APP_NAME, user_id=USER_ID, session_id=session_id
            )
            if completed_session:
                await memory_service.add_session_to_memory(completed_session)
                logger.info(f"Session '{session_id}' successfully added to memory.")
            else:
                logger.warning(f"Could not retrieve session '{session_id}' to add to memory.")
        except Exception as e:
            logger.error(f"Failed to add session '{session_id}' to memory.", exc_info=True)
        # ==========================================

    return final_response

if __name__ == "__main__":
    # This allows for manual, one-off test runs of the agent.
    import uuid
    test_session_id = f"manual_run_{str(uuid.uuid4())[:8]}"
    test_task = "Execute security events analysis"
    logger.info(f"--- Running a single manual test with Session ID: {test_session_id} ---")
    result = asyncio.run(run_agent_session(session_id=test_session_id, task_input=test_task))
    logger.info(f"--- Manual Test Complete ---")
    print("\n--- AGENT FINAL RESPONSE ---")
    print(result)
    print("--------------------------")
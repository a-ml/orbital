# --- START: Python Path Hotfix ---
import sys
import os
import json

# Get the absolute path of the directory containing this script (evals/)
script_dir = os.path.dirname(os.path.abspath(__file__))
# Get the path of the parent directory of evals/ (orbital/)
project_dir = os.path.dirname(script_dir)
# Get the path of the parent directory of orbital/ (projects/)
# Note: You need to go up two levels from `evals` to get to the root `_ai` directory
# that contains `projects`
project_root = os.path.dirname(os.path.dirname(project_dir))

# Add the project root to the Python path
if project_root not in sys.path:
    sys.path.insert(0, project_root)
# ---  END: Python Path Hotfix  ---

import asyncio
from unittest.mock import patch

from inspect_ai import Task, task
from inspect_ai.dataset import Sample, json_dataset
# --- CORRECTED IMPORT ---
# Import the 'match' scorer directly, not 'score'.
from inspect_ai.scorer import match
from inspect_ai.solver import Solver, solver, TaskState
from inspect_ai.model import Model, get_model

# Now, use the absolute imports that you originally had. They will work
# because the project root is now in sys.path.
from projects.orbital.runner import run_agent_session
from projects.orbital.services import logger

# Disable the logger for clean eval output, inspect has its own logging.
logger.setLevel("CRITICAL")

# --- HELPER FUNCTION (Correct) ---
def alert_to_sample(record: dict) -> Sample:
    """ Maps a record from our dataset to an inspect-ai Sample. """
    return Sample(
        input=json.dumps(record["alert_data"]),
        metadata=record["expected_outcome"],
        id=record["alert_data"].get("alert_id", None)
    )

# --- SOLVER 1: RUN THE ORBITAL AGENT (Correct) ---
@solver
def run_orbital_agent() -> Solver:
    """ An Inspect solver that executes the full Orbital agent workflow. """
    async def solve(state: TaskState, model: Model) -> TaskState:
        mock_alert_data = json.loads(state.input)
        with patch("projects.orbital.orbital.tools.get_alert_details_thehive.thehive_alerts") as mock_thehive:
            mock_thehive.return_value = [mock_alert_data]
            session_id = f"eval_run_{state.sample_id}"
            initial_prompt = "Execute security events analysis"
            try:
                final_response = await run_agent_session(session_id, initial_prompt)
                state.completion = final_response
            except Exception as e:
                state.completion = f"Agent execution failed: {str(e)}"
        return state
    return solve

# --- SOLVER 2: GRADE THE AGENT'S RESPONSE (Correct) ---
@solver
def grade_agent_response() -> Solver:
    """ An Inspect solver that acts as an LLM judge. """
    judge_model = get_model("google/gemini-1.5-flash")
    judge_prompt = """
    You are an expert SOC Manager evaluating the final report from an AI agent.
    Based on the target criteria, determine if the agent's final response is correct.

    The response is correct if it:
    1. Correctly identifies the disposition (True Positive, False Positive, or Benign).
    2. Recommends the appropriate actions.
    3. Identifies the correct threat actor or provides an appropriate summary.

    TARGET CRITERIA (from metadata):
    - Expected Disposition: ${state.metadata.disposition}
    - Expected Actor/Summary: ${state.metadata.get('actor') or state.metadata.get('summary', 'N/A')}
    - Expected Actions: ${state.metadata.actions}

    AGENT'S FULL RESPONSE:
    ${state.completion}

    CRITICAL EVALUATION: Based on all the above, is the agent's response correct?
    Answer with only the single word: CORRECT or INCORRECT.
    """
    async def solve(state: TaskState, model: Model) -> TaskState:
        response = await judge_model.generate(
            prompt=judge_prompt,
            state=state
        )
        state.completion = response.text.strip().upper()
        return state
    return solve

# --- MAIN EVALUATION TASK ---
@task
def orbital_e2e_eval():
    """ Main evaluation task for the Orbital agent. """
    return Task(
        dataset=json_dataset(
            "dataset.jsonl",
            sample_fields=alert_to_sample
        ),
        plan=[
            run_orbital_agent(),
            grade_agent_response()
        ],
        # --- CORRECTED SCORER ---
        # Use the 'match' scorer to check for an exact string match.
        scorer=match("CORRECT")
    )
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
    return Sample(
        input=json.dumps(record["alert_data"]),
        metadata=record["expected_outcome"],
        id=record["alert_data"].get("alert_id")
    )

# --- SOLVER 1: RUN THE ORBITAL AGENT (Correct) ---
@solver
def run_orbital_agent() -> Solver:
    async def solve(state: TaskState, model: Model) -> TaskState:
        mock_alert_data = json.loads(state.input)
        patch_path = "projects.orbital.orbital.sub_agents.alert_ingestor_enricher.agent.get_alert_details_thehive.thehive_alerts"
        with patch(patch_path) as mock_thehive:
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

# --- SOLVER 2: GRADE THE AGENT'S RESPONSE (Corrected Structure) ---
# @solver
# def grade_agent_response() -> Solver:
#     """
#     An Inspect solver that acts as an LLM judge.
#     This function correctly returns an async 'solve' function.
#     """
#     async def solve(state: TaskState, model: Model) -> TaskState:
#         # Define the judge model inside the solve function
#         judge_model = get_model("google/gemini-1.5-flash")

#         # Manually format the prompt using the state's data
#         judge_prompt = f"""
#         You are an expert SOC Manager evaluating the final report from an AI agent.
#         Based on the target criteria, determine if the agent's final response is correct.

#         TARGET CRITERIA (from metadata):
#         - Expected Disposition: {state.metadata.get('disposition', 'N/A')}
#         - Expected Actor/Summary: {state.metadata.get('actor') or state.metadata.get('summary', 'N/A')}
#         - Expected Actions: {state.metadata.get('actions', [])}

#         AGENT'S FULL RESPONSE:
#         {state.completion}

#         CRITICAL EVALUATION: Based on all the above, is the agent's response correct?
#         Answer with only the single word: CORRECT or INCORRECT.
#         """

#         # Call the judge model with the formatted prompt as the input
#         response = await judge_model.generate(input=judge_prompt)

#         # Overwrite 'completion' with the simple grade for the scorer to check
#         state.completion = response.completion.strip().upper()
#         return state

#     # The @solver decorated function MUST return the async 'solve' function
#     return solve
@solver
def grade_agent_response() -> Solver:
    """ An Inspect solver that acts as an LLM judge. """
    async def solve(state: TaskState, model: Model) -> TaskState:
        judge_model = get_model("google/gemini-1.5-flash")

        judge_prompt = f"""
        You are an expert SOC Manager evaluating the final report from an AI agent.
        Your evaluation must be strict.

        AGENT'S FULL RESPONSE:
        {state.completion}

        TARGET CRITERIA (from metadata):
        - Expected Disposition: {state.metadata.get('disposition', 'N/A')}
        - Expected Actor/Summary: {state.metadata.get('actor') or state.metadata.get('summary', 'N/A')}
        - Expected Actions: {state.metadata.get('actions', [])}

        CRITICAL EVALUATION:
        1. First, check if the agent's response contains a specific analysis of the alert. If the response is generic, like "No alerts to process" or "Task complete", it has failed.
        2. If the analysis is present, compare it to the TARGET CRITERIA. The disposition must be semantically correct, and the recommended actions must be appropriate.

        Based on this strict evaluation, is the agent's response correct?
        Answer with only the single word: CORRECT or INCORRECT.
        """

        response = await judge_model.generate(input=judge_prompt)
        state.completion = response.completion.strip().upper()
        return state
    return solve

# --- MAIN EVALUATION TASK ---
@task
def orbital_e_eval():
    """ Main evaluation task for the Orbital agent. """
    return Task(
        dataset=json_dataset(
            "dataset_extended.jsonl",
            sample_fields=alert_to_sample
        ),
        plan=[
            run_orbital_agent(),
            grade_agent_response()
        ],
        scorer=match("CORRECT")
    )
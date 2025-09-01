"""Defines Senior SOC Analyst agent."""

from google.adk.agents.llm_agent import Agent
from google.adk.tools import google_search

from ...shared_libraries import constants
from . import prompt

web_search_agent = Agent(
    model=constants.WEB_SEARCH_MODEL,
    name="web_search_agent",
    description=prompt.DESCRIPTION_WEB_SEARCH_ANALYST,
    instruction=prompt.INSTRUCTIONS_WEB_SEARCH_ANALYST,
    tools=[google_search],
    output_key="web_search_results",
)
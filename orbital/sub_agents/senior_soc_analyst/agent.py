"""Defines Senior SOC Analyst agent."""

from google.adk.agents.llm_agent import Agent

from ...shared_libraries import constants

from . import prompt

senior_soc_analyst_agent = Agent(
    model=constants.MODEL,
    name="senior_soc_analyst_agent",
    description=prompt.DESCRIPTION_SENIOR_SOC_ANALYST,
    instruction=prompt.INSTRUCTIONS_SENIOR_SOC_ANALYST,
    output_key="reviewed_alerts",
)
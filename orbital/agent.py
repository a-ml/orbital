"""Defines SOC Manager Agent"""

from google.adk.agents import SequentialAgent, Agent
#from google.adk.tools import agent_tool
from google.adk.tools import load_memory
from .shared_libraries import constants

from .sub_agents.alert_ingestor_enricher.agent import alert_ingestor_enricher_agent
from .sub_agents.senior_soc_analyst.agent import senior_soc_analyst_agent
from .sub_agents.threat_intelligence_analyst.agent import threat_intelligence_analyst_agent

#from .tools.save_memory import save_incident_summary

from datetime import date

today_date = date.today().strftime("%d-%m-%Y")

from . import prompt


soc_manager_agent = Agent(
    model=constants.MODEL,
    name=constants.AGENT_NAME,
    description=prompt.DESCRIPTION_SOC_MANAGER,
    instruction=prompt.INSTRUCTIONS_SOC_MANAGER,
    global_instruction=constants.GLOBAL_DESCRIPTION,
    sub_agents=[
        alert_ingestor_enricher_agent,
        threat_intelligence_analyst_agent,
        senior_soc_analyst_agent,
    ],
    tools=[
        load_memory,
    ],
)
root_agent = soc_manager_agent
# """Defines Senior SOC Analyst agent."""

# from google.adk.agents.llm_agent import Agent
# from google.adk.tools import agent_tool
# # from langchain_community.tools import DuckDuckGoSearchRun

# from ..web_search.agent import web_search_agent
# from ...shared_libraries import constants
# from ...tools import verify_abusedb, iplookup, url_analysis, hash_verify_vt
# from . import prompt

# # web_search_tool = DuckDuckGoSearchRun()

# threat_intelligence_analyst_agent = Agent(
#     model=constants.MODEL,
#     name="threat_intelligence_analyst_agent",
#     description=prompt.DESCRIPTION_THREAT_INTELLIGENCE_ANALYST,
#     instruction=prompt.INSTRUCTIONS_THREAT_INTELLIGENCE_ANALYST,
#     #sub_agents=[web_search_agent],
#     tools=[agent_tool.AgentTool(agent=web_search_agent),
#         verify_abusedb.check_abuse_ip,
#         iplookup.get_ip_info,
#         hash_verify_vt.check_file_reputation,
#         #url_analysis.is_url_malicious
#     ],
#     output_key="enriched_alerts",
# )
"""Defines Threat Intelligence Analyst agent."""

from google.adk.agents.llm_agent import Agent
from google.adk.tools import agent_tool

from ..web_search.agent import web_search_agent
from ...shared_libraries import constants
from . import prompt

threat_intelligence_analyst_agent = Agent(
    model=constants.MODEL,
    name="threat_intelligence_analyst_agent",
    description=prompt.DESCRIPTION_THREAT_INTELLIGENCE_ANALYST,
    instruction=prompt.INSTRUCTIONS_THREAT_INTELLIGENCE_ANALYST,
    tools=[
        agent_tool.AgentTool(agent=web_search_agent),
    ],
    output_key="enriched_alerts",
)
"""Defines Senior SOC Analyst agent."""

from google.adk.agents.llm_agent import Agent


from ...shared_libraries import constants
from ...tools import get_alert_details_thehive, verify_abusedb, iplookup, url_analysis, hash_verify_vt, internal_asset_identifier
from . import prompt

ipaddress_identifier_tool = internal_asset_identifier.InternalAssetIdentifier()

alert_ingestor_enricher_agent = Agent(
    model=constants.MODEL,
    name="alert_ingestor_enricher_agent",
    description=prompt.DESCRIPTION_ALERT_INGESTOR_ENRICHER,
    instruction=prompt.INSTRUCTIONS_ALERT_INGESTOR_ENRICHER_ITERATIVE,
    tools=[
        get_alert_details_thehive.thehive_alerts,
        verify_abusedb.check_abuse_ip,
        iplookup.get_ip_info,
        hash_verify_vt.check_file_reputation,
        ipaddress_identifier_tool._is_internal_ip_,
        url_analysis.is_url_malicious
    ],
    output_key="ingested_and_enriched_alerts",
)
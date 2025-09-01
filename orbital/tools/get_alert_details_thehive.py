from google.adk.tools import ToolContext
import os
import json
import requests
import logging
import configparser
from textwrap import dedent
from datetime import datetime
from random import randint
from typing import Union, List, Tuple, Dict

# Custom help function to connect to TheHive platform and grab the events.
def thehive_alerts():
    """
    Retrieves security alerts from TheHive5 Case management platform.

    For Agents:
    - Use this tool to retrieve security alerts when you need to analyze or monitor security incidents
    - No input parameters are required
    - Alerts are automatically filtered for Medium(2), High(3), and Critical(4) severities
    - Only 'New' status alerts are returned
    - Results are limited to 15 most recent alerts per severity level

    Configuration Requirements:
        Requires a config.ini file in the same directory with:
        [DEFAULT]
        thehive_url = your_thehive_url_here
        thehive_api_key = your_api_key_here

    Returns:
        str: JSON string containing list of alerts with the following structure:
        [
            {
                "severity": int,        # 2 (Medium), 3 (High), 4 (Critical)
                "status": "New",
                "title": str,          # Alert title
                "date": int,           # Timestamp
                "importDate": str,     # Date when alert was imported
                "caseNumber": str      # Associated case number if any
                ...
            },
            ...
        ]
        Returns None if configuration is missing or connection fails.

    Raises:
        ValueError: If an invalid severity level is provided
        requests.exceptions.HTTPError: If the API request fails
        requests.exceptions.Timeout: If the request times out
        requests.exceptions.RequestException: For other request-related errors

    Example Usage:
        alerts = thehive_alerts()
        if alerts:
            alert_data = json.loads(alerts)
            # Process alert_data as needed
    """

    config = configparser.ConfigParser()
    # Get the directory containing the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config.ini')
    
    # Try to read the config file
    if not os.path.exists(config_path):
        logging.error(f"Config file not found at: {config_path}")
        return None
        
    config.read(config_path)
    # Check if thehive_url and thehive_api_key are present in the config file
    if 'thehive_url' not in config['DEFAULT'] or 'thehive_api_key' not in config['DEFAULT']:
        logging.error("TheHive URL or API key not found in config file.")
        return None

    # Read TheHive instance URL from the config file
    thehive_url = config['DEFAULT']['thehive_url']

    # Read TheHive API key from the config file
    thehive_api_key = config['DEFAULT']['thehive_api_key']

    severities = [2, 3, 4]
    alerts = []

    for severity in severities:
        if severity not in [1, 2, 3, 4]:
            raise ValueError("Invalid severity level. Allowed values: 1 (low), 2 (medium), 3 (high), 4 (critical)")

        query_params = {
            "query": [
                {
                    "_name": "listAlert"
                },
                {
                    "_name": "filter",
                    "_field": "severity",
                    "_value": severity
                },
                {
                    "_name": "filter",
                    "_field": "status",
                    "_value": "New"  # Filter for "New" status
                },
                {
                    "_name": "sort",
                    "_fields": [
                        {
                            "date": "desc"
                        }
                    ]
                },
                {
                    "_name": "page",
                    "from": 0,
                    "to": 15,
                    "extraData": [
                        "importDate",
                        "caseNumber"
                    ]
                }
            ]
        }

        try:
            response = requests.post(
                f'{thehive_url}/v1/query?name=alerts',
                json=query_params,
                headers={'Authorization': f'Bearer {thehive_api_key}'}
            )
            response.raise_for_status()  # Raise for non-200 status codes
            alerts += response.json()  # Convert response to JSON and append to the list

        except requests.exceptions.HTTPError as err:
            logging.error(f"HTTP Error: {err}")
        except requests.exceptions.Timeout as err:
            logging.error(f"Request timed out: {err}")
        except requests.exceptions.RequestException as err:
            logging.error(f"General TheHive request error: {err}")

    return json.dumps(alerts)

# class TheHiveAlertsTool(tool_context: ToolContext):
#     name: str = "TheHiveTool"
#     description: str = "Enables reading and extracting data from TheHive5 Case management platform."

#     def _to_args_and_kwargs(self, tool_input: Union[str, Dict]) -> Tuple[Tuple, Dict]:
#         return (), {}

#     def _run(self):
#         retrieved_alerts = thehive_alerts()
#         return retrieved_alerts

#     def _arun(self):
#         raise NotImplementedError("Not alerts to retrieve")

if __name__ == "__main__":
    # Example usage
    alerts = thehive_alerts()
    print(alerts)
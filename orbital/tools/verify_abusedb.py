import requests
import json
import configparser
import os
import sys # Retained for potential future use, though not actively used in the snippet
from typing import Dict, Optional, Any, List # Added List

# --- Constants for Configuration (Consistent with previous tools) ---
DEFAULT_CONFIG_FILE_ABUSEIPDB = "config.ini" # Can be the same general config.ini
DEFAULT_ABUSEIPDB_SECTION = "ABUSE_DB"       # Specific section for this tool
DEFAULT_ABUSEIPDB_API_KEY_NAME = "abusedb_api_key"
DEFAULT_ABUSEIPDB_MAX_AGE_DAYS = 90

# --- Re-usable API Key Loading Function (from previous examples, ensure it's defined once in your project) ---
# For brevity, I'll assume the robust `load_api_key` function (as refactored for URLScanTool)
# is available in this scope or imported. If not, you'd include its definition here.
# For this example, let's put a simplified version here.
# In a real project, put this in a shared 'utils.py' or similar.

def load_api_key_from_config_or_env(
    config_file_name: Optional[str],
    section_name: str,
    key_identifier: str,
    env_var_name: Optional[str] = None
) -> Optional[str]:
    """
    Load API key from a config file or environment variable.
    """
    # 1. Try Environment Variable First (if specified)
    if env_var_name and env_var_name in os.environ:
        env_key = os.environ[env_var_name]
        if env_key and env_key.strip():
            # print(f"Using API key from environment variable {env_var_name}")
            return env_key.strip()

    # 2. Try Config File
    cfg_file_to_use = config_file_name if config_file_name is not None else "config.ini" # Default internal config file name
    
    base_dirs = [os.getcwd()]
    if "__file__" in globals():
        base_dirs.insert(0, os.path.dirname(os.path.abspath(__file__)))

    resolved_config_path = None
    if os.path.isabs(cfg_file_to_use):
        if os.path.exists(cfg_file_to_use):
            resolved_config_path = cfg_file_to_use
    else:
        for base_dir in base_dirs:
            path_to_check = os.path.join(base_dir, cfg_file_to_use)
            if os.path.exists(path_to_check):
                resolved_config_path = path_to_check
                break
    
    if not resolved_config_path and os.path.exists(cfg_file_to_use): # Fallback
            resolved_config_path = cfg_file_to_use

    if resolved_config_path and os.path.exists(resolved_config_path):
        try:
            config = configparser.ConfigParser()
            read_files = config.read(resolved_config_path)
            if not read_files:
                # print(f"Warning: Config file '{resolved_config_path}' was found but could not be read or is empty.")
                return None # Or raise error if config file is mandatory

            if section_name in config and key_identifier in config[section_name]:
                api_key_value = config[section_name][key_identifier]
                if api_key_value and api_key_value.strip():
                    # print(f"Found API key in config file: {resolved_config_path}")
                    return api_key_value.strip()
        except configparser.Error as e:
            print(f"Warning: Error parsing config file '{resolved_config_path}': {e}")
            # Don't raise here, allow fallback to env var if env_var_name was None initially
    
    # If env_var_name was None and we haven't returned yet, check again for env var (if there's a standard one)
    # This part is a bit redundant if env_var_name is always passed.
    # For a generic loader, you might decide the order or if both are always checked.

    # print(f"Could not find valid API key for {section_name}/{key_identifier} in config or environment.")
    return None


class AbuseIPDBTool:
    """
    A tool to check IP addresses against the AbuseIPDB database.
    AbuseIPDB is a database of reported IP addresses involved in malicious activities.
    API Documentation: https://docs.abuseipdb.com/
    """

    def __init__(self, api_key: str):
        """
        Initialize the AbuseIPDBTool.
        Args:
            api_key (str): The API key for AbuseIPDB. Must not be empty.
        """
        if not api_key or not api_key.strip():
            raise ValueError("API key for AbuseIPDBTool cannot be empty.")
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        self.default_timeout = 15 # Default timeout for requests in seconds

    @classmethod
    def from_config(
        cls,
        config_file_path: Optional[str] = None,
        section: Optional[str] = None,
        key_name: Optional[str] = None
    ) -> 'AbuseIPDBTool':
        """
        Create an AbuseIPDBTool instance by loading the API key.
        """
        cfg_file = config_file_path # load_api_key_from_config_or_env handles its own default if None
        cfg_section = section if section is not None else DEFAULT_ABUSEIPDB_SECTION
        cfg_key = key_name if key_name is not None else DEFAULT_ABUSEIPDB_API_KEY_NAME
        
        api_key_val = load_api_key_from_config_or_env(
            config_file_name=cfg_file,
            section_name=cfg_section,
            key_identifier=cfg_key,
            env_var_name="ABUSEDB_API_KEY" # Standard env var to check
        )
        if not api_key_val:
            raise ValueError(f"AbuseIPDB API key not found in config (section: '{cfg_section}', key: '{cfg_key}') or environment variable 'ABUSEDB_API_KEY'.")
        return cls(api_key_val)

    def _make_request(self, method: str, endpoint: str, params: Optional[Dict[str, Any]] = None, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Helper method to make HTTP requests and handle common errors."""
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.request(method=method.upper(), url=url, headers=self.headers, params=params, json=data, timeout=self.default_timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            status_code = getattr(http_err.response, 'status_code', 'N/A')
            response_text = getattr(http_err.response, 'text', 'No response body')[:500]
            # AbuseIPDB often returns errors in a JSON 'errors' list
            errors_detail = ""
            try:
                err_json = http_err.response.json()
                if 'errors' in err_json and isinstance(err_json['errors'], list):
                    errors_detail = " API Errors: " + "; ".join([e.get('detail', str(e)) for e in err_json['errors']])
            except ValueError:
                pass # Response was not JSON
            error_message = f"HTTP error {status_code} for {method.upper()} {url}: {http_err}.{errors_detail} Response snippet: {response_text}"
            return {'error': error_message, 'status_code': status_code}
        except requests.exceptions.RequestException as req_err:
            return {'error': f"RequestException for {method.upper()} {url}: {req_err}"}
        except ValueError as json_err:
            return {'error': f"JSONDecodeError for {method.upper()} {url}: {json_err}. Response was not valid JSON."}

    def check_ip(self, ip_address: str, max_age_in_days: int = DEFAULT_ABUSEIPDB_MAX_AGE_DAYS) -> Dict[str, Any]:
        """
        Check an IP address against the AbuseIPDB database.
        Args:
            ip_address (str): The IP address to check.
            max_age_in_days (int): Max age of reports (default: from constant).
        Returns:
            Dict[str, Any]: IP information or an error dictionary.
        """
        # Basic IP validation (optional, can be more sophisticated)
        # import re
        # if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address) and not re.match(r"^[0-9a-fA-F:]+$", ip_address):
        #     return {'error': f"Invalid IP address format provided: {ip_address}", 'ip_address': ip_address}

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": str(max_age_in_days)
            # "verbose": True # Optionally add for more details if needed by the agent
        }
        result = self._make_request(method="GET", endpoint="/check", params=params)
        # Ensure 'data' key exists for successful responses as per AbuseIPDB format
        if 'error' not in result and 'data' not in result:
            return {'error': 'API response for check_ip missing "data" field.', 'raw_response': result, 'ip_address': ip_address}
        return result # Contains {'data': {...}} or {'error': ...}

    def report_ip(self, ip_address: str, categories: List[int], comment: Optional[str] = None) -> Dict[str, Any]:
        """
        Report an abusive IP address to AbuseIPDB.
        Args:
            ip_address (str): The IP address to report.
            categories (List[int]): List of category IDs. See abuseipdb.com/categories.
            comment (Optional[str]): Additional information about the abuse.
        Returns:
            Dict[str, Any]: API response or an error dictionary.
        """
        if not categories:
            return {'error': "Categories list cannot be empty for reporting an IP.", 'ip_address': ip_address}

        params = { # AbuseIPDB report uses POST with query parameters for some reason, not JSON body
            "ip": ip_address,
            "categories": ",".join(map(str, categories))
        }
        if comment and comment.strip():
            params["comment"] = comment.strip()

        # Note: AbuseIPDB's /report endpoint uses POST but expects parameters in the query string or form-encoded,
        # not as a JSON body. requests.post with `params` kwarg handles this.
        # If it were a JSON body, we'd use the `json` kwarg in _make_request.
        # For now, we'll assume _make_request's `params` with POST is fine,
        # or adjust _make_request if AbuseIPDB needs form-data for POST reports.
        # Typically, POST for creation uses a request body. Let's assume params for now.
        # Update: The API docs show POST /report with x-www-form-urlencoded or query params.
        # So, using `params` with `requests.post` is not standard but might work if their server is lenient.
        # A safer bet for POST with form data is `data` kwarg.
        # Let's use GET with params for /check and for /report we should use POST with data if that's what API expects.
        # The provided class used GET for /check and POST for /report, both with `params`.
        # Sticking to the original class's method for POST /report via params for now.
        # If issues, change to self._make_request(method="POST", endpoint="/report", data=params)
        # and adjust _make_request to handle `data` for POST properly (e.g. as form data).

        result = self._make_request(method="POST", endpoint="/report", params=params) # Original used params for POST
        if 'error' not in result and 'data' not in result:
             return {'error': 'API response for report_ip missing "data" field.', 'raw_response': result, 'ip_address': ip_address}
        return result

    def __call__(self, ip_address: str, max_age_in_days: int = DEFAULT_ABUSEIPDB_MAX_AGE_DAYS) -> Dict[str, Any]:
        """
        Make the tool callable, calling check_ip.
        """
        return self.check_ip(ip_address, max_age_in_days)

# --- MODIFIED Agent-Callable Tool Function ---
def check_abuse_ip(
    ip_address: str,
    max_age_in_days_input: Optional[int],
    api_key_input: Optional[str], # Renamed for clarity to avoid clash with internal var
    config_file_path_input: Optional[str]
) -> Dict[str, Any]:
    """
    Checks an IP address against the AbuseIPDB database for reported malicious activity.

    Args:
        ip_address (str): The IP address to check (e.g., "1.2.3.4"). This is mandatory.
        max_age_in_days_input (Optional[int]): The maximum age of reports (in days) to consider.
                                               If not provided (null/None), defaults internally to 90 days.
        api_key_input (Optional[str]): The AbuseIPDB API key.
                                       If not provided (null/None), the tool attempts to load it from a configuration file or environment variable.
        config_file_path_input (Optional[str]): Path to the configuration file for the AbuseIPDB API key.
                                                If not provided (null/None), defaults internally to "config.ini".

    Returns:
        Dict[str, Any]: A dictionary containing the AbuseIPDB report data for the IP address.
                        This includes fields like 'abuseConfidenceScore', 'totalReports', 'countryCode', 'isp', etc.
                        If an error occurs (e.g., API key issue, network problem, invalid IP),
                        the dictionary will contain an 'error' key with a descriptive message.
                        A successful response from AbuseIPDB is nested under a 'data' key.
    """
    # Internal defaults if LLM omits optional parameters
    max_age = max_age_in_days_input if max_age_in_days_input is not None else DEFAULT_ABUSEIPDB_MAX_AGE_DAYS
    
    # API key loading logic
    # If api_key_input is provided directly by LLM, use it. Otherwise, try loading.
    effective_api_key = api_key_input 
    if not effective_api_key: # If LLM provided None or empty string for api_key_input
        try:
            effective_api_key = load_api_key_from_config_or_env(
                config_file_name=config_file_path_input, # load_api_key handles its own default if this is None
                section_name=DEFAULT_ABUSEIPDB_SECTION,
                key_identifier=DEFAULT_ABUSEIPDB_API_KEY_NAME,
                env_var_name="ABUSEDB_API_KEY"
            )
        except (FileNotFoundError, KeyError, ValueError) as e: # Catch errors from key loading
            return {'error': f"API key configuration error: {str(e)}", 'ip_address': ip_address, 'status': 'config_error'}

    if not effective_api_key: # If still no API key after trying to load
        return {'error': "AbuseIPDB API key is required but was not provided and could not be loaded.", 'ip_address': ip_address, 'status': 'config_error'}

    try:
        tool = AbuseIPDBTool(api_key=effective_api_key)
        return tool.check_ip(ip_address, max_age_in_days=max_age)
    except ValueError as ve: # Catch init errors from AbuseIPDBTool if API key is now invalid
        return {'error': f"Tool initialization error: {str(ve)}", 'ip_address': ip_address}
    except Exception as e: # Catch any other unexpected errors
        return {'error': f"Unexpected error in check_abuse_ip: {str(e)}", 'ip_address': ip_address}


if __name__ == "__main__":
    # --- Create a dummy config.ini for testing if it doesn't exist ---
    dummy_config_file = DEFAULT_CONFIG_FILE_ABUSEIPDB
    if not os.path.exists(dummy_config_file):
        print(f"Creating dummy {dummy_config_file} for testing...")
        cfg = configparser.ConfigParser()
        cfg[DEFAULT_ABUSEIPDB_SECTION] = {DEFAULT_ABUSEIPDB_API_KEY_NAME: "YOUR_ABUSEIPDB_API_KEY_HERE"} # Or leave blank
        with open(dummy_config_file, 'w') as configfile:
            cfg.write(configfile)
        print(f"IMPORTANT: Ensure '{DEFAULT_ABUSEIPDB_API_KEY_NAME}' in section '[{DEFAULT_ABUSEIPDB_SECTION}]' of {dummy_config_file} is set for actual tests.")
        print("If API key is blank or invalid, tests will likely show errors.\n")
    # --- End dummy config creation ---

    test_ip = "1.1.1.1" # A public IP for testing

    print(f"--- Testing check_abuse_ip for: {test_ip} (LLM provides no optionals) ---")
    # Simulate LLM calling with only mandatory fields (or providing None for optionals)
    result1 = check_abuse_ip(
        ip_address=test_ip,
        max_age_in_days_input=None,
        api_key_input=None,
        config_file_path_input=None
    )
    print(json.dumps(result1, indent=2))
    print("-" * 50)

    print(f"--- Testing check_abuse_ip for: {test_ip} (LLM provides some optionals) ---")
    # Simulate LLM providing some optional values
    # To test with a direct API key, replace None with your actual key string
    # direct_api_key_test = "YOUR_ACTUAL_API_KEY_IF_TESTING_THIS_WAY" 
    direct_api_key_test = None # Default to config/env loading

    result2 = check_abuse_ip(
        ip_address=test_ip,
        max_age_in_days_input=30,
        api_key_input=direct_api_key_test, 
        config_file_path_input=dummy_config_file # Explicitly pass config path
    )
    print(json.dumps(result2, indent=2))
    print("-" * 50)

    # Example of using the class directly with from_config
    print(f"--- Testing AbuseIPDBTool.from_config() and check_ip for: {test_ip} ---")
    try:
        # No arguments to from_config, so it uses all internal defaults for paths/sections/keys
        tool_instance = AbuseIPDBTool.from_config() 
        class_result = tool_instance.check_ip(test_ip, max_age_in_days=180)
        print(json.dumps(class_result, indent=2))
    except Exception as e:
        print(f"Error using AbuseIPDBTool.from_config(): {e}")
    print("-" * 50)

    # Test reporting (CAUTION: This will make a real report if API key is valid)
    # print(f"--- Testing report_ip (CAUTION: LIVE REPORT IF API KEY IS VALID) ---")
    # try:
    #     tool_instance_for_report = AbuseIPDBTool.from_config()
    #     # Example categories for Brute-Force (SSH) and Bad Web Bot
    #     report_categories = [22, 19] # Check https://www.abuseipdb.com/categories
    #     # Provide a public, non-critical IP you're testing against, or a known test IP.
    #     # DO NOT report random innocent IPs.
    #     ip_to_report_for_test = "192.0.2.1" # RFC 5737 TEST-NET-1, should not be reported. Use a real (but safe-to-report) IP for actual test.
    #     # For a real test, use an IP you have confirmed is abusive.
    #     # report_result = tool_instance_for_report.report_ip(ip_to_report_for_test, report_categories, "Test report from automated tool.")
    #     # print(json.dumps(report_result, indent=2))
    #     print("Report IP test skipped by default to avoid accidental reports.")
    # except Exception as e:
    #     print(f"Error during report_ip test: {e}")
    # print("-" * 50)
    # Example 3: Using the class with direct API key
    # API_KEY = "YOUR_OWN_API_KEY"
    # abuse_tool = AbuseIPDBTool(api_key=API_KEY)
    # result = abuse_tool.check_ip("118.25.6.39")
    # print(json.dumps(result, indent=2))
    
    # Example 4: Reporting an IP (uncomment to use)
    # Categories: 15 = Hacking, 21 = Web Spam
    # result = abuse_tool.report_ip("192.0.2.1", categories=[15, 21], comment="Attempted SQL injection")
    # print(json.dumps(result, indent=2))
import requests
import json
import time
import configparser
import os
from typing import Dict, Optional, Any, Tuple, List # Added List for type hinting

# --- Constants for Configuration ---
DEFAULT_CONFIG_FILE = "config.ini"
DEFAULT_URLSCAN_SECTION = "URLSCAN_IO"
DEFAULT_URLSCAN_API_KEY_NAME = "urlscan_api_key"

class URLScanTool:
    """
    A tool for scanning URLs using the urlscan.io API and extracting security verdicts.
    API Documentation: https://urlscan.io/docs/api/
    """

    def __init__(self, api_key: str):
        """
        Initialize the URLScan tool with your API key.
        Args:
            api_key (str): Your urlscan.io API key. Must not be empty.
        """
        if not api_key or not api_key.strip():
            raise ValueError("API key for URLScanTool cannot be empty.")
        self.api_key = api_key
        self.headers = {
            'API-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        self.base_url = "https://urlscan.io/api/v1"
        self.default_timeout = 30 # Default timeout for requests in seconds

    @classmethod
    def from_config(
        cls,
        config_file: Optional[str] = None,
        section: Optional[str] = None,
        key_name: Optional[str] = None
    ) -> 'URLScanTool': # Forward reference for return type
        """
        Create a URLScanTool instance by loading the API key from a config file.
        Args:
            config_file (Optional[str]): Path to the config file. Defaults to "config.ini".
            section (Optional[str]): Section in the config file. Defaults to "URLSCAN_IO".
            key_name (Optional[str]): Name of the key in the section. Defaults to "urlscan_api_key".
        Returns:
            URLScanTool: A new instance initialized with the API key.
        """
        # Use internal defaults if parameters are None
        cfg_file = config_file if config_file is not None else DEFAULT_CONFIG_FILE
        cfg_section = section if section is not None else DEFAULT_URLSCAN_SECTION
        cfg_key_name = key_name if key_name is not None else DEFAULT_URLSCAN_API_KEY_NAME

        api_key_val = load_api_key(cfg_file, cfg_section, cfg_key_name) # Call the modified load_api_key
        if not api_key_val: # load_api_key will raise error if key not found
             raise ValueError(f"API key could not be loaded for URLScanTool from {cfg_file}.")
        return cls(api_key_val)

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Helper method to make HTTP requests and handle common errors."""
        url = f"{self.base_url}{endpoint}"
        try:
            if method.upper() == 'POST':
                response = requests.post(url, headers=self.headers, data=json.dumps(data) if data else None, timeout=self.default_timeout)
            elif method.upper() == 'GET':
                response = requests.get(url, headers=self.headers, params=params, timeout=self.default_timeout)
            else:
                return {'error': f"Unsupported HTTP method: {method}"}

            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            status_code = getattr(http_err.response, 'status_code', 'N/A')
            response_text = getattr(http_err.response, 'text', 'No response body')[:500] # Limit response text
            error_message = f"HTTP error {status_code} for {method} {url}: {http_err}. Response: {response_text}"
            # Specific handling for 404 on get_scan_results
            if method.upper() == 'GET' and endpoint.startswith("/result/") and status_code == 404:
                 return {'error': "Scan not found or not completed yet", 'status_code': 404, 'scan_id': endpoint.split('/')[2]}
            return {'error': error_message, 'status_code': status_code}
        except requests.exceptions.RequestException as req_err:
            return {'error': f"RequestException for {method} {url}: {req_err}"}
        except ValueError as json_err: # If response.json() fails
            return {'error': f"JSONDecodeError for {method} {url}: {json_err}. Response was not valid JSON."}


    def submit_scan(self, url: str, visibility: str = "public") -> Dict[str, Any]:
        """
        Submit a URL to be scanned by urlscan.io.
        Args:
            url (str): The URL to scan.
            visibility (str, optional): Scan visibility ('public', 'unlisted', 'private'). Defaults to 'public'.
        Returns:
            Dict[str, Any]: API response with scan submission details or an error dictionary.
        """
        if visibility not in ["public", "unlisted", "private"]:
            return {'error': f"Invalid visibility option: {visibility}. Must be 'public', 'unlisted', or 'private'."}
        scan_data = {"url": url, "visibility": visibility}
        return self._make_request('POST', "/scan/", data=scan_data)

    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """
        Get complete results of a previously submitted scan.
        Args:
            scan_id (str): The UUID of the scan.
        Returns:
            Dict[str, Any]: The complete scan results or an error dictionary.
        """
        return self._make_request('GET', f"/result/{scan_id}/")

    def get_verdict_only(self, scan_id: str) -> Dict[str, Any]:
        """
        Get only the verdict information from a scan result.
        Args:
            scan_id (str): The UUID of the scan.
        Returns:
            Dict[str, Any]: Dictionary with verdict information or an error dictionary.
        """
        full_results = self.get_scan_results(scan_id)
        if 'error' in full_results:
            return full_results # Propagate error from get_scan_results

        # Extract only the verdict information
        if 'verdicts' in full_results and isinstance(full_results.get('verdicts'), dict):
            verdicts = full_results['verdicts']
            task = full_results.get('task', {})
            page = full_results.get('page', {}) # 'page' often contains the final URL after redirects

            return {
                'scan_id': scan_id,
                'submitted_url': task.get('url'),
                'effective_url': page.get('url', task.get('url')), # Prefer final URL
                'report_url': task.get('reportURL'),
                'screenshot_url': task.get('screenshotURL'),
                'verdicts': verdicts,
                'status': 'completed'
            }
        else:
            # This might happen if the scan is done but somehow lacks verdict structure
            return {'scan_id': scan_id, 'error': 'No valid verdict information available in scan results.', 'status': 'completed_no_verdict', 'raw_results_preview': str(full_results)[:200]}

    def wait_for_verdict(
        self,
        scan_id: str,
        max_wait_time: int = 60,
        check_interval: int = 10 # Increased default interval slightly
    ) -> Dict[str, Any]:
        """
        Wait for a scan to complete and return only the verdict information.
        Args:
            scan_id (str): The UUID of the scan.
            max_wait_time (int, optional): Maximum time to wait in seconds. Defaults to 60.
            check_interval (int, optional): How often to check status in seconds. Defaults to 10.
        Returns:
            Dict[str, Any]: The verdict information when complete or an error dictionary.
        """
        elapsed_time = 0
        while elapsed_time < max_wait_time:
            result = self.get_verdict_only(scan_id)
            if 'error' in result:
                # Check if it's the "not completed yet" error specifically
                if result.get('status_code') == 404 or "not completed yet" in result['error']:
                    if elapsed_time + check_interval >= max_wait_time: # Check before last sleep
                        return {'scan_id': scan_id, 'error': f"Scan did not complete within {max_wait_time} seconds (last status: pending).", 'status': 'timeout'}
                    time.sleep(check_interval)
                    elapsed_time += check_interval
                    continue
                else:
                    return result # Propagate other errors immediately
            # If no error and result is presumably complete verdict data
            return result

        return {'scan_id': scan_id, 'error': f"Scan did not complete within {max_wait_time} seconds.", 'status': 'timeout'}


# MODIFIED Helper function to load API key
def load_api_key(
    config_file_name: Optional[str], # Now just the file name/path string
    section_name: Optional[str],
    key_identifier: Optional[str]
) -> Optional[str]:
    """
    Load API key from a config file (e.g., config.ini).
    Searches in standard locations: script directory, current working directory, and direct path.
    Args:
        config_file_name (Optional[str]): Name/path of the config file. Defaults to "config.ini" if None.
        section_name (Optional[str]): Section in the config file. Defaults to "URLSCAN_IO" if None.
        key_identifier (Optional[str]): Name of the key in the section. Defaults to "urlscan_api_key" if None.
    Returns:
        Optional[str]: The API key if found, otherwise None (or raises error).
    Raises:
        FileNotFoundError: If the config file is not found.
        KeyError: If the section or key is not found in the config file.
    """
    cfg_file = config_file_name if config_file_name is not None else DEFAULT_CONFIG_FILE
    cfg_section = section_name if section_name is not None else DEFAULT_URLSCAN_SECTION
    cfg_key = key_identifier if key_identifier is not None else DEFAULT_URLSCAN_API_KEY_NAME

    # Define potential base directories
    base_dirs = [os.getcwd()] # Current working directory
    if "__file__" in globals(): # Script directory if available
        base_dirs.insert(0, os.path.dirname(os.path.abspath(__file__)))

    resolved_config_path = None
    # Check if cfg_file is absolute, if so, use it directly
    if os.path.isabs(cfg_file):
        if os.path.exists(cfg_file):
            resolved_config_path = cfg_file
    else: # If relative, check against base_dirs
        for base_dir in base_dirs:
            path_to_check = os.path.join(base_dir, cfg_file)
            if os.path.exists(path_to_check):
                resolved_config_path = path_to_check
                break
    
    if not resolved_config_path: # Fallback to trying the name directly (could be in PYTHONPATH or CWD if not caught above)
        if os.path.exists(cfg_file):
            resolved_config_path = cfg_file
        else:
            tried_paths = [os.path.join(base_dir, cfg_file) for base_dir in base_dirs]
            if os.path.isabs(config_file_name or ""): tried_paths.append(config_file_name or "")
            raise FileNotFoundError(f"Config file '{cfg_file}' not found. Tried: {list(set(tried_paths))}")

    config = configparser.ConfigParser()
    try:
        read_files = config.read(resolved_config_path)
        if not read_files:
            raise FileNotFoundError(f"Config file '{resolved_config_path}' was found but could not be read or is empty.")
    except configparser.Error as e:
        raise ValueError(f"Error parsing config file '{resolved_config_path}': {e}")


    if cfg_section not in config:
        raise KeyError(f"Section '{cfg_section}' not found in '{resolved_config_path}'. Available: {config.sections()}")
    if cfg_key not in config[cfg_section]:
        raise KeyError(f"Key '{cfg_key}' not found in section '{cfg_section}' of '{resolved_config_path}'. Available: {list(config[cfg_section].keys())}")

    api_key_value = config[cfg_section][cfg_key]
    if not api_key_value or not api_key_value.strip():
        raise ValueError(f"API key '{cfg_key}' in section '{cfg_section}' of '{resolved_config_path}' is empty.")
    return api_key_value.strip()


# --- MODIFIED Agent-Callable Tool Functions ---

def scan_url_security(
    url: str,
    wait_for_results: Optional[bool],
    max_wait_time_seconds: Optional[int],
    visibility_option: Optional[str],
    config_file_path: Optional[str], # Parameter names are now more descriptive
    config_section_name: Optional[str]
) -> Dict[str, Any]:
    """
    Scans a URL using urlscan.io and returns security verdict information.
    This tool submits a URL for analysis and can optionally wait for the scan to complete.

    Args:
        url (str): The URL to scan (e.g., "http://example.com"). This is mandatory.
        wait_for_results (Optional[bool]): If true, the tool will wait for the scan to finish and return the verdict.
                                           If false, it will return submission details immediately.
                                           If not provided by the caller (null/None), defaults internally to True.
        max_wait_time_seconds (Optional[int]): Maximum time in seconds to wait for scan results if wait_for_results is true.
                                               If not provided (null/None), defaults internally to 60 seconds.
        visibility_option (Optional[str]): Visibility of the scan on urlscan.io ('public', 'unlisted', 'private').
                                           If not provided (null/None), defaults internally to 'public'.
        config_file_path (Optional[str]): Path to the configuration file for urlscan.io API key.
                                          If not provided (null/None), defaults internally to "config.ini".
        config_section_name (Optional[str]): Section name in the config file for urlscan.io settings.
                                             If not provided (null/None), defaults internally to "URLSCAN_IO".

    Returns:
        Dict[str, Any]: A dictionary containing scan submission details or security verdict information.
                        Includes an 'error' key if any issues occur.
    """
    # Internal defaults if LLM omits optional parameters
    should_wait = wait_for_results if wait_for_results is not None else True
    max_wait = max_wait_time_seconds if max_wait_time_seconds is not None else 60
    visibility = visibility_option if visibility_option is not None else "public"
    cfg_file = config_file_path # load_api_key handles its own defaults if this is None
    cfg_section = config_section_name # load_api_key handles its own defaults if this is None

    try:
        api_key = load_api_key(cfg_file, cfg_section, DEFAULT_URLSCAN_API_KEY_NAME)
        scanner = URLScanTool(api_key=api_key)

        submission_result = scanner.submit_scan(url, visibility=visibility)
        if 'error' in submission_result:
            return {**submission_result, 'url': url, 'status': 'submission_failed'}

        scan_id = submission_result.get("uuid")
        if not scan_id:
            return {'error': "Failed to get scan_id from submission response.", 'url': url, 'submission_response': submission_result, 'status': 'submission_failed'}

        if not should_wait:
            return {
                'scan_id': scan_id,
                'url': url,
                'report_url_pending': submission_result.get('result'), # URL to the result page, may not be active yet
                'api_visibility': submission_result.get('visibility'),
                'status': 'submitted_not_waiting',
                'message': 'Scan submitted. Use get_scan_verdict with this scan_id to retrieve results later.'
            }

        return scanner.wait_for_verdict(scan_id, max_wait_time=max_wait, check_interval=10)

    except FileNotFoundError as fnf_err:
        return {'error': f"Configuration file error: {str(fnf_err)}", 'url': url, 'status': 'config_error'}
    except KeyError as key_err:
        return {'error': f"Configuration key error: {str(key_err)}", 'url': url, 'status': 'config_error'}
    except ValueError as val_err: # Catch API key empty error from load_api_key or URLScanTool init
        return {'error': f"Configuration or API key error: {str(val_err)}", 'url': url, 'status': 'config_error'}
    except Exception as e:
        return {'error': f"Unexpected error in scan_url_security: {str(e)}", 'url': url, 'status': 'failed'}


def get_scan_verdict(
    scan_id: str,
    config_file_path: Optional[str],
    config_section_name: Optional[str]
) -> Dict[str, Any]:
    """
    Retrieves the security verdict for a previously submitted urlscan.io scan.

    Args:
        scan_id (str): The UUID of the scan (obtained from a previous call to scan_url_security). This is mandatory.
        config_file_path (Optional[str]): Path to the configuration file for urlscan.io API key.
                                          If not provided (null/None), defaults internally to "config.ini".
        config_section_name (Optional[str]): Section name in the config file for urlscan.io settings.
                                             If not provided (null/None), defaults internally to "URLSCAN_IO".
    Returns:
        Dict[str, Any]: A dictionary containing the security verdict information or an error.
    """
    cfg_file = config_file_path # load_api_key handles its own defaults
    cfg_section = config_section_name # load_api_key handles its own defaults

    try:
        api_key = load_api_key(cfg_file, cfg_section, DEFAULT_URLSCAN_API_KEY_NAME)
        scanner = URLScanTool(api_key=api_key)
        return scanner.get_verdict_only(scan_id)
    except FileNotFoundError as fnf_err:
        return {'error': f"Configuration file error: {str(fnf_err)}", 'scan_id': scan_id, 'status': 'config_error'}
    except KeyError as key_err:
        return {'error': f"Configuration key error: {str(key_err)}", 'scan_id': scan_id, 'status': 'config_error'}
    except ValueError as val_err:
        return {'error': f"Configuration or API key error: {str(val_err)}", 'scan_id': scan_id, 'status': 'config_error'}
    except Exception as e:
        return {'error': f"Unexpected error in get_scan_verdict: {str(e)}", 'scan_id': scan_id, 'status': 'failed'}


def is_url_malicious(
    url: str,
    max_wait_time_seconds: Optional[int],
    visibility_option: Optional[str],
    config_file_path: Optional[str],
    config_section_name: Optional[str]
) -> Tuple[bool, Dict[str, Any]]:
    """
    Simplified tool to quickly determine if a URL is malicious by scanning it and checking its verdict.
    This tool always waits for the scan results.

    Args:
        url (str): The URL to scan. This is mandatory.
        max_wait_time_seconds (Optional[int]): Maximum time in seconds to wait for scan results.
                                               If not provided (null/None), defaults internally to 60 seconds.
        visibility_option (Optional[str]): Visibility of the scan on urlscan.io ('public', 'unlisted', 'private').
                                           If not provided (null/None), defaults internally to 'public'.
        config_file_path (Optional[str]): Path to the configuration file for urlscan.io API key.
                                          If not provided (null/None), defaults internally to "config.ini".
        config_section_name (Optional[str]): Section name in the config file for urlscan.io settings.
                                             If not provided (null/None), defaults internally to "URLSCAN_IO".

    Returns:
        Tuple[bool, Dict[str, Any]]:
            - bool: True if the URL is determined to be malicious, False otherwise or if an error occurs.
            - Dict[str, Any]: A dictionary with supporting verdict information or error details.
    """
    # Call scan_url_security, ensuring wait_for_results is True
    verdict_result = scan_url_security(
        url=url,
        wait_for_results=True, # Always wait for this simplified tool
        max_wait_time_seconds=max_wait_time_seconds, # Pass through or allow internal default
        visibility_option=visibility_option, # Pass through or allow internal default
        config_file_path=config_file_path, # Pass through or allow internal default
        config_section_name=config_section_name # Pass through or allow internal default
    )

    if 'error' in verdict_result:
        # Ensure the summary indicates failure clearly
        summary = {
            'url': url,
            'is_malicious': False, # Default to not malicious on error for safety in some contexts
            'status': 'scan_failed_or_config_error',
            'error_details': verdict_result['error'],
            'raw_scan_result': verdict_result # Include the raw error result
        }
        return False, summary

    overall_verdict = verdict_result.get('verdicts', {}).get('overall', {})
    is_malicious_flag = overall_verdict.get('malicious', False)

    # Create a more detailed summary for this specific tool's output
    summary = {
        'url': verdict_result.get('effective_url', url), # Use effective_url if available
        'is_malicious': is_malicious_flag,
        'score': overall_verdict.get('score', 0),
        'categories': overall_verdict.get('categories', []),
        'tags': overall_verdict.get('tags', []),
        'report_url': verdict_result.get('report_url'),
        'screenshot_url': verdict_result.get('screenshot_url'),
        'scan_id': verdict_result.get('scan_id'),
        'status': verdict_result.get('status', 'completed_unknown_verdict_structure'),
        'engines_total': verdict_result.get('verdicts', {}).get('engines', {}).get('enginesTotal'),
        'engines_malicious': verdict_result.get('verdicts', {}).get('engines', {}).get('maliciousTotal'),
        'community_votes_total': verdict_result.get('verdicts', {}).get('community', {}).get('votesTotal'),
        'community_votes_malicious': verdict_result.get('verdicts', {}).get('community', {}).get('votesMalicious'),
        # 'raw_scan_result': verdict_result # Optionally include full verdict for detailed inspection
    }
    return is_malicious_flag, summary


if __name__ == "__main__":
    # --- Create a dummy config.ini for testing ---
    if not os.path.exists(DEFAULT_CONFIG_FILE):
        print(f"Creating dummy {DEFAULT_CONFIG_FILE} for testing...")
        cfg = configparser.ConfigParser()
        cfg[DEFAULT_URLSCAN_SECTION] = {DEFAULT_URLSCAN_API_KEY_NAME: "YOUR_API_KEY_HERE_OR_LEAVE_BLANK_FOR_ERROR_TEST"}
        with open(DEFAULT_CONFIG_FILE, 'w') as configfile:
            cfg.write(configfile)
        print(f"IMPORTANT: Replace 'YOUR_API_KEY_HERE_OR_LEAVE_BLANK_FOR_ERROR_TEST' in {DEFAULT_CONFIG_FILE} with a real API key for actual scans.")
        print("If API key is blank, tests will likely show config errors or submission failures.\n")
    # --- End dummy config creation ---

    test_url = "http://example.com" # A safe URL for basic testing
    # test_url_potentially_bad = "http://testphp.vulnweb.com/" # For actual malicious checks, use with caution and a valid API key

    print(f"--- Testing scan_url_security (wait_for_results=False) for: {test_url} ---")
    # LLM would typically omit None values, so simulate that by not passing them or passing None explicitly.
    result_no_wait = scan_url_security(
        url=test_url,
        wait_for_results=False,
        max_wait_time_seconds=None, # Simulate LLM not providing it
        visibility_option="public", # LLM might provide this
        config_file_path=None,    # Simulate LLM not providing it
        config_section_name=None  # Simulate LLM not providing it
    )
    print(json.dumps(result_no_wait, indent=2))
    scan_id_for_later = result_no_wait.get('scan_id')
    print("-" * 50)

    if scan_id_for_later and 'error' not in result_no_wait:
        print(f"--- Testing get_scan_verdict for scan_id: {scan_id_for_later} (may need to wait if you run this part immediately) ---")
        # Allow some time for the scan to potentially progress if testing live
        # print("Waiting a few seconds before trying to get verdict...")
        # time.sleep(15) # Only for interactive testing
        verdict_later = get_scan_verdict(
            scan_id=scan_id_for_later,
            config_file_path=DEFAULT_CONFIG_FILE, # LLM might provide this from context
            config_section_name=DEFAULT_URLSCAN_SECTION
        )
        print(json.dumps(verdict_later, indent=2))
        print("-" * 50)

    print(f"--- Testing scan_url_security (wait_for_results=True) for: {test_url} ---")
    result_wait = scan_url_security(
        url=test_url,
        wait_for_results=True,
        max_wait_time_seconds=30, # Shorter wait for example
        visibility_option="unlisted",
        config_file_path=DEFAULT_CONFIG_FILE,
        config_section_name=DEFAULT_URLSCAN_SECTION
    )
    print(json.dumps(result_wait, indent=2))
    print("-" * 50)

    print(f"--- Testing is_url_malicious for: {test_url} ---")
    is_malicious_flag, malicious_verdict_summary = is_url_malicious(
        url=test_url,
        max_wait_time_seconds=None, # Let internal default apply
        visibility_option=None,     # Let internal default apply
        config_file_path=None,    # Let internal default apply
        config_section_name=None  # Let internal default apply
    )
    print(f"Is malicious: {is_malicious_flag}")
    print(json.dumps(malicious_verdict_summary, indent=2))
    print("-" * 50)

    # Test error case for load_api_key directly (config file might not exist or key might be wrong)
    print("--- Testing load_api_key with potentially missing file/section/key ---")
    try:
        key = load_api_key("non_existent_config.ini", "WRONG_SECTION", "WRONG_KEY")
        print(f"load_api_key returned: {key} (unexpected for this test)")
    except Exception as e:
        print(f"load_api_key correctly raised error: {e}")
    # print(f"- Security engines checked: {verdict['engines']['total']}")
    # print(f"- Engines reporting malicious: {verdict['engines']['malicious_count']}")
    # print(f"- Community votes: {verdict['community']['total_votes']}")
    # print(f"- Community malicious votes: {verdict['community']['malicious_votes']}")
    # print(f"\nFull report available at: {verdict['report_url']}")
import requests
import json
import time
import configparser
import os
from typing import Dict, Optional, Union, List, Any

class URLScanTool:
    """
    A tool for scanning URLs using the urlscan.io API.
    
    This tool allows an agent to submit URLs for scanning and retrieve the scan results.
    It supports both submitting new scans and fetching results of existing scans.
    
    API Documentation: https://urlscan.io/docs/api/
    
    Note:
        Requires an API key from urlscan.io which can be:
        1. Passed directly to the constructor, or
        2. Loaded from a config.ini file using the from_config() class method
    """
    
    def __init__(self, api_key: str):
        """
        Initialize the URLScan tool with your API key.
        
        Args:
            api_key (str): Your urlscan.io API key
        """
        self.api_key = api_key
        self.headers = {
            'API-Key': api_key,
            'Content-Type': 'application/json'
        }
        self.base_url = "https://urlscan.io/api/v1"
        
    @classmethod
    def from_config(cls, config_file="config.ini", section="URLSCAN_IO", key_name="urlscan_api_key"):
        """
        Create a URLScanTool instance by loading the API key from a config file.
        
        Args:
            config_file (str, optional): Path to the config file. Defaults to "config.ini".
            section (str, optional): Section in the config file. Defaults to "URLSCAN_IO".
            key_name (str, optional): Name of the key in the section. Defaults to "urlscan_api_key".
            
        Returns:
            URLScanTool: A new instance initialized with the API key from the config
            
        Raises:
            FileNotFoundError: If the config file doesn't exist
            KeyError: If the section or key doesn't exist in the config file
        """
        api_key = load_api_key(config_file, section, key_name)
        return cls(api_key)
    
    def submit_scan(self, url: str, visibility: str = "public", tags: List[str] = None, 
                   custom_user_agent: str = None) -> Dict[str, Any]:
        """
        Submit a URL to be scanned by urlscan.io.
        
        Args:
            url (str): The URL to scan
            visibility (str, optional): Scan visibility - either 'public', 'unlisted' or 'private'. 
                                       Defaults to 'public'.
            tags (List[str], optional): List of tags to associate with the scan
            custom_user_agent (str, optional): Custom User-Agent header for the scan
        
        Returns:
            Dict[str, Any]: The API response containing scan submission details including:
                - uuid: The scan's unique identifier
                - visibility: The scan's visibility setting
                - url: The URL being scanned
                - result: The URL where results will be available when complete
                - api: The API endpoint to query for results
                - message: Confirmation message from the API
        
        Raises:
            Exception: If the API request fails
        """
        endpoint = f"{self.base_url}/scan/"
        
        # Prepare request data
        data = {"url": url, "visibility": visibility}
        
        # Add optional parameters if provided
        if tags:
            data["tags"] = tags
        if custom_user_agent:
            data["customagent"] = custom_user_agent
            
        try:
            # Debug information
            print(f"Submitting scan for URL: {url}")
            print(f"API Key length: {len(self.api_key)}")
            print(f"Headers: {self.headers}")
            print(f"Data: {data}")
            
            response = requests.post(
                endpoint,
                headers=self.headers,
                data=json.dumps(data)
            )
            # Print response details for debugging
            print(f"Response status code: {response.status_code}")
            print(f"Response text: {response.text}")
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            # More detailed error message
            error_details = f"Status code: {getattr(e.response, 'status_code', 'N/A')}, "
            error_details += f"Response: {getattr(e.response, 'text', 'N/A')}"
            raise Exception(f"Failed to submit URL scan: {str(e)}\nDetails: {error_details}")
    
    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """
        Get results of a previously submitted scan.
        
        Args:
            scan_id (str): The UUID of the scan as returned by submit_scan
        
        Returns:
            Dict[str, Any]: The complete scan results
        
        Raises:
            Exception: If the API request fails or the scan is not ready
        """
        endpoint = f"{self.base_url}/result/{scan_id}/"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                raise Exception("Scan not found or not completed yet")
            else:
                raise Exception(f"Failed to retrieve scan results: {str(e)}")
    
    def wait_for_scan_completion(self, scan_id: str, max_wait_time: int = 60, 
                               check_interval: int = 5) -> Dict[str, Any]:
        """
        Wait for a scan to complete and return its results.
        
        Args:
            scan_id (str): The UUID of the scan as returned by submit_scan
            max_wait_time (int, optional): Maximum time to wait in seconds. Defaults to 60.
            check_interval (int, optional): How often to check status in seconds. Defaults to 5.
        
        Returns:
            Dict[str, Any]: The scan results when complete
        
        Raises:
            Exception: If the scan doesn't complete within max_wait_time
        """
        elapsed_time = 0
        
        while elapsed_time < max_wait_time:
            try:
                results = self.get_scan_results(scan_id)
                return results
            except Exception as e:
                if "not completed yet" not in str(e):
                    raise
                
                print(f"Scan not complete yet, waiting {check_interval} seconds...")
                time.sleep(check_interval)
                elapsed_time += check_interval
        
        raise Exception(f"Scan did not complete within {max_wait_time} seconds")
    
    def search_scans(self, query: str, size: int = 10) -> Dict[str, Any]:
        """
        Search for existing URL scans using the urlscan.io search API.
        
        Args:
            query (str): The search query (see urlscan.io docs for query syntax)
            size (int, optional): Maximum number of results to return. Defaults to 10.
        
        Returns:
            Dict[str, Any]: The search results
        
        Raises:
            Exception: If the API request fails
        """
        endpoint = f"{self.base_url}/search/?q={query}&size={size}"
        
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to search URL scans: {str(e)}")


# Helper function to load API key from config file
def load_api_key(config_file="config.ini", section="URLSCAN_IO", key_name="urlscan_api_key"):
    """
    Load API key from a config.ini file.
    
    Args:
        config_file (str, optional): Path to the config file. Defaults to "config.ini".
        section (str, optional): Section in the config file. Defaults to "URLSCAN_IO".
        key_name (str, optional): Name of the key in the section. Defaults to "urlscan_api_key".
    
    Returns:
        str: The API key
    """
    # Get the directory containing the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, config_file)
    
    # Debug information about paths
    print(f"Current working directory: {os.getcwd()}")
    print(f"Script directory: {script_dir}")
    print(f"Looking for config at: {config_path}")
    
    if not os.path.exists(config_path):
        # Look for the config file in the current working directory as fallback
        cwd_config_path = os.path.join(os.getcwd(), config_file)
        print(f"Config not found at script directory, trying current working directory: {cwd_config_path}")
        
        if os.path.exists(cwd_config_path):
            config_path = cwd_config_path
            print(f"Config found at: {config_path}")
        else:
            raise FileNotFoundError(f"Config file not found at either {config_path} or {cwd_config_path}")
    
    config = configparser.ConfigParser()
    config.read(config_path)
    
    print(f"Config sections: {config.sections()}")
    
    if section not in config:
        raise KeyError(f"Section '{section}' not found in config file. Available sections: {config.sections()}")
    
    if key_name not in config[section]:
        available_keys = list(config[section].keys())
        raise KeyError(f"Key '{key_name}' not found in section '{section}'. Available keys: {available_keys}")
    
    api_key = config[section][key_name]
    # Hide the actual API key but show length for debugging
    print(f"API key found, length: {len(api_key)}")
    
    return api_key

# Example usage function that an LLM agent could call
def scan_url(url: str, wait_for_results: bool = False, 
             config_file="config.ini", config_section="URLSCAN_IO") -> Dict[str, Any]:
    """
    Scan a URL using urlscan.io and optionally wait for the results.
    API key is loaded from the config.ini file.
    
    Args:
        url (str): The URL to scan
        wait_for_results (bool, optional): Whether to wait for scan results. Defaults to False.
        config_file (str, optional): Path to the config file. Defaults to "config.ini".
        config_section (str, optional): Section in the config file. Defaults to "URLSCAN_IO".
    
    Returns:
        Dict[str, Any]: Either scan submission details or complete scan results
    
    Examples:
        Basic scan submission:
        >>> result = scan_url("https://example.com")
        >>> print(result["uuid"])  # Get the scan ID for later use
        
        Submit and wait for results:
        >>> results = scan_url("https://example.com", wait_for_results=True)
        >>> print(results["page"])  # Access scan details about the page
        
    Notes:
        Requires a config.ini file in the same directory with format:
        [URLSCAN_IO]
        urlscan_api_key = your-api-key-here
    """
    try:
        # Load API key from config file
        api_key = load_api_key(config_file, config_section)
        
        scanner = URLScanTool(api_key)
        
        # Submit the URL for scanning
        submission = scanner.submit_scan(url)
        
        # If the agent doesn't need to wait for results, return submission info
        if not wait_for_results:
            return submission
        
        # Otherwise wait for the scan to complete and return results
        scan_id = submission["uuid"]
        return scanner.wait_for_scan_completion(scan_id)
    except Exception as e:
        print(f"Error in scan_url: {str(e)}")
        raise


# Debugging function to check if config file exists and is readable
def check_config(config_file="config.ini"):
    """Check if config file exists and print its contents for debugging"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, config_file)
    cwd_config_path = os.path.join(os.getcwd(), config_file)
    
    print(f"Checking for config file:")
    print(f"- Script directory: {script_dir}")
    print(f"- Config path from script dir: {config_path}")
    print(f"- Current working directory: {os.getcwd()}")
    print(f"- Config path from current dir: {cwd_config_path}")
    
    if os.path.exists(config_path):
        print(f"Config file found at: {config_path}")
        read_config(config_path)
    elif os.path.exists(cwd_config_path):
        print(f"Config file found at: {cwd_config_path}")
        read_config(cwd_config_path)
    else:
        print(f"Config file not found in either location!")
        print(f"Directory contents of script dir:")
        print(os.listdir(script_dir))
        print(f"Directory contents of current dir:")
        print(os.listdir(os.getcwd()))

def read_config(config_path):
    """Read and print config contents (excluding actual API key)"""
    try:
        config = configparser.ConfigParser()
        config.read(config_path)
        print(f"Config sections: {config.sections()}")
        for section in config.sections():
            print(f"Section: {section}")
            for key in config[section]:
                value = config[section][key]
                # Hide actual API key
                if "api_key" in key.lower():
                    print(f"  {key}: {'*' * 5}[hidden, length: {len(value)}]")
                else:
                    print(f"  {key}: {value}")
    except Exception as e:
        print(f"Error reading config: {str(e)}")


if __name__ == "__main__":
    # Run config check first
    check_config()
    
    try:
        # Test the scan function
        print("\nTesting URL scan...")
        results = scan_url("https://refretetwy.weebly.com/", wait_for_results=True)
        print("\nScan completed successfully!")
        print(results)
        #print(f"Page title: {results.get('page', {}).get('title', 'N/A')}")
        #print(f"Final URL: {results.get('page', {}).get('url', 'N/A')}")
    except Exception as e:
        print(f"\nError during scan: {str(e)}")
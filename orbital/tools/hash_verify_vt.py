import requests
import json
import configparser
import os
import sys
import re
from typing import Dict, Optional, Any, Union, List, Tuple

class VirusTotalTool:
    """
    A tool to query the VirusTotal API for file reputation and analysis.
    VirusTotal analyzes files and URLs to detect malware and other breaches.
    """

    def __init__(self, api_key: Optional[str] = None, config_path: str = "config.ini"):
        """
        Initialize the VirusTotalTool.

        Args:
            api_key (Optional[str]): The API key for VirusTotal. If not provided,
                                    will try to read from config file.
            config_path (str): Path to the config file that contains API key. Default is "config.ini".
        """
        # If API key is not provided directly, try to read from config file
        self.api_key = api_key
        if self.api_key is None:
            self.api_key = self._get_api_key_from_config(config_path)

        if not self.api_key:
            print("\nDebug information:")
            print(f"Current working directory: {os.getcwd()}")
            # Ensure __file__ is used correctly if the script structure supports it
            script_dir = "."
            if "__file__" in globals():
                script_dir = os.path.dirname(os.path.abspath(__file__))
            print(f"Script location context: {script_dir}")
            print(f"Config path specified to __init__: {config_path}")
            print("Failed to find API key in config file or as direct parameter.\n")
            raise ValueError("API key is required. Provide it directly or via config file.")

        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

    def _get_api_key_from_config(self, config_path: str) -> Optional[str]:
        """
        Read API key from config file.

        Args:
            config_path (str): Path to the config file.

        Returns:
            Optional[str]: API key if found, None otherwise.
        """
        possible_paths = [
            config_path, # User-provided path relative to CWD or absolute
            os.path.join(os.getcwd(), config_path), # Relative to Current working directory
        ]
        # Add path relative to script directory if __file__ is available
        if "__file__" in globals():
            possible_paths.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), config_path))
        
        # Remove duplicates by converting to dict and back to list
        possible_paths = list(dict.fromkeys(possible_paths))


        for path_attempt in possible_paths:
            # Normalize the path to resolve any relative segments like '..'
            normalized_path = os.path.abspath(path_attempt)
            if os.path.exists(normalized_path):
                try:
                    config = configparser.ConfigParser()
                    config.read(normalized_path)

                    if "VIRUSTOTAL" in config and "virustotal_api_key" in config["VIRUSTOTAL"]:
                        api_key_val = config["VIRUSTOTAL"]["virustotal_api_key"]
                        if api_key_val and api_key_val.strip():
                            print(f"Found API key in config file: {normalized_path}")
                            return api_key_val.strip()
                except Exception as e:
                    print(f"Error reading config file {normalized_path}: {str(e)}")
                    continue
        
        if "VIRUSTOTAL_API_KEY" in os.environ:
            env_api_key = os.environ["VIRUSTOTAL_API_KEY"]
            if env_api_key and env_api_key.strip():
                print("Using API key from environment variable VIRUSTOTAL_API_KEY")
                return env_api_key.strip()

        print(f"Could not find valid API key in config file (checked paths based on '{config_path}') or environment variable.")
        print(f"Effective paths tried: {[os.path.abspath(p) for p in possible_paths]}")
        return None

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Get a report for a file based on its hash.

        Args:
            file_hash (str): The hash (SHA-256, SHA-1, or MD5) of the file to check.

        Returns:
            Dict[str, Any]: Dictionary containing information about the file.

        Raises:
            ValueError: If the hash format is invalid.
            Exception: If the API request fails.
        """
        if not self._is_valid_hash(file_hash):
            raise ValueError(f"Invalid hash format: {file_hash}")

        url = f"{self.base_url}/files/{file_hash}"
        try:
            response = requests.get(url, headers=self.headers, timeout=10) # Added timeout
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            # More specific error message
            error_message = f"Error getting file report from VirusTotal for hash '{file_hash}'. Error: {str(e)}."
            if response is not None:
                error_message += f" Status Code: {response.status_code}. Response: {response.text[:200]}" # Log part of response
            raise Exception(error_message)

    def extract_hashes_from_text(self, text: str) -> List[Dict[str, str]]:
        """
        Extract potential file hashes from text.

        Args:
            text (str): Text to extract hashes from.

        Returns:
            List[Dict[str, str]]: List of dictionaries containing extracted hashes and their types.
        """
        hash_patterns = {
            'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b')
        }
        results = []
        for hash_type, pattern in hash_patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                results.append({'hash': match, 'type': hash_type})
        return results

    def analyze_hashes_from_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Extract hashes from text and analyze them using VirusTotal.

        Args:
            text (str): Text containing potential file hashes.

        Returns:
            List[Dict[str, Any]]: Analysis results for extracted hashes.
        """
        extracted_hashes = self.extract_hashes_from_text(text)
        results = []
        for hash_info in extracted_hashes:
            try:
                report = self.get_file_report(hash_info['hash'])
                report['hash_type'] = hash_info['type'] # Add hash_type to the main report
                results.append(report)
            except Exception as e:
                results.append({
                    'hash': hash_info['hash'],
                    'hash_type': hash_info['type'],
                    'error': str(e)
                })
        return results

    def is_file_malicious(self, file_hash: str, threshold: int = 5) -> Tuple[bool, Dict[str, Any]]:
        """
        Determine if a file is malicious based on VirusTotal results.

        Args:
            file_hash (str): The hash of the file to check.
            threshold (int): Minimum number of positive detections to consider malicious. Default is 5.

        Returns:
            Tuple[bool, Dict[str, Any]]: (is_malicious, report_data)
        """
        # The default for threshold (5) within the class method is fine,
        # as this method itself is not directly exposed as the primary tool function to the LLM.
        # If you were to expose this method directly, threshold's default might also need removal.
        try:
            report = self.get_file_report(file_hash)
            if 'data' in report and 'attributes' in report['data']:
                attributes = report['data']['attributes']
                if 'last_analysis_stats' in attributes:
                    stats = attributes['last_analysis_stats']
                    malicious_count = stats.get('malicious', 0)
                    # Consider suspicious as contributing to maliciousness for a conservative approach
                    suspicious_count = stats.get('suspicious', 0)
                    total_positive_detections = malicious_count + suspicious_count
                    is_malicious = total_positive_detections >= threshold
                    return is_malicious, report
                if 'reputation' in attributes: # Fallback to reputation
                    is_malicious = attributes['reputation'] < 0
                    return is_malicious, report
            # If insufficient data to determine, conservatively assume not definitively benign
            return False, {"message": "Insufficient data in report to determine malicious status.", **report} # Changed from True
        except Exception as e:
            return True, {'error': str(e), 'hash': file_hash, "message": "Error during analysis, assuming suspicious."} # Assume suspicious on error

    def _is_valid_hash(self, hash_str: str) -> bool:
        """
        Validate if a string is a valid file hash.
        """
        return bool(re.match(r'^[a-fA-F0-9]{32}$', hash_str) or \
                    re.match(r'^[a-fA-F0-9]{40}$', hash_str) or \
                    re.match(r'^[a-fA-F0-9]{64}$', hash_str))

    def __call__(self, file_hash: str) -> Dict[str, Any]:
        """
        Make the tool callable, which simply calls the get_file_report method.
        """
        return self.get_file_report(file_hash)


# MODIFIED Function definition for the agent framework
def check_file_reputation(
    file_hash: str,
    api_key: Optional[str],  # No default value here
    config_path: Optional[str] # No default value here
) -> Dict[str, Any]:
    """
    Tool function to check file reputation using VirusTotal.
    It retrieves a report for a file based on its hash (SHA-256, SHA-1, or MD5).

    Args:
        file_hash (str): The hash (SHA-256, SHA-1, or MD5) of the file to check. This is a mandatory field.
        api_key (Optional[str]): The API key for VirusTotal.
                                 If not provided or set to null/None by the caller,
                                 the tool will attempt to load the key from the config file specified by config_path or from environment variables.
        config_path (Optional[str]): Path to the configuration file that might contain the VirusTotal API key.
                                     If not provided or set to null/None by the caller, this will default internally to "config.ini".
                                     The tool searches for this file in standard locations (e.g., relative to current working directory or script location).
    Returns:
        Dict[str, Any]: A dictionary containing the file report from VirusTotal.
                        In case of an error during the process (e.g., API key issue, network problem, invalid hash),
                        the dictionary will contain an 'error' key with a descriptive message.
    """
    try:
        # Determine the configuration path to use.
        # If the LLM doesn't provide config_path (it's None), default to "config.ini".
        # This internal default is fine; the key is no default in the function signature for the schema.
        current_config_path = config_path if config_path is not None else "config.ini"

        # The api_key can be None. VirusTotalTool's __init__ handles loading it
        # from the config file or environment if api_key is None.
        tool = VirusTotalTool(api_key=api_key, config_path=current_config_path)
        return tool.get_file_report(file_hash)
    except ValueError as ve: # Catch specific errors like API key missing or invalid hash
        return {'error': f"ValueError: {str(ve)}", 'hash_provided': file_hash}
    except Exception as e: # Catch any other unexpected errors
        return {'error': f"Unexpected error in check_file_reputation: {str(e)}", 'hash_provided': file_hash}


def extract_and_analyze_hashes(text: str, api_key: Optional[str] = None, config_path: str = "config.ini") -> List[Dict[str, Any]]:
    """
    Tool function to extract hashes from text and analyze them using VirusTotal.
    
    Args:
        text (str): Text containing potential file hashes.
        api_key (Optional[str]): The API key for VirusTotal.
        config_path (str): Path to the config file that contains API key.
        
    Returns:
        List[Dict[str, Any]]: Analysis results for extracted hashes.
    """
    tool = VirusTotalTool(api_key=api_key, config_path=config_path)
    return tool.analyze_hashes_from_text(text)


# # OpenAI function definition
# virustotal_function_definition = {
#     "name": "check_file_reputation",
#     "description": "Check the reputation of a file hash using VirusTotal to determine if it is malicious.",
#     "parameters": {
#         "type": "object",
#         "properties": {
#             "file_hash": {
#                 "type": "string",
#                 "description": "The hash (SHA-256, SHA-1, or MD5) of the file to check."
#             },
#             "config_path": {
#                 "type": "string",
#                 "description": "Path to the config.ini file containing VirusTotal API key.",
#                 "default": "config.ini"
#             }
#         },
#         "required": ["file_hash"]
#     }
# }

# # OpenAI function definition for hash extraction and analysis
# analyze_text_function_definition = {
#     "name": "extract_and_analyze_hashes",
#     "description": "Extract file hashes from text and analyze them using VirusTotal.",
#     "parameters": {
#         "type": "object",
#         "properties": {
#             "text": {
#                 "type": "string",
#                 "description": "Text containing potential file hashes to be analyzed."
#             },
#             "config_path": {
#                 "type": "string",
#                 "description": "Path to the config.ini file containing VirusTotal API key.",
#                 "default": "config.ini"
#             }
#         },
#         "required": ["text"]
#     }
# }


# Example usage
if __name__ == "__main__":
    # Debug information
    print(f"Current working directory: {os.getcwd()}")
    print(f"Looking for config file...")
    
    try:
        # Example: Initialize tool
        vt_tool = VirusTotalTool(config_path="config.ini")
        
        # Example 1: Check a known malicious hash (Ryuk ransomware sample)
        sample_hash = "8d3f68b16f0710f858d8c1d2c699260e6f43161a5510abb0e7ba567bd72c965b"
        print(f"\nChecking VirusTotal for hash: {sample_hash}")
        is_malicious, report = vt_tool.is_file_malicious(sample_hash)
        
        print(f"Is malicious: {is_malicious}")
        if 'data' in report and 'attributes' in report['data']:
            attributes = report['data']['attributes']
            if 'popular_threat_classification' in attributes:
                threat_class = attributes['popular_threat_classification']
                if 'suggested_threat_label' in threat_class:
                    print(f"Threat label: {threat_class['suggested_threat_label']}")
                    
                if 'popular_threat_category' in threat_class:
                    print("Threat categories:")
                    for category in threat_class['popular_threat_category']:
                        print(f"  - {category['value']} (count: {category['count']})")
        
        # Example 2: Extract and analyze hashes from text
    #     sample_text = """
    #     We found suspicious files with these hashes in the system:
    #     8d3f68b16f0710f858d8c1d2c699260e6f43161a5510abb0e7ba567bd72c965b
    #     5767653494d05b3f3f38f1662a63335d09ae6489
    #     """
        
    #     print("\nExtracting and analyzing hashes from text:")
    #     hashes = vt_tool.extract_hashes_from_text(sample_text)
    #     print(f"Extracted hashes: {hashes}")
        
    except Exception as e:
        print(f"Error during VirusTotal analysis: {str(e)}")
        
    #     # Fallback to environment variable
    #     if "VIRUSTOTAL_API_KEY" not in os.environ:
    #         print("\nTo use environment variable, set VIRUSTOTAL_API_KEY:")
    #         print("export VIRUSTOTAL_API_KEY=your_api_key_here")
        
    #     # Prompt for API key as last resort
    #     print("\nEnter your VirusTotal API key manually: ")
    #     api_key = input().strip()
    #     if api_key:
    #         try:
    #             vt_tool = VirusTotalTool(api_key=api_key)
    #             sample_hash = "8d3f68b16f0710f858d8c1d2c699260e6f43161a5510abb0e7ba567bd72c965b"
    #             result = vt_tool.get_file_report(sample_hash)
    #             print(json.dumps(result, indent=2))
    #         except Exception as inner_e:
    #             print(f"Still encountering errors: {str(inner_e)}")
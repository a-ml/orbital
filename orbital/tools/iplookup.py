import requests
import json # Not strictly used in this snippet, but often imported with requests
from typing import Dict, Optional, Any

class IPInfoTool:
    """
    A tool to retrieve information about IP addresses using the ipinfo.io API.
    Provides details such as geolocation, ASN, and company.
    """

    def __init__(self, token: Optional[str] = None):
        """
        Initialize the IPInfoTool.

        Args:
            token (Optional[str]): The API token for ipinfo.io. If not provided,
                                  requests will be unauthenticated, potentially rate-limited,
                                  and some data fields may be unavailable.
        """
        self.base_url = "https://ipinfo.io"
        self.token = token
        self.headers = {"Accept": "application/json"}

    def lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Look up information about an IP address.

        Args:
            ip_address (str): The IP address to look up (e.g., "8.8.8.8").

        Returns:
            Dict[str, Any]: Dictionary containing information about the IP address.
                            Example keys: "ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone".
                            If an error occurs (e.g., invalid IP, network issue, API error),
                            the dictionary will contain an 'error' key with a descriptive message.

        Raises:
            Exception: If the API request itself fails critically (this is now caught and returned as dict).
        """
        # Basic validation for IP address format (optional, but good for early failure)
        # This is a simple regex, more comprehensive validation might be needed for edge cases.
        # import re
        # if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address) and \
        #    not re.match(r"^[0-9a-fA-F:]+$", ip_address): # Basic IPv6 check
        #     return {'error': f"Invalid IP address format: {ip_address}", 'ip_provided': ip_address}


        url = f"{self.base_url}/{ip_address}"
        params = {}
        if self.token:
            params["token"] = self.token

        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=10) # Added timeout
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            # More specific error for HTTP errors, including status code and response if possible
            error_details = f"HTTP error occurred: {http_err}. Status Code: {http_err.response.status_code}."
            try:
                # Attempt to get more details from the JSON response if it exists
                error_content = http_err.response.json()
                if 'error' in error_content and 'message' in error_content['error']:
                     error_details += f" API Message: {error_content['error']['message']}"
                elif 'error' in error_content:
                    error_details += f" API Error: {error_content['error']}"
                else:
                    error_details += f" Response: {http_err.response.text[:200]}" # Log part of text response
            except ValueError: # If response is not JSON
                error_details += f" Response: {http_err.response.text[:200]}"
            return {'error': error_details, 'ip_provided': ip_address}
        except requests.exceptions.RequestException as req_err:
            # For other request exceptions like connection errors, timeouts (if not HTTPError)
            return {'error': f"Request error looking up IP information: {req_err}", 'ip_provided': ip_address}
        except Exception as e:
            # Catch-all for any other unexpected errors during the lookup
            return {'error': f"An unexpected error occurred during IP lookup: {str(e)}", 'ip_provided': ip_address}


    def __call__(self, ip_address: str) -> Dict[str, Any]:
        """
        Make the tool callable, which simply calls the lookup method.

        Args:
            ip_address (str): The IP address to look up.

        Returns:
            Dict[str, Any]: Dictionary containing information about the IP address.
        """
        return self.lookup(ip_address)


# MODIFIED Function definition for the agent framework
def get_ip_info(
    ip_address: str,
    token: Optional[str] # No default value here
) -> Dict[str, Any]:
    """
    Tool function to get information about an IP address using the ipinfo.io service.
    It retrieves details such as geolocation, ASN, and company associated with the IP.

    Args:
        ip_address (str): The IP address to look up (e.g., "8.8.8.8" or an IPv6 address). This is a mandatory field.
        token (Optional[str]): The API token for ipinfo.io.
                               If not provided by the caller or set to null/None,
                               requests will be made without authentication, which might be rate-limited
                               or offer fewer details. The tool will still attempt to fetch basic information.
    Returns:
        Dict[str, Any]: A dictionary containing information about the IP address.
                        Common keys include "ip", "hostname", "city", "region", "country", "loc" (coordinates),
                        "org" (organization/ISP), "postal", "timezone".
                        If an error occurs (e.g., invalid IP format given to the tool, network issue, API error),
                        the dictionary will contain an 'error' key with a descriptive message.
    """
    try:
        # The token can be None, IPInfoTool's __init__ handles it.
        tool = IPInfoTool(token=token)
        return tool.lookup(ip_address)
    except Exception as e:
        # This is a fallback, but IPInfoTool.lookup should ideally catch its own errors.
        return {'error': f"Unexpected error in get_ip_info: {str(e)}", 'ip_provided': ip_address}

# # Example of how this might be used in an OpenAI function definition
# ip_info_function_definition = {
#     "name": "get_ip_info",
#     "description": "Get information about an IP address, including geolocation data, organization, and more.",
#     "parameters": {
#         "type": "object",
#         "properties": {
#             "ip_address": {
#                 "type": "string",
#                 "description": "The IP address to look up information for."
#             }
#         },
#         "required": ["ip_address"]
#     }
# }


# Example usage
if __name__ == "__main__":
    # Example 1: Using the class directly
    # ip_tool = IPInfoTool()
    # result = ip_tool.lookup("8.8.8.8")
    # print(json.dumps(result, indent=2))
    
    # Example 2: Using the function
    result = get_ip_info("1.1.1.1")
    print(json.dumps(result, indent=2))
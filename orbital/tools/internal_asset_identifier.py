import ipaddress
import json

# --- Configuration for Organization-Specific Internal Ranges ---
# In a real application, this would likely come from a config file,
# environment variables, or a dedicated configuration service.
ORGANIZATION_INTERNAL_RANGES = [
    {"cidr": "172.16.113.0/24", "classification": "Company DMZ Block"},
    {"cidr": "192.168.0.0/16", "classification": "Company Internal Production Subnet"},
    {"cidr": "2001:db8:abcd::/48", "classification": "Company IPv6 Guest Network"},
    # Add more organization-specific ranges here
]

# Pre-compile network objects for efficiency
COMPILED_ORG_RANGES = []
for r in ORGANIZATION_INTERNAL_RANGES:
    try:
        COMPILED_ORG_RANGES.append({
            "network": ipaddress.ip_network(r["cidr"], strict=False),
            "classification": r["classification"],
            "cidr_str": r["cidr"]
        })
    except ValueError as e:
        print(f"Warning: Invalid CIDR in ORGANIZATION_INTERNAL_RANGES '{r['cidr']}': {e}")


def get_rfc1918_ula_subnet(ip_obj):
    """
    Determines the encompassing RFC1918 or ULA subnet for a private IP.
    """
    if ip_obj.version == 4:
        if ip_obj in ipaddress.ip_network("10.0.0.0/8", strict=False):
            return "10.0.0.0/8"
        elif ip_obj in ipaddress.ip_network("172.16.0.0/12", strict=False):
            return "172.16.0.0/12"
        elif ip_obj in ipaddress.ip_network("192.168.0.0/16", strict=False):
            return "192.168.0.0/16"
    elif ip_obj.version == 6:
        # Check for ULA (fc00::/7)
        if ip_obj.is_private: # For IPv6, is_private checks for ULA
             # fc00::/7 is the range for Unique Local Addresses
            if ip_obj in ipaddress.ip_network("fc00::/7", strict=False):
                return "fc00::/7"
    return None

class InternalAssetIdentifier:
    def _is_internal_ip_(self, ip_address_str: str) -> str:
        """
        Determines if a given IP address is internal to the organization.

        Args:
            ip_address_str: The IP address string to check.

        Returns:
            A JSON string with the analysis result.
        """
        result = {
            "ip_address": ip_address_str,
            "is_internal": False,
            "classification": "Unrecognized",
            "matched_subnet": None,
            "error": None
        }

        try:
            ip_obj = ipaddress.ip_address(ip_address_str)
        except ValueError as e:
            result["error"] = f"Invalid IP address format: {e}"
            result["is_internal"] = False # Ensure this is false on error
            return json.dumps(result)

        # 1. Check against organization-specific configured ranges first
        for org_range in COMPILED_ORG_RANGES:
            if ip_obj in org_range["network"]:
                result["is_internal"] = True
                result["classification"] = org_range["classification"]
                result["matched_subnet"] = org_range["cidr_str"]
                return json.dumps(result)

        # 2. Check for standard private ranges (RFC1918 for IPv4, ULA for IPv6)
        if ip_obj.is_private:
            result["is_internal"] = True
            result["classification"] = "RFC4193 Unique Local Address (ULA)" if ip_obj.version == 6 else "RFC1918 Private"
            result["matched_subnet"] = get_rfc1918_ula_subnet(ip_obj)
            return json.dumps(result)

        # 3. Check for loopback addresses
        if ip_obj.is_loopback:
            result["is_internal"] = True
            result["classification"] = "Loopback"
            result["matched_subnet"] = "127.0.0.0/8" if ip_obj.version == 4 else "::1/128"
            return json.dumps(result)

        # 4. Check for link-local addresses
        if ip_obj.is_link_local:
            result["is_internal"] = True
            result["classification"] = "Link-Local"
            result["matched_subnet"] = "169.254.0.0/16" if ip_obj.version == 4 else "fe80::/10"
            return json.dumps(result)

        # 5. If none of the above, it's considered external (if global) or unrecognized
        if ip_obj.is_global:
            result["is_internal"] = False
            result["classification"] = "External Public IP"
        else:
            # Covers multicast, reserved, unspecified, etc. that aren't explicitly internal
            result["is_internal"] = False
            result["classification"] = "Other Non-Internal (e.g., Multicast, Reserved)"

        return json.dumps(result)

# --- Example Usage (how an agent might call it) ---
if __name__ == "__main__":
    identifier_tool = InternalAssetIdentifier()

    test_ips = [
        "192.168.1.10",         # RFC1918 Private
        "10.0.5.23",            # RFC1918 Private
        "172.16.31.45",         # RFC1918 Private
        "fd00:1234:5678::1",    # RFC4193 ULA (IPv6 Private)
        "203.0.113.55",         # Company DMZ (from config)
        "198.51.100.10",        # Company Internal Prod (from config)
        "2001:db8:abcd::cafe",  # Company IPv6 Guest (from config)
        "8.8.8.8",              # External Public IP
        "127.0.0.1",            # Loopback IPv4
        "::1",                  # Loopback IPv6
        "169.254.10.20",        # Link-Local IPv4
        "fe80::1234:5678:9abc:def0", # Link-Local IPv6
        "224.0.0.1",            # Multicast (Other Non-Internal)
        "invalid-ip",           # Invalid IP
        "240.0.0.1"             # Reserved (Class E - Other Non-Internal)
    ]

    print("--- Testing internal_asset_identifier._is_internal_ip_ ---")
    for ip_to_test in test_ips:
        json_output = identifier_tool._is_internal_ip_(ip_address_str=ip_to_test)
        # In a real agent, you'd just get the json_output string.
        # Here we parse it back for pretty printing.
        output_dict = json.loads(json_output)
        print(f"\nInput IP: {ip_to_test}")
        print(f"  Is Internal: {output_dict['is_internal']}")
        print(f"  Classification: {output_dict['classification']}")
        print(f"  Matched Subnet: {output_dict['matched_subnet']}")
        if output_dict['error']:
            print(f"  Error: {output_dict['error']}")

    # Example of how an agent would get the raw JSON string
    print("\n--- Raw JSON output for one IP ---")
    raw_json = identifier_tool._is_internal_ip_("10.1.2.3")
    print(raw_json)
    # Expected: {"ip_address": "10.1.2.3", "is_internal": true, "classification": "RFC1918 Private", "matched_subnet": "10.0.0.0/8", "error": null}
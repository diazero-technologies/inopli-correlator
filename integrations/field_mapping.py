# Dictionary mapping normalized field types to possible field names in events from different sources
# Example: 'ip' can be 'src_ip', 'ip', 'source_ip', etc.

FIELD_MAPPING = {
    "ip": [
        "ip", "src_ip", "source_ip", "srcip", "client_ip", "remote_ip",
        "data.srcip", "data.dstip", "offense_source"  # QRadar specific
    ],
    "domain": [
        "domain", "fqdn", "hostname", "host", "url_domain"
    ],
    "file_hash": [
        "hash", "file_hash", "sha256", "sha1", "md5"
    ],
    "url": [
        "url", "uri", "link", "data.url"
    ],
    "description": [
        "description", "message", "alert_description", "rule_description"
    ],
    "severity": [
        "severity", "level", "priority", "risk_level", "magnitude"  # QRadar uses magnitude
    ],
    "categories": [
        "categories", "tags", "labels", "security_categories"
    ],
    "source_network": [
        "source_network", "src_network", "source_net", "network"
    ],
    "destination_networks": [
        "destination_networks", "dst_networks", "dest_networks"
    ],
    "rule_id": [
        "rule_id", "detection_rule_id", "description"  # QRadar: use description as rule_id
    ],
    "credibility": [
        "credibility", "confidence", "relevance"  # QRadar specific
    ],
    "status": [
        "status", "state", "offense_status"
    ],
    # Add more mappings as needed
}

def get_field_value(event: dict, field_type: str):
    """
    Given an event dict and a normalized field type, return the first matching value found.
    Supports nested field access using dot notation (e.g., 'rule.id').
    """
    for field_name in FIELD_MAPPING.get(field_type, []):
        if '.' in field_name:
            # Handle nested field access (e.g., 'rule.id')
            value = _get_nested_value(event, field_name)
            if value is not None:
                return value
        elif field_name in event:
            value = event[field_name]
            
            # Special handling for QRadar rules array
            if field_name == "rules" and isinstance(value, list) and len(value) > 0:
                # Return the first rule ID from the rules array
                first_rule = value[0]
                if isinstance(first_rule, dict) and "id" in first_rule:
                    return first_rule["id"]
            
            return value
    return None


def _get_nested_value(event: dict, field_path: str):
    """
    Get value from nested dictionary using dot notation.
    Example: _get_nested_value(event, 'rule.id') -> event['rule']['id']
    """
    try:
        keys = field_path.split('.')
        value = event
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value
    except (KeyError, TypeError, AttributeError):
        return None 
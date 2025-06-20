# Dictionary mapping normalized field types to possible field names in events from different sources
# Example: 'ip' can be 'src_ip', 'ip', 'source_ip', etc.

FIELD_MAPPING = {
    "ip": ["ip", "src_ip", "source_ip", "srcip", "client_ip", "remote_ip"],
    "domain": ["domain", "fqdn", "hostname", "host", "url_domain"],
    "file_hash": ["hash", "file_hash", "sha256", "sha1", "md5"],
    "url": ["url", "uri", "link"],
    # Add more mappings as needed
}

def get_field_value(event: dict, field_type: str):
    """
    Given an event dict and a normalized field type, return the first matching value found.
    """
    for field_name in FIELD_MAPPING.get(field_type, []):
        if field_name in event:
            return event[field_name]
    return None 
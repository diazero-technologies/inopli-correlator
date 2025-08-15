import requests
import json
from datetime import datetime, timedelta
from .base import ThreatIntelligenceIntegration
from config.debug import DEBUG_MODE
from utils.ip_utils import is_public_ip

class TAXIIIntegration(ThreatIntelligenceIntegration):
    SUPPORTED_FIELDS = ["ip", "domain", "file_hash", "url"]
    
    def __init__(self, config):
        super().__init__(config)
        self.server_url = config.get("server_url")
        self.username = config.get("username")
        self.password = config.get("password")
        self.api_key = config.get("api_key")
        self.collection_id = config.get("collection_id")
        self.timeout = config.get("timeout", 30)
        self.no_auth = config.get("no_auth", False)
        self.taxii_version = config.get("taxii_version", "2.1")  # Default to 2.1, can be 1.1
        
        # Validate required configuration
        if not self.server_url:
            raise ValueError("TAXII server URL is required in config.")
        if not self.collection_id:
            raise ValueError("TAXII collection ID is required in config.")
        
        # Validate authentication configuration
        if not self.no_auth:
            if not (self.username and self.password) and not self.api_key:
                raise ValueError("TAXII requires either username/password, API key, or no_auth=true in config.")
        
        # Normalize server URL based on TAXII version
        self._normalize_server_url()

    def query(self, field_type: str, value: str):
        if field_type not in self.SUPPORTED_FIELDS:
            return None
        try:
            return self._query_taxii(field_type, value)
        except Exception as e:
            if DEBUG_MODE:
                print(f"[DEBUG] TAXIIIntegration error for {field_type}={value}: {e}")
        return None

    def _normalize_server_url(self):
        """Normalize server URL based on TAXII version"""
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        
        if self.taxii_version == "2.1":
            # TAXII 2.1 uses /api1/ endpoint
            if not self.server_url.endswith('/api1/'):
                self.server_url += 'api1/'
        elif self.taxii_version == "1.1":
            # TAXII 1.1 uses different endpoints, keep base URL
            pass

    def _headers(self):
        """Get headers based on TAXII version"""
        if self.taxii_version == "2.1":
            headers = {
                "Accept": f"application/taxii+json;version={self.taxii_version}",
                "Content-Type": f"application/taxii+json;version={self.taxii_version}"
            }
        elif self.taxii_version == "1.1":
            headers = {
                "X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
                "X-TAXII-Accept": "urn:taxii.mitre.org:message:xml:1.1",
                "X-TAXII-Services": "urn:taxii.mitre.org:services:1.1",
                "X-TAXII-Protocol": "urn:taxii.mitre.org:protocol:http:1.0",
                "Content-Type": "application/xml"
            }
        else:
            raise ValueError(f"Unsupported TAXII version: {self.taxii_version}")
        
        # Add authentication headers only if not using no_auth mode
        if not self.no_auth:
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            elif self.username and self.password:
                # For basic auth, requests will handle this automatically
                pass
            
        return headers

    def _auth(self):
        """Return authentication tuple for requests"""
        if self.no_auth:
            return None
        if self.username and self.password:
            return (self.username, self.password)
        return None

    def _query_taxii(self, field_type: str, value: str):
        """Query TAXII server for threat intelligence"""
        
        # Skip private IPs for IP queries
        if field_type == "ip" and not is_public_ip(value):
            if DEBUG_MODE:
                print(f"[DEBUG] IP {value} is not public, skipping TAXII query")
            return None

        if self.taxii_version == "2.1":
            return self._query_taxii_21(field_type, value)
        elif self.taxii_version == "1.1":
            return self._query_taxii_11(field_type, value)
        else:
            raise ValueError(f"Unsupported TAXII version: {self.taxii_version}")

    def _query_taxii_21(self, field_type: str, value: str):
        """Query TAXII 2.1 server for threat intelligence"""
        # Build STIX pattern based on field type
        stix_pattern = self._build_stix_pattern(field_type, value)
        
        # Set time range (last 30 days by default)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=30)
        
        # Build TAXII 2.1 query
        query_data = {
            "match[type]": "indicator",
            "match[pattern]": stix_pattern,
            "added_after": start_time.isoformat() + "Z",
            "limit": 100
        }
        
        url = f"{self.server_url}collections/{self.collection_id}/objects/"
        
        try:
            resp = requests.get(
                url, 
                headers=self._headers(), 
                auth=self._auth(),
                params=query_data,
                timeout=self.timeout
            )
            
            if resp.status_code != 200:
                if DEBUG_MODE:
                    print(f"[DEBUG] TAXII 2.1 query failed: {resp.status_code} {resp.text}")
                return None
                
            data = resp.json()
            objects = data.get("objects", [])
            
            if not objects:
                return None
                
            # Process results and return threat information
            return self._process_taxii_results(field_type, value, objects)
            
        except requests.exceptions.RequestException as e:
            if DEBUG_MODE:
                print(f"[DEBUG] TAXII 2.1 request failed: {e}")
            return None

    def _query_taxii_11(self, field_type: str, value: str):
        """Query TAXII 1.1 server for threat intelligence"""
        # TAXII 1.1 uses XML format and different endpoints
        # This is a simplified implementation - TAXII 1.1 is more complex
        
        # Build STIX pattern based on field type
        stix_pattern = self._build_stix_pattern(field_type, value)
        
        # Set time range (last 30 days by default)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=30)
        
        # TAXII 1.1 Poll Request XML
        poll_request_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<taxii_11:Poll_Request xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" 
                       message_id="1" collection_name="{self.collection_id}">
    <taxii_11:Poll_Parameters>
        <taxii_11:Response_Type>FULL</taxii_11:Response_Type>
        <taxii_11:Content_Binding binding_id="urn:stix.mitre.org:xml:1.1.1"/>
        <taxii_11:Query>
            <stix:STIX_Package xmlns:stix="http://stix.mitre.org/stix-1">
                <stix:Indicators>
                    <stix:Indicator>
                        <stix:Indicator_Type>{stix_pattern}</stix:Indicator_Type>
                    </stix:Indicator>
                </stix:Indicators>
            </stix:STIX_Package>
        </taxii_11:Query>
        <taxii_11:Delivery_Parameters>
            <taxii_11:Protocol_Binding>urn:taxii.mitre.org:protocol:http:1.0</taxii_11:Protocol_Binding>
            <taxii_11:Address>http://localhost</taxii_11:Address>
            <taxii_11:Message_Binding>urn:taxii.mitre.org:message:xml:1.1</taxii_11:Message_Binding>
        </taxii_11:Delivery_Parameters>
    </taxii_11:Poll_Parameters>
</taxii_11:Poll_Request>"""
        
        url = f"{self.server_url}taxii-poll-service"
        
        try:
            resp = requests.post(
                url,
                headers=self._headers(),
                auth=self._auth(),
                data=poll_request_xml,
                timeout=self.timeout
            )
            
            if resp.status_code != 200:
                if DEBUG_MODE:
                    print(f"[DEBUG] TAXII 1.1 query failed: {resp.status_code} {resp.text}")
                return None
            
            # TAXII 1.1 returns XML, would need XML parsing here
            # For now, return None as TAXII 1.1 implementation is complex
            if DEBUG_MODE:
                print(f"[DEBUG] TAXII 1.1 response received, but XML parsing not implemented")
            return None
            
        except requests.exceptions.RequestException as e:
            if DEBUG_MODE:
                print(f"[DEBUG] TAXII 1.1 request failed: {e}")
            return None

    def _build_stix_pattern(self, field_type: str, value: str):
        """Build STIX pattern for the given field type and value"""
        if field_type == "ip":
            return f"[ipv4-addr:value = '{value}' OR ipv6-addr:value = '{value}']"
        elif field_type == "domain":
            return f"[domain-name:value = '{value}']"
        elif field_type == "file_hash":
            # Try different hash types
            return f"[file:hashes.MD5 = '{value}' OR file:hashes.SHA-1 = '{value}' OR file:hashes.SHA-256 = '{value}']"
        elif field_type == "url":
            return f"[url:value = '{value}']"
        else:
            return None

    def _process_taxii_results(self, field_type: str, value: str, objects):
        """Process TAXII results and extract threat information"""
        threats = []
        
        for obj in objects:
            if obj.get("type") == "indicator":
                indicator = obj
                
                # Check if indicator is active
                valid_from = indicator.get("valid_from")
                valid_until = indicator.get("valid_until")
                
                if valid_until and datetime.fromisoformat(valid_until.replace('Z', '+00:00')) < datetime.now():
                    continue  # Indicator has expired
                    
                # Extract threat information
                threat_info = {
                    "id": indicator.get("id"),
                    "name": indicator.get("name"),
                    "description": indicator.get("description"),
                    "pattern": indicator.get("pattern"),
                    "valid_from": valid_from,
                    "valid_until": valid_until,
                    "confidence": indicator.get("confidence"),
                    "severity": indicator.get("severity"),
                    "labels": indicator.get("labels", []),
                    "external_references": indicator.get("external_references", [])
                }
                
                threats.append(threat_info)
        
        if threats:
            return {
                "integration": "taxii",
                "field_type": field_type,
                "value": value,
                "threat": True,
                "details": {
                    "threat_count": len(threats),
                    "threats": threats,
                    "server_url": self.server_url,
                    "collection_id": self.collection_id
                }
            }
        
        return None

    def get_collections(self):
        """Get available collections from TAXII server"""
        if self.taxii_version == "2.1":
            return self._get_collections_21()
        elif self.taxii_version == "1.1":
            return self._get_collections_11()
        else:
            return []

    def _get_collections_21(self):
        """Get collections from TAXII 2.1 server"""
        try:
            url = f"{self.server_url}collections/"
            resp = requests.get(
                url,
                headers=self._headers(),
                auth=self._auth(),
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                data = resp.json()
                return data.get("collections", [])
            else:
                if DEBUG_MODE:
                    print(f"[DEBUG] Failed to get TAXII 2.1 collections: {resp.status_code}")
                return []
                
        except Exception as e:
            if DEBUG_MODE:
                print(f"[DEBUG] Error getting TAXII 2.1 collections: {e}")
            return []

    def _get_collections_11(self):
        """Get collections from TAXII 1.1 server"""
        try:
            # TAXII 1.1 Collection Information Request XML
            collection_request_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<taxii_11:Collection_Information_Request xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" message_id="1"/>"""
            
            url = f"{self.server_url}taxii-collection-management-service"
            resp = requests.post(
                url,
                headers=self._headers(),
                auth=self._auth(),
                data=collection_request_xml,
                timeout=self.timeout
            )
            
            if resp.status_code == 200:
                # TAXII 1.1 returns XML, would need XML parsing here
                if DEBUG_MODE:
                    print(f"[DEBUG] TAXII 1.1 collections response received, but XML parsing not implemented")
                return []
            else:
                if DEBUG_MODE:
                    print(f"[DEBUG] Failed to get TAXII 1.1 collections: {resp.status_code}")
                return []
                
        except Exception as e:
            if DEBUG_MODE:
                print(f"[DEBUG] Error getting TAXII 1.1 collections: {e}")
            return []

    def test_connection(self):
        """Test connection to TAXII server"""
        try:
            collections = self.get_collections()
            if collections:
                return {
                    "status": "success",
                    "message": f"Connected to TAXII server. Found {len(collections)} collections.",
                    "collections": [c.get("id") for c in collections]
                }
            else:
                return {
                    "status": "warning",
                    "message": "Connected to TAXII server but no collections found."
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to connect to TAXII server: {str(e)}"
            }

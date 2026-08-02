"""
Windows_security.py

Normalizes raw xml logs from windows secutity.evtx files
into standardized NormalizedEvent objects.
"""

import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional, Dict, Any
from .base import BaseNormalizer, NormalizedEvent

class WindowsSecurityNormalizer(BaseNormalizer):
    """
    Parser and normalizer for Windows Security Event Logs (XML format).
    """
    NS = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

    # Mapping common Windows Security Event IDs to readable types and severities
    EVENT_METADATA = {
        "4624": {"type": "USER_LOGON_SUCCESS", "severity": "INFO"},
        "4625": {"type": "USER_LOGON_FAILURE", "severity": "MEDIUM"},
        "4648": {"type": "EXPLICIT_CREDENTIAL_LOGON", "severity": "MEDIUM"},
        "4672": {"type": "SPECIAL_PRIVILEGES_ASSIGNED", "severity": "INFO"},
        "4688": {"type": "PROCESS_CREATED", "severity": "INFO"},
        "4720": {"type": "USER_ACCOUNT_CREATED", "severity": "HIGH"},
        "4732": {"type": "USER_ADDED_TO_ADMIN_GROUP", "severity": "HIGH"},
        "1102": {"type": "AUDIT_LOG_CLEARED", "severity": "CRITICAL"}
    }

    def __init__(self):
        super().__init__(source_name="windows_security")

    def _extract_event_data_map(self, root: ET.Element) -> Dict[str, str]:
        """
        Helper method to map Windows <EventData><Data Name="Key">Value</Data></EventData>
        elements into a clean Python dictionary.
        """
        data_map = {}
        event_data_node = root.find('.//ns:EventData', self.NS)
        
        if event_data_node is not None:
            for data_elem in event_data_node.findall('ns:Data', self.NS):
                name = data_elem.attrib.get('Name')
                text = data_elem.text
                if name:
                    data_map[name] = text if text is not None else ""
                    
        return data_map



    def parse_record(self, raw_xml: str) -> Optional[NormalizedEvent]:
        """
        Parses a raw Windows Security Event XML string into a NormalizedEvent object.
        """
        try:
            root = ET.fromstring(raw_xml)

            # 1. Extract Event ID
            event_id_node = root.find('.//ns:EventID', self.NS)
            if event_id_node is None or not event_id_node.text:
                return None
            event_id = event_id_node.text.strip()

            # 2. Extract Timestamp
            time_node = root.find('.//ns:TimeCreated', self.NS)
            if time_node is not None and 'SystemTime' in time_node.attrib:
                raw_time_str = time_node.attrib['SystemTime']
                # Truncate nanoseconds to microseconds so datetime.fromisoformat can parse it
                clean_time_str = raw_time_str[:26] + "Z" if len(raw_time_str) > 26 else raw_time_str
                dt = datetime.fromisoformat(clean_time_str.replace('Z', '+00:00'))
                formatted_timestamp = self.format_timestamp(dt)
            else:
                formatted_timestamp = self.format_timestamp(datetime.utcnow())

            # 3. Lookup Metadata (Type & Severity)
            meta = self.EVENT_METADATA.get(event_id, {"type": f"UNKNOWN_EVENT_{event_id}", "severity": "INFO"})

            # 4. Parse key-value pairs inside EventData
            data_map = self._extract_event_data_map(root)

            # Extract common security attributes (handling different Windows XML field names)
            user = data_map.get("TargetUserName") or data_map.get("SubjectUserName") or "N/A"
            source_ip = data_map.get("IpAddress") or data_map.get("WorkstationName") or "N/A"
            process_name = data_map.get("NewProcessName") or data_map.get("ProcessName") or "N/A"

            # Filter out local Windows machine account noisy logs if needed (e.g. SYSTEM or ANONYMOUS)
            if user.endswith("$"):
                user = f"MACHINE_ACCT ({user})"

            # 5. Build and return the standardized NormalizedEvent object
            return NormalizedEvent(
                timestamp=formatted_timestamp,
                log_source=self.source_name,
                event_id=event_id,
                event_type=meta["type"],
                severity=meta["severity"],
                user=user,
                source_ip=source_ip,
                destination_ip="N/A",  # Local endpoint
                process_name=process_name,
                raw_payload=raw_xml[:300] + "..." if len(raw_xml) > 300 else raw_xml # Truncated raw payload for auditing
            )

        except ET.ParseError:
            # Skip records if the XML is malformed
            return None
        except Exception as e:
            # Handle unexpected structure without failing the pipeline
            print(f"[!] Exception while parsing Windows Security log record: {e}")
            return None
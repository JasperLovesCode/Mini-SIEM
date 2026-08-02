import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedEvent:
    timestamp: str  # ISO 8601 formatted string (e.g., '2026-08-02T10:00:00Z')
    log_source: str  # Source type
    event_id: str  # Event ID or status code (e.g., '4625', '404', 'SSH_FAILED')
    event_type: str  # Human-readable event category (e.g., 'USER_LOGON_FAILURE')
    severity: str  # Default severity: 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'

    # Optional Fields, will default to "N/A" if not provided
    user: Optional[str] = "N/A"
    source_ip: Optional[str] = "N/A"
    destination_ip: Optional[str] = "N/A"
    process_name: Optional[str] = "N/A"
    raw_payload: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Converts the dataclass instance into a standard python dictionary.
        Useful for feeding directly into the threat detection engine."""
        return asdict(self)

    def to_json(self) -> str:
        """Converts the dataclass instance into a JSON string.
        Useful for storage, logging, or APIs."""
        return json.dumps(self.to_dict(), default=str)


class BaseNormalizer(ABC):
    """Abstract base class that every log normalizer should inherit from."""

    def __init__(self, source_name: str):
        self.source_name = source_name

    @abstractmethod
    def parse_record(self, raw_record: Any) -> Optional[NormalizedEvent]:
        """Must be implemented by subclasses to parse specific log formats."""
        pass

    def format_timestamp(self, dt_obj: datetime) -> str:
        """Utility Method: Takes a datetime object and normalizes it to UTC ISO 8601 string format.
        Inherited by all child normalizers to ensure consistent timestamps across all logs.
        """
        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        return dt_obj.isoformat()
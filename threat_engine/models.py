import json
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

@dataclass
class Alert:
    rule_name: str
    severity: str
    description: str
    timestamp: str
    attacker_ip: Optional[str] = "N/A"
    target_user: Optional[str] = "N/A"
    log_source: str = "windows_security"

    def to_dict(self) -> Dict[str, Any]:
        """Converts the dataclass instance into a standard python dictionary.
        Useful for feeding directly into the threat detection engine."""
        return asdict(self)
    
    def to_json(self) -> str:
        """Converts the dataclass instance into a JSON string.
        Useful for storage, logging, or APIs."""
        return json.dumps(self.to_dict(), default=str)
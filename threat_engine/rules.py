from datetime import datetime, timezone
from typing import List, Dict, Optional
from normalizers.base import NormalizedEvent
from threat_engine.models import Alert

class DetectionEngine:
    def __init__(self):
        # Initialize a dictionary to track failed logon attempts per user.
        self.failed_logons: Dict[str, List[datetime]] = {}

    def _parse_iso_timestamp(self, ts_str: str) -> datetime:
        """Parse an ISO 8601 timestamp string into a datetime object."""
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def evaluate_event(self, event: NormalizedEvent) -> List[Alert]:
        """Runs an incoming normalized event against all registered rules."""
        alerts = []

        # Run individual rule checks
        bf_alert = self.check_brute_force(event)
        if bf_alert:
            alerts.append(bf_alert)

        priv_alert = self.check_privilege_escalation(event)
        if priv_alert:
            alerts.append(priv_alert)

        tamper_alert = self.check_log_tampering(event)
        if tamper_alert:
            alerts.append(tamper_alert)

        return alerts

    def check_brute_force(self, event: NormalizedEvent) -> Optional[Alert]:
        """
        Rule: Trigger alert if >= 5 USER_LOGON_FAILURE (Event 4625) 
        occur within 60 seconds from the same IP.
        """
        if event.event_id != "4625" or event.source_ip in ("N/A", "", None):
            return None

        ip = event.source_ip
        event_time = self._parse_iso_timestamp(event.timestamp)

        if ip not in self.failed_logons:
            self.failed_logons[ip] = []

        # Append current failure timestamp
        self.failed_logons[ip].append(event_time)

        # Sliding window filter: Keep timestamps within the last 60 seconds
        window_start = event_time.timestamp() - 60
        self.failed_logons[ip] = [
            t for t in self.failed_logons[ip] 
            if t.timestamp() >= window_start
        ]

        # Trigger alert if threshold met
        if len(self.failed_logons[ip]) >= 5:
            # Clear or reset window to prevent continuous alert spamming on every subsequent failure
            count = len(self.failed_logons[ip])
            self.failed_logons[ip] = [] 
            
            return Alert(
                rule_name="BRUTE_FORCE_DETECTED",
                severity="HIGH",
                description=f"Detected {count} failed logon attempts from IP {ip} within 60 seconds.",
                timestamp=event.timestamp,
                attacker_ip=ip,
                target_user=event.user,
                log_source=event.log_source
            )
        return None

    def check_privilege_escalation(self, event: NormalizedEvent) -> Optional[Alert]:
        """Rule: Trigger alert when a user is added to local Admin Group (Event 4732)."""
        if event.event_id == "4732":
            return Alert(
                rule_name="PRIVILEGE_ESCALATION_ADMIN_ADDED",
                severity="HIGH",
                description=f"User '{event.user}' was added to a local security-enabled administrative group.",
                timestamp=event.timestamp,
                attacker_ip=event.source_ip,
                target_user=event.user,
                log_source=event.log_source
            )
        return None

    def check_log_tampering(self, event: NormalizedEvent) -> Optional[Alert]:
        """Rule: Trigger CRITICAL alert if Windows Audit Logs are cleared (Event 1102)."""
        if event.event_id == "1102":
            return Alert(
                rule_name="AUDIT_LOG_CLEARED",
                severity="CRITICAL",
                description=f"The Windows Security audit log was cleared by user '{event.user}'.",
                timestamp=event.timestamp,
                attacker_ip=event.source_ip,
                target_user=event.user,
                log_source=event.log_source
            )
        return None

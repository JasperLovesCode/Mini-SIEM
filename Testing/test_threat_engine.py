import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from normalizers.base import NormalizedEvent
from threat_engine.rules import DetectionEngine


from datetime import datetime, timezone
from normalizers.base import NormalizedEvent
from threat_engine.rules import DetectionEngine

def test_engine():
    engine = DetectionEngine()
    print("=== Testing Detection Engine Rules ===\n")

    # --- Test 1: Privilege Escalation ---
    priv_event = NormalizedEvent(
        timestamp="2026-08-02T12:00:00Z",
        log_source="windows_security",
        event_id="4732",
        event_type="USER_ADDED_TO_ADMIN_GROUP",
        severity="HIGH",
        user="attacker_account",
        source_ip="192.168.1.50"
    )
    alerts = engine.evaluate_event(priv_event)
    print(f"[+] Privilege Escalation Alert Generated: {len(alerts) == 1}")
    if alerts:
        print(alerts[0].to_json())

    # --- Test 2: Log Tampering ---
    tamper_event = NormalizedEvent(
        timestamp="2026-08-02T12:01:00Z",
        log_source="windows_security",
        event_id="1102",
        event_type="AUDIT_LOG_CLEARED",
        severity="CRITICAL",
        user="rogue_admin",
        source_ip="10.0.0.15"
    )
    alerts = engine.evaluate_event(tamper_event)
    print(f"\n[+] Log Tampering Alert Generated: {len(alerts) == 1}")
    if alerts:
        print(alerts[0].to_json())

    # --- Test 3: Brute Force (5 Failures within 60 Seconds) ---
    print("\n[+] Simulating 5 rapid failed logons for Brute-Force check...")
    bf_alerts = []
    for i in range(5):
        failure_event = NormalizedEvent(
            timestamp=f"2026-08-02T12:02:0{i}Z",
            log_source="windows_security",
            event_id="4625",
            event_type="USER_LOGON_FAILURE",
            severity="MEDIUM",
            user="administrator",
            source_ip="185.220.101.5"
        )
        res = engine.evaluate_event(failure_event)
        if res:
            bf_alerts.extend(res)

    print(f"[+] Brute-Force Alert Triggered: {len(bf_alerts) == 1}")
    if bf_alerts:
        print(bf_alerts[0].to_json())

if __name__ == "__main__":
    test_engine()
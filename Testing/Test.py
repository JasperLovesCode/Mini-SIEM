import json
import os
import sys
from typing import List

# Ensure the root folder is accessible for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Evtx.Evtx import Evtx
from normalizers.windows_security import WindowsSecurityNormalizer
from threat_engine.rules import DetectionEngine
from threat_engine.models import Alert

def process_and_detect(evtx_path: str, max_records: int = 1000):
    """
    Parses a real .evtx log file, normalizes the security events,
    and runs them through the Threat Engine to detect suspicious behavior.
    """
    if not os.path.exists(evtx_path):
        print(f"[!] Error: Log file not found at '{evtx_path}'")
        return

    normalizer = WindowsSecurityNormalizer()
    engine = DetectionEngine()
    
    generated_alerts: List[Alert] = []
    processed_count = 0

    print(f"[*] Ingesting and analyzing real security log: {evtx_path} ...")

    with Evtx(evtx_path) as log:
        for record in log.records():
            try:
                # 1. Extract raw XML from binary EVTX record
                raw_xml = record.xml()

                # 2. Normalize raw XML into standard NormalizedEvent object
                event = normalizer.parse_record(raw_xml)
                if not event:
                    continue
                
                processed_count += 1

                # 3. Pass normalized event to Detection Engine
                alerts = engine.evaluate_event(event)
                if alerts:
                    generated_alerts.extend(alerts)

                # Stop after max_records to prevent long wait times during testing
                if processed_count >= max_records:
                    break

            except Exception as e:
                # Skip corrupted individual records
                continue

    print(f"[+] Successfully evaluated {processed_count} events!")
    print(f"[!] Total Threats/Alerts Detected: {len(generated_alerts)}\n")

    # --- PRINT DETECTED ALERTS ---
    if generated_alerts:
        print("=" * 60)
        print("SECURITY ALERTS GENERATED:")
        print("=" * 60)
        for alert in generated_alerts:
            print(alert.to_json())
            print("-" * 60)
    else:
        print("[*] No threats detected based on current active rules.")

    # --- SAVE ALERTS TO A JSON FILE ---
    output_file = "logs/threat_alerts_output.json"
    alerts_data = [alert.to_dict() for alert in generated_alerts]
    with open(output_file, "w") as f:
        json.dump(alerts_data, f, indent=2)

    print(f"\n[+] Saved generated alerts to: '{output_file}'")


if __name__ == "__main__":
    # Point to your binary log file inside logs/
    LOG_FILE_PATH = "logs/Security.evtx"
    
    # Analyze the first 1000 records
    process_and_detect(LOG_FILE_PATH, max_records=1000)
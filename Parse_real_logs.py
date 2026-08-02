import json
import os
from Evtx.Evtx import Evtx
from normalizers.windows_security import WindowsSecurityNormalizer


def process_evtx_file(evtx_path: str, max_records: int = 50):
    """Reads a binary .evtx file, normalizes records, and prints parsed JSON events."""
    if not os.path.exists(evtx_path):
        print(f"❌ Error: Log file not found at '{evtx_path}'")
        return

    normalizer = WindowsSecurityNormalizer()
    normalized_events = []
    
    print(f"🔍 Reading binary log file: {evtx_path} ...")

    # Open the binary .evtx file
    with Evtx(evtx_path) as log:
        for record in log.records():
            try:
                # Extract raw XML string from the record
                raw_xml = record.xml()

                # Pass XML to your normalizer
                event = normalizer.parse_record(raw_xml)

                if event:
                    normalized_events.append(event)
                    
                # Limit count for testing so your console doesn't get flooded
                if len(normalized_events) >= max_records:
                    break

            except Exception as e:
                # Defensive parsing: skip corrupted individual records
                continue

    print(f"✅ Successfully normalized {len(normalized_events)} events!\n")

    # --- PRINT SAMPLE RESULTS ---
    print("=" * 60)
    print(f"SAMPLE NORMALIZED EVENT (1 of {len(normalized_events)}):")
    print("=" * 60)
    if normalized_events:
        print(normalized_events[0].to_json())
    print("=" * 60)

    # --- SAVE OUTPUT TO A JSON FILE ---
    output_file = "logs/normalized_output.json"
    json_data = [event.to_dict() for event in normalized_events]

    with open(output_file, "w") as f:
        json.dump(json_data, f, indent=2)

    print(f"\n💾 Saved all {len(normalized_events)} normalized events to: '{output_file}'")


if __name__ == "__main__":
    # Point to your local copied log file
    LOG_FILE_PATH = "logs/Security.evtx"
    
    # Process the first 50 events for quick testing
    process_evtx_file(LOG_FILE_PATH, max_records=50)
import unittest
from normalizers.windows_security import WindowsSecurityNormalizer


class TestWindowsSecurityNormalizer(unittest.TestCase):

    def setUp(self):
        self.normalizer = WindowsSecurityNormalizer()
        self.mock_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-08-02T10:15:30.123456Z" />
  </System>
  <EventData>
    <Data Name="TargetUserName">bad_actor</Data>
    <Data Name="IpAddress">185.220.101.5</Data>
  </EventData>
</Event>"""

    def test_failed_logon_parsing(self):
        event = self.normalizer.parse_record(self.mock_xml)

        # Print visual separator
        print("\n" + "=" * 60)
        print("INPUT (RAW WINDOWS XML):")
        print("=" * 60)
        print(self.mock_xml)

        print("\n" + "=" * 60)
        print("OUTPUT (NORMALIZED JSON):")
        print("=" * 60)

        # Type check guard for Pylance / type checkers
        assert event is not None

        # Print the normalized event formatted as JSON
        print(event.to_json())
        print("=" * 60 + "\n")

        # Verify parsing results match expected schema output
        self.assertEqual(event.event_id, "4625")
        self.assertEqual(event.event_type, "USER_LOGON_FAILURE")
        self.assertEqual(event.severity, "MEDIUM")
        self.assertEqual(event.user, "bad_actor")
        self.assertEqual(event.source_ip, "185.220.101.5")
        self.assertEqual(event.log_source, "windows_security")

    def test_invalid_xml_handling(self):
        # Ensure invalid XML gracefully returns None without crashing
        event = self.normalizer.parse_record("<Invalid>XML string</NotClosed>")
        self.assertIsNone(event)


if __name__ == "__main__":
    unittest.main()
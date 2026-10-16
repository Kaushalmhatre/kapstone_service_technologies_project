import unittest
from app.engine import analyze_logs

class EngineTests(unittest.TestCase):
    def test_empty_message_is_skipped_and_summary_counts(self):
        result=analyze_logs([{"message":"MFA challenge passed successfully","event_type":"authentication","severity":"low"},{"message":""}])
        self.assertEqual(result["summary"]["total_events"],1)
        self.assertEqual(len(result["events"]),1)
    def test_suspicious_auth_chain_correlates(self):
        logs=[
          {"event_id":"A","timestamp":"2026-10-16T08:10:00Z","event_type":"authentication","source_ip":"198.51.100.24","asset":"vpn-1","severity":"high","message":"Multiple failed login attempts against admin account"},
          {"event_id":"B","timestamp":"2026-10-16T08:15:00Z","event_type":"access","source_ip":"198.51.100.24","asset":"finance-1","severity":"critical","message":"Privilege escalation detected for account without approval"}
        ]
        result=analyze_logs(logs)
        self.assertEqual(result["summary"]["total_events"],2)
        self.assertGreaterEqual(len(result["incidents"]),1)
        self.assertTrue(all("compliance" in e for e in result["events"]))
    def test_normalized_defaults(self):
        result=analyze_logs([{"message":"Routine system health check completed"}])
        event=result["events"][0]
        self.assertEqual(event["event_type"],"unknown")
        self.assertEqual(event["severity"],"medium")
        self.assertIn("risk_score",event)

if __name__ == '__main__': unittest.main()

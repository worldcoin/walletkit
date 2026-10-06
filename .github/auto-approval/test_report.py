import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import gate
import report


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.verdict = {"head": "abc123", "evidence": "hash", "approve": True, "reason": "Ready",
                        "review_coverage": "CodeRabbit and Copilot completed",
                        "discussion_resolution": "Resolved", "independent_review": "Passed",
                        "policy_checks": "Passed"}

    def test_report_separates_recommendation_from_actual_approval(self):
        body = report.render_report(self.verdict, "Review complete.",
                                    {"status": "withheld", "reason": "Evidence changed"}, "https://example.com/run")
        self.assertIn("Approval withheld", body)
        self.assertIn("Evidence changed", body)
        self.assertIn("recommendation: **approve**", body)
        self.assertIn("Review complete.", body)
        self.assertIn("<summary>verdict.json</summary>", body)
        self.assertIn("CodeRabbit and Copilot completed", body)
        self.assertIn("abc123", body)

    def test_public_output_escapes_redacts_and_bounds_agent_text(self):
        verdict = self.verdict | {"reason": "secret </pre><img src=x> @team"}
        body = report.render_report(verdict, "secret </pre>" + "&" * 100000,
                                    {"status": "unconfirmed", "reason": "Request failed"}, "https://example.com", ["secret"])
        self.assertNotIn("secret", body)
        self.assertNotIn("<img", body)
        self.assertNotIn("@team", body)
        self.assertIn("[redacted]", body)
        self.assertIn("Approval not confirmed", body)
        self.assertLess(len(body), 65536)

    @patch("gate.api")
    @patch("gate.pages")
    def test_upsert_edits_only_bots_own_report(self, pages, api):
        api.return_value = {"login": "bot"}
        spoof = {"id": 1, "user": {"login": "author"}, "body": gate.REPORT_MARKER}
        own = {"id": 2, "user": {"login": "bot"}, "body": gate.REPORT_MARKER + " old report"}
        pages.return_value = [spoof, own]
        report.publish("owner/repo", 1, "bot", "report")
        api.assert_called_with("repos/owner/repo/issues/comments/2", {"body": "report"}, method="PATCH")
        pages.return_value = [spoof]
        report.publish("owner/repo", 1, "bot", "report")
        api.assert_called_with("repos/owner/repo/issues/1/comments", {"body": "report"})
        api.return_value = {"login": "wrong"}
        with self.assertRaisesRegex(RuntimeError, "credential"):
            report.publish("owner/repo", 1, "bot", "report")

    def test_report_filter_keeps_other_bot_and_human_comments(self):
        self.assertTrue(gate.is_report({"user": {"login": "bot"}, "body": gate.REPORT_MARKER}, "bot"))
        for login, body in [("author", gate.REPORT_MARKER), ("bot", "Review concern"), ("bot", None)]:
            self.assertFalse(gate.is_report({"user": {"login": login}, "body": body}, "bot"))

    def test_final_response_excludes_intermediate_text_thinking_and_tools(self):
        def assistant(reason, text):
            return {"type": "message_end", "message": {"role": "assistant", "stopReason": reason,
                    "content": [{"type": "text", "text": text}, {"type": "thinking", "thinking": "private"}]}}
        events = [assistant("toolUse", "Investigating"), {"type": "tool_execution_end", "result": "private"},
                  assistant("stop", "Final public summary")]
        command = ["jq", "-nr", "-f", str(Path(__file__).with_name("final-response.jq"))]
        result = subprocess.run(command, input="\n".join(map(json.dumps, events)),
                                text=True, capture_output=True, timeout=5, check=True)
        self.assertEqual(result.stdout.strip(), "Final public summary")
        events.append(assistant("error", "Partial response"))
        result = subprocess.run(command, input="\n".join(map(json.dumps, events)),
                                text=True, capture_output=True, timeout=5, check=True)
        self.assertEqual(result.stdout.strip(), "")

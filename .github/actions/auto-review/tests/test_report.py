import os
import tempfile
import unittest
from unittest import mock

from auto_review import report, state
from support import FakeGithub, config, pull


class ReportTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        os.environ["RUNNER_TEMP"] = temp.name

    def report(self, **overrides) -> list[tuple[str, str]]:
        client = FakeGithub(pull())
        with mock.patch.object(report.github, "Github", return_value=client):
            report.run(config(**overrides))
        return client.comments

    def test_an_ineligible_pull_request_posts_nothing(self):
        state.write_text("answer.md", "Approved: yes.")
        self.assertEqual(self.report(pr_head_repo="someone/fork"), [])

    def test_the_answer_is_posted_with_the_decision(self):
        state.write_text("answer.md", "Approved: yes, a small change.")
        state.write_json("decision", {"score": 0.9, "model": "jev"})
        body = self.report()[0][1]
        self.assertIn("Approved: yes, a small change.", body)
        self.assertIn("Decision (jev): 0.9", body)

    def test_the_answer_is_posted_when_the_screen_never_recorded_a_result(self):
        # The screen failed and failed open; the review ran, so its answer must be posted.
        state.write_text("answer.md", "Approved: no, large surface.")
        body = self.report()[0][1]
        self.assertIn("Approved: no, large surface.", body)
        self.assertIn("No approval", body)

    def test_a_rejected_pull_request_posts_the_screen_result(self):
        state.write_json("screen", {"score": 0.9, "model": "jev"})
        body = self.report()[0][1]
        self.assertIn("rejected", body)
        self.assertIn("No approval", body)

    def test_a_missing_answer_posts_no_approval(self):
        body = self.report()[0][1]
        self.assertIn("No approval", body)


if __name__ == "__main__":
    unittest.main()

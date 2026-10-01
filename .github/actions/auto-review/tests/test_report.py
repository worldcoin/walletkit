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

    def report(self) -> list[tuple[str, str]]:
        client = FakeGithub(pull())
        with mock.patch.object(report.github, "Github", return_value=client):
            report.run(config())
        return client.comments

    def test_no_screen_state_posts_nothing(self):
        self.assertEqual(self.report(), [])

    def test_an_ineligible_pull_request_posts_nothing(self):
        state.write_json("screen", {"eligible": False})
        self.assertEqual(self.report(), [])

    def test_a_rejected_pull_request_posts_the_screen_result(self):
        state.write_json("screen", {"eligible": True, "score": 0.9, "model": "jev"})
        body = self.report()[0][1]
        self.assertIn("rejected", body)
        self.assertIn("No approval", body)

    def test_the_answer_is_posted_with_the_decision(self):
        state.write_json("screen", {"eligible": True, "score": 0.1, "model": "jev"})
        state.write_text("answer.md", "Approved: yes, a small change.")
        state.write_json("decision", {"score": 0.9, "model": "jev"})
        body = self.report()[0][1]
        self.assertIn("Approved: yes, a small change.", body)
        self.assertIn("Decision (jev): 0.9", body)

    def test_a_screen_failure_after_eligibility_still_posts_the_answer(self):
        state.write_json("screen", {"eligible": True, "score": None, "model": None})
        state.write_text("answer.md", "Approved: no, large surface.")
        body = self.report()[0][1]
        self.assertIn("Approved: no, large surface.", body)
        self.assertIn("No approval", body)


if __name__ == "__main__":
    unittest.main()

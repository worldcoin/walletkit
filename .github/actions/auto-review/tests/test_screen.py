import os
import tempfile
import unittest
from unittest import mock

from auto_review import screen, state
from support import FakeGithub, config, pull


class ScreenTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        os.environ["RUNNER_TEMP"] = self.temp.name
        self.output = os.path.join(self.temp.name, "output")
        os.environ["GITHUB_OUTPUT"] = self.output

    def output_value(self, name):
        with open(self.output) as output:
            for line in output:
                if line.startswith(f"{name}="):
                    return line.strip().split("=", 1)[1]
        return None

    def test_a_crashing_screen_still_runs_the_review(self):
        with mock.patch.object(screen.github, "Github", side_effect=RuntimeError("boom")):
            screen.run(config())
        self.assertEqual(self.output_value("run_review"), "true")

    def test_a_high_score_rejects(self):
        with mock.patch.object(screen.github, "Github", return_value=FakeGithub(pull())):
            with mock.patch.object(screen.jev, "ask", return_value=(0.9, "jev")):
                screen.run(config())
        self.assertEqual(self.output_value("run_review"), "false")
        self.assertEqual(state.read_json("screen"), {"score": 0.9, "model": "jev"})

    def test_a_low_score_runs_the_review(self):
        with mock.patch.object(screen.github, "Github", return_value=FakeGithub(pull())):
            with mock.patch.object(screen.jev, "ask", return_value=(0.1, "jev")):
                screen.run(config())
        self.assertEqual(self.output_value("run_review"), "true")

    def test_a_missing_answer_runs_the_review(self):
        with mock.patch.object(screen.github, "Github", return_value=FakeGithub(pull())):
            with mock.patch.object(screen.jev, "ask", return_value=(None, "jev")):
                screen.run(config())
        self.assertEqual(self.output_value("run_review"), "true")

    def test_a_fork_is_never_screened(self):
        # Eligibility comes from the event payload, so nothing is read and nothing is asked.
        with mock.patch.object(screen.github, "Github") as client:
            with mock.patch.object(screen.jev, "ask") as ask:
                screen.run(config(pr_head_repo="someone/fork"))
        self.assertEqual(self.output_value("run_review"), "false")
        client.assert_not_called()
        ask.assert_not_called()

    def test_a_wrong_base_branch_is_never_screened(self):
        with mock.patch.object(screen.jev, "ask") as ask:
            screen.run(config(pr_base_ref="release"))
        self.assertEqual(self.output_value("run_review"), "false")
        ask.assert_not_called()


if __name__ == "__main__":
    unittest.main()

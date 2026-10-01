import os
import tempfile
import unittest
from unittest import mock

from auto_review import decide, state
from support import config


class DecideTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        os.environ["RUNNER_TEMP"] = temp.name

    def decide(self, score):
        state.write_text("answer.md", "Approved: yes.")
        with mock.patch.object(decide.jev, "ask", return_value=(score, "jev")):
            decide.run(config())
        return state.read_json("decision")

    def test_an_approving_score_is_recorded(self):
        self.assertEqual(self.decide(0.9), {"score": 0.9, "model": "jev"})

    def test_a_below_threshold_score_is_not_recorded(self):
        self.assertIsNone(self.decide(0.5))

    def test_a_missing_score_is_not_recorded(self):
        self.assertIsNone(self.decide(None))

    def test_no_answer_is_not_recorded(self):
        with mock.patch.object(decide.jev, "ask") as ask:
            decide.run(config())
        ask.assert_not_called()
        self.assertIsNone(state.read_json("decision"))

    def test_a_failed_decision_is_not_recorded(self):
        state.write_text("answer.md", "Approved: yes.")
        with mock.patch.object(
            decide.jev, "ask", side_effect=decide.jev.JevError("no route")
        ):
            decide.run(config())
        self.assertIsNone(state.read_json("decision"))


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from auto_review import prompt


class ReviewSystemPromptTest(unittest.TestCase):
    def test_defaults_carry_the_question(self):
        text = prompt.review_system_prompt("", "")
        self.assertIn(prompt.REVIEW_QUESTION, text)
        self.assertNotIn("repository's guidelines", text)

    def test_guidelines_and_policy_are_included(self):
        text = prompt.review_system_prompt("Preserve the on-disk format.", "Never approve lock bumps.")
        self.assertIn("Preserve the on-disk format.", text)
        self.assertIn("Never approve lock bumps.", text)


class ScreenStateTest(unittest.TestCase):
    def test_every_field_is_present(self):
        state = prompt.screen_state("title", "body", "commits", "guidelines", "policy", "diff")
        self.assertEqual(
            set(state), {"title", "body", "commits", "guidelines", "policy", "diff"}
        )

    def test_long_fields_are_truncated(self):
        state = prompt.screen_state("t", "x" * (prompt.MAX_BODY + 1), "", "", "", "d" * (prompt.MAX_DIFF + 1))
        self.assertEqual(len(state["body"]), prompt.MAX_BODY)
        self.assertEqual(len(state["diff"]), prompt.MAX_DIFF)


class ReadRepoFileTest(unittest.TestCase):
    def test_missing_file_is_empty(self):
        self.assertEqual(prompt.read_repo_file("/does/not/exist", "AGENTS.md", 100), "")

    def test_file_is_read_and_bounded(self):
        with tempfile.TemporaryDirectory() as workspace:
            Path(workspace, "AGENTS.md").write_text("abcdef")
            self.assertEqual(prompt.read_repo_file(workspace, "AGENTS.md", 3), "abc")


if __name__ == "__main__":
    unittest.main()

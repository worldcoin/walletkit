import os
import subprocess
import tempfile
import unittest
from unittest import mock

from auto_review import review, state
from support import config


class ReviewTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        os.environ["RUNNER_TEMP"] = temp.name

    def test_the_answer_is_captured_from_stdout(self):
        result = subprocess.CompletedProcess([], 0, stdout="Approved: yes.", stderr="")
        with mock.patch.object(review.subprocess, "run", return_value=result):
            review.run(config())
        self.assertEqual(state.read_text("answer.md"), "Approved: yes.")

    def test_a_non_zero_exit_fails(self):
        result = subprocess.CompletedProcess([], 1, stdout="", stderr="boom")
        with mock.patch.object(review.subprocess, "run", return_value=result):
            with self.assertRaises(review.ReviewError):
                review.run(config())

    def test_the_agent_cannot_write_the_runner_command_files(self):
        os.environ["GITHUB_ENV"] = os.path.join(self.temp_dir(), "env")
        os.environ["GITHUB_OUTPUT"] = os.path.join(self.temp_dir(), "output")
        result = subprocess.CompletedProcess([], 0, stdout="Approved: yes.", stderr="")
        with mock.patch.object(review.subprocess, "run", return_value=result) as run:
            review.run(config())
        environment = run.call_args.kwargs["env"]
        for name in review.RUNNER_COMMAND_FILES:
            self.assertNotIn(name, environment)

    def test_the_command_includes_the_skills_directory_when_present(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        os.makedirs(os.path.join(workspace.name, ".agents/skills"))
        command = review.command_for(config(workspace=workspace.name))
        self.assertIn("--skill", command)
        self.assertIn(os.path.join(workspace.name, ".agents/skills"), command)

    def temp_dir(self) -> str:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        return temp.name


if __name__ == "__main__":
    unittest.main()

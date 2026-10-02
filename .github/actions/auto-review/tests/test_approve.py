import os
import tempfile
import unittest
from unittest import mock

from auto_review import approve, state
from support import FakeGithub, config, pull


class GuardsTest(unittest.TestCase):
    def guards(self, request=None, files=None, reviews=None, **overrides):
        client = FakeGithub(request or pull(), files, reviews)
        return approve.guards(config(**overrides), client)

    def test_a_clean_pull_has_no_problems(self):
        self.assertEqual(self.guards(), [])

    def test_a_draft_is_refused(self):
        self.assertIn("it is a draft", self.guards(pull(draft=True)))

    def test_the_bot_as_author_is_refused(self):
        self.assertIn("the bot is the author", self.guards(pull(user={"login": "wld-walletkit-bot"})))

    def test_an_external_author_is_refused(self):
        problems = self.guards(pull(user={"login": "stranger"}, author_association="NONE"))
        self.assertTrue(any("not a collaborator" in problem for problem in problems))

    def test_a_workflow_change_is_refused(self):
        problems = self.guards(files=[".github/workflows/ci.yml", "src/lib.rs"])
        self.assertIn("a changed file is under .github", problems)

    def test_a_moved_head_is_refused(self):
        self.assertIn("the head moved", self.guards(expected_head="different-sha"))

    def test_a_fork_is_refused(self):
        request = pull(head={"repo": {"full_name": "someone/fork"}, "sha": "head-sha"})
        self.assertIn("the head is not a branch of this repository", self.guards(request))

    def test_an_already_approved_head_is_refused(self):
        reviews = [
            {"user": {"login": "wld-walletkit-bot"}, "state": "APPROVED", "commit_id": "head-sha"}
        ]
        self.assertIn("this head is already approved", self.guards(reviews=reviews))


class ApproveTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        os.environ["RUNNER_TEMP"] = temp.name

    def test_no_decision_does_not_approve(self):
        with mock.patch.object(approve.github, "Github") as client:
            approve.run(config())
        client.assert_not_called()

    def test_a_decision_below_the_threshold_does_not_approve(self):
        state.write_json("decision", {"score": 0.5, "model": "jev"})
        with mock.patch.object(approve.github, "Github") as client:
            approve.run(config())
        client.assert_not_called()

    def test_an_approving_decision_submits_an_approval(self):
        state.write_json("decision", {"score": 0.9, "model": "jev"})
        client = FakeGithub(pull())
        with mock.patch.object(approve.github, "Github", return_value=client):
            approve.run(config())
        self.assertEqual(client.approvals, [("1", "head-sha", "Risk agent: jev approved this at 0.9.")])


if __name__ == "__main__":
    unittest.main()

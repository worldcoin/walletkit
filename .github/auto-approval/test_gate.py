import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import gate


class ApprovalGateTests(unittest.TestCase):
    def setUp(self):
        self.pr = {"state": "open", "draft": False, "base": {"ref": "main", "sha": "base"},
                   "head": {"sha": "head", "repo": {"full_name": "owner/repo"}},
                   "user": {"login": "author"},
                   "labels": [], "changed_files": 1, "title": "Fix", "body": "Description"}
        self.files = [{"filename": "src/lib.rs"}]
        self.reviews = []
        self.discussions = []
        self.permission = "write"

    def check(self):
        gate.eligibility(self.pr, self.files, self.reviews, self.discussions, "owner/repo", "bot",
                         self.permission)

    def test_author_without_write_access_blocks(self):
        self.permission = "admin"
        self.check()
        for permission in ["read", "none"]:
            with self.subTest(permission=permission):
                self.permission = permission
                with self.assertRaisesRegex(gate.Ineligible, f"write access.*{permission}"):
                    self.check()

    @patch("gate.api")
    def test_author_permission_uses_repository_access(self, api):
        api.return_value = {"permission": "write", "role_name": "maintain"}
        self.assertEqual(gate.author_permission("owner/repo", self.pr), "write")
        api.assert_called_once_with("repos/owner/repo/collaborators/author/permission")

    def test_review_requirements_are_left_to_agent_policy(self):
        self.check()
        self.reviews = [{"state": "COMMENTED", "commit_id": "old", "user": {"login": "any-agent"},
                         "body": "Quota exhausted"}]
        self.check()

    def test_unresolved_outdated_thread_blocks(self):
        self.discussions = [{"isResolved": False, "isOutdated": True}]
        with self.assertRaisesRegex(gate.Ineligible, "Unresolved"):
            self.check()

    def test_resolved_thread_is_left_to_agent_for_substantive_assessment(self):
        self.discussions = [{"isResolved": True, "isOutdated": False}]
        self.check()

    def test_comment_does_not_clear_changes_requested(self):
        self.reviews = [{"state": state, "user": {"login": "reviewer"}, "commit_id": "head"}
                        for state in ["CHANGES_REQUESTED", "COMMENTED"]]
        with self.assertRaisesRegex(gate.Ineligible, "Outstanding"):
            self.check()
        self.reviews.append({"state": "DISMISSED", "user": {"login": "reviewer"}, "commit_id": "head"})
        self.check()

    def test_policy_rename_out_of_protected_path_blocks(self):
        for path in [".github/workflows/check.yml", ".code-review.md", "src/AGENTS.md", "CLAUDE.md"]:
            with self.subTest(path=path):
                self.files[0]["previous_filename"] = path
                with self.assertRaisesRegex(gate.Ineligible, "policy changes"):
                    self.check()

    def test_closed_draft_fork_deleted_head_and_opt_out_block(self):
        original = copy.deepcopy(self.pr)
        variants = [{"state": "closed"}, {"draft": True}, {"head": {"repo": None}},
                    {"head": {"repo": {"full_name": "other/repo"}}},
                    {"labels": [{"name": "no-auto-approve"}]}, {"changed_files": 2}]
        for fields in variants:
            with self.subTest(fields=fields):
                self.pr = original | fields
                with self.assertRaises(gate.Ineligible):
                    self.check()

    def test_only_current_bot_approval_prevents_duplicate(self):
        self.reviews = [{"state": "APPROVED", "user": {"login": "bot"}, "commit_id": "old"}]
        self.check()
        self.reviews[0]["commit_id"] = "head"
        with self.assertRaisesRegex(gate.Ineligible, "already approved"):
            self.check()

    def test_fingerprint_binds_policy_commit_and_discussion(self):
        evidence = {"head": "a", "base": "b", "policy_files": {"rule": "sha-one"}, "comments": ["fixed"]}
        expected = gate.fingerprint(evidence)
        self.assertEqual(expected, gate.fingerprint(dict(reversed(list(evidence.items())))))
        for key in evidence:
            with self.subTest(key=key):
                self.assertNotEqual(expected, gate.fingerprint(evidence | {key: "changed"}))

    def test_verdict_requires_boolean_and_bound_evidence(self):
        verdict = {"head": "head", "evidence": "hash", "approve": True, "reason": "OK",
                   "review_coverage": "OK", "discussion_resolution": "OK",
                   "independent_review": "OK", "policy_checks": "OK"}
        gate.validate_verdict(verdict, "head", "hash")
        for fields in [{"approve": "true"}, {"extra": True}, {"policy_checks": ""}]:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                gate.validate_verdict(verdict | fields, "head", "hash")
        gate.validate_verdict(verdict | {"approve": False}, "head", "hash")
        for fields in [{"head": "new"}, {"evidence": "other"}]:
            with self.subTest(fields=fields), self.assertRaises(gate.Ineligible):
                gate.validate_verdict(verdict | fields, "head", "hash")

    @patch("gate.api")
    def test_rest_lists_are_paginated(self, api):
        api.return_value = [[1, 2], [3]]
        self.assertEqual(gate.pages("repos/owner/repo/pulls/1/reviews"), [1, 2, 3])
        self.assertTrue(api.call_args.kwargs["paginate"])

    @patch("gate.api")
    def test_thread_pages_and_incomplete_discussion(self, api):
        def response(nodes, more, cursor):
            return {"data": {"repository": {"pullRequest": {"reviewThreads": {
                "nodes": nodes, "pageInfo": {"hasNextPage": more, "endCursor": cursor}}}}}}
        thread = {"comments": {"pageInfo": {"hasNextPage": False}}}
        api.side_effect = [response([thread], True, "next"), response([thread], False, None)]
        self.assertEqual(len(gate.threads("owner/repo", 1)), 2)
        self.assertEqual(api.call_args.args[1]["variables"]["cursor"], "next")
        thread["comments"]["pageInfo"]["hasNextPage"] = True
        api.side_effect = [response([thread], False, None)]
        with self.assertRaisesRegex(gate.Ineligible, "100 comments"):
            gate.threads("owner/repo", 1)

    @patch("gate.api")
    def test_policy_comes_from_base_and_includes_ancestors_only(self, api):
        entries = [{"path": name, "mode": "100644", "sha": str(i)} for i, name in enumerate(
            [".code-review.md", "AGENTS.md", "src/AGENTS.md", "unrelated/AGENTS.md"])]
        api.return_value = {"truncated": False, "tree": entries}
        result = gate.policies("owner/repo", "trusted-base", self.files)
        self.assertEqual(result, {".code-review.md": "0", "AGENTS.md": "1", "src/AGENTS.md": "2"})
        self.assertIn("trusted-base", api.call_args_list[0].args[0])

    @patch("gate.api")
    def test_review_input_contains_readable_base_policy_files(self, api):
        api.return_value = {"encoding": "base64", "size": 4,
                            "content": base64.b64encode(b"rule").decode()}
        evidence = {"repo": "owner/repo", "policy_files": {
            ".code-review.md": "base-policy", "src/AGENTS.md": "base-instructions"}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "input"
            gate.write_review_input(evidence, root)
            self.assertEqual((root / ".code-review.md").read_text(), "rule")
            self.assertEqual((root / "src/AGENTS.md").read_text(), "rule")
            self.assertEqual(json.loads((root / "evidence.json").read_text()), evidence)
        self.assertEqual([c.args[0] for c in api.call_args_list], [
            "repos/owner/repo/git/blobs/base-policy", "repos/owner/repo/git/blobs/base-instructions"])

    @patch("gate.api")
    def test_oversized_policy_file_withholds_review(self, api):
        api.return_value = {"encoding": "base64", "size": 100001}
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(gate.Ineligible):
            gate.write_review_input({"repo": "owner/repo", "policy_files": {".code-review.md": "sha"}},
                                    Path(directory))

    @patch("gate.api")
    def test_incomplete_policy_tree_blocks(self, api):
        api.return_value = {"truncated": True}
        with self.assertRaisesRegex(gate.Ineligible, "enumerate"):
            gate.policies("owner/repo", "base", self.files)

    @patch("gate.api")
    @patch("gate.snapshot")
    def test_approval_rechecks_snapshot_and_posts_exact_commit(self, snapshot, api):
        evidence = {"head": "head", "base": "base", "comments": []}
        fingerprint = gate.fingerprint(evidence)
        verdict = {"head": "head", "evidence": fingerprint, "approve": True, "reason": "OK",
                   "review_coverage": "OK", "discussion_resolution": "OK",
                   "independent_review": "OK", "policy_checks": "OK"}
        env = {"GITHUB_REPOSITORY": "owner/repo", "BOT_LOGIN": "bot", "EXPECTED_HEAD": "head",
               "EXPECTED_FINGERPRINT": fingerprint, "GITHUB_RUN_ID": "123"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verdict/verdict.json"
            path.parent.mkdir()
            path.write_text(json.dumps(verdict))
            with patch.dict(os.environ, env), patch("sys.argv", ["gate.py", "approve", "1"]), \
                    patch("gate.Path", side_effect=lambda name: Path(directory) / name):
                snapshot.return_value = evidence | {"comments": ["new concern"]}
                gate.main()
                api.assert_not_called()
                snapshot.return_value = evidence
                api.return_value = {"login": "bot"}
                gate.main()
                self.assertEqual(api.call_args.args[1]["commit_id"], "head")
                self.assertEqual(api.call_args.args[1]["event"], "APPROVE")
                result_path = Path(directory) / "approval-result.json"
                self.assertEqual(json.loads(result_path.read_text())["status"], "approved")
                api.reset_mock()
                path.write_text(json.dumps(verdict | {"approve": False}))
                gate.main()
                api.assert_not_called()
                self.assertEqual(json.loads(result_path.read_text())["status"], "withheld")
                path.write_text(json.dumps(verdict))
                api.side_effect = RuntimeError("Request failed")
                with self.assertRaises(RuntimeError):
                    gate.main()
                self.assertEqual(json.loads(result_path.read_text())["status"], "unconfirmed")

    @patch("gate.subprocess.run")
    def test_api_failure_and_graphql_errors_are_surfaced(self, run):
        run.return_value.returncode = 1
        with self.assertRaisesRegex(RuntimeError, "GitHub request failed"):
            gate.api("graphql")
        run.return_value.returncode = 0
        run.return_value.stdout = '{"data": null, "errors": [{"message": "denied"}]}'
        with self.assertRaisesRegex(RuntimeError, "incomplete data"):
            gate.api("graphql")
        self.assertEqual(run.call_args.kwargs["timeout"], 90)


if __name__ == "__main__":
    unittest.main()

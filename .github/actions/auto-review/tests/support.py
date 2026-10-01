"""Shared fixtures for the auto-review action tests."""

from auto_review.config import Config

REPO = "worldcoin/walletkit"


def config(**overrides) -> Config:
    values = dict(
        repo=REPO,
        pull_number="1",
        expected_head="head-sha",
        workspace="/tmp",
        base_branch="main",
        bot_login="wld-walletkit-bot",
        guidelines_file="AGENTS.md",
        policy_file=".auto-approve.md",
        skills_path=".agents/skills",
        review_token="read-token",
        bot_token="bot-token",
        openrouter_api_key="openrouter-key",
        provider="openrouter",
        model="deepseek/deepseek-v4.1-flash",
        prefilter_model="typesafe/jev-1.13",
        prefilter_threshold=0.5,
        decision_model="typesafe/jev-1.13",
        decision_threshold=0.8,
    )
    values.update(overrides)
    return Config(**values)


def pull(**overrides) -> dict:
    values = {
        "title": "A small change",
        "body": "A description",
        "base": {"ref": "main"},
        "head": {"repo": {"full_name": REPO}, "sha": "head-sha"},
        "draft": False,
        "user": {"login": "contributor"},
        "author_association": "MEMBER",
    }
    values.update(overrides)
    return values


class FakeGithub:
    """Stands in for the gh wrapper; records no approval unless a test reads it."""

    def __init__(self, pull_request: dict, files: list[str] | None = None, reviews=None):
        self.pull = pull_request
        self.files = files or []
        self.review_list = reviews or []
        self.approvals = []

    def pull_request(self, number):
        return self.pull

    def changed_files(self, number):
        return list(self.files)

    def reviews(self, number):
        return list(self.review_list)

    def commit_messages(self, number):
        return "commit one"

    def diff(self, number):
        return "diff --git a/file b/file"

    def submit_approval(self, number, commit_id, body):
        self.approvals.append((number, commit_id, body))

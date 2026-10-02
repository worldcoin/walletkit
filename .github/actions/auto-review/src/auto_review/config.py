"""The action inputs, read from the environment the composite steps set."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    repo: str
    pull_number: str
    expected_head: str
    pr_head_repo: str
    pr_base_ref: str
    workspace: str
    base_branch: str
    bot_login: str
    guidelines_file: str
    policy_file: str
    skills_path: str
    review_token: str
    bot_token: str
    openrouter_api_key: str
    provider: str
    model: str
    prefilter_model: str
    prefilter_threshold: float
    decision_model: str
    decision_threshold: float

    def eligible(self) -> bool:
        """Whether this pull request may be reviewed and approved at all.

        Taken from the event payload rather than the API, so a failure to read the pull request
        cannot make an eligible run look ineligible.
        """
        return self.pr_head_repo == self.repo and self.pr_base_ref == self.base_branch

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            repo=os.environ.get("GH_REPO", ""),
            pull_number=os.environ.get("PR_NUMBER", ""),
            expected_head=os.environ.get("EXPECTED_HEAD", ""),
            pr_head_repo=os.environ.get("PR_HEAD_REPO", ""),
            pr_base_ref=os.environ.get("PR_BASE_REF", ""),
            workspace=os.environ.get("WORKSPACE") or os.environ.get("GITHUB_WORKSPACE", ""),
            base_branch=os.environ.get("BASE_BRANCH", "main"),
            bot_login=os.environ.get("BOT_LOGIN", ""),
            guidelines_file=os.environ.get("GUIDELINES_FILE", "AGENTS.md"),
            policy_file=os.environ.get("POLICY_FILE", ".auto-approve.md"),
            skills_path=os.environ.get("SKILLS_PATH", ".agents/skills"),
            review_token=os.environ.get("REVIEW_GH_TOKEN", ""),
            bot_token=os.environ.get("BOT_TOKEN", ""),
            openrouter_api_key=os.environ.get("OPENROUTER_API_KEY", ""),
            provider=os.environ.get("PROVIDER", "openrouter"),
            model=os.environ.get("MODEL", "deepseek/deepseek-v4.1-flash"),
            prefilter_model=os.environ.get("PREFILTER_MODEL", "typesafe/jev-1.13"),
            prefilter_threshold=float(os.environ.get("PREFILTER_THRESHOLD", "0.5")),
            decision_model=os.environ.get("DECISION_MODEL", "typesafe/jev-1.13"),
            decision_threshold=float(os.environ.get("DECISION_THRESHOLD", "0.8")),
        )

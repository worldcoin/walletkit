"""Pull request data and write endpoints, through the gh CLI the runner provides."""

import json
import os
import subprocess


class GithubError(RuntimeError):
    pass


class Github:
    def __init__(self, repo: str, token: str):
        self.repo = repo
        self.token = token

    def _call(self, *args: str, input: str | None = None) -> str:
        environment = {
            **os.environ,
            "GH_TOKEN": self.token,
            "GH_REPO": self.repo,
            "GH_PROMPT_DISABLED": "1",
        }
        result = subprocess.run(
            ["gh", *args], env=environment, input=input, capture_output=True, text=True
        )
        if result.returncode != 0:
            # The token travels in the environment, so the arguments are safe to report.
            raise GithubError(f"gh {args[0]} {args[1]} failed: {result.stderr.strip()}")
        return result.stdout

    def pull_request(self, number: str) -> dict:
        return json.loads(self._call("api", f"repos/{self.repo}/pulls/{number}"))

    def diff(self, number: str) -> str:
        return self._call(
            "api",
            f"repos/{self.repo}/pulls/{number}",
            "-H",
            "Accept: application/vnd.github.v3.diff",
        )

    def commit_messages(self, number: str) -> str:
        return self._call(
            "api",
            "--paginate",
            f"repos/{self.repo}/pulls/{number}/commits?per_page=100",
            "--jq",
            ".[].commit.message",
        )

    def changed_files(self, number: str) -> list[str]:
        output = self._call(
            "api",
            "--paginate",
            f"repos/{self.repo}/pulls/{number}/files?per_page=100",
            "--jq",
            ".[].filename",
        )
        return [line for line in output.splitlines() if line]

    def reviews(self, number: str) -> list[dict]:
        return json.loads(self._call("api", f"repos/{self.repo}/pulls/{number}/reviews?per_page=100"))

    def comment(self, number: str, body: str) -> None:
        try:
            self._call("pr", "comment", str(number), "--body-file", "-", "--edit-last", input=body)
        except GithubError:
            # --edit-last fails when the bot has not commented yet.
            self._call("pr", "comment", str(number), "--body-file", "-", input=body)

    def submit_approval(self, number: str, commit_id: str, body: str) -> None:
        self._call(
            "api",
            "-X",
            "POST",
            f"repos/{self.repo}/pulls/{number}/reviews",
            "-f",
            f"commit_id={commit_id}",
            "-f",
            "event=APPROVE",
            "-f",
            f"body={body}",
        )

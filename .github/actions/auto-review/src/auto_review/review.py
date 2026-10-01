"""The review: pi inspects the pull request and answers the auto-approval question."""

import os
import subprocess
import sys
from pathlib import Path

from . import prompt, state
from .config import Config

TIMEOUT_SECONDS = 900

# The runner applies these files to the steps that follow the one that writes them. The review
# agent must not be able to set environment variables, outputs or the path for the stages after it.
RUNNER_COMMAND_FILES = ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STATE")


class ReviewError(RuntimeError):
    pass


def run(config: Config) -> None:
    command = command_for(config)
    environment = {**os.environ, "GH_TOKEN": config.review_token, "GH_REPO": config.repo}
    for name in RUNNER_COMMAND_FILES:
        environment.pop(name, None)
    try:
        result = subprocess.run(
            command,
            cwd=config.workspace,
            env=environment,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise ReviewError(f"the review did not finish within {TIMEOUT_SECONDS}s") from error

    # The final message is the answer; the rest of the log stays in the run.
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        raise ReviewError(f"pi exited with {result.returncode}")

    state.write_text("answer.md", result.stdout)


def command_for(config: Config) -> list[str]:
    system_prompt = prompt.review_system_prompt(
        prompt.guidelines(config.workspace, config.guidelines_file),
        prompt.policy(config.workspace, config.policy_file),
    )
    command = [
        "pi",
        "--print",
        "--mode",
        "text",
        "--no-session",
        "--provider",
        config.provider,
        "--model",
        config.model,
        "--system-prompt",
        system_prompt,
        # The workspace is a base-branch checkout, so pi may trust its project-local files. Only
        # the skills below are wanted, so the other project-local sources stay off.
        "--approve",
        "--no-context-files",
        "--no-extensions",
        "--no-prompt-templates",
        "--no-themes",
    ]
    skills = Path(config.workspace) / config.skills_path
    if skills.exists():
        command += ["--skill", str(skills)]
    command.append(f"Review {config.repo}#{config.pull_number} and answer.")
    return command

"""The report: the review's answer and the decision as a pull request comment."""

from . import github, prompt, state
from .config import Config


def run(config: Config) -> None:
    if not config.eligible():
        # Ineligible pull requests never ran a review, so they get no comment.
        return

    screen = state.read_json("screen") or {}
    answer = state.read_text("answer.md").strip()
    if answer:
        body = f"Risk agent, on {config.expected_head}:\n\n{answer}"
    elif screen.get("score") is not None:
        body = (
            f"Risk agent: the screen ({screen['model']}, score {screen['score']}) rejected this "
            "pull request, so no review ran."
        )
    else:
        body = "Risk agent: no review answer was recorded, so no approval."

    decision = state.read_json("decision")
    if decision:
        body += (
            f"\n\nDecision ({decision['model']}): {decision['score']}, so an approval is "
            "submitted if the guards hold."
        )
    else:
        body += "\n\nNo approval is submitted."

    github.Github(config.repo, config.bot_token).comment(
        config.pull_number, body[: prompt.MAX_COMMENT]
    )

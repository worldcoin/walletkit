"""The decision: jev decides whether the review's answer is an approval."""

from . import jev, prompt, state
from .config import Config


def run(config: Config) -> None:
    # Decisions come from the review answer, which the review agent produced. The agent runs before
    # this stage with a shell in the same sandbox, so a decision file it planted must not count.
    state.remove("decision")

    answer = state.read_text("answer.md")
    if not answer.strip():
        state.notice("no review answer was recorded, so there is no decision")
        return

    try:
        score, model = jev.ask(
            config.openrouter_api_key,
            config.decision_model,
            {"answer": answer[: prompt.MAX_ANSWER]},
            "approve",
            prompt.DECISION_INSTRUCTIONS,
        )
    except jev.JevError as error:
        state.notice(f"the decision failed, so there is no approval: {error}")
        return

    if score is None:
        state.notice("the decision gave no answer, so there is no approval")
        return

    # Only an approving decision is recorded, so the presence of a decision means an approval.
    if score < config.decision_threshold:
        state.notice(f"{model} did not approve: {score} is below {config.decision_threshold}")
        return
    state.write_json("decision", {"score": score, "model": model})
    state.notice(f"{model} approved at {score}")

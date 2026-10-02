"""The screen: a cheap decision model can reject a pull request before the review runs."""

from . import github, jev, prompt, state
from .config import Config


def run(config: Config) -> None:
    run_review = True
    try:
        run_review = screen(config)
    except Exception as error:  # noqa: BLE001
        # The screen can only withhold an approval, so a screen that cannot run must not withhold
        # the review as well.
        state.notice(f"the screen failed, so the review runs: {error}")
    state.set_output("run_review", str(run_review).lower())


def screen(config: Config) -> bool:
    if not config.eligible():
        state.notice("this pull request cannot be approved automatically, so it is not reviewed")
        return False

    client = github.Github(config.repo, config.review_token)
    pull = client.pull_request(config.pull_number)

    context = prompt.screen_state(
        title=pull["title"],
        body=pull.get("body") or "",
        commits=client.commit_messages(config.pull_number),
        guidelines_text=prompt.guidelines(config.workspace, config.guidelines_file),
        policy_text=prompt.policy(config.workspace, config.policy_file),
        diff=client.diff(config.pull_number),
    )
    score, model = jev.ask(
        config.openrouter_api_key,
        config.prefilter_model,
        context,
        "reject",
        prompt.SCREEN_INSTRUCTIONS,
    )
    state.write_json("screen", {"score": score, "model": model})
    if score is None:
        state.notice("the screen gave no answer, so the review runs")
        return True
    if score >= config.prefilter_threshold:
        state.notice(
            f"{model} scored this {score}, at or above {config.prefilter_threshold}: no review"
        )
        return False
    return True

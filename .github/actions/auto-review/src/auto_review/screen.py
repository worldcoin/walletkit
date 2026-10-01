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
    client = github.Github(config.repo, config.review_token)
    pull = client.pull_request(config.pull_number)

    if (pull["head"]["repo"] or {}).get("full_name") != config.repo:
        state.write_json("screen", {"eligible": False})
        state.notice("the pull request comes from a fork, so it is never approved")
        return False

    # Record eligibility before anything else can fail, so the report still runs when the rest of
    # the screen cannot.
    state.write_json("screen", {"eligible": True, "score": None, "model": None})

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
    state.write_json("screen", {"eligible": True, "score": score, "model": model})
    if score is None:
        state.notice("the screen gave no answer, so the review runs")
        return True
    if score >= config.prefilter_threshold:
        state.notice(
            f"{model} scored this {score}, at or above {config.prefilter_threshold}: no review"
        )
        return False
    return True

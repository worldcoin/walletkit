"""The approval: guard checks, then an approval bound to the reviewed head."""

from . import github, state
from .config import Config

TRUSTED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}


def run(config: Config) -> None:
    decision = state.read_json("decision")
    if not decision or decision.get("score", 0) < config.decision_threshold:
        state.notice("there is no approving decision, so no approval")
        return

    client = github.Github(config.repo, config.bot_token)
    problems = guards(config, client)
    if problems:
        state.notice("not approving: " + "; ".join(problems))
        return

    body = f"Risk agent: {decision['model']} approved this at {decision['score']}."
    client.submit_approval(config.pull_number, config.expected_head, body)


def guards(config: Config, client: github.Github) -> list[str]:
    pull = client.pull_request(config.pull_number)
    problems = []
    if pull["base"]["ref"] != config.base_branch:
        problems.append(f"the base is {pull['base']['ref']}")
    if (pull["head"]["repo"] or {}).get("full_name") != config.repo:
        problems.append("the head is not a branch of this repository")
    if pull["draft"]:
        problems.append("it is a draft")
    if pull["user"]["login"] == config.bot_login:
        problems.append("the bot is the author")
    if pull.get("author_association") not in TRUSTED_ASSOCIATIONS:
        problems.append(f"the author is not a collaborator ({pull.get('author_association')})")
    if config.expected_head and pull["head"]["sha"] != config.expected_head:
        problems.append("the head moved")
    if any(path.startswith(".github/") for path in client.changed_files(config.pull_number)):
        problems.append("a changed file is under .github")
    if any(
        review["user"]["login"] == config.bot_login
        and review["state"] == "APPROVED"
        and review["commit_id"] == config.expected_head
        for review in client.reviews(config.pull_number)
    ):
        problems.append("this head is already approved")
    return problems

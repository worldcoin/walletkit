"""Trusted GitHub state collection and approval submission; no model policy decisions."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess


POLICY_NAMES = {"AGENTS.md", "CLAUDE.md", ".code-review.md"}
MAX_EVIDENCE_BYTES = 2_000_000


class Ineligible(Exception):
    """An expected reason to leave approval to a human."""


def api(endpoint, payload=None, paginate=False):
    command = ["gh", "api", endpoint]
    if paginate:
        command += ["--paginate", "--slurp"]
    if payload is not None:
        command += ["--input", "-"]
    result = subprocess.run(command, input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True, timeout=90)
    if result.returncode:
        raise RuntimeError(f"GitHub request failed: {endpoint} (exit {result.returncode})")
    value = json.loads(result.stdout)
    if isinstance(value, dict) and value.get("errors"):
        raise RuntimeError(f"GitHub returned incomplete data: {endpoint}")
    return value


def pages(endpoint):
    return [item for page in api(endpoint + "?per_page=100", paginate=True) for item in page]


def fingerprint(evidence):
    return hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()


def threads(repo, number):
    owner, name = repo.split("/")
    query = """query($owner:String!,$name:String!,$number:Int!,$cursor:String) {
      repository(owner:$owner,name:$name) { pullRequest(number:$number) {
        reviewThreads(first:100,after:$cursor) {
          pageInfo { hasNextPage endCursor }
          nodes { id isResolved isOutdated path
            comments(first:100) { pageInfo { hasNextPage }
              nodes { id body updatedAt author { login } originalCommit { oid } }
            }
          }
        }
      } }
    }"""
    result, cursor = [], None
    while True:
        response = api("graphql", {"query": query, "variables": {
            "owner": owner, "name": name, "number": number, "cursor": cursor}})
        connection = response["data"]["repository"]["pullRequest"]["reviewThreads"]
        for thread in connection["nodes"]:
            if thread["comments"]["pageInfo"]["hasNextPage"]:
                raise Ineligible("A discussion exceeds the supported 100 comments")
        result.extend(connection["nodes"])
        if not connection["pageInfo"]["hasNextPage"]:
            return result
        cursor = connection["pageInfo"]["endCursor"]


def eligibility(pr, files, reviews, discussions, repo, bot):
    if (pr["state"] != "open" or pr["draft"] or pr["base"]["ref"] != "main"
            or not pr["head"]["repo"] or pr["head"]["repo"]["full_name"] != repo):
        raise Ineligible("PR must be open, ready, and from this repository into main")
    if pr["author_association"] not in {"OWNER", "MEMBER", "COLLABORATOR"}:
        raise Ineligible("External contributor")
    if pr["user"]["login"] == bot:
        raise Ineligible("Approval bot authored this PR")
    if any(label["name"] == "no-auto-approve" for label in pr["labels"]):
        raise Ineligible("no-auto-approve label")
    if len(files) != pr["changed_files"]:
        raise Ineligible("Incomplete changed-file list")
    for file in files:
        for path in (file["filename"], file.get("previous_filename", file["filename"])):
            if path.startswith(".github/") or PurePosixPath(path).name in POLICY_NAMES:
                raise Ineligible("Workflow or review policy changes require human approval")
    if any(not thread["isResolved"] for thread in discussions):
        raise Ineligible("Unresolved review discussion, including outdated threads")
    latest = {}
    for review in reviews:
        if review["state"] in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest[review["user"]["login"]] = review["state"]
    if "CHANGES_REQUESTED" in latest.values():
        raise Ineligible("Outstanding changes requested")
    if any(r["user"]["login"] == bot and r["state"] == "APPROVED"
           and r["commit_id"] == pr["head"]["sha"] for r in reviews):
        raise Ineligible("This commit is already approved by the bot")


def policies(repo, base, files):
    tree = api(f"repos/{repo}/git/trees/{base}?recursive=1")
    if tree["truncated"]:
        raise Ineligible("Cannot enumerate trusted review instructions")
    directories = {PurePosixPath(".")}
    for file in files:
        for path in (file["filename"], file.get("previous_filename", file["filename"])):
            directories.update(PurePosixPath(path).parents)
    result = {}
    for entry in tree["tree"]:
        path = PurePosixPath(entry["path"])
        if path.name not in POLICY_NAMES or path.parent not in directories:
            continue
        if entry["mode"] not in {"100644", "100755"}:
            raise Ineligible("Review instructions must be regular text files")
        blob = api(f"repos/{repo}/git/blobs/{entry['sha']}")
        if blob["encoding"] != "base64" or blob["size"] > 100_000:
            raise Ineligible("Unsupported or oversized review instructions")
        result[str(path)] = base64.b64decode(blob["content"]).decode("utf-8")
    if ".code-review.md" not in result:
        raise Ineligible("No trusted .code-review.md policy")
    return result


def snapshot(repo, number, bot):
    prefix = f"repos/{repo}/pulls/{number}"
    pr = api(prefix)
    files = pages(prefix + "/files")
    reviews = pages(prefix + "/reviews")
    discussions = threads(repo, number)
    eligibility(pr, files, reviews, discussions, repo, bot)
    evidence = {"repo": repo, "number": number, "head": pr["head"]["sha"],
                "base": pr["base"]["sha"], "title": pr["title"], "body": pr["body"],
                "labels": sorted(label["name"] for label in pr["labels"]),
                "files": files, "reviews": reviews, "threads": discussions,
                "comments": pages(f"repos/{repo}/issues/{number}/comments"),
                "trusted_policy": policies(repo, pr["base"]["sha"], files)}
    if len(json.dumps(evidence).encode()) > MAX_EVIDENCE_BYTES:
        raise Ineligible("Review evidence exceeds supported size; refusing to truncate")
    current = api(prefix)
    if current["head"]["sha"] != evidence["head"] or current["base"]["sha"] != evidence["base"]:
        raise Ineligible("PR moved while collecting evidence")
    eligibility(current, files, reviews, discussions, repo, bot)
    if any(current[key] != pr[key] for key in ("title", "body", "labels")):
        raise Ineligible("PR metadata changed while collecting evidence")
    return evidence


def validate_verdict(value, expected_head, expected_fingerprint):
    fields = {"head", "evidence", "approve", "reason", "review_coverage",
              "discussion_resolution", "independent_review", "policy_checks"}
    if not isinstance(value, dict) or set(value) != fields or type(value["approve"]) is not bool:
        raise ValueError("Invalid verdict schema")
    if any(not isinstance(value[key], str) or not 1 <= len(value[key]) <= 8000
           for key in fields - {"approve"}):
        raise ValueError("Verdict evidence must be nonempty bounded text")
    if value["head"] != expected_head or value["evidence"] != expected_fingerprint:
        raise Ineligible("Verdict does not match the prepared commit and evidence")
    if not value["approve"]:
        raise Ineligible("Agent withheld approval; inspect the verdict artifact")


def output(name, value):
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        stream.write(f"{name}={value}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["prepare", "approve"])
    parser.add_argument("number", type=int)
    args = parser.parse_args()
    if args.number <= 0:
        parser.error("PR number must be positive")
    repo, bot = os.environ["GITHUB_REPOSITORY"], os.environ["BOT_LOGIN"]
    try:
        evidence = snapshot(repo, args.number, bot)
        if args.mode == "prepare":
            Path("evidence.json").write_text(json.dumps(evidence, indent=2))
            output("head", evidence["head"])
            output("fingerprint", fingerprint(evidence))
            output("eligible", "true")
            print("Eligible for agent review")
            return
        verdict_path = Path("verdict/verdict.json")
        if verdict_path.stat().st_size > 64_000:
            raise ValueError("Oversized verdict")
        validate_verdict(json.loads(verdict_path.read_text()), os.environ["EXPECTED_HEAD"],
                         os.environ["EXPECTED_FINGERPRINT"])
        if fingerprint(evidence) != os.environ["EXPECTED_FINGERPRINT"]:
            raise Ineligible("Head, base, policy, or review evidence changed during review")
        if api("user")["login"] != bot:
            raise RuntimeError("Approval credential does not match configured bot")
        api(f"repos/{repo}/pulls/{args.number}/reviews", {
            "commit_id": evidence["head"], "event": "APPROVE",
            "body": "Agent review passed the repository review policy, discussion resolution, "
                    "and independent code review. Verdict and evidence: "
                    f"https://github.com/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"})
        print("Approved reviewed commit " + evidence["head"])
    except Ineligible as error:
        print("Human review required: " + str(error))
        if args.mode == "prepare":
            output("eligible", "false")


if __name__ == "__main__":
    main()

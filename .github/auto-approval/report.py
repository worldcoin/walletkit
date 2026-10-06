"""Publish the completed agent review and the trusted approval outcome."""

import argparse
from html import escape
import json
import os
from pathlib import Path

import gate


def render_report(verdict, response, result, run_url, secrets=()):
    def safe(value, limit=3000):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[redacted]")
        # Bound before escaping so truncation cannot split an HTML entity.
        if len(value) > limit:
            value = value[:limit] + "\n[Truncated; see the run artifact for full output.]"
        return escape(value).replace("@", "@\u200b")

    status = {"approved": "Approved", "withheld": "Approval withheld",
              "unconfirmed": "Approval not confirmed"}[result["status"]]
    parts = [gate.REPORT_MARKER, f"## Agent review · {status}",
             f"<pre>{safe(result['reason'])}</pre>",
             f"Reviewed commit: <code>{safe(verdict['head'], 100)}</code> · [Workflow run]({run_url})",
             "Agent recommendation: **" + ("approve" if verdict["approve"] else "withhold approval") + "**",
             f"<pre>{safe(verdict['reason'])}</pre>",
             "### Final agent response", f"<pre>{safe(response or 'No final response was emitted.', 6000)}</pre>",
             "<details><summary>Structured review assessment</summary>\n"]
    for field, title in [("review_coverage", "Review coverage"),
                         ("discussion_resolution", "Discussion resolution"),
                         ("independent_review", "Independent review"),
                         ("policy_checks", "Repository policy")]:
        parts.append(f"<h4>{title}</h4>\n<pre>{safe(verdict[field], 2000)}</pre>")
    parts += ["</details>", "<details><summary>verdict.json</summary>\n",
              f"<pre>{safe(json.dumps(verdict, indent=2), 12000)}</pre>", "</details>"]
    body = "\n\n".join(parts)
    if len(body) > 60000:
        # Escaping can expand text sixfold; keep the public comment within GitHub's limit.
        body = "\n\n".join(parts[:5]) + "\n\nReport exceeds the comment limit; see the workflow artifacts."
    return body


def publish(repo, number, bot, body):
    if gate.api("user")["login"] != bot:
        raise RuntimeError("Report credential does not match configured bot")
    comments = gate.pages(f"repos/{repo}/issues/{number}/comments")
    existing = next((c for c in comments if gate.is_report(c, bot)), None)
    if existing:
        gate.api(f"repos/{repo}/issues/comments/{existing['id']}", {"body": body}, method="PATCH")
    else:
        gate.api(f"repos/{repo}/issues/{number}/comments", {"body": body})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("number", type=int)
    args = parser.parse_args()
    if args.number <= 0:
        parser.error("PR number must be positive")
    path = Path("verdict/verdict.json")
    if path.stat().st_size > 64000:
        raise ValueError("Oversized verdict; refusing to publish")
    verdict = json.loads(path.read_text())
    gate.validate_verdict(verdict, os.environ["EXPECTED_HEAD"], os.environ["EXPECTED_FINGERPRINT"])
    with Path("verdict/final-response.txt").open() as stream:
        response = stream.read(128000)
    result_path = Path("approval-result.json")
    result = json.loads(result_path.read_text()) if result_path.exists() else {
        "status": "unconfirmed", "reason": "Approval step did not record an outcome; inspect the run log."}
    repo = os.environ["GITHUB_REPOSITORY"]
    run_url = f"https://github.com/{repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    body = render_report(verdict, response, result, run_url,
                         [os.environ.get(key, "") for key in ("GH_TOKEN", "OPENROUTER_API_KEY")])
    publish(repo, args.number, os.environ["BOT_LOGIN"], body)
    print("Published agent review report")


if __name__ == "__main__":
    main()

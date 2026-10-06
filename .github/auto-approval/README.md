# Agent-gated approval

The agent uses `gh` and the review-pr skill to apply natural-language requirements
from `.code-review.md` and applicable `AGENTS.md` / `CLAUDE.md` files. Reviewer
identities, required coverage, substantive resolution, and extra human-review
conditions belong in those instructions, not Python configuration.

The harness is pi 1.0.4, installed with jq from pinned nixpkgs revision
`061e83fc010a624d8045793836ee20bb8f4b5348`. The model is
`deepseek/deepseek-v4.1-flash` through OpenRouter. Jev is not used.
The review skill is registered with `--skill` and invoked with `/skill:review-pr`;
pi's default system prompt and automatic resource discovery remain enabled.

The prepare job writes `.code-review.md` and applicable instruction files from
base-commit blobs into the review working directory. The agent reads these files
directly. `evidence.json` holds PR evidence and a `policy_files` map of paths to blob
SHAs, not embedded policy text. Those SHAs participate in the evidence fingerprint.

Pi runs in JSON mode. An unbuffered jq filter prints assistant text deltas as they
arrive and tool start/end markers to the Actions log, without raw tool payloads or
thinking blocks. Newlines in the text become log lines; GitHub may add display
latency. Pipeline failures propagate through `pipefail`. GitHub workflow-command
parsing is suspended around model output so it is treated as log text.

`verdict.json` contains `approve`, `reason`, `review_coverage`,
`discussion_resolution`, `independent_review`, `policy_checks`, `head`, and
`evidence` (the fingerprint). The final job validates it before submitting approval.

The workflow runs on PR changes and general PR comments. An hourly sweep catches
review submissions and thread resolutions, for which this workflow has no direct
trusted Actions trigger. Use **Auto approve → Run workflow → pr_number** for an
immediate recheck. Re-run all jobs rather than only failed jobs, because evidence
artifacts are scoped to the run attempt. At most two PRs per invocation are reviewed concurrently; each
agent has a 15-minute deadline. The sweep refuses more than 100 candidates rather
than silently omitting PRs. Reviews that withhold approval may run again hourly;
the `no-auto-approve` label opts a PR out. Disable the Auto approve workflow to
stop the automation without affecting normal human review.

Three separate GitHub-hosted jobs collect evidence, run the agent, and approve.
Only the final job receives `WALLETKIT_BOT_TOKEN`. It re-fetches the evidence,
validates the verdict, and submits an approval for the exact reviewed commit.
The original evidence fingerprint is a prepare-job output, not an agent-controlled
artifact. Invalid output and API failures fail the job. Ordinary ineligibility
leaves the PR unapproved with a reason in the run log. Decisions and source review
evidence are retained as run artifacts for seven days; the approval links the run.
After a completed, valid verdict, the bot creates or updates one PR comment with
its final response, recommendation, actual approval outcome, and collapsible
assessments and JSON. Changed evidence can withhold approval despite a positive
recommendation; API failures are reported as unconfirmed. Reporting errors fail
the job. Early eligibility stops and invalid/incomplete agent output remain in
Actions logs. The report identifies the reviewed SHA and links the run. Its own
comment is excluded from evidence and does not trigger another review.

Only the final assistant text is published, not thinking or tool results. Public
text is escaped, known credentials are redacted, and long output is truncated with
an artifact link. The verdict artifact includes `final-response.txt`; raw pi events
remain temporary runner files.

The code always rejects forks, drafts, external authors, bot-authored PRs,
outstanding change requests, unresolved threads, and changes to `.github/` or
review instruction files (including renames). It does not decide which reviewers
must participate. All review policy comes from the base commit, never the PR.
The agent has read-only GitHub credentials and must not execute PR code.

The agent still receives the OpenRouter key and can run shell commands. A prompt
injection can potentially expose that key or influence its verdict. Job isolation
protects the approval credential, not the model credential or the quality of its
judgment. Use a dedicated, budget-limited OpenRouter key. The existing release-bot
token is retained without expanding its access; a repository-scoped approval App
is a possible later replacement.

GitHub does not offer an atomic compare-and-approve operation for discussions.
The final state comparison narrows the race, while required thread resolution and
stale-approval dismissal remain merge-time protections. Apply the accompanying
`infrastructure` change enabling stale-approval dismissal before enabling this
workflow. Existing CI/merge protections remain responsible for merge eligibility;
this workflow does not merge or bypass them. Read access to legacy branch
protection was unavailable during development, so verify effective protections
during deployment rather than treating Terraform configuration as proof of live
settings.

For another repository, port the workflow/helper/skill together, set its approver
identity and secret, and write its `.code-review.md`. This pilot does not introduce
a shared service or change other repositories' approval rules. The reusable
workflow currently checks out caller-repository helpers, so it is not yet a
standalone cross-repository package.

Run helper regressions with `python3 -m unittest discover -s .github/auto-approval`.
Use Nix-provided Python and jq where they are not in the development shell. Validate both
workflow files with `actionlint`. These checks do not invoke a model or submit a
GitHub review.

GitHub references: [workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows) and [stale approval rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

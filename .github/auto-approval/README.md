# Agent-gated approval

The agent uses `gh` and the review-pr skill to apply natural-language requirements
from `.code-review.md` and applicable `AGENTS.md` / `CLAUDE.md` files. Reviewer
identities, required coverage, substantive resolution, and extra human-review
conditions belong in those instructions, not Python configuration.

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
No model-authored text is posted to public comments.

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
Use Nix-provided Python where it is not in the development shell. Validate both
workflow files with `actionlint`. These checks do not invoke a model or submit a
GitHub review.

GitHub references: [workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows) and [stale approval rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets).

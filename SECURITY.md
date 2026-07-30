# Security Policy

## Report a vulnerability in Claude Security

Report vulnerabilities in the Claude Security CLI, bundled plugin, or release
artifacts **privately**, not in a public issue or pull request:

> Go to this repository's **Security** tab and choose **Report a vulnerability**.

That opens a private advisory visible only to you and the maintainer. It is
deliberately described by location rather than by link, so it keeps working if
the repository is renamed, moved, or forked.

Include the affected version, the security impact, and the smallest safe
reproduction. Strip API keys, access tokens, private source code, and customer
data from the report unless a private submission genuinely requires that
material and you have permission to share it.

**Response expectations:** this is a small project with a single maintainer.
Reports are handled on a best-effort basis, with no guaranteed response time. If
a report gets no reply and the issue is being actively exploited, treat
disclosure as your call to make — an unanswered report is not an agreement to
stay quiet indefinitely.

**Do not send reports about this project to OpenAI or to Anthropic.** Claude
Security is an independent derivative of
[Codex Security](https://github.com/openai/codex-security) that calls Anthropic's
API. Neither company publishes or supports it, and neither can fix a bug here.
Report to them only what is actually theirs: a flaw in the upstream scanning
pipeline belongs to OpenAI's program, and a flaw in the Claude Agent SDK or the
API belongs to Anthropic's.

Public GitHub issues are for ordinary bugs, documentation problems, and feature
requests. Keep unpatched vulnerabilities and sensitive scan artifacts out of
them.

## Report a finding in a scanned repository

A vulnerability found in another repository belongs to that repository's owner.
Follow its security policy or coordinated disclosure process, and share the
finding only with people authorized to receive it. This project's reporting
channel is for flaws in Claude Security itself, not for findings in the code it
scanned.

## Scanning untrusted code requires a container

**This tool does not sandbox the code it scans.** The scan agent runs with
`Bash` enabled and pre-approved (`permissionMode: "dontAsk"`), so it executes
shell commands with your user's privileges, your network access, and your
credentials. The runtime narrows the tool set and tells the agent to treat the
target as read-only, but nothing *enforces* that.

This is a real difference from upstream Codex Security, which runs scans inside
the Codex sandbox. Do not assume the same protection here.

Scan untrusted or unfamiliar code only inside a disposable, network-restricted
container. For code you own and trust, running on the host is reasonable.

## Treat the scanned repository as untrusted input

Repository contents reach the model: source, comments, build scripts, and
documentation. A repository can contain text written to influence the scan — for
example, instructions claiming a vulnerability is intentional or already
reviewed. The bundled skills are written to treat such text as data rather than
instructions, and to treat a stored dismissal as a claim to re-check rather than
an order to stay silent. That mitigates the problem; it does not eliminate it.
Review findings, and be more skeptical of a clean report on code you have reason
to doubt.

## Handle scan artifacts as sensitive

Findings, reports, `usage.json`, SARIF exports, and the SQLite scan history
contain private source code, vulnerability details, and reproduction steps.

- Keep the scan bundle outside the Git worktree being scanned. The tool enforces
  this, so a report is never committed by accident.
- Restrict access to scan artifacts, set a retention period, and review them
  before sharing or uploading them anywhere.
- Review any proposed patch before applying or merging it.

## Handle credentials carefully

Prefer `ANTHROPIC_API_KEY` in the environment, or an existing Claude Code
sign-in. `claude-security login --with-api-key` writes the key as plain JSON with
mode `600` in a `700` directory — adequate for a single-user machine, not for a
shared one. Keys are read from stdin, never from a command-line argument, so they
do not land in shell history or the process table.

Keep the state directory (`CLAUDE_SECURITY_STATE_DIR`) outside the repository
being scanned; it holds credentials and scan history.

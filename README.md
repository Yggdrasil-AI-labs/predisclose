# leakguard

[![leakguard](https://github.com/Yggdrasil-AI-labs/leakguard/actions/workflows/leakguard.yml/badge.svg)](https://github.com/Yggdrasil-AI-labs/leakguard/actions/workflows/leakguard.yml)

> [!WARNING]
> **Experimental, pre-1.0, under active development.** Detection rules, CLI flags,
> and output formats may change without notice. It has not been hardened for
> production use. Pin a tagged version, treat it as a safety net rather than a
> guarantee, and review findings yourself.

Catch internal identifiers, secrets, and PII before they leak into public
artifacts. leakguard scans local files, git staged content (as a pre-commit
hook), the full git history, and already-published GitHub repos, then reports
each hit with a line reference and a suggested fix. It is detection-only; it
never edits your content. The core is pure Python standard library with zero
runtime dependencies. The optional AI layers are installed separately.

## The safety model

The thing most likely to leak from a secret-scanner is its own rule list, because
that list is an inventory of exactly what you are trying to hide. leakguard is
built so that does not happen:

- The repo ships only generic patterns (cloud keys, private-key blocks, RFC1918
  and CGNAT addresses, common token formats). These contain no
  organization-specific values.
- Your organization-specific patterns (internal hostnames, private project names,
  people, locations) live in a private rules file you keep out of version control.
  leakguard loads it at runtime. It is gitignored by default.

leakguard targets disclosure, not only credentials. A generic secret scanner
answers "did I commit an AWS key?". leakguard also answers "did I leak the name of
an internal host, an unreleased project, or a person?", which is the kind of
attribution trail a clean-looking public repo, blog post, or AI-generated draft
can still carry. You cannot answer that second question with a public rule list,
so leakguard keeps the engine public and the inventory private.

It also applies to AI-assisted writing and code generation, where internal
identifiers can slip into generated output: run leakguard over generated artifacts
before they ship. Optional local AI layers (`leakguard[ai]`) add a Presidio PII
pass and a local-LLM reviewer on top of the regex engine; see below.

## How it compares

| | leakguard | gitleaks | trufflehog | detect-secrets |
|---|---|---|---|---|
| Generic secret detectors | ~63 | ~140 | 800+ | curated |
| Private org-identifier rules, kept out of the repo | yes | no | no | no |
| Disclosure / PII (hostnames, project names, people) | yes | partial | no | partial |
| Baseline (adopt a dirty repo, alert only on new) | yes | partial | no | yes |
| Git-history scan | yes | yes | yes | yes |
| Entropy detection | yes (opt-in) | yes | yes | yes |
| Live credential verification | opt-in (~10 providers) | no | yes (800+) | no |
| Local-LLM semantic review | yes | no | no | no |
| Agentic triage loop (scan → judge → act → re-scan, local) | yes | no | no | no |
| SARIF / GitHub code scanning | yes | yes | partial | no |
| pre-commit framework hook | yes | yes | yes | yes |
| Core runtime dependencies | none | Go binary | Go binary | Python deps |

leakguard does not aim to match the big scanners on raw credential breadth;
trufflehog (800+ detectors, with live verification) and gitleaks cover that. Its
focus is the private-inventory model and disclosure coverage: catching an internal
hostname, an unreleased project name, or a person, with the rule list kept
private, in a stdlib-only core you can read end to end and drop into any CI.

Who it is for: anyone publishing from a private environment (open-sourcing an
internal tool, writing a blog post or docs, or reviewing AI-generated output) who
needs to catch internal identifiers and secrets before they go public.

## Install

```
pip install leakguard         # or: pip install . from a clone
```

Python 3.8+, standard library only (the core has no runtime dependencies).

The optional AI layers add dependencies and are installed separately:

```
pip install 'leakguard[ai]'   # presidio-analyzer + spacy
python -m spacy download en_core_web_lg
```

## Usage

Scan a tree:

```
leakguard scan .
```

Scan only what is staged for commit (used by the pre-commit hook):

```
leakguard scan --staged
```

Scan the full git history. This finds secrets that were committed and later
removed; each finding is tagged with the short SHA of the commit it was seen in:

```
leakguard scan --history
leakguard scan --history --since v1.0.0      # only commits in v1.0.0..HEAD
```

Also flag high-entropy strings that no pattern matched (opt-in; see below):

```
leakguard scan . --entropy
leakguard scan . --entropy --entropy-threshold 4.5
```

Audit published repos read-only (an org, a user, or specific repos):

```
leakguard github --org your-org
leakguard github --repo owner/name --repo owner/other
```

Adopt leakguard into a repo that already has findings: snapshot them as a
baseline, then get alerted only on new leaks. The baseline stores hashes, not the
secrets, so it is safe to commit:

```
leakguard scan . --baseline .leakguard-baseline.json --update-baseline   # snapshot
leakguard scan . --baseline .leakguard-baseline.json                     # only new
```

Scaffold a private rules file (writes `.leakguard.local.json` and gitignores it):

```
leakguard init
```

Check whether matched credentials are live (opt-in; makes network calls only for
supported types):

```
leakguard scan . --verify
```

Exit code is `0` when clean (or only findings below the threshold) and `1` when
there are findings at or above `--fail-on` (default `medium`), which makes it
usable as a CI gate. `--format json` emits machine-readable output, `--format
sarif` emits SARIF 2.1.0 for GitHub code scanning, and `--format md` emits a
Markdown summary for a job summary or PR comment. See "Reporting and alerts" below
for how findings reach people.

## Private rules

Copy `rules/example.rules.json` to `.leakguard.local.json` at your repo root (or
anywhere, and point `--rules` / `LEAKGUARD_RULES` at it). It is auto-loaded and
gitignored. Format:

```json
{
  "rules": [
    {"id": "internal-host", "pattern": "\\bacme-[a-z0-9]+\\b",
     "severity": "high", "message": "internal hostname",
     "suggestion": "use a public codename", "flags": "i"}
  ],
  "allow": ["acme-public-handle", "203.0.113.5"]
}
```

`pattern` is a Python regular expression. `severity` is `low`, `medium`, or
`high`. `allow` is a list of literal strings; any match equal to an allow entry
is dropped, which is how you whitelist public names that resemble internal ones.

## Entropy detection

Pattern rules catch known secret shapes. Entropy detection is a complementary
pass: it flags long, high-Shannon-entropy base64/hex-ish tokens that look random
enough to be a credential even when no pattern matched. It is off by default
(noisy by nature) and findings are low severity, so it does not block a commit
unless you opt in with `--fail-on low`.

Enable it per-run with `--entropy`, or persistently via an `"entropy"` block in
your private rules file:

```json
{ "entropy": { "enabled": true, "b64_threshold": 4.2, "severity": "low" } }
```

It honors the `allow` list, skips tokens already covered by a pattern match, and
skips common false positives (lockfiles, subresource-integrity hashes, 40-char
git object hashes).

## Verification (`--verify`)

By default leakguard reports that a string looks like a credential. `--verify`
goes one step further for a small set of providers: it asks the provider whether
the credential is live, so you can tell an active leak from a long-dead one. It is
opt-in, makes network calls only for supported types, and does not change the exit
code. It annotates findings:

- `active`: the provider accepted it; rotate it.
- `inactive`: the provider returned 401; likely already revoked.
- `unknown`: network error, rate limit, or an ambiguous response.

Supported today: GitHub (classic and fine-grained), GitLab, Slack, Stripe,
SendGrid, npm, OpenAI, Anthropic, and Hugging Face. Other types are left
unverified. AWS and GCP (which need request signing) are not yet supported. It
uses stdlib `urllib` only, and sends the credential only to its own provider.

## Keyword proximity (`--proximity`)

Some secrets have no distinctive prefix; they are bare hex/alnum tokens (Datadog,
Algolia, Cloudflare, Heroku, JFrog, Facebook, Mapbox, Twitter). A regex for "32
hex chars" alone would match many hashes, so these are off by default. With
`--proximity`, leakguard flags such a token only when a provider keyword
("datadog", "algolia", and so on) sits within about 30 characters on the same
line, the same keyword-gating approach gitleaks uses. The keyword requirement
keeps false positives down; a bare token with no nearby provider name is not
flagged.

```
leakguard scan . --proximity
```

## Optional AI layers (`leakguard[ai]`)

Two local, opt-in layers supplement the regex engine. They produce the same
findings and flow through the same exit-code path, so they add coverage on top of
the built-in and private rules. The zero-dependency core keeps working without
them; if the extra is not installed, each layer prints a one-line install hint and
is skipped (it does not crash the scan).

Enable them with flags on either `scan` or `github`:

```
pip install 'leakguard[ai]'
python -m spacy download en_core_web_lg

leakguard scan . --presidio              # Presidio PII pass
leakguard scan . --review                # local-LLM reviewer
leakguard scan . --presidio --review     # both, merged with the regex findings
leakguard github --org your-org --presidio --review
```

### Presidio PII pass (`--presidio`)

Runs Microsoft [Presidio](https://github.com/microsoft/presidio) as a second PII
detector (names, phone numbers, credit cards, SSNs, IBANs, and more). Each
detected entity becomes a finding with `rule_id` `presidio:<ENTITY_TYPE>`; entity
types map to leakguard severities and the engine's `allow` list is honored. Hits
below a confidence threshold are dropped.

| env | default | meaning |
| --- | --- | --- |
| `LEAKGUARD_PRESIDIO_THRESHOLD` | `0.5` | drop hits below this confidence score |
| `LEAKGUARD_PRESIDIO_LANG` | `en` | spaCy language |

### Local-LLM reviewer (`--review`)

Sends each scanned file plus the findings collected so far to a local
OpenAI-compatible `/v1/chat/completions` endpoint and asks the model to flag
items the rules and Presidio did not catch. It is model-agnostic and uses only the
standard-library `urllib` (no client dependency). Model-flagged items become
findings with `rule_id` `llm-review`.

Local-first by default: the default endpoint is a localhost server (Ollama's
default port). Pointing it at a remote/cloud endpoint is opt-in via env.

| env | default | meaning |
| --- | --- | --- |
| `LEAKGUARD_LLM_BASE` | `http://localhost:11434/v1` | OpenAI-compatible base URL |
| `LEAKGUARD_LLM_MODEL` | `llama3.1` | model name |
| `LEAKGUARD_LLM_KEY` | _(unset)_ | bearer token, only for endpoints that need auth |
| `LEAKGUARD_LLM_TIMEOUT` | `60` | per-request timeout, seconds |
| `LEAKGUARD_LLM_MAX_CHARS` | `16000` | max chars of a file sent per request |

```
# point at any local OpenAI-compatible server
export LEAKGUARD_LLM_BASE=http://localhost:11434/v1
export LEAKGUARD_LLM_MODEL=qwen2.5-coder
leakguard scan . --review
```

Both layers are detection-only and run locally by default. The LLM reviewer sends
file content to whatever endpoint you configure, so keep it pointed at a local
model unless you have decided otherwise.

## Agent mode (`leakguard agent`)

`scan` finds and reports; `agent` runs the same detection as a loop that also
*acts*. It scans, asks a LOCAL model to judge each finding, acts on the verdict,
then re-scans, repeating until the artifact is clean or a step budget runs out.
LeakGuard's job is unchanged; this is the one-shot scan turned into an agent.

```
leakguard agent .
leakguard agent . --apply-allow --max-steps 5
```

Each finding is classified as one of:

- `real_leak`: genuinely sensitive; reported with a rotation/scrub action and
  counted toward the exit code.
- `false_positive`: the pattern matched but it is not sensitive (a test fixture,
  a documentation example, an obvious placeholder). Set aside with a reason.
- `allowlist_candidate`: a real, correct match that is meant to be public (a
  published handle or address). Proposed as an `allow` entry.

The control flow is bounded Python; the model provides judgment only, so it
works with small local models that do not do native tool-calling. It is
**local-first**: it reuses the same configuration as `--review`
(`LEAKGUARD_LLM_BASE`, `LEAKGUARD_LLM_MODEL`, and the other `LEAKGUARD_LLM_*`
vars; default endpoint is a localhost Ollama). It is **conservative**: any
finding the model cannot classify (endpoint down, unparseable reply) stays a
`real_leak`, so the agent never hides a possible leak.

Like the rest of leakguard, agent mode is **detection / proposal-only and never
edits your scanned content**. By default `allowlist_candidate` matches are only
*proposed*. With `--apply-allow` it appends them to your private
`.leakguard.local.json` (configuration, gitignored) and re-scans, which is what
lets the loop reach a clean state. It exits `1` if any `real_leak` is at or
above `--fail-on` (default `medium`), else `0`.

To be told about leaks out of band, add `--notify-webhook <url>` (or set
`LEAKGUARD_WEBHOOK`). When the agent finishes with a confirmed `real_leak` at or
above `--fail-on`, it POSTs a summary to Slack, Discord, or a generic webhook
(pick with `--notify-style`). Only the leaks the agent *kept* are sent, not the
false positives or allowlist candidates it filtered out, so the alert is the
high-signal subset rather than the raw scan.

```
export LEAKGUARD_LLM_BASE=http://localhost:11434/v1
export LEAKGUARD_LLM_MODEL=gemma3:12b
leakguard agent ./path-about-to-be-published
```

## Pre-commit hook

Plain git hook:

```
ln -sf ../../hooks/pre-commit .git/hooks/pre-commit
```

Or via the [pre-commit framework](https://pre-commit.com), add to your
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Yggdrasil-AI-labs/leakguard
    rev: v0.6.1
    hooks:
      - id: leakguard
```

Both scan staged content and block the commit on findings at or above the
threshold (default `medium`). Bypass once with `git commit --no-verify`.

## CI

`.github/workflows/leakguard.yml` runs a scan on every push and pull request and
runs a gating scan that fails the job on findings at or above `medium`. To use
private patterns in CI, store the rules JSON as a `LEAKGUARD_RULES_JSON`
repository secret; the workflow writes it to `.leakguard.local.json` at runtime
(it is never committed).

## Reporting and alerts

leakguard surfaces a finding four ways; the bundled workflow wires up the first
three out of the box.

- Exit code: `1` when any finding is at or above `--fail-on` (default `medium`),
  else `0`. This is what fails a CI job or blocks a commit.
- Job summary: `leakguard scan . --format md` prints a findings table; the
  workflow appends it to `$GITHUB_STEP_SUMMARY`, so every Actions run page shows
  it (matched values are redacted).
- Pull-request comment: the workflow posts and updates one sticky comment with
  that table on each PR, so reviewers see findings inline.
- SARIF / Security tab: `--format sarif`, uploaded via
  `github/codeql-action/upload-sarif`; alerts show under Security, Code scanning.
- Webhook push: `--notify-webhook <url>` (or the `LEAKGUARD_WEBHOOK` env var)
  POSTs a summary to Slack, Discord, or a generic webhook when findings hit the
  threshold. Stdlib only; meant for scheduled scans with no PR to comment on. Pick
  the shape with `--notify-style slack|discord|generic` (or
  `LEAKGUARD_WEBHOOK_STYLE`).

### Permissions and tokens you need

The bundled workflow already requests these. If you wire leakguard into your own
workflow, you must grant them yourself. The automatic `GITHUB_TOKEN` Actions
injects is read-only by default, so the `write` scopes below are required.

| Surface | Requires | Notes |
| --- | --- | --- |
| Exit code / job summary | nothing | works out of the box |
| SARIF, Security tab | `permissions: security-events: write` | GitHub-hosted code scanning |
| PR comment | `permissions: pull-requests: write` | uses the built-in `GITHUB_TOKEN`; no PAT or extra secret |
| Webhook push | a `LEAKGUARD_WEBHOOK` secret (your incoming-webhook URL) | uncomment the "Notify webhook" step to enable |
| Private org rules | a `LEAKGUARD_RULES_JSON` secret | written to `.leakguard.local.json` at runtime, never committed |

You do not create or store a personal access token for the PR comment or SARIF
upload; both use the `GITHUB_TOKEN` GitHub injects automatically. You only grant
it the `write` scopes above in the workflow's `permissions:` block.

## Built-in patterns

Around 63 generic detectors, including: cloud credentials (AWS, GCP API keys and
service-account markers, Azure Storage keys and SAS tokens, DigitalOcean);
source-control and registry tokens (GitHub classic and fine-grained PATs, GitLab
PATs, npm, PyPI); SaaS and AI-provider keys (Anthropic, OpenAI, Hugging Face,
Stripe, Twilio, SendGrid, Mailchimp, Google OAuth, Square, Shopify, Postman,
Notion, Dropbox, Telegram, Slack and Discord tokens/webhooks); observability and
platform tokens (Sentry DSNs, Databricks, New Relic, Linear, Doppler, Grafana,
Mailgun, Pulumi, Terraform Cloud, HashiCorp Vault, GCP OAuth refresh tokens,
`.npmrc` auth tokens); private-key blocks, JWTs, database connection URIs and
basic-auth URLs with embedded credentials, hard-coded secret assignments, and
Authorization headers; RFC1918 and CGNAT IP addresses, Tailscale MagicDNS
hostnames, and email addresses. Tune severities or disable the built-ins with
`--no-builtin` and supply your own. Breadth is not a goal of this project; see
"How it compares".

## License

MIT.

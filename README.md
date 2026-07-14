# predisclose

[![predisclose](https://github.com/Yggdrasil-AI-labs/predisclose/actions/workflows/predisclose.yml/badge.svg)](https://github.com/Yggdrasil-AI-labs/predisclose/actions/workflows/predisclose.yml)

> [!WARNING]
> **Experimental, pre-1.0, under active development.** Detection rules, CLI flags,
> and output formats may change without notice. It has not been hardened for
> production use. Pin a tagged version, treat it as a safety net rather than a
> guarantee, and review findings yourself.

Catch internal identifiers, secrets, and PII before they leak into public
artifacts. predisclose scans local files, git staged content (as a pre-commit
hook), the full git history, and already-published GitHub repos, then reports
each hit with a line reference and a suggested fix. It is detection-only; it
never edits your content. The core is pure Python standard library with zero
runtime dependencies. The optional AI layers are installed separately.

## The safety model

The thing most likely to leak from a secret-scanner is its own rule list, because
that list is an inventory of exactly what you are trying to hide. predisclose is
built so that does not happen:

- The repo ships only generic patterns (cloud keys, private-key blocks, RFC1918
  and CGNAT addresses, common token formats). These contain no
  organization-specific values.
- Your organization-specific patterns (internal hostnames, private project names,
  people, locations) live in a private rules file you keep out of version control.
  predisclose loads it at runtime. It is gitignored by default.

predisclose targets disclosure, not only credentials. A generic secret scanner
answers "did I commit an AWS key?". predisclose also answers "did I leak the name of
an internal host, an unreleased project, or a person?", which is the kind of
attribution trail a clean-looking public repo, blog post, or AI-generated draft
can still carry. You cannot answer that second question with a public rule list,
so predisclose keeps the engine public and the inventory private.

It also applies to AI-assisted writing and code generation, where internal
identifiers can slip into generated output: run predisclose over generated artifacts
before they ship. Optional local AI layers (`predisclose[ai]`) add a Presidio PII
pass and a local-LLM reviewer on top of the regex engine; see below.

## How it compares

| | predisclose | gitleaks | trufflehog | detect-secrets |
|---|---|---|---|---|
| Generic secret detectors | ~63 | ~140 | 800+ | curated |
| Private org-identifier rules, kept out of the repo | yes | no | no | no |
| Disclosure / PII (hostnames, project names, people) | yes | partial | no | partial |
| Baseline (adopt a dirty repo, alert only on new) | yes | partial | no | yes |
| Git-history scan | yes | yes | yes | yes |
| Entropy detection | yes (opt-in) | yes | yes | yes |
| Live credential verification | opt-in (~10 providers) | no | yes (800+) | no |
| Local-LLM semantic review | yes | no | no | no |
| Bounded triage loop (scan → judge → act → re-scan, local) | yes | no | no | no |
| SARIF / GitHub code scanning | yes | yes | partial | no |
| pre-commit framework hook | yes | yes | yes | yes |
| Core runtime dependencies | none | Go binary | Go binary | Python deps |

predisclose does not aim to match the big scanners on raw credential breadth;
trufflehog (800+ detectors, with live verification) and gitleaks cover that. Its
focus is the private-inventory model and disclosure coverage: catching an internal
hostname, an unreleased project name, or a person, with the rule list kept
private, in a stdlib-only core you can read end to end and drop into any CI. It sits in the
publish step rather than the security-audit step: the question is not only whether
a credential is live, but whether an artifact you are about to make public still
carries an internal identifier. And because the core is standard-library only, it
also builds into a single file you can run in an ephemeral environment with
nothing installed (see Single-file build).

Who it is for: anyone publishing from a private environment (open-sourcing an
internal tool, writing a blog post or docs, or reviewing AI-generated output) who
needs to catch internal identifiers and secrets before they go public.

## Install

```
pip install predisclose         # or: pip install . from a clone
```

Python 3.8+, standard library only (the core has no runtime dependencies).

The optional AI layers add dependencies and are installed separately:

```
pip install 'predisclose[ai]'   # presidio-analyzer + spacy
python -m spacy download en_core_web_lg
```

### Single-file build (no install)

The stdlib core also builds into one self-contained executable you can copy
anywhere Python 3.8+ runs, with nothing to install:

```
python scripts/build_pyz.py          # writes dist/predisclose.pyz
python dist/predisclose.pyz scan .
```

Every tagged release also attaches a prebuilt `predisclose.pyz`, so you can drop
it straight into an ephemeral environment (a notebook cell, an agent scratchpad,
a bare container) as a last-mile scrub before pushing work public:

```
curl -sSL -o predisclose.pyz \
  https://github.com/Yggdrasil-AI-labs/predisclose/releases/latest/download/predisclose.pyz
python predisclose.pyz scan .
```

The archive is plain Python; unzip it and read it end to end. Only the core runs
from the .pyz; the optional AI layers still need the `predisclose[ai]` extra.

## Usage

Scan a tree:

```
predisclose scan .
```

Scan only what is staged for commit (used by the pre-commit hook):

```
predisclose scan --staged
```

Scan the full git history. This finds secrets that were committed and later
removed; each finding is tagged with the short SHA of the commit it was seen in:

```
predisclose scan --history
predisclose scan --history --since v1.0.0      # only commits in v1.0.0..HEAD
```

Also flag high-entropy strings that no pattern matched (opt-in; see below):

```
predisclose scan . --entropy
predisclose scan . --entropy --entropy-threshold 4.5
```

Audit repos you have already pushed. This is a post-publish safety net; the pre-commit and `scan` workflows above are the primary use. Read-only (an org, a user, or specific repos):

```
predisclose github --org your-org
predisclose github --user your-username
predisclose github --repo owner/name --repo owner/other
```

By default this reads public repos only, unauthenticated. Set `GH_TOKEN` (or
`GITHUB_TOKEN`) and add `--include-private` to also scan private repos you have
access to. Both the repo listing and the file contents go through the
authenticated GitHub API, so private content is read the same way as public
(the public CDN does not serve private files):

```
GH_TOKEN=ghp_... predisclose github --org your-org --include-private
```

Adopt predisclose into a repo that already has findings: snapshot them as a
baseline, then get alerted only on new leaks. The baseline stores hashes, not the
secrets, so it is safe to commit:

```
predisclose scan . --baseline .predisclose-baseline.json --update-baseline   # snapshot
predisclose scan . --baseline .predisclose-baseline.json                     # only new
```

Scaffold a private rules file (writes `.predisclose.local.json` and gitignores it):

```
predisclose init
```

Check whether matched credentials are live (opt-in; makes network calls only for
supported types):

```
predisclose scan . --verify
```

Exit code is `0` when clean (or only findings below the threshold) and `1` when
there are findings at or above `--fail-on` (default `medium`), which makes it
usable as a CI gate. `--format json` emits machine-readable output, `--format
sarif` emits SARIF 2.1.0 for GitHub code scanning, and `--format md` emits a
Markdown summary for a job summary or PR comment. See "Reporting and alerts" below
for how findings reach people.

## Private rules

Copy `rules/example.rules.json` to `.predisclose.local.json` at your repo root (or
anywhere, and point `--rules` / `PREDISCLOSE_RULES` at it). It is auto-loaded and
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

Because `pattern` is a standard-library `re` expression run over file contents (capped at 800 KB per file), keep private-rule patterns linear-time: avoid nested quantifiers like `(a+)+` that can backtrack catastrophically. The built-in patterns are all single-quantifier shapes.

### Sharing private rules across a team

The rules file is gitignored on purpose, so a small team needs a way to share it
without committing it. Point predisclose at a URL instead of a local path and it
fetches the JSON at runtime with stdlib `urllib`:

```
predisclose scan . --rules https://gist.githubusercontent.com/you/ID/raw/rules.json
# or, so every run picks it up:
export PREDISCLOSE_RULES_URL=https://gist.githubusercontent.com/you/ID/raw/rules.json
predisclose scan .
```

One person maintains a private gist (or a raw file in a private repo); everyone
else gets the current rules on their next run, using the token they already have.
For a private source, provide a token via the environment: `PREDISCLOSE_RULES_TOKEN`
(sent as a bearer token, any host), or the `GH_TOKEN` / `GITHUB_TOKEN` /
`GITLAB_TOKEN` already in your environment for GitHub and GitLab hosts. If the
fetch fails, the scan stops with an error rather than silently running without
your private rules.

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

By default predisclose reports that a string looks like a credential. `--verify`
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
`--proximity`, predisclose flags such a token only when a provider keyword
("datadog", "algolia", and so on) sits within about 30 characters on the same
line, the same keyword-gating approach gitleaks uses. The keyword requirement
keeps false positives down; a bare token with no nearby provider name is not
flagged.

```
predisclose scan . --proximity
```

## Optional AI layers (`predisclose[ai]`)

Two local, opt-in layers supplement the regex engine. They produce the same
findings and flow through the same exit-code path, so they add coverage on top of
the built-in and private rules. The zero-dependency core keeps working without
them; if the extra is not installed, each layer prints a one-line install hint and
is skipped (it does not crash the scan).

Enable them with flags on either `scan` or `github`:

```
pip install 'predisclose[ai]'
python -m spacy download en_core_web_lg

predisclose scan . --presidio              # Presidio PII pass
predisclose scan . --review                # local-LLM reviewer
predisclose scan . --presidio --review     # both, merged with the regex findings
predisclose github --org your-org --presidio --review
```

### Presidio PII pass (`--presidio`)

Runs Microsoft [Presidio](https://github.com/microsoft/presidio) as a second PII
detector (names, phone numbers, credit cards, SSNs, IBANs, and more). Each
detected entity becomes a finding with `rule_id` `presidio:<ENTITY_TYPE>`; entity
types map to predisclose severities and the engine's `allow` list is honored. Hits
below a confidence threshold are dropped.

| env | default | meaning |
| --- | --- | --- |
| `PREDISCLOSE_PRESIDIO_THRESHOLD` | `0.5` | drop hits below this confidence score |
| `PREDISCLOSE_PRESIDIO_LANG` | `en` | spaCy language |

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
| `PREDISCLOSE_LLM_BASE` | `http://localhost:11434/v1` | OpenAI-compatible base URL |
| `PREDISCLOSE_LLM_MODEL` | `llama3.1` | model name |
| `PREDISCLOSE_LLM_KEY` | _(unset)_ | bearer token, only for endpoints that need auth |
| `PREDISCLOSE_LLM_TIMEOUT` | `60` | per-request timeout, seconds |
| `PREDISCLOSE_LLM_MAX_CHARS` | `16000` | max chars of a file sent per request |

```
# point at any local OpenAI-compatible server
export PREDISCLOSE_LLM_BASE=http://localhost:11434/v1
export PREDISCLOSE_LLM_MODEL=qwen2.5-coder
predisclose scan . --review
```

Both layers are detection-only and run locally by default. The LLM reviewer sends
file content to whatever endpoint you configure, so keep it pointed at a local
model unless you have decided otherwise.

## Agent mode (`predisclose agent`)

`scan` finds and reports; `agent` runs the same detection as a loop that also
*acts*. It scans, asks a LOCAL model to judge each finding, acts on the verdict,
then re-scans, repeating until the artifact is clean or a step budget runs out.
The detection is unchanged; this is the one-shot scan run as a bounded loop.

```
predisclose agent .
predisclose agent . --apply-allow --max-steps 5
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
(`PREDISCLOSE_LLM_BASE`, `PREDISCLOSE_LLM_MODEL`, and the other `PREDISCLOSE_LLM_*`
vars; default endpoint is a localhost Ollama). It is **conservative**: any
finding the model cannot classify (endpoint down, unparseable reply) stays a
`real_leak`, so the agent never hides a possible leak.

Like the rest of predisclose, agent mode is **detection / proposal-only and never
edits your scanned content**. By default `allowlist_candidate` matches are only
*proposed*. With `--apply-allow` it appends them to your private
`.predisclose.local.json` (configuration, gitignored) and re-scans, which is what
lets the loop reach a clean state. It exits `1` if any `real_leak` is at or
above `--fail-on` (default `medium`), else `0`.

To be told about leaks out of band, add `--notify-webhook <url>` (or set
`PREDISCLOSE_WEBHOOK`). When the agent finishes with a confirmed `real_leak` at or
above `--fail-on`, it POSTs a summary to Slack, Discord, or a generic webhook
(pick with `--notify-style`). Only the leaks the agent *kept* are sent, not the
false positives or allowlist candidates it filtered out, so the alert is the
high-signal subset rather than the raw scan.

```
export PREDISCLOSE_LLM_BASE=http://localhost:11434/v1
export PREDISCLOSE_LLM_MODEL=gemma3:12b
predisclose agent ./path-about-to-be-published
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
  - repo: https://github.com/Yggdrasil-AI-labs/predisclose
    rev: v0.6.1
    hooks:
      - id: predisclose
```

Both scan staged content and block the commit on findings at or above the
threshold (default `medium`). Bypass once with `git commit --no-verify`.

## CI

`.github/workflows/predisclose.yml` runs a scan on every push and pull request and
runs a gating scan that fails the job on findings at or above `medium`. To use
private patterns in CI, store the rules JSON as a `PREDISCLOSE_RULES_JSON`
repository secret; the workflow writes it to `.predisclose.local.json` at runtime
(it is never committed).

## Reporting and alerts

predisclose surfaces a finding four ways; the bundled workflow wires up the first
three out of the box.

- Exit code: `1` when any finding is at or above `--fail-on` (default `medium`),
  else `0`. This is what fails a CI job or blocks a commit.
- Job summary: `predisclose scan . --format md` prints a findings table; the
  workflow appends it to `$GITHUB_STEP_SUMMARY`, so every Actions run page shows
  it (matched values are redacted).
- Pull-request comment: the workflow posts and updates one sticky comment with
  that table on each PR, so reviewers see findings inline.
- SARIF / Security tab: `--format sarif`, uploaded via
  `github/codeql-action/upload-sarif`; alerts show under Security, Code scanning.
- Webhook push: `--notify-webhook <url>` (or the `PREDISCLOSE_WEBHOOK` env var)
  POSTs a summary to Slack, Discord, or a generic webhook when findings hit the
  threshold. Stdlib only; meant for scheduled scans with no PR to comment on. Pick
  the shape with `--notify-style slack|discord|generic` (or
  `PREDISCLOSE_WEBHOOK_STYLE`).

### Permissions and tokens you need

The bundled workflow already requests these. If you wire predisclose into your own
workflow, you must grant them yourself. The automatic `GITHUB_TOKEN` Actions
injects is read-only by default, so the `write` scopes below are required.

| Surface | Requires | Notes |
| --- | --- | --- |
| Exit code / job summary | nothing | works out of the box |
| SARIF, Security tab | `permissions: security-events: write` | GitHub-hosted code scanning |
| PR comment | `permissions: pull-requests: write` | uses the built-in `GITHUB_TOKEN`; no PAT or extra secret |
| Webhook push | a `PREDISCLOSE_WEBHOOK` secret (your incoming-webhook URL) | uncomment the "Notify webhook" step to enable |
| Private org rules | a `PREDISCLOSE_RULES_JSON` secret | written to `.predisclose.local.json` at runtime, never committed |

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

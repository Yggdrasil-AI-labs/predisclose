# Benchmark: predisclose vs gitleaks on a third-party corpus

A file-level recall check on a public, planted-secret corpus that neither tool
authored. Reproduce it with `scripts/benchmark.py` (see the end).

## Setup

- Corpus: [Plazmaz/leaky-repo](https://github.com/Plazmaz/leaky-repo) at commit
  `2e95135`, 61 files. A community set of files with planted secrets, built for
  testing scanners.
- gitleaks: v8.30.1 (`gitleaks dir`, default rules).
- predisclose: this commit, run two ways. Default is the deterministic engine.
  The second run adds the opt-in `--proximity` and `--entropy` passes.

## Method and caveats

Read these before quoting any number.

- The metric is a coarse recall proxy: whether a tool flagged ANY secret in a
  file, not per-secret precision/recall against labeled ground truth.
- leaky-repo is heavy on dotfiles and credential/config files (`.netrc`,
  `.dockercfg`, `id_rsa`, `db` dumps). That favors the disclosure angle
  predisclose is built for. It does NOT exercise raw cloud/SaaS credential
  breadth or live verification, where gitleaks (about 140 rules) and trufflehog
  (800-plus rules with verification) remain ahead.
- So do not read "predisclose flagged more files" as "predisclose beats
  gitleaks". It means predisclose covers this class of file well; breadth and
  verification are a different axis this corpus does not test.

## Results

| tool | findings | files flagged (of 61) |
|---|---|---|
| gitleaks v8.30.1 | 22 | 13 |
| predisclose (default) | 39 | 18 |
| predisclose (`--proximity --entropy`) | 127 | 29 |

Finding mix:

- gitleaks: 18 `generic-api-key` (its high-entropy catch-all), 2 `private-key`,
  1 `mailchimp-api-key`, 1 `slack-user-token`.
- predisclose default: 19 `generic-assignment-secret`, 8 `email-address`, 4
  `docker-config-auth`, 2 `netrc-credentials`, 2 `private-key-block`, and 1 each
  of `slack-token`, `npmrc-auth-token`, `mailchimp-api-key`, `db-connection-uri`.
- predisclose full: the same deterministic 39, plus 88 `high-entropy-string`
  from the opt-in `--entropy` pass. That pass is noisy by design and its findings
  are low severity, which is why it is off by default.

## Where each tool wins

- Files gitleaks caught that predisclose (default) missed: `cloud/heroku.json`,
  `web/ruby/secrets.yml`. Both are high-entropy VALUES with no distinctive
  format. predisclose flags them only with `--entropy` on; it keeps that pass
  opt-in for precision, whereas gitleaks fires its `generic-api-key` catch-all
  by default. With `--entropy`, predisclose (full) misses none of gitleaks
  files.
- Files predisclose caught that gitleaks missed (16): `.netrc`,
  `.git-credentials`, `etc/shadow`, `web/var/www/public_html/.htpasswd`,
  `web/ruby/config/master.key`, `db/dump.sql`, `db/dbeaver-data-sources.xml`,
  `db/mongoid.yml`, `filezilla/recentservers.xml`, `ventrilo_srv.ini`,
  `proftpdpasswd`, `.esmtprc`, `web/var/www/.env`, `.ssh/id_rsa.pub`,
  `.mozilla/firefox/logins.json`, `high-entropy-misc.txt`. These are the
  credential and config files the disclosure angle targets.

## Takeaway

On a disclosure-heavy corpus, predisclose file-level recall is at least on par
with gitleaks and adds coverage of credential and config files gitleaks does not
flag by default. The tradeoff is deliberate: predisclose keeps high-entropy-value
detection opt-in to stay precise, and does not compete on raw credential-format
breadth or live verification.

Finding this benchmark also fixed a real bug: predisclose used to skip files with
no known extension, so `.ssh/id_rsa` and similar were silently never scanned. It
now content-sniffs extensionless files.

## Reproduce

```
git clone https://github.com/Plazmaz/leaky-repo
# optional, for the comparison column: install gitleaks and put it on PATH
python scripts/benchmark.py leaky-repo
```

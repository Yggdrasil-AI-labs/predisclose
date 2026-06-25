"""Built-in, GENERIC detection patterns.

These are universal secret/identifier shapes (cloud keys, private keys, private
IP ranges, common token formats). They contain NO organization-specific values.
Anything specific to your infrastructure (internal hostnames, private tool names,
people, locations) belongs in a private rules file loaded at runtime via --rules
or an auto-loaded `.leakguard.local.json`, never here, never in the repo.

Each entry: (id, regex, severity, message, suggestion). Severity is one of
"low" | "medium" | "high".
"""

# (id, pattern, severity, message, suggestion)
BUILTIN_PATTERNS = [
    # ---- cloud provider credentials ----
    ("aws-access-key-id", r"\bAKIA[0-9A-Z]{16}\b", "high",
     "AWS access key id", "rotate the key and remove it from the artifact"),
    ("gcp-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high",
     "Google API key", "rotate the key; load it from a secret store"),
    ("gcp-service-account", r'"type"\s*:\s*"service_account"', "high",
     "GCP service-account key JSON marker", "remove the key file; use workload identity"),
    ("azure-storage-key", r"AccountKey=[A-Za-z0-9+/]{86,}==", "high",
     "Azure Storage account key", "rotate the key; prefer a SAS token or managed identity"),
    ("azure-sas-token", r"\bsig=[A-Za-z0-9%+/]{43,}", "high",
     "Azure SAS token signature", "revoke and regenerate the SAS token"),
    ("digitalocean-token", r"\bdop_v1_[A-Za-z0-9]{32,}\b", "high",
     "DigitalOcean personal access token", "revoke the token"),

    # ---- source-control / package-registry tokens ----
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "high",
     "GitHub token", "revoke the token immediately"),
    ("github-pat-fine-grained", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", "high",
     "GitHub fine-grained PAT", "revoke the token immediately"),
    ("gitlab-pat", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", "high",
     "GitLab personal access token", "revoke the token"),
    ("npm-access-token", r"\bnpm_[A-Za-z0-9]{32,}\b", "high",
     "npm access token", "revoke the token in your npm account settings"),
    ("pypi-token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", "high",
     "PyPI API token", "revoke the token on PyPI and issue a scoped replacement"),

    # ---- SaaS / AI-provider API keys ----
    ("anthropic-api-key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", "high",
     "Anthropic API key", "revoke the key in the Anthropic console"),
    ("openai-api-key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}\b", "high",
     "OpenAI API key", "revoke the key in the OpenAI dashboard"),
    ("huggingface-token", r"\bhf_[A-Za-z0-9]{34}\b", "high",
     "Hugging Face access token", "revoke the token"),
    ("stripe-secret-key", r"\b[sr]k_(live|test)_[A-Za-z0-9]{16,}\b", "high",
     "Stripe secret/restricted key", "roll the key"),
    ("twilio-account-sid", r"\bAC[0-9a-fA-F]{32}\b", "medium",
     "Twilio Account SID", "treat as sensitive; rotate the paired auth token"),
    ("twilio-api-key", r"\bSK[0-9a-fA-F]{32}\b", "high",
     "Twilio API key SID", "revoke the API key"),
    ("sendgrid-api-key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "high",
     "SendGrid API key", "revoke the key"),
    ("mailchimp-api-key", r"\b[0-9A-Za-z]{32}-us\d{1,2}\b", "high",
     "Mailchimp API key", "revoke the key"),
    ("google-oauth-client-secret", r"\bGOCSPX-[A-Za-z0-9_\-]{20,}\b", "high",
     "Google OAuth client secret", "rotate the client secret"),
    ("square-access-token", r"\bsq0(?:atp|csp)-[A-Za-z0-9_\-]{22,}\b", "high",
     "Square access token", "revoke the token"),
    ("shopify-token", r"\bshp(?:at|ss|ca|pa)_[A-Za-z0-9]{32}\b", "high",
     "Shopify access token", "revoke the token"),
    ("postman-api-key", r"\bPMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}\b", "high",
     "Postman API key", "revoke the key"),
    ("notion-token", r"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b", "high",
     "Notion integration token", "revoke the integration token"),
    ("dropbox-token", r"\bsl\.[A-Za-z0-9_\-]{100,}\b", "high",
     "Dropbox access token", "revoke the token"),
    ("telegram-bot-token", r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b", "high",
     "Telegram bot token", "revoke the bot token via BotFather"),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "high",
     "Slack token", "revoke the token"),
    ("slack-webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+\-]+", "high",
     "Slack incoming webhook URL", "rotate the webhook"),
    ("discord-webhook",
     r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+",
     "high", "Discord webhook URL", "delete and recreate the webhook"),
    ("slack-app-token", r"\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+\b", "high",
     "Slack app-level token", "revoke the token"),

    # ---- observability / infra / platform tokens ----
    ("sentry-dsn", r"https://[0-9a-f]{32}@[\w.\-]+\.sentry\.io/\d+", "medium",
     "Sentry DSN", "rotate the DSN / client key"),
    ("databricks-pat", r"\bdapi[0-9a-f]{32}\b", "high",
     "Databricks personal access token", "revoke the token"),
    ("newrelic-api-key", r"\bNRAK-[A-Z0-9]{27}\b", "high",
     "New Relic API key", "revoke the key"),
    ("gcp-oauth-refresh-token", r"\b1//[0-9A-Za-z_\-]{30,}\b", "high",
     "Google OAuth refresh token", "revoke the token"),
    ("linear-api-key", r"\blin_api_[A-Za-z0-9_\-]{32,}\b", "high",
     "Linear API key", "revoke the key"),
    ("doppler-token", r"\bdp\.pt\.[A-Za-z0-9]{40,}\b", "high",
     "Doppler service/personal token", "revoke the token"),
    ("grafana-service-account", r"\bglsa_[A-Za-z0-9]{32}_[0-9A-Fa-f]{8}\b", "high",
     "Grafana service-account token", "revoke the token"),
    ("mailgun-api-key", r"\bkey-[0-9a-f]{32}\b", "high",
     "Mailgun API key", "revoke the key"),
    ("pulumi-token", r"\bpul-[0-9a-f]{40}\b", "high",
     "Pulumi access token", "revoke the token"),
    ("terraform-cloud-token", r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b", "high",
     "Terraform Cloud / Atlas API token", "revoke the token"),
    ("hashicorp-vault-token", r"\bhvs\.[A-Za-z0-9_\-]{24,}\b", "high",
     "HashiCorp Vault token", "revoke the token"),
    ("npmrc-auth-token", r"_authToken=[A-Za-z0-9_\-]{20,}", "high",
     ".npmrc auth token", "revoke the token; do not commit .npmrc"),
    ("atlassian-api-token", r"\bATATT3[A-Za-z0-9_\-=]{40,}\b", "high",
     "Atlassian API token", "revoke the token"),
    ("firebase-fcm-key", r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{100,}\b", "high",
     "Firebase Cloud Messaging server key", "rotate the FCM server key"),
    ("newrelic-license-key", r"\bNRAL-[A-Za-z0-9]{40}\b", "high",
     "New Relic license/ingest key", "revoke the key"),
    ("okta-token", r"\b00[A-Za-z0-9_\-]{40}\b", "medium",
     "Okta API token", "revoke the token"),
    ("azure-ad-client-secret", r"\b[A-Za-z0-9._\-]{1,8}~[A-Za-z0-9._~\-]{24,}\b", "high",
     "Azure AD client secret", "rotate the client secret in Entra ID"),
    ("docker-config-auth", r"\"auth\"\s*:\s*\"[A-Za-z0-9+/_\-]{16,}={0,2}\"", "high",
     "Docker config.json auth (base64 user:pass)", "rotate the registry credential"),
    ("jdbc-url-password",
     r"\bjdbc:[a-z0-9]+://[^\s\"']*[?&]password=[^\s&\"']{4,}", "high",
     "JDBC URL with embedded password", "move the password to a secret store"),
    ("netrc-credentials",
     r"\bmachine\s+\S+\s+login\s+\S+\s+password\s+\S{4,}", "high",
     ".netrc machine credentials", "do not commit .netrc; use a credential helper"),

    # ---- private keys / tokens / generic secret shapes ----
    ("private-key-block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
     "high", "private key block", "remove the key; never commit private keys"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b", "medium",
     "JSON Web Token", "tokens often embed claims/PII; do not commit live tokens"),
    ("db-connection-uri",
     r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^:@\s/]*:[^@\s/]+@[^\s/]+",
     "high", "database connection URI with embedded credentials",
     "move credentials to a secret store; use a credential-less DSN"),
    ("url-basic-auth", r"\bhttps?://[^:@\s/]*:[^@\s/]+@[^\s/]+", "medium",
     "URL with embedded basic-auth credentials",
     "strip user:pass from the URL; inject credentials at runtime"),
    ("generic-assignment-secret",
     r"(?i)\b(?:api[_-]?key|client[_-]?secret|secret|passwd|password|token|access[_-]?key)\b"
     r"\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?",
     "medium", "hard-coded secret assignment",
     "load from an environment variable or secret store, not source"),
    ("authorization-header",
     r"(?i)\bauthorization\b\s*[:=]\s*[\"']?(?:bearer|basic|token)\s+[A-Za-z0-9._\-+/=]{8,}",
     "medium", "Authorization header with embedded credential",
     "do not hard-code credentials in headers; inject them at runtime"),

    # ---- private / non-routable network addresses ----
    # Written so example/doc ranges (RFC5737 203.0.113.x / 192.0.2.x / 198.51.100.x)
    # do NOT match. Lookaround avoids version-string false positives like 1.10.0.0.
    ("private-ip", r"(?<![\d.])(?:"
                   r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                   r"|192\.168\.\d{1,3}\.\d{1,3}"
                   r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                   r")(?![\d.])",
     "medium", "RFC1918 private IP address",
     "replace with an RFC5737 placeholder (203.0.113.x) or drop it"),
    ("cgnat-ip", r"(?<![\d.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(?![\d.])",
     "medium", "CGNAT / Tailscale-range IP (100.64/10)",
     "drop internal overlay addresses"),
    ("tailscale-magicdns", r"\b[A-Za-z0-9-]+\.ts\.net\b", "medium",
     "Tailscale MagicDNS hostname", "use a generic hostname"),

    # ---- PII (commonly over-shared; tune/disable per project) ----
    ("email-address",
     r"\b[A-Za-z0-9._%+\-]+@(?!example\.(?:com|org|net)\b)[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
     "low", "email address (possible PII)",
     "use a role/no-reply address or redact"),
]


# Prefilter anchors: lowercase literal substring(s), AT LEAST ONE of which MUST
# appear in any match of the rule. Used to skip a rule's regex when none are
# present (big speedup on lines with no secrets). Each anchor MUST be a guaranteed
# (case-insensitive) substring of every match or matches will be missed. Rules
# absent here (or with no reliable literal, e.g. twilio AC/SK, telegram, okta)
# have no prefilter and always run.
ANCHORS = {
    "aws-access-key-id": ["akia"],
    "gcp-api-key": ["aiza"],
    "gcp-service-account": ["service_account"],
    "azure-storage-key": ["accountkey="],
    "azure-sas-token": ["sig="],
    "digitalocean-token": ["dop_v1_"],
    "github-token": ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
    "github-pat-fine-grained": ["github_pat_"],
    "gitlab-pat": ["glpat-"],
    "npm-access-token": ["npm_"],
    "pypi-token": ["pypi-ageichlwas5vcmc"],
    "anthropic-api-key": ["sk-ant-"],
    "openai-api-key": ["sk-"],
    "huggingface-token": ["hf_"],
    "stripe-secret-key": ["k_live_", "k_test_"],
    "sendgrid-api-key": ["sg."],
    "mailchimp-api-key": ["-us"],
    "google-oauth-client-secret": ["gocspx-"],
    "square-access-token": ["sq0atp-", "sq0csp-"],
    "shopify-token": ["shpat_", "shpss_", "shpca_", "shppa_"],
    "postman-api-key": ["pmak-"],
    "notion-token": ["secret_", "ntn_"],
    "dropbox-token": ["sl."],
    "slack-token": ["xox"],
    "slack-webhook": ["hooks.slack.com"],
    "discord-webhook": ["discord"],
    "slack-app-token": ["xapp-"],
    "sentry-dsn": ["sentry.io"],
    "databricks-pat": ["dapi"],
    "newrelic-api-key": ["nrak-"],
    "gcp-oauth-refresh-token": ["1//"],
    "linear-api-key": ["lin_api_"],
    "doppler-token": ["dp.pt."],
    "grafana-service-account": ["glsa_"],
    "mailgun-api-key": ["key-"],
    "pulumi-token": ["pul-"],
    "terraform-cloud-token": [".atlasv1."],
    "hashicorp-vault-token": ["hvs."],
    "npmrc-auth-token": ["_authtoken="],
    "atlassian-api-token": ["atatt3"],
    "firebase-fcm-key": ["aaaa"],
    "newrelic-license-key": ["nral-"],
    "azure-ad-client-secret": ["~"],
    "docker-config-auth": ['"auth"'],
    "jdbc-url-password": ["jdbc:"],
    "netrc-credentials": ["machine"],
    "private-key-block": ["private key"],
    "jwt": ["eyj"],
    "db-connection-uri": ["postgres", "mysql", "mongodb", "redis", "amqp"],
    "url-basic-auth": ["://"],
    "generic-assignment-secret": ["key", "secret", "passwd", "password", "token"],
    "authorization-header": ["authorization"],
    "private-ip": ["10.", "192.168.", "172."],
    "cgnat-ip": ["100."],
    "tailscale-magicdns": [".ts.net"],
    "email-address": ["@"],
}


def builtin_rules():
    """Return BUILTIN_PATTERNS as plain dicts (engine compiles them)."""
    return [
        {"id": i, "pattern": p, "severity": s, "message": m, "suggestion": g,
         "anchor": ANCHORS.get(i)}
        for (i, p, s, m, g) in BUILTIN_PATTERNS
    ]

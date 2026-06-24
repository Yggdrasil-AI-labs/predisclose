"""Built-in, GENERIC detection patterns.

These are universal secret/identifier shapes (cloud keys, private keys, private
IP ranges, common token formats). They contain NO organization-specific values.
Anything specific to your infrastructure (internal hostnames, private tool names,
people, locations) belongs in a private rules file loaded at runtime via --rules
or an auto-loaded `.leakguard.local.json` — never here, never in the repo.

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
    ("digitalocean-token", r"\bdop_v1_[a-f0-9]{64}\b", "high",
     "DigitalOcean personal access token", "revoke the token"),

    # ---- source-control / package-registry tokens ----
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "high",
     "GitHub token", "revoke the token immediately"),
    ("github-pat-fine-grained", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", "high",
     "GitHub fine-grained PAT", "revoke the token immediately"),
    ("gitlab-pat", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", "high",
     "GitLab personal access token", "revoke the token"),
    ("npm-access-token", r"\bnpm_[A-Za-z0-9]{36}\b", "high",
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
    ("stripe-secret-key", r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b", "high",
     "Stripe secret key", "roll the key"),
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

    # ---- private keys / tokens / generic secret shapes ----
    ("private-key-block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
     "high", "private key block", "remove the key; never commit private keys"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b", "medium",
     "JSON Web Token", "tokens often embed claims/PII; do not commit live tokens"),
    ("db-connection-uri",
     r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^:@\s/]+:[^@\s/]+@[^\s/]+",
     "high", "database connection URI with embedded credentials",
     "move credentials to a secret store; use a credential-less DSN"),
    ("url-basic-auth", r"\bhttps?://[^:@\s/]+:[^@\s/]+@[^\s/]+", "medium",
     "URL with embedded basic-auth credentials",
     "strip user:pass from the URL; inject credentials at runtime"),
    ("generic-assignment-secret",
     r"(?i)\b(?:api[_-]?key|secret|passwd|password|token|access[_-]?key)\b\s*[:=]\s*"
     r"['\"][^'\"\s]{8,}['\"]",
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


def builtin_rules():
    """Return BUILTIN_PATTERNS as plain dicts (engine compiles them)."""
    return [
        {"id": i, "pattern": p, "severity": s, "message": m, "suggestion": g}
        for (i, p, s, m, g) in BUILTIN_PATTERNS
    ]

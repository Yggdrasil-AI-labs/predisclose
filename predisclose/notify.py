"""Push a findings summary to a webhook (Slack / Discord / generic). Stdlib only.

Opt-in: fires only when a webhook URL is configured (`--notify-webhook` or the
`PREDISCLOSE_WEBHOOK` env var). The CLI calls it only when there are findings at or
above the fail threshold, so a webhook means "predisclose found something you said
should block." Never raises: a notification problem prints a one-line note and
never breaks the scan or changes its exit code.

Payload style (`--notify-style` / `PREDISCLOSE_WEBHOOK_STYLE`):
  slack   (default)  -> {"text": <summary>}     Slack / Mattermost incoming webhooks
  discord            -> {"content": <summary>}   Discord webhooks
  generic            -> {"text": <summary>, "findings": [<finding dicts>]}
"""
import json
import os
import sys
import urllib.request

DISCORD_LIMIT = 1900  # Discord content cap is 2000 chars; leave headroom


def webhook_from_env():
    return os.environ.get("PREDISCLOSE_WEBHOOK", "")


def style_from_env(default="slack"):
    return os.environ.get("PREDISCLOSE_WEBHOOK_STYLE", default)


def build_payload(style, text, findings):
    style = (style or "slack").lower()
    if style == "discord":
        return {"content": text[:DISCORD_LIMIT]}
    if style == "generic":
        return {"text": text, "findings": [f.as_dict() for f in findings]}
    return {"text": text}  # slack / mattermost / default


def notify(url, summary_text, findings, style=None, timeout=15):
    """POST the summary to the webhook. Returns True on success, False otherwise."""
    if not url:
        return False
    payload = build_payload(style or style_from_env(), summary_text, findings)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "predisclose"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read()
        return True
    except Exception as e:
        print(f"predisclose: webhook notify failed: {e}", file=sys.stderr)
        return False

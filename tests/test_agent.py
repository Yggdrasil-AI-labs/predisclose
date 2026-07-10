"""leakguard agent-loop tests (stdlib unittest; the local-model HTTP call is
mocked via ai._http_post_json, so the suite runs with no model and no network).

Run: python -m unittest
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from leakguard import agent, ai, cli
from leakguard.engine import Finding


def _finding(match, rule_id="generic-assignment-secret", severity="high",
             path="f.py", line=1):
    return Finding(rule_id=rule_id, severity=severity, path=path, line=line,
                   column=1, match=match, message="m", suggestion="fix it")


def _resp(verdict, confidence=0.9, reason="r", action="a"):
    body = {"verdict": verdict, "confidence": confidence,
            "reason": reason, "action": action}
    return {"choices": [{"message": {"content": json.dumps(body)}}]}


def _verdict_by_match(rules):
    """Return a fake _http_post_json that picks a verdict from the matched_text
    in the request payload, using the mapping in `rules` (default real_leak)."""
    def fake_post(url, payload, headers, timeout):
        user = json.loads(payload["messages"][1]["content"])
        verdict = rules.get(user["matched_text"], "real_leak")
        return _resp(verdict)
    return fake_post


CFG = {"base": "http://x/v1", "model": "m", "key": "", "timeout": 1.0,
       "max_chars": 1000}


class TestTriage(unittest.TestCase):
    def test_classifies_each_verdict(self):
        for verdict in ("real_leak", "false_positive", "allowlist_candidate"):
            with mock.patch.object(ai, "_http_post_json",
                                   return_value=_resp(verdict)):
                out = agent.triage_finding(_finding("x"), "line\nx\nline", CFG)
            self.assertEqual(out["verdict"], verdict)

    def test_unavailable_model_is_conservative_real_leak(self):
        def boom(*a, **k):
            raise OSError("connection refused")
        with mock.patch.object(ai, "_http_post_json", boom):
            out = agent.triage_finding(_finding("x"), "x", CFG)
        self.assertEqual(out["verdict"], "real_leak")
        self.assertEqual(out["confidence"], 0.0)

    def test_garbage_verdict_falls_back_to_real_leak(self):
        with mock.patch.object(ai, "_http_post_json",
                               return_value=_resp("maybe?")):
            out = agent.triage_finding(_finding("x"), "x", CFG)
        self.assertEqual(out["verdict"], "real_leak")


class TestAgentLoop(unittest.TestCase):
    def _scanner_for(self, finding):
        # Emits `finding` until its match is on the allowlist, then reports clean.
        def scanner(paths, rules, allow, root):
            return ([] if finding.match in allow else [finding]), 1
        return scanner

    def test_real_leak_blocks_and_reports(self):
        f = _finding("AKIAREAL...KEY", rule_id="aws-access-key-id")
        with mock.patch.object(ai, "_http_post_json",
                               _verdict_by_match({})):  # -> real_leak
            res = agent.run_agent(["."], [], set(), cfg=CFG,
                                  scanner=self._scanner_for(f),
                                  reader=lambda p: "AKIAREAL...KEY")
        self.assertFalse(res["clean"])
        self.assertEqual([x.match for x in res["real_leaks"]], ["AKIAREAL...KEY"])
        self.assertEqual(res["proposed_allow"], [])

    def test_allowlist_candidate_proposed_but_not_written(self):
        f = _finding("press@publicco.io", rule_id="email-address", severity="low")
        with tempfile.TemporaryDirectory() as d:
            lr = os.path.join(d, ".leakguard.local.json")
            with mock.patch.object(ai, "_http_post_json", _verdict_by_match(
                    {"press@publicco.io": "allowlist_candidate"})):
                res = agent.run_agent(["."], [], set(), cfg=CFG, apply_allow=False,
                                      local_rules_path=lr,
                                      scanner=self._scanner_for(f),
                                      reader=lambda p: "press@publicco.io")
            self.assertEqual(res["proposed_allow"], ["press@publicco.io"])
            self.assertEqual(res["applied_allow"], [])
            self.assertFalse(os.path.exists(lr))  # proposal-only: nothing written

    def test_apply_allow_writes_and_reaches_clean(self):
        f = _finding("press@publicco.io", rule_id="email-address", severity="low")
        with tempfile.TemporaryDirectory() as d:
            lr = os.path.join(d, ".leakguard.local.json")
            with mock.patch.object(ai, "_http_post_json", _verdict_by_match(
                    {"press@publicco.io": "allowlist_candidate"})):
                res = agent.run_agent(["."], [], set(), cfg=CFG, apply_allow=True,
                                      max_steps=3, local_rules_path=lr,
                                      scanner=self._scanner_for(f),
                                      reader=lambda p: "press@publicco.io")
            self.assertTrue(res["clean"])
            self.assertEqual(res["applied_allow"], ["press@publicco.io"])
            self.assertGreaterEqual(res["steps"], 2)  # applied, then re-scanned clean
            with open(lr, encoding="utf-8") as fh:
                written = json.load(fh)
            self.assertIn("press@publicco.io", written["allow"])

    def test_step_budget_is_honored(self):
        # A finding the model keeps calling a real_leak never resolves; the loop
        # must stop at max_steps rather than spin.
        f = _finding("AKIAREAL...KEY", rule_id="aws-access-key-id")
        with mock.patch.object(ai, "_http_post_json", _verdict_by_match({})):
            res = agent.run_agent(["."], [], set(), cfg=CFG, max_steps=2,
                                  apply_allow=True,
                                  scanner=self._scanner_for(f),
                                  reader=lambda p: "x")
        self.assertLessEqual(res["steps"], 2)


class TestAgentWebhook(unittest.TestCase):
    """End-to-end through cli.main: the agent pushes only the confirmed,
    blocking real leaks to the webhook. cli imports `notify` into its own
    namespace, so that is the patch target."""

    def test_pushes_confirmed_blocking_leak(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "conf.txt"), "w", encoding="utf-8") as fh:
                fh.write('github_token = "ghp_' + "a" * 36 + '"\n')
            calls = []
            with mock.patch.object(ai, "_http_post_json", _verdict_by_match({})), \
                 mock.patch.object(cli, "notify",
                                   lambda url, summary, findings, style=None:
                                   calls.append((url, findings)) or True):
                rc = cli.main(["agent", d, "--notify-webhook", "http://hook",
                               "--no-color", "--fail-on", "high"])
            self.assertEqual(rc, 1)
            self.assertEqual(len(calls), 1)
            url, findings = calls[0]
            self.assertEqual(url, "http://hook")
            self.assertTrue(any(f.rule_id == "github-token" for f in findings))

    def test_no_push_when_nothing_blocks(self):
        # An allowlist_candidate is not a real_leak, so nothing should be pushed.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "c.txt"), "w", encoding="utf-8") as fh:
                fh.write("email = hello@publicco.io\n")
            calls = []
            with mock.patch.object(ai, "_http_post_json", _verdict_by_match(
                    {"hello@publicco.io": "allowlist_candidate"})), \
                 mock.patch.object(cli, "notify",
                                   lambda *a, **k: calls.append(a) or True):
                cli.main(["agent", d, "--notify-webhook", "http://hook",
                          "--no-color", "--fail-on", "low"])
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()

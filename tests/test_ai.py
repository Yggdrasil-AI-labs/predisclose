"""predisclose AI-layer tests (stdlib unittest; presidio + the HTTP call are
mocked so the suite runs without the heavy `predisclose[ai]` dependencies).

Run: python -m unittest
"""
import json
import unittest
from unittest import mock

from predisclose import ai
from predisclose.engine import Finding


class FakeResult:
    """Stand-in for presidio_analyzer.RecognizerResult."""
    def __init__(self, entity_type, start, end, score):
        self.entity_type = entity_type
        self.start = start
        self.end = end
        self.score = score


class FakeAnalyzer:
    def __init__(self, results):
        self._results = results

    def analyze(self, text, language="en", **kw):
        return self._results


def _reset_ai_state():
    ai._ANALYZER = None
    ai._ANALYZER_TRIED = False
    ai._PRESIDIO_HINTED = False
    ai._LLM_ERROR_HINTED = False


def _chat_response(content):
    return {"choices": [{"message": {"content": content}}]}


class TestPresidio(unittest.TestCase):
    def setUp(self):
        _reset_ai_state()

    def tearDown(self):
        _reset_ai_state()

    def test_maps_entities_to_findings(self):
        text = "line one\ncontact John Smith now"
        start = text.index("John Smith")
        ai._ANALYZER = FakeAnalyzer([FakeResult("PERSON", start, start + 10, 0.9)])
        fs = ai.presidio_scan(text, allow=set(), path="f.txt")
        self.assertEqual(len(fs), 1)
        self.assertIsInstance(fs[0], Finding)
        self.assertEqual(fs[0].rule_id, "presidio:PERSON")
        self.assertEqual(fs[0].severity, "medium")
        self.assertEqual(fs[0].line, 2)
        self.assertEqual(fs[0].match, "John Smith")

    def test_entity_severity_mapping(self):
        text = "4111111111111111"
        ai._ANALYZER = FakeAnalyzer([FakeResult("CREDIT_CARD", 0, 16, 0.99)])
        fs = ai.presidio_scan(text, path="f.txt")
        self.assertEqual(fs[0].severity, "high")

    def test_unknown_entity_defaults_medium(self):
        text = "zzz"
        ai._ANALYZER = FakeAnalyzer([FakeResult("MADE_UP_ENTITY", 0, 3, 0.99)])
        fs = ai.presidio_scan(text, path="f.txt")
        self.assertEqual(fs[0].severity, ai.DEFAULT_PRESIDIO_SEVERITY)

    def test_threshold_drops_low_score(self):
        ai._ANALYZER = FakeAnalyzer([FakeResult("PERSON", 0, 10, 0.2)])
        self.assertEqual(ai.presidio_scan("John Smith", path="f.txt"), [])

    def test_allow_list_drops_match(self):
        ai._ANALYZER = FakeAnalyzer([FakeResult("PERSON", 0, 10, 0.9)])
        fs = ai.presidio_scan("John Smith", allow={"John Smith"}, path="f.txt")
        self.assertEqual(fs, [])

    def test_missing_presidio_skips_cleanly(self):
        # Force the "presidio not installed" path regardless of the environment.
        with mock.patch.object(ai, "_get_analyzer", return_value=None):
            fs = ai.presidio_scan("anything sensitive", path="f.txt")
        self.assertEqual(fs, [])


class TestLLMReview(unittest.TestCase):
    def setUp(self):
        _reset_ai_state()

    def tearDown(self):
        _reset_ai_state()

    def test_parses_findings_and_locates_column(self):
        text = "alpha\nsecret_token = ABC123XYZ\nbeta"
        captured = {}

        def fake_post(url, payload, headers, timeout):
            captured["url"] = url
            captured["payload"] = payload
            return _chat_response(
                '{"findings": [{"line": 2, "severity": "high", '
                '"match": "ABC123XYZ", "message": "hardcoded token", '
                '"suggestion": "use env var"}]}')

        with mock.patch.object(ai, "_http_post_json", fake_post):
            fs = ai.llm_review_scan(text, [], path="f.py")

        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].rule_id, "llm-review")
        self.assertEqual(fs[0].severity, "high")
        self.assertEqual(fs[0].line, 2)
        self.assertEqual(fs[0].match, "ABC123XYZ")
        self.assertEqual(fs[0].column,
                         text.splitlines()[1].index("ABC123XYZ") + 1)
        self.assertTrue(captured["url"].endswith("/v1/chat/completions"))
        self.assertEqual(captured["payload"]["messages"][0]["role"], "system")

    def test_default_endpoint_is_localhost(self):
        # Critical safety property: the shipped default must never be a remote
        # host. (Assumes no PREDISCLOSE_LLM_BASE override in the test environment.)
        cfg = ai.llm_config_from_env()
        self.assertTrue(cfg["base"].startswith("http://localhost"),
                        f"default base must be localhost, got {cfg['base']!r}")
        self.assertEqual(ai.DEFAULT_LLM_BASE, "http://localhost:11434/v1")

    def test_unreachable_endpoint_returns_empty(self):
        def boom(url, payload, headers, timeout):
            raise OSError("connection refused")

        with mock.patch.object(ai, "_http_post_json", boom):
            fs = ai.llm_review_scan("x", [], path="f.py")
        self.assertEqual(fs, [])

    def test_allow_list_drops_llm_match(self):
        def fake_post(url, payload, headers, timeout):
            return _chat_response(
                '{"findings": [{"line": 1, "severity": "low", '
                '"match": "public-handle", "message": "x"}]}')

        with mock.patch.object(ai, "_http_post_json", fake_post):
            fs = ai.llm_review_scan("public-handle", [], path="f",
                                    allow={"public-handle"})
        self.assertEqual(fs, [])

    def test_handles_json_in_code_fence(self):
        def fake_post(url, payload, headers, timeout):
            return _chat_response('```json\n{"findings": []}\n```')

        with mock.patch.object(ai, "_http_post_json", fake_post):
            fs = ai.llm_review_scan("x", [], path="f")
        self.assertEqual(fs, [])

    def test_malformed_content_returns_empty(self):
        def fake_post(url, payload, headers, timeout):
            return _chat_response("sorry, I cannot help with that")

        with mock.patch.object(ai, "_http_post_json", fake_post):
            fs = ai.llm_review_scan("x", [], path="f")
        self.assertEqual(fs, [])

    def test_bad_line_falls_back_to_search(self):
        text = "one\ntwo SEKRET three"

        def fake_post(url, payload, headers, timeout):
            return _chat_response(
                '{"findings": [{"line": 999, "severity": "high", '
                '"match": "SEKRET", "message": "leak"}]}')

        with mock.patch.object(ai, "_http_post_json", fake_post):
            fs = ai.llm_review_scan(text, [], path="f")
        self.assertEqual(fs[0].line, 2)


class TestHook(unittest.TestCase):
    def setUp(self):
        _reset_ai_state()

    def tearDown(self):
        _reset_ai_state()

    def test_no_layers_returns_none(self):
        self.assertIsNone(ai.make_hook(False, False))

    def test_review_sees_prior_and_presidio_findings(self):
        text = "alice@example.net is the contact"
        end = len("alice@example.net")
        ai._ANALYZER = FakeAnalyzer([FakeResult("EMAIL_ADDRESS", 0, end, 0.9)])
        seen = {}

        def fake_post(url, payload, headers, timeout):
            seen["payload"] = payload
            return _chat_response('{"findings": []}')

        base = [Finding("aws-access-key-id", "high", "f", 1, 1, "AKIA...",
                        "key", "rotate")]
        with mock.patch.object(ai, "_http_post_json", fake_post):
            hook = ai.make_hook(use_presidio=True, use_review=True, allow=set())
            out = hook(text, "f", base)

        self.assertTrue(any(f.rule_id.startswith("presidio:") for f in out))
        user_msg = json.loads(seen["payload"]["messages"][1]["content"])
        rules_seen = {af["rule"] for af in user_msg["already_found"]}
        self.assertIn("aws-access-key-id", rules_seen)
        self.assertTrue(any(r.startswith("presidio:") for r in rules_seen))


if __name__ == "__main__":
    unittest.main()

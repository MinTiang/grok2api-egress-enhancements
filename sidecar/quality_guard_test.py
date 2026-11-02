#!/usr/bin/env python3
"""Tests for the quality guard classifiers and the account-first response.

Run with:  python3 sidecar/quality_guard_test.py
Standard library only, so the image and CI need no extra packages.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("quality_guard.py")


def _load_guard():
    spec = importlib.util.spec_from_file_location("quality_guard", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # dataclasses resolve string annotations via sys.modules[cls.__module__],
    # so the module must be registered before exec_module runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


quality_guard = _load_guard()


def config(**overrides):
    """A Config with production-shaped defaults and no I/O."""
    values = {
        "base_url": "http://grok2api:8000",
        "internal_token": "test-token",
        "model": "grok-4.5",
        "node_ids": (),
        "mode": "passive",
        "active_interval_seconds": 1800,
        "passive_poll_seconds": 5,
        "passive_page_size": 200,
        "passive_max_pages": 10,
        "jitter_seconds": 30,
        "request_timeout_seconds": 120,
        "soft_tps": 200.0,
        "hard_tps": 1000.0,
        "consecutive_soft": 2,
        "consecutive_errors": 2,
        "quarantine_seconds": 30,
        "no_account_backoff_seconds": 300,
        "min_healthy_nodes": 1,
        "max_output_tokens": 384,
        "fail_closed": True,
        "enabled": True,
        "quarantine_enabled": True,
        "account_degrade_enabled": True,
        "account_degrade_window_seconds": 600,
        "account_degrade_accounts": 3,
        "min_generation_ms": 1000,
        "rotation_url": "",
        "rotation_token": "",
        "rotation_timeout_seconds": 45,
        "rotatable_node_ids": (),
        "prompt": "probe prompt",
        "expected": "QUALITY_OK",
        "state_file": pathlib.Path("/tmp/state.json"),
        "lock_file": pathlib.Path("/tmp/guard.lock"),
        "runtime_config_file": pathlib.Path("/tmp/runtime-config.json"),
    }
    values.update(overrides)
    return quality_guard.Config(**values)


def audit(**overrides):
    """A successful grok_build streaming sample. 100 output tokens over 2s."""
    values = {
        "provider": "grok_build",
        "streaming": True,
        "statusCode": 200,
        "firstTokenMs": 500,
        "durationMs": 2500,
        "outputTokens": 100,
        "reasoningTokens": 40,
    }
    values.update(overrides)
    return values


def probe(**overrides):
    values = {
        "expectedMatched": True,
        "outputTokens": 120,
        "reasoningTokens": 60,
        "firstTokenMs": 500,
        "durationMs": 2000,
        "outputTokensPerSecond": 80.0,
    }
    values.update(overrides)
    return values


class GenerationWindowTests(unittest.TestCase):
    def test_plain_tail_is_duration_minus_first_token(self):
        self.assertEqual(quality_guard.generation_window_ms(500, 2500), 2000)

    def test_degenerate_windows_are_zero(self):
        self.assertEqual(quality_guard.generation_window_ms(0, 0), 0)
        self.assertEqual(quality_guard.generation_window_ms(2500, 2500), 0)
        self.assertEqual(quality_guard.generation_window_ms(3000, 2500), 0)

    def test_short_tail_with_reasoning_uses_full_duration(self):
        # 9000ms first-token wait, 300ms tail, but 900 reasoning tokens:
        # the tail is a flush artefact, not a 300ms generation.
        self.assertEqual(quality_guard.generation_window_ms(9000, 9300, 900), 9300)

    def test_short_tail_without_reasoning_stays_short(self):
        # No reasoning evidence: keep the tail so a real burst stays visible.
        self.assertEqual(quality_guard.generation_window_ms(9000, 9300, 0), 300)

    def test_negative_first_token_is_clamped(self):
        self.assertEqual(quality_guard.generation_window_ms(-50, 2000), 2000)


class ClassifyAuditTests(unittest.TestCase):
    def test_never_reports_missing_thinking(self):
        """A zero-reasoning user stream is an account symptom, not a node one."""
        cfg = config()
        for tokens in (32, 40, 64, 200):
            for reasoning in (0, 1):
                classification, reason, _speed, _out = quality_guard.classify_audit(
                    audit(outputTokens=tokens, reasoningTokens=reasoning), cfg
                )
                self.assertNotEqual(reason, "missing_thinking")
                self.assertIn(classification, {"healthy", "soft", "hard"})

    def test_slow_but_healthy_sample(self):
        # 100 tokens / 2000ms = 50 TPS, below soft.
        classification, reason, speed, _ = quality_guard.classify_audit(audit(), config())
        self.assertEqual((classification, reason), ("healthy", "within_threshold"))
        self.assertAlmostEqual(speed, 50.0)

    def test_soft_threshold(self):
        # 500 tokens / 2000ms = 250 TPS, above soft 200, below hard 1000.
        classification, reason, _speed, _ = quality_guard.classify_audit(
            audit(outputTokens=500), config()
        )
        self.assertEqual((classification, reason), ("soft", "soft_tps"))

    def test_hard_threshold(self):
        # 3000 tokens / 2000ms = 1500 TPS.
        classification, reason, _speed, _ = quality_guard.classify_audit(
            audit(outputTokens=3000), config()
        )
        self.assertEqual((classification, reason), ("hard", "hard_tps"))

    def test_buffered_burst_in_fail_closed(self):
        # 400 tokens in a 400ms tail = 1000 TPS in a sub-1s window.
        classification, reason, _speed, _ = quality_guard.classify_audit(
            audit(outputTokens=400, durationMs=900), config(fail_closed=True)
        )
        self.assertEqual((classification, reason), ("hard", "buffered_burst"))

    def test_reasoning_tail_is_not_a_burst(self):
        """The generation-window fix must stop false buffered_burst."""
        # 9000ms to first token, 900 reasoning tokens, 300ms tail.
        # Naive duration-first_token gives a huge TPS; the corrected window
        # makes it a normal sample.
        value = audit(outputTokens=900, reasoningTokens=900, firstTokenMs=9000, durationMs=9300)
        classification, reason, _speed, _ = quality_guard.classify_audit(value, config())
        self.assertEqual((classification, reason), ("healthy", "within_threshold"))

    def test_ignored_samples(self):
        cfg = config()
        self.assertEqual(quality_guard.classify_audit(audit(provider="web"), cfg)[0], "ignored")
        self.assertEqual(quality_guard.classify_audit(audit(streaming=False), cfg)[0], "ignored")
        self.assertEqual(quality_guard.classify_audit(audit(statusCode=500), cfg)[0], "ignored")
        self.assertEqual(quality_guard.classify_audit(audit(errorCode="timeout"), cfg)[0], "ignored")
        self.assertEqual(quality_guard.classify_audit(audit(firstTokenMs=None), cfg)[0], "ignored")
        self.assertEqual(quality_guard.classify_audit(audit(outputTokens=20), cfg)[0], "ignored")


class ClassifyResultTests(unittest.TestCase):
    def test_missing_thinking_only_when_requested(self):
        degraded = probe(outputTokens=120, reasoningTokens=0)
        self.assertEqual(
            quality_guard.classify_result({**degraded, "thinkingRequired": True}, config())[:2],
            ("hard", "missing_thinking"),
        )
        # Throughput probes and non-thinking models must not be flagged.
        self.assertNotEqual(
            quality_guard.classify_result({**degraded, "thinkingRequired": False}, config())[1],
            "missing_thinking",
        )
        self.assertNotEqual(
            quality_guard.classify_result(degraded, config())[1],
            "missing_thinking",
        )

    def test_short_reply_with_thinking_required_is_not_missing_thinking(self):
        # Below the 64-token guard floor: judged on tokens, not thinking.
        result = probe(outputTokens=40, reasoningTokens=0, thinkingRequired=True)
        classification, reason = quality_guard.classify_result(result, config())[:2]
        self.assertNotEqual(reason, "missing_thinking")
        self.assertEqual(classification, "healthy")

    def test_marker_missing_is_soft(self):
        self.assertEqual(
            quality_guard.classify_result(probe(expectedMatched=False), config())[:2],
            ("soft", "expected_marker_missing"),
        )

    def test_insufficient_output_tokens_is_soft(self):
        self.assertEqual(
            quality_guard.classify_result(probe(outputTokens=10), config())[:2],
            ("soft", "insufficient_output_tokens"),
        )

    def test_tps_thresholds(self):
        cfg = config()
        self.assertEqual(quality_guard.classify_result(probe(outputTokensPerSecond=1500.0), cfg)[:2],
                         ("hard", "hard_tps"))
        self.assertEqual(quality_guard.classify_result(probe(outputTokensPerSecond=300.0), cfg)[:2],
                         ("soft", "soft_tps"))
        self.assertEqual(quality_guard.classify_result(probe(outputTokensPerSecond=80.0), cfg)[:2],
                         ("healthy", "within_threshold"))

    def test_tps_is_recomputed_when_absent(self):
        # classify_result returns (class, reason) only, so exercise the shared
        # helper the guard now falls back to when the probe omits TPS.
        self.assertAlmostEqual(
            quality_guard.output_tokens_per_second(200, 500, 2500, 100), 100.0
        )


class StateMappingTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        self.guard = quality_guard.Guard.__new__(quality_guard.Guard)
        self.guard.config = self.cfg
        self.guard.state = {
            "version": 1,
            "nodes": {},
            "statistics": quality_guard.default_statistics(),
        }

    def test_distinct_accounts_count_once(self):
        guard = self.guard
        count = guard._note_node_degrade_account("7", "11", now=1000.0)
        self.assertEqual(count, 1)
        count = guard._note_node_degrade_account("7", "11", now=1010.0)
        self.assertEqual(count, 1, "same account must not count twice")
        count = guard._note_node_degrade_account("7", "12", now=1020.0)
        self.assertEqual(count, 2)

    def test_old_samples_age_out(self):
        guard = self.guard
        guard._note_node_degrade_account("7", "11", now=1000.0)
        guard._note_node_degrade_account("7", "12", now=1000.0)
        # Window is 600s; move well past it.
        count = guard._note_node_degrade_account("7", "13", now=1000.0 + 601)
        self.assertEqual(count, 1)

    def test_sample_list_is_bounded(self):
        guard = self.guard
        for index in range(80):
            guard._note_node_degrade_account("7", str(index), now=1000.0 + index)
        samples = guard.state["nodes"]["7"]["degrade_account_samples"]
        self.assertLessEqual(len(samples), 50)


class RuntimeConfigSchemaTests(unittest.TestCase):
    """The upstream schema has no `enabled`; we must accept both."""

    def _write(self, settings):
        import json
        import tempfile

        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump({"version": 1, "settings": settings}, handle)
        handle.close()
        return pathlib.Path(handle.name)

    def _upstream_settings(self, **overrides):
        values = {
            "mode": "passive",
            "active_interval_seconds": 1800,
            "passive_poll_seconds": 5,
            "soft_tps": 200,
            "hard_tps": 1000,
            "consecutive_soft": 2,
            "consecutive_errors": 2,
            "quarantine_seconds": 30,
            "min_healthy_nodes": 1,
        }
        values.update(overrides)
        return values

    def test_upstream_schema_without_enabled_is_accepted(self):
        path = self._write(self._upstream_settings())
        try:
            result = quality_guard.load_runtime_config(config(), path)
        finally:
            path.unlink()
        self.assertEqual(result.soft_tps, 200.0)
        self.assertTrue(result.enabled, "absent enabled must default to on")

    def test_local_schema_with_enabled_is_still_accepted(self):
        path = self._write(self._upstream_settings(enabled=False))
        try:
            result = quality_guard.load_runtime_config(config(), path)
        finally:
            path.unlink()
        self.assertFalse(result.enabled)

    def test_unknown_field_is_rejected(self):
        path = self._write(self._upstream_settings(surprise=1))
        try:
            with self.assertRaises(ValueError):
                quality_guard.load_runtime_config(config(), path)
        finally:
            path.unlink()

    def test_missing_required_field_is_rejected(self):
        settings = self._upstream_settings()
        settings.pop("soft_tps")
        path = self._write(settings)
        try:
            with self.assertRaises(ValueError):
                quality_guard.load_runtime_config(config(), path)
        finally:
            path.unlink()


class LeaseCapabilityTests(unittest.TestCase):
    """A guard paired with an image lacking /egress-leases must not crash."""

    def _guard(self, api):
        guard = quality_guard.Guard.__new__(quality_guard.Guard)
        guard.config = config()
        guard.state = {"version": 1, "nodes": {}, "statistics": quality_guard.default_statistics()}
        guard.api = api
        guard.rank = {}
        guard._admin = None
        guard._lease_supported = None
        guard._save = lambda: None
        return guard

    def test_lease_scoped_detection(self):
        self.assertTrue(quality_guard.Guard._is_lease_scoped({"accountBoundProxy": True}))
        self.assertFalse(quality_guard.Guard._is_lease_scoped({"accountBoundProxy": False}))
        self.assertFalse(quality_guard.Guard._is_lease_scoped({}))

    def test_403_downgrades_and_caches(self):
        calls = []

        class Api:
            def list_leases(self):
                calls.append(1)
                raise quality_guard.ApiError(403, "forbidden", "denied")

        guard = self._guard(Api())
        self.assertFalse(guard._lease_api_available())
        self.assertFalse(guard._lease_api_available())
        self.assertEqual(len(calls), 1, "capability must be probed only once")

    def test_500_is_inconclusive_not_permanent(self):
        class Api:
            def list_leases(self):
                raise quality_guard.ApiError(503, "unavailable", "later")

        guard = self._guard(Api())
        self.assertFalse(guard._lease_api_available())
        self.assertIsNone(guard._lease_supported, "transient errors must not cache a downgrade")

    def test_lease_node_is_never_node_quarantined(self):
        disabled = []

        class Api:
            def set_enabled(self, node_id, enabled):
                disabled.append((node_id, enabled))
                return 1

        guard = self._guard(Api())
        node = {"id": "5", "name": "lease-node", "enabled": True, "accountBoundProxy": True}
        guard._quarantine([node], node, "missing_thinking", 1000.0, recover_now=False)
        self.assertEqual(disabled, [], "account-bound proxy node must not be disabled")

    def test_lease_quarantine_pins_the_account(self):
        recorded = []

        class Api:
            def list_leases(self):
                return []

            def quarantine_lease(self, node_id, account_id, reason):
                recorded.append((node_id, account_id, reason))
                return {"nodeId": node_id, "accountId": account_id, "version": "v1", "cooldownUntil": 9999}

        guard = self._guard(Api())
        node = {"id": "5", "name": "lease-node", "enabled": True, "accountBoundProxy": True}
        guard._handle_account_degrade([node], node, {"accountId": "42"}, "missing_thinking", 1000.0)
        self.assertEqual(recorded, [("5", "42", "missing_thinking")])
        self.assertEqual(node["enabled"], True)

    def test_lease_conflict_drops_stale_state(self):
        class Api:
            def quality_test(self, node_id, profile_id="", account_id=""):
                return probe(thinkingRequired=False)

            def restore_lease(self, node_id, account_id, version):
                raise quality_guard.ApiError(409, "qualityLeaseConflict", "stale")

        guard = self._guard(Api())
        guard.state["leases"] = {"5:42": {"version": "old"}}
        guard.state["lease_recovery"] = {"5:42": {"failures": 1}}
        node = {"id": "5", "name": "n", "accountBoundProxy": True}
        guard._recover_lease(node, {"nodeId": "5", "accountId": "42", "version": "old"}, 1000.0)
        self.assertNotIn("5:42", guard.state["leases"])
        self.assertNotIn("5:42", guard.state["lease_recovery"])


    def test_admin_switch_skipped_when_lease_applied(self):
        """A lease-capable stack must not also need admin credentials."""
        lease_calls = []
        admin_calls = []

        class Api:
            def list_leases(self):
                return []

            def quarantine_lease(self, node_id, account_id, reason):
                lease_calls.append(account_id)
                return {"nodeId": node_id, "accountId": account_id, "version": "v1", "cooldownUntil": 1}

        guard = self._guard(Api())
        # Any admin-API switch would go through here; failing loudly proves the
        # lease path never reached for admin credentials.
        def _boom(*_a, **_k):
            admin_calls.append(1)
            raise AssertionError("admin API must not be used when a lease was applied")

        guard._force_account_switch = _boom
        node = {"id": "5", "name": "node-level", "enabled": True, "accountBoundProxy": False}
        guard._handle_account_degrade([node], node, {"accountId": "42"}, "missing_thinking", 1000.0)
        self.assertEqual(lease_calls, ["42"])
        self.assertEqual(admin_calls, [], "lease applied, so no admin switch")

    def test_admin_switch_used_when_lease_absent(self):
        switched = []

        class Api:
            def list_leases(self):
                raise quality_guard.ApiError(403, "forbidden", "not in allowlist")

        guard = self._guard(Api())
        guard._force_account_switch = lambda value, reason, now: switched.append(value.get("accountId"))
        node = {"id": "5", "name": "node-level", "enabled": True, "accountBoundProxy": False}
        guard._handle_account_degrade([node], node, {"accountId": "42"}, "missing_thinking", 1000.0)
        self.assertEqual(switched, ["42"], "no lease support -> fall back to admin switch")


if __name__ == "__main__":
    unittest.main(verbosity=2)

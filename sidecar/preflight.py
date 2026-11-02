#!/usr/bin/env python3
"""Preflight: verify a Quality Guard sidecar against a real grok2api endpoint.

Reads the same bootstrap file the guard uses, then probes each route the guard
depends on. Use this before switching a stack to a new guard image: the main
service scopes the internal token to a fixed route allowlist, so a guard built
against a different generation answers 403 on routes it assumes exist.

    # inside the guard container
    python3 /usr/local/bin/grok2api-egress-quality-guard --preflight

Exit codes: 0 all required routes ok, 1 a required route failed,
2 configuration/bootstrap problem.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

import quality_guard as guard  # same directory when invoked as a script


def _probe(api: guard.ApiClient, label: str, call, required: bool = True) -> bool:
    try:
        result = call()
    except guard.ApiError as exc:
        status = "missing" if exc.status in {401, 403, 404, 405, 501} else "error"
        marker = "FAIL" if required else "skip"
        print(f"  [{marker}] {label}: HTTP {exc.status} {exc.code} ({status})")
        return not required
    except Exception as exc:  # network/timeout
        print(f"  [FAIL] {label}: {type(exc).__name__}")
        return not required
    detail = ""
    if isinstance(result, list):
        detail = f"{len(result)} item(s)"
    elif isinstance(result, dict):
        detail = f"{len(result)} key(s)"
    print(f"  [ ok ] {label}{': ' + detail if detail else ''}")
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check a Quality Guard sidecar against its grok2api")
    parser.parse_args(argv)
    try:
        config = guard.Config.from_bootstrap()
    except guard.GuardDisabled as exc:
        print(f"guard disabled: {exc}")
        return 0
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    print(f"base url      : {config.base_url}")
    print(f"mode          : {config.mode}")
    print(f"model         : {config.model}")
    print(f"configured    : {'auto (empty nodeIDs)' if not config.node_ids else len(config.node_ids)}")
    print(f"rotatable     : {len(config.rotatable_node_ids)}")
    print(f"rotation url  : {'set' if config.rotation_url else 'not set'}")
    print("routes:")

    api = guard.ApiClient(config)
    ok = _probe(api, "egress-nodes", api.list_nodes)
    nodes = []
    try:
        nodes = api.list_nodes()
    except Exception:
        pass
    ok &= _probe(api, "egress-operations", api.fixed_fallback_node_ids)
    ok &= _probe(api, "request-audits", api.list_audits)
    # Lease routes are optional: an older main service answers 403 because the
    # internal token allowlist predates them. The guard degrades gracefully, so
    # this only reports what behaviour to expect.
    lease_ok = _probe(api, "egress-leases", api.list_leases, required=False)

    lease_nodes = [node for node in nodes if node.get("accountBoundProxy")]
    print("capabilities:")
    print(f"  lease API          : {'available' if lease_ok else 'absent -> account degrade falls back to admin API'}")
    print(f"  account-bound nodes: {len(lease_nodes)} of {len(nodes)}")
    if lease_nodes and not lease_ok:
        print("  WARNING: account-bound proxy nodes are present but the lease API")
        print("           is absent; those nodes can only be handled per-account")
        print("           through the admin API, never node-wide." if config.fail_closed else "")

    runtime = config.runtime_config_file
    if runtime.exists():
        try:
            guard.load_runtime_config(config, runtime)
            print("runtime-config: loads cleanly")
        except ValueError as exc:
            print(f"runtime-config: REJECTED ({exc}) -> admin thresholds will not apply")
            ok = False
    else:
        print("runtime-config: not present (bootstrap values in effect)")

    print("RESULT:", "ok" if ok else "problems found")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

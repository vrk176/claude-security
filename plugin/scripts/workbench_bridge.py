#!/usr/bin/env python3
"""JSON bridge from the Claude Security CLI to the workbench database.

`workbench_cli.py` only parses arguments; the command implementations live in
`workbench_db.py` and `workbench_scan_history.py` as functions taking
`(connection, argparse.Namespace)`. This module supplies the missing dispatch
so the TypeScript CLI can drive scan history over a stable JSON interface:

    workbench_bridge.py <command> '<json-args>'

Every command prints one JSON object on stdout. Failures print
`{"error": "..."}` and exit non-zero.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import workbench_db as db  # noqa: E402
import workbench_scan_history as history  # noqa: E402


def _namespace(payload: dict, **defaults) -> argparse.Namespace:
    """Build the Namespace the workbench functions expect, filling defaults."""
    merged = dict(defaults)
    merged.update({k: v for k, v in payload.items() if v is not None})
    return argparse.Namespace(**merged)


def cmd_register(conn, payload: dict) -> dict:
    args = _namespace(
        payload,
        scan_dir=None,
        repository=None,
        recipe_json=None,
        parent_scan_id=None,
        # Upstream's --archived-scan-dir supports reusing a previously archived
        # output directory. This port always registers into a fresh directory,
        # so the value is absent — but the workbench reads the attribute
        # unconditionally, and omitting it is an AttributeError at registration.
        archived_scan_dir=None,
    )
    result = db.register_cli_scan(conn, args)
    conn.commit()
    return result


def cmd_list(conn, payload: dict) -> dict:
    args = _namespace(
        payload,
        target_id=None,
        status=None,
        mode=None,
        repository=None,
        scan_root=None,
        offset=0,
        limit=25,
        query=None,
    )
    return history.list_scans(conn, args)


def cmd_get(conn, payload: dict) -> dict:
    """Look up one scan by full id or a unique id prefix."""
    scan_id = payload.get("scan_id")
    if not scan_id:
        raise SystemExit("scan_id is required")
    # list_scans owns the projection (progress, finding counts, target summary),
    # so resolve the prefix against its output rather than re-querying columns.
    listing = history.list_scans(
        conn,
        _namespace(
            {},
            target_id=None,
            status=None,
            mode=None,
            repository=None,
            scan_root=None,
            offset=0,
            limit=1000,
            query=None,
        ),
    )
    matches = [
        scan for scan in listing.get("scans", []) if str(scan.get("scanId", "")).startswith(scan_id)
    ]
    if not matches:
        raise SystemExit(f"No scan matching {scan_id}")
    if len(matches) > 1:
        raise SystemExit(f"{scan_id} matches {len(matches)} scans; use a longer prefix")
    return matches[0]


def cmd_contract(conn, payload: dict) -> dict:
    """Return the manifest contract the workbench will verify a draft against.

    `complete` re-derives this contract and rejects any draft that disagrees, so
    the agent has to be told it up front. Several fields are not guessable from
    the working tree: `allowedKinds` is `git_revision` for a clean checkout but
    `git_worktree` for a dirty one, and `targetId` is a workbench identity, not
    a path. Upstream exposes this through the scan detail payload
    (`scan_result` -> "contract"); this command is the same data on its own.
    """
    scan = db.require_scan(conn, payload.get("scan_id"))
    return db.scan_contract(scan)


def cmd_complete(conn, payload: dict) -> dict:
    """Seal a scan into the workbench so its findings become comparable.

    Registration only records that a scan started. Completion runs the contract
    finalizer and ingests the sealed findings into the database — without it,
    `compare` has nothing to compare.
    """
    payload = dict(payload)
    # cost arrives as an object; the workbench validates a JSON string.
    if isinstance(payload.get("cost"), dict):
        payload["cost_json"] = json.dumps(payload.pop("cost"))
    args = _namespace(payload, scan_id=None, claim_token=None, cost_json=None)
    result = db.complete_scan(conn, args)
    conn.commit()
    return result


def cmd_match(conn, payload: dict) -> dict:
    """Link findings that share a root cause across two sealed scans.

    Upstream this is a semantic step: `save_scan_comparison` validates and
    persists a precomputed match set but never derives one. It does not need to
    be a model call here — the contract's semantic fingerprint
    (`fingerprints.primary`) is derived from target id, rule id, anchor, and
    instance, so it is stable across scans of the same target. Equal
    fingerprints are therefore the same finding, which resolves the common case
    exactly and for free.

    `uncertain` stays empty by construction: it records *ambiguous pairings*,
    and fingerprint equality is unambiguous. A finding present on only one side
    is simply unmatched, which `compare` then classifies as new or resolved.
    """
    before_id = payload.get("before_scan_id")
    after_id = payload.get("after_scan_id")
    before = db.require_scan(conn, before_id)
    after = db.require_scan(conn, after_id)

    def fingerprints(scan_row) -> dict[str, str]:
        """Map fingerprint -> occurrence id for one sealed scan."""
        findings = json.loads(
            (Path(scan_row["scan_dir"]) / "findings.json").read_text(encoding="utf-8")
        )
        mapping: dict[str, str] = {}
        for finding in findings.get("findings", []):
            primary = (finding.get("fingerprints") or {}).get("primary")
            occurrence = finding.get("occurrenceId")
            if primary and occurrence:
                mapping[primary] = occurrence
        return mapping

    before_map = fingerprints(before)
    after_map = fingerprints(after)

    matches = [
        {
            "beforeOccurrenceIds": [before_map[fp]],
            "afterOccurrenceIds": [after_map[fp]],
            "reason": "identical semantic fingerprint",
        }
        for fp in before_map
        if fp in after_map
    ]
    uncertain: list[dict] = []

    args = _namespace(
        {
            "before_scan_id": before["id"],
            "after_scan_id": after["id"],
            "matches_json": json.dumps({"matches": matches, "uncertain": uncertain}),
        }
    )
    result = history.save_scan_comparison(
        conn,
        args,
        now=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        require_scan=db.require_scan,
        read_coverage=db.coverage_for_comparison,
    )
    conn.commit()
    return {"matched": len(matches), "uncertain": len(uncertain), **result}


def cmd_compare(conn, payload: dict) -> dict:
    """Diff two sealed scans: new / persisting / resolved / reopened / unknown."""
    args = _namespace(
        payload,
        before_scan_id=None,
        after_scan_id=None,
        include_matching_inputs=False,
        require_matches=False,
    )
    return history.compare_scans(
        conn,
        args,
        require_scan=db.require_scan,
        read_coverage=db.coverage_for_comparison,
        backfill_finding_details=db.backfill_legacy_finding_details,
        include_matching_inputs=bool(payload.get("include_matching_inputs")),
        require_matches=bool(payload.get("require_matches")),
    )


def cmd_unmatched(conn, payload: dict) -> dict:
    """List scan pairs of the same target that have no saved match yet."""
    args = _namespace(payload, repository=None, target_id=None, limit=25, offset=0)
    return history.list_unmatched_scan_pairs(
        conn,
        args,
        backfill_finding_details=db.backfill_legacy_finding_details,
        read_coverage=db.coverage_for_comparison,
    )


def cmd_recipe(conn, payload: dict) -> dict:
    """Return the launch recipe a scan was registered with, for a rerun."""
    args = _namespace(payload, scan_id=None)
    return db.get_scan_recipe(conn, args)


def cmd_triage(conn, payload: dict) -> dict:
    """Record a human verdict on one finding occurrence.

    `false_positive` and `wont_fix` both require a note: a dismissal without a
    stated reason cannot be re-evaluated later, and later scans reuse this
    reason to decide whether the dismissal still applies.
    """
    args = _namespace(
        payload,
        occurrence_id=None,
        status="closed",
        close_reason=None,
        note=None,
    )
    result = db.set_finding_triage(conn, args)
    conn.commit()
    return result


def cmd_feedback(conn, payload: dict) -> dict:
    """List prior triage verdicts that apply to a scan's findings."""
    import workbench_feedback as feedback

    scan = db.require_scan(conn, payload.get("scan_id"))
    return feedback.get_scan_feedback(conn, scan)


def cmd_findings(conn, payload: dict) -> dict:
    """List a scan's findings with their occurrence ids and triage state."""
    args = _namespace(
        payload,
        scan_id=None,
        occurrence_id=None,
        status=None,
        severity=None,
        offset=0,
        limit=100,
        query=None,
    )
    result = db.list_findings(conn, args)
    # list_findings nests its payload under findingsPage; flatten to a compact
    # projection so the CLI does not carry full finding bodies around.
    page = result.get("findingsPage", result)
    findings = [
        {
            "occurrenceId": f.get("occurrenceId"),
            "title": f.get("title"),
            "severity": (f.get("severity") or {}).get("level")
            if isinstance(f.get("severity"), dict)
            else f.get("severity"),
            "status": f.get("status") or (f.get("triage") or {}).get("status") or "open",
            "closeReason": (f.get("triage") or {}).get("closeReason"),
            "note": (f.get("triage") or {}).get("note"),
        }
        for f in page.get("findings", [])
    ]
    return {"findings": findings, "total": page.get("total", len(findings))}


COMMANDS = {
    "recipe": cmd_recipe,
    "triage": cmd_triage,
    "feedback": cmd_feedback,
    "findings": cmd_findings,
    "register": cmd_register,
    "list": cmd_list,
    "get": cmd_get,
    "contract": cmd_contract,
    "complete": cmd_complete,
    "match": cmd_match,
    "compare": cmd_compare,
    "unmatched": cmd_unmatched,
}


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print(
            json.dumps({"error": f"usage: {sys.argv[0]} <{'|'.join(COMMANDS)}> [json]"}),
            file=sys.stdout,
        )
        return 2
    command = sys.argv[1]
    payload = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    try:
        conn = db.connect()
        result = COMMANDS[command](conn, payload)
    except SystemExit as exc:
        print(json.dumps({"error": str(exc.code if exc.code else exc)}))
        return 1
    except Exception as exc:  # noqa: BLE001 - surface the message, not a traceback
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1
    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

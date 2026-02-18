from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.services.log_parsing import ParsedEvent

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "ERROR": 3,
    "WARNING": 2,
    "INFO": 1,
    "DEBUG": 0,
    "TRACE": -1,
    None: -2,
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_message_for_signature(message: str) -> str:
    """Normalize a message for stable signature hashing by removing high-cardinality tokens."""
    s = message
    s = re.sub(r"\b[0-9a-f]{8,}\b", "<HEX>", s, flags=re.IGNORECASE)  # ids, hashes
    s = re.sub(r"\b\d{4,}\b", "<NUM>", s)  # large ints like ids
    s = re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "<IP>", s)  # IPs
    s = re.sub(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "<UUID>",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(r"\s+", " ", s).strip()
    return s[:4000]


def _signature_key(event: ParsedEvent) -> str:
    """Compute a stable signature key for a parsed event."""
    base = "|".join(
        [
            (event.severity or "").upper(),
            event.component or "",
            event.service or "",
            _normalize_message_for_signature(event.message),
        ]
    )
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


@dataclass
class FindingOut:
    """Finding structure persisted to DB and returned via API."""

    severity: str
    title: str
    description: str
    root_cause: str | None
    evidence: dict[str, Any]
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    occurrences: int


# PUBLIC_INTERFACE
def analyze_events(events: list[ParsedEvent], *, incident_name: str | None = None) -> dict[str, Any]:
    """
    Perform evidence-driven analysis aligned to the production-log-analysis skill.

    This implementation is intentionally conservative: it extracts evidence from logs,
    detects recurring issues/patterns/anomalies, and produces root-cause hypotheses with
    explicit uncertainty and suggested validation steps.

    Returns:
      dict containing:
        - report: structured report JSON with the 10 required sections (plus structured subfields)
        - summary: small JSON summary for analysis_runs.summary
        - findings: list of findings to persist
    """
    if not events:
        report = _build_empty_report(incident_name=incident_name)
        return {"report": report, "summary": {"events": 0}, "findings": []}

    # --- Window ---
    known_ts = [e.event_ts for e in events if e.event_ts is not None]
    window_start = min(known_ts) if known_ts else None
    window_end = max(known_ts) if known_ts else None

    # --- Severity counts & slices ---
    sev_counts = Counter((e.severity or "UNKNOWN").upper() for e in events)
    top_sev = sorted(sev_counts.items(), key=lambda kv: (-kv[1], kv[0]))

    critical_events = [e for e in events if (e.severity or "").upper() == "CRITICAL"]
    error_events = [e for e in events if (e.severity or "").upper() == "ERROR"]
    warning_events = [e for e in events if (e.severity or "").upper() == "WARNING"]

    # --- Signatures ---
    sig_events: dict[str, list[ParsedEvent]] = defaultdict(list)
    for e in events:
        sig_events[_signature_key(e)].append(e)

    # Sort signatures by highest severity then count
    sig_rank = sorted(
        sig_events.items(),
        key=lambda kv: (
            -max(SEVERITY_ORDER.get((ev.severity or "").upper(), -2) for ev in kv[1]),
            -len(kv[1]),
        ),
    )
    top_sigs = sig_rank[:10]

    # Additional ranked signatures by count for anomalies/patterns
    sig_rank_by_count = sorted(sig_events.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    most_frequent_sigs = sig_rank_by_count[:10]

    # --- Timeline construction (evidence-first) ---
    timeline_entries: list[dict[str, Any]] = []
    first_high = next((e for e in events if (e.severity or "").upper() in ("ERROR", "CRITICAL")), None)
    if first_high:
        timeline_entries.append(
            _timeline_entry(
                ts=first_high.event_ts,
                label="First high-severity symptom observed (ERROR/CRITICAL)",
                event=first_high,
            )
        )

    for sig_key, evs in top_sigs[:3]:
        evs_sorted = sorted(evs, key=lambda x: x.event_ts or _utc_now())
        representative = evs_sorted[0]
        title = _make_signature_title(representative)
        first_seen = min((e.event_ts for e in evs if e.event_ts), default=None)
        timeline_entries.append(
            _timeline_entry(
                ts=first_seen,
                label=f"Signature first seen: {title} (count={len(evs)})",
                event=representative,
            )
        )

    # --- Pattern / anomaly detection heuristics ---
    patterns = _detect_patterns_and_anomalies(
        events=events,
        sig_events=sig_events,
        window_start=window_start,
        window_end=window_end,
    )

    # --- Findings (persisted) and per-signature RCA hypotheses ---
    findings: list[FindingOut] = []
    signature_analysis = _signature_analysis_section(top_sigs)

    # Hypotheses are generated for top ERROR/CRITICAL signatures with explicit uncertainty.
    # These will be embedded in report sections so frontend can render them deterministically.
    hypotheses = _build_root_cause_hypotheses(
        top_sigs=top_sigs,
        patterns=patterns,
        window_start=window_start,
        window_end=window_end,
    )

    # Build findings from top signatures (primarily as dashboard-friendly objects).
    for sig_key, evs in top_sigs[:5]:
        evs_sorted = sorted(evs, key=lambda x: x.event_ts or _utc_now())
        rep = evs_sorted[0]
        sev = (rep.severity or "UNKNOWN").upper()
        title = _make_signature_title(rep)

        first_seen = min((e.event_ts for e in evs if e.event_ts), default=None)
        last_seen = max((e.event_ts for e in evs if e.event_ts), default=None)

        evidence = {
            "signature_key": sig_key,
            "representative_excerpt": _evidence_excerpt(rep),
            "examples": [_evidence_excerpt(e) for e in evs_sorted[:3]],
            "contexts": _top_contexts(evs),
        }

        description = (
            "Recurring issue signature grouped by stable fields (severity/component/service + normalized message). "
            "Excerpts show representative instances and context distribution."
        )

        # Attach hypothesis summary (if any) for this signature.
        hypothesis = next((h for h in hypotheses if h.get("signature_key") == sig_key), None)
        root_cause = None
        if hypothesis:
            root_cause = hypothesis.get("hypothesis_summary")

        findings.append(
            FindingOut(
                severity=sev if sev != "UNKNOWN" else "WARNING",
                title=title,
                description=description,
                root_cause=root_cause,
                evidence=evidence,
                first_seen_at=first_seen,
                last_seen_at=last_seen,
                occurrences=len(evs),
            )
        )

    # --- Executive summary ---
    incident_label = incident_name or "Log analysis run"
    impact = _impact_phrase(sev_counts)
    status = "unknown (logs only)"  # Do not infer recovery unless directly evidenced
    exec_summary = (
        f"{incident_label} analyzed {len(events)} log events"
        + (
            f" spanning {window_start.isoformat()} to {window_end.isoformat()} (UTC)."
            if window_start and window_end
            else "."
        )
        + f" Observed severity distribution includes: {', '.join([f'{k}={v}' for k, v in top_sev[:5]])}. "
        + f"{impact} Current status is {status}."
    )

    # --- Scope ---
    scope_sources = (
        "The analysis used only the provided log file content. "
        "All conclusions are evidence-based and limited by what appears in the logs; "
        "missing deploy/traffic/metrics context is explicitly treated as uncertainty."
    )

    # --- Key observations: include explicit counts + top recurring signatures + notable patterns ---
    key_obs = _key_observations(
        top_sigs=top_sigs,
        sev_counts=sev_counts,
        anomalies=patterns.get("anomalies_text", []),
        patterns_text=patterns.get("patterns_text", []),
    )

    # --- Root cause analysis section (structured narrative + hypotheses list) ---
    rca_section = _root_cause_section_text(hypotheses=hypotheses)

    troubleshooting = _troubleshooting_recommendations(top_sigs=top_sigs, hypotheses=hypotheses)
    remediation = _remediation_plan(top_sigs=top_sigs)
    observability = _observability_improvements(events=events)
    missing = _missing_data_section(events=events)

    # Dedicated issue breakdown section: explicit errors/warnings/critical issues for rendering.
    issue_breakdown = _build_issue_breakdown(
        critical_events=critical_events,
        error_events=error_events,
        warning_events=warning_events,
        sig_events=sig_events,
        most_frequent_sigs=most_frequent_sigs,
    )

    report = {
        "schema_name": "production-log-analysis",
        "report_version": "1.1",
        "generated_at": _utc_now().isoformat(),
        "sections": {
            "1_executive_summary": exec_summary,
            "2_scope_environment_data_sources": (
                "Time window: "
                f"{window_start.isoformat() if window_start else 'unknown'} to "
                f"{window_end.isoformat() if window_end else 'unknown'} (UTC). "
                + scope_sources
            ),
            "3_key_observations_from_logs": key_obs,
            "4_incident_timeline": {
                "window_start": window_start.isoformat() if window_start else None,
                "window_end": window_end.isoformat() if window_end else None,
                "entries": timeline_entries,
            },
            "5_error_warning_signature_analysis": {
                "issue_breakdown": issue_breakdown,
                "signature_analysis": signature_analysis,
                "patterns_and_anomalies": patterns,
            },
            "6_root_cause_analysis": {
                "narrative": rca_section,
                "hypotheses": hypotheses,
                "uncertainty_notes": (
                    "Hypotheses are ranked using only log evidence and simple heuristics; "
                    "confidence is qualitative and should be validated with deploy history, metrics, and traces."
                ),
            },
            "7_troubleshooting_steps_performed_or_recommended": troubleshooting,
            "8_remediation_plan": remediation,
            "9_logging_and_observability_improvements": observability,
            "10_open_questions_and_missing_data": missing,
        },
        "meta": {
            "event_count": len(events),
            "severity_counts": dict(sev_counts),
            "top_signatures": [
                {"signature_key": k, "count": len(v), "severity": (v[0].severity or "UNKNOWN").upper()}
                for k, v in top_sigs[:10]
            ],
            "issue_counts": {
                "critical": len(critical_events),
                "errors": len(error_events),
                "warnings": len(warning_events),
            },
        },
    }

    summary = {
        "events": len(events),
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
        "severity_counts": dict(sev_counts),
        "issue_counts": {
            "critical": len(critical_events),
            "errors": len(error_events),
            "warnings": len(warning_events),
        },
        "top_signature_count": len(top_sigs),
        "anomaly_count": len(patterns.get("anomalies_text", [])),
    }

    return {"report": report, "summary": summary, "findings": [f.__dict__ for f in findings]}


def _build_empty_report(*, incident_name: str | None) -> dict[str, Any]:
    label = incident_name or "Log analysis run"
    return {
        "schema_name": "production-log-analysis",
        "report_version": "1.1",
        "generated_at": _utc_now().isoformat(),
        "sections": {
            "1_executive_summary": f"{label} contained no parsable events.",
            "2_scope_environment_data_sources": "No data sources were provided or the log was empty.",
            "3_key_observations_from_logs": "No observations available due to empty input.",
            "4_incident_timeline": {"entries": []},
            "5_error_warning_signature_analysis": {
                "issue_breakdown": {"critical": [], "errors": [], "warnings": [], "top_recurring_signatures": []},
                "signature_analysis": [],
                "patterns_and_anomalies": {"patterns_text": [], "anomalies_text": [], "detectors": {}},
            },
            "6_root_cause_analysis": {
                "narrative": "Root cause cannot be assessed without log evidence.",
                "hypotheses": [],
                "uncertainty_notes": "No logs provided.",
            },
            "7_troubleshooting_steps_performed_or_recommended": "Provide logs or expand collection window.",
            "8_remediation_plan": "N/A",
            "9_logging_and_observability_improvements": "Ensure log collection includes timestamps and severity.",
            "10_open_questions_and_missing_data": "What system, time window, and incident are being investigated?",
        },
        "meta": {"event_count": 0},
    }


def _make_signature_title(e: ParsedEvent) -> str:
    sev = (e.severity or "UNKNOWN").upper()
    comp = e.component or e.service or "unknown-component"
    msg = _normalize_message_for_signature(e.message)
    msg_short = msg if len(msg) <= 120 else msg[:117] + "..."
    return f"{sev} in {comp}: {msg_short}"


def _evidence_excerpt(e: ParsedEvent) -> dict[str, Any]:
    return {
        "timestamp": e.event_ts.isoformat() if e.event_ts else None,
        "severity": (e.severity or "UNKNOWN").upper(),
        "component": e.component,
        "service": e.service,
        "host": e.host,
        "request_id": e.request_id,
        "message": e.message[:2000],
        "raw_line": e.raw_line[:2000],
    }


def _timeline_entry(*, ts: datetime | None, label: str, event: ParsedEvent) -> dict[str, Any]:
    return {"timestamp": ts.isoformat() if ts else None, "label": label, "evidence": _evidence_excerpt(event)}


def _top_contexts(evs: list[ParsedEvent]) -> dict[str, Any]:
    comps = Counter(e.component or "unknown" for e in evs).most_common(3)
    svcs = Counter(e.service or "unknown" for e in evs).most_common(3)
    hosts = Counter(e.host or "unknown" for e in evs).most_common(3)
    return {"components": comps, "services": svcs, "hosts": hosts}


def _impact_phrase(sev_counts: Counter) -> str:
    if sev_counts.get("CRITICAL", 0) > 0:
        return "Critical events suggest potential availability or data integrity impact."
    if sev_counts.get("ERROR", 0) > 0:
        return "Errors indicate failed operations and potential user-facing impact, depending on context."
    if sev_counts.get("WARNING", 0) > 0:
        return "Warnings may indicate precursors or degraded behavior, but impact is uncertain from logs alone."
    return "No errors/warnings observed; impact appears minimal based on log evidence."


def _key_observations(
    *,
    top_sigs: list[tuple[str, list[ParsedEvent]]],
    sev_counts: Counter,
    anomalies: list[str],
    patterns_text: list[str],
) -> str:
    lines: list[str] = []
    lines.append(
        "Severity distribution (from parsed events): "
        f"CRITICAL={sev_counts.get('CRITICAL', 0)}, ERROR={sev_counts.get('ERROR', 0)}, "
        f"WARNING={sev_counts.get('WARNING', 0)}, INFO={sev_counts.get('INFO', 0)}."
    )

    if top_sigs:
        lines.append("Top recurring signatures (grouped by stable signature key) include:")
        for k, evs in top_sigs[:5]:
            rep = evs[0]
            lines.append(
                f"- {(rep.severity or 'UNKNOWN').upper()} "
                f"component={rep.component or 'unknown'} service={rep.service or 'unknown'} "
                f"count={len(evs)} signature_key={k[:10]}…"
            )

    if patterns_text:
        lines.append("Detected patterns:")
        lines.extend([f"- {p}" for p in patterns_text])

    if anomalies:
        lines.append("Potential anomalies:")
        lines.extend([f"- {a}" for a in anomalies])

    return "\n".join(lines)


def _signature_analysis_section(top_sigs: list[tuple[str, list[ParsedEvent]]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for sig_key, evs in top_sigs[:10]:
        rep = evs[0]
        sev = (rep.severity or "UNKNOWN").upper()
        first_seen = min((e.event_ts for e in evs if e.event_ts), default=None)
        last_seen = max((e.event_ts for e in evs if e.event_ts), default=None)
        out.append(
            {
                "signature_key": sig_key,
                "signature_name": _make_signature_title(rep),
                "severity": sev,
                "frequency": len(evs),
                "first_seen_at": first_seen.isoformat() if first_seen else None,
                "last_seen_at": last_seen.isoformat() if last_seen else None,
                "representative_excerpt": _evidence_excerpt(rep),
                "correlated_context": _top_contexts(evs),
                "why_it_matters": (
                    "Higher-severity and higher-frequency signatures are prioritized because they are more likely "
                    "to reflect user impact or systemic degradation. Grouping avoids overcounting high-cardinality IDs "
                    "and focuses on stable failure modes."
                ),
            }
        )
    return out


def _build_issue_breakdown(
    *,
    critical_events: list[ParsedEvent],
    error_events: list[ParsedEvent],
    warning_events: list[ParsedEvent],
    sig_events: dict[str, list[ParsedEvent]],
    most_frequent_sigs: list[tuple[str, list[ParsedEvent]]],
) -> dict[str, Any]:
    """Create a frontend-friendly breakdown of critical/errors/warnings with evidence excerpts."""
    def _top_examples(evs: list[ParsedEvent], limit: int = 5) -> list[dict[str, Any]]:
        evs_sorted = sorted(evs, key=lambda e: e.event_ts or _utc_now())
        return [_evidence_excerpt(e) for e in evs_sorted[:limit]]

    def _summarize_category(evs: list[ParsedEvent], limit: int = 10) -> list[dict[str, Any]]:
        # Group by signature for the category
        cat_sigs: dict[str, list[ParsedEvent]] = defaultdict(list)
        for e in evs:
            cat_sigs[_signature_key(e)].append(e)

        ranked = sorted(cat_sigs.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]
        out: list[dict[str, Any]] = []
        for sig_key, group in ranked:
            rep = sorted(group, key=lambda e: e.event_ts or _utc_now())[0]
            out.append(
                {
                    "signature_key": sig_key,
                    "signature_name": _make_signature_title(rep),
                    "frequency": len(group),
                    "first_seen_at": min((e.event_ts for e in group if e.event_ts), default=None).isoformat()
                    if any(e.event_ts for e in group)
                    else None,
                    "last_seen_at": max((e.event_ts for e in group if e.event_ts), default=None).isoformat()
                    if any(e.event_ts for e in group)
                    else None,
                    "examples": _top_examples(group, limit=3),
                }
            )
        return out

    top_recurring = []
    for sig_key, group in most_frequent_sigs[:10]:
        rep = sorted(group, key=lambda e: e.event_ts or _utc_now())[0]
        top_recurring.append(
            {
                "signature_key": sig_key,
                "signature_name": _make_signature_title(rep),
                "severity": (rep.severity or "UNKNOWN").upper(),
                "frequency": len(group),
                "examples": _top_examples(group, limit=2),
            }
        )

    return {
        "critical": _summarize_category(critical_events),
        "errors": _summarize_category(error_events),
        "warnings": _summarize_category(warning_events),
        "top_recurring_signatures": top_recurring,
    }


def _detect_patterns_and_anomalies(
    *,
    events: list[ParsedEvent],
    sig_events: dict[str, list[ParsedEvent]],
    window_start: datetime | None,
    window_end: datetime | None,
) -> dict[str, Any]:
    """
    Detect coarse patterns and anomalies.

    This is heuristic: we avoid claims that require external data (metrics/traces).
    Output is structured so the frontend can render it, and it can be used by RCA hypothesis ranking.
    """
    patterns_text: list[str] = []
    anomalies_text: list[str] = []
    detectors: dict[str, Any] = {}

    # 1) Cascading failure hint: warnings preceding errors near in time (only if timestamps exist).
    if window_start and window_end:
        # Take a small sample of first N errors and check for warnings in the preceding 60s.
        errors_sorted = sorted(
            (e for e in events if (e.severity or "").upper() in ("ERROR", "CRITICAL") and e.event_ts),
            key=lambda e: e.event_ts,  # type: ignore[arg-type]
        )
        warnings_sorted = sorted(
            (e for e in events if (e.severity or "").upper() == "WARNING" and e.event_ts),
            key=lambda e: e.event_ts,  # type: ignore[arg-type]
        )
        warn_deque = deque(warnings_sorted)
        precede_hits = 0
        checked = 0
        for err in errors_sorted[:20]:
            if not err.event_ts:
                continue
            checked += 1
            # Move left bound (keep warnings within last 60 seconds)
            # Since we only move forward, this is cheap.
            while warn_deque and warn_deque[0].event_ts and warn_deque[0].event_ts < err.event_ts:
                break
            # Count warnings in [err_ts - 60s, err_ts)
            err_ts = err.event_ts
            window_lo = err_ts.timestamp() - 60
            window_hi = err_ts.timestamp()
            # Scan last few warnings by peeking into original list (bounded).
            # We'll just count from warnings_sorted for simplicity.
            local_hits = sum(
                1
                for w in warnings_sorted
                if w.event_ts and window_lo <= w.event_ts.timestamp() < window_hi
            )
            if local_hits >= 3:
                precede_hits += 1

        if checked > 0:
            ratio = precede_hits / checked
            detectors["warnings_precede_errors_60s"] = {"checked_errors": checked, "hits": precede_hits, "ratio": ratio}
            if ratio >= 0.3:
                patterns_text.append(
                    "In multiple instances, clusters of WARNING events occurred within ~60s before ERROR/CRITICAL events, "
                    "which may indicate degradations/precursors preceding failures."
                )

    # 2) Burst detection: count events per minute when timestamps exist.
    if window_start and window_end:
        # Bucket by minute for ERROR/CRITICAL.
        buckets: Counter[str] = Counter()
        for e in events:
            if not e.event_ts:
                continue
            if (e.severity or "").upper() not in ("ERROR", "CRITICAL"):
                continue
            key = e.event_ts.replace(second=0, microsecond=0).isoformat()
            buckets[key] += 1
        if buckets:
            peak_minute, peak_count = buckets.most_common(1)[0]
            mean = sum(buckets.values()) / max(len(buckets), 1)
            detectors["error_burst_per_minute"] = {"peak_minute": peak_minute, "peak_count": peak_count, "mean": mean}
            # Simple anomaly: peak is much larger than mean
            if mean > 0 and peak_count >= max(10, 5 * mean):
                anomalies_text.append(
                    f"Possible error burst: {peak_count} ERROR/CRITICAL events in minute starting {peak_minute} "
                    f"(mean≈{mean:.1f}/min). This can indicate an outage window, traffic spike, or a deploy-triggered regression."
                )

    # 3) Highly repetitive signature anomaly: one signature dominates errors.
    error_sig_counts: list[tuple[str, int]] = []
    total_err = 0
    for sig_key, evs in sig_events.items():
        sev_max = max(SEVERITY_ORDER.get((e.severity or "").upper(), -2) for e in evs)
        if sev_max >= SEVERITY_ORDER["ERROR"]:
            count = len(evs)
            error_sig_counts.append((sig_key, count))
            total_err += count

    error_sig_counts.sort(key=lambda kv: -kv[1])
    if total_err > 0 and error_sig_counts:
        top_key, top_count = error_sig_counts[0]
        frac = top_count / total_err
        detectors["dominant_error_signature"] = {"signature_key": top_key, "count": top_count, "fraction": frac}
        if frac >= 0.6 and top_count >= 10:
            anomalies_text.append(
                f"A single error signature accounts for ~{frac:.0%} of ERROR/CRITICAL events. "
                "This often suggests a single broken endpoint, misconfiguration, or failing dependency affecting many requests."
            )

    # 4) Timestamp quality
    if not any(e.event_ts for e in events):
        anomalies_text.append("Timestamps are missing/ambiguous; time-based patterns (bursts/precursors) cannot be assessed.")

    return {"patterns_text": patterns_text, "anomalies_text": anomalies_text, "detectors": detectors}


def _build_root_cause_hypotheses(
    *,
    top_sigs: list[tuple[str, list[ParsedEvent]]],
    patterns: dict[str, Any],
    window_start: datetime | None,
    window_end: datetime | None,
) -> list[dict[str, Any]]:
    """
    Build evidence-based RCA hypotheses for top signatures.

    Output format is structured, with:
      - hypothesis_summary
      - confidence (low/medium/high)
      - uncertainty
      - supporting_evidence (excerpts + why it supports)
      - validation_steps
    """
    hypotheses: list[dict[str, Any]] = []

    anomaly_notes = patterns.get("anomalies_text", [])
    pattern_notes = patterns.get("patterns_text", [])

    for sig_key, evs in top_sigs[:10]:
        rep = sorted(evs, key=lambda e: e.event_ts or _utc_now())[0]
        sev = (rep.severity or "UNKNOWN").upper()
        if sev not in ("ERROR", "CRITICAL", "WARNING"):
            continue

        normalized_msg = _normalize_message_for_signature(rep.message)
        msg_lower = normalized_msg.lower()

        # Simple keyword-based cues. These are *not* assertions; they help propose hypotheses.
        cues: list[str] = []
        if any(k in msg_lower for k in ["timeout", "timed out", "deadline exceeded"]):
            cues.append("timeout")
        if any(k in msg_lower for k in ["connection refused", "connect", "econnrefused", "broken pipe", "reset by peer"]):
            cues.append("network")
        if any(k in msg_lower for k in ["permission denied", "unauthorized", "forbidden", "auth"]):
            cues.append("authz/authn")
        if any(k in msg_lower for k in ["out of memory", "oom", "memoryerror"]):
            cues.append("oom")
        if any(k in msg_lower for k in ["nullpointer", "nil pointer", "attributeerror", "undefined is not a function"]):
            cues.append("null/bug")
        if any(k in msg_lower for k in ["sql", "deadlock", "lock wait", "too many connections", "connection pool"]):
            cues.append("database")
        if any(k in msg_lower for k in ["config", "configuration", "invalid", "missing env", "no such file"]):
            cues.append("configuration")

        # Determine confidence qualitatively (mostly based on strength of cues and supporting patterns).
        cue_strength = len(set(cues))
        base_conf = "low"
        if cue_strength >= 2:
            base_conf = "medium"
        if cue_strength >= 3:
            base_conf = "high"

        # Downgrade if severity is only WARNING (often precursor/noise)
        if sev == "WARNING" and base_conf != "low":
            base_conf = "low"

        # Use time patterns to nudge confidence a bit (still conservative).
        if window_start and window_end and patterns.get("detectors", {}).get("warnings_precede_errors_60s", {}).get("ratio", 0) >= 0.3:
            if base_conf == "low" and sev in ("ERROR", "CRITICAL"):
                base_conf = "medium"

        # Compose hypothesis summary.
        if "database" in cues:
            summary = "Hypothesis: database connectivity, pool saturation, or query/lock contention is contributing to failures."
        elif "timeout" in cues:
            summary = "Hypothesis: dependency latency/timeouts are causing request failures or retries, potentially cascading."
        elif "network" in cues:
            summary = "Hypothesis: network connectivity resets/refusals between services (or to an upstream dependency) are causing failures."
        elif "authz/authn" in cues:
            summary = "Hypothesis: authentication/authorization or token propagation issues are causing request rejection/failures."
        elif "configuration" in cues:
            summary = "Hypothesis: misconfiguration (missing/invalid config/env/paths) is causing runtime errors."
        elif "oom" in cues:
            summary = "Hypothesis: memory pressure or leaks are causing instability (OOM/restarts) leading to observed errors."
        elif "null/bug" in cues:
            summary = "Hypothesis: an application bug (null handling / unexpected input) is triggering exceptions."
        else:
            summary = (
                "Hypothesis: application error path or dependency interaction is failing; "
                "insufficient signal to pinpoint without additional context."
            )
            base_conf = "low"

        # Uncertainty statement: always present.
        uncertainty_bits: list[str] = [
            "Logs alone do not prove causality; hypotheses reflect best-effort inference from message patterns and timing.",
            "Confirm via correlation IDs/traces, deployment history, and dependency telemetry where available.",
        ]
        if "Timestamps are missing/ambiguous" in " ".join(anomaly_notes):
            uncertainty_bits.append("Timestamps are missing/ambiguous, limiting temporal correlation and burst detection.")

        # Evidence: excerpts + contextual metrics.
        evs_sorted = sorted(evs, key=lambda e: e.event_ts or _utc_now())
        contexts = _top_contexts(evs)
        first_seen = min((e.event_ts for e in evs if e.event_ts), default=None)
        last_seen = max((e.event_ts for e in evs if e.event_ts), default=None)

        supporting_evidence = [
            {
                "why": "Representative event excerpt for this recurring signature.",
                "excerpt": _evidence_excerpt(evs_sorted[0]),
            },
        ]
        if len(evs_sorted) > 1:
            supporting_evidence.append(
                {
                    "why": "Additional example excerpt (shows recurrence across time/contexts).",
                    "excerpt": _evidence_excerpt(evs_sorted[min(1, len(evs_sorted) - 1)]),
                }
            )

        # Validation steps aligned to cues (what to check next).
        validation_steps: list[str] = [
            "Collect 20–50 surrounding log lines before/after the first occurrence to capture precursors and causal chain.",
            "Correlate first_seen timestamp with deploy/config change records (if available).",
        ]
        if "database" in cues:
            validation_steps.extend(
                [
                    "Check DB metrics/logs for connection pool exhaustion, slow queries, deadlocks, or error spikes in the same window.",
                    "Verify application DB connection settings (pool size, timeouts) and recent schema/migration changes.",
                ]
            )
        if "timeout" in cues:
            validation_steps.extend(
                [
                    "Inspect upstream/downstream latency metrics and timeout configurations for implicated dependencies.",
                    "Look for retries/circuit-breaker logs or queue backlogs indicating saturation.",
                ]
            )
        if "network" in cues:
            validation_steps.extend(
                [
                    "Check service discovery/DNS/load balancer logs for resets/refusals and health check flaps.",
                    "Validate network policy/firewall changes during the window.",
                ]
            )
        if "authz/authn" in cues:
            validation_steps.extend(
                [
                    "Verify identity provider/token issuer availability and clock skew issues.",
                    "Check for changes in auth middleware configuration or rotated keys/certs.",
                ]
            )
        if "configuration" in cues:
            validation_steps.extend(
                [
                    "Diff runtime configuration/env vars against known-good versions; check secrets mounts and file paths.",
                    "Confirm the failing component started with expected config (versioned config, feature flags).",
                ]
            )
        if "oom" in cues:
            validation_steps.extend(
                [
                    "Check container/node memory usage and OOM kill events (kubelet/system logs) for the same time range.",
                    "Inspect recent changes that could increase memory footprint; enable heap profiling if feasible.",
                ]
            )

        # Add pattern/anomaly notes to hypothesis, so frontend can show global context.
        global_context = []
        global_context.extend(pattern_notes[:3])
        global_context.extend(anomaly_notes[:3])

        hypotheses.append(
            {
                "signature_key": sig_key,
                "signature_name": _make_signature_title(rep),
                "severity": sev,
                "frequency": len(evs),
                "first_seen_at": first_seen.isoformat() if first_seen else None,
                "last_seen_at": last_seen.isoformat() if last_seen else None,
                "contexts": contexts,
                "hypothesis_summary": summary,
                "confidence": base_conf,
                "uncertainty": " ".join(uncertainty_bits),
                "supporting_evidence": supporting_evidence,
                "validation_steps": validation_steps,
                "global_patterns_considered": global_context,
            }
        )

    # Sort hypotheses by severity then frequency (best-effort ranking)
    def _hyp_rank(h: dict[str, Any]) -> tuple[int, int]:
        s = SEVERITY_ORDER.get(str(h.get("severity") or "").upper(), -2)
        return (s, int(h.get("frequency") or 0))

    hypotheses.sort(key=_hyp_rank, reverse=True)
    return hypotheses[:10]


def _root_cause_section_text(*, hypotheses: list[dict[str, Any]]) -> str:
    if not hypotheses:
        return (
            "No ERROR/CRITICAL signatures were identified, or insufficient evidence exists to propose "
            "root-cause hypotheses. If this is unexpected, expand the log window and ensure ERROR level logging is enabled."
        )

    # Provide a readable narrative that is still evidence-based and explicitly uncertain.
    lines: list[str] = []
    lines.append(
        "Root cause analysis is presented as ranked hypotheses derived from recurring signatures and supporting log excerpts. "
        "Confidence is qualitative and intentionally conservative."
    )
    lines.append("Top hypotheses:")
    for h in hypotheses[:5]:
        lines.append(
            f"- [{h.get('confidence','low')}] {h.get('hypothesis_summary')} "
            f"(severity={h.get('severity')}, count={h.get('frequency')}, signature_key={str(h.get('signature_key'))[:10]}…)."
        )
    lines.append("Each hypothesis includes validation steps to reduce uncertainty.")
    return "\n".join(lines)


def _troubleshooting_recommendations(
    *,
    top_sigs: list[tuple[str, list[ParsedEvent]]],
    hypotheses: list[dict[str, Any]],
) -> str:
    steps: list[str] = []
    steps.append(
        "No explicit mitigation actions (restart/rollback/config change) are assumed unless directly visible in logs. "
        "Recommended steps below are prioritized to reduce uncertainty and confirm/rule out top hypotheses."
    )
    if not top_sigs:
        steps.append("- Collect a broader time window and include ERROR/WARNING level logs.")
        return "\n".join(steps)

    steps.extend(
        [
            "- Identify whether the top ERROR/CRITICAL signatures correspond to user-facing requests (check request_id/trace_id fields).",
            "- For top signatures, retrieve 20–50 surrounding lines before/after first occurrence to capture precursor warnings and causal chain.",
            "- Correlate timestamps with deploy/config changes (CI/CD records) to test for deployment regressions as triggers.",
            "- If dependency errors are suspected, cross-check dependency logs (DB, cache, upstream services) for the same window.",
        ]
    )

    if hypotheses:
        steps.append("")
        steps.append("Hypothesis-driven validation (from RCA section):")
        for h in hypotheses[:3]:
            steps.append(f"- For signature {str(h.get('signature_key'))[:10]}…: {h.get('hypothesis_summary')}")
            for vs in (h.get("validation_steps") or [])[:3]:
                steps.append(f"  - {vs}")

    return "\n".join(steps)


def _remediation_plan(*, top_sigs: list[tuple[str, list[ParsedEvent]]]) -> str:
    today: list[str] = [
        "Today (mitigate impact):",
        "- If errors are ongoing, consider rate limiting or shedding load on failing endpoints to protect core availability.",
        "- If dependency timeouts are visible, temporarily increase timeouts or enable fallbacks/circuit breakers where safe.",
    ]
    follow_up: list[str] = [
        "Engineering follow-up (durable fixes):",
        "- Fix the underlying error path indicated by the highest-impact signature(s) and add regression tests.",
        "- Add structured fields (service/component/request_id/version) so signatures and RCA become more reliable.",
        "- Improve alerting/SLOs for the signature(s) with highest severity and blast radius.",
    ]
    return "\n".join(today + [""] + follow_up)


def _observability_improvements(*, events: list[ParsedEvent]) -> str:
    has_request_ids = any(e.request_id for e in events)
    has_components = any(e.component or e.service for e in events)
    has_ts = any(e.event_ts for e in events)

    recs: list[str] = []
    recs.append("Recommended improvements based on observed log quality:")
    if not has_ts:
        recs.append("- Ensure ISO-8601 timestamps with timezone (UTC preferred) are included on every line/event.")
    if not has_components:
        recs.append("- Include service/component/logger name fields consistently for reliable grouping.")
    if not has_request_ids:
        recs.append("- Add correlation IDs (request_id/trace_id) propagated across services to connect multi-step failures.")
    recs.extend(
        [
            "- Use consistent severity levels (DEBUG/INFO/WARNING/ERROR/CRITICAL) and avoid overusing WARNING for expected states.",
            "- Include stack traces for exceptions and structured error codes where possible.",
            "- Avoid logging secrets/PII; add redaction at log sink if needed.",
        ]
    )
    return "\n".join(recs)


def _missing_data_section(*, events: list[ParsedEvent]) -> str:
    missing: list[str] = []
    missing.append(
        "This analysis is constrained to the provided logs. The following data would reduce uncertainty for RCA and impact quantification:"
    )
    missing.extend(
        [
            "- Deployment history (version/build identifiers, rollout timestamps) for the investigated window.",
            "- Request/response metrics (5xx rate, latency percentiles) to quantify user impact and confirm recovery.",
            "- Dependency health (DB connection pool saturation, slow queries, upstream error rates).",
            "- Traces for representative failing requests (if available).",
        ]
    )
    if not any(e.event_ts for e in events):
        missing.append(
            "- Timestamps are missing/ambiguous in logs; provide logs with reliable timestamps or add time sync/formatting."
        )
    return "\n".join(missing)

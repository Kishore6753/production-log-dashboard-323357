from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.services.log_parsing import ParsedEvent

SEVERITY_ORDER = {"CRITICAL": 4, "ERROR": 3, "WARNING": 2, "INFO": 1, "DEBUG": 0, "TRACE": -1, None: -2}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_message_for_signature(message: str) -> str:
    # Remove obvious high-cardinality values to stabilize signatures.
    s = message
    s = re.sub(r"\b[0-9a-f]{8,}\b", "<HEX>", s, flags=re.IGNORECASE)  # ids, hashes
    s = re.sub(r"\b\d{4,}\b", "<NUM>", s)  # large ints like ids
    s = re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "<IP>", s)  # IPs
    s = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<UUID>", s, flags=re.IGNORECASE)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:4000]


def _signature_key(event: ParsedEvent) -> str:
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

    Returns:
      dict containing:
        - report: structured report JSON with the 10 required sections
        - summary: small JSON summary for analysis_runs.summary
        - findings: list of findings to persist
    """
    if not events:
        report = _build_empty_report(incident_name=incident_name)
        return {"report": report, "summary": {"events": 0}, "findings": []}

    # Compute window
    known_ts = [e.event_ts for e in events if e.event_ts is not None]
    window_start = min(known_ts) if known_ts else None
    window_end = max(known_ts) if known_ts else None

    # Severity counts
    sev_counts = Counter((e.severity or "UNKNOWN").upper() for e in events)
    top_sev = sorted(sev_counts.items(), key=lambda kv: (-kv[1], kv[0]))

    # Signatures
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

    findings: list[FindingOut] = []
    timeline_entries: list[dict[str, Any]] = []

    # Timeline: take first occurrences of top 3 signatures + first error
    first_error = next((e for e in events if (e.severity or "").upper() in ("ERROR", "CRITICAL")), None)
    if first_error:
        timeline_entries.append(
            _timeline_entry(
                ts=first_error.event_ts,
                label="First high-severity symptom observed",
                event=first_error,
            )
        )

    for sig_key, evs in top_sigs[:3]:
        evs_sorted = sorted(evs, key=lambda x: x.event_ts or _utc_now())
        representative = evs_sorted[0]
        sev = (representative.severity or "UNKNOWN").upper()
        title = _make_signature_title(representative)
        occurrences = len(evs)

        first_seen = min((e.event_ts for e in evs if e.event_ts), default=None)
        last_seen = max((e.event_ts for e in evs if e.event_ts), default=None)

        evidence = {
            "signature_key": sig_key,
            "representative_excerpt": _evidence_excerpt(representative),
            "examples": [_evidence_excerpt(e) for e in evs_sorted[:3]],
            "contexts": _top_contexts(evs),
        }

        description = (
            "This signature groups similar events using stable fields (severity/component/service + normalized message). "
            "The provided excerpts show representative instances."
        )

        root_cause = None
        if sev in ("ERROR", "CRITICAL"):
            # Conservative: propose a hypothesis rather than asserting facts.
            root_cause = (
                "Hypothesis: this error reflects a failing code path or dependency interaction. "
                "Confirm by correlating request IDs/trace IDs (if present) and checking surrounding warnings/timeouts."
            )

        findings.append(
            FindingOut(
                severity=sev if sev != "UNKNOWN" else "WARNING",
                title=title,
                description=description,
                root_cause=root_cause,
                evidence=evidence,
                first_seen_at=first_seen,
                last_seen_at=last_seen,
                occurrences=occurrences,
            )
        )

        timeline_entries.append(
            _timeline_entry(
                ts=first_seen,
                label=f"Signature first seen: {title} (count={occurrences})",
                event=representative,
            )
        )

    # Patterns/anomalies (simple heuristics)
    anomalies: list[str] = []
    if sev_counts.get("CRITICAL", 0) > 0 and sev_counts.get("ERROR", 0) > 0:
        anomalies.append("Both CRITICAL and ERROR events present; prioritize user impact and possible cascading failures.")
    if sev_counts.get("WARNING", 0) > 50 and sev_counts.get("ERROR", 0) == 0:
        anomalies.append("High volume of warnings with few/no errors; may be noisy but still indicates potential precursors.")

    # Executive summary narrative (evidence-based)
    incident_label = incident_name or "Log analysis run"
    impact = _impact_phrase(sev_counts)
    status = "unknown (logs only)"  # we do not infer recovery unless logs show it

    exec_summary = (
        f"{incident_label} analyzed {len(events)} log events"
        + (f" spanning {window_start.isoformat()} to {window_end.isoformat()} (UTC)." if window_start and window_end else ".")
        + f" Observed severity distribution includes: {', '.join([f'{k}={v}' for k, v in top_sev[:5]])}. "
        + f" {impact} Current status is {status}."
    )

    scope_sources = (
        "The analysis used only the provided log file content. "
        "If deployment/config/traffic context is not present in logs, it is treated as missing data."
    )

    key_obs = _key_observations(top_sigs=top_sigs, sev_counts=sev_counts, anomalies=anomalies)

    rca_text = (
        "Based on the available logs, the most impactful issues are represented by the top error signatures. "
        "A definitive root cause cannot be asserted without corroborating signals (deploy events, metrics, traces). "
        "Ranked hypotheses are described per signature using supporting excerpts and suggested validation steps."
    )

    troubleshooting = _troubleshooting_recommendations(top_sigs=top_sigs)
    remediation = _remediation_plan(top_sigs=top_sigs)
    observability = _observability_improvements(events=events)
    missing = _missing_data_section(events=events)

    report = {
        "schema_name": "production-log-analysis",
        "report_version": "1.0",
        "generated_at": _utc_now().isoformat(),
        "sections": {
            "1_executive_summary": exec_summary,
            "2_scope_environment_data_sources": (
                f"Time window: "
                f"{window_start.isoformat() if window_start else 'unknown'} to {window_end.isoformat() if window_end else 'unknown'} (UTC). "
                + scope_sources
            ),
            "3_key_observations_from_logs": key_obs,
            "4_incident_timeline": {
                "window_start": window_start.isoformat() if window_start else None,
                "window_end": window_end.isoformat() if window_end else None,
                "entries": timeline_entries,
            },
            "5_error_warning_signature_analysis": _signature_analysis_section(top_sigs),
            "6_root_cause_analysis": rca_text,
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
        },
    }

    summary = {
        "events": len(events),
        "window_start": window_start.isoformat() if window_start else None,
        "window_end": window_end.isoformat() if window_end else None,
        "severity_counts": dict(sev_counts),
        "top_signature_count": len(top_sigs),
    }

    return {"report": report, "summary": summary, "findings": [f.__dict__ for f in findings]}


def _build_empty_report(*, incident_name: str | None) -> dict[str, Any]:
    label = incident_name or "Log analysis run"
    return {
        "schema_name": "production-log-analysis",
        "report_version": "1.0",
        "generated_at": _utc_now().isoformat(),
        "sections": {
            "1_executive_summary": f"{label} contained no parsable events.",
            "2_scope_environment_data_sources": "No data sources were provided or the log was empty.",
            "3_key_observations_from_logs": "No observations available due to empty input.",
            "4_incident_timeline": {"entries": []},
            "5_error_warning_signature_analysis": [],
            "6_root_cause_analysis": "Root cause cannot be assessed without log evidence.",
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


def _key_observations(*, top_sigs: list[tuple[str, list[ParsedEvent]]], sev_counts: Counter, anomalies: list[str]) -> str:
    lines: list[str] = []
    lines.append(
        "The logs show a mix of severities. "
        f"Counts: CRITICAL={sev_counts.get('CRITICAL', 0)}, ERROR={sev_counts.get('ERROR', 0)}, "
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
    if anomalies:
        lines.append("Potential anomalies/patterns identified:")
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
                    "Higher-severity signatures are prioritized because they are more likely to reflect user impact. "
                    "This grouping avoids overcounting per-request IDs and focuses on stable failure modes."
                ),
            }
        )
    return out


def _troubleshooting_recommendations(*, top_sigs: list[tuple[str, list[ParsedEvent]]]) -> str:
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
    # If events have no timestamps, explicitly call it out.
    if not any(e.event_ts for e in events):
        missing.append("- Timestamps are missing/ambiguous in logs; provide logs with reliable timestamps or add time sync/formatting.")
    return "\n".join(missing)

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import UploadFile
from sqlalchemy.orm import Session

from src.core.config import get_settings
from src.db.models import AnalysisRun, Finding, StructuredReport, Upload


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# PUBLIC_INTERFACE
def persist_upload(
    db: Session,
    *,
    file: UploadFile,
    raw_bytes: bytes,
    source_system: str | None,
    environment: str | None,
    metadata: dict[str, Any] | None,
) -> Upload:
    """Persist an uploaded log artifact and write it to local storage."""
    settings = get_settings()
    os.makedirs(settings.uploads_dir, exist_ok=True)

    upload_id = uuid.uuid4()
    safe_name = os.path.basename(file.filename or "upload.log")
    storage_path = os.path.join(settings.uploads_dir, f"{upload_id}__{safe_name}")

    with open(storage_path, "wb") as f:
        f.write(raw_bytes)

    up = Upload(
        id=upload_id,
        user_id=None,  # auth not implemented in this subtask
        original_filename=safe_name,
        storage_path=storage_path,
        content_type=file.content_type,
        file_size_bytes=len(raw_bytes),
        file_sha256=_sha256_bytes(raw_bytes),
        received_at=_utc_now(),
        source_system=source_system,
        environment=environment,
        metadata=metadata or {},
    )
    db.add(up)
    db.commit()
    db.refresh(up)
    return up


# PUBLIC_INTERFACE
def create_run(db: Session, *, upload_id: uuid.UUID, parser_name: str, parameters: dict[str, Any]) -> AnalysisRun:
    """Create an analysis_runs row with status=running."""
    run = AnalysisRun(
        id=uuid.uuid4(),
        upload_id=upload_id,
        triggered_by=None,
        status="running",
        started_at=_utc_now(),
        finished_at=None,
        tool_version="production-log-analysis/1.0",
        parser_name=parser_name,
        parameters=parameters,
        summary={},
        error_message=None,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


# PUBLIC_INTERFACE
def mark_run_succeeded(db: Session, *, run_id: uuid.UUID, summary: dict[str, Any]) -> None:
    """Mark a run as succeeded and persist summary."""
    run: AnalysisRun | None = db.get(AnalysisRun, run_id)
    if not run:
        raise ValueError("Run not found")
    run.status = "succeeded"
    run.finished_at = _utc_now()
    run.summary = summary
    db.add(run)
    db.commit()


# PUBLIC_INTERFACE
def mark_run_failed(db: Session, *, run_id: uuid.UUID, error_message: str) -> None:
    """Mark a run as failed and persist error message."""
    run: AnalysisRun | None = db.get(AnalysisRun, run_id)
    if not run:
        raise ValueError("Run not found")
    run.status = "failed"
    run.finished_at = _utc_now()
    run.error_message = error_message
    db.add(run)
    db.commit()


# PUBLIC_INTERFACE
def persist_findings(db: Session, *, upload_id: uuid.UUID, run_id: uuid.UUID, findings: list[dict[str, Any]]) -> None:
    """Persist findings produced by analysis."""
    for f in findings:
        rec = Finding(
            id=uuid.uuid4(),
            run_id=run_id,
            upload_id=upload_id,
            severity=f.get("severity") or "WARNING",
            title=f.get("title") or "Finding",
            description=f.get("description"),
            root_cause=f.get("root_cause"),
            evidence=f.get("evidence") or {},
            related_signature_id=None,
            first_seen_at=f.get("first_seen_at"),
            last_seen_at=f.get("last_seen_at"),
            occurrences=int(f.get("occurrences") or 1),
            created_at=_utc_now(),
        )
        db.add(rec)
    db.commit()


# PUBLIC_INTERFACE
def persist_structured_report(
    db: Session,
    *,
    upload_id: uuid.UUID,
    run_id: uuid.UUID,
    report: dict[str, Any],
) -> StructuredReport:
    """Persist the final structured report JSON for a run."""
    rec = StructuredReport(
        id=uuid.uuid4(),
        run_id=run_id,
        upload_id=upload_id,
        created_at=_utc_now(),
        report_version=str(report.get("report_version") or "1.0"),
        schema_name=str(report.get("schema_name") or "production-log-analysis"),
        report=report,
        is_active=True,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec

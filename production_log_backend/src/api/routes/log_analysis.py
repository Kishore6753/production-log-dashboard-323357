from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.api.schemas import (
    RunCreateResponse,
    RunStatusResponse,
    StructuredReportResponse,
    UploadResponse,
)
from src.db.models import AnalysisRun, StructuredReport, Upload
from src.db.session import get_db
from src.services.analysis_service import analyze_events
from src.services.log_parsing import parse_log_lines
from src.services.persistence_service import (
    create_run,
    mark_run_failed,
    mark_run_succeeded,
    persist_findings,
    persist_structured_report,
    persist_upload,
)

router = APIRouter(prefix="/v1", tags=["Log analysis"])


class AnalyzeRequest(BaseModel):
    incident_name: str | None = Field(
        None, description="Optional human-readable incident name used in the report."
    )
    source_system: str | None = Field(None, description="Optional source system identifier.")
    environment: str | None = Field(None, description="Optional environment (prod/staging/etc).")
    metadata: dict = Field(default_factory=dict, description="Arbitrary metadata stored with the upload.")
    parser_name: str = Field("auto", description="Parser identifier (currently 'auto').")


@router.post(
    "/uploads",
    summary="Upload a log file",
    description="Uploads a log file and persists an uploads row. Does not run analysis automatically.",
    response_model=UploadResponse,
)
# PUBLIC_INTERFACE
def upload_log(
    source_system: str | None = None,
    environment: str | None = None,
    file: UploadFile = File(..., description="Log file to upload."),
    db: Session = Depends(get_db),
) -> UploadResponse:
    """Upload endpoint for log artifacts."""
    raw_bytes = file.file.read()
    up = persist_upload(
        db,
        file=file,
        raw_bytes=raw_bytes,
        source_system=source_system,
        environment=environment,
        metadata={},
    )
    return UploadResponse(
        id=up.id,
        original_filename=up.original_filename,
        received_at=up.received_at,
        file_size_bytes=up.file_size_bytes,
        content_type=up.content_type,
    )


@router.post(
    "/uploads/{upload_id}/analyze",
    summary="Run analysis for an uploaded log file",
    description=(
        "Runs parsing + issue detection + patterns/anomalies + RCA hypotheses and generates a structured report "
        "following the production-log-analysis skill format. Persists analysis_runs, findings, and structured_reports."
    ),
    response_model=RunCreateResponse,
)
# PUBLIC_INTERFACE
def analyze_upload(
    upload_id: uuid.UUID,
    request: AnalyzeRequest,
    db: Session = Depends(get_db),
) -> RunCreateResponse:
    """Create an analysis run and synchronously execute analysis for the referenced upload."""
    upload: Upload | None = db.get(Upload, upload_id)
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")
    if not upload.storage_path:
        raise HTTPException(status_code=400, detail="Upload missing storage_path")

    run = create_run(db, upload_id=upload_id, parser_name=request.parser_name, parameters=request.model_dump())

    try:
        with open(upload.storage_path, "rb") as f:
            raw_text = f.read().decode("utf-8", errors="replace")

        events = parse_log_lines(raw_text)
        result = analyze_events(events, incident_name=request.incident_name)

        persist_findings(db, upload_id=upload_id, run_id=run.id, findings=result["findings"])
        persist_structured_report(db, upload_id=upload_id, run_id=run.id, report=result["report"])
        mark_run_succeeded(db, run_id=run.id, summary=result["summary"])
    except Exception as e:  # noqa: BLE001 - boundary catches and persists failure
        mark_run_failed(db, run_id=run.id, error_message=str(e))
        raise HTTPException(status_code=500, detail="Analysis failed") from e

    return RunCreateResponse(run_id=run.id, upload_id=upload_id, status="succeeded")


@router.get(
    "/runs/{run_id}",
    summary="Get analysis run status",
    description="Returns analysis run state, timestamps, and summary/error information.",
    response_model=RunStatusResponse,
)
# PUBLIC_INTERFACE
def get_run_status(run_id: uuid.UUID, db: Session = Depends(get_db)) -> RunStatusResponse:
    """Retrieve an analysis run row."""
    run: AnalysisRun | None = db.get(AnalysisRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return RunStatusResponse(
        run_id=run.id,
        upload_id=run.upload_id,
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        summary=run.summary or {},
        error_message=run.error_message,
    )


@router.get(
    "/runs/{run_id}/report",
    summary="Get structured report for a run",
    description="Returns the final structured report JSON generated by the analysis run.",
    response_model=StructuredReportResponse,
)
# PUBLIC_INTERFACE
def get_structured_report(run_id: uuid.UUID, db: Session = Depends(get_db)) -> StructuredReportResponse:
    """Fetch the structured report JSON for a run."""
    report: StructuredReport | None = (
        db.query(StructuredReport).filter(StructuredReport.run_id == run_id).limit(1).one_or_none()
    )
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return StructuredReportResponse(
        run_id=report.run_id,
        upload_id=report.upload_id,
        created_at=report.created_at,
        schema_name=report.schema_name,
        report_version=report.report_version,
        report=report.report,
    )

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    id: UUID = Field(..., description="Upload ID.")
    original_filename: str = Field(..., description="Original filename as received.")
    received_at: datetime = Field(..., description="When the upload was received (UTC).")
    file_size_bytes: int | None = Field(None, description="Size of uploaded file in bytes.")
    content_type: str | None = Field(None, description="MIME type.")


class RunCreateResponse(BaseModel):
    run_id: UUID = Field(..., description="Created analysis run ID.")
    upload_id: UUID = Field(..., description="Associated upload ID.")
    status: str = Field(..., description="Run status (running/succeeded/failed).")


class RunStatusResponse(BaseModel):
    run_id: UUID = Field(..., description="Analysis run ID.")
    upload_id: UUID = Field(..., description="Associated upload ID.")
    status: str = Field(..., description="Run status.")
    started_at: datetime = Field(..., description="Run start timestamp.")
    finished_at: datetime | None = Field(None, description="Run completion timestamp (if finished).")
    summary: dict = Field(..., description="Small JSON summary, suitable for dashboards.")
    error_message: str | None = Field(None, description="Failure reason (if failed).")


class StructuredReportResponse(BaseModel):
    run_id: UUID = Field(..., description="Analysis run ID.")
    upload_id: UUID = Field(..., description="Associated upload ID.")
    created_at: datetime = Field(..., description="When the structured report was created.")
    schema_name: str | None = Field(None, description="Report schema name.")
    report_version: str | None = Field(None, description="Report version.")
    report: dict = Field(..., description="Full structured report JSON.")

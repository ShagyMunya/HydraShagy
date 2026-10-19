from datetime import date, datetime, time, timezone
from uuid import UUID, uuid4
from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, Time, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.db import Base

def utcnow(): return datetime.now(timezone.utc)

class Assessment(Base):
    __tablename__ = "assessments"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(String(120), index=True)
    name: Mapped[str] = mapped_column(String(240))
    unit: Mapped[str] = mapped_column(String(160))
    owner: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(40), default="planning")
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date] = mapped_column(Date)
    objective: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(String(120), index=True)
    assessment_id: Mapped[UUID | None] = mapped_column(ForeignKey("assessments.id", ondelete="SET NULL"), index=True)
    name: Mapped[str] = mapped_column(String(240))
    target: Mapped[str] = mapped_column(String(253), default="")
    web_url: Mapped[str] = mapped_column(String(1000), default="")
    unit: Mapped[str] = mapped_column(String(160))
    service_owner: Mapped[str] = mapped_column(String(200))
    asset_type: Mapped[str] = mapped_column(String(80))
    criticality: Mapped[str] = mapped_column(String(24), default="medium")
    environment: Mapped[str] = mapped_column(String(80), default="internal")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Authorization(Base):
    __tablename__ = "authorizations"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(String(120), index=True)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    authority_reference: Mapped[str] = mapped_column(String(240))
    system_owner: Mapped[str] = mapped_column(String(200))
    target_allowlist: Mapped[list] = mapped_column(JSON, default=list)
    exclusions: Mapped[list] = mapped_column(JSON, default=list)
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date] = mapped_column(Date)
    daily_start: Mapped[time] = mapped_column(Time)
    daily_end: Mapped[time] = mapped_column(Time)
    weekdays_only: Mapped[bool] = mapped_column(Boolean, default=True)
    timezone_name: Mapped[str] = mapped_column(String(80), default="Africa/Harare")
    escalation_contact: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(40), default="pending")
    approved_by: Mapped[str | None] = mapped_column(String(200))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(String(120), index=True)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), index=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(24))
    cvss_base: Mapped[float | None] = mapped_column(Float)
    business_impact: Mapped[str] = mapped_column(String(24), default="moderate")
    priority_score: Mapped[float | None] = mapped_column(Float)
    cve_id: Mapped[str | None] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(40), default="open")
    remediation_owner: Mapped[str] = mapped_column(String(200))
    due_date: Mapped[date | None] = mapped_column(Date)
    summary: Mapped[str] = mapped_column(Text, default="")
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class TestCheck(Base):
    __tablename__ = "test_checks"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(String(120), index=True)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    category: Mapped[str] = mapped_column(String(120))
    title: Mapped[str] = mapped_column(String(400))
    status: Mapped[str] = mapped_column(String(24), default="not_started")
    evidence_reference: Mapped[str] = mapped_column(String(500), default="")
    assessor_note: Mapped[str] = mapped_column(String(2000), default="")
    updated_by: Mapped[str] = mapped_column(String(200))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class ScanJob(Base):
    __tablename__ = "scan_jobs"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(String(120), index=True)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="queued")
    requested_by: Mapped[str] = mapped_column(String(200))
    celery_task_id: Mapped[str | None] = mapped_column(String(64))
    result_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    xml_object_key: Mapped[str | None] = mapped_column(String(500))
    xml_object_keys: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class ValidationRequest(Base):
    __tablename__ = "validation_requests"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(String(120), index=True)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[UUID] = mapped_column(ForeignKey("assets.id", ondelete="RESTRICT"), index=True)
    purpose: Mapped[str] = mapped_column(Text)
    procedure_reference: Mapped[str] = mapped_column(String(240))
    proposed_window: Mapped[str] = mapped_column(String(240))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    requester: Mapped[str] = mapped_column(String(200))
    reviewer: Mapped[str | None] = mapped_column(String(200))
    outcome: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(String(120), index=True)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"), index=True)
    object_key: Mapped[str] = mapped_column(String(500), unique=True)
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(120))
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    encrypted: Mapped[bool] = mapped_column(Boolean, default=True)
    source_tool: Mapped[str] = mapped_column(String(40), default="manual")
    analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    uploaded_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class CVERecord(Base):
    __tablename__ = "cve_records"
    __table_args__ = (Index("ix_cve_cpes_gin", "cpes", postgresql_using="gin"),)
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str] = mapped_column(Text)
    cvss_base: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(24), default="unknown")
    cpes: Mapped[list] = mapped_column(JSONB, default=list)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

class ToolRun(Base):
    __tablename__ = "tool_runs"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(String(120), index=True)
    assessment_id: Mapped[UUID] = mapped_column(ForeignKey("assessments.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    tool_id: Mapped[str] = mapped_column(String(80))
    profile_id: Mapped[str] = mapped_column(String(120))
    requested_by: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(32), default="queued")
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=120)
    result_location: Mapped[str | None] = mapped_column(String(500))
    error_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_org_created", "organization_id", "created_at"),)
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    organization_id: Mapped[str] = mapped_column(String(120), index=True)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(120))
    resource_type: Mapped[str] = mapped_column(String(80))
    resource_id: Mapped[str] = mapped_column(String(80))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


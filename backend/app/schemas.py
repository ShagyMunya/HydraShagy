from datetime import date, time
from uuid import UUID
from pydantic import BaseModel, Field

class AssessmentCreate(BaseModel):
    name: str = Field(min_length=3, max_length=240)
    unit: str = Field(min_length=2, max_length=160)
    owner: str = Field(min_length=2, max_length=160)
    kind: str = Field(max_length=80)
    start_date: date
    end_date: date
    objective: str = Field(default="", max_length=5000)

class AssetCreate(BaseModel):
    assessment_id: UUID | None = None
    name: str = Field(min_length=2, max_length=240)
    target: str = Field(min_length=1, max_length=253)
    web_url: str = Field(default="", max_length=1000)
    unit: str = Field(min_length=2, max_length=160)
    service_owner: str = Field(min_length=2, max_length=200)
    asset_type: str = Field(max_length=80)
    criticality: str = "medium"
    environment: str = "internal"

class AuthorizationCreate(BaseModel):
    assessment_id: UUID
    authority_reference: str = Field(min_length=3, max_length=240)
    system_owner: str = Field(min_length=2, max_length=200)
    target_allowlist: list[str] = Field(min_length=1, max_length=100)
    exclusions: list[str] = Field(default_factory=list, max_length=100)
    start_date: date
    end_date: date
    daily_start: time
    daily_end: time
    weekdays_only: bool = True
    timezone_name: str = "Africa/Harare"
    escalation_contact: str = Field(min_length=3, max_length=240)

class FindingCreate(BaseModel):
    assessment_id: UUID
    asset_id: UUID
    title: str = Field(min_length=4, max_length=300)
    severity: str
    cvss_base: float | None = Field(default=None, ge=0, le=10)
    business_impact: str = "moderate"
    cve_id: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d{4,}$")
    remediation_owner: str = Field(min_length=2, max_length=200)
    due_date: date | None = None
    summary: str = Field(default="", max_length=10000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=50)

class ScanCreate(BaseModel):
    asset_id: UUID
    kind: str = Field(pattern="^(nmap|zap_baseline|web_posture|sqlmap|metasploit_http_title|john_audit|hashcat_audit|hydra_single_login)$")
    hash_evidence_id: UUID | None = None
    wordlist_evidence_id: UUID | None = None
    hash_mode: str | None = Field(default=None, pattern="^(0|1000|1800|3200)$")
    hydra_service: str | None = Field(default=None, pattern="^(ssh|ftp|http-get|https-get|smb)$")
    hydra_username: str | None = Field(default=None, min_length=1, max_length=200, pattern=r"^[^\r\n]+$")
    hydra_password: str | None = Field(default=None, min_length=1, max_length=200, pattern=r"^[^\r\n]+$")

class ValidationCreate(BaseModel):
    assessment_id: UUID
    finding_id: UUID
    asset_id: UUID
    purpose: str = Field(min_length=10, max_length=5000)
    procedure_reference: str = Field(min_length=3, max_length=240)
    proposed_window: str = Field(min_length=5, max_length=240)

class Decision(BaseModel):
    decision: str = Field(pattern="^(approve|return)$")
    note: str = Field(default="", max_length=2000)

class AuthorizationDecision(BaseModel):
    decision: str = Field(pattern="^(approve|return|revoke)$")
    note: str = Field(default="", max_length=2000)

class FindingStatus(BaseModel):
    status: str = Field(pattern="^(open|in_progress|risk_accepted|closed)$")

class TestCheckCreate(BaseModel):
    assessment_id: UUID
    category: str = Field(min_length=2,max_length=120)
    title: str = Field(min_length=4,max_length=400)

class TestCheckUpdate(BaseModel):
    status: str = Field(pattern="^(not_started|in_progress|completed|not_applicable)$")
    evidence_reference: str = Field(default="",max_length=500)
    assessor_note: str = Field(default="",max_length=2000)


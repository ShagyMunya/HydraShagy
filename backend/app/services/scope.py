import ipaddress
import re
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import Assessment, Asset, Authorization

HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*\.?$")

def normalize_target(value: str) -> str:
    value=value.strip().rstrip(".")
    if not value or any(c in value for c in ("*","/",","," ","@")):
        raise HTTPException(422,"Target must be one exact hostname or IP; wildcards, CIDRs, URLs, and lists are not accepted.")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        if not HOST_RE.fullmatch(value):
            raise HTTPException(422,"Target is not a valid exact hostname or IP address.")
        try:
            return value.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise HTTPException(422,"Invalid internationalized hostname.") from exc

def active_authorization(db: Session, organization_id: str, asset_id, *, check_clock=True):
    asset=db.scalar(select(Asset).where(Asset.id==asset_id,Asset.organization_id==organization_id))
    if asset is None:
        raise HTTPException(404,"Asset not found")
    if not asset.assessment_id or not asset.target:
        raise HTTPException(409,"Asset must have an assessment and an exact target")
    assessment=db.scalar(select(Assessment).where(Assessment.id==asset.assessment_id,Assessment.organization_id==organization_id))
    if assessment is None or assessment.status!="active":
        raise HTTPException(409,"Assessment must be active")
    candidates=db.scalars(select(Authorization).where(Authorization.organization_id==organization_id,Authorization.assessment_id==assessment.id,Authorization.status=="approved")).all()
    today=datetime.now(ZoneInfo("Africa/Harare")).date()
    authorization=next((a for a in candidates if normalize_target(asset.target) in {normalize_target(x) for x in a.target_allowlist}),None)
    if authorization is None:
        raise HTTPException(403,"No approved authorization includes this exact target")
    if not (assessment.start_date <= today <= assessment.end_date and authorization.start_date <= today <= authorization.end_date):
        raise HTTPException(403,"Outside the authorized assessment dates")
    if check_clock:
        try:
            local=datetime.now(ZoneInfo(authorization.timezone_name))
        except ZoneInfoNotFoundError as exc:
            raise HTTPException(500,"Authorization timezone is invalid") from exc
        if authorization.weekdays_only and local.weekday() >= 5:
            raise HTTPException(403,"Authorization is limited to weekdays")
        if not authorization.daily_start <= local.time().replace(tzinfo=None) <= authorization.daily_end:
            raise HTTPException(403,"Outside the authorized daily testing window")
    return asset,assessment,authorization


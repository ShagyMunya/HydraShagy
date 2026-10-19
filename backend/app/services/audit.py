from sqlalchemy.orm import Session
from app.models import AuditEvent
from app.security import Principal

def record(db: Session, actor: Principal, action: str, resource_type: str, resource_id: str, detail: dict | None = None):
    db.add(AuditEvent(organization_id=actor.organization_id,actor=actor.subject,action=action,
        resource_type=resource_type,resource_id=str(resource_id),detail=detail or {}))

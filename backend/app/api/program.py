from datetime import datetime, timezone, timedelta
from html import escape
import csv
import io
import json
from collections import Counter
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo
from uuid import UUID
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import Assessment, Asset, Authorization, AuditEvent, Evidence, Finding, ScanJob, ValidationRequest, CVERecord, TestCheck, ToolRun
from app.schemas import AssessmentCreate, AssetCreate, AuthorizationCreate, AuthorizationDecision, Decision, FindingCreate, FindingStatus, ScanCreate, ValidationCreate, TestCheckCreate, TestCheckUpdate
from app.security import Principal, current_principal, require_roles
from app.services.audit import record
from app.services.scope import normalize_target, active_authorization
from app.services.object_store import get_decrypted, put_encrypted, delete_encrypted
from app.workers.celery_app import celery
from app.tools_registry import TOOLS, get_tool

router=APIRouter(prefix="/api/v1",tags=["program"])

def _parse_external_report(source_tool:str,filename:str,content:bytes)->dict:
    """Extract bounded review metadata; keep the original report encrypted as evidence."""
    lower=filename.lower()
    if source_tool=="manual": return {"format":"unparsed","note":"Stored as encrypted evidence; no report parser was selected."}
    if source_tool=="burp_suite":
        if not lower.endswith(".xml"): raise HTTPException(422,"Burp import currently accepts Burp XML issue reports only")
        from defusedxml import ElementTree as SafeET
        try: root=SafeET.fromstring(content)
        except Exception as exc: raise HTTPException(422,"Could not parse Burp XML report") from exc
        def local(tag): return tag.rsplit("}",1)[-1].lower()
        issues=[]
        for node in root.iter():
            if local(node.tag)!="issue": continue
            fields={local(child.tag):" ".join("".join(child.itertext()).split()) for child in list(node) if local(child.tag) in {"name","severity","confidence","host"}}
            raw_host=fields.get("host","")
            host_node=next((child for child in list(node) if local(child.tag)=="host"),None)
            candidate=(host_node.text or "").strip() if host_node is not None else raw_host
            if candidate.startswith(("http://","https://")):
                parsed=urlsplit(candidate);safe_host=f"{parsed.scheme}://{parsed.hostname or ''}{parsed.path[:300]}"
            else: safe_host=candidate[:300]
            issues.append({"name":fields.get("name","Unnamed issue")[:300],"severity":fields.get("severity","Unknown")[:40],"confidence":fields.get("confidence","Unknown")[:40],"host":safe_host})
            if len(issues)>=500: break
        counts=Counter(item["severity"].lower() for item in issues)
        return {"format":"burp_xml_issue_report","issue_count":len(issues),"severity_counts":dict(counts),"issues":issues,"truncated":len(issues)>=500,"review_note":"Imported Burp issue ratings are triage signals. Validate affected URL, evidence, confidence, and business impact before recording a finding."}
    if source_tool=="wireshark":
        if lower.endswith((".pcap",".pcapng")):
            return {"format":"wireshark_capture","parsed":False,"note":"Raw capture stored encrypted. Review it offline in Wireshark; packet payloads are not parsed by Fieldnote."}
        if not lower.endswith(".csv"): raise HTTPException(422,"Wireshark import accepts packet-summary CSV or encrypted PCAP/PCAPNG evidence")
        try:
            text=content.decode("utf-8-sig")
            reader=csv.DictReader(io.StringIO(text))
            if not reader.fieldnames: raise ValueError("missing headers")
            headers={str(name).strip().lower():name for name in reader.fieldnames if name}
            protocol_key=next((headers[k] for k in ("protocol","_ws.col.protocol") if k in headers),None)
            length_key=next((headers[k] for k in ("length","_ws.col.length") if k in headers),None)
            if not protocol_key: raise ValueError("missing Protocol column")
            protocols=Counter();total_bytes=0;packet_count=0
            for row in reader:
                if packet_count>=50000: break
                protocol=(row.get(protocol_key) or "Unknown").strip()[:80] or "Unknown"
                protocols[protocol]+=1;packet_count+=1
                if length_key:
                    try: total_bytes+=max(0,int((row.get(length_key) or "0").strip()))
                    except ValueError: pass
            if packet_count==0: raise ValueError("no packet rows")
            return {"format":"wireshark_packet_summary_csv","packets_summarized":packet_count,"total_frame_bytes":total_bytes if length_key else None,"protocol_counts":dict(protocols.most_common(30)),"truncated":packet_count>=50000,"review_note":"This summary counts protocols and frame sizes only. It does not identify vulnerabilities or inspect payload content."}
        except HTTPException: raise
        except Exception as exc: raise HTTPException(422,"Could not parse Wireshark CSV; export packet summary columns including Protocol and optionally Length") from exc
    if source_tool=="strix":
        if not lower.endswith((".json", ".sarif")):
            return {"format":"external_tool_artifact","parsed":False,"note":"Strix reports must be vulnerabilities.json or findings.sarif to show a review summary. Original file is encrypted."}
        if len(content)>10*1024*1024: raise HTTPException(413,"Strix JSON report must be 10 MB or smaller")
        try: report=json.loads(content.decode("utf-8-sig"))
        except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise HTTPException(422,"Could not parse Strix JSON report") from exc
        if lower.endswith(".sarif"):
            if not isinstance(report,dict) or report.get("version")!="2.1.0": raise HTTPException(422,"Expected a SARIF 2.1.0 report")
            candidates=[]
            for run in report.get("runs",[])[:20] if isinstance(report.get("runs"),list) else []:
                if not isinstance(run,dict): continue
                tool=run.get("tool",{});driver=tool.get("driver",{}) if isinstance(tool,dict) else {}
                rules=driver.get("rules",[]) if isinstance(driver,dict) and isinstance(driver.get("rules",[]),list) else []
                rule_map={str(rule.get("id")):rule for rule in rules if isinstance(rule,dict)}
                for result in run.get("results",[]) if isinstance(run.get("results"),list) else []:
                    if not isinstance(result,dict): continue
                    rule=rule_map.get(str(result.get("ruleId","")),{})
                    props=rule.get("properties",{}) if isinstance(rule.get("properties"),dict) else {}
                    severity_value=props.get("security-severity") or props.get("cvssScore")
                    try: score=float(severity_value); score=score if 0<=score<=10 else None
                    except (ValueError,TypeError): score=None
                    level=str(result.get("level", "warning")).lower()
                    severity=("critical" if score is not None and score>=9 else "high" if score is not None and score>=7 else "medium" if score is not None and score>=4 else "low" if score is not None and score>0 else {"error":"high","warning":"medium","note":"low"}.get(level,"info"))
                    locations=result.get("locations",[]); location=locations[0].get("physicalLocation",{}) if isinstance(locations,list) and locations and isinstance(locations[0],dict) else {}
                    artifact_location=location.get("artifactLocation",{}) if isinstance(location,dict) else {}
                    artifact=artifact_location.get("uri") if isinstance(artifact_location,dict) else None
                    region=location.get("region",{}) if isinstance(location,dict) else {}
                    message=result.get("message",{}).get("text","") if isinstance(result.get("message"),dict) else ""
                    help_text=rule.get("fullDescription",{}).get("text","") if isinstance(rule.get("fullDescription"),dict) else ""
                    short_description=rule.get("shortDescription",{});short_text=short_description.get("text","") if isinstance(short_description,dict) else ""
                    candidates.append({"title":str(rule.get("name") or short_text or result.get("ruleId") or "SARIF finding")[:300],"severity":severity,"cvss":score,"confidence":"not reported","description":str(message or help_text)[:2000],"location":str(artifact or "")[:500]+(f":{region['startLine']}" if isinstance(region,dict) and region.get("startLine") else ""),"cwe":str(props.get("cwe") or "")[:32],"remediation":str(rule.get("help",{}).get("text", "") if isinstance(rule.get("help"),dict) else "")[:1500]})
                    if len(candidates)>=500: break
                if len(candidates)>=500: break
            report_format="strix_sarif"
        else:
            if not isinstance(report,list): raise HTTPException(422,"Expected Strix vulnerabilities.json to contain a list")
            candidates=[]
            for item in report[:500]:
                if not isinstance(item,dict): continue
                score=item.get("cvss");
                try: score=float(score); score=score if 0<=score<=10 else None
                except (ValueError,TypeError): score=None
                severity=str(item.get("severity", "info")).lower()
                if severity not in {"critical","high","medium","low","info"}: severity="info"
                candidates.append({"title":str(item.get("title") or item.get("name") or "Strix finding")[:300],"severity":severity,"cvss":score,"confidence":str(item.get("confidence") or "not reported")[:80],"description":str(item.get("description") or item.get("impact") or "")[:2000],"location":str(item.get("endpoint") or item.get("target") or "")[:500],"cwe":str(item.get("cwe") or "")[:32],"remediation":str(item.get("remediation") or item.get("fix") or "")[:1500]})
            report_format="strix_vulnerabilities_json"
        counts=Counter(item["severity"] for item in candidates)
        return {"format":report_format,"issue_count":len(candidates),"severity_counts":dict(counts),"candidates":candidates,"truncated":len(candidates)>=500,"review_note":"Imported reports are unverified candidates. Confirm scope, reproduce safely, review counterevidence, and assess business impact before creating a finding."}
    if source_tool=="metasploit":
        if not lower.endswith(".xml"):
            return {"format":"external_tool_artifact","parsed":False,"note":"Metasploit XML database exports receive a bounded host/service summary. Other files remain encrypted for offline review."}
        if len(content)>10*1024*1024: raise HTTPException(413,"Metasploit XML report must be 10 MB or smaller")
        from defusedxml import ElementTree as SafeET
        try: root=SafeET.fromstring(content)
        except Exception as exc: raise HTTPException(422,"Could not parse Metasploit XML export") from exc
        hosts=[]
        for node in root.iter():
            if node.tag.rsplit("}",1)[-1].lower()!="host": continue
            address=(node.get("address") or node.findtext("address") or "")[:120]
            services=[]
            for service in node.iter():
                if service.tag.rsplit("}",1)[-1].lower()!="service": continue
                services.append({"port":(service.get("port") or service.findtext("port") or "")[:10],"protocol":(service.get("proto") or service.findtext("proto") or "")[:20],"name":(service.get("name") or service.findtext("name") or "")[:100]})
                if len(services)>=100: break
            hosts.append({"address":address,"services":services})
            if len(hosts)>=500: break
        return {"format":"metasploit_xml_inventory","host_count":len(hosts),"hosts":hosts,"truncated":len(hosts)>=500,"review_note":"Imported inventory is an external observation. Confirm it is within the approved scope before recording findings."}
    if source_tool in {"john","hashcat"}:
        if len(content)>10*1024*1024: raise HTTPException(413,"Password audit output must be 10 MB or smaller")
        try: lines=content.decode("utf-8-sig",errors="replace").splitlines()
        except Exception as exc: raise HTTPException(422,"Could not read password audit output") from exc
        # Potfiles contain recovered secrets. Count entries only; never persist them in the parsed summary.
        entries=sum(1 for line in lines[:100000] if line and ":" in line)
        return {"format":"password_audit_summary","tool":source_tool,"line_count":min(len(lines),100000),"recovered_entry_count":entries,"truncated":len(lines)>100000,"secrets_redacted":True,"review_note":"Recovered passwords and hashes are not displayed in this summary. The original output remains encrypted evidence; handle it under approved credential and retention controls."}
    if source_tool=="hydra":
        if len(content)>10*1024*1024: raise HTTPException(413,"Hydra output must be 10 MB or smaller")
        text=content.decode("utf-8-sig",errors="replace")
        successes=sum(1 for line in text.splitlines()[:100000] if "login:" in line.lower() and "password:" in line.lower())
        return {"format":"hydra_result_summary","success_count":successes,"secrets_redacted":True,"review_note":"Credential values are not displayed in the summary. Confirm each result and scope; the original output remains encrypted evidence."}
    if source_tool in {"metasploit","sqlmap","john","hashcat","hydra","pentera","nodezero"}:
        return {"format":"external_tool_artifact","parsed":False,"note":"Stored encrypted without parsing or displaying report contents. Review the original file offline, validate any claim in the approved scope, then link validated evidence to a finding."}
    raise HTTPException(422,"Unsupported external report source")

def own(db, model, item_id, org_id):
    obj=db.scalar(select(model).where(model.id==item_id,model.organization_id==org_id))
    if obj is None: raise HTTPException(404,"Record not found")
    return obj

@router.get("/tools")
def list_tools(user:Principal=Depends(current_principal)):
    return TOOLS

@router.get("/tool-runs")
def list_tool_runs(db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    return db.scalars(select(ToolRun).where(ToolRun.organization_id==user.organization_id).order_by(desc(ToolRun.created_at)).limit(250)).all()

@router.post("/tool-runs",status_code=201)
def create_tool_run(tool_id:str,profile_id:str,assessment_id:UUID,asset_id:UUID|None=None,timeout_seconds:int=120,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","program_manager"))):
    tool=get_tool(tool_id)
    if not tool: raise HTTPException(404,"Tool is not registered")
    if tool["execution"] is not False: raise HTTPException(409,"Use the tool's dedicated authorized scan workflow")
    own(db,Assessment,assessment_id,user.organization_id)
    if asset_id: own(db,Asset,asset_id,user.organization_id)
    timeout_seconds=max(30,min(timeout_seconds,3600))
    item=ToolRun(organization_id=user.organization_id,assessment_id=assessment_id,asset_id=asset_id,tool_id=tool_id,profile_id=profile_id,requested_by=user.subject,status="queued",timeout_seconds=timeout_seconds,error_summary="Non-executable review request. No command or vendor action was run.")
    db.add(item);db.flush();record(db,user,"tool_run.requested","tool_run",item.id,{"tool_id":tool_id,"profile_id":profile_id,"execution":False});db.commit();db.refresh(item);return item

@router.get("/tool-runs/{run_id}")
def get_tool_run(run_id:UUID,db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    return own(db,ToolRun,run_id,user.organization_id)

@router.post("/tool-runs/{run_id}/cancel")
def cancel_tool_run(run_id:UUID,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","program_manager"))):
    item=own(db,ToolRun,run_id,user.organization_id)
    if item.status in {"queued","starting","running"}: item.status="cancelled";record(db,user,"tool_run.cancelled","tool_run",item.id);db.commit()
    return item

@router.get("/summary")
def summary(db:Session=Depends(get_db), user:Principal=Depends(current_principal)):
    assessments=db.scalars(select(Assessment).where(Assessment.organization_id==user.organization_id).order_by(desc(Assessment.created_at)).limit(250)).all()
    assets=db.scalars(select(Asset).where(Asset.organization_id==user.organization_id).limit(1000)).all()
    findings=db.scalars(select(Finding).where(Finding.organization_id==user.organization_id).limit(2000)).all()
    pending=db.scalars(select(Authorization).where(Authorization.organization_id==user.organization_id,Authorization.status=="pending")).all()
    return {"assessments":assessments,"asset_count":len(assets),"finding_count":len(findings),"pending_authorizations":len(pending),"priority_risks":sum(1 for f in findings if f.severity in ("critical","high") and f.status in ("open","in_progress"))}

@router.get("/assessments")
def list_assessments(db:Session=Depends(get_db), user:Principal=Depends(current_principal)):
    return db.scalars(select(Assessment).where(Assessment.organization_id==user.organization_id).order_by(desc(Assessment.created_at))).all()

@router.post("/assessments",status_code=201)
def create_assessment(body:AssessmentCreate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("program_manager","security_analyst"))):
    if body.end_date<body.start_date: raise HTTPException(422,"End date must follow start date")
    obj=Assessment(organization_id=user.organization_id,**body.model_dump(),created_by=user.subject)
    db.add(obj);db.flush();record(db,user,"assessment.created","assessment",obj.id,{"name":obj.name});db.commit();db.refresh(obj);return obj

@router.put("/assessments/{assessment_id}")
def update_assessment(assessment_id:UUID,body:AssessmentCreate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("program_manager","security_analyst"))):
    if body.end_date<body.start_date: raise HTTPException(422,"End date must follow start date")
    obj=own(db,Assessment,assessment_id,user.organization_id)
    for key,value in body.model_dump().items(): setattr(obj,key,value)
    record(db,user,"assessment.updated","assessment",obj.id,{"name":obj.name});db.commit();db.refresh(obj);return obj

@router.delete("/assessments/{assessment_id}",status_code=204)
def delete_assessment(assessment_id:UUID,db:Session=Depends(get_db),user:Principal=Depends(require_roles("program_manager"))):
    obj=own(db,Assessment,assessment_id,user.organization_id);db.delete(obj);record(db,user,"assessment.deleted","assessment",obj.id);db.commit();return None

@router.get("/assets")
def list_assets(db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    return db.scalars(select(Asset).where(Asset.organization_id==user.organization_id).order_by(Asset.name)).all()

@router.post("/assets",status_code=201)
def create_asset(body:AssetCreate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("program_manager","security_analyst"))):
    target=normalize_target(body.target)
    if body.web_url:
        from urllib.parse import urlparse
        u=urlparse(body.web_url)
        if u.scheme not in ("http","https") or u.username or u.password or (u.hostname or "").lower().rstrip(".")!=target:
            raise HTTPException(422,"Web URL must use HTTP(S) and the exact registered target host")
    if body.assessment_id: own(db,Assessment,body.assessment_id,user.organization_id)
    obj=Asset(organization_id=user.organization_id,**body.model_dump(exclude={"target"}),target=target)
    db.add(obj);db.flush();record(db,user,"asset.created","asset",obj.id,{"target":target});db.commit();db.refresh(obj);return obj

@router.put("/assets/{asset_id}")
def update_asset(asset_id:UUID,body:AssetCreate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("program_manager","security_analyst"))):
    target=normalize_target(body.target)
    if body.web_url:
        from urllib.parse import urlparse
        u=urlparse(body.web_url)
        if u.scheme not in ("http","https") or u.username or u.password or (u.hostname or "").lower().rstrip(".")!=target: raise HTTPException(422,"Web URL must use HTTP(S) and the exact registered target host")
    obj=own(db,Asset,asset_id,user.organization_id)
    if body.assessment_id: own(db,Assessment,body.assessment_id,user.organization_id)
    for key,value in body.model_dump(exclude={"target"}).items(): setattr(obj,key,value)
    obj.target=target;record(db,user,"asset.updated","asset",obj.id,{"target":target});db.commit();db.refresh(obj);return obj

@router.delete("/assets/{asset_id}",status_code=204)
def delete_asset(asset_id:UUID,db:Session=Depends(get_db),user:Principal=Depends(require_roles("program_manager"))):
    obj=own(db,Asset,asset_id,user.organization_id);db.delete(obj);record(db,user,"asset.deleted","asset",obj.id);db.commit();return None

@router.get("/authorizations")
def list_authorizations(db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    return db.scalars(select(Authorization).where(Authorization.organization_id==user.organization_id).order_by(desc(Authorization.created_at))).all()

@router.post("/authorizations",status_code=201)
def create_authorization(body:AuthorizationCreate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("program_manager","security_analyst"))):
    from zoneinfo import ZoneInfo,ZoneInfoNotFoundError
    try: ZoneInfo(body.timezone_name)
    except ZoneInfoNotFoundError as exc: raise HTTPException(422,"Unknown IANA timezone") from exc
    assessment=own(db,Assessment,body.assessment_id,user.organization_id)
    if body.start_date>body.end_date or body.daily_start>=body.daily_end: raise HTTPException(422,"Authorization date or daily window is invalid")
    if body.start_date<assessment.start_date or body.end_date>assessment.end_date: raise HTTPException(422,"Authorization dates must fit within the assessment dates")
    targets=list(dict.fromkeys(normalize_target(t) for t in body.target_allowlist))
    obj=Authorization(organization_id=user.organization_id,**body.model_dump(exclude={"target_allowlist"}),target_allowlist=targets,status="pending",created_by=user.subject)
    db.add(obj);db.flush();record(db,user,"authorization.submitted","authorization",obj.id,{"targets":targets});db.commit();db.refresh(obj);return obj

@router.post("/authorizations/{authorization_id}/decision")
def authorization_decision(authorization_id:UUID,body:AuthorizationDecision,db:Session=Depends(get_db),user:Principal=Depends(require_roles("authorization_approver","program_manager"))):
    obj=own(db,Authorization,authorization_id,user.organization_id)
    if body.decision == "revoke":
        if obj.status != "approved": raise HTTPException(409,"Only approved authorizations can be revoked")
        obj.status="revoked"
    else:
        if obj.status!="pending": raise HTTPException(409,"Only pending requests can be decided")
        if obj.created_by==user.subject and "admin" not in user.roles: raise HTTPException(403,"Four-eyes control: requester cannot approve their own authorization")
        obj.status="approved" if body.decision=="approve" else "returned"
    if obj.status=="approved":
        obj.approved_by=user.subject;obj.approved_at=datetime.now(timezone.utc)
        assessment=own(db,Assessment,obj.assessment_id,user.organization_id)
        today=datetime.now(ZoneInfo(obj.timezone_name)).date()
        if assessment.start_date<=today<=assessment.end_date and obj.start_date<=today<=obj.end_date: assessment.status="active"
    record(db,user,f"authorization.{obj.status}","authorization",obj.id,{"note":body.note});db.commit();return obj

@router.get("/findings")
def list_findings(db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    return db.scalars(select(Finding).where(Finding.organization_id==user.organization_id).order_by(desc(Finding.created_at))).all()

@router.delete("/authorizations/{authorization_id}",status_code=204)
def delete_authorization(authorization_id:UUID,db:Session=Depends(get_db),user:Principal=Depends(require_roles("program_manager"))):
    obj=own(db,Authorization,authorization_id,user.organization_id)
    if obj.status=="approved": raise HTTPException(409,"Revoke approved authorizations instead of deleting them")
    db.delete(obj);record(db,user,"authorization.deleted","authorization",obj.id);db.commit();return None

@router.post("/findings",status_code=201)
def create_finding(body:FindingCreate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","program_manager"))):
    own(db,Assessment,body.assessment_id,user.organization_id);asset=own(db,Asset,body.asset_id,user.organization_id)
    if asset.assessment_id!=body.assessment_id: raise HTTPException(422,"Finding asset must belong to the selected assessment")
    if body.severity.lower() not in {"critical","high","medium","low","info"}: raise HTTPException(422,"Invalid severity")
    data=body.model_dump();data["severity"]=body.severity.lower();data["business_impact"]=body.business_impact.lower()
    if data["business_impact"] not in {"low","moderate","high","critical"}: raise HTTPException(422,"Invalid business impact")
    if data["cvss_base"] is not None:
        factor={"low":0.7,"moderate":1.0,"high":1.2,"critical":1.5}[data["business_impact"]]
        data["priority_score"]=min(10.0,round(data["cvss_base"]*factor,1))
        score=data["priority_score"]
        data["severity"]="critical" if score>=9 else "high" if score>=7 else "medium" if score>=4 else "low" if score>0 else "info"
    obj=Finding(organization_id=user.organization_id,**data,created_by=user.subject)
    db.add(obj);db.flush();record(db,user,"finding.created","finding",obj.id,{"severity":obj.severity,"cve_id":obj.cve_id});db.commit();db.refresh(obj);return obj

@router.put("/findings/{finding_id}")
def update_finding_record(finding_id:UUID,body:FindingCreate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","program_manager"))):
    obj=own(db,Finding,finding_id,user.organization_id);own(db,Assessment,body.assessment_id,user.organization_id);asset=own(db,Asset,body.asset_id,user.organization_id)
    if asset.assessment_id!=body.assessment_id: raise HTTPException(422,"Finding asset must belong to the selected assessment")
    data=body.model_dump();data["severity"]=body.severity.lower();data["business_impact"]=body.business_impact.lower()
    if data["business_impact"] not in {"low","moderate","high","critical"}: raise HTTPException(422,"Invalid business impact")
    for key,value in data.items(): setattr(obj,key,value)
    record(db,user,"finding.updated","finding",obj.id);db.commit();db.refresh(obj);return obj

@router.delete("/findings/{finding_id}",status_code=204)
def delete_finding(finding_id:UUID,db:Session=Depends(get_db),user:Principal=Depends(require_roles("program_manager"))):
    obj=own(db,Finding,finding_id,user.organization_id);db.delete(obj);record(db,user,"finding.deleted","finding",obj.id);db.commit();return None

@router.patch("/findings/{finding_id}/status")
def update_finding(finding_id:UUID,body:FindingStatus,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","program_manager","remediation_owner"))):
    obj=own(db,Finding,finding_id,user.organization_id);old=obj.status;obj.status=body.status
    record(db,user,"finding.status_changed","finding",obj.id,{"from":old,"to":obj.status});db.commit();return obj

@router.get("/checks")
def list_checks(assessment_id:UUID|None=None,db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    stmt=select(TestCheck).where(TestCheck.organization_id==user.organization_id)
    if assessment_id: stmt=stmt.where(TestCheck.assessment_id==assessment_id)
    return db.scalars(stmt.order_by(TestCheck.category,TestCheck.title)).all()

@router.post("/checks",status_code=201)
def create_check(body:TestCheckCreate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","program_manager"))):
    own(db,Assessment,body.assessment_id,user.organization_id)
    obj=TestCheck(organization_id=user.organization_id,**body.model_dump(),updated_by=user.subject)
    db.add(obj);db.flush();record(db,user,"test_check.created","test_check",obj.id);db.commit();db.refresh(obj);return obj

@router.patch("/checks/{check_id}")
def update_check(check_id:UUID,body:TestCheckUpdate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","program_manager"))):
    obj=own(db,TestCheck,check_id,user.organization_id);obj.status=body.status;obj.evidence_reference=body.evidence_reference;obj.assessor_note=body.assessor_note;obj.updated_by=user.subject;obj.updated_at=datetime.now(timezone.utc)
    record(db,user,"test_check.updated","test_check",obj.id,{"status":obj.status});db.commit();return obj

@router.post("/scans",status_code=202)
def create_scan(body:ScanCreate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","scanner_operator"))):
    asset,assessment,authorization=active_authorization(db,user.organization_id,body.asset_id)
    if body.kind in {"zap_baseline","web_posture","sqlmap","metasploit_http_title"} and not asset.web_url: raise HTTPException(422,"Set an HTTP(S) URL on this asset before requesting this web scan")
    hydra_fields=body.hydra_service or body.hydra_username or body.hydra_password
    hash_fields=body.hash_evidence_id or body.wordlist_evidence_id or body.hash_mode
    if body.kind in {"john_audit","hashcat_audit"} and hydra_fields: raise HTTPException(422,"Hydra credentials are only accepted by its single-account workflow")
    if body.kind=="hydra_single_login" and hash_fields: raise HTTPException(422,"Hash inputs are only accepted by offline password audits")
    options={}
    if body.kind in {"john_audit","hashcat_audit"}:
        if not body.hash_evidence_id or not body.wordlist_evidence_id: raise HTTPException(422,"Select encrypted hash input and wordlist evidence")
        hashes=own(db,Evidence,body.hash_evidence_id,user.organization_id);wordlist=own(db,Evidence,body.wordlist_evidence_id,user.organization_id)
        if hashes.id==wordlist.id: raise HTTPException(422,"Choose distinct hash input and wordlist evidence")
        if hashes.assessment_id!=assessment.id or wordlist.assessment_id!=assessment.id: raise HTTPException(422,"Hash input and wordlist must belong to the authorized assessment")
        if hashes.size_bytes>2_000_000 or wordlist.size_bytes>20_000_000: raise HTTPException(413,"Hash input is limited to 2 MB and wordlists to 20 MB")
        if body.kind=="hashcat_audit" and not body.hash_mode: raise HTTPException(422,"Select a supported Hashcat hash mode")
        options={"hash_evidence_id":str(hashes.id),"wordlist_evidence_id":str(wordlist.id),"hash_mode":body.hash_mode}
    elif body.kind=="hydra_single_login":
        if not body.hydra_service or not body.hydra_username or not body.hydra_password: raise HTTPException(422,"Select a service and provide one authorized test account")
        options={"hydra_service":body.hydra_service}
        credential_payload=json.dumps({"username":body.hydra_username,"password":body.hydra_password}).encode("utf-8")
    elif body.hash_evidence_id or body.wordlist_evidence_id or body.hash_mode or body.hydra_service or body.hydra_username or body.hydra_password:
        raise HTTPException(422,"Options do not match the selected tool workflow")
    in_flight=db.scalar(select(ScanJob.id).where(ScanJob.organization_id==user.organization_id,ScanJob.asset_id==asset.id,ScanJob.status.in_(["queued","running"])).limit(1))
    if in_flight: raise HTTPException(429,"A scan is already queued or running for this asset")
    recent=db.scalar(select(ScanJob.id).where(ScanJob.organization_id==user.organization_id,ScanJob.asset_id==asset.id,ScanJob.created_at>=datetime.now(timezone.utc)-timedelta(seconds=30)).limit(1))
    if recent: raise HTTPException(429,"Wait 30 seconds between scan requests for one asset")
    if body.kind=="hydra_single_login": secret_key,_=put_encrypted(credential_payload,"application/json")
    job=ScanJob(organization_id=user.organization_id,assessment_id=assessment.id,asset_id=asset.id,kind=body.kind,options=options,status="queued",requested_by=user.subject)
    if body.kind=="hydra_single_login": job.xml_object_key=secret_key
    db.add(job);db.flush();record(db,user,"scan.queued","scan_job",job.id,{"kind":body.kind,"asset_id":str(asset.id),"authorization_id":str(authorization.id)});db.commit();db.refresh(job)
    try:
        async_result=celery.send_task("app.workers.tasks.run_scan_job",args=[str(job.id)],queue="scans")
        job.celery_task_id=async_result.id;db.commit()
    except Exception as exc:
        job.status="failed";job.error="Worker queue unavailable";db.commit()
        if job.kind=="hydra_single_login" and job.xml_object_key: delete_encrypted(job.xml_object_key)
        raise HTTPException(503,"Scanner worker queue unavailable") from exc
    return job

@router.get("/scans")
def list_scans(db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    return db.scalars(select(ScanJob).where(ScanJob.organization_id==user.organization_id).order_by(desc(ScanJob.created_at)).limit(250)).all()

@router.get("/scans/{job_id}")
def get_scan(job_id:UUID,db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    return own(db,ScanJob,job_id,user.organization_id)

@router.post("/validations",status_code=201)
def create_validation(body:ValidationCreate,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst"))):
    asset,assessment,_=active_authorization(db,user.organization_id,body.asset_id,check_clock=False)
    finding=own(db,Finding,body.finding_id,user.organization_id)
    if assessment.id!=body.assessment_id or finding.assessment_id!=assessment.id or finding.asset_id!=asset.id: raise HTTPException(422,"Validation finding and asset must belong to the same authorized assessment")
    item=ValidationRequest(organization_id=user.organization_id,assessment_id=assessment.id,finding_id=finding.id,asset_id=asset.id,purpose=body.purpose,procedure_reference=body.procedure_reference,proposed_window=body.proposed_window,status="pending",requester=user.subject)
    db.add(item);db.flush();record(db,user,"validation.requested","validation",item.id,{"finding_id":str(finding.id)});db.commit();db.refresh(item);return item

@router.get("/validations")
def list_validations(db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    return db.scalars(select(ValidationRequest).where(ValidationRequest.organization_id==user.organization_id).order_by(desc(ValidationRequest.created_at))).all()

@router.post("/validations/{validation_id}/decision")
def validation_decision(validation_id:UUID,body:Decision,db:Session=Depends(get_db),user:Principal=Depends(require_roles("validation_approver","program_manager"))):
    item=own(db,ValidationRequest,validation_id,user.organization_id)
    if item.status!="pending": raise HTTPException(409,"Only pending validation requests can be decided")
    if item.requester==user.subject and "admin" not in user.roles: raise HTTPException(403,"Requester cannot approve their own validation")
    active_authorization(db,user.organization_id,item.asset_id,check_clock=False)
    item.status="approved" if body.decision=="approve" else "returned";item.reviewer=user.subject
    record(db,user,f"validation.{item.status}","validation",item.id,{"note":body.note});db.commit();return item

@router.post("/validations/{validation_id}/outcome")
def validation_outcome(validation_id:UUID,outcome:str,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst"))):
    if outcome not in {"confirmed","not_reproducible","inconclusive"}: raise HTTPException(422,"Unsupported outcome")
    item=own(db,ValidationRequest,validation_id,user.organization_id)
    if item.status!="approved": raise HTTPException(409,"Approved validation is required")
    active_authorization(db,user.organization_id,item.asset_id)
    item.outcome=outcome;item.status="completed";record(db,user,"validation.outcome","validation",item.id,{"outcome":outcome});db.commit();return item

@router.get("/cves")
def search_cves(q:str="",limit:int=50,db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    from sqlalchemy import or_
    limit=max(1,min(limit,100));stmt=select(CVERecord)
    if q: stmt=stmt.where(or_(CVERecord.cve_id.ilike(f"%{q[:80]}%"),CVERecord.description.ilike(f"%{q[:120]}%")))
    return db.scalars(stmt.order_by(desc(CVERecord.modified_at)).limit(limit)).all()

@router.post("/cves/sync",status_code=202)
def queue_cve_sync(user:Principal=Depends(require_roles("program_manager","security_analyst"))):
    task=celery.send_task("app.workers.tasks.sync_nvd_recent",queue="feeds")
    return {"task_id":task.id,"status":"queued"}

@router.post("/evidence",status_code=201)
async def upload_evidence(assessment_id:UUID=Form(...),finding_id:UUID|None=Form(None),source_tool:str=Form("manual"),file:UploadFile=File(...),db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","evidence_custodian"))):
    own(db,Assessment,assessment_id,user.organization_id)
    if finding_id:
        finding=own(db,Finding,finding_id,user.organization_id)
        if finding.assessment_id!=assessment_id: raise HTTPException(422,"Evidence and finding must belong to the same assessment")
    content=await file.read(20*1024*1024+1)
    if not content or len(content)>20*1024*1024: raise HTTPException(413,"Evidence file must be between 1 byte and 20 MB")
    import re
    filename=(file.filename or "evidence.bin").replace("\\","/").split("/")[-1]
    filename=re.sub(r"[^A-Za-z0-9._ -]", "_", filename).strip(" .")[:255] or "evidence.bin"
    analysis=_parse_external_report(source_tool,filename,content)
    content_type=file.content_type or "application/octet-stream"
    object_key,digest=put_encrypted(content,content_type)
    item=Evidence(organization_id=user.organization_id,assessment_id=assessment_id,finding_id=finding_id,object_key=object_key,filename=filename,content_type=content_type,size_bytes=len(content),sha256=digest,encrypted=True,source_tool=source_tool,analysis=analysis,uploaded_by=user.subject)
    db.add(item);db.flush();record(db,user,"evidence.uploaded","evidence",item.id,{"sha256":digest,"size_bytes":len(content)});db.commit();db.refresh(item)
    record(db,user,"evidence.imported","evidence",item.id,{"source_tool":source_tool,"format":analysis.get("format")});db.commit()
    return {"id":item.id,"filename":item.filename,"sha256":item.sha256,"size_bytes":item.size_bytes,"encrypted":item.encrypted,"source_tool":item.source_tool,"analysis":item.analysis,"created_at":item.created_at}

@router.get("/evidence")
def list_evidence(assessment_id:UUID|None=None,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","scanner_operator","evidence_custodian","auditor","program_manager"))):
    stmt=select(Evidence).where(Evidence.organization_id==user.organization_id)
    if assessment_id: stmt=stmt.where(Evidence.assessment_id==assessment_id)
    return db.scalars(stmt.order_by(desc(Evidence.created_at)).limit(1000)).all()

@router.get("/evidence/{evidence_id}/download")
def download_evidence(evidence_id:UUID,db:Session=Depends(get_db),user:Principal=Depends(require_roles("security_analyst","evidence_custodian","auditor","program_manager"))):
    import hashlib
    item=own(db,Evidence,evidence_id,user.organization_id);content=get_decrypted(item.object_key)
    if hashlib.sha256(content).hexdigest()!=item.sha256: raise HTTPException(503,"Evidence integrity check failed")
    record(db,user,"evidence.downloaded","evidence",item.id,{"sha256":item.sha256});db.commit()
    safe_name=item.filename.replace('"',"")
    return Response(content,media_type=item.content_type,headers={"Content-Disposition":f'attachment; filename="{safe_name}"',"X-Content-SHA256":item.sha256,"Cache-Control":"no-store"})

@router.get("/reports/{assessment_id}.md")
def assessment_report(assessment_id:UUID,db:Session=Depends(get_db),user:Principal=Depends(current_principal)):
    assessment=own(db,Assessment,assessment_id,user.organization_id)
    assets=db.scalars(select(Asset).where(Asset.organization_id==user.organization_id,Asset.assessment_id==assessment.id)).all()
    findings=db.scalars(select(Finding).where(Finding.organization_id==user.organization_id,Finding.assessment_id==assessment.id)).all()
    approvals=db.scalars(select(Authorization).where(Authorization.organization_id==user.organization_id,Authorization.assessment_id==assessment.id)).all()
    lines=[f"# Security assessment report: {assessment.name}","",f"- Unit: {assessment.unit}",f"- Owner: {assessment.owner}",f"- Status: {assessment.status}",f"- Period: {assessment.start_date} to {assessment.end_date}","", "## Authorized scope"]
    lines.extend(f"- {a.name}: {a.target} ({a.asset_type}; {a.environment})" for a in assets)
    lines += ["","## Authorizations"]
    lines.extend(f"- {a.authority_reference}: {a.status}; targets: {', '.join(a.target_allowlist)}; expiry: {a.end_date}" for a in approvals)
    lines += ["","## Findings"]
    for f in findings:
        lines += [f"### {f.title}",f"- Severity: {f.severity}; CVSS base: {f.cvss_base if f.cvss_base is not None else 'not scored'}; business impact: {f.business_impact}",f"- CVE: {f.cve_id or 'not assigned'}; status: {f.status}; remediation owner: {f.remediation_owner}",f"- Evidence references: {', '.join(f.evidence_refs) or 'none'}","",f.summary or "No summary provided.",""]
    lines += ["> Handle this report under the agency's approved information classification, retention, and distribution rules."]
    return Response("\n".join(lines),media_type="text/markdown",headers={"Content-Disposition":f'attachment; filename="assessment-{assessment.id}.md"'})

@router.get("/audit")
def audit_events(limit:int=200,db:Session=Depends(get_db),user:Principal=Depends(require_roles("auditor","program_manager"))):
    return db.scalars(select(AuditEvent).where(AuditEvent.organization_id==user.organization_id).order_by(desc(AuditEvent.created_at)).limit(max(1,min(limit,1000)))).all()


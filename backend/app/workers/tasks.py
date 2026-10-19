import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID
from urllib.parse import urlparse
import httpx
from defusedxml import ElementTree as ET
from celery.utils.log import get_task_logger
from sqlalchemy import select
from app.config import settings
from app.db import SessionLocal
from app.models import Assessment, Asset, Authorization, CVERecord, Evidence, ScanJob
from app.services.scope import active_authorization
from app.services.object_store import put_encrypted,get_decrypted,delete_encrypted
from app.workers.celery_app import celery

log=get_task_logger(__name__)

def _resolved_ips(host:str)->list[str]:
    try: addresses=[ipaddress.ip_address(host)]
    except ValueError: pass
    else: return [addresses[0].compressed]
    import socket
    addresses=[]
    for item in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM):
        ip=ipaddress.ip_address(item[4][0])
        if not any((ip.is_loopback,ip.is_link_local,ip.is_multicast,ip.is_unspecified,ip.is_reserved)) and ip not in addresses: addresses.append(ip)
    if not addresses: raise RuntimeError("Target resolved to no permitted addresses (loopback, link-local, multicast, unspecified, and reserved addresses are blocked)")
    return [ip.compressed for ip in addresses[:4]]

def _parse_nmap(xml_bytes:bytes)->dict:
    xml_bytes=re.sub(rb"<!DOCTYPE[^>]*(?:\[[\s\S]*?\]\s*)?>",b"",xml_bytes,count=1)
    root=ET.fromstring(xml_bytes)
    if root.tag!="nmaprun": raise ValueError("Not an Nmap XML document")
    hosts=[]
    for host in root.findall("host"):
        address=next((x.get("addr") for x in host.findall("address") if x.get("addrtype") in {"ipv4","ipv6"}),None)
        status=host.find("status")
        ports=[]
        for port in host.findall("./ports/port"):
            state=port.find("state");service=port.find("service")
            ports.append({"protocol":port.get("protocol"),"port":int(port.get("portid","0")),"state":state.get("state") if state is not None else "unknown",
                "service":service.get("name") if service is not None else None,"product":service.get("product") if service is not None else None,
                "version":service.get("version") if service is not None else None,"cpe":[c.text for c in service.findall("cpe") if c.text] if service is not None else []})
        hosts.append({"address":address,"status":status.get("state") if status is not None else "unknown","ports":ports})
    return {"nmap_version":root.get("version"),"hosts":hosts}

def _run_nmap(target_ip:str)->bytes:
    args=["nmap","-n","-Pn","-sT","-sV","--version-light","--top-ports","100","--max-rate",str(max(1,min(settings.nmap_max_rate,50))),"--max-retries","1","--host-timeout","120s","--reason","-oX","-",target_ip]
    completed=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=150,check=False)
    if completed.returncode not in (0,1): raise RuntimeError("Nmap failed: "+completed.stderr.decode("utf-8","replace")[-1000:])
    if len(completed.stdout)>8_000_000: raise RuntimeError("Nmap XML exceeded the configured result limit")
    return completed.stdout

def _zap_baseline(asset:Asset)->dict:
    if not settings.zap_api_key: raise RuntimeError("ZAP API key is not configured")
    from zapv2 import ZAPv2
    zap=ZAPv2(apikey=settings.zap_api_key,proxies={"http":settings.zap_api_url,"https":settings.zap_api_url})
    from urllib.parse import urlparse
    parsed=urlparse(asset.web_url)
    host=(parsed.hostname or "").lower().rstrip(".")
    if host!=asset.target.lower().rstrip(".") or parsed.scheme not in {"https","http"} or parsed.username or parsed.password:
        raise RuntimeError("Asset URL does not match its exact approved hostname")
    regex=r"^https?://"+re.escape(host)+r"(?::\d+)?(?:/.*)?$"
    context=f"fieldnote-{asset.id}"
    try: zap.context.new_context(context)
    except Exception: pass
    zap.context.include_in_context(context,regex)
    zap.spider.set_option_max_depth(3);zap.spider.set_option_max_duration(2);zap.spider.set_option_max_children(50)
    scan_id=zap.spider.scan(asset.web_url,contextname=context,subtreeonly=True)
    deadline=time.monotonic()+120
    while time.monotonic()<deadline:
        if int(zap.spider.status(scan_id))>=100: break
        time.sleep(2)
    else: raise TimeoutError("ZAP spider exceeded 120 seconds")
    passive_deadline=time.monotonic()+90
    while time.monotonic()<passive_deadline:
        if int(zap.pscan.records_to_scan)==0: break
        time.sleep(2)
    alerts=zap.core.alerts(baseurl=asset.web_url)
    safe=[{"name":a.get("name"),"risk":a.get("risk"),"confidence":a.get("confidence"),"url":a.get("url"),"cweid":a.get("cweid"),"description":(a.get("description") or "")[:2000]} for a in alerts[:500]]
    zap.context.remove_context(context)
    return {"zap_version":zap.core.version,"target":asset.web_url,"mode":"passive_baseline","alerts":safe,"alert_count":len(safe)}

def _web_posture(asset:Asset)->dict:
    """Low-impact web configuration checks using one GET and one OPTIONS request."""
    from urllib.parse import urljoin, urlparse
    parsed=urlparse(asset.web_url or "")
    host=(parsed.hostname or "").lower().rstrip(".")
    if host!=asset.target.lower().rstrip(".") or parsed.scheme not in {"https","http"} or parsed.username or parsed.password:
        raise RuntimeError("Asset URL must use HTTP(S), contain no credentials, and match its exact approved hostname")
    if parsed.port and not (1<=parsed.port<=65535): raise RuntimeError("Asset URL port is invalid")
    _resolved_ips(host)
    checks=[];response_data={"url":asset.web_url,"status":None,"final_url":None,"headers":{},"cookies":[]};request_error=None
    try:
        with httpx.Client(timeout=10,follow_redirects=False,verify=True,trust_env=False,headers={"User-Agent":"Fieldnote-Security-Posture/1.0","Accept":"text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5"}) as client:
            current=asset.web_url
            for _ in range(4):
                with client.stream("GET",current) as response:
                    safe_header_names={"strict-transport-security","content-security-policy","x-content-type-options","x-frame-options","referrer-policy","permissions-policy"}
                    response_data.update({"status":response.status_code,"final_url":str(response.url),"headers":{k.lower():v for k,v in response.headers.items() if k.lower() in safe_header_names}})
                    safe_cookies=[]
                    for cookie in response.headers.get_list("set-cookie")[:20]:
                        parts=[part.strip() for part in cookie.split(";")]
                        attrs={part.split("=",1)[0].strip().lower():part.split("=",1)[1].strip() if "=" in part else True for part in parts[1:] if part}
                        safe_cookies.append({"secure":"secure" in attrs,"httponly":"httponly" in attrs,"samesite":attrs.get("samesite") if isinstance(attrs.get("samesite"),str) else None})
                    response_data["cookies"]=safe_cookies
                    if response.status_code not in {301,302,303,307,308}: break
                    location=response.headers.get("location")
                    if not location: break
                    next_url=urljoin(str(response.url),location);next_parsed=urlparse(next_url)
                    if (next_parsed.hostname or "").lower().rstrip(".")!=host or next_parsed.scheme not in {"http","https"}:
                        response_data["redirect_out_of_scope"]=next_url
                        break
                    current=next_url
            try:
                options=client.options(asset.web_url)
                response_data["options_status"]=options.status_code
                response_data["allow_header"]=options.headers.get("allow")
                response_data["access_control_allow_methods"]=options.headers.get("access-control-allow-methods")
            except httpx.HTTPError as exc:
                response_data["options_error"]=type(exc).__name__
    except httpx.HTTPError as exc:
        request_error=type(exc).__name__
    headers=response_data["headers"]
    def add(check_id,label,status,severity,evidence,recommendation):
        checks.append({"id":check_id,"name":label,"status":status,"severity":severity,"evidence":evidence,"recommendation":recommendation})
    if request_error:
        add("web_reachability","HTTPS certificate and page response","not_assessed","unknown",f"Request failed: {request_error}","Confirm the approved URL and service availability; review certificate or network errors from an approved location.")
    else:
        secure=urlparse(response_data.get("final_url") or asset.web_url).scheme=="https"
        add("https_transport","HTTPS transport","pass" if secure else "review","low" if not secure else "info",f"Final page URL uses {urlparse(response_data.get('final_url') or asset.web_url).scheme.upper()} (HTTP {response_data['status']}).","Use HTTPS for sensitive web services and redirect HTTP to HTTPS where appropriate.")
        for key,label,acceptable,recommendation in [
            ("strict-transport-security","HTTP Strict Transport Security (HSTS)",bool(headers.get("strict-transport-security")),"For HTTPS services, consider an HSTS policy appropriate to the domain and deployment."),
            ("content-security-policy","Content Security Policy (CSP)",bool(headers.get("content-security-policy")),"Set a CSP suited to the application; test it to avoid breaking required content."),
            ("x-content-type-options","Content type sniffing protection",headers.get("x-content-type-options","").lower()=="nosniff","Set X-Content-Type-Options: nosniff."),
            ("frame-protection","Clickjacking protection",bool(headers.get("content-security-policy") and "frame-ancestors" in headers.get("content-security-policy","")) or headers.get("x-frame-options","").lower() in {"deny","sameorigin"},"Set CSP frame-ancestors or X-Frame-Options according to intended embedding."),
            ("referrer-policy","Referrer-Policy",bool(headers.get("referrer-policy")),"Set a Referrer-Policy that limits unintended URL referrer disclosure."),
            ("permissions-policy","Permissions-Policy",bool(headers.get("permissions-policy")),"Review whether a Permissions-Policy is appropriate for the browser features used."),
        ]:
            status=("not_applicable" if key=="strict-transport-security" and not secure else ("pass" if acceptable else ("review" if key in {"strict-transport-security","content-security-policy","x-content-type-options","frame-protection"} else "informational")))
            evidence=f"{key}: {headers.get(key,'not present')}"+(" (only assessed on HTTPS)" if key=="strict-transport-security" and not secure else "")
            add(key,label,status,"low" if status=="review" else "info",evidence,recommendation)
        cookies=response_data["cookies"]
        if not cookies:
            add("cookie_flags","Cookie security attributes","not_observed","info","The initial response set no cookies.","Review cookie attributes during an approved authenticated session if the application uses session cookies.")
        else:
            for index,cookie in enumerate(cookies):
                missing=[]
                if not cookie["secure"]: missing.append("Secure")
                if not cookie["httponly"]: missing.append("HttpOnly")
                if not cookie["samesite"]: missing.append("SameSite")
                add(f"cookie_{index+1}","Cookie security attributes","review" if missing else "pass","low" if missing else "info",f"Cookie {index+1}: "+(", ".join("missing "+x for x in missing) if missing else "Secure, HttpOnly, and SameSite attributes observed."),"Review whether Secure, HttpOnly, and an appropriate SameSite value are needed for this cookie.")
        allow=response_data.get("allow_header") or response_data.get("access_control_allow_methods")
        risky=[method for method in re.split(r"[,\s]+",allow.upper()) if method in {"TRACE","PUT","DELETE","CONNECT"}] if allow else []
        add("http_methods","HTTP method advertisement","review" if risky else "informational","info",f"OPTIONS status {response_data.get('options_status','unavailable')}; advertised methods: {allow or 'not reported'}"+(f"; review {', '.join(risky)}" if risky else ""),"Confirm advertised methods are expected; an Allow header alone does not prove that a method is enabled or exploitable.")
    return {"scanner":"web_posture","target":asset.web_url,"mode":"low_impact_http_configuration","probes":["GET (same-host redirects only; up to four requests)","OPTIONS"],"response":response_data,"checks":checks,"limitations":["Unauthenticated root-page checks only; authenticated routes and role-based access are not tested.","Missing headers and advertised methods are configuration observations, not proof of exploitability.","No payloads, state-changing requests, crawling, or exploit attempts are sent."]}

def _run_sqlmap_baseline(asset:Asset)->dict:
    """Run a fixed low-risk detection profile against one registered web URL."""
    parsed=urlparse(asset.web_url or "")
    host=(parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http","https"} or parsed.username or parsed.password or host!=asset.target.lower().rstrip("."):
        raise RuntimeError("sqlmap requires an HTTP(S) URL matching the registered asset hostname")
    _resolved_ips(host)
    with tempfile.TemporaryDirectory(prefix="fieldnote-sqlmap-") as output_dir:
        args=["sqlmap","-u",asset.web_url,"--batch","--smart","--level=1","--risk=1","--threads=1","--delay=1","--timeout=8","--retries=0","--technique=BEU","--ignore-redirects","--output-dir",output_dir,"--flush-session","--disable-coloring"]
        log_path=f"{output_dir}/runner.log"
        try:
            with open(log_path,"wb") as output:
                completed=subprocess.run(args,stdout=output,stderr=subprocess.STDOUT,timeout=180,check=False,cwd=output_dir,env={**os.environ,"HOME":output_dir,"PYTHONUNBUFFERED":"1"})
            exit_code=completed.returncode;timed_out=False
        except subprocess.TimeoutExpired:
            exit_code=None;timed_out=True
        try:
            with open(log_path,"rb") as output: raw=output.read(2_000_000)
        except OSError:
            raw=b""
    output=raw.decode("utf-8","replace")
    markers=("appears to be injectable","might be injectable","is vulnerable","parameter '" )
    signals=[]
    for line in output.splitlines():
        if any(marker in line.lower() for marker in markers):
            signal=re.sub(r"([?&][^=\s]+)=([^&\s]*)",r"\1=[REDACTED]"," ".join(line.split()))[:500]
            if signal not in signals: signals.append(signal)
            if len(signals)>=20: break
    stored=raw or b"No sqlmap output was produced."
    object_key,digest=put_encrypted(stored,"text/plain")
    summary={"scanner":"sqlmap","target":asset.target,"profile":"authorized-low-impact-detection","status":"timed_out" if timed_out else "completed","exit_code":exit_code,"candidate_signals":signals,"candidate_signal_count":len(signals),"evidence_sha256":digest,"evidence_object":object_key,"evidence_size_bytes":len(stored),"limitations":["Fixed level 1 / risk 1 detection profile; no database enumeration, data extraction, file access, shell, or OS takeover options are enabled.","Signals are scanner leads, not confirmed vulnerabilities; verify manually within the approved scope.","Only the registered asset URL is used; arbitrary parameters and request bodies are not accepted."]}
    return summary

def _run_metasploit_http_title(asset:Asset)->dict:
    """Run one non-exploit HTTP title scanner module against the registered URL."""
    parsed=urlparse(asset.web_url or "");host=(parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http","https"} or parsed.username or parsed.password or host!=asset.target.lower().rstrip("."):
        raise RuntimeError("Metasploit requires an HTTP(S) URL matching the registered asset hostname")
    port=parsed.port or (443 if parsed.scheme=="https" else 80)
    network_ip=_resolved_ips(host)[0]
    with tempfile.TemporaryDirectory(prefix="fieldnote-msf-") as work:
        resource=os.path.join(work,"scan.rc");log_path=os.path.join(work,"output.txt")
        commands=["use auxiliary/scanner/http/title",f"set RHOSTS {network_ip}",f"set VHOST {host}",f"set RPORT {port}",f"set SSL {'true' if parsed.scheme=='https' else 'false'}","set TARGETURI /","set THREADS 1","run","exit -y"]
        with open(resource,"w",encoding="utf-8") as script: script.write("\n".join(commands)+"\n")
        with open(log_path,"wb") as output:
            try: completed=subprocess.run(["msfconsole","-q","-r",resource],stdout=output,stderr=subprocess.STDOUT,timeout=90,check=False,cwd=work)
            except subprocess.TimeoutExpired: raise RuntimeError("Metasploit HTTP title scan exceeded 90 seconds")
        with open(log_path,"rb") as output: text=output.read(1_000_000).decode("utf-8","replace")
        if completed.returncode not in (0,1): raise RuntimeError("Metasploit HTTP title scanner exited unsuccessfully")
    observations=[]
    for line in text.splitlines():
        clean=" ".join(line.split())
        if "[+]" in clean and f":{port}" in clean: observations.append(clean[:500])
        if len(observations)>=20: break
    summary={"scanner":"metasploit","module":"auxiliary/scanner/http/title","target":asset.web_url,"status":"completed","observations":observations,"observation_count":len(observations),"limitations":["Only the fixed HTTP title auxiliary scanner is run; no exploit, payload, or arbitrary module is accepted.","Observations require assessor validation."]}
    raw=json.dumps(summary,ensure_ascii=False).encode("utf-8");key,digest=put_encrypted(raw,"application/json")
    summary.update({"evidence_object":key,"evidence_sha256":digest,"evidence_size_bytes":len(raw)})
    return summary

def _run_password_audit(tool:str,options:dict,db,assessment:Assessment,job:ScanJob)->dict:
    hash_record=db.get(Evidence,UUID(options["hash_evidence_id"]))
    word_record=db.get(Evidence,UUID(options["wordlist_evidence_id"]))
    if not hash_record or not word_record or hash_record.assessment_id!=assessment.id or word_record.assessment_id!=assessment.id:
        raise RuntimeError("Hash and wordlist evidence must belong to the authorized assessment")
    hash_bytes=get_decrypted(hash_record.object_key);word_bytes=get_decrypted(word_record.object_key)
    if len(hash_bytes)>2_000_000 or len(word_bytes)>50_000_000: raise RuntimeError("Hash input or wordlist exceeds its size limit")
    with tempfile.TemporaryDirectory(prefix=f"fieldnote-{tool}-") as work:
        hash_path=os.path.join(work,"hashes.txt");word_path=os.path.join(work,"wordlist.txt");pot_path=os.path.join(work,"recovered.pot")
        with open(hash_path,"wb") as f: f.write(hash_bytes)
        with open(word_path,"wb") as f: f.write(word_bytes)
        if tool=="john":
            try: subprocess.run(["john",f"--wordlist={word_path}",f"--pot={pot_path}","--max-run-time=120",hash_path],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=125,check=False,cwd=work)
            except subprocess.TimeoutExpired: pass
            try: recovered=sum(1 for line in open(pot_path,"rb") if line.strip())
            except OSError: recovered=0
        else:
            mode=options.get("hash_mode")
            if mode not in {"0","1000","1800","3200"}: raise RuntimeError("Unsupported Hashcat mode")
            try: subprocess.run(["hashcat","--quiet","--potfile-path",pot_path,"--runtime=120","--status","-m",mode,"-a","0",hash_path,word_path],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=125,check=False,cwd=work)
            except subprocess.TimeoutExpired: pass
            try: recovered=sum(1 for line in open(pot_path,"rb") if line.strip())
            except OSError: recovered=0
    summary={"scanner":tool,"status":"completed","hash_count":sum(1 for line in hash_bytes.splitlines() if line.strip()),"recovered_count":recovered,"secrets_redacted":True,"profile":"wordlist-audit-120s","limitations":["Offline audit only; the supplied encrypted hash and wordlist evidence are used.","Recovered secret values are never returned or persisted in the result.","A 120-second runtime limit applies; no brute-force or mask modes are enabled."]}
    raw=json.dumps(summary,ensure_ascii=False).encode("utf-8");key,digest=put_encrypted(raw,"application/json")
    db.add(Evidence(organization_id=job.organization_id,assessment_id=assessment.id,object_key=key,filename=f"{job.id}-{tool}-summary.json",content_type="application/json",size_bytes=len(raw),sha256=digest,encrypted=True,source_tool=tool,analysis={"format":"offline_password_audit_summary","recovered_count":recovered,"secrets_redacted":True},uploaded_by=f"system:{tool}"))
    return summary

def _run_hydra_single_login(asset:Asset,job:ScanJob)->dict:
    key=job.xml_object_key
    if not key: raise RuntimeError("Encrypted one-account test credential is missing")
    try:
        credential=json.loads(get_decrypted(key).decode("utf-8"))
        service=job.options.get("hydra_service")
        ports={"ssh":22,"ftp":21,"http-get":80,"https-get":443,"smb":445}
        if service not in ports: raise RuntimeError("Unsupported Hydra service")
        target=asset.target;network_ip=_resolved_ips(target)[0]
        with tempfile.TemporaryDirectory(prefix="fieldnote-hydra-") as work:
            user_path=os.path.join(work,"user.txt");password_path=os.path.join(work,"password.txt")
            for path,value in ((user_path,credential["username"]),(password_path,credential["password"])):
                with open(path,"w",encoding="utf-8") as output: output.write(value+"\n")
                os.chmod(path,0o600)
            args=["hydra","-L",user_path,"-P",password_path,"-t","1","-f","-W","3","-w","3","-s",str(ports[service]),network_ip,service]
            try: completed=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=45,check=False,cwd=work)
            except subprocess.TimeoutExpired: raise RuntimeError("Hydra one-account check exceeded 45 seconds")
            # Hydra output includes credentials; inspect in memory only and never log or persist it.
            output=completed.stdout.decode("utf-8","replace")
            found=any("login:" in line.lower() and "password:" in line.lower() for line in output.splitlines())
        summary={"scanner":"hydra","target":target,"service":service,"status":"completed" if completed.returncode in (0,1) else "error","credential_accepted":found,"attempt_limit":1,"secrets_redacted":True,"limitations":["Exactly one supplied username/password pair is tested against the selected service on its standard port.","No credential lists, guessing, retries, or parallel attempts are accepted.","The credential is encrypted at rest and its encrypted temporary object is deleted after the run."]}
        raw=json.dumps(summary,ensure_ascii=False).encode("utf-8");obj,digest=put_encrypted(raw,"application/json")
        summary.update({"evidence_object":obj,"evidence_sha256":digest,"evidence_size_bytes":len(raw)})
        return summary
    finally:
        delete_encrypted(key)

@celery.task(name="app.workers.tasks.run_scan_job",bind=True,max_retries=0)
def run_scan_job(self,job_id:str):
    with SessionLocal() as db:
        job=db.get(ScanJob,UUID(job_id))
        if not job:return {"error":"scan job missing"}
        job.status="running";job.started_at=datetime.now(timezone.utc);db.commit()
        try:
            asset,assessment,_=active_authorization(db,job.organization_id,job.asset_id)
            if assessment.id!=job.assessment_id: raise RuntimeError("Assessment binding changed")
            if job.kind=="nmap":
                hosts=[];xml_objects=[];xml_hashes=[]
                for ip in _resolved_ips(asset.target):
                    xml=_run_nmap(ip);object_key,digest=put_encrypted(xml,"application/xml");xml_objects.append(object_key);xml_hashes.append(digest);hosts.extend(_parse_nmap(xml)["hosts"])
                    db.add(Evidence(organization_id=job.organization_id,assessment_id=assessment.id,object_key=object_key,filename=f"{job.id}-{ip}.xml",content_type="application/xml",size_bytes=len(xml),sha256=digest,encrypted=True,uploaded_by="system:nmap"))
                job.xml_object_keys=xml_objects;job.xml_object_key=xml_objects[0] if xml_objects else None
                candidates={}
                for host in hosts:
                    for port in host["ports"]:
                        for cpe in port["cpe"]:
                            matches=db.scalars(select(CVERecord).where(CVERecord.cpes.contains([cpe])).limit(20)).all()
                            for cve in matches:candidates[cve.cve_id]={"cve_id":cve.cve_id,"cvss_base":cve.cvss_base,"severity":cve.severity,"cpe":cpe,"port":port["port"],"confidence":"candidate — verify product/version and affected range"}
                summary={"scanner":"nmap","target":asset.target,"hosts":hosts,"nvd_cve_candidates":list(candidates.values())[:100],"raw_xml_objects":xml_objects,"raw_xml_sha256":xml_hashes}
            elif job.kind=="zap_baseline":
                summary=_zap_baseline(asset)
                raw=json.dumps(summary,ensure_ascii=False).encode("utf-8");object_key,digest=put_encrypted(raw,"application/json")
                job.xml_object_key=object_key;job.xml_object_keys=[object_key]
                db.add(Evidence(organization_id=job.organization_id,assessment_id=assessment.id,object_key=object_key,filename=f"{job.id}-zap-baseline.json",content_type="application/json",size_bytes=len(raw),sha256=digest,encrypted=True,uploaded_by="system:zap"))
            elif job.kind=="web_posture":
                summary=_web_posture(asset)
                raw=json.dumps(summary,ensure_ascii=False).encode("utf-8");object_key,digest=put_encrypted(raw,"application/json")
                job.xml_object_key=object_key;job.xml_object_keys=[object_key]
                db.add(Evidence(organization_id=job.organization_id,assessment_id=assessment.id,object_key=object_key,filename=f"{job.id}-web-posture.json",content_type="application/json",size_bytes=len(raw),sha256=digest,encrypted=True,uploaded_by="system:web-posture"))
            elif job.kind=="sqlmap":
                summary=_run_sqlmap_baseline(asset)
                db.add(Evidence(organization_id=job.organization_id,assessment_id=assessment.id,object_key=summary["evidence_object"],filename=f"{job.id}-sqlmap-output.txt",content_type="text/plain",size_bytes=summary["evidence_size_bytes"],sha256=summary["evidence_sha256"],encrypted=True,source_tool="sqlmap",analysis={"format":"sqlmap_low_impact_detection","candidate_signal_count":summary["candidate_signal_count"]},uploaded_by="system:sqlmap"))
            elif job.kind=="metasploit_http_title":
                summary=_run_metasploit_http_title(asset)
                db.add(Evidence(organization_id=job.organization_id,assessment_id=assessment.id,object_key=summary["evidence_object"],filename=f"{job.id}-metasploit-summary.json",content_type="application/json",size_bytes=summary["evidence_size_bytes"],sha256=summary["evidence_sha256"],encrypted=True,source_tool="metasploit",analysis={"format":"metasploit_http_title"},uploaded_by="system:metasploit"))
            elif job.kind in {"john_audit","hashcat_audit"}:
                summary=_run_password_audit("john" if job.kind=="john_audit" else "hashcat",job.options or {},db,assessment,job)
            elif job.kind=="hydra_single_login":
                summary=_run_hydra_single_login(asset,job)
                job.xml_object_key=summary["evidence_object"];job.xml_object_keys=[job.xml_object_key]
                db.add(Evidence(organization_id=job.organization_id,assessment_id=assessment.id,object_key=job.xml_object_key,filename=f"{job.id}-hydra-summary.json",content_type="application/json",size_bytes=summary["evidence_size_bytes"],sha256=summary["evidence_sha256"],encrypted=True,source_tool="hydra",analysis={"format":"hydra_single_login","credential_accepted":summary["credential_accepted"],"secrets_redacted":True},uploaded_by="system:hydra"))
            else: raise RuntimeError("Unsupported scan kind")
            job.result_summary=summary
            failed=(job.kind=="sqlmap" and summary.get("status")=="timed_out") or (job.kind=="hydra_single_login" and summary.get("status")=="error")
            job.status="failed" if failed else "completed";job.error="Tool execution did not complete within its supported profile." if failed else None;job.completed_at=datetime.now(timezone.utc)
        except Exception as exc:
            log.exception("scanner job failed",extra={"job_id":job_id})
            if job.kind=="hydra_single_login" and job.xml_object_key: delete_encrypted(job.xml_object_key)
            job.status="failed";job.error=str(exc)[:2000];job.completed_at=datetime.now(timezone.utc)
        db.commit()
        return {"job_id":job_id,"status":job.status}

@celery.task(name="app.workers.tasks.sync_nvd_recent",bind=True,max_retries=3,rate_limit="1/m",autoretry_for=(httpx.HTTPError,),retry_backoff=True)
def sync_nvd_recent(self):
    """Incremental NVD CVE feed sync. CVE matches are triage leads, not confirmed findings."""
    now=datetime.now(timezone.utc);start=(now-timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z");end=now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    headers={"apiKey":settings.nvd_api_key} if settings.nvd_api_key else {}
    count=0;start_index=0
    with httpx.Client(timeout=30,headers=headers) as client, SessionLocal() as db:
        while count<5000:
            response=client.get("https://services.nvd.nist.gov/rest/json/cves/2.0",params={"lastModStartDate":start,"lastModEndDate":end,"startIndex":start_index,"resultsPerPage":2000})
            response.raise_for_status();payload=response.json();items=payload.get("vulnerabilities",[])
            if not items:break
            for item in items:
                cve=item["cve"];cve_id=cve["id"]
                descriptions=cve.get("descriptions",[]);description=next((x["value"] for x in descriptions if x.get("lang")=="en"),"")[:8000]
                score=None;severity="unknown";metrics=cve.get("metrics",{})
                for group in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                    if metrics.get(group):
                        data=metrics[group][0].get("cvssData",{});score=data.get("baseScore");severity=(data.get("baseSeverity") or metrics[group][0].get("baseSeverity") or "unknown").lower();break
                cpes=[]
                for config in cve.get("configurations",[]):
                    for node in config.get("nodes",[]):
                        for match in node.get("cpeMatch",[]):
                            if match.get("vulnerable") and match.get("criteria"):cpes.append(match["criteria"])
                def parsedate(value):
                    return datetime.fromisoformat(value.replace("Z","+00:00")) if value else None
                modified=parsedate(cve.get("lastModified"))
                obj=db.get(CVERecord,cve_id)
                values={"description":description,"cvss_base":score,"severity":severity,"cpes":cpes,"published_at":parsedate(cve.get("published")),"modified_at":modified}
                if obj:
                    for key,value in values.items(): setattr(obj,key,value)
                else: db.add(CVERecord(cve_id=cve_id,**values))
                count+=1
            db.commit();start_index+=len(items)
            if start_index>=payload.get("totalResults",0) or len(items)<2000:break
            time.sleep(6 if not settings.nvd_api_key else .7)
    return {"updated":count,"window_start":start,"window_end":end}

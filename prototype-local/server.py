"""Fieldnote local program console. Python standard library only."""
from __future__ import annotations

import json
import ipaddress
import sqlite3
import socket
import ssl
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "fieldnote.sqlite3"
PORTS = {21:"FTP",22:"SSH",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP submission",993:"IMAPS",995:"POP3S",1433:"Microsoft SQL Server",1521:"Oracle DB",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",8080:"HTTP alternate",8443:"HTTPS alternate"}
LAST_SCAN = {}

def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

@contextmanager
def db_session():
    db = connect()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def initialize():
    with db_session() as db:
        db.execute("CREATE TABLE IF NOT EXISTS app_state (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL, updated_at TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL)")

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send_json(self, value, status=200):
        raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/state":
            with db_session() as db:
                row = db.execute("SELECT payload, updated_at FROM app_state WHERE id=1").fetchone()
            self.send_json({"state": json.loads(row["payload"]) if row else None, "updated_at": row["updated_at"] if row else None})
            return
        if path == "/api/audit":
            with db_session() as db:
                rows = db.execute("SELECT created_at, actor, action, detail FROM audit_log ORDER BY id DESC LIMIT 500").fetchall()
            self.send_json([dict(row) for row in rows])
            return
        if path == "/":
            self.path = "/index.html"
        super().do_GET()

    def do_PUT(self):
        if urlparse(self.path).path != "/api/state":
            self.send_json({"error": "Not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > 2_000_000:
                self.send_json({"error": "Request size must be under 2 MB"}, 413)
                return
            data = json.loads(self.rfile.read(length))
            state = data.get("state")
            event = data.get("event", {})
            if not isinstance(state, dict) or not isinstance(state.get("engagements"), list):
                self.send_json({"error": "Invalid program state"}, 400)
                return
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            encoded = json.dumps(state, ensure_ascii=False)
            with db_session() as db:
                db.execute("INSERT INTO app_state(id,payload,updated_at) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at", (encoded, now))
                action = str(event.get("action", "Program data updated"))[:120]
                detail = str(event.get("detail", ""))[:500]
                actor = str(event.get("actor", "Program coordinator"))[:100]
                db.execute("INSERT INTO audit_log(created_at,actor,action,detail) VALUES(?,?,?,?)", (now, actor, action, detail))
            self.send_json({"ok": True, "updated_at": now})
        except (ValueError, json.JSONDecodeError):
            self.send_json({"error": "Invalid JSON"}, 400)

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/api/scan/dns", "/api/scan/ports", "/api/scan/web"):
            self.send_json({"error": "Not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 2 or length > 16_000:
                self.send_json({"error": "Invalid request size"}, 413)
                return
            request = json.loads(self.rfile.read(length))
            asset, target, error = self.authorized_target(request.get("asset_id"))
            if error:
                self.send_json({"error": error}, 403)
                return
            key = (self.client_address[0], asset["id"], path)
            remaining = 20 - (time.monotonic() - LAST_SCAN.get(key, 0))
            if remaining > 0:
                self.send_json({"error": f"Rate limit: wait {int(remaining)+1} seconds before the next check for this target."}, 429)
                return
            LAST_SCAN[key] = time.monotonic()
            addresses = self.resolve(target)
            if path == "/api/scan/dns":
                result = {"type":"dns", "asset":asset["name"], "target":target, "addresses":addresses, "checked_at":datetime.now(timezone.utc).isoformat(timespec="seconds")}
            elif path == "/api/scan/ports":
                selected = request.get("ports", list(PORTS))
                if not isinstance(selected, list) or len(selected) > 12 or any(type(p) is not int or p not in PORTS for p in selected):
                    self.send_json({"error": "Select up to 12 ports from the approved common-port list."}, 400)
                    return
                opened=[]
                for address in addresses[:4]:
                    for port in selected:
                        family=socket.AF_INET6 if ":" in address else socket.AF_INET
                        sock=socket.socket(family,socket.SOCK_STREAM)
                        sock.settimeout(.35)
                        try:
                            sock.connect((address,port))
                            opened.append({"address":address,"port":port,"service":PORTS[port],"state":"open"})
                        except (OSError,TimeoutError):
                            pass
                        finally:
                            sock.close()
                result={"type":"ports","asset":asset["name"],"target":target,"addresses":addresses,"open_ports":opened,"ports_checked":selected,"checked_at":datetime.now(timezone.utc).isoformat(timespec="seconds")}
            else:
                result=self.check_web(asset["name"],target,addresses)
            self.record_scan(result)
            self.send_json({"result":result})
        except (ValueError, json.JSONDecodeError):
            self.send_json({"error":"Invalid JSON"},400)
        except (OSError, socket.gaierror, URLError, ssl.SSLError) as exc:
            self.send_json({"error":f"Check failed: {str(exc)[:240]}"},502)

    def authorized_target(self, asset_id):
        """Fail closed unless an exact target is bound to a current written approval."""
        if not isinstance(asset_id,str):
            return None,None,"Choose a registered asset."
        with db_session() as db:
            row=db.execute("SELECT payload FROM app_state WHERE id=1").fetchone()
        if not row:
            return None,None,"Program database is empty."
        data=json.loads(row["payload"])
        asset=next((x for x in data.get("assets",[]) if x.get("id")==asset_id),None)
        if not asset:
            return None,None,"Asset is not in the register."
        target=(asset.get("target") or "").strip()
        if not target or any(x in target for x in ("*",",","/"," ")) and "://" not in target:
            return None,None,"Register one exact hostname or IP address for this asset first."
        parsed=urlparse(target if "://" in target else "//"+target)
        host=parsed.hostname
        try:
            port=parsed.port
        except ValueError:
            return None,None,"Target format is invalid."
        if not host or port is not None or parsed.username or parsed.password or parsed.path not in ("","/") or parsed.query or parsed.fragment:
            return None,None,"Target must be a single hostname or IP, without port, credentials, paths, or query strings."
        target=host
        local_now=datetime.now(ZoneInfo("Africa/Harare"))
        today=local_now.date().isoformat()
        engagement=next((x for x in data.get("engagements",[]) if x.get("id")==asset.get("assessment")),None)
        if not engagement or engagement.get("status")!="Active":
            return None,None,"The asset must be linked to an active assessment."
        if not engagement.get("start") or not engagement.get("end") or not engagement["start"]<=today<=engagement["end"]:
            return None,None,"The current date is outside the assessment window."
        approvals=[x for x in data.get("authorizations",[]) if x.get("engagementId")==engagement.get("id") and x.get("status")=="Approved"]
        approval=next((x for x in approvals if x.get("expiry") and x["expiry"]>=today),None)
        if not approval:
            return None,None,"No current approved authorization is recorded for this assessment."
        if not approval.get("windowStart") or not approval.get("windowEnd"):
            return None,None,"Authorization has no structured daily test window. Record its start and end times first."
        try:
            start=datetime.strptime(approval["windowStart"],"%H:%M").time()
            end=datetime.strptime(approval["windowEnd"],"%H:%M").time()
        except ValueError:
            return None,None,"Authorization test window is invalid."
        current=local_now.time().replace(tzinfo=None)
        if not start <= current <= end:
            return None,None,"Outside the approved daily testing hours (Africa/Harare)."
        if approval.get("weekdaysOnly",True) and local_now.weekday()>=5:
            return None,None,"Authorization permits weekday testing only."
        approved_scope=(approval.get("scope") or "").lower()
        if target.lower() not in approved_scope:
            return None,None,"The exact registered target is not named in the approved scope. Update the authorization record first."
        return asset,target,None

    @staticmethod
    def resolve(host):
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        items=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
        result=[]
        for item in items:
            address=item[4][0]
            if address not in result:
                result.append(address)
        if not result:
            raise socket.gaierror("No addresses returned")
        return result[:4]

    @staticmethod
    def check_web(asset_name,host,addresses):
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        scheme="https"
        req=Request(f"{scheme}://{host}/",method="HEAD",headers={"User-Agent":"Fieldnote-Authorized-Assessment/1.0","Range":"bytes=0-0"})
        opener=build_opener(NoRedirect)
        try:
            response=opener.open(req,timeout=5)
        except HTTPError as exc:
            response=exc
        headers={k.lower():v for k,v in response.headers.items()}
        missing=[h for h in ("strict-transport-security","content-security-policy","x-content-type-options","referrer-policy") if h not in headers]
        cookies=headers.get("set-cookie","").lower()
        cookie_flags=[]
        if cookies:
            for flag in ("secure","httponly","samesite"):
                if flag not in cookies: cookie_flags.append(flag)
        return {"type":"web","asset":asset_name,"target":host,"addresses":addresses,"scheme":scheme,"http_status":response.status,"server_header":headers.get("server","Not disclosed"),"missing_headers":missing,"cookie_flags_missing":cookie_flags,"redirect_blocked":response.status in (301,302,303,307,308),"checked_at":datetime.now(timezone.utc).isoformat(timespec="seconds")}

    @staticmethod
    def record_scan(result):
        with db_session() as db:
            row=db.execute("SELECT payload FROM app_state WHERE id=1").fetchone()
            if not row: return
            data=json.loads(row["payload"])
            data.setdefault("scanResults",[]).insert(0,result)
            data["scanResults"]=data["scanResults"][:100]
            now=datetime.now(timezone.utc).isoformat(timespec="seconds")
            db.execute("UPDATE app_state SET payload=?,updated_at=? WHERE id=1",(json.dumps(data,ensure_ascii=False),now))
            detail=f"{result['type']} check · {result['asset']} · {result['target']}"
            db.execute("INSERT INTO audit_log(created_at,actor,action,detail) VALUES(?,?,?,?)",(now,"Fieldnote scanner","Authorized check recorded",detail))

if __name__ == "__main__":
    initialize()
    server = ThreadingHTTPServer(("127.0.0.1", 8765), Handler)
    print("Fieldnote running at http://127.0.0.1:8765")
    print("SQLite database: fieldnote.sqlite3")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Fieldnote")
        server.server_close()

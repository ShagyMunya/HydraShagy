# HydraShagy — organizational security assurance

The primary app is a containerized organizational assessment platform. The first local prototype is preserved in [`prototype-local/`](prototype-local/) for reference.

## Stack

- React, TypeScript, Vite, Tailwind CSS
- FastAPI, SQLAlchemy, Alembic, PostgreSQL
- Celery and Redis background workers
- Nmap with machine-readable XML, OWASP ZAP passive baseline integration, and low-impact HTTP security-posture checks
- NVD CVE 2.0 feed synchronization and CPE candidate matching
- Keycloak OIDC, role claims, organization claim, and an MFA claim check
- S3-compatible MinIO evidence storage with AES-256-GCM application-layer encryption
- OpenTelemetry traces/logs, Collector, Loki, Tempo, and Grafana
- Docker Compose

## Local setup

Use Docker Desktop with Compose, Python is not required on the host.

1. Copy `.env.example` to `.env`.
2. Set each local password and generate a 32-byte evidence key:

   ```powershell
   python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
   ```

   Put the output in `EVIDENCE_ENCRYPTION_KEY` in `.env`.

3. Start the stack:

   ```powershell
   docker compose up --build
   ```

4. Open `http://localhost:8080`. Keycloak sign-in is at `http://localhost:8081`.

Development users imported by Keycloak:

- `analyst` / `ChangeMe123!` — analyst, scanner, evidence roles
- `approver` / `ChangeMe123!` — program manager, authorization approver, validation approver, auditor

These credentials and the disabled local MFA requirement are for local development only. Change them or remove the import users before any shared environment. The Keycloak database role also has a fixed local-only password in `compose.yaml` and `infra/postgres-init.sql`.

## Scanner behavior and approval gates

Scanner requests refer to a registered asset ID, not a caller-supplied host. The API and worker each re-check organization ownership, active assessment dates, an approved authorization, exact target membership, authorization expiry, weekday rules, and the Africa/Harare daily test window. Wildcards, URLs, CIDRs, and target lists are rejected as scanner targets. Scan submissions are limited per asset; workers run one scan at a time.

Nmap runs one resolved IP at a time using TCP connect, light service/version detection, the top 100 ports, retry/timeout/rate caps, and `-oX -`. Nmap XML is parsed into structured service, version, CPE, and port records; the raw XML is encrypted and stored as an evidence object. NVD matches are candidate triage leads and require assessor verification. OS fingerprinting and NSE scripts are not enabled.

ZAP uses a bounded spider and passive rules only, in a context restricted to the registered hostname. Active attack mode is not enabled. Controlled exploitation is a reviewer-approved documentation workflow; the app does not launch exploits.

The Web posture scan makes a small number of same-host GET/OPTIONS requests to the asset's configured web URL. It reviews HTTPS use, common security headers, cookies set by the initial response, and advertised HTTP methods. It is unauthenticated and does not crawl, submit forms, send exploit payloads, or change application state; results are configuration observations that require assessor review.

The sqlmap workflow is launched from Tools & review or Recon & scans. It uses only an asset's registered web URL after the API and worker re-check its current authorization. The fixed profile uses level 1, risk 1, one thread, a one-second delay, a 180-second timeout, and Boolean/error/UNION detection; it does not enumerate databases, extract data, or accept caller-supplied commands or request bodies. Output is encrypted as evidence and displayed as candidate signals for assessor validation. The backend image includes sqlmap.

The scan worker is built from [`docker/Dockerfile.scan-worker`](docker/Dockerfile.scan-worker) and includes the locally runnable Metasploit, John, Hashcat, and Hydra tools. Metasploit runs only the HTTP title auxiliary module against an authorized registered web URL. John and Hashcat run bounded 120-second offline wordlist audits using hash and wordlist evidence already encrypted in the assessment; Hashcat supports NTLM, MD5, sha512crypt, and bcrypt modes. Hydra accepts one nominated account for one attempt against a registered asset's standard SSH, FTP, HTTP, HTTPS, or SMB port; credentials are encrypted for the queue and deleted after the worker handles the job. These workflows are available from Tools & review and Recon & scans. Pentera and NodeZero remain unconfigured pending vendor API access and credentials.

Strix `vulnerabilities.json` and SARIF 2.1.0 reports can be imported for bounded candidate summaries; the original report remains encrypted. The UI shows up to 100 candidates at a time with severity, confidence, description, location, and remediation when present. Treat imported items as leads to review, not confirmed findings. Externally run Burp Suite XML issue reports and Wireshark packet-summary CSV files can also be imported for review. Burp import extracts issue name, scanner severity/confidence, and host only; it does not import request/response bodies. Wireshark CSV import summarizes packet counts, protocol counts, and frame bytes without retaining packet contents in the parsed summary. PCAP/PCAPNG files are stored encrypted for offline review and are not parsed by the app. Imported John/Hashcat/Hydra outputs are still accepted as encrypted evidence with redacted summaries; recovered credential values never appear in those summaries. Pentera and NodeZero outputs remain encrypted, unparsed evidence until their vendor APIs are configured. External tool imports do not create findings automatically; assessors validate and record findings separately.

## Main endpoints and consoles

- Frontend: `http://localhost:8080`
- FastAPI docs (development only): `http://localhost:8000/api/docs`
- Keycloak: `http://localhost:8081`
- Grafana: `http://localhost:3000` (admin password from `.env` or the local default)
- Evidence object store is internal to the Compose network; files are uploaded/downloaded through the authenticated API.

## Deployment boundary

Compose is a local development stack, not a production deployment profile. Before organizational use, put it behind agency-managed TLS and network controls; replace development OIDC, passwords, MFA policy, and Keycloak settings; configure production Postgres/Redis and backups; use a managed KMS/HSM or envelope-key service with rotation for evidence; configure retention, immutable audit export, scanner egress allowlists, NVD API policy, container image verification, and incident monitoring. The in-database audit trail is application-level and is not tamper-proof against database administrators. The Nmap worker can send active probes, so production authorization and egress policy must be reviewed by the responsible agency owner.

The prototype's Nmap integration follows the upstream recommendation to consume XML for programmatic integrations rather than parse human-oriented terminal output: [Nmap XML output documentation](https://nmap.org/book/output-formats-xml-output.html). Tailwind is wired through its official Vite plugin flow: [Tailwind CSS with Vite](https://tailwindcss.com/docs/installation/using-vite).

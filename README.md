# CrimeLens - Secure Investigation Platform

Project Crime Lens is an investigation prototype for ingesting structured and unstructured evidence, extracting entities and relationships, visualizing an evidence graph, and providing an investigation assistant.

## Current version

This package includes the updated light professional interface and security layer:

- Light investigation dashboard with navy sidebar
- Role-based login: Admin, Investigator, Auditor
- Backend-enforced role permissions on every protected endpoint (see Roles and permissions)
- Authorization denials recorded as security events and audit-ledger blocks
- scrypt password hashing
- HMAC-signed HttpOnly session cookie
- Session expiration
- CSRF protection for state-changing operations
- Security response headers and Content Security Policy
- Upload extension allow-list and 25 MB limit
- Unique stored evidence filenames
- Failed-login rate limiting and security events
- SHA-256 evidence fingerprinting
- Evidence integrity verification: VERIFIED / TAMPERED / MISSING
- Tamper-evident hash-linked audit ledger
- Ledger verification
- Audit trail and Security Center
- Case creation and case workspace
- Entity graph and graph assistant
- Structured/unstructured evidence ingestion
- OCR support through Tesseract when installed

The ledger is a local permissioned-style hash chain for the prototype. It is not presented as a distributed public blockchain.

## Windows setup

Open PowerShell in this folder.

### 1. Create a virtual environment if you do not already have one

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can run the project without activation by using `.venv\Scripts\python.exe` and `.venv\Scripts\uvicorn.exe` directly.

### 2. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 3. Migrate/verify the security database

```powershell
python migrate_security.py
```

The included database already contains the synthetic Operation Blue Lantern data and security records. Do not delete `crimelens.db` unless you intentionally want a fresh database.

### 4. Start the application

```powershell
uvicorn app.main:app --reload
```

Or double-click:

`START_CRIMELENS.bat`

### 5. Open the dashboard

http://127.0.0.1:8000

## Demo accounts

Admin:

- Username: `admin@crimelens.local`
- Password: `Admin@12345`

Investigator:

- Username: `investigator@crimelens.local`
- Password: `Invest@12345`

Auditor:

- Username: `auditor@crimelens.local`
- Password: `Audit@12345`

For a real deployment, replace the development credentials with environment-managed credentials and a strong `SESSION_SECRET`.

## Roles and permissions

Authentication (who the user is) and authorization (what the user may do) are
separate concerns. Every protected API endpoint declares the permission it
requires, and the role is re-checked on the backend for each request, so role
information coming from the browser is never trusted.

| Permission | Admin | Investigator | Auditor |
| --- | --- | --- | --- |
| `case:view` - view case workspaces | yes | yes | yes |
| `case:create` - create cases | yes | yes | no |
| `evidence:view` - view the evidence register | yes | yes | yes |
| `evidence:ingest` - ingest evidence | yes | yes | no |
| `evidence:verify` - verify evidence integrity (SHA-256) | yes | yes | yes |
| `entity:view` - view entity records | yes | yes | yes |
| `entity:photo` - attach entity photographs | yes | yes | no |
| `graph:view` - view the investigation graph and paths | yes | yes | yes |
| `assistant:query` - query the investigation assistant | yes | yes | no |
| `security:view` - Security Center (events, audit trail) | yes | no | yes |
| `ledger:view` - view the hash-chain ledger | yes | no | yes |
| `ledger:verify` - verify the ledger | yes | no | yes |

- Roles are defined once in `app/rbac.py` and used by both the API layer and the UI.
- Unknown or unmapped roles receive no permissions, so an unexpected role fails closed.
- A refused request returns HTTP 403 and is recorded as an `AUTHORIZATION_DENIED`
  audit event, a `WARNING` security event and a hash-linked ledger block.
- The dashboard hides controls the signed-in role may not use (declared with
  `data-permission` attributes and applied from the permissions returned by
  `/api/session`). This is presentation only; the backend check is authoritative.
- Security posture counters (failed logins, security events, ledger blocks) in
  `/api/stats` are returned only to roles with `security:view`.


## Project structure

```text
CrimeLens/
├── app/
│   ├── main.py
│   ├── models.py
│   ├── security.py
│   ├── database.py
│   ├── schemas.py
│   ├── config.py
│   ├── services/
│   │   ├── assistant.py
│   │   ├── graph_service.py
│   │   └── ingestion.py
│   ├── static/
│   │   ├── app.js
│   │   └── styles.css
│   └── templates/
│       └── index.html
├── data/
├── uploads/
├── crimelens.db
├── migrate_security.py
├── START_CRIMELENS.bat
└── requirements.txt
```

## Important security note

This is a local academic/prototype system. For production use, place it behind HTTPS, use a strong secret from a secure secret manager/environment, add proper authorization policies, malware/content scanning for uploads, trusted reverse-proxy configuration, centralized audit storage, and a real permissioned distributed ledger if blockchain is required.

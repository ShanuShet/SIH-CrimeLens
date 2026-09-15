# CrimeLens - Secure Investigation Platform

Project Crime Lens is an investigation prototype for ingesting structured and unstructured evidence, extracting entities and relationships, visualizing an evidence graph, and providing an investigation assistant.

## Current version

This package includes the updated light professional interface and security layer:

- Light investigation dashboard with navy sidebar
- Role-based login: Admin, Investigator, Auditor
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

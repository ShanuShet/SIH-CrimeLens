from pathlib import Path
import hashlib
import hmac
import json
import os
import secrets
import shutil
import time
from datetime import datetime
from threading import Lock
from uuid import uuid4

from fastapi import FastAPI, Request, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .database import Base, engine, get_db, SessionLocal
from .models import (
    Entity, Relationship, Case, Document,
    User, AuditEvent, BlockchainBlock,
    EvidenceIntegrity, SecurityEvent,
)
from .schemas import ChatRequest, PathRequest
from .services.ingestion import (
    ALLOWED_EXTENSIONS,
    classify_extension,
    extract_entities,
    extract_relationships,
    create_case_backbone,
    parse_structured,
    read_document,
)
from .services.graph_service import upsert_graph, graph_payload, shortest_path, GraphService
from .services.assistant import answer_question
from .security import (
    SESSION_COOKIE, SESSION_TTL,
    current_user, require_user, require_csrf,
    hash_password, verify_password, make_session,
    client_ip,
)

BASE = Path(__file__).resolve().parent
UPLOADS = BASE.parent / "uploads"
UPLOADS.mkdir(exist_ok=True)
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE_MB", "25")) * 1024 * 1024

app = FastAPI(title="CrimeLens Secure Investigation Platform", docs_url="/docs", redoc_url="/redoc")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
app.mount("/uploads", StaticFiles(directory=str(UPLOADS)), name="uploads")
templates = Jinja2Templates(directory=str(BASE / "templates"))
Base.metadata.create_all(bind=engine)
graph = GraphService()
security_lock = Lock()
login_attempts = {}


def ensure_default_case():
    db = SessionLocal()
    try:
        if not db.query(Case).filter(Case.title == "Operation Blue Lantern").first():
            db.add(Case(
                title="Operation Blue Lantern",
                status="Pending",
                risk="Medium",
                description="Synthetic investigation case for CrimeLens evidence analysis."
            ))
            db.commit()
    finally:
        db.close()


def ensure_demo_users():
    db = SessionLocal()
    try:
        defaults = [
            (os.getenv("ADMIN_USERNAME", "admin@crimelens.local"), os.getenv("ADMIN_PASSWORD", "Admin@12345"), "Admin"),
            (os.getenv("INVESTIGATOR_USERNAME", "investigator@crimelens.local"), os.getenv("INVESTIGATOR_PASSWORD", "Invest@12345"), "Investigator"),
            (os.getenv("AUDITOR_USERNAME", "auditor@crimelens.local"), os.getenv("AUDITOR_PASSWORD", "Audit@12345"), "Auditor"),
        ]
        for username, password, role in defaults:
            if not db.query(User).filter(User.username == username).first():
                db.add(User(username=username, password_hash=hash_password(password), role=role, active=1))
        db.commit()
    finally:
        db.close()


ensure_default_case()
ensure_demo_users()


def backfill_evidence_integrity():
    """Fingerprint legacy evidence already present in the prototype database."""
    db = SessionLocal()
    try:
        changed = False
        system_user = db.query(User).filter(User.role == "Admin").first()
        for document in db.query(Document).all():
            if db.query(EvidenceIntegrity).filter(EvidenceIntegrity.document_id == document.id).first():
                continue
            candidate = UPLOADS / document.filename
            if not candidate.exists():
                continue
            digest = sha256_file(candidate)
            db.add(EvidenceIntegrity(document_id=document.id, sha256=digest, file_size=candidate.stat().st_size, stored_path=str(candidate), status="VERIFIED"))
            audit(db, system_user, "LEGACY_EVIDENCE_FINGERPRINTED", document.filename, f"SHA-256: {digest}")
            changed = True
        if changed:
            db.commit()
    finally:
        db.close()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def append_block(db: Session, event_type: str, payload: dict) -> BlockchainBlock:
    last = db.query(BlockchainBlock).order_by(BlockchainBlock.block_index.desc()).first()
    index = (last.block_index + 1) if last else 0
    previous_hash = last.block_hash if last else "GENESIS"
    created = datetime.utcnow().isoformat(timespec="microseconds")
    body = {
        "index": index,
        "event_type": event_type,
        "payload": payload,
        "previous_hash": previous_hash,
        "created_at": created,
    }
    block_hash = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    block = BlockchainBlock(
        block_index=index,
        event_type=event_type,
        payload=canonical_json(payload),
        previous_hash=previous_hash,
        block_hash=block_hash,
        created_at=datetime.fromisoformat(created),
    )
    db.add(block)
    db.flush()
    return block


def audit(db: Session, user: User | None, action: str, resource: str = "", detail: str = "", request: Request | None = None, severity: str | None = None):
    username = user.username if user else "system"
    role = user.role if user else "system"
    ip = client_ip(request) if request else "system"
    event = AuditEvent(username=username, role=role, action=action, resource=resource, detail=detail, ip_address=ip)
    db.add(event)
    db.flush()
    append_block(db, "AUDIT_EVENT", {
        "audit_id": event.id,
        "username": username,
        "role": role,
        "action": action,
        "resource": resource,
        "detail": detail,
        "ip": ip,
    })
    if severity:
        db.add(SecurityEvent(event_type=action, severity=severity, username=username, detail=detail, ip_address=ip))


def verify_blockchain(db: Session):
    blocks = db.query(BlockchainBlock).order_by(BlockchainBlock.block_index.asc()).all()
    previous = "GENESIS"
    for expected_index, block in enumerate(blocks):
        try:
            payload = json.loads(block.payload or "{}")
        except Exception:
            return {"valid": False, "checked_blocks": expected_index, "error": f"Invalid JSON payload in block {block.block_index}"}
        body = {
            "index": block.block_index,
            "event_type": block.event_type,
            "payload": payload,
            "previous_hash": block.previous_hash,
            "created_at": block.created_at.isoformat(timespec="microseconds") if block.created_at else "",
        }
        calculated = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        if block.block_index != expected_index or block.previous_hash != previous or not hmac.compare_digest(calculated, block.block_hash):
            return {"valid": False, "checked_blocks": expected_index + 1, "error": f"Ledger mismatch at block {block.block_index}"}
        previous = block.block_hash
    return {"valid": True, "checked_blocks": len(blocks), "error": None}


def rate_limited(ip: str) -> bool:
    now = time.time()
    with security_lock:
        attempts = [t for t in login_attempts.get(ip, []) if now - t < 300]
        login_attempts[ip] = attempts
        return len(attempts) >= 5


def record_login_failure(ip: str, username: str):
    with security_lock:
        login_attempts.setdefault(ip, []).append(time.time())
    db = SessionLocal()
    try:
        event = SecurityEvent(event_type="FAILED_LOGIN", severity="WARNING", username=username[:120], detail="Invalid credentials or locked login window", ip_address=ip)
        db.add(event)
        db.flush()
        append_block(db, "SECURITY_EVENT", {"event_id": event.id, "event_type": "FAILED_LOGIN", "username": username[:120], "ip": ip})
        db.commit()
    finally:
        db.close()


backfill_evidence_integrity()

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request},
    )


@app.post("/api/login")
async def login(request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    if rate_limited(ip):
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Try again in a few minutes.")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid login request")
    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", ""))
    user = db.query(User).filter(User.username == username, User.active == 1).first()
    if not user or not verify_password(password, user.password_hash):
        record_login_failure(ip, username)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    user.last_login = datetime.utcnow()
    audit(db, user, "LOGIN_SUCCESS", "AUTH", "Successful authentication", request)
    db.commit()
    token, csrf = make_session(user)
    response = JSONResponse({"ok": True, "user": {"username": user.username, "role": user.role}, "csrf_token": csrf, "expires_in": SESSION_TTL})
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, secure=os.getenv("COOKIE_SECURE", "false").lower() == "true", samesite="lax")
    return response


@app.post("/api/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_csrf(request)
    audit(db, user, "LOGOUT", "AUTH", "User logged out", request)
    db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/api/session")
def session_info(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    session = request.cookies.get(SESSION_COOKIE)
    from .security import decode_session
    decoded = decode_session(session)
    return {"authenticated": True, "user": {"username": user.username, "role": user.role}, "csrf_token": decoded["csrf"] if decoded else ""}


@app.get("/api/stats")
def stats(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    cases = db.query(Case).all()
    return {
        "total_cases": len(cases),
        "solved_cases": sum(c.status.lower() == "solved" for c in cases),
        "pending_cases": sum(c.status.lower() == "pending" for c in cases),
        "high_risk_entities": sum((e.risk or 0) >= 70 for e in db.query(Entity).all()),
        "active_leads": db.query(Relationship).count(),
        "entities": db.query(Entity).count(),
        "evidence_documents": db.query(Document).count(),
        "integrity_verified": db.query(EvidenceIntegrity).filter(EvidenceIntegrity.status == "VERIFIED").count(),
        "ledger_blocks": db.query(BlockchainBlock).count(),
        "security_events": db.query(SecurityEvent).count(),
        "failed_logins": db.query(SecurityEvent).filter(SecurityEvent.event_type == "FAILED_LOGIN").count(),
        "role": user.role,
    }


@app.get("/api/graph")
def graph_api(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    return graph_payload(db)


@app.get("/api/cases")
def cases_api(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    return [{"id": c.id, "title": c.title, "status": c.status, "risk": c.risk, "description": c.description} for c in db.query(Case).all()]


@app.post("/api/cases")
async def create_case(
    request: Request,
    db: Session = Depends(get_db),
):
    user = require_user(request, db)
    require_csrf(request)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid case request")

    title = str(body.get("title", body.get("name", ""))).strip()
    if not title:
        raise HTTPException(status_code=400, detail="Case name is required")
    if len(title) > 255:
        raise HTTPException(status_code=400, detail="Case name is too long")

    description = str(body.get("description", "")).strip()
    if len(description) > 5000:
        raise HTTPException(status_code=400, detail="Case description is too long")

    risk = str(body.get("risk", "Medium")).strip()
    if risk not in {"Low", "Medium", "High"}:
        risk = "Medium"

    status = str(body.get("status", "Pending")).strip()
    if status not in {"Pending", "Solved", "Open", "Closed"}:
        status = "Pending"

    reference_id = str(body.get("reference_id", body.get("case_id", ""))).strip()
    if reference_id:
        description = (
            f"Reference ID: {reference_id}\n\n{description}"
            if description else f"Reference ID: {reference_id}"
        )

    case = Case(
        title=title,
        status=status,
        risk=risk,
        description=description,
    )
    db.add(case)
    db.flush()

    audit(
        db, user, "CASE_CREATED", str(case.id),
        f"title={title}; risk={risk}; status={status}", request
    )
    db.commit()

    return {
        "ok": True,
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "risk": case.risk,
        "description": case.description or "",
    }


@app.get("/api/entity/{entity_key:path}")
def entity_details_api(entity_key: str, request: Request, db: Session = Depends(get_db)):
    """Return detailed, evidence-backed information for one graph entity."""
    require_user(request, db)
    key = str(entity_key).strip()
    entity = db.query(Entity).filter(Entity.key == key).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    relationships = db.query(Relationship).filter(
        (Relationship.source == key) | (Relationship.target == key)
    ).all()

    connected_keys = set()
    for rel in relationships:
        other = rel.target if rel.source == key else rel.source
        if other and other != key:
            connected_keys.add(other)

    connected_entities = {}
    if connected_keys:
        for item in db.query(Entity).filter(Entity.key.in_(list(connected_keys))).all():
            connected_entities[item.key] = item

    connections = []
    for rel in relationships:
        other_key = rel.target if rel.source == key else rel.source
        other = connected_entities.get(other_key)
        if not other:
            continue
        outgoing = rel.source == key
        relation = str(rel.relation or "RELATED_TO")
        connections.append({
            "key": other.key,
            "name": other.name,
            "label": other.label,
            "relation": relation,
            "relation_display": relation.replace("_", " "),
            "direction": "OUTGOING" if outgoing else "INCOMING",
            "timestamp": rel.timestamp or "",
            "amount": rel.amount,
        })

    case_rows = []
    for rel in relationships:
        if str(rel.relation or "").upper() != "PART_OF_CASE":
            continue
        case_key = rel.target if rel.source == key else rel.source
        if str(case_key).upper().startswith("CASE:"):
            title = str(case_key).split(":", 1)[1].replace("_", " ")
            case_rows.append({"key": case_key, "title": title})
        else:
            other = db.query(Entity).filter(Entity.key == case_key).first()
            if other:
                case_rows.append({"key": case_key, "title": other.name})

    # The graph stores case membership as contextual relationships. Also expose
    # the default investigation case when the entity has no explicit case edge.
    if not case_rows:
        default_case = db.query(Case).filter(Case.title == "Operation Blue Lantern").first()
        if default_case:
            case_rows.append({"key": f"CASE:{default_case.id}", "title": default_case.title})

    connections.sort(key=lambda x: (x["name"].lower(), x["relation"]))
    return {
        "entity": {
            "key": entity.key,
            "label": entity.label,
            "name": entity.name,
            "risk": entity.risk or 0,
            "image": entity.image_path or "",
        },
        "connections": connections,
        "cases": case_rows,
        "connection_count": len(connections),
    }

@app.get("/api/documents")
def documents_api(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    docs = db.query(Document).order_by(Document.id.desc()).limit(50).all()
    integrity = {x.document_id: x for x in db.query(EvidenceIntegrity).all()}
    return [{
        "id": d.id, "filename": d.filename, "doc_type": d.doc_type, "data_category": d.data_category,
        "file_extension": d.file_extension, "file_size": d.file_size, "extraction_method": d.extraction_method,
        "status": d.status, "created_at": d.created_at.isoformat() if d.created_at else None,
        "sha256": integrity.get(d.id).sha256 if integrity.get(d.id) else None,
        "integrity_status": integrity.get(d.id).status if integrity.get(d.id) else "NOT_CHECKED",
    } for d in docs]


@app.post("/api/upload")
async def upload(request: Request, files: list[UploadFile] = File(...), doc_type: str = "AUTO", db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_csrf(request)
    results = []
    for file in files:
        original_name = Path(file.filename or "unknown").name
        suffix = Path(original_name).suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            results.append({"ok": False, "filename": original_name, "error": f"Unsupported file type: {suffix or 'none'}"})
            db.add(SecurityEvent(event_type="BLOCKED_FILE_TYPE", severity="WARNING", username=user.username, detail=original_name, ip_address=client_ip(request)))
            audit(db, user, "BLOCKED_FILE_TYPE", original_name, "Unsupported evidence extension", request, "WARNING")
            db.commit()
            continue
        stored_name = f"{uuid4().hex}{suffix}"
        path = UPLOADS / stored_name
        try:
            size = 0
            with path.open("wb") as buffer:
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_FILE_SIZE:
                        raise ValueError(f"File exceeds {MAX_FILE_SIZE // (1024 * 1024)} MB limit")
                    buffer.write(chunk)
            file_hash = sha256_file(path)
            category = classify_extension(original_name)
            chosen_type = doc_type.upper()
            if chosen_type == "AUTO":
                chosen_type = "STRUCTURED" if category == "STRUCTURED" else "OTHER"

            if category == "STRUCTURED":
                entities, relationships, metadata = parse_structured(str(path), chosen_type)
                content = json.dumps(metadata, ensure_ascii=False, default=str)
                structured_preview = json.dumps(metadata.get("preview", []), ensure_ascii=False, default=str)
                extraction_method = f"STRUCTURED_PARSER:{metadata.get('detected_type', chosen_type)}"
            else:
                content, extraction_method = read_document(str(path))
                metadata = {"characters": len(content), "detected_type": chosen_type}
                structured_preview = ""
                known_entities = [{"key": e.key, "label": e.label, "name": e.name} for e in db.query(Entity).all()]
                entities = extract_entities(content, known_entities)
                relationships = extract_relationships(content, known_entities)

            create_case_backbone("CL-001", "Operation Blue Lantern", entities, relationships)
            upsert_graph(db, entities, relationships)
            document = Document(
                filename=original_name, doc_type=chosen_type, data_category=category, file_extension=suffix,
                file_size=size, extraction_method=extraction_method, content=content[:100000],
                structured_preview=structured_preview[:50000], status="INGESTED",
            )
            db.add(document)
            db.flush()
            db.add(EvidenceIntegrity(document_id=document.id, sha256=file_hash, file_size=size, stored_path=str(path), status="VERIFIED"))
            audit(db, user, "EVIDENCE_INGESTED", original_name, f"SHA-256: {file_hash}; entities={len(entities)}; relationships={len(relationships)}", request)
            db.commit()
            for e in db.query(Entity).all():
                graph.sync_entity(e)
            for r in db.query(Relationship).all():
                graph.sync_relationship(r)
            result = {
                "ok": True, "filename": original_name, "data_category": category, "doc_type": chosen_type,
                "file_extension": suffix, "file_size": size, "sha256": file_hash,
                "extraction_method": extraction_method, "entities_added": len(entities), "relationships_added": len(relationships),
            }
            result.update(metadata)
            results.append(result)
        except Exception as exc:
            if path.exists():
                path.unlink(missing_ok=True)
            db.rollback()
            results.append({"ok": False, "filename": original_name, "data_category": category if 'category' in locals() else "", "error": str(exc)})
    return {"ok": all(r.get("ok") for r in results) if results else False, "results": results}


@app.post("/api/chat")
def chat(request: Request, req: ChatRequest, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_csrf(request)
    result = answer_question(db, req.question)
    audit(db, user, "GRAPH_QUERY", "ASSISTANT", req.question[:500], request)
    db.commit()
    return result


@app.post("/api/path")
def path(request: Request, req: PathRequest, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_csrf(request)
    result = shortest_path(db, req.source, req.target, req.max_hops)
    audit(db, user, "PATH_QUERY", f"{req.source}->{req.target}", f"max_hops={req.max_hops}", request)
    db.commit()
    return result


@app.get("/api/health")
def health():
    return {"status": "online", "application": "CrimeLens", "security": "enabled"}


@app.get("/api/security/overview")
def security_overview(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    ledger = verify_blockchain(db)
    integrity_total = db.query(EvidenceIntegrity).count()
    integrity_verified = db.query(EvidenceIntegrity).filter(EvidenceIntegrity.status == "VERIFIED").count()
    failed = db.query(SecurityEvent).filter(SecurityEvent.event_type == "FAILED_LOGIN").count()
    blocked = db.query(SecurityEvent).filter(SecurityEvent.event_type == "BLOCKED_FILE_TYPE").count()
    return {
        "user": {"username": user.username, "role": user.role},
        "ledger": ledger,
        "evidence_integrity": {"total": integrity_total, "verified": integrity_verified, "status": "SECURE" if integrity_total == integrity_verified else "REVIEW"},
        "failed_logins": failed,
        "blocked_files": blocked,
        "security_headers": True,
        "authentication": "HMAC signed session + scrypt password hashing",
        "audit_chain": "Tamper-evident hash-linked ledger",
    }


@app.get("/api/security/audit")
def security_audit(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    rows = db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(100).all()
    return [{"id": x.id, "username": x.username, "role": x.role, "action": x.action, "resource": x.resource, "detail": x.detail, "ip": x.ip_address, "created_at": x.created_at.isoformat() if x.created_at else None} for x in rows]


@app.get("/api/security/events")
def security_events(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    rows = db.query(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(100).all()
    return [{"id": x.id, "event_type": x.event_type, "severity": x.severity, "username": x.username, "detail": x.detail, "ip": x.ip_address, "created_at": x.created_at.isoformat() if x.created_at else None} for x in rows]


@app.get("/api/security/ledger")
def security_ledger(request: Request, db: Session = Depends(get_db)):
    require_user(request, db)
    rows = db.query(BlockchainBlock).order_by(BlockchainBlock.block_index.desc()).limit(100).all()
    return [{"index": x.block_index, "event_type": x.event_type, "payload": json.loads(x.payload or "{}"), "previous_hash": x.previous_hash, "block_hash": x.block_hash, "created_at": x.created_at.isoformat() if x.created_at else None} for x in rows]


@app.post("/api/security/verify")
def security_verify(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_csrf(request)
    result = verify_blockchain(db)
    audit(db, user, "LEDGER_VERIFICATION", "BLOCKCHAIN_LEDGER", json.dumps(result), request, "INFO" if result["valid"] else "CRITICAL")
    db.commit()
    return result


@app.get("/api/evidence/{document_id}/verify")
def verify_evidence(document_id: int, request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    record = db.query(EvidenceIntegrity).filter(EvidenceIntegrity.document_id == document_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Integrity record not found")
    path = Path(record.stored_path)
    if not path.exists():
        record.status = "MISSING"
        db.add(SecurityEvent(event_type="EVIDENCE_MISSING", severity="CRITICAL", username=user.username, detail=f"Document {document_id}", ip_address=client_ip(request)))
        db.commit()
        return {"valid": False, "status": "MISSING", "sha256": record.sha256}
    actual = sha256_file(path)
    valid = hmac.compare_digest(actual, record.sha256)
    record.status = "VERIFIED" if valid else "TAMPERED"
    record.verified_at = datetime.utcnow()
    audit(db, user, "EVIDENCE_INTEGRITY_CHECK", str(document_id), f"expected={record.sha256}; actual={actual}; valid={valid}", request, "INFO" if valid else "CRITICAL")
    db.commit()
    return {"valid": valid, "status": record.status, "expected_sha256": record.sha256, "actual_sha256": actual}


@app.post("/api/entity/{entity_key:path}/photo")
async def upload_entity_photo(entity_key: str, request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    user = require_user(request, db)
    require_csrf(request)
    entity = db.query(Entity).filter(Entity.key == entity_key).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    if entity.label != "Person":
        raise HTTPException(status_code=400, detail="Photos can currently be attached only to Person entities.")
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".jpg", ".jpeg", ".png"}:
        raise HTTPException(status_code=400, detail="Only JPG, JPEG and PNG images are supported.")
    person_dir = UPLOADS / "persons"
    person_dir.mkdir(parents=True, exist_ok=True)
    safe_name = entity.key.replace(":", "_").replace("/", "_").replace("\\", "_")
    image_name = safe_name + suffix
    image_path = person_dir / image_name
    with image_path.open("wb") as buffer:
        size = 0
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > 8 * 1024 * 1024:
                image_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="Profile image exceeds 8 MB limit")
            buffer.write(chunk)
    entity.image_path = "/uploads/persons/" + image_name
    audit(db, user, "ENTITY_PHOTO_ATTACHED", entity.key, f"size={size}", request)
    db.commit()
    return {"ok": True, "image_path": entity.image_path}

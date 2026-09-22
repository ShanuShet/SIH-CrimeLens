from pathlib import Path
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import time
from datetime import datetime
from threading import Lock
from uuid import uuid4

from fastapi import FastAPI, Request, UploadFile, File, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .database import (
    Base,
    engine,
    get_db,
    SessionLocal,
    migrate_case_fields,
)

from .models import (
    Entity, Relationship, Case, Document,
    User, AuditEvent, BlockchainBlock,
    EvidenceIntegrity, SecurityEvent, DocumentChunk,
)
from .rbac import (
    PERM_ASSISTANT_QUERY,
    PERM_CASE_CREATE,
    PERM_CASE_DELETE,
    PERM_CASE_VIEW,
    PERM_ENTITY_PHOTO,
    PERM_ENTITY_VIEW,
    PERM_EVIDENCE_INGEST,
    PERM_EVIDENCE_VERIFY,
    PERM_EVIDENCE_VIEW,
    PERM_GRAPH_VIEW,
    PERM_LEDGER_VERIFY,
    PERM_LEDGER_VIEW,
    PERM_SECURITY_VIEW,
    has_permission,
    permission_description,
    sorted_permissions,
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
from .services.graph_service import (
    upsert_graph,
    graph_payload,
    shortest_path,
    GraphService,
    entity_photo_url,
)
from .services.risk_service import (
    HIGH_RISK_THRESHOLD,
    compute_case_risk_from_rows,
    refresh_stored_entity_risk,
    risk_band,
    risk_scores_for_rows,
    stored_risk_basis,
)
from .services.assistant import answer_question, get_entities
from .services.rag_service import invalidate_case_cache
from .security import (
    SESSION_COOKIE, SESSION_TTL,
    current_user, require_user, require_csrf,
    hash_password, verify_password, make_session,
    client_ip,
)

BASE = Path(__file__).resolve().parent
# Evidence storage directory. Defaults to the existing project "uploads" folder,
# but can be relocated with EVIDENCE_DIR (used for isolated test runs).
UPLOADS = Path(os.getenv("EVIDENCE_DIR", str(BASE.parent / "uploads"))).resolve()
UPLOADS.mkdir(parents=True, exist_ok=True)
# Entity profile photographs live inside the private evidence store as well, so
# they inherit the same access rules as evidence documents.
ENTITY_PHOTOS = (UPLOADS / "persons").resolve()
MAX_FILE_SIZE = int(os.getenv("MAX_FILE_SIZE_MB", "25")) * 1024 * 1024

app = FastAPI(title="CrimeLens Secure Investigation Platform", docs_url="/docs", redoc_url="/redoc")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
# Security: the evidence store is deliberately NOT mounted as static files. If it
# were, anyone who guessed a filename could read evidence without authenticating.
# Evidence bytes are only served by the authenticated, authorized endpoints
# /api/evidence/{document_id}/download and /api/entity/{entity_key}/photo, and the
# physical storage path is never returned to the client.
templates = Jinja2Templates(directory=str(BASE / "templates"))
Base.metadata.create_all(bind=engine)
migrate_case_fields()
graph = GraphService()
security_lock = Lock()
login_attempts = {}


def backfill_case_references(db: Session) -> int:
    """
    Guarantee that every case has a stable, unique reference ID.

    Cases created before reference IDs existed have none. The graph stores a
    case backbone node keyed on the reference ID ("CASE:<reference>"), so two
    different cases must never share a reference - otherwise their graphs would
    share one Case node.
    """

    updated = 0

    for case in db.query(Case).order_by(Case.id.asc()).all():

        if (case.reference_id or "").strip():
            continue

        candidate = f"CL-LEGACY-{case.id:03d}"

        while (
            db.query(Case)
            .filter(Case.reference_id == candidate)
            .first()
        ):
            candidate += "X"

        case.reference_id = candidate
        updated += 1

    if updated:
        db.commit()

    return updated


def ensure_default_case():
    db = SessionLocal()

    try:
        case = (
            db.query(Case)
            .filter(Case.reference_id == "CL-001")
            .first()
        )

        if not case:

            # Adopt a case that predates reference IDs instead of creating a
            # duplicate default case in the case selector.
            legacy_case = next(
                (
                    item
                    for item in db.query(Case)
                    .order_by(Case.id.asc())
                    .all()
                    if not (item.reference_id or "").strip()
                ),
                None,
            )

            if legacy_case:
                legacy_case.reference_id = "CL-001"
                db.commit()
            else:
                case = Case(
                    reference_id="CL-001",
                    title="Operation Blue Lantern",
                    status="Pending",
                    risk="Medium",
                    description=(
                        "Synthetic investigation case for "
                        "CrimeLens evidence analysis."
                    ),
                )

                db.add(case)
                db.commit()

        backfill_case_references(db)

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


def resolve_storage_reference(stored_reference: str) -> Path:
    """
    Resolve a stored evidence reference to a real file inside the evidence store.

    Evidence rows keep the location of the stored file so integrity can be
    re-checked. That stored value is trusted data, but it is still resolved and
    confined here: a reference that points outside the evidence directory -
    through ".." traversal or through a symlink that leaves the directory - is
    refused, so a tampered database row can never be used to read arbitrary
    files from the host.

    Raises ValueError when the reference is empty or escapes the store.
    """

    raw = str(stored_reference or "").strip()

    if not raw:
        raise ValueError("Evidence reference is empty")

    candidate = Path(raw)

    if not candidate.is_absolute():
        candidate = UPLOADS / candidate

    # resolve() collapses ".." and follows symlinks, so the containment check
    # below is performed on the real target rather than on the raw string.
    resolved = candidate.resolve()

    try:
        resolved.relative_to(UPLOADS)
    except ValueError:
        raise ValueError("Evidence reference is outside the evidence store")

    return resolved


# Audit actions whose resource is a Document row's numeric id.
DOCUMENT_AUDIT_ACTIONS_BY_ID = (
    "EVIDENCE_DOWNLOADED",
    "EVIDENCE_INTEGRITY_CHECK",
    "EVIDENCE_ACCESS_DENIED",
    "EVIDENCE_ACCESS_REJECTED",
)

# Audit actions whose resource is the original evidence filename.
DOCUMENT_AUDIT_ACTIONS_BY_NAME = (
    "EVIDENCE_INGESTED",
    "EVIDENCE_INGEST_FAILED",
    "LEGACY_EVIDENCE_FINGERPRINTED",
)


def storage_reference_label(stored_reference: str) -> tuple[str, bool]:
    """
    Provenance-safe label for a stored evidence reference.

    Provenance has to record where an evidence file is stored, but the physical
    host path must never leave the server (see resolve_storage_reference and the
    evidence download endpoint). The label is therefore the location relative to
    the evidence store, and it is only produced once the reference has been
    verified to be inside the store.

    Returns (label, valid). An empty or escaping reference yields ("", False)
    instead of raising, so a tampered row is reported rather than breaking the
    provenance report.
    """

    try:
        resolved = resolve_storage_reference(stored_reference)
    except ValueError:
        return "", False

    return resolved.relative_to(UPLOADS).as_posix(), True


def ledger_anchor_for_audit(db: Session, audit_id: int) -> dict | None:
    """
    Tamper-evident anchor for one audit event.

    audit() writes each event into the hash-linked ledger, so the block that
    carries this audit_id is the anchor that proves the audit entry has not been
    altered. The SQL prefilter is deliberately loose; the payload is then parsed
    and compared exactly so a partial id match can never return the wrong block.
    Only the block identity is returned; the payload is already exposed by the
    audit event itself.
    """

    needle = f'"audit_id":{int(audit_id)}'

    candidates = (
        db.query(BlockchainBlock)
        .filter(BlockchainBlock.event_type == "AUDIT_EVENT")
        .filter(BlockchainBlock.payload.contains(needle))
        .order_by(BlockchainBlock.block_index.asc())
        .limit(20)
        .all()
    )

    for block in candidates:

        try:
            payload = json.loads(block.payload or "{}")
        except (TypeError, ValueError):
            continue

        if not isinstance(payload, dict) or payload.get("audit_id") != int(audit_id):
            continue

        return {
            "block_index": block.block_index,
            "block_hash": block.block_hash,
            "previous_hash": block.previous_hash,
            "created_at": block.created_at.isoformat() if block.created_at else None,
        }

    return None


def document_provenance_events(db: Session, document: Document) -> list[AuditEvent]:
    """
    Audit events that belong to this document, and only this document.

    Numeric resources are matched against the evidence actions that use a
    document id. Filename resources are only accepted when the recorded detail
    does not name a different case, so two documents that share a filename in
    different cases cannot leak each other's history into the provenance chain.
    """

    case_marker = f"case_id={document.case_id};"

    conditions = (AuditEvent.resource == str(document.id)) & (
        AuditEvent.action.in_(DOCUMENT_AUDIT_ACTIONS_BY_ID)
    )

    # A document without a stored filename has no filename-based history.
    if (document.filename or "").strip():
        conditions = conditions | (
            (AuditEvent.resource == document.filename)
            & (AuditEvent.action.in_(DOCUMENT_AUDIT_ACTIONS_BY_NAME))
        )

    events = (
        db.query(AuditEvent)
        .filter(conditions)
        .order_by(AuditEvent.id.asc())
        .all()
    )

    matched: list[AuditEvent] = []

    for event in events:

        if event.action in DOCUMENT_AUDIT_ACTIONS_BY_ID:
            matched.append(event)
            continue

        detail = event.detail or ""

        # A filename-only match is ambiguous when another case later ingested a
        # file with the same name. Events that declare a case must match this
        # document's case; events recorded before case ids were logged are kept.
        if "case_id=" in detail and case_marker not in detail:
            continue

        matched.append(event)

    return matched


def entity_photo_candidates(entity_key: str) -> list[Path]:
    """
    Candidate on-disk locations for an entity's stored profile photograph.

    The upload endpoint derives the filename from the entity key. A stricter
    fallback name is also checked so photographs written by earlier versions
    stay reachable. Every candidate is confined to the photo directory.
    """

    raw = str(entity_key or "")

    names = [
        raw.replace(":", "_").replace("/", "_").replace("\\", "_"),
        re.sub(r"[^A-Za-z0-9._-]", "_", raw),
    ]

    candidates: list[Path] = []

    for name in names:

        if not name:
            continue

        for suffix in (".jpg", ".jpeg", ".png"):

            candidate = (ENTITY_PHOTOS / f"{name}{suffix}").resolve()

            try:
                candidate.relative_to(ENTITY_PHOTOS)
            except ValueError:
                continue

            if candidate not in candidates:
                candidates.append(candidate)

    return candidates


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


def require_permission(permission: str):
    """
    Authorization dependency: authenticated user + role allowed to act.

    Authentication (require_user) only proves identity, so every protected
    endpoint additionally declares the permission it needs. Refused attempts
    are recorded as security events and hash-linked ledger blocks: a denied
    action is itself security-relevant and must be auditable.

    The FastAPI dependencies are cached per request, so this dependency and the
    endpoint receive the same database session.
    """

    def dependency(request: Request, db: Session = Depends(get_db)) -> User:

        user = require_user(request, db)

        if has_permission(user.role, permission):
            return user

        role_label = user.role or "unknown"

        audit(
            db,
            user,
            "AUTHORIZATION_DENIED",
            permission,
            f"role={role_label}; required={permission}",
            request,
            "WARNING",
        )
        db.commit()

        raise HTTPException(
            status_code=403,
            detail=(
                f"Role '{role_label}' is not authorized to "
                f"{permission_description(permission)}."
            ),
        )

    return dependency


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
        name="home.html",
        context={"request": request},
    )


@app.get("/dashboard", response_class=HTMLResponse)
@app.get("/cases", response_class=HTMLResponse)
@app.get("/evidence", response_class=HTMLResponse)
@app.get("/entities", response_class=HTMLResponse)
@app.get("/relationships", response_class=HTMLResponse)
@app.get("/graph", response_class=HTMLResponse)
@app.get("/risk", response_class=HTMLResponse)
@app.get("/assistant", response_class=HTMLResponse)
@app.get("/audit", response_class=HTMLResponse)
def app_views(request: Request):
    path = request.url.path.strip("/")
    section_map = {
        "dashboard": "overview",
        "cases": "casesSection",
        "evidence": "evidenceSection",
        "entities": "entitiesSection",
        "relationships": "relationshipsSection",
        "graph": "graphSection",
        "risk": "riskSection",
        "assistant": "assistantSection",
        "audit": "securitySection",
    }
    initial_section = section_map.get(path, "overview")
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request, "initial_section": initial_section},
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
    response = JSONResponse({
        "ok": True,
        "user": {"username": user.username, "role": user.role},
        "permissions": sorted_permissions(user.role),
        "csrf_token": csrf,
        "expires_in": SESSION_TTL,
    })
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
    return {
        "authenticated": True,
        "user": {"username": user.username, "role": user.role},
        # Role permissions are exported for UI gating only. Every request is
        # re-authorized on the backend, so the frontend is never the authority.
        "permissions": sorted_permissions(user.role),
        "csrf_token": decoded["csrf"] if decoded else "",
    }


@app.get("/api/stats")
def stats(
    request: Request,
    case_id: int | None = None,
    user: User = Depends(require_permission(PERM_CASE_VIEW)),
    db: Session = Depends(get_db),
):

    # Validate selected case
    case = None

    if case_id is not None:
        case = db.query(Case).filter(
            Case.id == case_id
        ).first()

        if not case:
            raise HTTPException(
                status_code=404,
                detail="Case not found"
            )

    # Case-specific relationships
    relationship_query = db.query(Relationship)

    # Case-specific documents
    document_query = db.query(Document)

    if case_id is not None:
        relationship_query = relationship_query.filter(
            Relationship.case_id == case_id
        )

        document_query = document_query.filter(
            Document.case_id == case_id
        )

    relationships = relationship_query.all()
    documents = document_query.all()

    # Case-specific evidence integrity
    document_ids = [d.id for d in documents]

    if document_ids:
        integrity_records = db.query(EvidenceIntegrity).filter(
            EvidenceIntegrity.document_id.in_(document_ids)
        ).all()
    else:
        integrity_records = []

    # Case isolation: entity counters must describe the selected case only.
    # "Which entities belong to a case" is defined once in the assistant
    # (entities reachable through that case's relationships), so it is reused
    # here rather than re-implemented.
    if case_id is not None:
        case_entities = get_entities(db, case_id)
    else:
        case_entities = db.query(Entity).all()

    # ------------------------------------------------------------
    # COMPUTED RISK (CASE SCOPED)
    # ------------------------------------------------------------
    if case_id is not None:
        risk_report = compute_case_risk_from_rows(
            case_entities,
            relationships,
            case=case,
            case_id=case_id,
        )
        high_risk_count = sum(
            1
            for entry in risk_report["entities"].values()
            if entry["score"] >= HIGH_RISK_THRESHOLD
        )
    else:
        risk_report = None
        high_risk_count = sum(
            float(e.risk or 0.0) >= HIGH_RISK_THRESHOLD
            for e in case_entities
        )

    # Database-derived case statistics across the entire case portfolio
    total_cases_count = db.query(Case).count()
    solved_cases_count = db.query(Case).filter(
        Case.status.ilike("solved")
    ).count()
    pending_cases_count = db.query(Case).filter(
        Case.status.ilike("pending")
    ).count()
    active_cases_count = db.query(Case).filter(
        Case.status.ilike("open") | Case.status.ilike("active") | Case.status.ilike("pending")
    ).count()

    selected_case_info = None
    if case:
        selected_case_info = {
            "id": case.id,
            "title": case.title,
            "reference_id": case.reference_id,
            "status": case.status,
            "risk": case.risk,
            "description": case.description,
        }

    payload = {
        # Total Cases must always reflect the total cases in the database,
        # never collapsed to 1 simply because a single case is currently selected.
        "total_cases": total_cases_count,
        "active_cases": active_cases_count,
        "solved_cases": solved_cases_count,
        "pending_cases": pending_cases_count,
        "selected_case": selected_case_info,

        "high_risk_entities": high_risk_count,
        "active_leads": len(relationships),
        "entities": len(case_entities),
        "evidence_documents": len(documents),

        "integrity_verified": sum(
            record.status == "VERIFIED"
            for record in integrity_records
        ),
        "integrity_pending": sum(
            record.status != "VERIFIED"
            for record in integrity_records
        ),

        "role": user.role,
        "case_id": case_id,

        # Computed case risk, kept separate from the manually recorded case label
        # so an investigator can never mistake one for the other.
        "risk": (
            {
                "basis": risk_report["basis"],
                "algorithm": risk_report["algorithm"],
                "score": risk_report["case"]["score"],
                "band": risk_report["case"]["band"],
                "factors": risk_report["case"]["factors"],
                "declared_label": risk_report["case"]["declared_risk"],
                "declared_label_note": risk_report["case"]["declared_risk_note"],
                "threshold": risk_report["high_risk_threshold"],
                "counts": risk_report["case"]["counts"],
            }
            if risk_report
            else {
                "basis": stored_risk_basis(None),
                "algorithm": None,
                "score": None,
                "band": "UNSCORED",
                "factors": [],
                "declared_label": None,
                "declared_label_note": (
                    "Select a case to compute a case-scoped risk score."
                ),
                "threshold": HIGH_RISK_THRESHOLD,
                "counts": {},
            }
        ),

        "risk_basis": (
            risk_report["basis"] if risk_report else stored_risk_basis(None)
        ),
    }

    # Security posture counters are oversight data. Roles without Security
    # Center access do not receive them instead of leaking platform posture.
    if has_permission(user.role, PERM_SECURITY_VIEW):
        payload["ledger_blocks"] = db.query(BlockchainBlock).count()
        payload["security_events"] = db.query(SecurityEvent).count()
        payload["failed_logins"] = db.query(SecurityEvent).filter(
            SecurityEvent.event_type == "FAILED_LOGIN"
        ).count()

    return payload


@app.get("/api/entities")
def entities_api(
    request: Request,
    case_id: int | None = None,
    user: User = Depends(require_permission(PERM_ENTITY_VIEW)),
    db: Session = Depends(get_db),
):
    """List entities with deterministic resolution metadata and case-scoped risk."""
    rel_query = db.query(Relationship)
    if case_id is not None:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        entities = get_entities(db, case_id)
        rels = rel_query.filter(Relationship.case_id == case_id).all()
        risk_report = compute_case_risk_from_rows(entities, rels, case=case, case_id=case_id)
        entity_risk = risk_report["entities"]
        all_rels = rels
    else:
        entities = db.query(Entity).all()
        entity_risk = {}
        all_rels = rel_query.all()

    rel_counts = {}
    for r in all_rels:
        if r.source:
            rel_counts[r.source] = rel_counts.get(r.source, 0) + 1
        if r.target:
            rel_counts[r.target] = rel_counts.get(r.target, 0) + 1

    result = []
    for e in entities:
        risk_entry = entity_risk.get(e.key) or {}
        score = risk_entry.get("score") if risk_entry else float(e.risk or 0.0)
        band = risk_entry.get("band") if risk_entry else risk_band(score)
        result.append({
            "id": e.id,
            "key": e.key,
            "label": e.label,
            "name": e.name,
            "risk": score,
            "risk_band": band,
            "phone": getattr(e, "phone", None) or "",
            "email": getattr(e, "email", None) or "",
            "account": getattr(e, "account", None) or "",
            "vehicle": getattr(e, "vehicle", None) or "",
            "identifier": getattr(e, "identifier", None) or "",
            "resolution_status": getattr(e, "resolution_status", None) or "NEW_ENTITY",
            "match_reason": getattr(e, "match_reason", None) or "",
            "case_id": getattr(e, "case_id", None),
            "relationships_count": rel_counts.get(e.key, 0),
            "image": entity_photo_url(e.key, getattr(e, "image_path", "")),
        })
    return result


@app.get("/api/relationships")
def relationships_api(
    request: Request,
    case_id: int | None = None,
    user: User = Depends(require_permission(PERM_GRAPH_VIEW)),
    db: Session = Depends(get_db),
):
    """List relationships with connection metadata and case isolation."""
    query = db.query(Relationship)
    if case_id is not None:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        query = query.filter(Relationship.case_id == case_id)
    relationships = query.all()

    keys = set()
    for r in relationships:
        if r.source:
            keys.add(r.source)
        if r.target:
            keys.add(r.target)

    entity_map = {}
    if keys:
        for ent in db.query(Entity).filter(Entity.key.in_(list(keys))).all():
            entity_map[ent.key] = {
                "name": ent.name,
                "label": ent.label,
                "phone": getattr(ent, "phone", None) or "",
                "account": getattr(ent, "account", None) or "",
            }

    return [
        {
            "id": r.id,
            "source": r.source,
            "source_info": entity_map.get(r.source, {"name": r.source, "label": "Entity"}),
            "target": r.target,
            "target_info": entity_map.get(r.target, {"name": r.target, "label": "Entity"}),
            "relation": r.relation,
            "timestamp": r.timestamp,
            "amount": r.amount,
            "case_id": r.case_id,
        }
        for r in relationships
    ]


@app.get("/api/risk")
def risk_api(
    request: Request,
    case_id: int | None = None,
    user: User = Depends(require_permission(PERM_CASE_VIEW)),
    db: Session = Depends(get_db),
):
    """Return explainable risk intelligence for the selected case."""
    from .services.risk_service import compute_case_risk
    if case_id is not None:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        return compute_case_risk(db, case_id=case_id, case=case)
    return compute_case_risk(db, case_id=None)


@app.get("/api/graph")
def graph_api(
    request: Request,
    case_id: int | None = None,
    _user: User = Depends(require_permission(PERM_GRAPH_VIEW)),
    db: Session = Depends(get_db),
):
    if case_id is not None:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

    return graph_payload(db, case_id=case_id)


@app.get("/api/cases")
def cases_api(
    request: Request,
    _user: User = Depends(require_permission(PERM_CASE_VIEW)),
    db: Session = Depends(get_db)
):
    cases = (
        db.query(Case)
        .order_by(Case.id.asc())
        .all()
    )

    result = []
    for c in cases:
        doc_count = db.query(Document).filter(Document.case_id == c.id).count()
        rel_count = db.query(Relationship).filter(Relationship.case_id == c.id).count()
        ent_count = len(get_entities(db, c.id))
        result.append({
            "id": c.id,
            "reference_id": c.reference_id,
            "title": c.title,
            "status": c.status,
            "risk": c.risk,
            "description": c.description or "",
            "evidence_count": doc_count,
            "entity_count": ent_count,
            "relationship_count": rel_count,
        })
    return result


@app.post("/api/cases")
async def create_case(
    request: Request,
    user: User = Depends(require_permission(PERM_CASE_CREATE)),
    db: Session = Depends(get_db),
):
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

    reference_id = str(
        body.get("reference_id", body.get("case_id", ""))
    ).strip()

    if not reference_id:
        raise HTTPException(
            status_code=400,
            detail="Case reference ID is required",
        )

    if len(reference_id) > 120:
        raise HTTPException(
            status_code=400,
            detail="Case reference ID is too long",
        )

    existing_case = (
        db.query(Case)
        .filter(Case.reference_id == reference_id)
        .first()
    )

    if existing_case:
        raise HTTPException(
            status_code=409,
            detail=f"Case reference ID already exists: {reference_id}",
        )

    case = Case(
        reference_id=reference_id,
        title=title,
        status=status,
        risk=risk,
        description=description,
    )
    db.add(case)
    db.flush()

    audit(
        db,
        user,
        "CASE_CREATED",
        str(case.id),
        f"reference_id={reference_id}; title={title}; risk={risk}; status={status}",
        request,
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


@app.delete("/api/cases/{case_id}")
async def delete_case(
    case_id: int,
    request: Request,
    user: User = Depends(require_permission(PERM_CASE_DELETE)),
    db: Session = Depends(get_db),
):
    """
    Remove an investigation case and its associated investigation data.
    Enforces RBAC authorization (case:delete) and CSRF protection.
    Cascade-removes case-scoped relationships, documents, integrity records, RAG chunks,
    and orphan entities while preserving the immutable tamper-evident audit ledger.
    """
    require_csrf(request)

    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case #{case_id} not found")

    case_ref = case.reference_id or f"CL-{case.id:03d}"
    case_title = case.title

    # 1. Collect all documents for this case
    docs = db.query(Document).filter(Document.case_id == case.id).all()
    doc_ids = [d.id for d in docs]

    # 2. Delete EvidenceIntegrity records for these documents
    if doc_ids:
        db.query(EvidenceIntegrity).filter(EvidenceIntegrity.document_id.in_(doc_ids)).delete(synchronize_session=False)

    # 3. Delete DocumentChunk records (case RAG vector store)
    db.query(DocumentChunk).filter(DocumentChunk.case_id == case.id).delete(synchronize_session=False)

    # 4. Identify entity keys in this case's graph before removing relationships
    case_rels = db.query(Relationship).filter(Relationship.case_id == case.id).all()
    candidate_entity_keys = set()
    for r in case_rels:
        if r.source:
            candidate_entity_keys.add(r.source)
        if r.target:
            candidate_entity_keys.add(r.target)

    # 5. Delete all relationships for this case
    db.query(Relationship).filter(Relationship.case_id == case.id).delete(synchronize_session=False)

    # 6. Delete all documents for this case
    db.query(Document).filter(Document.case_id == case.id).delete(synchronize_session=False)

    # 7. Delete case node entities
    case_node_keys = {f"CASE:{case_ref}", f"CASE:{case.id}", f"CASE:{case_title}"}
    db.query(Entity).filter(Entity.key.in_(case_node_keys)).delete(synchronize_session=False)

    # 8. Clean up orphan entities created solely for this case that have no relationships left in any case
    if candidate_entity_keys:
        remaining_rels = db.query(Relationship.source, Relationship.target).filter(
            (Relationship.source.in_(candidate_entity_keys)) | (Relationship.target.in_(candidate_entity_keys))
        ).all()
        active_keys = set()
        for s, t in remaining_rels:
            if s:
                active_keys.add(s)
            if t:
                active_keys.add(t)

        orphans = (candidate_entity_keys - active_keys) - case_node_keys
        if orphans:
            db.query(Entity).filter(
                (Entity.key.in_(orphans)) & ((Entity.case_id == case.id) | (Entity.case_id.is_(None)))
            ).delete(synchronize_session=False)

    # Also clean up any entities explicitly linked to this case_id with no relationships
    orphan_case_entities = db.query(Entity).filter(Entity.case_id == case.id).all()
    for oce in orphan_case_entities:
        has_any_rel = db.query(Relationship).filter(
            (Relationship.source == oce.key) | (Relationship.target == oce.key)
        ).first()
        if not has_any_rel:
            db.delete(oce)

    # 9. Invalidate RAG assistant cache for this case
    invalidate_case_cache(case.id)

    # 10. Record immutable audit event and block in ledger
    audit(
        db,
        user,
        "CASE_DELETED",
        case_ref,
        f"case_id={case.id}; title={case_title}",
        request,
    )

    # 11. Delete the case itself and commit
    db.delete(case)
    db.commit()

    return {
        "ok": True,
        "message": f"Case '{case_title}' (#{case_id}) and its associated investigation data were successfully removed.",
        "case_id": case_id,
        "title": case_title,
    }


# NOTE: the entity photo routes are declared before the catch-all entity detail

# route below. FastAPI matches routes in declaration order, so a request such as
# /api/entity/Person:foo/photo would otherwise be captured by
# /api/entity/{entity_key:path} as the key "Person:foo/photo".
@app.get("/api/entity/{entity_key:path}/photo")
def get_entity_photo(
    entity_key: str,
    request: Request,
    _user: User = Depends(require_permission(PERM_ENTITY_VIEW)),
    db: Session = Depends(get_db),
):
    """
    Serve an entity's stored profile photograph.

    Photographs live in the same private store as evidence, so they are only
    reachable through this authorized endpoint rather than a public URL. The
    on-disk location is derived from the entity key and the physical path is
    never sent to the client.
    """

    entity = db.query(Entity).filter(Entity.key == entity_key).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    for candidate in entity_photo_candidates(entity.key):
        if candidate.is_file():
            media_type = (
                mimetypes.guess_type(candidate.name)[0]
                or "application/octet-stream"
            )
            return FileResponse(candidate, media_type=media_type)

    raise HTTPException(status_code=404, detail="Entity photograph not found")


@app.post("/api/entity/{entity_key:path}/photo")
async def upload_entity_photo(
    entity_key: str,
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_permission(PERM_ENTITY_PHOTO)),
    db: Session = Depends(get_db),
):
    require_csrf(request)
    entity = db.query(Entity).filter(Entity.key == entity_key).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    if entity.label != "Person":
        raise HTTPException(status_code=400, detail="Photos can currently be attached only to Person entities.")
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".jpg", ".jpeg", ".png"}:
        raise HTTPException(status_code=400, detail="Only JPG, JPEG and PNG images are supported.")
    person_dir = ENTITY_PHOTOS
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
    # Drop any earlier photograph with a different extension so exactly one file
    # per entity remains and the photo endpoint always serves the current image.
    for stale in person_dir.glob(f"{safe_name}.*"):
        if stale != image_path:
            stale.unlink(missing_ok=True)
    # Store the authorized endpoint, not a public uploads URL. The physical
    # storage path is never persisted as a client-visible URL.
    entity.image_path = entity_photo_url(entity.key, image_name)
    audit(db, user, "ENTITY_PHOTO_ATTACHED", entity.key, f"size={size}", request)
    db.commit()
    return {"ok": True, "image_path": entity.image_path}



@app.get("/api/entity/{entity_key:path}")
def entity_details_api(
    entity_key: str,
    request: Request,
    case_id: int | None = None,
    _user: User = Depends(require_permission(PERM_ENTITY_VIEW)),
    db: Session = Depends(get_db),
):
    """Return detailed, evidence-backed information for one graph entity."""
    key = str(entity_key).strip()
    entity = db.query(Entity).filter(Entity.key == key).first()
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    if case_id is not None:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

    relationship_query = db.query(Relationship).filter(
        (Relationship.source == key) | (Relationship.target == key)
    )

    # Case isolation: an entity opened from a case graph must only expose the
    # relationships recorded inside that case.
    if case_id is not None:
        relationship_query = relationship_query.filter(
            Relationship.case_id == case_id
        )

    relationships = relationship_query.all()

    # Case isolation: an entity requested within a case MUST belong to that case.
    if case_id is not None and not relationships:
        raise HTTPException(
            status_code=404,
            detail="Entity not found in the selected case.",
        )

    # Risk is scored over the whole investigation, not only over the entity's own
    # connections, so the case's membership is resolved the same way every other
    # case-scoped surface resolves it. With no case selected there is no
    # investigation to score, so the stored aggregate is used and labelled as
    # case blind instead of silently mixing cases together.
    if case_id is not None:
        risk_relationships = relationships
        case_entities_for_risk = get_entities(db, case_id)
    else:
        risk_relationships = relationships
        case_entities_for_risk = []

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

    if not case_rows and case_id is not None and case:
        case_rows.append({"key": f"CASE:{case.reference_id or case.id}", "title": case.title})

    connections.sort(key=lambda x: (x["name"].lower(), x["relation"]))

    # ------------------------------------------------------------
    # COMPUTED ENTITY RISK (CASE SCOPED)
    # ------------------------------------------------------------
    # The score must describe this entity inside the selected case, so it is
    # recomputed from the case's own graph. Entity.risk is a case-blind aggregate
    # and is therefore only used when no case is selected, clearly labelled as
    # such. Either way the score is deterministic: no clock, no randomness.

    scores, _case_scores = risk_scores_for_rows(
        case_entities_for_risk,
        risk_relationships,
        case=case,
        case_id=case_id,
    )

    risk_entry = scores.get(key) or {}

    return {
        "entity": {
            "key": entity.key,
            "label": entity.label,
            "name": entity.name,
            "risk": (
                risk_entry.get("score")
                if risk_entry
                else round(float(entity.risk or 0.0), 2)
            ),
            "risk_band": (
                risk_entry.get("band")
                if risk_entry
                else risk_band(float(entity.risk or 0.0))
            ),
            "risk_basis": (
                risk_entry.get("basis")
                if risk_entry
                else stored_risk_basis(case_id)
            ),
            "risk_factors": risk_entry.get("factors", []),
            "resolution": {
                "status": getattr(entity, "resolution_status", None) or "NEW_ENTITY",
                "reason": getattr(entity, "match_reason", None) or "",
            },
            "phone": getattr(entity, "phone", None) or "",
            "email": getattr(entity, "email", None) or "",
            "account": getattr(entity, "account", None) or "",
            "vehicle": getattr(entity, "vehicle", None) or "",
            "identifier": getattr(entity, "identifier", None) or "",
            # Authorized endpoint only; never the storage path or a public URL.
            "image": entity_photo_url(entity.key, entity.image_path),
        },
        "connections": connections,
        "cases": case_rows,
        "connection_count": len(connections),
        "risk": {
            "algorithm": "weighted-sum-v1",
            "threshold": HIGH_RISK_THRESHOLD,
            "case_id": case_id,
            "basis": (
                risk_entry.get("basis")
                if risk_entry
                else stored_risk_basis(case_id)
            ),
        },
    }

@app.get("/api/documents")
def documents_api(
    request: Request,
    case_id: int | None = None,
    _user: User = Depends(require_permission(PERM_EVIDENCE_VIEW)),
    db: Session = Depends(get_db),
):
    if case_id is not None:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

    query = db.query(Document)

    if case_id is not None:
        query = query.filter(Document.case_id == case_id)

    docs = query.order_by(Document.id.desc()).limit(50).all()

    integrity = {
        x.document_id: x
        for x in db.query(EvidenceIntegrity).all()
    }

    # Provenance must stay connected to the correct case, so each register row
    # carries the case it belongs to and the link to its full provenance chain.
    case_ids = {d.case_id for d in docs if d.case_id is not None}
    cases = {}

    if case_ids:
        cases = {
            c.id: c
            for c in db.query(Case).filter(Case.id.in_(case_ids)).all()
        }

    chunk_docs = {
        row[0] for row in db.query(DocumentChunk.document_id).filter(DocumentChunk.document_id.in_([d.id for d in docs])).distinct().all()
    } if docs else set()

    return [
        {
            "id": d.id,
            "filename": d.filename,
            "doc_type": d.doc_type,
            "data_category": d.data_category,
            "file_extension": d.file_extension,
            "file_size": d.file_size,
            "extraction_method": d.extraction_method,
            "status": d.status,
            "created_at": d.created_at.isoformat() if d.created_at else None,
            "case_id": d.case_id,
            "case_reference": (
                cases[d.case_id].reference_id
                if d.case_id in cases
                else None
            ),
            "case_title": (
                cases[d.case_id].title
                if d.case_id in cases
                else None
            ),
            "provenance_url": f"/api/evidence/{d.id}/provenance",
            "sha256": integrity.get(d.id).sha256 if integrity.get(d.id) else None,
            "integrity_status": (
                integrity.get(d.id).status
                if integrity.get(d.id)
                else "NOT_CHECKED"
            ),
            "rag_indexed": d.id in chunk_docs,
        }
        for d in docs
    ]


@app.get("/api/documents/{document_id}")
def get_document_details(
    document_id: int,
    request: Request,
    case_id: int | None = None,
    _user: User = Depends(require_permission(PERM_EVIDENCE_VIEW)),
    db: Session = Depends(get_db),
):
    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Evidence document not found")

    if case_id is not None and doc.case_id != case_id:
        raise HTTPException(
            status_code=403,
            detail="Evidence does not belong to the selected case."
        )

    case = db.query(Case).filter(Case.id == doc.case_id).first() if doc.case_id else None
    integrity = db.query(EvidenceIntegrity).filter(EvidenceIntegrity.document_id == doc.id).first()
    rag_chunks = db.query(DocumentChunk).filter(DocumentChunk.document_id == doc.id).count()

    return {
        "id": doc.id,
        "filename": doc.filename,
        "case_id": doc.case_id,
        "case_reference": case.reference_id if case else None,
        "case_title": case.title if case else None,
        "doc_type": doc.doc_type,
        "data_category": doc.data_category,
        "file_extension": doc.file_extension,
        "file_size": doc.file_size,
        "extraction_method": doc.extraction_method,
        "content_preview": (doc.content or "")[:2000],
        "structured_preview": doc.structured_preview or "",
        "status": doc.status,
        "created_at": doc.created_at.isoformat() if doc.created_at else None,
        "sha256": integrity.sha256 if integrity else None,
        "integrity_status": integrity.status if integrity else "NOT_CHECKED",
        "verified_at": integrity.verified_at.isoformat() if integrity and integrity.verified_at else None,
        "rag_chunks_count": rag_chunks,
        "rag_indexed": rag_chunks > 0,
    }


@app.delete("/api/documents/{document_id}")
async def delete_document_api(
    document_id: int,
    request: Request,
    case_id: int | None = None,
    user: User = Depends(require_permission(PERM_EVIDENCE_INGEST)),
    db: Session = Depends(get_db),
):
    """
    Remove an evidence document, associated integrity records, RAG embeddings,
    and stored disk file while recording an immutable audit event and ledger block.
    Enforces RBAC authorization (evidence:ingest) and CSRF protection.
    """
    require_csrf(request)

    doc = db.query(Document).filter(Document.id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Evidence document not found")

    if case_id is not None and doc.case_id != case_id:
        audit(
            db,
            user,
            "EVIDENCE_DELETE_DENIED",
            str(document_id),
            f"requested case_id={case_id}; document case_id={doc.case_id}",
            request,
            "WARNING",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail="Evidence does not belong to the selected case."
        )

    doc_case_id = doc.case_id
    filename = doc.filename

    # Delete EvidenceIntegrity record and physical file
    integrity = db.query(EvidenceIntegrity).filter(EvidenceIntegrity.document_id == doc.id).first()
    if integrity:
        try:
            stored_p = resolve_storage_reference(integrity.stored_path)
            if stored_p.is_file():
                stored_p.unlink(missing_ok=True)
        except Exception:
            pass
        db.delete(integrity)

    # Delete DocumentChunk records (RAG embeddings)
    db.query(DocumentChunk).filter(DocumentChunk.document_id == doc.id).delete(synchronize_session=False)

    # Delete Document
    db.delete(doc)

    # Invalidate RAG cache for this case
    if doc_case_id:
        invalidate_case_cache(doc_case_id)

    # Audit & Ledger
    audit(
        db,
        user,
        "EVIDENCE_DELETED",
        filename,
        f"document_id={document_id}; case_id={doc_case_id}",
        request,
    )
    db.commit()

    return {
        "ok": True,
        "message": f"Evidence '{filename}' (#{document_id}) removed successfully.",
        "document_id": document_id,
        "case_id": doc_case_id,
    }


def resolve_case_id(form_value, request: Request) -> int | None:
    """
    Resolve the selected case id for evidence ingestion.

    The dashboard submits case_id as a multipart form field. A query-string
    case_id is still accepted for direct API clients.
    """

    raw = form_value

    if raw is None or str(raw).strip() == "":
        raw = request.query_params.get("case_id")

    if raw is None or str(raw).strip() == "":
        return None

    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail="Invalid case id.",
        )


@app.post("/api/upload")
async def upload(
    request: Request,
    files: list[UploadFile] = File(...),
    doc_type: str = Form("AUTO"),
    case_id: str | None = Form(None),
    user: User = Depends(require_permission(PERM_EVIDENCE_INGEST)),
    db: Session = Depends(get_db),
):
    require_csrf(request)

    selected_case_id = resolve_case_id(case_id, request)

    if selected_case_id is None:
        raise HTTPException(
            status_code=400,
            detail="A case must be selected before uploading evidence.",
        )

    case = db.query(Case).filter(Case.id == selected_case_id).first()
    if not case:
        raise HTTPException(
            status_code=404,
            detail="Selected case not found.",
        )

    results = []

    for file in files:
        original_name = Path(file.filename or "unknown").name
        suffix = Path(original_name).suffix.lower()
        category = ""
        try:
            if suffix not in ALLOWED_EXTENSIONS:
                results.append({
                    "ok": False,
                    "filename": original_name,
                    "error": f"Unsupported file type: {suffix or 'none'}",
                })
                db.add(SecurityEvent(
                    event_type="BLOCKED_FILE_TYPE",
                    severity="WARNING",
                    username=user.username,
                    detail=original_name,
                    ip_address=client_ip(request),
                ))
                audit(db, user, "BLOCKED_FILE_TYPE", original_name, "Unsupported evidence extension", request, "WARNING")
                db.commit()
                continue

            stored_name = f"{uuid4().hex}{suffix}"
            path = UPLOADS / stored_name
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
                entities, relationships, metadata = parse_structured(str(path), chosen_type, original_name)
                content = json.dumps(metadata, ensure_ascii=False, default=str)
                structured_preview = json.dumps(metadata.get("preview", []), ensure_ascii=False, default=str)
                extraction_method = f"STRUCTURED_PARSER:{metadata.get('detected_type', chosen_type)}"
            else:
                content, extraction_method = read_document(str(path))
                metadata = {"characters": len(content), "detected_type": chosen_type}
                structured_preview = ""
                known_entities = [{"key": e.key, "label": e.label, "name": e.name} for e in get_entities(db, case_id=case.id)]
                entities = extract_entities(content, known_entities)
                relationships = extract_relationships(content, known_entities)

            # Case backbone: link every extracted entity to the selected case.
            # Legacy cases created before reference IDs existed fall back to a
            # deterministic reference derived from the case id.
            case_reference = case.reference_id or f"CL-{case.id:03d}"

            create_case_backbone(
                case_reference,
                case.title,
                entities,
                relationships,
            )

            upsert_graph(
                db,
                entities,
                relationships,
                case_id=case.id,
            )

            document = Document(
                filename=original_name,
                case_id=case.id,
                doc_type=chosen_type,
                data_category=category,
                file_extension=suffix,
                file_size=size,
                extraction_method=extraction_method,
                content=content[:100000],
                structured_preview=structured_preview[:50000],
                status="INGESTED",
            )
            db.add(document)
            db.flush()
            db.add(EvidenceIntegrity(
                document_id=document.id,
                sha256=file_hash,
                file_size=size,
                stored_path=str(path),
                status="VERIFIED",
            ))
            audit(
                db,
                user,
                "EVIDENCE_INGESTED",
                original_name,
                (
                    f"case_id={case.id}; case={case_reference}; "
                    f"SHA-256: {file_hash}; entities={len(entities)}; "
                    f"relationships={len(relationships)}"
                ),
                request,
            )

            # Entity.risk is a case-blind stored aggregate, so it is refreshed here
            # as the documented "highest computed risk in any investigation". It
            # never answers a case-scoped question (graph, entity detail, assistant
            # and statistics all recompute for the active case), so refreshing it
            # cannot leak one case's risk into another case's displayed score.
            # The refresh mutates the session only; the commit below stays the
            # single transaction boundary for this file.
            refresh_stored_entity_risk(db, [case.id])

            db.commit()

            # RAG Indexing: Chunk and embed document for semantic retrieval.
            # Safe and non-blocking: per Section 30, any indexing failure must never
            # corrupt evidence integrity or roll back already-persisted evidence.
            try:
                from .services.rag_service import index_document
                index_document(db, document)
                db.commit()
            except Exception:
                db.rollback()

            for e in db.query(Entity).all():
                graph.sync_entity(e)
            for r in db.query(Relationship).all():
                graph.sync_relationship(r)

            result = {
                "ok": True,
                "filename": original_name,
                "case_id": case.id,
                "case_reference": case_reference,
                "data_category": category,
                "doc_type": chosen_type,
                "file_extension": suffix,
                "file_size": size,
                "sha256": file_hash,
                "extraction_method": extraction_method,
                "entities_added": len(entities),
                "relationships_added": len(relationships),
            }
            result.update({k: v for k, v in metadata.items() if k != "records"})
            results.append(result)
        except Exception as exc:
            if "path" in locals() and path.exists():
                path.unlink(missing_ok=True)
            db.rollback()

            error_text = str(exc) or type(exc).__name__

            # A failed ingestion must never be silent, so it is recorded the same
            # way a blocked file type is. If the audit trail itself cannot be
            # written, that is reported in the result instead of being hidden or
            # allowed to mask the original parsing error.
            try:
                audit(
                    db,
                    user,
                    "EVIDENCE_INGEST_FAILED",
                    original_name,
                    error_text[:500],
                    request,
                    "WARNING",
                )
                db.commit()
            except Exception as audit_exc:
                db.rollback()
                error_text = f"{error_text} (audit trail unavailable: {audit_exc})"

            results.append({
                "ok": False,
                "filename": original_name,
                "data_category": category if category else "",
                "error": error_text,
            })

    return {
        "ok": all(r.get("ok") for r in results) if results else False,
        "results": results,
    }


@app.post("/api/chat")
def chat(
    request: Request,
    req: ChatRequest,
    user: User = Depends(require_permission(PERM_ASSISTANT_QUERY)),
    db: Session = Depends(get_db),
):
    require_csrf(request)
    result = answer_question(db, req.question, req.case_id)
    audit(db, user, "GRAPH_QUERY", "ASSISTANT", req.question[:500], request)
    db.commit()
    return result


@app.post("/api/assistant/reindex")
def reindex_assistant(
    request: Request,
    case_id: int | None = None,
    user: User = Depends(require_permission(PERM_EVIDENCE_INGEST)),
    db: Session = Depends(get_db),
):
    require_csrf(request)
    from .services.rag_service import index_case_documents
    target_case_id = resolve_case_id(str(case_id) if case_id else None, request)
    if target_case_id is None:
        raise HTTPException(status_code=400, detail="Active case required for indexing.")
    count = index_case_documents(db, target_case_id)
    audit(db, user, "RAG_REINDEX", f"case_{target_case_id}", f"chunks_indexed={count}", request)
    db.commit()
    return {"ok": True, "case_id": target_case_id, "chunks_indexed": count}



@app.post("/api/path")
def path(
    request: Request,
    req: PathRequest,
    user: User = Depends(require_permission(PERM_GRAPH_VIEW)),
    db: Session = Depends(get_db),
):
    require_csrf(request)
    result = shortest_path(db, req.source, req.target, req.max_hops, req.case_id,)
    audit(db, user, "PATH_QUERY", f"{req.source}->{req.target}", f"max_hops={req.max_hops}", request)
    db.commit()
    return result


@app.get("/api/health")
def health():
    return {"status": "online", "application": "CrimeLens", "security": "enabled"}


@app.get("/api/security/overview")
def security_overview(
    request: Request,
    user: User = Depends(require_permission(PERM_SECURITY_VIEW)),
    db: Session = Depends(get_db),
):
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
def security_audit(
    request: Request,
    _user: User = Depends(require_permission(PERM_SECURITY_VIEW)),
    db: Session = Depends(get_db),
):
    rows = db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(100).all()
    return [{"id": x.id, "username": x.username, "role": x.role, "action": x.action, "resource": x.resource, "detail": x.detail, "ip": x.ip_address, "created_at": x.created_at.isoformat() if x.created_at else None} for x in rows]


@app.get("/api/security/events")
def security_events(
    request: Request,
    _user: User = Depends(require_permission(PERM_SECURITY_VIEW)),
    db: Session = Depends(get_db),
):
    rows = db.query(SecurityEvent).order_by(SecurityEvent.id.desc()).limit(100).all()
    return [{"id": x.id, "event_type": x.event_type, "severity": x.severity, "username": x.username, "detail": x.detail, "ip": x.ip_address, "created_at": x.created_at.isoformat() if x.created_at else None} for x in rows]


@app.get("/api/security/ledger")
def security_ledger(
    request: Request,
    _user: User = Depends(require_permission(PERM_LEDGER_VIEW)),
    db: Session = Depends(get_db),
):
    rows = db.query(BlockchainBlock).order_by(BlockchainBlock.block_index.desc()).limit(100).all()
    return [{"index": x.block_index, "event_type": x.event_type, "payload": json.loads(x.payload or "{}"), "previous_hash": x.previous_hash, "block_hash": x.block_hash, "created_at": x.created_at.isoformat() if x.created_at else None} for x in rows]


@app.post("/api/security/verify")
def security_verify(
    request: Request,
    user: User = Depends(require_permission(PERM_LEDGER_VERIFY)),
    db: Session = Depends(get_db),
):
    require_csrf(request)
    result = verify_blockchain(db)
    audit(db, user, "LEDGER_VERIFICATION", "BLOCKCHAIN_LEDGER", json.dumps(result), request, "INFO" if result["valid"] else "CRITICAL")
    db.commit()
    return result


@app.get("/api/evidence/{document_id}/download")
def download_evidence(
    document_id: int,
    request: Request,
    case_id: int | None = None,
    user: User = Depends(require_permission(PERM_EVIDENCE_VIEW)),
    db: Session = Depends(get_db),
):
    """
    Serve the original evidence bytes.

    The evidence store is private and is never exposed as static files, so this
    authorized endpoint is the only way to read stored evidence. Access requires
    the evidence:view permission, the document must exist, and an optional
    case_id must match the document's case. The storage path is resolved
    internally and is never returned to the client.
    """

    document = db.query(Document).filter(Document.id == document_id).first()
    if not document:
        raise HTTPException(status_code=404, detail="Evidence document not found")

    # Case scope: a case-scoped request must not be able to pull evidence that
    # belongs to a different case.
    if case_id is not None and document.case_id != case_id:
        audit(
            db,
            user,
            "EVIDENCE_ACCESS_DENIED",
            str(document_id),
            f"requested case_id={case_id}; document case_id={document.case_id}",
            request,
            "WARNING",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail="Evidence does not belong to the selected case.",
        )

    if document.case_id is not None:
        case = db.query(Case).filter(Case.id == document.case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

    record = (
        db.query(EvidenceIntegrity)
        .filter(EvidenceIntegrity.document_id == document_id)
        .first()
    )

    if not record:
        raise HTTPException(status_code=404, detail="Integrity record not found")

    try:
        path = resolve_storage_reference(record.stored_path)
    except ValueError:
        db.add(SecurityEvent(
            event_type="EVIDENCE_PATH_REJECTED",
            severity="CRITICAL",
            username=user.username,
            detail=f"Document {document_id}",
            ip_address=client_ip(request),
        ))
        audit(
            db,
            user,
            "EVIDENCE_ACCESS_REJECTED",
            str(document_id),
            "stored evidence reference is outside the evidence store",
            request,
            "CRITICAL",
        )
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Stored evidence reference is invalid.",
        )

    if not path.is_file():
        record.status = "MISSING"
        db.add(SecurityEvent(
            event_type="EVIDENCE_MISSING",
            severity="CRITICAL",
            username=user.username,
            detail=f"Document {document_id}",
            ip_address=client_ip(request),
        ))
        db.commit()
        raise HTTPException(status_code=404, detail="Stored evidence file is missing")

    audit(
        db,
        user,
        "EVIDENCE_DOWNLOADED",
        str(document_id),
        f"case_id={document.case_id}; file={document.filename}",
        request,
    )
    db.commit()

    media_type = (
        mimetypes.guess_type(document.filename or "")[0]
        or "application/octet-stream"
    )

    return FileResponse(
        path,
        media_type=media_type,
        filename=document.filename or f"evidence-{document_id}",
    )


@app.get("/api/evidence/{document_id}/verify")
def verify_evidence(
    document_id: int,
    request: Request,
    case_id: int | None = None,
    user: User = Depends(require_permission(PERM_EVIDENCE_VERIFY)),
    db: Session = Depends(get_db),
):
    """
    Re-hash stored evidence and compare it with the recorded SHA-256.

    Integrity is part of evidence provenance, so this endpoint is case scoped the
    same way the download endpoint is: a case-scoped request must never verify or
    report on another case's evidence. Like the download endpoint, the stored
    location is resolved through the confined resolver so a tampered database row
    cannot turn an integrity check into a way to hash arbitrary host files.
    """

    document = db.query(Document).filter(Document.id == document_id).first()
    if not document:
        raise HTTPException(status_code=404, detail="Evidence document not found")

    if case_id is not None and document.case_id != case_id:
        audit(
            db,
            user,
            "EVIDENCE_ACCESS_DENIED",
            str(document_id),
            f"requested case_id={case_id}; document case_id={document.case_id}",
            request,
            "WARNING",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail="Evidence does not belong to the selected case.",
        )

    record = db.query(EvidenceIntegrity).filter(EvidenceIntegrity.document_id == document_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Integrity record not found")

    try:
        path = resolve_storage_reference(record.stored_path)
    except ValueError:
        db.add(SecurityEvent(
            event_type="EVIDENCE_PATH_REJECTED",
            severity="CRITICAL",
            username=user.username,
            detail=f"Document {document_id}",
            ip_address=client_ip(request),
        ))
        audit(
            db,
            user,
            "EVIDENCE_ACCESS_REJECTED",
            str(document_id),
            "stored evidence reference is outside the evidence store",
            request,
            "CRITICAL",
        )
        db.commit()
        raise HTTPException(
            status_code=400,
            detail="Stored evidence reference is invalid.",
        )

    if not path.exists():
        record.status = "MISSING"
        db.add(SecurityEvent(event_type="EVIDENCE_MISSING", severity="CRITICAL", username=user.username, detail=f"Document {document_id}", ip_address=client_ip(request)))
        db.commit()
        return {"valid": False, "status": "MISSING", "sha256": record.sha256}
    actual = sha256_file(path)
    valid = hmac.compare_digest(actual, record.sha256)
    record.status = "VERIFIED" if valid else "TAMPERED"
    record.verified_at = datetime.utcnow()
    audit(db, user, "EVIDENCE_INTEGRITY_CHECK", str(document_id), f"case_id={document.case_id}; expected={record.sha256}; actual={actual}; valid={valid}", request, "INFO" if valid else "CRITICAL")
    db.commit()
    return {"valid": valid, "status": record.status, "expected_sha256": record.sha256, "actual_sha256": actual}



@app.get("/api/evidence/{document_id}/provenance")
def evidence_provenance(
    document_id: int,
    request: Request,
    case_id: int | None = None,
    _user: User = Depends(require_permission(PERM_EVIDENCE_VIEW)),
    db: Session = Depends(get_db),
):
    """
    Answer "where did this investigative information come from?" for one document.

    The chain already exists in the database (Case -> Document -> SHA-256 ->
    EvidenceIntegrity -> AuditEvent -> hash-linked ledger block), so this endpoint
    reports it instead of introducing a second provenance model. Every value is
    read from the existing rows, and the report is case scoped exactly like the
    download endpoint: a case-scoped request must never read another case's
    provenance.

    The physical storage path is never returned. The storage reference is reported
    relative to the private evidence store, and an escaping or missing reference is
    reported as invalid rather than resolved.
    """

    document = db.query(Document).filter(Document.id == document_id).first()
    if not document:
        raise HTTPException(status_code=404, detail="Evidence document not found")

    # Case scope: provenance of another case's evidence must not be readable.
    if case_id is not None and document.case_id != case_id:
        audit(
            db,
            _user,
            "EVIDENCE_ACCESS_DENIED",
            str(document_id),
            f"requested case_id={case_id}; document case_id={document.case_id}",
            request,
            "WARNING",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail="Evidence does not belong to the selected case.",
        )

    case = None
    if document.case_id is not None:
        case = db.query(Case).filter(Case.id == document.case_id).first()

    record = (
        db.query(EvidenceIntegrity)
        .filter(EvidenceIntegrity.document_id == document_id)
        .first()
    )

    stored_label, stored_valid = (
        storage_reference_label(record.stored_path) if record else ("", False)
    )

    events = document_provenance_events(db, document)

    audit_trail = []

    anchored = 0

    for event in events:

        anchor = ledger_anchor_for_audit(db, event.id)

        if anchor:
            anchored += 1

        audit_trail.append({
            "id": event.id,
            "action": event.action,
            "username": event.username,
            "role": event.role,
            "detail": event.detail,
            "ip_address": event.ip_address,
            "created_at": event.created_at.isoformat() if event.created_at else None,
            "ledger": anchor,
        })

    # The stored file is only checked for presence here; re-hashing is the job of
    # the dedicated integrity verification endpoint.
    file_present = False

    if stored_valid:
        try:
            file_present = resolve_storage_reference(record.stored_path).is_file()
        except ValueError:
            file_present = False

    integrity_status = record.status if record else "NOT_CHECKED"

    chain = [
        {
            "step": "case",
            "status": "LINKED" if case else "UNLINKED",
            "detail": (
                f"{case.reference_id or '-'} · {case.title}"
                if case
                else "No case is linked to this evidence"
            ),
        },
        {
            "step": "document",
            "status": "RECORDED",
            "detail": f"Document #{document.id} · {document.filename}",
        },
        {
            "step": "storage",
            "status": "AVAILABLE" if file_present else "UNAVAILABLE",
            "detail": stored_label or "No valid storage reference",
        },
        {
            "step": "hash",
            "status": "RECORDED" if record else "MISSING",
            "detail": (
                f"SHA-256 {record.sha256}" if record else "No SHA-256 fingerprint"
            ),
        },
        {
            "step": "integrity",
            "status": integrity_status,
            "detail": (
                f"Verified at {record.verified_at.isoformat()}"
                if record and record.verified_at
                else "Not yet verified"
            ),
        },
        {
            "step": "audit",
            "status": "RECORDED" if audit_trail else "MISSING",
            "detail": f"{len(audit_trail)} audit entries · {anchored} anchored in the ledger",
        },
    ]

    return {
        "document_id": document.id,
        "case": {
            "case_id": document.case_id,
            "reference_id": case.reference_id if case else None,
            "title": case.title if case else None,
            "status": case.status if case else None,
        },
        "document": {
            "id": document.id,
            "filename": document.filename,
            "doc_type": document.doc_type,
            "data_category": document.data_category,
            "file_extension": document.file_extension,
            "file_size": document.file_size,
            "extraction_method": document.extraction_method,
            "status": document.status,
            "ingested_at": document.created_at.isoformat() if document.created_at else None,
        },
        "integrity": {
            "algorithm": "SHA-256",
            "sha256": record.sha256 if record else None,
            "file_size": record.file_size if record else None,
            "status": integrity_status,
            "verified_at": (
                record.verified_at.isoformat()
                if record and record.verified_at
                else None
            ),
            "storage_reference": stored_label or None,
            "storage_reference_valid": stored_valid,
            "file_present": file_present,
        },
        "chain": chain,
        "audit_trail": audit_trail,
    }


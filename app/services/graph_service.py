from collections import deque
import re
from urllib.parse import quote
from uuid import uuid4

from sqlalchemy.orm import Session

from ..models import Entity, Relationship
from ..config import (
    USE_NEO4J,
    NEO4J_URI,
    NEO4J_USER,
    NEO4J_PASSWORD,
    NEO4J_DATABASE,
)
from .risk_service import compute_case_risk_from_rows


# ============================================================
# ENTITY NORMALIZATION
# ============================================================

def normalize_name(value: str) -> str:
    """
    Normalize person or entity name:
    - lowercase
    - trim whitespace
    - collapse repeated whitespace
    - strip punctuation (dots in initials like 'R. Kumar' -> 'R Kumar', commas, quotes)
    """
    if not value:
        return ""
    text = str(value).strip().lower()
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def normalize_phone(value: str) -> str:
    """
    Normalize phone number:
    - extract digits only
    - strip Indian country code prefix 91 if 12 digits
    """
    if not value:
        return ""
    digits = re.sub(r"\D", "", str(value))
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    return digits


def normalize_email(value: str) -> str:
    """
    Normalize email:
    - lowercase
    - strip whitespace
    """
    if not value:
        return ""
    return str(value).strip().lower()


def normalize_account(value: str) -> str:
    """
    Normalize bank account identifier:
    - uppercase alphanumeric only
    """
    if not value:
        return ""
    return re.sub(r"[^A-Z0-9]", "", str(value).strip().upper())


def normalize_vehicle(value: str) -> str:
    """
    Normalize vehicle registration number:
    - uppercase alphanumeric only
    """
    if not value:
        return ""
    return re.sub(r"[^A-Z0-9]", "", str(value).strip().upper())


def normalize_identity(label, value):
    """
    Convert different representations of the same entity
    into a comparable identity according to its entity type.
    """
    lbl = str(label or "Entity").strip().lower()
    if "phone" in lbl or "mobile" in lbl:
        return normalize_phone(value)
    if "account" in lbl or "bank" in lbl:
        return normalize_account(value)
    if "vehicle" in lbl:
        return normalize_vehicle(value)
    if "email" in lbl:
        return normalize_email(value)
    if "person" in lbl:
        return normalize_name(value)
    return str(value or "").strip().lower()


def entity_identity(entity):
    return normalize_identity(
        entity.get("label"),
        entity.get("name")
    )


def database_entity_identity(entity):
    return normalize_identity(
        entity.label,
        entity.name
    )


# ============================================================
# ENTITY PHOTO ACCESS
# ============================================================

def entity_photo_url(entity_key, image_path=None):
    """
    Return the authenticated API URL for an entity's stored profile image.
    """
    if not image_path:
        return ""

    return f"/api/entity/{quote(str(entity_key), safe='')}/photo"


# ============================================================
# CASE-SCOPED ENTITIES QUERY
# ============================================================

def get_case_entities(db: Session, case_id=None):
    """
    Query entities that belong to the specified case_id.
    Derives case membership from case-scoped relationships and entity.case_id.
    """
    if case_id is None:
        return db.query(Entity).all()

    rel_rows = (
        db.query(Relationship.source, Relationship.target)
        .filter(Relationship.case_id == case_id)
        .all()
    )

    keys = set()
    for s, t in rel_rows:
        if s:
            keys.add(s)
        if t:
            keys.add(t)

    conditions = [Entity.case_id == case_id]
    if keys:
        conditions.append(Entity.key.in_(keys))

    return (
        db.query(Entity)
        .filter(
            conditions[0] if len(conditions) == 1 else (conditions[0] | conditions[1])
        )
        .all()
    )


# ============================================================
# DETERMINISTIC MULTI-SIGNAL ENTITY RESOLUTION
# ============================================================

def resolve_existing_entity(db: Session, incoming_entity: dict, case_id=None, batch_relationships=None):
    """
    Deterministic multi-signal entity resolution strictly respecting case isolation.

    Returns: tuple (matched_entity_or_None, status_str, reason_str)
    Statuses:
        - EXACT_MATCH: Strong identifier match or same name + strong identifier.
        - PROBABLE_MATCH: Strong contextual match (e.g. location/org).
        - AMBIGUOUS: Same name only; retained as separate entity without merging.
        - NEW_ENTITY: New entity with no matching candidates.
    """
    label = str(incoming_entity.get("label") or "Entity").strip()
    norm_label = label.lower()

    # 1. Candidate search strictly scoped to the active case
    candidates = get_case_entities(db, case_id=case_id)
    same_type_cands = [c for c in candidates if str(c.label).lower() == norm_label]

    # Extract incoming signals
    inc_name = incoming_entity.get("name") or ""
    norm_inc_name = normalize_name(inc_name)
    inc_phone = normalize_phone(incoming_entity.get("phone") or "")
    inc_email = normalize_email(incoming_entity.get("email") or "")
    inc_account = normalize_account(incoming_entity.get("account") or "")
    inc_vehicle = normalize_vehicle(incoming_entity.get("vehicle") or "")
    inc_id = str(incoming_entity.get("identifier") or incoming_entity.get("id") or "").strip().upper()

    # Extract related signals from batch_relationships if available
    inc_key = incoming_entity.get("key")
    if batch_relationships and inc_key:
        for r in batch_relationships:
            other = None
            if r.get("source") == inc_key:
                other = r.get("target")
            elif r.get("target") == inc_key:
                other = r.get("source")
            if other and ":" in other:
                prefix, val = other.split(":", 1)
                if prefix == "PHONE" and not inc_phone:
                    inc_phone = normalize_phone(val)
                elif prefix == "ACCOUNT" and not inc_account:
                    inc_account = normalize_account(val)
                elif prefix == "VEHICLE" and not inc_vehicle:
                    inc_vehicle = normalize_vehicle(val)

    # -------------------------------------------------------------
    # NON-PERSON ENTITY RESOLUTION
    # -------------------------------------------------------------
    if "person" not in norm_label:
        norm_val = normalize_identity(label, incoming_entity.get("name") or incoming_entity.get("key"))
        for cand in same_type_cands:
            cand_val = normalize_identity(cand.label, cand.name or cand.key)
            if cand_val and cand_val == norm_val:
                return (cand, "EXACT_MATCH", f"Matched exact normalized {label.lower()} identifier")
        return (None, "NEW_ENTITY", f"New {label.lower()} entity")

    # -------------------------------------------------------------
    # PERSON RESOLUTION
    # -------------------------------------------------------------
    # Build candidate signal maps from candidate attributes and case relationships
    cand_phone_map = {}
    cand_account_map = {}
    cand_vehicle_map = {}

    if case_id is not None:
        rel_records = db.query(Relationship).filter(Relationship.case_id == case_id).all()
        for rel in rel_records:
            for c in same_type_cands:
                other = None
                if rel.source == c.key:
                    other = rel.target
                elif rel.target == c.key:
                    other = rel.source
                if other and ":" in other:
                    pfx, pval = other.split(":", 1)
                    if pfx == "PHONE":
                        cand_phone_map.setdefault(c.id, set()).add(normalize_phone(pval))
                    elif pfx == "ACCOUNT":
                        cand_account_map.setdefault(c.id, set()).add(normalize_account(pval))
                    elif pfx == "VEHICLE":
                        cand_vehicle_map.setdefault(c.id, set()).add(normalize_vehicle(pval))

    strong_matches = []
    different_identifier_cands = []
    name_only_cands = []

    for cand in same_type_cands:
        cand_norm_name = normalize_name(cand.name)

        c_phones = set()
        if cand.phone:
            c_phones.add(normalize_phone(cand.phone))
        c_phones.update(cand_phone_map.get(cand.id, set()))
        c_phones.discard("")

        c_emails = set()
        if cand.email:
            c_emails.add(normalize_email(cand.email))
        c_emails.discard("")

        c_accounts = set()
        if cand.account:
            c_accounts.add(normalize_account(cand.account))
        c_accounts.update(cand_account_map.get(cand.id, set()))
        c_accounts.discard("")

        c_vehicles = set()
        if cand.vehicle:
            c_vehicles.add(normalize_vehicle(cand.vehicle))
        c_vehicles.update(cand_vehicle_map.get(cand.id, set()))
        c_vehicles.discard("")

        c_id = str(cand.identifier or "").strip().upper()

        # Check STRONG IDENTIFIERS
        matched_strong = []
        if inc_phone and inc_phone in c_phones:
            matched_strong.append(f"phone number ({inc_phone})")
        if inc_email and inc_email in c_emails:
            matched_strong.append(f"email ({inc_email})")
        if inc_account and inc_account in c_accounts:
            matched_strong.append(f"account number ({inc_account})")
        if inc_vehicle and inc_vehicle in c_vehicles:
            matched_strong.append(f"vehicle ({inc_vehicle})")
        if inc_id and c_id and inc_id == c_id:
            matched_strong.append(f"unique identifier ({inc_id})")

        if matched_strong:
            if norm_inc_name and norm_inc_name == cand_norm_name:
                strong_matches.append((cand, f"Matched because normalized name and {', '.join(matched_strong)} are identical"))
            else:
                strong_matches.append((cand, f"Matched because {', '.join(matched_strong)} is identical"))
            continue

        # Check if name matches, but identifiers conflict or are missing
        if norm_inc_name and norm_inc_name == cand_norm_name:
            has_conflict = False
            if inc_phone and c_phones and inc_phone not in c_phones:
                has_conflict = True
                different_identifier_cands.append((cand, f"Name matches existing entity but phone number differs ({inc_phone} vs {list(c_phones)[0]}); treated as distinct person"))
            elif inc_email and c_emails and inc_email not in c_emails:
                has_conflict = True
                different_identifier_cands.append((cand, f"Name matches existing entity but email differs ({inc_email} vs {list(c_emails)[0]}); treated as distinct person"))
            elif inc_account and c_accounts and inc_account not in c_accounts:
                has_conflict = True
                different_identifier_cands.append((cand, f"Name matches existing entity but account differs ({inc_account} vs {list(c_accounts)[0]}); treated as distinct person"))
            elif inc_vehicle and c_vehicles and inc_vehicle not in c_vehicles:
                has_conflict = True
                different_identifier_cands.append((cand, f"Name matches existing entity but vehicle registration differs ({inc_vehicle} vs {list(c_vehicles)[0]}); treated as distinct person"))
            elif inc_id and c_id and inc_id != c_id:
                has_conflict = True
                different_identifier_cands.append((cand, f"Name matches existing entity but identifier differs ({inc_id} vs {c_id}); treated as distinct person"))

            if not has_conflict:
                name_only_cands.append((cand, "Name matches but no unique identifier was found; treated as separate entity"))

    # Strong match found -> EXACT_MATCH
    if strong_matches:
        cand, reason = strong_matches[0]
        return (cand, "EXACT_MATCH", reason)

    # Conflicting identifier -> separate NEW_ENTITY
    if different_identifier_cands:
        cand, reason = different_identifier_cands[0]
        return (None, "NEW_ENTITY", reason)

    # Name-only match with no strong identifiers -> AMBIGUOUS (do NOT merge)
    if name_only_cands:
        cand, reason = name_only_cands[0]
        return (None, "AMBIGUOUS", reason)

    return (None, "NEW_ENTITY", "New person entity detected")



# ============================================================
# GRAPH SERVICE
# ============================================================

class GraphService:

    def __init__(self):

        self.driver = None

        if USE_NEO4J:

            try:

                from neo4j import GraphDatabase

                self.driver = GraphDatabase.driver(
                    NEO4J_URI,
                    auth=(
                        NEO4J_USER,
                        NEO4J_PASSWORD
                    )
                )

            except Exception:

                self.driver = None

    def close(self):

        if self.driver:
            self.driver.close()

    def sync_entity(self, entity):

        if not self.driver:
            return

        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            session.run(
                """
                MERGE (n {key:$key})
                SET
                    n.label=$label,
                    n.name=$name,
                    n.risk=$risk
                """,
                key=entity.key,
                label=entity.label,
                name=entity.name,
                risk=entity.risk,
            )

    def sync_relationship(self, rel):

        if not self.driver:
            return

        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            relation_type = "".join(
                ch
                if ch.isalnum() or ch == "_"
                else "_"
                for ch in rel.relation.upper()
            )

            query = f"""
            MATCH (a {{key:$source}})
            MATCH (b {{key:$target}})
            MERGE (a)-[r:{relation_type}]->(b)
            SET
                r.timestamp=$timestamp,
                r.amount=$amount
            """

            session.run(
                query,
                source=rel.source,
                target=rel.target,
                timestamp=rel.timestamp,
                amount=rel.amount,
            )

    def cypher_query(
        self,
        query,
        params=None
    ):

        if not self.driver:
            return []

        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            return [
                dict(record)
                for record in session.run(
                    query,
                    params or {}
                )
            ]


# ============================================================
# UPSERT GRAPH
# ============================================================

def upsert_graph(
    db: Session,
    entities,
    relationships,
    case_id=None,
):

    # Maps temporary incoming keys
    # to canonical database keys.
    key_mapping = {}

    # --------------------------------------------------------
    # ENTITIES
    # --------------------------------------------------------

    for incoming in entities:

        incoming_key = incoming.get("key") or incoming.get("id")

        if not incoming_key:
            continue

        existing_match, status, reason = resolve_existing_entity(
            db,
            incoming,
            case_id=case_id,
            batch_relationships=relationships,
        )

        if existing_match:

            # Re-use the existing entity key
            key_mapping[incoming_key] = existing_match.key

            # Update attributes if incoming has new ones
            for attr, norm_fn in [
                ("phone", normalize_phone),
                ("email", normalize_email),
                ("account", normalize_account),
                ("vehicle", normalize_vehicle),
                ("identifier", lambda v: str(v or "").strip().upper()),
            ]:
                val = incoming.get(attr)
                if val and not getattr(existing_match, attr, None):
                    setattr(existing_match, attr, norm_fn(str(val)))

            existing_match.resolution_status = status
            existing_match.match_reason = reason

        else:

            # Target key: if incoming_key is already in db from another case or person, generate a scoped unique key
            target_key = incoming_key
            already_in_db = (
                db.query(Entity)
                .filter(Entity.key == target_key)
                .first()
            )

            if already_in_db is not None:
                clean_name = re.sub(r'[^A-Za-z0-9_]', '', incoming.get("name", "entity")).upper()[:12]
                prefix = incoming_key.split(":", 1)[0] if ":" in incoming_key else "ENTITY"
                target_key = f"{prefix}:C{case_id or 0}_{clean_name}_{uuid4().hex[:6]}"

            label = incoming.get(
                "label",
                "Entity"
            )
            name = incoming.get(
                "name",
                incoming_key
            )

            raw_id = incoming.get("identifier")
            clean_id = str(raw_id).strip().upper() if raw_id else None

            obj = Entity(
                key=target_key,
                label=label,
                name=name,
                risk=0,
                case_id=case_id,
                phone=normalize_phone(incoming.get("phone") or "") or None,
                email=normalize_email(incoming.get("email") or "") or None,
                account=normalize_account(incoming.get("account") or "") or None,
                vehicle=normalize_vehicle(incoming.get("vehicle") or "") or None,
                identifier=clean_id,
                resolution_status=status,
                match_reason=reason,
            )

            db.add(obj)
            db.flush()

            key_mapping[incoming_key] = obj.key

    # --------------------------------------------------------
    # RELATIONSHIPS
    # --------------------------------------------------------

    for incoming_relation in relationships:

        source = incoming_relation.get(
            "source"
        )

        target = incoming_relation.get(
            "target"
        )

        if not source or not target:
            continue

        canonical_source = key_mapping.get(
            source,
            source
        )

        canonical_target = key_mapping.get(
            target,
            target
        )

        if canonical_source == canonical_target:
            continue

        # Avoid duplicate identical relationships inside the same case.
        # The case_id filter is required: without it, an identical
        # relation in a different case would be silently skipped and that
        # case's graph would lose the edge.
        existing_relation = (
            db.query(Relationship)
            .filter(
                Relationship.case_id == case_id,
                Relationship.source == canonical_source,
                Relationship.target == canonical_target,
                Relationship.relation ==
                incoming_relation.get(
                    "relation",
                    "RELATED_TO"
                ),
                Relationship.timestamp ==
                incoming_relation.get(
                    "timestamp",
                    ""
                ),
            )
            .first()
        )

        if existing_relation:
            continue

        db.add(
            Relationship(
                source=canonical_source,
                target=canonical_target,
                relation=incoming_relation.get(
                    "relation",
                    "RELATED_TO",
                ),
                timestamp=incoming_relation.get(
                    "timestamp",
                    "",
                ),
                amount=incoming_relation.get(
                    "amount"
                ),
                case_id=case_id,
            )
        )

    # Mutates the session and flushes keys, but never commits:
    # the outer caller (e.g. upload transaction) controls transaction boundaries.
    db.flush()


# ============================================================
# GRAPH PAYLOAD
# ============================================================

def graph_payload(db: Session, case_id=None):

    # --------------------------------------------------------
    # CASE-SCOPED RELATIONSHIPS
    # --------------------------------------------------------

    relationship_query = db.query(Relationship)

    if case_id is not None:
        relationship_query = relationship_query.filter(
            Relationship.case_id == case_id
        )

    relationships = relationship_query.all()

    # --------------------------------------------------------
    # FIND ENTITIES BELONGING TO THE SELECTED GRAPH
    # --------------------------------------------------------

    entity_keys = set()

    for relationship in relationships:
        entity_keys.add(relationship.source)
        entity_keys.add(relationship.target)

    # --------------------------------------------------------
    # LOAD ONLY GRAPH ENTITIES
    # --------------------------------------------------------

    entity_query = db.query(Entity)

    if entity_keys:
        entity_query = entity_query.filter(
            Entity.key.in_(entity_keys)
        )
    else:
        entity_query = entity_query.filter(False)

    entities = entity_query.all()

    # --------------------------------------------------------
    # COMPUTED RISK (CASE SCOPED)
    # --------------------------------------------------------
    risk_report = compute_case_risk_from_rows(
        entities,
        relationships,
        case_id=case_id,
    )

    entity_risk = risk_report["entities"]

    # --------------------------------------------------------
    # BUILD NODES
    # --------------------------------------------------------

    nodes = []

    for entity in entities:

        risk_entry = entity_risk.get(entity.key) or {}

        nodes.append({
            "data": {
                "id": entity.key,
                "label": entity.label,
                "name": entity.name,
                "risk": risk_entry.get("score", 0.0),
                "risk_band": risk_entry.get("band", "UNSCORED"),
                "risk_basis": risk_entry.get(
                    "basis",
                    "STORED_CROSS_CASE_AGGREGATE",
                ),
                "resolution_status": getattr(entity, "resolution_status", None) or "NEW_ENTITY",
                "match_reason": getattr(entity, "match_reason", None) or "",
                "phone": getattr(entity, "phone", None) or "",
                "email": getattr(entity, "email", None) or "",
                "account": getattr(entity, "account", None) or "",
                "vehicle": getattr(entity, "vehicle", None) or "",
                "identifier": getattr(entity, "identifier", None) or "",
                "image": entity_photo_url(
                    entity.key,
                    getattr(entity, "image_path", "")
                ),
            }
        })

    # --------------------------------------------------------
    # BUILD EDGES
    # --------------------------------------------------------

    edges = []

    for relationship in relationships:
        edges.append({
            "data": {
                "id": str(relationship.id),
                "source": relationship.source,
                "target": relationship.target,
                "relation": relationship.relation,
                "timestamp": relationship.timestamp,
                "amount": relationship.amount,
                "case_id": relationship.case_id,
            }
        })

    return {
        "nodes": nodes,
        "edges": edges,
    }


# ============================================================
# SHORTEST PATH
# ============================================================

def shortest_path(
    db: Session,
    source,
    target,
    max_hops=5,
    case_id=None,
):

    relationship_query = db.query(Relationship)

    if case_id is not None:
        relationship_query = relationship_query.filter(
            Relationship.case_id == case_id
        )

    relationships = relationship_query.all()

    adjacency = {}

    for relationship in relationships:

        adjacency.setdefault(
            relationship.source,
            []
        ).append(
            (
                relationship.target,
                relationship.relation
            )
        )

        adjacency.setdefault(
            relationship.target,
            []
        ).append(
            (
                relationship.source,
                relationship.relation
            )
        )

    queue = deque([
        (
            source,
            [source],
            []
        )
    ])

    seen = {source}

    while queue:

        node, path, relation_path = (
            queue.popleft()
        )

        if node == target:

            return {
                "nodes": path,
                "relations": relation_path
            }

        if len(path) - 1 >= max_hops:
            continue

        for next_node, relation in adjacency.get(
            node,
            []
        ):

            if next_node in seen:
                continue

            seen.add(next_node)

            queue.append(
                (
                    next_node,
                    path + [next_node],
                    relation_path + [relation]
                )
            )

    return {
        "nodes": [],
        "relations": []
    }
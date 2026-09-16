from collections import deque
import re
from urllib.parse import quote

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

def normalize_identity(label, value):
    """
    Convert different representations of the same entity
    into a comparable identity.

    Examples:

        +91 9000000001
        919000000001
        9000000001

    all become:

        9000000001
    """

    value = str(value or "").strip().upper()

    if label == "PhoneNumber":
        digits = re.sub(r"\D", "", value)

        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]

        return digits

    if label == "BankAccount":
        return re.sub(
            r"[^A-Z0-9]",
            "",
            value
        )

    if label == "Vehicle":
        return re.sub(
            r"[^A-Z0-9]",
            "",
            value
        )

    return value.strip().lower()


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

    Evidence storage is private: the uploads directory is deliberately not
    served as static files, so photographs are only reachable through the
    authorized /api/entity/{key}/photo endpoint. Rows written by earlier
    versions may still hold the old public "/uploads/persons/..." value; the
    stored string is therefore only treated as a flag meaning "a photograph
    exists" and is never handed to the browser as a URL.
    """

    if not image_path:
        return ""

    return f"/api/entity/{quote(str(entity_key), safe='')}/photo"


# ============================================================
# ENTITY RESOLUTION
# ============================================================

def resolve_existing_entity(db, incoming_entity):

    label = incoming_entity.get("label")
    identity = entity_identity(incoming_entity)

    if not label or not identity:
        return None

    existing_entities = (
        db.query(Entity)
        .filter(Entity.label == label)
        .all()
    )

    for existing in existing_entities:

        existing_identity = database_entity_identity(
            existing
        )

        if existing_identity == identity:
            return existing

    return None


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

        incoming_key = incoming.get("key")

        if not incoming_key:
            continue

        # The canonical key is authoritative: the same identifier seen again -
        # even with a different display name in a later document, such as
        # "PH001" versus "9000000001" - is the same entity and must be reused.
        # Inserting it again would violate the unique key and abort the whole
        # ingestion. Resolution by identity below therefore only runs for keys
        # that are not stored yet.
        existing = (
            db.query(Entity)
            .filter(Entity.key == incoming_key)
            .first()
        )

        if not existing:

            existing = resolve_existing_entity(
                db,
                incoming
            )

        if existing:

            # IMPORTANT:
            # Reuse the Entity Master key.
            key_mapping[incoming_key] = existing.key

        else:

            obj = Entity(
                key=incoming_key,
                label=incoming.get(
                    "label",
                    "Entity"
                ),
                name=incoming.get(
                    "name",
                    incoming_key
                ),
                risk=0,
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

    db.commit()


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
    # Risk is recomputed from this case's own graph rather than read from
    # Entity.risk. That column is case blind, so a canonical entity such as a
    # phone number shared with another case would otherwise display a score
    # influenced by that other case. compute_case_risk_from_rows never reads the
    # column, the clock or a random source, so the same graph always yields the
    # same score, and every point is attributable to a named factor.

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
                # Never emit a storage path or a public uploads URL: the
                # browser only receives the authorized photo endpoint.
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
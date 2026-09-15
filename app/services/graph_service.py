from collections import deque
import re

from sqlalchemy.orm import Session

from ..models import Entity, Relationship
from ..config import (
    USE_NEO4J,
    NEO4J_URI,
    NEO4J_USER,
    NEO4J_PASSWORD,
    NEO4J_DATABASE,
)


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
    relationships
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

        # Avoid duplicate identical relationships.
        existing_relation = (
            db.query(Relationship)
            .filter(
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
                    "RELATED_TO"
                ),
                timestamp=incoming_relation.get(
                    "timestamp",
                    ""
                ),
                amount=incoming_relation.get(
                    "amount"
                ),
            )
        )

    db.commit()


# ============================================================
# GRAPH PAYLOAD
# ============================================================

def graph_payload(db: Session):

    nodes = []

    for entity in db.query(Entity).all():

        nodes.append({
            "data": {
                "id": entity.key,
                "label": entity.label,
                "name": entity.name,
                "risk": entity.risk,
                "image": getattr(
                    entity,
                    "image_path",
                    ""
                ) or "",
            }
        })

    edges = []

    for relationship in db.query(
        Relationship
    ).all():

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
        "edges": edges
    }


# ============================================================
# SHORTEST PATH
# ============================================================

def shortest_path(
    db: Session,
    source,
    target,
    max_hops=5
):

    relationships = (
        db.query(Relationship)
        .all()
    )

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
import json
import re

from ..config import OPENAI_API_KEY, OPENAI_MODEL
from ..models import Entity, Relationship, Document, Case
from .risk_service import risk_band, risk_scores_for_rows


# ============================================================
# BASIC HELPERS
# ============================================================

def normalize_text(value):
    return str(value or "").strip().lower()


def clean_text(value):
    return re.sub(r"\s+", " ", str(value or "").strip())


def entity_display_name(entity):
    return entity.name or entity.key


# ============================================================
# DATABASE LOADERS
# ============================================================

def get_entities(db, case_id=None):
    # Entity currently has no case_id column, so case ownership is derived
    # through case-scoped relationships - the same rule used by graph_payload.
    if case_id is None:
        return db.query(Entity).all()

    rows = (
        db.query(Relationship.source, Relationship.target)
        .filter(Relationship.case_id == case_id)
        .all()
    )

    keys = set()

    for source, target in rows:
        if source:
            keys.add(source)

        if target:
            keys.add(target)

    if not keys:
        return []

    return (
        db.query(Entity)
        .filter(Entity.key.in_(keys))
        .all()
    )


def get_relationships(db, case_id=None):
    query = db.query(Relationship)

    if case_id is not None:
        query = query.filter(Relationship.case_id == case_id)

    return query.all()


def get_documents(db, case_id=None):
    query = db.query(Document)

    if case_id is not None:
        query = query.filter(Document.case_id == case_id)

    return (
        query
        .order_by(Document.id.asc())
        .all()
    )


def get_cases(db):
    return db.query(Case).all()


# ============================================================
# GRAPH ANALYSIS
# ============================================================

def calculate_degrees(relationships):
    degree = {}

    for r in relationships:
        degree[r.source] = degree.get(r.source, 0) + 1
        degree[r.target] = degree.get(r.target, 0) + 1

    return degree


def relationship_to_dict(r):
    return {
        "source": r.source,
        "target": r.target,
        "relation": r.relation,
        "timestamp": r.timestamp or "",
        "amount": r.amount,
    }


def entity_to_dict(entity, degree=None):
    result = {
        "key": entity.key,
        "name": entity.name,
        "label": entity.label,
    }

    if degree is not None:
        result["degree"] = degree

    return result


def find_entities(db, question):
    """
    Find entities mentioned in the user's question.

    Supports:
    - Entity ID
    - entity key
    - full name
    - partial name
    - phone number
    - account number
    - vehicle number
    """

    q = normalize_text(question)

    entities = get_entities(db)

    exact = []

    for entity in entities:

        name = normalize_text(entity.name)
        key = normalize_text(entity.key)

        if name and name in q:
            exact.append(entity)
            continue

        if key and key in q:
            exact.append(entity)
            continue

    if exact:
        return exact

    # Partial matching
    partial = []

    for entity in entities:

        name = normalize_text(entity.name)

        if not name:
            continue

        tokens = name.split()

        for token in tokens:

            if len(token) >= 4 and token in q:
                partial.append(entity)
                break

    return partial


def get_connected_entities(db, entity_keys,case_id=None):
    relationships = get_relationships(db,case_id)
    entities = get_entities(db,case_id)

    entity_map = {
        e.key: e
        for e in entities
    }

    connected_keys = set()
    matching_relationships = []

    for r in relationships:

        if r.source in entity_keys:

            connected_keys.add(r.target)
            matching_relationships.append(r)

        elif r.target in entity_keys:

            connected_keys.add(r.source)
            matching_relationships.append(r)

    connected_entities = []

    for key in connected_keys:

        entity = entity_map.get(key)

        if entity:
            connected_entities.append(entity)

    return connected_entities, matching_relationships


# ============================================================
# GRAPH SUMMARY
# ============================================================

def build_graph_summary(db,case_id=None):

    entities = get_entities(db,case_id)
    relationships = get_relationships(db,case_id)
    documents = get_documents(db,case_id)
    cases = get_cases(db)

    degree = calculate_degrees(relationships)

    label_counts = {}

    for entity in entities:

        label = entity.label or "Entity"

        label_counts[label] = (
            label_counts.get(label, 0) + 1
        )

    ranked_entities = sorted(
        entities,
        key=lambda e: degree.get(e.key, 0),
        reverse=True
    )

    return {
        "total_entities": len(entities),
        "total_relationships": len(relationships),
        "total_documents": len(documents),
        "total_cases": len(cases),
        "entity_types": label_counts,
        "most_connected": [
            {
                "name": e.name,
                "label": e.label,
                "key": e.key,
                "degree": degree.get(e.key, 0),
            }
            for e in ranked_entities[:10]
        ],
    }


# ============================================================
# DOCUMENT SEARCH
# ============================================================

def search_documents(db, question, limit=5, case_id=None):

    q = normalize_text(question)

    if not q:
        return []

    documents = get_documents(db,case_id)

    results = []

    # Extract useful search words
    words = [
        w
        for w in re.findall(r"[a-zA-Z0-9]+", q)
        if len(w) >= 3
    ]

    for document in documents:

        content = clean_text(document.content)

        if not content:
            continue

        content_lower = content.lower()

        score = 0

        for word in words:

            if word in content_lower:
                score += 1

        if score == 0:
            continue

        results.append(
            (
                score,
                document,
            )
        )

    results.sort(
        key=lambda item: item[0],
        reverse=True
    )

    return [
        document
        for _, document in results[:limit]
    ]


def make_document_snippet(document, question):

    content = clean_text(document.content)

    if not content:
        return ""

    q = normalize_text(question)

    words = [
        w
        for w in re.findall(r"[a-zA-Z0-9]+", q)
        if len(w) >= 4
    ]

    lower_content = content.lower()

    position = -1

    for word in words:

        position = lower_content.find(word)

        if position >= 0:
            break

    if position < 0:
        return content[:800]

    start = max(0, position - 300)
    end = min(
        len(content),
        position + 700
    )

    return content[start:end]


# ============================================================
# CASE / INCIDENT SUPPORT
# ============================================================

def find_current_case(db):

    entities = get_entities(db)

    # Prefer explicit Incident
    incident = [
        e
        for e in entities
        if normalize_text(e.label) == "incident"
    ]

    if incident:
        return incident

    # Otherwise use the current CrimeLens case
    case_entities = [
        e
        for e in entities
        if normalize_text(e.label) == "case"
    ]

    preferred = [
        e
        for e in case_entities
        if (
            "blue lantern" in normalize_text(e.name)
            or "cl-001" in normalize_text(e.key)
        )
    ]

    if preferred:
        return preferred

    return case_entities[:1]


# ============================================================
# LOCAL FREE-FORM ANSWER
# ============================================================

def local_freeform_answer(db, question,case_id=None):

    q = normalize_text(question)

    entities = get_entities(db,case_id)
    relationships = get_relationships(db,case_id)
    documents = get_documents(db,case_id)

    degree = calculate_degrees(relationships)

    # --------------------------------------------------------
    # EMPTY DATABASE
    # --------------------------------------------------------

    if not entities and not documents:

        return {
            "mode": "LOCAL_GRAPH",
            "answer": (
                "There is currently no evidence available "
                "to analyze."
            ),
            "entities": [],
            "relationships": [],
        }

    # --------------------------------------------------------
    # SUMMARY / OVERVIEW
    # --------------------------------------------------------

    summary_words = [
        "summarize",
        "summary",
        "overview",
        "brief",
        "give me an overview",
        "give me a summary",
        "what do we know",
        "what is this case about",
    ]

    if any(word in q for word in summary_words):

        graph_summary = build_graph_summary(db, case_id)

        entity_types = ", ".join(
            f"{k}: {v}"
            for k, v in graph_summary["entity_types"].items()
        )

        top_entities = graph_summary["most_connected"][:5]

        top_text = "\n".join(
            f"- {e['name']} ({e['label']}) — "
            f"{e['degree']} connections"
            for e in top_entities
        )

        document_names = [
            d.filename
            for d in documents[:10]
        ]

        answer = (
            "CrimeLens Evidence Summary\n\n"
            f"Entities: {graph_summary['total_entities']}\n"
            f"Relationships: {graph_summary['total_relationships']}\n"
            f"Evidence documents: {graph_summary['total_documents']}\n\n"
            f"Entity types: {entity_types or 'None'}\n\n"
            "Most connected entities:\n"
            f"{top_text or '- None'}\n\n"
            "Evidence sources:\n"
            + (
                "\n".join(
                    f"- {name}"
                    for name in document_names
                )
                if document_names
                else "- None"
            )
        )

        return {
            "mode": "LOCAL_GRAPH",
            "answer": answer,
            "entities": [
                entity_to_dict(
                    e,
                    degree.get(e.key, 0)
                )
                for e in entities
            ],
            "relationships": [],
        }

    # --------------------------------------------------------
    # MOST CONNECTED
    # --------------------------------------------------------

    if (
        "most connected" in q
        or "highest degree" in q
        or "most connections" in q
    ):

        ranked = sorted(
            entities,
            key=lambda e: degree.get(e.key, 0),
            reverse=True,
        )[:10]

        lines = []

        for index, entity in enumerate(
            ranked,
            start=1
        ):

            lines.append(
                f"{index}. {entity.name} "
                f"({entity.label}) — "
                f"{degree.get(entity.key, 0)} connections"
            )

        return {
            "mode": "LOCAL_GRAPH",
            "answer": (
                "Most connected entities:\n\n"
                + "\n".join(lines)
            ),
            "entities": [
                entity_to_dict(
                    e,
                    degree.get(e.key, 0)
                )
                for e in ranked
            ],
            "relationships": [],
        }

    # --------------------------------------------------------
    # PHONE / COMMUNICATION
    # --------------------------------------------------------

    if (
        "communication" in q
        or "phone calls" in q
        or "call activity" in q
        or "phone network" in q
        or "calls" in q
    ):

        phone_keys = {
            e.key
            for e in entities
            if normalize_text(e.label)
            == "phonenumber"
        }

        phone_relationships = [
            r
            for r in relationships
            if (
                r.relation == "CALL_MADE_TO"
                and r.source in phone_keys
                and r.target in phone_keys
            )
        ]

        involved = set()

        for r in phone_relationships:

            involved.add(r.source)
            involved.add(r.target)

        phone_entities = [
            entity_to_dict(e)
            for e in entities
            if e.key in involved
        ]

        if not phone_relationships:

            return {
                "mode": "LOCAL_GRAPH",
                "answer": (
                    "No direct communication links "
                    "between phone numbers were found."
                ),
                "entities": phone_entities,
                "relationships": [],
            }

        return {
            "mode": "LOCAL_GRAPH",
            "answer": (
                f"Found {len(phone_relationships)} "
                "communication relationship(s) "
                "between phone numbers."
            ),
            "entities": phone_entities,
            "relationships": [
                relationship_to_dict(r)
                for r in phone_relationships
            ],
        }

    # --------------------------------------------------------
    # FINANCIAL / TRANSACTION QUESTIONS
    # --------------------------------------------------------

    if (
        "transaction" in q
        or "financial" in q
        or "money transfer" in q
        or "fund transfer" in q
        or "transferred" in q
        or "bank activity" in q
    ):

        financial_relationships = [
            r
            for r in relationships
            if r.relation
            == "TRANSFERRED_FUNDS_TO"
        ]

        if not financial_relationships:

            return {
                "mode": "LOCAL_GRAPH",
                "answer": (
                    "No financial transfer relationships "
                    "are currently recorded."
                ),
                "entities": [],
                "relationships": [],
            }

        lines = []

        for r in financial_relationships:

            amount = ""

            if r.amount is not None:
                amount = f" | Amount: {r.amount}"

            lines.append(
                f"{r.source} → {r.target}"
                f"{amount}"
            )

        return {
            "mode": "LOCAL_GRAPH",
            "answer": (
                "Financial relationships found:\n\n"
                + "\n".join(lines)
            ),
            "entities": [],
            "relationships": [
                relationship_to_dict(r)
                for r in financial_relationships
            ],
        }

    # -------------------------------------------------------
    # ENTITY-BASED QUESTIONS
    # --------------------------------------------------------

    matched_entities = find_entities(
        db,
        question
    )

    if matched_entities:

        matched_keys = {
            e.key
            for e in matched_entities
        }

        connected, matching_relationships = (
        get_connected_entities(
            db,
            matched_keys,
            case_id
        )
    )

        result_entities = [
            entity_to_dict(e)
            for e in matched_entities
        ]

        result_entities.extend(
            entity_to_dict(e)
            for e in connected
            if e.key not in matched_keys
        )

        names = ", ".join(
            e.name
            for e in matched_entities
        )

        if matching_relationships:

            relationship_lines = []

            for r in matching_relationships:

                relationship_lines.append(
                    f"{r.source} "
                    f"→ {r.relation} → "
                    f"{r.target}"
                )

            return {
                "mode": "LOCAL_GRAPH",
                "answer": (
                    f"Evidence connected to {names}:\n\n"
                    + "\n".join(
                        f"- {line}"
                        for line in relationship_lines
                    )
                ),
                "entities": result_entities,
                "relationships": [
                    relationship_to_dict(r)
                    for r in matching_relationships
                ],
            }

        # Entity exists but has no relationships
        return {
            "mode": "LOCAL_GRAPH",
            "answer": (
                f"{names} exists in the current "
                "evidence graph, but no direct "
                "relationships are recorded."
            ),
            "entities": result_entities,
            "relationships": [],
        }

    # --------------------------------------------------------
    # DOCUMENT SEARCH FALLBACK
    # --------------------------------------------------------

    matching_documents = search_documents(
    db,
    question,
    case_id=case_id
)

    if matching_documents:

        snippets = []

        for document in matching_documents:

            snippet = make_document_snippet(
                document,
                question
            )

            snippets.append(
                f"[{document.filename}]\n{snippet}"
            )

        return {
            "mode": "LOCAL_EVIDENCE_SEARCH",
            "answer": (
                "I found relevant evidence in "
                "the following documents:\n\n"
                + "\n\n".join(snippets)
            ),
            "entities": [],
            "relationships": [],
        }

    # --------------------------------------------------------
    # GENERIC FALLBACK
    # --------------------------------------------------------

    graph_summary = build_graph_summary(db)

    return {
        "mode": "LOCAL_GRAPH",
        "answer": (
            "I could not find a direct answer to that "
            "question in the current graph using local "
            "analysis.\n\n"
            f"The current evidence contains "
            f"{graph_summary['total_entities']} entities, "
            f"{graph_summary['total_relationships']} "
            "relationships, and "
            f"{graph_summary['total_documents']} documents.\n\n"
            "Try asking about a person, phone number, "
            "bank account, vehicle, location, relationship, "
            "transaction, communication activity, or "
            "case summary."
        ),
        "entities": [],
        "relationships": [],
    }


# ============================================================
# LLM / GRAPH-RAG ANSWER
# ============================================================

def llm_answer(db, question, case_id=None):

    from openai import OpenAI

    client = OpenAI(
        api_key=OPENAI_API_KEY
    )

    entities = get_entities(db, case_id)
    relationships = get_relationships(db, case_id)
    documents = get_documents(db, case_id)
    cases = get_cases(db)

    # --------------------------------------------------------
    # ENTITY CONTEXT
    # --------------------------------------------------------
    # Entity.risk is a case-blind stored aggregate, so it must not be quoted to
    # the model as "the risk in this case": an entity shared with another case
    # would carry a score influenced by that other case. The score is recomputed
    # from the active case's own graph. With no active case there is no
    # investigation to score, so the stored value is reported with its band and
    # the basis is left unset rather than presenting a cross-case number as a
    # case-scoped one.

    if case_id is not None:
        risk_entities, case_risk = risk_scores_for_rows(
            entities, relationships, case_id=case_id
        )
    else:
        risk_entities, case_risk = {}, {}

    entity_context = [
        {
            "key": e.key,
            "label": e.label,
            "name": e.name,
            "risk": (
                (risk_entities.get(e.key) or {}).get("score")
                if risk_entities
                else e.risk
            ),
            "risk_band": (
                (risk_entities.get(e.key) or {}).get("band")
                if risk_entities
                else risk_band(float(e.risk or 0.0))
            ),
            "risk_basis": (
                (risk_entities.get(e.key) or {}).get("basis")
                if risk_entities
                else "STORED_CROSS_CASE_AGGREGATE"
            ),
        }
        for e in entities
    ]

    # --------------------------------------------------------
    # RELATIONSHIP CONTEXT
    # --------------------------------------------------------

    relationship_context = [
        {
            "source": r.source,
            "target": r.target,
            "relation": r.relation,
            "timestamp": r.timestamp,
            "amount": r.amount,
        }
        for r in relationships
    ]

    # --------------------------------------------------------
    # CASE CONTEXT
    # --------------------------------------------------------

    case_context = [
        {
            "title": c.title,
            "status": c.status,
            "risk": c.risk,
            "description": c.description,
        }
        for c in cases
    ]

    # --------------------------------------------------------
    # DOCUMENT CONTEXT
    # --------------------------------------------------------

    document_context = []

    total_chars = 0
    max_chars = 60000

    for document in documents:

        content = clean_text(
            document.content
        )

        if not content:
            continue

        remaining = max_chars - total_chars

        if remaining <= 0:
            break

        content = content[:remaining]

        document_context.append(
            {
                "filename": document.filename,
                "doc_type": document.doc_type,
                "data_category": document.data_category,
                "extraction_method": document.extraction_method,
                "content": content,
            }
        )

        total_chars += len(content)

    context = {
        "cases": case_context,
        "entities": entity_context,
        "relationships": relationship_context,
        "documents": document_context,
    }

    context_json = json.dumps(
        context,
        ensure_ascii=False,
        default=str,
        indent=2,
    )

    # --------------------------------------------------------
    # INVESTIGATIVE SYSTEM PROMPT
    # --------------------------------------------------------

    system_prompt = """
You are CrimeLens, an AI-powered crime-investigation
evidence analysis assistant.

Your job is to answer ANY reasonable investigation question
using ONLY the evidence supplied in the current CrimeLens
case.

You are NOT restricted to predefined questions.

You may answer questions about:

- people
- phone numbers
- bank accounts
- vehicles
- locations
- incidents
- cases
- communication
- financial transactions
- relationships
- evidence documents
- timelines
- summaries
- connections
- patterns
- comparisons
- counts
- evidence sources

IMPORTANT EVIDENCE RULES:

1. Never invent a person, relationship, event, phone number,
   account, vehicle, location, or evidence.

2. Never claim that someone is guilty.

3. Distinguish direct evidence from inference.

4. If the supplied evidence does not contain enough information,
   explicitly say that.

5. Do not assume that two entities are related simply because
   they appear in the same document.

6. Use actual graph relationships when discussing connections.

7. When summarizing, summarize the supplied evidence rather
   than creating a fictional narrative.

8. When the user asks a vague question such as "summarize",
   provide a useful overview of the current case and evidence.

9. When the user asks a question involving an entity,
   identify the entity from the supplied graph and explain
   its recorded connections and relevant evidence.

10. Keep answers clear and suitable for an investigative
    dashboard.

The data is synthetic demonstration data unless the evidence
itself states otherwise.
"""

    user_prompt = f"""
USER QUESTION:

{question}

CURRENT CRIMELENS EVIDENCE:

{context_json}

Answer the user's question using only this evidence.
"""

    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": user_prompt,
            },
        ],
        temperature=0.1,
    )

    return {
        "mode": "LLM",
        "answer": response.choices[0].message.content,
    }


# ============================================================
# MAIN ASSISTANT ENTRY POINT
# ============================================================

def answer_question(db, question: str,case_id=None):

    question = str(
        question or ""
    ).strip()

    if not question:

        return {
            "mode": "LOCAL_GRAPH",
            "answer": (
                "Please enter an investigation question."
            ),
            "entities": [],
            "relationships": [],
        }

    # --------------------------------------------------------
    # If OpenAI is configured:
    # ALWAYS allow free-form questions.
    # --------------------------------------------------------

    if OPENAI_API_KEY:

        try:
            return llm_answer(
                db,
                question,
                case_id
            )

        except Exception as exc:

            local_result = local_freeform_answer(
            db,
            question,
            case_id
        )

            return {
                "mode": "LOCAL_GRAPH_FALLBACK",
                "answer": (
                    "AI analysis is temporarily unavailable. "
                    "Using local evidence analysis instead.\n\n"
                    f"{local_result['answer']}"
                ),
                "entities": local_result.get(
                    "entities",
                    []
                ),
                "relationships": local_result.get(
                    "relationships",
                    []
                ),
                "error": type(exc).__name__,
            }

    # --------------------------------------------------------
    # No API key:
    # Use dynamic local evidence analysis.
    # --------------------------------------------------------
    return local_freeform_answer(
    db,
    question,
    case_id
)
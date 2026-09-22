import json
import re

from ..config import OPENAI_API_KEY, OPENAI_MODEL, OPENAI_BASE_URL, RAG_TOP_K
from ..models import Entity, Relationship, Document, Case
from .risk_service import risk_band, risk_scores_for_rows
from .rag_service import (
    retrieve_relevant_chunks,
    get_cached_assistant_response,
    set_cached_assistant_response,
    invalidate_case_cache,
)
from .llm_provider import (
    is_model_api_configured,
    call_pretrained_model,
    get_model_info,
)


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


def get_cases(db, case_id=None):
    query = db.query(Case)
    if case_id is not None:
        query = query.filter(Case.id == case_id)
    return query.all()


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


def find_entities(db, question, case_id=None):
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

    entities = get_entities(db, case_id)

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

def build_graph_summary(db, case_id=None):

    entities = get_entities(db, case_id)
    relationships = get_relationships(db, case_id)
    documents = get_documents(db, case_id)
    cases = get_cases(db, case_id)

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

def find_current_case(db, case_id=None):

    if case_id is not None:
        case = db.query(Case).filter(Case.id == case_id).first()
        if case:
            return [case]

    entities = get_entities(db, case_id)

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
        question,
        case_id=case_id
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

    graph_summary = build_graph_summary(db, case_id=case_id)

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
# RAG + PRETRAINED MODEL INVESTIGATION ASSISTANT
# ============================================================

def synthesize_grounded_rag_answer(
    db,
    question: str,
    case_id: int,
    rag_chunks: list,
    sources: list,
    relevant_entities: list,
    relevant_relationships: list,
    is_fallback: bool = False,
    error: str = None,
):
    """
    Synthesize an evidence-grounded answer locally without hallucination.
    Used when Pretrained Model API is not configured or during API error fallback.
    """
    # 1. First check if specialized graph queries apply (most connected, communication, etc.)
    q_lower = question.lower()
    if any(k in q_lower for k in ["most connected", "highest degree", "most connections", "communication", "phone calls", "call activity", "summary", "overview"]):
        local_res = local_freeform_answer(db, question, case_id)
        local_res["mode"] = "RAG_LOCAL_FALLBACK" if is_fallback else "RAG_LOCAL_GROUNDED"
        local_res["sources"] = sources
        local_res["case_id"] = case_id
        if error:
            local_res["error"] = error
        return local_res

    # 2. Check if relevant entities with graph connections were found
    lines = []
    if is_fallback:
        lines.append("*(AI model API temporarily unavailable — using local evidence-grounded synthesis)*\n")

    has_substantive_evidence = False

    # Evidence from retrieved RAG chunks (requiring substantive relevance)
    STOP_WORDS = {
        "the", "is", "at", "which", "on", "what", "where", "who", "when", "why",
        "how", "a", "an", "and", "or", "in", "to", "for", "of", "with", "by",
        "from", "as", "about", "this", "that", "these", "those", "it", "its", "are", "was", "were"
    }
    q_words = set(re.findall(r"\w+", question.lower()))
    meaningful_q_words = [w for w in q_words if len(w) >= 3 and w not in STOP_WORDS]

    valid_chunks = []
    for c in rag_chunks:
        text = c.get("chunk_text", "").lower()
        hits = sum(1 for w in meaningful_q_words if w in text)
        if (hits > 0 and c.get("score", 0) >= 0.12) or (c.get("score", 0) >= 0.40):
            valid_chunks.append(c)

    if valid_chunks:
        has_substantive_evidence = True
        lines.append("### Retrieved Case Evidence:")
        for idx, c in enumerate(valid_chunks[:3], 1):
            prov = c.get("provenance") or {}
            fn = c.get("filename") or prov.get("filename", "Evidence")
            loc = f", Row {c['row']}" if c.get("row") else (f", Section {c['section']}" if c.get("section") else "")
            # Clean chunk text to remove duplicate [Evidence: ...] prefix if present
            raw_text = c.get("chunk_text", "").strip()
            lines.append(f"{idx}. **[Source: {fn}{loc}]**")
            lines.append(f"   > {raw_text}\n")

    # Graph connections
    if relevant_relationships:
        has_substantive_evidence = True
        lines.append("### Relevant Graph Connections:")
        for r in relevant_relationships[:5]:
            amt = f" (Amount: {r['amount']})" if r.get("amount") else ""
            ts = f" at {r['timestamp']}" if r.get("timestamp") else ""
            lines.append(f"- **{r['source']}** —`{r['relation']}`→ **{r['target']}**{amt}{ts}")
        lines.append("")

    # Relevant entities
    if relevant_entities:
        has_substantive_evidence = True
        lines.append("### Identified Entities:")
        for e in relevant_entities[:5]:
            name = e.get("name") or e.get("key")
            label = e.get("label", "Entity")
            risk = e.get("risk", 0.0)
            lines.append(f"- **{name}** ({label}) — Risk: {risk:.1f}")
        lines.append("")

    if not has_substantive_evidence:
        answer_text = (
            "I could not find sufficient evidence in the current case to establish this. "
            "No matching records or graph relationships were found in the active case evidence."
        )
    else:
        answer_text = "\n".join(lines)

    mode = "RAG_LOCAL_FALLBACK" if is_fallback else "RAG_LOCAL_GROUNDED"
    res = {
        "mode": mode,
        "answer": answer_text,
        "sources": sources,
        "entities": relevant_entities,
        "relationships": relevant_relationships,
        "case_id": case_id,
        "confidence": 0.85 if valid_chunks else 0.5,
    }
    if error:
        res["error"] = error
    return res


def llm_answer(db, question: str, case_id: int, rag_chunks: list, sources: list, relevant_entities: list, relevant_relationships: list):
    """
    RAG-powered evidence-grounded answer using the configured Pretrained Model API.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    case_title = case.title if case else f"Case #{case_id}"
    case_ref = case.reference_id if case else "N/A"
    case_status = case.status if case else "Active"

    # Format RAG evidence chunks with exact provenance
    rag_context_blocks = []
    for c in rag_chunks:
        prov = c.get("provenance") or {}
        fn = c.get("filename") or prov.get("filename", "Evidence")
        loc = f" Row {c['row']}" if c.get("row") else (f" Section {c['section']}" if c.get("section") else "")
        rag_context_blocks.append(f"[Source: {fn}{loc}]\n{c.get('chunk_text', '')}")

    rag_text = "\n\n".join(rag_context_blocks) if rag_context_blocks else "No relevant evidence chunks retrieved."

    # Format Graph Context
    entity_lines = [
        f"- {e.get('name') or e.get('key')} ({e.get('label')}, Risk: {e.get('risk', 0)})"
        for e in relevant_entities[:10]
    ]
    graph_entities_text = "\n".join(entity_lines) if entity_lines else "No specific entities identified."

    rel_lines = [
        f"- {r.get('source')} --[{r.get('relation')}]--> {r.get('target')}" + (f" (Amount: {r.get('amount')})" if r.get('amount') else "")
        for r in relevant_relationships[:10]
    ]
    graph_rel_text = "\n".join(rel_lines) if rel_lines else "No specific relationships recorded."

    system_prompt = """You are CrimeLens, an AI-powered investigation intelligence assistant.
Your responsibility is to analyze evidence and answer questions strictly grounded in the active case evidence.

CRITICAL INVESTIGATION RULES:
1. Ground your answers ONLY in the supplied case evidence chunks and graph relationships.
2. NEVER invent, assume, or hallucinate entities, accounts, phone numbers, transactions, locations, dates, or case facts.
3. If the supplied evidence and graph do not contain enough information to answer the question, explicitly state:
   "I could not find sufficient evidence in the current case to establish this."
4. ALWAYS cite source provenance in your answer when referencing facts, using "[Source: <filename>, Row <row>]" or "[Source: <filename>]".
5. Distinguish clearly between:
   - DIRECT EVIDENCE (explicitly written in retrieved evidence documents)
   - GRAPH-DERIVED CONNECTIONS (relationships between entities in the graph)
   - INSUFFICIENT EVIDENCE
6. Maintain an objective, professional tone suitable for a law-enforcement / intelligence investigative dashboard.
"""

    user_prompt = f"""ACTIVE CASE:
Title: {case_title} (ID: {case_id} | Ref: {case_ref})
Status: {case_status}

RETRIEVED CASE EVIDENCE (RAG CHUNKS):
{rag_text}

RELEVANT CASE GRAPH:
Entities:
{graph_entities_text}

Relationships:
{graph_rel_text}

INVESTIGATOR QUESTION:
{question}

Answer the investigator's question using ONLY the evidence and graph context above. Cite sources explicitly. If evidence is insufficient, state so directly.
"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    res = call_pretrained_model(messages, temperature=0.1, max_tokens=1000)
    return res


# ============================================================
# MAIN ASSISTANT ENTRY POINT
# ============================================================

def answer_question(db, question: str, case_id=None):
    """
    Main entry point for CrimeLens Investigation Assistant.
    Enforces active-case boundary, performs case-scoped RAG retrieval,
    gathers graph context, and uses the Pretrained Model API with local grounded fallback.
    """
    question = str(question or "").strip()

    if not question:
        return {
            "mode": "LOCAL_GRAPH",
            "answer": "Please enter an investigation question.",
            "entities": [],
            "relationships": [],
            "sources": [],
            "case_id": case_id,
        }

    # Strict active-case boundary: a case must be selected before querying the assistant.
    if case_id is None:
        return {
            "mode": "CASE_REQUIRED",
            "answer": (
                "No active case selected. Please select an investigation case "
                "from the workspace before querying the assistant."
            ),
            "entities": [],
            "relationships": [],
            "sources": [],
            "case_id": None,
        }

    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        return {
            "mode": "CASE_NOT_FOUND",
            "answer": f"Selected case #{case_id} was not found.",
            "entities": [],
            "relationships": [],
            "sources": [],
            "case_id": case_id,
        }

    # Check case-scoped cache
    cached = get_cached_assistant_response(case_id, question)
    if cached:
        return cached

    # 1. CASE-SCOPED RAG RETRIEVAL
    rag_chunks = retrieve_relevant_chunks(db, question, case_id=case_id, top_k=RAG_TOP_K)
    sources = []
    for c in rag_chunks:
        prov = c.get("provenance") or {}
        sources.append({
            "document_id": c.get("document_id"),
            "filename": c.get("filename") or prov.get("filename", "Evidence Document"),
            "row": c.get("row") or prov.get("row"),
            "section": c.get("section") or prov.get("section"),
            "doc_type": c.get("doc_type") or prov.get("doc_type", ""),
            "score": c.get("score", 0.0),
            "preview": c.get("chunk_text", "")[:250],
        })

    # 2. CASE-SCOPED GRAPH CONTEXT
    case_entities = get_entities(db, case_id)
    case_relationships = get_relationships(db, case_id)

    # Compute case-scoped risk scores
    risk_entities, _ = risk_scores_for_rows(case_entities, case_relationships, case_id=case_id)

    # Find entities mentioned in question or top chunks
    q_clean = normalize_text(question)
    matching_entities = []
    for e in case_entities:
        e_name = normalize_text(e.name)
        e_key = normalize_text(e.key)
        if (len(e_name) >= 3 and e_name in q_clean) or (len(e_key) >= 4 and e_key in q_clean):
            matching_entities.append(e)

    # If no entities directly in question, check top RAG chunk texts
    if not matching_entities and rag_chunks:
        chunk_text_combined = " ".join(c.get("chunk_text", "").lower() for c in rag_chunks[:2])
        for e in case_entities:
            e_name = normalize_text(e.name)
            e_key = normalize_text(e.key)
            if (len(e_name) >= 4 and e_name in chunk_text_combined) or (len(e_key) >= 5 and e_key in chunk_text_combined):
                matching_entities.append(e)

    entity_keys = {e.key for e in matching_entities}
    matching_relationships = [
        r for r in case_relationships
        if r.source in entity_keys or r.target in entity_keys
    ]

    relevant_entity_dicts = [
        {
            "key": e.key,
            "label": e.label,
            "name": e.name,
            "risk": (risk_entities.get(e.key) or {}).get("score", e.risk),
            "risk_band": (risk_entities.get(e.key) or {}).get("band", risk_band(float(e.risk or 0.0))),
        }
        for e in matching_entities
    ]
    relevant_rel_dicts = [relationship_to_dict(r) for r in matching_relationships]

    # 3. PRETRAINED MODEL API OR GROUNDED LOCAL SYNTHESIS
    if is_model_api_configured():
        llm_res = llm_answer(
            db=db,
            question=question,
            case_id=case_id,
            rag_chunks=rag_chunks,
            sources=sources,
            relevant_entities=relevant_entity_dicts,
            relevant_relationships=relevant_rel_dicts,
        )
        if llm_res.get("ok"):
            response = {
                "mode": "RAG_PRETRAINED_MODEL",
                "answer": llm_res.get("content", ""),
                "sources": sources,
                "entities": relevant_entity_dicts,
                "relationships": relevant_rel_dicts,
                "case_id": case_id,
                "confidence": 0.95 if sources else 0.70,
            }
            set_cached_assistant_response(case_id, question, response)
            return response
        else:
            # Model API call failed (timeout, rate limit, auth) -> gracefully fall back
            response = synthesize_grounded_rag_answer(
                db=db,
                question=question,
                case_id=case_id,
                rag_chunks=rag_chunks,
                sources=sources,
                relevant_entities=relevant_entity_dicts,
                relevant_relationships=relevant_rel_dicts,
                is_fallback=True,
                error=llm_res.get("error"),
            )
            set_cached_assistant_response(case_id, question, response)
            return response

    # 4. No Model API configured: use Grounded Local Synthesis
    response = synthesize_grounded_rag_answer(
        db=db,
        question=question,
        case_id=case_id,
        rag_chunks=rag_chunks,
        sources=sources,
        relevant_entities=relevant_entity_dicts,
        relevant_relationships=relevant_rel_dicts,
        is_fallback=False,
    )
    set_cached_assistant_response(case_id, question, response)
    return response
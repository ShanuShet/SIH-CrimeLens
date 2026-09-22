"""
CrimeLens Case-Isolated RAG (Retrieval-Augmented Generation) Service.

Provides:
- Deterministic and semantic chunking for structured (CSV/XLSX/JSON) and unstructured (PDF/DOCX/TXT/OCR) evidence.
- Dual-mode embeddings: Pretrained embedding API (OpenAI/compatible) with robust deterministic local unit-vector fallback.
- Case-isolated SQLite vector storage in `document_chunks`.
- Top-K cosine similarity retrieval with keyword boosting and provenance tracking (filename, row, page).
- Case-scoped assistant response caching and cache invalidation.
"""

import hashlib
import json
import re
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from sqlalchemy.orm import Session

from ..config import (
    OPENAI_API_KEY,
    OPENAI_BASE_URL,
    EMBEDDING_MODEL,
    RAG_TOP_K,
    RAG_CHUNK_SIZE,
    RAG_CHUNK_OVERLAP,
)
from ..models import Document, DocumentChunk


# ============================================================
# CASE-SCOPED CACHE
# ============================================================

_ASSISTANT_CACHE: Dict[Tuple[int, str], Dict[str, Any]] = {}


def get_cached_assistant_response(case_id: int, question: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached assistant response for the exact active case and question."""
    if case_id is None:
        return None
    key = (case_id, question.strip().lower())
    return _ASSISTANT_CACHE.get(key)


def set_cached_assistant_response(case_id: int, question: str, response: Dict[str, Any]) -> None:
    """Cache assistant response strictly keyed by (case_id, normalized_question)."""
    if case_id is None:
        return
    key = (case_id, question.strip().lower())
    _ASSISTANT_CACHE[key] = response


def invalidate_case_cache(case_id: Optional[int] = None) -> None:
    """Invalidate all cached responses for a specific case, or all if case_id is None."""
    global _ASSISTANT_CACHE
    if case_id is None:
        _ASSISTANT_CACHE.clear()
    else:
        keys_to_delete = [k for k in _ASSISTANT_CACHE.keys() if k[0] == case_id]
        for k in keys_to_delete:
            _ASSISTANT_CACHE.pop(k, None)


# ============================================================
# DOCUMENT CHUNKING
# ============================================================

def chunk_document(document: Document) -> List[Dict[str, Any]]:
    """
    Split a document into meaningful semantic chunks with provenance metadata.
    Handles both structured data records and unstructured text documents.
    """
    chunks: List[Dict[str, Any]] = []
    content = document.content or ""
    filename = document.filename or f"document_{document.id}"
    doc_id = document.id
    case_id = document.case_id or 0

    if not content.strip():
        return []

    # --------------------------------------------------------
    # STRUCTURED EVIDENCE (CSV, XLSX, XLS, JSON)
    # --------------------------------------------------------
    is_structured = (document.data_category == "STRUCTURED") or content.strip().startswith("{") or content.strip().startswith("[")

    if is_structured:
        records = []
        try:
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                records = parsed.get("records") or parsed.get("preview") or []
                # If no records list, chunk the key-values of the dict
                if not records:
                    records = [parsed]
            elif isinstance(parsed, list):
                records = parsed
        except Exception:
            records = []

        if records and isinstance(records, list):
            for idx, row in enumerate(records):
                if isinstance(row, dict):
                    # Format as clean field summary
                    fields_str = " | ".join(
                        f"{k}: {v}"
                        for k, v in row.items()
                        if v not in (None, "", "null")
                    )
                    chunk_text = f"[Evidence: {filename} | Row {idx + 1}] {fields_str}"
                    provenance = {
                        "document_id": doc_id,
                        "case_id": case_id,
                        "filename": filename,
                        "row": idx + 1,
                        "doc_type": document.doc_type,
                        "data_category": "STRUCTURED",
                    }
                else:
                    chunk_text = f"[Evidence: {filename} | Entry {idx + 1}] {str(row)}"
                    provenance = {
                        "document_id": doc_id,
                        "case_id": case_id,
                        "filename": filename,
                        "row": idx + 1,
                        "doc_type": document.doc_type,
                        "data_category": "STRUCTURED",
                    }

                chunks.append({
                    "chunk_index": idx,
                    "chunk_text": chunk_text,
                    "provenance": provenance,
                })
            return chunks

    # --------------------------------------------------------
    # UNSTRUCTURED EVIDENCE (PDF, DOCX, TXT, OCR)
    # --------------------------------------------------------
    text = re.sub(r"\r\n|\r", "\n", content).strip()
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]

    chunk_idx = 0
    current_chunk = []
    current_length = 0

    for para in paragraphs:
        para_len = len(para)
        if current_length + para_len > RAG_CHUNK_SIZE and current_chunk:
            combined_text = "\n\n".join(current_chunk)
            chunks.append({
                "chunk_index": chunk_idx,
                "chunk_text": f"[Evidence: {filename} | Section {chunk_idx + 1}]\n{combined_text}",
                "provenance": {
                    "document_id": doc_id,
                    "case_id": case_id,
                    "filename": filename,
                    "section": chunk_idx + 1,
                    "doc_type": document.doc_type,
                    "data_category": "UNSTRUCTURED",
                },
            })
            chunk_idx += 1
            # Retain overlap if desired
            current_chunk = [para]
            current_length = para_len
        else:
            current_chunk.append(para)
            current_length += para_len + 2

    if current_chunk:
        combined_text = "\n\n".join(current_chunk)
        chunks.append({
            "chunk_index": chunk_idx,
            "chunk_text": f"[Evidence: {filename} | Section {chunk_idx + 1}]\n{combined_text}",
            "provenance": {
                "document_id": doc_id,
                "case_id": case_id,
                "filename": filename,
                "section": chunk_idx + 1,
                "doc_type": document.doc_type,
                "data_category": "UNSTRUCTURED",
            },
        })

    # If document had no double-newlines (single block of text)
    if not chunks and text:
        start = 0
        step = max(50, RAG_CHUNK_SIZE - RAG_CHUNK_OVERLAP)
        while start < len(text):
            end = min(len(text), start + RAG_CHUNK_SIZE)
            segment = text[start:end].strip()
            if segment:
                chunks.append({
                    "chunk_index": chunk_idx,
                    "chunk_text": f"[Evidence: {filename} | Segment {chunk_idx + 1}]\n{segment}",
                    "provenance": {
                        "document_id": doc_id,
                        "case_id": case_id,
                        "filename": filename,
                        "section": chunk_idx + 1,
                        "doc_type": document.doc_type,
                        "data_category": "UNSTRUCTURED",
                    },
                })
                chunk_idx += 1
            start += step

    return chunks


# ============================================================
# EMBEDDINGS (PRETRAINED API + DETERMINISTIC LOCAL FALLBACK)
# ============================================================

LOCAL_EMBEDDING_DIM = 128


def _local_deterministic_embedding(text: str) -> List[float]:
    """
    Generate a deterministic 128-dimensional unit vector using feature hashing.
    Ensures 100% offline reliability, consistent cosine ranking, and zero external dependency.
    """
    vec = np.zeros(LOCAL_EMBEDDING_DIM, dtype=np.float32)
    tokens = re.findall(r"\w+", text.lower())

    if not tokens:
        vec[0] = 1.0
        return vec.tolist()

    for token in tokens:
        # Word hash
        h = int(hashlib.md5(token.encode("utf-8")).hexdigest()[:8], 16)
        idx = h % LOCAL_EMBEDDING_DIM
        sign = 1.0 if (h & 0x10) else -1.0
        vec[idx] += sign

        # Subword n-grams for typo & partial token matching
        for n in (3, 4):
            if len(token) >= n:
                for i in range(len(token) - n + 1):
                    sub = token[i:i + n]
                    sh = int(hashlib.md5(sub.encode("utf-8")).hexdigest()[:8], 16)
                    s_idx = sh % LOCAL_EMBEDDING_DIM
                    s_sign = 0.5 if (sh & 0x10) else -0.5
                    vec[s_idx] += s_sign

    norm = np.linalg.norm(vec)
    if norm > 1e-6:
        vec = vec / norm
    else:
        vec[0] = 1.0

    return vec.tolist()


def compute_embeddings(texts: List[str]) -> List[List[float]]:
    """
    Compute embeddings for a list of texts using the configured pretrained model API,
    or falling back to deterministic local unit vectors if unconfigured or unreachable.
    """
    if not texts:
        return []

    # Attempt Pretrained Embedding API if key is set
    if OPENAI_API_KEY and OPENAI_API_KEY.strip():
        try:
            from openai import OpenAI

            kwargs: Dict[str, Any] = {
                "api_key": OPENAI_API_KEY.strip(),
                "timeout": 15.0,
            }
            if OPENAI_BASE_URL and OPENAI_BASE_URL.strip():
                kwargs["base_url"] = OPENAI_BASE_URL.strip()

            client = OpenAI(**kwargs)
            res = client.embeddings.create(
                input=texts,
                model=EMBEDDING_MODEL,
            )
            return [data.embedding for data in res.data]

        except Exception:
            # Fall back smoothly without crashing or leaking secrets
            pass

    # Deterministic local fallback
    return [_local_deterministic_embedding(t) for t in texts]


# ============================================================
# INDEXING
# ============================================================

def index_document(db: Session, document: Document) -> int:
    """
    Generate chunks and embeddings for a document, storing them in `document_chunks`.
    Safe and recoverable: does not corrupt document or evidence integrity.
    """
    if not document or not document.id:
        return 0

    chunks_data = chunk_document(document)
    if not chunks_data:
        return 0

    texts = [c["chunk_text"] for c in chunks_data]
    embeddings = compute_embeddings(texts)

    # Remove any existing chunks for this document
    db.query(DocumentChunk).filter(DocumentChunk.document_id == document.id).delete()

    created_count = 0
    for chunk, emb in zip(chunks_data, embeddings):
        db_chunk = DocumentChunk(
            case_id=document.case_id or 0,
            document_id=document.id,
            chunk_index=chunk["chunk_index"],
            chunk_text=chunk["chunk_text"],
            embedding_json=json.dumps(emb),
            provenance_json=json.dumps(chunk["provenance"]),
        )
        db.add(db_chunk)
        created_count += 1

    db.flush()
    invalidate_case_cache(document.case_id)
    return created_count


def index_case_documents(db: Session, case_id: int) -> int:
    """Index all documents belonging to case_id that have not yet been indexed."""
    if case_id is None:
        return 0

    docs = db.query(Document).filter(Document.case_id == case_id).all()
    total_indexed = 0

    for doc in docs:
        chunk_count = db.query(DocumentChunk).filter(DocumentChunk.document_id == doc.id).count()
        if chunk_count == 0 and (doc.content or "").strip():
            total_indexed += index_document(db, doc)

    return total_indexed


# ============================================================
# CASE-ISOLATED RETRIEVAL
# ============================================================

def retrieve_relevant_chunks(
    db: Session,
    query: str,
    case_id: int,
    top_k: int = RAG_TOP_K,
) -> List[Dict[str, Any]]:
    """
    Retrieve top-K relevant chunks strictly scoped to active case_id.
    Guarantees no data from other cases is retrieved.
    """
    if case_id is None or not query.strip():
        return []

    # 1. STRICT CASE SCOPING
    chunks = (
        db.query(DocumentChunk)
        .filter(DocumentChunk.case_id == case_id)
        .all()
    )

    # Auto-index unindexed documents for this case if no chunks exist yet
    if not chunks:
        index_case_documents(db, case_id)
        chunks = (
            db.query(DocumentChunk)
            .filter(DocumentChunk.case_id == case_id)
            .all()
        )

    if not chunks:
        return []

    # 2. Compute query embedding
    q_vecs = compute_embeddings([query])
    if not q_vecs:
        return []
    q_vec = np.array(q_vecs[0], dtype=np.float32)
    q_norm = np.linalg.norm(q_vec)
    if q_norm > 1e-6:
        q_vec = q_vec / q_norm

    # 3. Score chunks using cosine similarity + keyword boost
    query_tokens = set(re.findall(r"\w+", query.lower()))
    scored_results = []

    for c in chunks:
        c_emb = json.loads(c.embedding_json or "[]")
        if not c_emb or len(c_emb) != len(q_vec):
            # If embedding dimension mismatch (e.g., switched from local to API), regenerate locally
            c_emb = _local_deterministic_embedding(c.chunk_text)

        c_vec = np.array(c_emb, dtype=np.float32)
        c_norm = np.linalg.norm(c_vec)
        if c_norm > 1e-6:
            c_vec = c_vec / c_norm

        # Cosine similarity
        cos_sim = float(np.dot(q_vec, c_vec))

        # Keyword boost for exact tokens (ignoring common stopwords)
        STOP_WORDS = {
            "the", "is", "at", "which", "on", "what", "where", "who", "when", "why",
            "how", "a", "an", "and", "or", "in", "to", "for", "of", "with", "by",
            "from", "as", "about", "this", "that", "these", "those", "it", "its", "are", "was", "were"
        }
        meaningful_tokens = [t for t in query_tokens if len(t) >= 3 and t not in STOP_WORDS]
        text_lower = c.chunk_text.lower()
        keyword_hits = sum(1 for t in meaningful_tokens if t in text_lower)
        keyword_boost = min(0.3, keyword_hits * 0.1)

        total_score = max(0.0, cos_sim + keyword_boost)


        provenance = json.loads(c.provenance_json or "{}")
        scored_results.append({
            "chunk_id": c.id,
            "document_id": c.document_id,
            "case_id": c.case_id,
            "chunk_text": c.chunk_text,
            "score": round(total_score, 4),
            "provenance": provenance,
            "filename": provenance.get("filename", ""),
            "row": provenance.get("row"),
            "section": provenance.get("section"),
            "doc_type": provenance.get("doc_type", ""),
        })

    # Sort descending by score
    scored_results.sort(key=lambda x: x["score"], reverse=True)
    return scored_results[:top_k]

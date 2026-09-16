from pathlib import Path
import csv
import json
import re
from datetime import datetime

ALLOWED_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".txt",
    ".csv",
    ".xlsx",
    ".xls",
    ".json",
    ".png",
    ".jpg",
    ".jpeg",
}


# ============================================================
# BASIC HELPERS
# ============================================================

def classify_extension(filename: str) -> str:
    suffix = Path(filename).suffix.lower()

    if suffix in {".csv", ".xlsx", ".xls", ".json"}:
        return "STRUCTURED"

    return "UNSTRUCTURED"


def normalize_doc_type(doc_type: str) -> str:
    value = str(doc_type or "OTHER").strip().upper()

    value = value.replace("-", "_")
    value = value.replace(" ", "_")

    aliases = {
        "CDR": "CDR",
        "CALL_DETAIL_RECORD": "CDR",
        "CALL_DETAILS": "CDR",
        "CALL_RECORD": "CDR",
        "CALL_RECORDS": "CDR",

        "FINANCIAL": "FINANCIAL",
        "FINANCIAL_TRANSACTION_LOG": "FINANCIAL",
        "FINANCIAL_LOG": "FINANCIAL",
        "TRANSACTION_LOG": "FINANCIAL",
        "BANK_TRANSACTION": "FINANCIAL",
        "BANK_TRANSACTIONS": "FINANCIAL",

        "FIR": "FIR",
        "FIR_POLICE_REPORT": "FIR",
        "POLICE_REPORT": "FIR",

        "SURVEILLANCE": "SURVEILLANCE",
        "SURVEILLANCE_REPORT": "SURVEILLANCE",

        "CRIMINAL_RECORD": "CRIMINAL_RECORD",
        "CRIMINAL_RECORDS": "CRIMINAL_RECORD",

        "ENTITY_MASTER": "ENTITY_MASTER",
    }

    return aliases.get(value, value)


def _clean(value):
    if value is None:
        return ""

    try:
        if hasattr(value, "item"):
            value = value.item()
    except Exception:
        pass

    text = str(value).strip()

    if text.lower() in {
        "",
        "nan",
        "none",
        "null",
        "nat",
    }:
        return ""

    return text


def _norm_column(name):
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        str(name).strip().lower()
    ).strip("_")


def _find_column(columns, candidates):
    normalized = {
        _norm_column(c): c
        for c in columns
    }

    for candidate in candidates:
        candidate_norm = _norm_column(candidate)

        if candidate_norm in normalized:
            return normalized[candidate_norm]

    # Partial matching
    for normalized_name, original in normalized.items():
        for candidate in candidates:
            candidate_norm = _norm_column(candidate)

            if (
                candidate_norm in normalized_name
                or normalized_name in candidate_norm
            ):
                return original

    return None


def _canonical_key(label, identifier):
    label = str(label or "Entity").strip()

    identifier = _clean(identifier)

    if not identifier:
        return None

    mapping = {
        "Person": "PERSON",
        "PhoneNumber": "PHONE",
        "BankAccount": "ACCOUNT",
        "Vehicle": "VEHICLE",
        "Location": "LOCATION",
        "Incident": "INCIDENT",
        "Organization": "ORGANIZATION",
    }

    prefix = mapping.get(label, label.upper())

    return f"{prefix}:{identifier}"


# ============================================================
# ENTITY CREATION
# ============================================================

def _entity(label, identifier, name=None):
    identifier = _clean(identifier)

    if not identifier:
        return None

    key = _canonical_key(label, identifier)

    if not key:
        return None

    return {
        "key": key,
        "label": label,
        "name": _clean(name) or identifier,
    }


def _add_entity(entity_list, seen, label, identifier, name=None):
    entity = _entity(label, identifier, name)

    if not entity:
        return

    if entity["key"] in seen:
        return

    seen.add(entity["key"])
    entity_list.append(entity)


# ============================================================
# ENTITY MASTER
# ============================================================

def _parse_entity_master(rows):
    entities = []
    relationships = []
    seen = set()

    if not rows:
        return entities, relationships

    # JSON evidence frequently mixes record shapes in one file (entity rows plus
    # separate relationship rows). Using the union of the keys keeps those
    # columns detectable; for a regular table this is the same as the header row.
    columns = []

    for row in rows:

        for column in row.keys():

            if column not in columns:
                columns.append(column)

    # --------------------------------------------------------
    # Identify columns
    # --------------------------------------------------------

    id_col = _find_column(
        columns,
        [
            "entity_id",
            "id",
            "person_id",
            "phone_id",
            "account_id",
            "vehicle_id",
            "location_id",
        ]
    )

    type_col = _find_column(
        columns,
        [
            "entity_type",
            "type",
            "label",
            "category",
        ]
    )

    name_col = _find_column(
        columns,
        [
            "name",
            "entity_name",
            "person_name",
            "full_name",
            "value",
        ]
    )

    phone_col = _find_column(
        columns,
        [
            "phone",
            "phone_number",
            "mobile",
            "mobile_number",
        ]
    )

    account_col = _find_column(
        columns,
        [
            "account",
            "account_number",
            "bank_account",
            "bank_account_number",
        ]
    )

    vehicle_col = _find_column(
        columns,
        [
            "vehicle",
            "vehicle_number",
            "registration",
            "registration_number",
        ]
    )

    location_col = _find_column(
        columns,
        [
            "location",
            "address",
            "place",
        ]
    )

    person_id_col = _find_column(
        columns,
        [
            "person_id",
            "personid",
            "person_key",
            "subject_id",
        ]
    )

    # --------------------------------------------------------
    # Relationship columns
    # --------------------------------------------------------

    relationship_col = _find_column(
        columns,
        [
            "relationship",
            "relation",
            "relationship_type",
            "relation_type",
        ]
    )

    related_id_col = _find_column(
        columns,
        [
            "related_entity_id",
            "related_id",
            "target_entity_id",
            "target_id",
            "linked_entity_id",
        ]
    )

    source_id_col = _find_column(
        columns,
        [
            "source_entity_id",
            "source_id",
            "from_entity_id",
            "from_id",
        ]
    )

    target_id_col = _find_column(
        columns,
        [
            "target_entity_id",
            "target_id",
            "to_entity_id",
            "to_id",
        ]
    )

    # --------------------------------------------------------
    # First pass:
    # create every canonical entity
    # --------------------------------------------------------

    for row in rows:

        entity_type = (
            _clean(row.get(type_col)).lower()
            if type_col else ""
        )

        entity_id = (
            _clean(row.get(id_col))
            if id_col else ""
        )

        name = (
            _clean(row.get(name_col))
            if name_col else ""
        )

        # ---------------- PERSON ----------------

        if "person" in entity_type:

            _add_entity(
                entities,
                seen,
                "Person",
                entity_id or name,
                name
            )

        # ---------------- PHONE ----------------

        elif (
            "phone" in entity_type
            or "mobile" in entity_type
        ):

            _add_entity(
                entities,
                seen,
                "PhoneNumber",
                entity_id or name,
                name
            )

        # ---------------- ACCOUNT ----------------

        elif (
            "account" in entity_type
            or "bank" in entity_type
        ):

            _add_entity(
                entities,
                seen,
                "BankAccount",
                entity_id or name,
                name
            )

        # ---------------- VEHICLE ----------------

        elif "vehicle" in entity_type:

            _add_entity(
                entities,
                seen,
                "Vehicle",
                entity_id or name,
                name
            )

        # ---------------- LOCATION ----------------

        elif "location" in entity_type:

            _add_entity(
                entities,
                seen,
                "Location",
                entity_id or name,
                name
            )

        # ---------------- EXPLICIT VALUES ----------------

        if phone_col:

            _add_entity(
                entities,
                seen,
                "PhoneNumber",
                row.get(phone_col)
            )

        if account_col:

            _add_entity(
                entities,
                seen,
                "BankAccount",
                row.get(account_col)
            )

        if vehicle_col:

            _add_entity(
                entities,
                seen,
                "Vehicle",
                row.get(vehicle_col)
            )

        if location_col:

            _add_entity(
                entities,
                seen,
                "Location",
                row.get(location_col)
            )

        # ---------------- PERSON WITHOUT AN EXPLICIT TYPE ----------------

        # Criminal records, FIR subject lists and plain contact exports carry a
        # person name but no entity_type column. Without this the subject of the
        # record would never become an entity at all, so the graph would lose the
        # person the evidence is about.

        if not entity_type:

            person_identifier = (
                _clean(row.get(person_id_col))
                if person_id_col
                else ""
            ) or name or entity_id

            _add_entity(
                entities,
                seen,
                "Person",
                person_identifier,
                name or person_identifier
            )

    # ========================================================
    # SECOND PASS:
    # CREATE EXPLICIT ENTITY MASTER RELATIONSHIPS
    # ========================================================

    # Build lookup:
    # identifier -> canonical key
    lookup = {}

    for entity in entities:

        lookup[
            _clean(entity["name"]).lower()
        ] = entity["key"]

        # Also allow the identifier from the key.
        if ":" in entity["key"]:

            identifier = entity["key"].split(
                ":",
                1
            )[1]

            lookup[
                _clean(identifier).lower()
            ] = entity["key"]

    # --------------------------------------------------------
    # Relationship type normalization
    # --------------------------------------------------------

    def normalize_relation(value):

        value = _clean(value).upper()

        if not value:
            return ""

        value = re.sub(
            r"[^A-Z0-9]+",
            "_",
            value
        ).strip("_")

        aliases = {

            "PHONE": "USES_PHONE",
            "USES_MOBILE": "USES_PHONE",
            "HAS_PHONE": "USES_PHONE",
            "OWNS_PHONE": "USES_PHONE",

            "ACCOUNT": "ASSOCIATED_WITH",
            "HAS_ACCOUNT": "ASSOCIATED_WITH",
            "OWNS_ACCOUNT": "ASSOCIATED_WITH",

            "VEHICLE": "USES_VEHICLE",
            "HAS_VEHICLE": "USES_VEHICLE",
            "OWNS_VEHICLE": "USES_VEHICLE",

            "LOCATION": "ASSOCIATED_WITH",
            "HAS_LOCATION": "ASSOCIATED_WITH",
        }

        return aliases.get(
            value,
            value
        )

    # --------------------------------------------------------
    # Process explicit source/target relationships
    # --------------------------------------------------------

    for row in rows:

        relation = normalize_relation(
            row.get(relationship_col)
        ) if relationship_col else ""

        if not relation:
            continue

        source_value = ""

        target_value = ""

        if source_id_col:

            source_value = _clean(
                row.get(source_id_col)
            )

        elif id_col:

            source_value = _clean(
                row.get(id_col)
            )

        if target_id_col:

            target_value = _clean(
                row.get(target_id_col)
            )

        elif related_id_col:

            target_value = _clean(
                row.get(related_id_col)
            )

        if not source_value or not target_value:
            continue

        source_key = lookup.get(
            source_value.lower()
        )

        target_key = lookup.get(
            target_value.lower()
        )

        if not source_key or not target_key:
            continue

        if source_key == target_key:
            continue

        relationships.append({
            "source": source_key,
            "target": target_key,
            "relation": relation,
            "timestamp": "",
            "amount": None,
        })

    return entities, relationships

# ============================================================
# CDR PARSER
# ============================================================

def _parse_cdr(rows):
    entities = []
    relationships = []
    seen = set()

    if not rows:
        return entities, relationships

    columns = list(rows[0].keys())

    source_col = _find_column(
        columns,
        [
            "caller",
            "caller_number",
            "calling_number",
            "source",
            "source_phone",
            "from",
            "from_number",
            "phone_a",
            "number_a",
        ]
    )

    target_col = _find_column(
        columns,
        [
            "callee",
            "receiver",
            "receiver_number",
            "called_number",
            "target",
            "target_phone",
            "to",
            "to_number",
            "phone_b",
            "number_b",
        ]
    )

    timestamp_col = _find_column(
        columns,
        [
            "timestamp",
            "datetime",
            "date_time",
            "call_time",
            "time",
            "date",
        ]
    )

    duration_col = _find_column(
        columns,
        [
            "duration",
            "duration_seconds",
            "call_duration",
        ]
    )

    for row in rows:
        source = _clean(row.get(source_col)) if source_col else ""
        target = _clean(row.get(target_col)) if target_col else ""

        if not source or not target:
            continue

        _add_entity(
            entities,
            seen,
            "PhoneNumber",
            source
        )

        _add_entity(
            entities,
            seen,
            "PhoneNumber",
            target
        )

        relationships.append({
            "source": _canonical_key("PhoneNumber", source),
            "target": _canonical_key("PhoneNumber", target),
            "relation": "CALL_MADE_TO",
            "timestamp": _clean(
                row.get(timestamp_col)
            ) if timestamp_col else "",
            "amount": None,
        })

    return entities, relationships


# ============================================================
# FINANCIAL PARSER
# ============================================================

def _parse_financial(rows):
    entities = []
    relationships = []
    seen = set()

    if not rows:
        return entities, relationships

    columns = list(rows[0].keys())

    source_col = _find_column(
        columns,
        [
            "sender_account",
            "source_account",
            "from_account",
            "debit_account",
            "account_from",
            "sender",
            "source",
            "payer_account",
        ]
    )

    target_col = _find_column(
        columns,
        [
            "receiver_account",
            "target_account",
            "to_account",
            "credit_account",
            "account_to",
            "receiver",
            "target",
            "payee_account",
        ]
    )

    amount_col = _find_column(
        columns,
        [
            "amount",
            "transaction_amount",
            "amount_inr",
            "value",
            "transaction_value",
        ]
    )

    timestamp_col = _find_column(
        columns,
        [
            "timestamp",
            "datetime",
            "date_time",
            "transaction_time",
            "time",
            "date",
        ]
    )

    for row in rows:
        source = _clean(row.get(source_col)) if source_col else ""
        target = _clean(row.get(target_col)) if target_col else ""

        if not source or not target:
            continue

        _add_entity(
            entities,
            seen,
            "BankAccount",
            source
        )

        _add_entity(
            entities,
            seen,
            "BankAccount",
            target
        )

        amount_text = (
            _clean(row.get(amount_col))
            if amount_col else ""
        )

        amount = None

        if amount_text:
            try:
                amount = float(
                    re.sub(
                        r"[^0-9.\-]",
                        "",
                        amount_text
                    )
                )
            except Exception:
                amount = None

        relationships.append({
            "source": _canonical_key(
                "BankAccount",
                source
            ),
            "target": _canonical_key(
                "BankAccount",
                target
            ),
            "relation": "TRANSFERRED_FUNDS_TO",
            "timestamp": _clean(
                row.get(timestamp_col)
            ) if timestamp_col else "",
            "amount": amount,
        })

    return entities, relationships


# ============================================================
# CSV READER
# ============================================================

def _read_csv(path):
    rows = []

    with open(
        path,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:
            rows.append(
                {
                    str(k): _clean(v)
                    for k, v in row.items()
                }
            )

    return rows


# ============================================================
# EXCEL READER
# ============================================================

def _read_excel(path):
    try:
        import pandas as pd
    except ImportError as exc:
        raise RuntimeError(
            "pandas is required for Excel files. "
            "Run: pip install pandas openpyxl"
        ) from exc

    df = pd.read_excel(path)

    df = df.fillna("")

    return df.to_dict(
        orient="records"
    )


# ============================================================
# JSON READER
# ============================================================

# Object keys understood to wrap a collection of records, so an export such as
# {"entities": [ {...} ]} is unwrapped instead of being treated as one record.
_JSON_RECORD_CONTAINERS = (
    "records",
    "entities",
    "persons",
    "people",
    "items",
    "entries",
    "rows",
    "results",
    "data",
)


def _json_records(value):
    """
    Normalize parsed JSON into a list of record dictionaries.

    Arrays of objects are used directly, a wrapping object such as
    {"records": [ {...} ]} is unwrapped (including nested wrappers), and a plain
    object is treated as a single record. JSON that cannot be understood as
    records raises an explicit error instead of silently extracting nothing.
    """

    if isinstance(value, dict):

        for key in _JSON_RECORD_CONTAINERS:

            inner = value.get(key)

            if isinstance(inner, dict):

                nested = _json_records(inner)

                if nested:
                    return nested

            elif (
                isinstance(inner, list)
                and inner
                and all(isinstance(item, dict) for item in inner)
            ):

                return list(inner)

        return [value]

    if isinstance(value, list):

        if not value:
            return []

        for index, item in enumerate(value):

            if not isinstance(item, dict):

                raise RuntimeError(
                    f"JSON array entry {index} is "
                    f"{type(item).__name__}, expected an object"
                )

        return list(value)

    raise RuntimeError(
        "Unsupported JSON document: expected an object or an array "
        f"of objects, found {type(value).__name__}"
    )


def _read_json(path, display_name=None):
    """
    Read a JSON evidence file.

    Returns (records, envelope): the record dictionaries to extract from, plus
    the wrapper object's own fields when the records were nested inside one
    (for example {"case_name": "...", "entities": [ {...} ]}), so wrapper context
    is preserved rather than discarded.

    display_name is the investigator-facing evidence name; stored files are
    renamed internally, so error messages must not report the storage name.

    Malformed JSON, unsupported document shapes and JSON without any records all
    fail here with an explicit message - a JSON evidence file must never be
    reported as ingested while contributing nothing.
    """

    label = display_name or Path(path).name

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

    except json.JSONDecodeError as exc:

        raise RuntimeError(
            f"Invalid JSON in {label}: {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno})"
        ) from exc

    records = _json_records(data)

    if not records or all(not record for record in records):

        raise RuntimeError(
            f"No records found in {label}: expected a JSON "
            "object or a non-empty array of objects"
        )

    envelope = {}

    if isinstance(data, dict) and records != [data]:

        for key, value in data.items():

            # Skip record collections and any nested wrapper that produced the
            # records themselves; keep the remaining context fields.
            if isinstance(value, list):
                continue

            if isinstance(value, dict) and _json_records(value) == records:
                continue

            envelope[key] = value

    return records, envelope


def _flatten_record(record, prefix="", depth=0):
    """
    Flatten a nested record into single level keys.

    Evidence fields are often nested ({"phone": {"number": "9000000001"}}).
    The extractors work on flat columns, so nested objects are flattened into
    "_"-joined keys, which keeps the value usable as an identifier instead of
    stringifying the nested object into a meaningless one.
    """

    flat = {}

    for key, value in record.items():

        name = f"{prefix}_{key}" if prefix else str(key)

        if isinstance(value, dict) and depth < 3:

            flat.update(
                _flatten_record(value, name, depth + 1)
            )

        else:

            flat[name] = value

    return flat


# ============================================================
# STRUCTURED PARSER
# ============================================================

def parse_structured(path: str, doc_type: str, display_name: str | None = None):
    path_obj = Path(path)

    normalized_type = normalize_doc_type(
        doc_type
    )

    suffix = path_obj.suffix.lower()

    envelope = {}

    if suffix == ".csv":
        source_rows = _read_csv(path)

    elif suffix in {".xlsx", ".xls"}:
        source_rows = _read_excel(path)

    elif suffix == ".json":
        source_rows, envelope = _read_json(path, display_name)

    else:
        raise RuntimeError(
            f"Unsupported structured file: {suffix}"
        )

    # The extractors work on flat column names, so nested record fields are
    # flattened for extraction only. The original records are kept for the
    # document preview so nested source information is preserved.
    rows = [
        _flatten_record(row)
        for row in source_rows
    ]

    entities = []
    relationships = []

    # ========================================================
    # ENTITY MASTER
    # ========================================================

    if normalized_type == "ENTITY_MASTER":

        entities, relationships = _parse_entity_master(
            rows
        )

    # ========================================================
    # CDR
    # ========================================================

    elif normalized_type == "CDR":

        entities, relationships = _parse_cdr(
            rows
        )

    # ========================================================
    # FINANCIAL
    # ========================================================

    elif normalized_type == "FINANCIAL":

        entities, relationships = _parse_financial(
            rows
        )

    # ========================================================
    # AUTOMATIC DETECTION
    # ========================================================

    else:

        columns = []

        for row in rows:

            for column in row.keys():

                if column not in columns:
                    columns.append(column)

        normalized_columns = {
            _norm_column(c)
            for c in columns
        }

        # ---------------- CDR ----------------

        if any(
            "caller" in c
            or "callee" in c
            or "called" in c
            for c in normalized_columns
        ):

            entities, relationships = _parse_cdr(
                rows
            )

        # ---------------- FINANCIAL ----------------

        elif any(
            "sender_account" in c
            or "receiver_account" in c
            or "transaction_amount" in c
            for c in normalized_columns
        ):

            entities, relationships = _parse_financial(
                rows
            )

        # ---------------- ENTITY MASTER ----------------

        else:

            entities, relationships = _parse_entity_master(
                rows
            )

    # ========================================================
    # METADATA
    # ========================================================

    metadata = {
        "detected_type": normalized_type,
        "rows": len(source_rows),
        "preview": source_rows[:10],
    }

    if envelope:
        metadata["envelope"] = envelope

    return (
        entities,
        relationships,
        metadata,
    )


# ============================================================
# OCR
# ============================================================

def _ocr_image(path: str) -> str:
    try:
        import pytesseract
        from PIL import Image

        tesseract_path = Path(
            r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        )

        if tesseract_path.exists():
            pytesseract.pytesseract.tesseract_cmd = str(
                tesseract_path
            )

        image = Image.open(path)

        return pytesseract.image_to_string(
            image
        )

    except ImportError as exc:
        raise RuntimeError(
            "OCR dependencies are not installed. "
            "Run: pip install pytesseract Pillow"
        ) from exc

    except Exception as exc:
        raise RuntimeError(
            f"Tesseract OCR failed: {exc}"
        ) from exc


# ============================================================
# DOCUMENT READER
# ============================================================

def read_document(path: str):
    path_obj = Path(path)
    suffix = path_obj.suffix.lower()

    if suffix in {".png", ".jpg", ".jpeg"}:
        return (
            _ocr_image(path),
            "IMAGE_OCR"
        )

    if suffix == ".txt":
        return (
            path_obj.read_text(
                encoding="utf-8",
                errors="ignore"
            ),
            "TEXT"
        )

    if suffix == ".pdf":
        try:
            from pypdf import PdfReader

            reader = PdfReader(path)

            text = "\n".join(
                page.extract_text() or ""
                for page in reader.pages
            )

            # If PDF text extraction is empty,
            # attempt OCR is not automatically done here.
            return text, "PDF_TEXT"

        except ImportError as exc:
            raise RuntimeError(
                "pypdf is required for PDF files. "
                "Run: pip install pypdf"
            ) from exc

    if suffix == ".docx":
        try:
            from docx import Document as DocxDocument

            document = DocxDocument(path)

            paragraphs = [
                p.text
                for p in document.paragraphs
                if p.text.strip()
            ]

            return (
                "\n".join(paragraphs),
                "DOCX_TEXT"
            )

        except ImportError as exc:
            raise RuntimeError(
                "python-docx is required for DOCX files. "
                "Run: pip install python-docx"
            ) from exc

    raise RuntimeError(
        f"Unsupported unstructured file: {suffix}"
    )

# ============================================================
# CRIMELENS ENTITY + RELATIONSHIP EXTRACTION
# ============================================================

def _normalize_text(value):
    return re.sub(r"\s+", " ", str(value or "").strip())


def _entity_lookup(known_entities):
    """
    Build lookup tables from entities already stored in the database.
    This allows unstructured documents to connect to canonical entities.
    """

    lookup = {}

    for entity in known_entities or []:
        key = entity.get("key")
        name = _normalize_text(entity.get("name"))

        if not key or not name:
            continue

        lookup[name.lower()] = {
            "key": key,
            "label": entity.get("label", "Entity"),
            "name": name,
        }

    return lookup


def _add_relationship(
    relationships,
    seen,
    source,
    target,
    relation,
    timestamp="",
    amount=None,
):
    """
    Add a relationship only once.
    """

    if not source or not target:
        return

    if source == target:
        return

    relationship_key = (
        source,
        target,
        relation,
        timestamp or "",
    )

    if relationship_key in seen:
        return

    seen.add(relationship_key)

    relationships.append({
        "source": source,
        "target": target,
        "relation": relation,
        "timestamp": timestamp or "",
        "amount": amount,
    })


def extract_entities(text: str, known_entities=None):
    """
    Extract entities from unstructured evidence.

    Known entities from Entity Master / existing database are preferred.
    This allows names and locations to be linked across documents.
    """

    entities = []
    seen = set()

    text = text or ""

    # --------------------------------------------------------
    # 1. EXISTING CANONICAL ENTITIES
    # --------------------------------------------------------

    lookup = _entity_lookup(known_entities)

    for entity_name, entity_data in lookup.items():

        # Word-boundary style matching for names/identifiers.
        pattern = re.escape(entity_name)

        if re.search(pattern, text, re.IGNORECASE):

            _add_entity(
                entities,
                seen,
                entity_data["label"],
                entity_data["key"].split(":", 1)[1]
                if ":" in entity_data["key"]
                else entity_data["name"],
                entity_data["name"],
            )

    # --------------------------------------------------------
    # 2. PHONE NUMBERS
    # --------------------------------------------------------

    phone_pattern = (
        r"(?<!\d)"
        r"(?:\+91[\s-]?)?"
        r"[6-9]\d{9}"
        r"(?!\d)"
    )

    for match in re.findall(phone_pattern, text):

        phone = re.sub(r"\D", "", match)

        if phone.startswith("91") and len(phone) == 12:
            phone = phone[2:]

        _add_entity(
            entities,
            seen,
            "PhoneNumber",
            phone,
            phone,
        )

    # --------------------------------------------------------
    # 3. INDIAN VEHICLE REGISTRATION
    # --------------------------------------------------------

    vehicle_pattern = (
        r"\b[A-Z]{2}\d{2}[A-Z]{1,3}\d{4}\b"
    )

    for vehicle in re.findall(
        vehicle_pattern,
        text.upper()
    ):

        _add_entity(
            entities,
            seen,
            "Vehicle",
            vehicle,
            vehicle,
        )

    # --------------------------------------------------------
    # 4. BANK ACCOUNT
    # --------------------------------------------------------

    account_pattern = (
        r"\b(?:ACC|A/C|ACCOUNT)"
        r"[-_ ]?[A-Z0-9]{3,15}\b"
    )

    for account in re.findall(
        account_pattern,
        text.upper()
    ):

        account = re.sub(
            r"[^A-Z0-9]",
            "",
            account
        )

        _add_entity(
            entities,
            seen,
            "BankAccount",
            account,
            account,
        )

    return entities


# ============================================================
# RELATIONSHIP / EVENT EXTRACTION
# ============================================================

def extract_relationships(
    text: str,
    known_entities=None,
):
    """
    Extract conservative, evidence-supported relationships
    from unstructured investigation documents.

    IMPORTANT:
    We only create a relationship when the text contains
    a recognizable relationship pattern.
    """

    relationships = []
    seen = set()

    text = text or ""

    lookup = _entity_lookup(known_entities)

    # --------------------------------------------------------
    # Find entities mentioned in a sentence
    # --------------------------------------------------------

    def entities_in_sentence(sentence):

        found = []

        for name_lower, entity in lookup.items():

            if re.search(
                re.escape(name_lower),
                sentence,
                re.IGNORECASE
            ):
                found.append(entity)

        # Phones
        for phone in re.findall(
            r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",
            sentence
        ):

            phone_clean = re.sub(
                r"\D",
                "",
                phone
            )

            if (
                phone_clean.startswith("91")
                and len(phone_clean) == 12
            ):
                phone_clean = phone_clean[2:]

            found.append({
                "key": _canonical_key(
                    "PhoneNumber",
                    phone_clean
                ),
                "label": "PhoneNumber",
                "name": phone_clean,
            })

        # Vehicles
        for vehicle in re.findall(
            r"\b[A-Z]{2}\d{2}[A-Z]{1,3}\d{4}\b",
            sentence.upper()
        ):

            found.append({
                "key": _canonical_key(
                    "Vehicle",
                    vehicle
                ),
                "label": "Vehicle",
                "name": vehicle,
            })

        # Remove duplicate entities
        unique = {}

        for entity in found:

            key = entity.get("key")

            if key:
                unique[key] = entity

        return list(unique.values())

    # --------------------------------------------------------
    # Split document into sentences
    # --------------------------------------------------------

    sentences = re.split(
        r"(?<=[.!?])\s+",
        text
    )

    # --------------------------------------------------------
    # CONTACTED
    # --------------------------------------------------------

    for sentence in sentences:

        if not re.search(
            r"\b(contacted|contact|called|spoke with|spoke to)\b",
            sentence,
            re.IGNORECASE
        ):
            continue

        found = entities_in_sentence(sentence)

        persons = [
            e for e in found
            if e["label"].lower() == "person"
        ]

        if len(persons) >= 2:

            source = persons[1]
            target = persons[0]

            _add_relationship(
                relationships,
                seen,
                source["key"],
                target["key"],
                "CONTACTED",
            )

        # Person → Phone
        for person in persons:

            for phone in [
                e for e in found
                if e["label"].lower()
                in {"phonenumber", "phone"}
            ]:

                _add_relationship(
                    relationships,
                    seen,
                    person["key"],
                    phone["key"],
                    "USES_PHONE",
                )

    # --------------------------------------------------------
    # SIGHTED_AT / OBSERVED_NEAR
    # --------------------------------------------------------

    # We maintain the most recently mentioned vehicle.
    current_vehicle = None

    for sentence in sentences:

        sentence_upper = sentence.upper()

        vehicle_matches = re.findall(
            r"\b[A-Z]{2}\d{2}[A-Z]{1,3}\d{4}\b",
            sentence_upper
        )

        if vehicle_matches:

            current_vehicle = _canonical_key(
                "Vehicle",
                vehicle_matches[0]
            )

        if re.search(
            r"\b("
            r"observed near|"
            r"observed at|"
            r"seen near|"
            r"seen at|"
            r"saw .* near|"
            r"saw .* at|"
            r"seeing .* near|"
            r"seeing .* at|"
            r"sighted near|"
            r"sighted at|"
            r"reported near|"
            r"reported at|"
            r"located near|"
            r"located at|"
            r"associated with|"
            r"present at"
            r")\b",
            sentence,
            re.IGNORECASE
        ):

            found = entities_in_sentence(sentence)

            # --------------------------------------------------------
            # Witness statement: "white hatchback"
            # If the document mentions a hatchback but does not
            # repeat the registration number, use the single known
            # vehicle from the canonical entity list.
            # --------------------------------------------------------

            vehicles = [
                e for e in found
                if e["label"].lower() == "vehicle"
            ]

            if (
                not vehicles
                and re.search(
                    r"\b(hatchback|vehicle|car)\b",
                    sentence,
                    re.IGNORECASE
                )
            ):

                known_vehicles = [
                    e for e in lookup.values()
                    if e["label"].lower() == "vehicle"
                ]

                if len(known_vehicles) == 1:
                    vehicles = [known_vehicles[0]]

            locations = [
                e for e in found
                if e["label"].lower()
                == "location"
            ]

            vehicles = [
                e for e in found
                if e["label"].lower()
                == "vehicle"
            ]

            # If vehicle is not explicitly repeated,
            # use the vehicle from the preceding sentence.
            if not vehicles and current_vehicle:

                vehicles = [{
                    "key": current_vehicle,
                    "label": "Vehicle",
                    "name": current_vehicle.split(
                        ":",
                        1
                    )[-1],
                }]

            for vehicle in vehicles:

                for location in locations:

                    _add_relationship(
                        relationships,
                        seen,
                        vehicle["key"],
                        location["key"],
                        "SIGHTED_AT",
                    )

    # --------------------------------------------------------
    # PERSON → LOCATION
    # --------------------------------------------------------

    for sentence in sentences:

        if not re.search(
            r"\b("
            r"seen near|"
            r"seen at|"
            r"saw .* near|"
            r"saw .* at|"
            r"seeing .* near|"
            r"seeing .* at|"
            r"observed near|"
            r"observed at|"
            r"located at|"
            r"located near|"
            r"present at|"
            r"described as .* near|"
            r"described as .* at"
            r")\b",
            sentence,
            re.IGNORECASE
        ):
            continue

        found = entities_in_sentence(sentence)

        persons = [
            e for e in found
            if e["label"].lower() == "person"
        ]

        locations = [
            e for e in found
            if e["label"].lower() == "location"
        ]

        for person in persons:

            for location in locations:

                _add_relationship(
                    relationships,
                    seen,
                    person["key"],
                    location["key"],
                    "SIGHTED_AT",
                )

    # --------------------------------------------------------
    # INCIDENT → LOCATION
    # --------------------------------------------------------

    location_pattern = re.compile(
        r"\b(at|near|inside|outside)\s+"
        r"([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,4})",
        re.IGNORECASE
    )

    # If an incident entity exists in the known master,
    # connect it only when the text explicitly indicates
    # an incident location.
    incidents = [
        e for e in lookup.values()
        if e["label"].lower() == "incident"
    ]

    if incidents:

        incident = incidents[0]

        for sentence in sentences:

            if not re.search(
                r"\b("
                r"incident|occurred|reported"
                r")\b",
                sentence,
                re.IGNORECASE
            ):
                continue

            found = entities_in_sentence(sentence)

            locations = [
                e for e in found
                if e["label"].lower()
                == "location"
            ]

            for location in locations:

                _add_relationship(
                    relationships,
                    seen,
                    incident["key"],
                    location["key"],
                    "OCCURRED_AT",
                )

    return relationships

# ============================================================
# CASE BACKBONE
# ============================================================

def create_case_backbone(
    case_id,
    case_name,
    entities,
    relationships,
):
    """
    Connect all evidence entities to the investigation case.

    This does NOT claim that entities are directly related.
    It records that they belong to the same investigation.
    """

    if not case_id:
        return

    case_key = f"CASE:{case_id}"

    # Add case as a graph entity
    case_entity = {
        "label": "Case",
        "name": case_name or case_id,
        "key": case_key,
    }

    entities.append(case_entity)

    # Avoid duplicate case links
    existing = {
        (
            r.get("source"),
            r.get("target"),
            r.get("relation")
        )
        for r in relationships
    }

    for entity in list(entities):

        key = entity.get("key")

        if not key:
            continue

        if key == case_key:
            continue

        relationship_key = (
            key,
            case_key,
            "PART_OF_CASE"
        )

        if relationship_key in existing:
            continue

        relationships.append({
            "source": key,
            "target": case_key,
            "relation": "PART_OF_CASE",
            "timestamp": "",
            "amount": None,
        })

        existing.add(relationship_key)
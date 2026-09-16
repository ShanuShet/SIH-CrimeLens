"""
Deterministic risk scoring for CrimeLens.

Design rules
------------
The score is computed from investigation data that already exists in the
database - nothing is invented, sampled, randomised or time dependent. The same
graph always produces the same score, and every point of the score is
attributable to a named factor with its raw measurement and weight, so a score
can be explained to an investigator.

Inputs used (all real, all already stored):

  * investigative relationship count touching the entity (degree)
  * number of distinct connected entities (counterparties)
  * number of distinct relationship types touching the entity
  * how much of the case is reachable within RISK_REACH_HOPS hops
  * the sum of Relationship.amount on edges touching the entity

``PART_OF_CASE`` edges are excluded
-----------------------------------
``create_case_backbone`` links every ingested entity to its case node and states
explicitly that this "does NOT claim that entities are directly related. It
records that they belong to the same investigation." Those edges are case
membership, not investigative connectivity. Counting them would hand every
entity a free point of connectivity and would rank the synthetic ``CASE:*`` node
as the most connected node in every case, so they are excluded from every
connectivity measurement and counted separately for reporting.

Entity risk is case scoped, stored risk is an aggregate
-------------------------------------------------------
``Entity.risk`` is a case-blind column: the same canonical entity (for example a
phone number) can appear in several cases. A case-relative score therefore must
never be read from that column inside a case context, because Case A would show a
number influenced by Case B. Consequently:

  * every case-scoped surface (graph, entity detail, statistics, assistant)
    computes risk for the active case and never reads ``Entity.risk``;
  * ``Entity.risk`` is still maintained, but only as the documented aggregate
    "highest computed risk this entity has in any investigation", so the column
    is meaningful for direct database inspection and legacy consumers;
  * the three concepts stay distinct: entity risk (per case), case risk (whole
    case), computed risk (the derived number both of those are built from).
"""

from collections import deque

from ..models import Case, Entity, Relationship

# Case-membership edge created by ingestion.create_case_backbone. Never treated
# as investigative connectivity.
PART_OF_CASE = "PART_OF_CASE"

# Synthetic graph node that represents the investigation itself.
CASE_NODE_PREFIX = "CASE:"

# Matches the "Risk score >= 70" description already shown in the dashboard KPI.
HIGH_RISK_THRESHOLD = 70.0

# How far the "reach" factor looks. Small on purpose: an investigation graph is
# shallow, and a larger radius would saturate every entity in a connected case.
RISK_REACH_HOPS = 3

# Entity factor weights. They sum to 1.0, so the weighted score is inherently
# bounded and 100 points means "maximal on every measured factor".
ENTITY_WEIGHTS = {
    "connectivity": 0.30,
    "counterparties": 0.25,
    "reach": 0.25,
    "relation_diversity": 0.10,
    "financial_exposure": 0.10,
}

# Case factor weights, also summing to 1.0. All four are derived from the case's
# own graph, so no external threshold or assumed currency scale is involved.
CASE_WEIGHTS = {
    "peak_entity_risk": 0.40,
    "connectivity_density": 0.25,
    "linked_fraction": 0.20,
    "mean_entity_risk": 0.15,
}

# How many investigative links an entity needs before connectivity is considered
# fully expressed. Investigations are shallow, so a small absolute saturation is
# used instead of a case-relative maximum: a case-relative maximum would award a
# perfect connectivity score to the best-connected entity of a two-entity case.
CONNECTIVITY_SATURATION = 8

# Distinct connected entities needed for the counterparties factor to saturate.
COUNTERPARTY_SATURATION = 5

# Distinct relationship types needed for the diversity factor to saturate.
RELATION_TYPE_SATURATION = 4

# Fraction of the case's other entities that must be reachable within
# RISK_REACH_HOPS for the reach factor to saturate. Being able to touch most of
# an investigation is itself the signal; a larger radius would saturate every
# entity in a connected case and stop discriminating.
REACH_FRACTION_SATURATION = 0.6

# Share of the case's largest recorded exposure that saturates the financial
# factor. Relative to the case because Relationship.amount carries no currency
# unit, so any absolute threshold would be invented.
FINANCIAL_RATIO_SATURATION = 0.75

# Investigative edges relative to all possible entity pairs. Real investigations
# are sparse, so a low saturation keeps the factor meaningful.
CONNECTIVITY_DENSITY_SATURATION = 0.10

# Score bands, highest threshold first.
RISK_BANDS = (
    (85.0, "CRITICAL"),
    (70.0, "HIGH"),
    (40.0, "MODERATE"),
    (0.0, "LOW"),
)


def risk_band(score):
    """Map a 0..100 score onto its band."""

    for threshold, name in RISK_BANDS:
        if float(score) >= threshold:
            return name

    return "LOW"


def is_case_node(key):
    """True for the synthetic ``CASE:<id>`` node."""

    return str(key or "").upper().startswith(CASE_NODE_PREFIX)


def is_investigative(relationship):
    """False for case-membership edges, which are not investigative links."""

    return str(relationship.relation or "").upper() != PART_OF_CASE


def clamp_unit(value):
    """Clamp a factor into 0..1, guarding against division edge cases."""

    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0

    if value != value:  # NaN
        return 0.0

    return min(1.0, max(0.0, value))


def numeric(value):
    """Read a stored amount without trusting its type or sign."""

    try:
        return abs(float(value))
    except (TypeError, ValueError):
        return 0.0


def canonical_relation(relation):
    """Normalise a relationship type so equivalents are counted once."""

    text = str(relation or "").strip().upper().replace(" ", "_")

    return text or "RELATED_TO"


def reachable_within(start, adjacency, hops):
    """Distinct nodes reachable from ``start`` within ``hops`` investigative links."""

    seen = {start}
    frontier = [start]

    for _ in range(max(0, int(hops))):

        following = []

        for node in frontier:
            for other, _, _ in adjacency.get(node, []):
                if other not in seen:
                    seen.add(other)
                    following.append(other)

        frontier = following

        if not frontier:
            break

    seen.discard(start)

    return seen


def build_case_graph(entities, relationships):
    """
    Build the case's investigative graph from rows that are already loaded.

    Returns (index, adjacency, investigative, membership_count):

      index            entity key -> Entity row
      adjacency        entity key -> [(other key, relation, amount), ...]
      investigative    the Relationship rows that represent investigative links
      membership_count number of PART_OF_CASE rows that were set aside
    """

    index = {entity.key: entity for entity in entities if entity.key}

    adjacency = {key: [] for key in index}

    investigative = []
    membership_count = 0

    for relationship in relationships:

        if not is_investigative(relationship):
            membership_count += 1
            continue

        source = relationship.source
        target = relationship.target

        if not source or not target:
            continue

        investigative.append(relationship)

        if source == target:
            # A self-loop is recorded evidence but adds no connectivity and no
            # counterparty, so it stays out of the adjacency used for scoring.
            continue

        adjacency.setdefault(source, []).append(
            (target, relationship.relation, relationship.amount)
        )
        adjacency.setdefault(target, []).append(
            (source, relationship.relation, relationship.amount)
        )

    return index, adjacency, investigative, membership_count


def make_factor(name, value, weight, raw, unit, note=""):
    """
    One attributable component of a score.

    ``value`` is normalised into 0..1 and clamped, so a factor can never exceed its
    weight. ``points`` is rounded once, and the final score is the sum of the
    rounded points, which keeps a report internally consistent: the factors shown
    to an investigator always add up exactly to the score.
    """

    normalized = clamp_unit(value)

    factor = {
        "factor": name,
        "value": raw,
        "unit": unit,
        "normalized": round(normalized, 4),
        "weight": weight,
        "points": round(weight * 100.0 * normalized, 2),
    }

    if note:
        factor["note"] = note

    return factor


def total_from_factors(factors):
    """Score from its factors, bounded to 0..100 by construction."""

    total = sum(factor["points"] for factor in factors)

    return round(min(100.0, max(0.0, total)), 2)


def score_entities(index, adjacency, investigative):
    """
    Compute a deterministic 0..100 risk score for every entity in the case graph.

    Each score is the weighted sum of five named factors, every one of them a
    measurement of the stored graph. No factor reads the clock, a random source,
    ``Entity.risk`` or another case.
    """

    peers = sorted(key for key in index if not is_case_node(key))
    peer_count = len(peers)

    # Total recorded amount per entity. The case maximum is used as the scale so
    # no currency or absolute amount has to be assumed.
    exposure = {key: 0.0 for key in index}

    for relationship in investigative:
        amount = numeric(relationship.amount)

        if not amount:
            continue

        exposure[relationship.source] = exposure.get(relationship.source, 0.0) + amount

        if relationship.target != relationship.source:
            exposure[relationship.target] = exposure.get(relationship.target, 0.0) + amount

    peak_exposure = max(exposure.values()) if exposure else 0.0

    reports = {}

    for key in sorted(index):

        links = adjacency.get(key, [])

        degree = len(links)

        counterparties = {other for other, _, _ in links if other != key}

        relation_types = {canonical_relation(relation) for _, relation, _ in links}

        reachable = reachable_within(key, adjacency, RISK_REACH_HOPS)

        # Only peers in this case count towards reach; a synthetic case node is
        # not a subject that risk is measured against.
        reachable_peers = {item for item in reachable if item in index and not is_case_node(item)}

        reach_denominator = max(0, peer_count - 1)

        reach_ratio = (
            len(reachable_peers) / reach_denominator
            if reach_denominator > 0
            else 0.0
        )

        financial_ratio = (
            exposure.get(key, 0.0) / peak_exposure
            if peak_exposure > 0
            else 0.0
        )

        factors = [
            make_factor(
                "connectivity",
                degree / CONNECTIVITY_SATURATION,
                ENTITY_WEIGHTS["connectivity"],
                round(float(degree), 2),
                "investigative links",
            ),
            make_factor(
                "counterparties",
                len(counterparties) / COUNTERPARTY_SATURATION,
                ENTITY_WEIGHTS["counterparties"],
                float(len(counterparties)),
                "distinct connected entities",
            ),
            make_factor(
                "reach",
                reach_ratio / REACH_FRACTION_SATURATION,
                ENTITY_WEIGHTS["reach"],
                float(len(reachable_peers)),
                f"case entities reachable within {RISK_REACH_HOPS} hops",
                note=f"of {reach_denominator} other case entities",
            ),
            make_factor(
                "relation_diversity",
                len(relation_types) / RELATION_TYPE_SATURATION,
                ENTITY_WEIGHTS["relation_diversity"],
                float(len(relation_types)),
                "distinct relationship types",
            ),
            make_factor(
                "financial_exposure",
                financial_ratio / FINANCIAL_RATIO_SATURATION,
                ENTITY_WEIGHTS["financial_exposure"],
                round(exposure.get(key, 0.0), 2),
                "recorded amount touching this entity",
                note=(
                    f"case peak recorded amount {round(peak_exposure, 2)}"
                    if peak_exposure > 0
                    else "no amount recorded in this case"
                ),
            ),
        ]

        score = total_from_factors(factors)

        reports[key] = {
            "key": key,
            "label": index[key].label,
            "name": index[key].name,
            "score": score,
            "band": risk_band(score),
            "basis": "COMPUTED_FROM_CASE_GRAPH",
            "synthetic": is_case_node(key),
            "degree": degree,
            "counterparties": len(counterparties),
            "relation_types": sorted(relation_types),
            "reachable": len(reachable_peers),
            "exposure": round(exposure.get(key, 0.0), 2),
            "factors": factors,
        }

    return reports


def score_case(index, adjacency, investigative, entity_reports):
    """
    Aggregate the case's own graph into a single deterministic 0..100 score.

    The four factors are all relative measurements of the same case, so a case is
    never scored against another case and never against an assumed scale. The
    synthetic case node is excluded so the investigation is not scored against
    itself.
    """

    peers = sorted(key for key in index if not is_case_node(key))
    peer_count = len(peers)

    scores = [entity_reports[key]["score"] for key in peers if key in entity_reports]

    peak_ratio = (max(scores) / 100.0) if scores else 0.0
    mean_ratio = (sum(scores) / len(scores) / 100.0) if scores else 0.0

    peer_set = set(peers)

    internal_edges = sum(
        1
        for relationship in investigative
        if relationship.source in peer_set
        and relationship.target in peer_set
        and relationship.source != relationship.target
    )

    possible_pairs = peer_count * (peer_count - 1) / 2

    density = internal_edges / possible_pairs if possible_pairs > 0 else 0.0

    linked = sum(
        1
        for key in peers
        if entity_reports.get(key, {}).get("degree", 0) > 0
    )

    linked_fraction = linked / peer_count if peer_count > 0 else 0.0

    factors = [
        make_factor(
            "peak_entity_risk",
            peak_ratio,
            CASE_WEIGHTS["peak_entity_risk"],
            round(max(scores), 2) if scores else 0.0,
            "highest entity risk in this case",
        ),
        make_factor(
            "connectivity_density",
            density / CONNECTIVITY_DENSITY_SATURATION,
            CASE_WEIGHTS["connectivity_density"],
            round(density, 4),
            "investigative links per possible entity pair",
            note=f"{internal_edges} links among {peer_count} entities",
        ),
        make_factor(
            "linked_fraction",
            linked_fraction,
            CASE_WEIGHTS["linked_fraction"],
            float(linked),
            "entities with at least one investigative link",
            note=f"of {peer_count} entities",
        ),
        make_factor(
            "mean_entity_risk",
            mean_ratio,
            CASE_WEIGHTS["mean_entity_risk"],
            round(sum(scores) / len(scores), 2) if scores else 0.0,
            "mean entity risk in this case",
        ),
    ]

    score = total_from_factors(factors)

    return {
        "score": score,
        "band": risk_band(score),
        "basis": "COMPUTED_FROM_CASE_GRAPH" if peer_count else "NO_INVESTIGATIVE_GRAPH",
        "factors": factors,
        "counts": {
            "entities": peer_count,
            "scored_entities": len(scores),
            "linked_entities": linked,
            "isolated_entities": peer_count - linked,
            "investigative_relationships": len(investigative),
            "internal_relationships": internal_edges,
            "membership_relationships": None,  # filled in by compute_case_risk
        },
    }


def compute_case_risk_from_rows(entities, relationships, case=None, case_id=None):
    """
    Full risk report for one case, built from rows that are already loaded.

    This is the single scoring entry point: the graph payload, the entity detail
    view, the dashboard counters and the stored aggregate all call it, so a score
    can never disagree between two screens.
    """

    index, adjacency, investigative, membership_count = build_case_graph(
        entities, relationships
    )

    entity_reports = score_entities(index, adjacency, investigative)

    case_report = score_case(index, adjacency, investigative, entity_reports)

    case_report["counts"]["membership_relationships"] = membership_count
    case_report["declared_risk"] = getattr(case, "risk", None) if case else None
    case_report["declared_risk_note"] = (
        "Manually recorded case label, not the computed score."
    )

    return {
        "case_id": case_id,
        "basis": "COMPUTED_FROM_CASE_GRAPH" if index else "NO_INVESTIGATIVE_GRAPH",
        "algorithm": "weighted-sum-v1",
        "entity_weights": dict(ENTITY_WEIGHTS),
        "case_weights": dict(CASE_WEIGHTS),
        "high_risk_threshold": HIGH_RISK_THRESHOLD,
        "excluded_relations": [PART_OF_CASE],
        "entities": entity_reports,
        "case": case_report,
    }


def compute_case_risk(db, case_id=None, case=None):
    """
    Load one case's graph and return its full risk report.

    The load is case scoped, so a report for Case A can never contain a Case B
    entity or relationship.
    """

    query = db.query(Relationship)

    if case_id is not None:
        query = query.filter(Relationship.case_id == case_id)

    relationships = query.all()

    keys = set()

    for relationship in relationships:
        if relationship.source:
            keys.add(relationship.source)
        if relationship.target:
            keys.add(relationship.target)

    entities = (
        db.query(Entity).filter(Entity.key.in_(keys)).all() if keys else []
    )

    if case is None and case_id is not None:
        case = db.query(Case).filter(Case.id == case_id).first()

    return compute_case_risk_from_rows(
        entities, relationships, case=case, case_id=case_id
    )


def risk_scores_for_rows(entities, relationships, case=None, case_id=None):
    """
    Convenience wrapper for callers that already hold the case's rows.

    Returns (entities_payload, case_payload) where ``entities_payload`` maps an
    entity key onto the whole per-entity risk report.
    """

    report = compute_case_risk_from_rows(
        entities, relationships, case=case, case_id=case_id
    )

    return report["entities"], report["case"]


def stored_risk_basis(case_id):
    """
    Basis label for a risk number that was not computed for one case.

    ``Entity.risk`` is a case-blind column, so a context without an active case
    must say so instead of presenting an aggregate as if it were case scoped.
    """

    if case_id is None:
        return "STORED_CROSS_CASE_AGGREGATE"

    return "COMPUTED_FROM_CASE_GRAPH"


def refresh_stored_entity_risk(db, case_ids=None):
    """
    Recompute ``Entity.risk`` as documented: the highest computed risk the entity
    has in any investigation.

    The column is case blind by construction, so it is never used to answer a
    case-scoped question - every case-scoped surface recomputes instead. It is kept
    truthful for direct database inspection and for legacy consumers that predate
    case-aware scoring.

    Mutates the session but never commits: transaction control belongs to the
    caller (see the ingestion transaction).
    """

    case_rows = db.query(Case).order_by(Case.id.asc()).all()

    if case_ids is not None:
        wanted = set(case_ids)
        case_rows = [case for case in case_rows if case.id in wanted]

    highest = {}

    for case in case_rows:
        report = compute_case_risk(db, case.id, case=case)

        for key, entry in report["entities"].items():
            if is_case_node(key):
                continue
            if key not in highest or entry["score"] > highest[key]:
                highest[key] = entry["score"]

    changed = 0

    for entity in db.query(Entity).all():
        target = round(highest.get(entity.key, 0.0), 2)
        current = round(float(entity.risk or 0.0), 2)
        if current != target:
            entity.risk = target
            changed += 1

    return changed



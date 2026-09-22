"""
Role based access control (RBAC) for CrimeLens.

Authentication answers "who is this user?". This module answers the separate
question "what is this user's role allowed to do?".

Authentication and authorization are intentionally kept apart: the session
cookie proves identity, and every protected endpoint additionally asks this
module whether the authenticated role may perform the requested action.

The matrix is deliberately small and explicit so that endpoints and UI
controls can be audited against one definition:

    Admin         full platform control
    Investigator  investigative workflow (cases, evidence, graph, assistant)
    Auditor       read-only oversight plus ledger and integrity verification

Unknown, missing or tampered role values receive no permissions at all, so an
unexpected role fails closed instead of silently acting as an investigator.
"""

# ---------------------------------------------------------------------------
# ROLES
# ---------------------------------------------------------------------------

ROLE_ADMIN = "Admin"
ROLE_INVESTIGATOR = "Investigator"
ROLE_AUDITOR = "Auditor"

KNOWN_ROLES = (
    ROLE_ADMIN,
    ROLE_INVESTIGATOR,
    ROLE_AUDITOR,
)

# ---------------------------------------------------------------------------
# PERMISSIONS
# ---------------------------------------------------------------------------

PERM_CASE_VIEW = "case:view"
PERM_CASE_CREATE = "case:create"
PERM_CASE_DELETE = "case:delete"
PERM_EVIDENCE_VIEW = "evidence:view"
PERM_EVIDENCE_INGEST = "evidence:ingest"
PERM_EVIDENCE_VERIFY = "evidence:verify"
PERM_ENTITY_VIEW = "entity:view"
PERM_ENTITY_PHOTO = "entity:photo"
PERM_GRAPH_VIEW = "graph:view"
PERM_ASSISTANT_QUERY = "assistant:query"
PERM_SECURITY_VIEW = "security:view"
PERM_LEDGER_VIEW = "ledger:view"
PERM_LEDGER_VERIFY = "ledger:verify"

PERMISSION_DESCRIPTIONS = {
    PERM_CASE_VIEW: "view case workspaces",
    PERM_CASE_CREATE: "create cases",
    PERM_CASE_DELETE: "delete cases and associated investigation data",
    PERM_EVIDENCE_VIEW: "view the evidence register",
    PERM_EVIDENCE_INGEST: "ingest evidence",
    PERM_EVIDENCE_VERIFY: "verify evidence integrity",
    PERM_ENTITY_VIEW: "view entity records",
    PERM_ENTITY_PHOTO: "attach entity photographs",
    PERM_GRAPH_VIEW: "view the investigation graph",
    PERM_ASSISTANT_QUERY: "query the investigation assistant",
    PERM_SECURITY_VIEW: "view the Security Center",
    PERM_LEDGER_VIEW: "view the audit ledger",
    PERM_LEDGER_VERIFY: "verify the audit ledger",
}

ALL_PERMISSIONS = frozenset(PERMISSION_DESCRIPTIONS)

# ---------------------------------------------------------------------------
# ROLE MATRIX
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS = {
    ROLE_ADMIN: ALL_PERMISSIONS,

    ROLE_INVESTIGATOR: frozenset({
        PERM_CASE_VIEW,
        PERM_CASE_CREATE,
        PERM_CASE_DELETE,
        PERM_EVIDENCE_VIEW,
        PERM_EVIDENCE_INGEST,
        PERM_EVIDENCE_VERIFY,
        PERM_ENTITY_VIEW,
        PERM_ENTITY_PHOTO,
        PERM_GRAPH_VIEW,
        PERM_ASSISTANT_QUERY,
    }),

    ROLE_AUDITOR: frozenset({
        PERM_CASE_VIEW,
        PERM_EVIDENCE_VIEW,
        PERM_EVIDENCE_VERIFY,
        PERM_ENTITY_VIEW,
        PERM_GRAPH_VIEW,
        PERM_SECURITY_VIEW,
        PERM_LEDGER_VIEW,
        PERM_LEDGER_VERIFY,
    }),
}

# Case-insensitive aliases so legacy or hand-written role values resolve to the
# canonical role names instead of accidentally failing closed.
_ROLE_ALIASES = {
    "admin": ROLE_ADMIN,
    "administrator": ROLE_ADMIN,
    "investigator": ROLE_INVESTIGATOR,
    "auditor": ROLE_AUDITOR,
}

NO_PERMISSIONS = frozenset()


def normalize_role(role: str | None) -> str:
    """Return the canonical role name, or an empty string when unknown."""

    if not role:
        return ""

    return _ROLE_ALIASES.get(str(role).strip().lower(), "")


def permissions_for_role(role: str | None) -> frozenset:
    """Permissions granted to a role. Unknown roles get none (deny by default)."""

    canonical = normalize_role(role)

    if not canonical:
        return NO_PERMISSIONS

    return ROLE_PERMISSIONS.get(canonical, NO_PERMISSIONS)


def has_permission(role: str | None, permission: str) -> bool:
    """True when the role is allowed to perform the requested action."""

    if not permission:
        return False

    return permission in permissions_for_role(role)


def permission_description(permission: str) -> str:
    """Human readable description used in authorization error messages."""

    return PERMISSION_DESCRIPTIONS.get(permission, permission)


def sorted_permissions(role: str | None) -> list[str]:
    """Permissions for a role as a stable, JSON friendly list for the UI."""

    return sorted(permissions_for_role(role))
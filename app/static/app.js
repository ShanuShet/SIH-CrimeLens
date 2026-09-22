





/* CrimeLens secure frontend */
"use strict";

let cy = null;
let csrfToken = "";
let currentUser = null;
let permissions = new Set();
let currentCaseId = null;
let currentCaseTitle = "";
let graphData = { nodes: [], edges: [] };
let currentEntityType = "ALL";
let selectedEntityKey = null;

const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function apiFetch(url, options = {}) {
  const config = { ...options, credentials: "same-origin" };
  const method = String(config.method || "GET").toUpperCase();
  const headers = new Headers(config.headers || {});
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  config.headers = headers;
  const response = await fetch(url, config);
  if (response.status === 401 && !url.includes("/api/login")) {
    showLogin();
  }
  return response;
}

function caseQuery() {
  // Case-scoped requests: omit the parameter entirely when no case is selected
  // so the backend never receives an empty/invalid case_id.
  if (currentCaseId === null || currentCaseId === undefined) return "";
  const numeric = Number(currentCaseId);
  if (!Number.isFinite(numeric)) return "";
  return `?case_id=${encodeURIComponent(numeric)}`;
}

function showLogin() {
  $("loginOverlay")?.classList.remove("hidden");
  $("appShell")?.classList.add("hidden");
}

function showApp() {
  $("loginOverlay")?.classList.add("hidden");
  $("appShell")?.classList.remove("hidden");
}

/* ---------------------------------------------------------------------------
 * Role based access control (UI side).
 *
 * The session endpoint reports the permissions granted to the signed-in role.
 * They are used to hide controls the role may not use; the backend re-checks
 * every request with the same permission names, so this is presentation only.
 * ------------------------------------------------------------------------- */

function can(permission) {
  return permissions.has(permission);
}

function setPermissions(list) {
  permissions = new Set(Array.isArray(list) ? list : []);
}

function canAccessSection(id) {
  const navButton = document.querySelector(`.main-nav .nav[data-section="${id}"]`);
  const required = navButton?.dataset.permission;
  return !required || can(required);
}

function applyRoleAccess() {
  document.querySelectorAll("[data-permission]").forEach(element => {
    const required = element.dataset.permission;
    if (required) element.classList.toggle("hidden", !can(required));
  });

  const openSection = Array.from(document.querySelectorAll(".section"))
    .find(section => !section.classList.contains("hidden"));

  if (openSection && openSection.id && !canAccessSection(openSection.id)) {
    showSection("overview");
  }
}

function markSecuritySummaryRestricted() {
  ["integrityStatus", "ledgerStatus", "securityIntegrity", "securityLedger"].forEach(id => {
    const element = $(id);
    if (element) element.textContent = "RESTRICTED";
  });
}

async function checkSession() {
  try {
    const response = await fetch("/api/session", { credentials: "same-origin" });
    if (!response.ok) {
      showLogin();
      return;
    }
    const data = await response.json();
    csrfToken = data.csrf_token || "";
    currentUser = data.user || { username: data.username, role: data.role };
    setPermissions(data.permissions);
    setUser(currentUser);
    applyRoleAccess();
    showApp();
    await refreshAll();
  } catch (error) {
    console.error("Session check failed:", error);
    showLogin();
  }
}

function setUser(user) {
  const username = user?.username || "—";
  const role = user?.role || "—";
  if ($("currentUser")) $("currentUser").textContent = username;
  if ($("currentRole")) $("currentRole").textContent = role;
  if ($("roleValue")) $("roleValue").textContent = role;
  if ($("userAvatar")) $("userAvatar").textContent = username.charAt(0).toUpperCase();
}

async function login(event) {
  event.preventDefault();
  const errorBox = $("loginError");
  if (errorBox) errorBox.textContent = "";
  try {
    const response = await fetch("/api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: $("loginUsername")?.value.trim() || "",
        password: $("loginPassword")?.value || ""
      })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (errorBox) errorBox.textContent = data.detail || "Unable to sign in.";
      return;
    }
    csrfToken = data.csrf_token || "";
    currentUser = data.user;
    setPermissions(data.permissions);
    setUser(currentUser);
    applyRoleAccess();
    if ($("loginPassword")) $("loginPassword").value = "";
    showApp();
    await refreshAll();
  } catch (error) {
    if (errorBox) errorBox.textContent = "Unable to connect to CrimeLens.";
    console.error(error);
  }
}

async function logout() {
  try {
    await apiFetch("/api/logout", { method: "POST" });
  } catch (error) {
    console.error(error);
  }
  csrfToken = "";
  currentUser = null;
  setPermissions([]);
  showLogin();
} function showSection(id, pushUrl = true) {
  const sectionAliases = {
    "evidence": "evidenceSection",
    "cases": "casesSection",
    "entities": "entitiesSection",
    "relationships": "relationshipsSection",
    "graph": "graphSection",
    "risk": "riskSection",
    "assistant": "assistantSection",
    "security": "securitySection",
    "ledger": "ledgerSection",
    "overview": "overview",
  };
  const targetId = sectionAliases[id] || id;

  // Never open a section the signed-in role has no permission for.
  if (!canAccessSection(targetId) && !canAccessSection(id)) {
    console.warn(`Role is not permitted to open section "${targetId}".`);
    showSection("overview", pushUrl);
    return;
  }

  document.querySelectorAll(".section").forEach(s => s.classList.add("hidden"));
  const section = $(targetId);
  if (section) section.classList.remove("hidden");

  document.querySelectorAll(".main-nav .nav").forEach(n => {
    const s = n.dataset.section;
    n.classList.toggle("active", s === targetId || s === id);
  });

  // Update page heading title
  const titles = {
    "overview": "Command Center Dashboard",
    "casesSection": "Case Management & Dossiers",
    "evidenceSection": "Evidence Locker & Repository",
    "entitiesSection": "Entity Intelligence Master",
    "relationshipsSection": "Intelligence Connections",
    "graphSection": "Investigation Relationship Graph",
    "riskSection": "Explainable Risk Intelligence",
    "assistantSection": "Grounded Investigation Assistant",
    "securitySection": "Security Center & Audit Trail",
    "ledgerSection": "Tamper-Evident Evidence Ledger",
  };
  if ($("pageSectionTitle")) {
    $("pageSectionTitle").textContent = titles[targetId] || "Command Center";
  }

  // Synchronize browser history / URL
  if (pushUrl && window.history && window.history.pushState) {
    const urlMap = {
      "overview": "/dashboard",
      "casesSection": "/cases",
      "evidenceSection": "/evidence",
      "entitiesSection": "/entities",
      "relationshipsSection": "/relationships",
      "graphSection": "/graph",
      "riskSection": "/risk",
      "assistantSection": "/assistant",
      "securitySection": "/audit",
      "ledgerSection": "/dashboard#ledger",
    };
    const newPath = urlMap[targetId];
    if (newPath && window.location.pathname !== newPath) {
      window.history.pushState({ section: targetId }, "", newPath);
    }
  }

  if (targetId === "overview") refreshAll();
  if (targetId === "casesSection") loadCasesSection();
  if (targetId === "evidenceSection") loadDocuments();
  if (targetId === "entitiesSection") loadEntitiesTable();
  if (targetId === "relationshipsSection") loadRelationshipsTable();
  if (targetId === "graphSection") setTimeout(loadGraph, 80);
  if (targetId === "riskSection") loadRiskSection();
  if (targetId === "securitySection") loadSecurity();
  if (targetId === "ledgerSection") loadLedger();
}

async function refreshAll() {
  await loadCases();

  const tasks = [
    loadStats(),
    loadDocuments(),
    loadGraph(),
    loadCasesSection(),
    loadEntitiesTable(),
    loadRelationshipsTable(),
    loadRiskSection()
  ];

  // Security posture is oversight data: only roles with Security Center access
  // request it, everyone else sees that it is restricted.
  if (can("security:view")) {
    tasks.push(loadSecuritySummary());
  } else {
    markSecuritySummaryRestricted();
  }

  await Promise.allSettled(tasks);
}

async function loadStats() {
  try {
    const response = await apiFetch(`/api/stats${caseQuery()}`);
    if (!response.ok) return;
    const s = await response.json();

    if ($("totalCases")) $("totalCases").textContent = s.total_cases ?? 0;
    if ($("subActiveCases")) {
      $("subActiveCases").textContent = s.active_cases !== undefined
        ? `${s.active_cases} active / pending`
        : "All portfolio cases";
    }
    if ($("evidenceDocuments")) $("evidenceDocuments").textContent = s.evidence_documents ?? s.evidenceDocuments ?? 0;
    if ($("entityTotal")) $("entityTotal").textContent = s.entity_total ?? s.entities ?? 0;
    if ($("activeLeads")) $("activeLeads").textContent = s.active_leads ?? 0;
    if ($("highRisk")) $("highRisk").textContent = s.high_risk_entities ?? 0;
    if ($("failedLogins")) {
      $("failedLogins").textContent = can("security:view")
        ? (s.failed_logins ?? 0)
        : "RESTRICTED";
    }
    if ($("roleValue")) $("roleValue").textContent = s.role ?? currentUser?.role ?? "—";

    // Active Case Dossier Hero Banner in Overview
    const dossierCard = $("activeCaseDossierCard");
    if (dossierCard) {
      const c = s.selected_case;
      if (c && currentCaseId !== null) {
        if ($("dossierCaseTitle")) $("dossierCaseTitle").textContent = c.title || currentCaseTitle || `Case #${currentCaseId}`;
        if ($("dossierCaseRef")) $("dossierCaseRef").textContent = c.reference_id || `#${currentCaseId}`;
        if ($("dossierCaseRisk")) $("dossierCaseRisk").textContent = c.risk || "Medium";
        if ($("dossierCaseDesc")) $("dossierCaseDesc").textContent = c.description || "Active investigative workspace.";
        if ($("dossierStatusBadge")) {
          $("dossierStatusBadge").textContent = (c.status || "OPEN").toUpperCase();
          $("dossierStatusBadge").className = `dossier-status-badge ${String(c.status || "open").toLowerCase()}`;
        }
      } else {
        if ($("dossierCaseTitle")) $("dossierCaseTitle").textContent = "No Active Case Selected";
        if ($("dossierCaseRef")) $("dossierCaseRef").textContent = "—";
        if ($("dossierCaseRisk")) $("dossierCaseRisk").textContent = "—";
        if ($("dossierCaseDesc")) $("dossierCaseDesc").textContent = "Select a case from the portfolio or create a new case workspace to focus investigation evidence and graph queries.";
        if ($("dossierStatusBadge")) {
          $("dossierStatusBadge").textContent = "GLOBAL VIEW";
          $("dossierStatusBadge").className = "dossier-status-badge";
        }
      }
    }
  } catch (error) {
    console.error("Stats error:", error);
  }
}

let caseExplicitlyCleared = false;
let caseToDelete = null;
let allCasesList = [];

async function loadCases() {
  try {
    const response = await apiFetch("/api/cases");
    if (!response.ok) return;
    const cases = await response.json();
    allCasesList = cases;

    if ($("portfolioCaseCount")) {
      $("portfolioCaseCount").textContent = `${cases.length} LIVE`;
    }

    const main = $("cases");
    if (main) {
      const canDelete = can("case:delete");
      main.innerHTML = cases.length ? cases.map(c => {
        const isActive = currentCaseId !== null && Number(c.id) === Number(currentCaseId);
        const status = String(c.status || "Pending").toLowerCase();
        const risk = String(c.risk || "Medium").toLowerCase();
        const evCount = c.evidence_count || 0;
        const entCount = c.entity_count || 0;
        const relCount = c.relationship_count || 0;
        return `
          <div class="case-dossier-card ${isActive ? "active-case-card" : ""}" data-case-id="${escapeHtml(c.id)}">
            <div class="case-dossier-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
              <div>
                <span class="case-ref-tag">${escapeHtml(c.reference_id || `#${c.id}`)}</span>
                <h4 class="case-dossier-title">${escapeHtml(c.title)}</h4>
              </div>
              ${isActive ? `<span class="badge verified" style="font-size: 9px; letter-spacing: 0.5px;">ACTIVE CASE</span>` : ""}
            </div>
            <div class="case-dossier-body">
              <div class="case-dossier-meta">
                <span class="case-badge ${escapeHtml(status)}">${escapeHtml(status.toUpperCase())}</span>
                <span class="case-badge ${escapeHtml(risk)}">RISK: ${escapeHtml(risk.toUpperCase())}</span>
              </div>
              <p class="case-dossier-desc">${escapeHtml(c.description || "No case description provided.")}</p>
              <div class="case-counts-strip">
                <div class="case-count-item"><span>Evidence:</span> <b>${evCount}</b></div>
                <div class="case-count-item"><span>Entities:</span> <b>${entCount}</b></div>
                <div class="case-count-item"><span>Connections:</span> <b>${relCount}</b></div>
              </div>
            </div>
            <div class="case-dossier-footer">
              <button type="button" class="case-btn-open ${isActive ? "primary" : "secondary"}" data-case-id="${escapeHtml(c.id)}" data-case-title="${escapeHtml(c.title)}">
                ${isActive ? "Open Investigation" : "Activate Case"}
              </button>
              ${canDelete ? `
                <button type="button" class="danger-btn case-btn-delete" data-case-id="${escapeHtml(c.id)}" data-case-title="${escapeHtml(c.title)}" data-case-ref="${escapeHtml(c.reference_id || `#${c.id}`)}">
                  Remove Case
                </button>
              ` : ""}
            </div>
          </div>
        `;
      }).join("") : `<div class="muted" style="padding: 16px; text-align: center;">No cases available.</div>`;

      main.querySelectorAll(".case-btn-open").forEach(btn => {
        btn.addEventListener("click", () => {
          selectCase(btn.dataset.caseId);
          if (btn.textContent.trim() === "Open Investigation") {
            showSection("graphSection");
          }
        });
      });
      main.querySelectorAll(".case-btn-delete").forEach(btn => {
        btn.addEventListener("click", () => openDeleteCaseModal(btn.dataset.caseId, btn.dataset.caseTitle, btn.dataset.caseRef));
      });
    }

    const sidebar = $("sidebarCases");
    if (sidebar) {
      sidebar.innerHTML = cases.length ? cases.map(c => `
        <button class="case-side" data-case-id="${escapeHtml(c.id)}">
          <span class="case-dot"></span>${escapeHtml(c.title)}
        </button>
      `).join("") : `<div class="muted">No cases</div>`;
      sidebar.querySelectorAll(".case-side").forEach(button => {
        button.addEventListener("click", () => selectCase(button.dataset.caseId));
      });

      const caseIds = cases.map(c => Number(c.id));

      // A previously selected case can disappear between refreshes.
      if (currentCaseId !== null && !caseIds.includes(Number(currentCaseId))) {
        currentCaseId = null;
        currentCaseTitle = "";
      }

      // Always keep one explicit active case unless explicitly cleared after case deletion
      if (currentCaseId === null && cases.length && !caseExplicitlyCleared) {
        currentCaseId = Number(cases[0].id);
        currentCaseTitle = cases[0].title || "";
      } else if (currentCaseId !== null) {
        const selected = cases.find(c => Number(c.id) === Number(currentCaseId));
        if (selected) currentCaseTitle = selected.title || "";
      }

      updateActiveCaseUi();
    }
  } catch (error) {
    console.error("Cases error:", error);
  }
}

async function loadCasesSection() {
  const container = $("casesDossierGrid");
  if (!container) return;
  try {
    const response = await apiFetch("/api/cases");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    allCasesList = await response.json();
    renderCasesGrid();
  } catch (error) {
    container.innerHTML = `<div class="muted">Unable to load cases: ${escapeHtml(error.message)}</div>`;
  }
}

function renderCasesGrid() {
  const container = $("casesDossierGrid");
  if (!container) return;

  const searchVal = ($("caseSearchInput")?.value || "").toLowerCase().trim();
  const activePill = document.querySelector("#caseStatusFilters .pill.active");
  const statusFilter = activePill?.dataset.status || "ALL";

  const filtered = allCasesList.filter(c => {
    const matchesSearch = !searchVal ||
      (c.title || "").toLowerCase().includes(searchVal) ||
      (c.reference_id || "").toLowerCase().includes(searchVal) ||
      (c.description || "").toLowerCase().includes(searchVal);
    const matchesStatus = statusFilter === "ALL" || (c.status || "").toUpperCase() === statusFilter;
    return matchesSearch && matchesStatus;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="muted" style="grid-column: 1/-1; padding: 24px; text-align: center;">No cases found matching the current filter.</div>`;
    return;
  }

  const canDelete = can("case:delete");

  container.innerHTML = filtered.map(c => {
    const isActive = currentCaseId !== null && Number(c.id) === Number(currentCaseId);
    const status = String(c.status || "Pending").toLowerCase();
    const risk = String(c.risk || "Medium").toLowerCase();
    const evCount = c.evidence_count || 0;
    const entCount = c.entity_count || 0;
    const relCount = c.relationship_count || 0;
    return `
      <div class="case-dossier-card ${isActive ? "active-case-card" : ""}" data-case-id="${escapeHtml(c.id)}">
        <div class="case-dossier-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div>
            <span class="case-ref-tag">${escapeHtml(c.reference_id || `#${c.id}`)}</span>
            <h4 class="case-dossier-title">${escapeHtml(c.title)}</h4>
          </div>
          ${isActive ? `<span class="badge verified" style="font-size: 9px; letter-spacing: 0.5px;">ACTIVE CASE</span>` : ""}
        </div>
        <div class="case-dossier-body">
          <div class="case-dossier-meta">
            <span class="case-badge ${escapeHtml(status)}">${escapeHtml(status.toUpperCase())}</span>
            <span class="case-badge ${escapeHtml(risk)}">RISK: ${escapeHtml(risk.toUpperCase())}</span>
          </div>
          <p class="case-dossier-desc">${escapeHtml(c.description || "No case description provided.")}</p>
          <div class="case-counts-strip">
            <div class="case-count-item"><span>Evidence:</span> <b>${evCount}</b></div>
            <div class="case-count-item"><span>Entities:</span> <b>${entCount}</b></div>
            <div class="case-count-item"><span>Connections:</span> <b>${relCount}</b></div>
          </div>
        </div>
        <div class="case-dossier-footer">
          <button type="button" class="case-btn-open ${isActive ? "primary" : "secondary"}" data-case-id="${escapeHtml(c.id)}" data-case-title="${escapeHtml(c.title)}">
            ${isActive ? "Active Case" : "Open Case"}
          </button>
          ${canDelete ? `
            <button type="button" class="danger-btn case-btn-delete" data-case-id="${escapeHtml(c.id)}" data-case-title="${escapeHtml(c.title)}" data-case-ref="${escapeHtml(c.reference_id || `#${c.id}`)}">
              Remove Case
            </button>
          ` : ""}
        </div>
      </div>
    `;
  }).join("");

  container.querySelectorAll(".case-btn-open").forEach(btn => {
    btn.addEventListener("click", () => selectCase(btn.dataset.caseId));
  });
  container.querySelectorAll(".case-btn-delete").forEach(btn => {
    btn.addEventListener("click", () => openDeleteCaseModal(btn.dataset.caseId, btn.dataset.caseTitle, btn.dataset.caseRef));
  });
}

function openDeleteCaseModal(caseId, caseTitle, caseRef) {
  caseToDelete = { id: caseId, title: caseTitle, ref: caseRef };
  if ($("deleteCaseModalTitle")) $("deleteCaseModalTitle").textContent = caseTitle || `Case #${caseId}`;
  if ($("deleteCaseModalRef")) $("deleteCaseModalRef").textContent = caseRef || `#${caseId}`;
  if ($("deleteCaseError")) $("deleteCaseError").textContent = "";
  const confirmBtn = $("confirmDeleteCaseButton");
  if (confirmBtn) {
    confirmBtn.disabled = false;
    confirmBtn.textContent = "REMOVE CASE";
  }
  $("deleteCaseModal")?.classList.remove("hidden");
}

function closeDeleteCaseModal() {
  caseToDelete = null;
  $("deleteCaseModal")?.classList.add("hidden");
}

async function deleteCase() {
  if (!caseToDelete || !caseToDelete.id) return;
  const caseId = caseToDelete.id;
  const confirmBtn = $("confirmDeleteCaseButton");
  const errorBox = $("deleteCaseError");
  if (confirmBtn) {
    confirmBtn.disabled = true;
    confirmBtn.textContent = "Removing Case…";
  }
  if (errorBox) errorBox.textContent = "";

  try {
    const response = await apiFetch(`/api/cases/${encodeURIComponent(caseId)}`, {
      method: "DELETE"
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || `HTTP ${response.status}: Failed to delete case`);
    }

    closeDeleteCaseModal();

    // If the deleted case was the active case:
    if (Number(currentCaseId) === Number(caseId)) {
      caseExplicitlyCleared = true;
      currentCaseId = null;
      currentCaseTitle = "";
      selectedEntityKey = null;

      // Clear graph
      if (cy) {
        cy.destroy();
        cy = null;
      }
      const cyContainer = $("cy");
      if (cyContainer) {
        cyContainer.innerHTML = `
          <div class="graph-placeholder">
            <strong>Case #${escapeHtml(caseId)} was removed</strong>
            <span>Select or create a new case to investigate evidence connections</span>
          </div>
        `;
      }

      // Clear entity sidebar
      const entityList = $("entityList");
      if (entityList) entityList.innerHTML = "";
      if ($("entityCount")) $("entityCount").textContent = "0";

      // Clear entity info panel
      const entityInfo = $("entityInfo");
      if (entityInfo) {
        entityInfo.innerHTML = `<div class="panel-title"><b>ENTITY INFORMATION</b><span>NO ACTIVE CASE</span></div><p class="muted">Case removed.</p>`;
      }

      // Clear assistant chat
      const chat = $("chatLog");
      if (chat) {
        chat.innerHTML = `<div class="bot"><b>CrimeLens:</b><div>Case #${escapeHtml(caseId)} was removed. Select or create another case to continue your investigation.</div></div>`;
      }

      updateActiveCaseUi();
    }

    // Refresh case list and statistics
    await loadCases();
    await loadCasesSection();
    await loadStats();

  } catch (error) {
    if (errorBox) errorBox.textContent = error.message;
    if (confirmBtn) {
      confirmBtn.disabled = false;
      confirmBtn.textContent = "REMOVE CASE";
    }
  }
}

function updateActiveCaseUi() {
  const badge = $("activeCase");
  const scopeBadge = $("caseScopeBadge");
  const sidebarTitle = $("sidebarActiveCaseTitle");
  const sidebarMeta = $("sidebarActiveCaseMeta");
  const evidenceScope = $("evidenceCaseContextBadge");
  const evidenceBadge = $("evidenceActiveCaseBadge");
  const graphTitle = $("graphActiveCaseTitle");
  const riskBadge = $("riskActiveCaseBadge");
  const secScope = $("securityActiveCaseScope");

  if (currentCaseId === null) {
    if (badge) badge.textContent = "No case selected";
    if (scopeBadge) {
      scopeBadge.textContent = "GLOBAL SCOPE";
      scopeBadge.style.color = "var(--text-secondary)";
    }
    if (sidebarTitle) sidebarTitle.textContent = "No case selected";
    if (sidebarMeta) sidebarMeta.textContent = "Select a case to isolate scope";
    if (evidenceScope) evidenceScope.textContent = "Scope: All Cases (Global)";
    if (evidenceBadge) evidenceBadge.textContent = "All Cases (Global)";
    if (graphTitle) graphTitle.textContent = "Global / All Cases";
    if (riskBadge) riskBadge.textContent = "Global Scope";
    if (secScope) secScope.textContent = "Global / All Cases";
  } else {
    const text = currentCaseTitle ? `${currentCaseTitle} (#${currentCaseId})` : `#${currentCaseId}`;
    if (badge) badge.textContent = text;
    if (scopeBadge) {
      scopeBadge.textContent = `ACTIVE: #${currentCaseId}`;
      scopeBadge.style.color = "var(--gold)";
    }
    if (sidebarTitle) sidebarTitle.textContent = currentCaseTitle || `Case #${currentCaseId}`;
    if (sidebarMeta) sidebarMeta.textContent = `Isolated Investigation Context (#${currentCaseId})`;
    if (evidenceScope) evidenceScope.textContent = `Scope: Case #${currentCaseId} (${currentCaseTitle || "Active"})`;
    if (evidenceBadge) evidenceBadge.textContent = currentCaseTitle || `Case #${currentCaseId}`;
    if (graphTitle) graphTitle.textContent = currentCaseTitle || `Case #${currentCaseId}`;
    if (riskBadge) riskBadge.textContent = currentCaseTitle || `Case #${currentCaseId}`;
    if (secScope) secScope.textContent = `Case #${currentCaseId} — ${currentCaseTitle || "Active"}`;
  }

  // Update active class in sidebar case shortcuts
  const sidebar = $("sidebarCases");
  if (sidebar) {
    sidebar.querySelectorAll(".case-side").forEach(button => {
      button.classList.toggle(
        "active",
        currentCaseId !== null &&
        Number(button.dataset.caseId) === Number(currentCaseId)
      );
    });
  }

  // Update active state in case cards if loaded
  document.querySelectorAll(".case-dossier-card").forEach(card => {
    card.classList.toggle(
      "active-case-card",
      currentCaseId !== null &&
      Number(card.dataset.caseId) === Number(currentCaseId)
    );
  });
}

async function selectCase(caseId) {
  const numericCaseId = Number(caseId);
  if (!Number.isFinite(numericCaseId)) {
    console.error("Invalid case id:", caseId);
    return;
  }

  caseExplicitlyCleared = false;
  currentCaseId = numericCaseId;
  selectedEntityKey = null;

  // Close modals to prevent stale entity / evidence inspection
  $("entityDossierModal")?.classList.add("hidden");
  $("evidenceViewModal")?.classList.add("hidden");
  $("deleteEvidenceModal")?.classList.add("hidden");

  const selectedBtn = document.querySelector(`.case-side[data-case-id="${numericCaseId}"], .case-btn-open[data-case-id="${numericCaseId}"]`);
  if (selectedBtn) {
    currentCaseTitle = selectedBtn.dataset.caseTitle || selectedBtn.textContent.trim() || `Case #${numericCaseId}`;
  } else {
    const found = allCasesList.find(c => Number(c.id) === numericCaseId);
    if (found) currentCaseTitle = found.title || `Case #${numericCaseId}`;
  }

  updateActiveCaseUi();

  // Reset entity detail panel and search on case switch
  const entityInfo = $("entityInfo");
  if (entityInfo) {
    entityInfo.innerHTML = `<div class="panel-title"><b>ENTITY INFORMATION</b><span>SELECT A NODE</span></div><p class="muted">Select an entity to inspect its identity and available connections.</p>`;
  }
  const entitySearch = $("entitySearch");
  if (entitySearch) entitySearch.value = "";

  // Reset assistant chat to active case context
  const chat = $("chatLog");
  if (chat) {
    chat.innerHTML = `<div class="bot"><b>CrimeLens:</b><div>Active case: <b>${escapeHtml(currentCaseTitle || `Case #${numericCaseId}`)}</b>. How can I assist with this investigation?</div></div>`;
  }

  await Promise.allSettled([
    loadStats(),
    loadDocuments(),
    loadGraph(),
    loadCasesSection(),
    loadEntitiesTable(),
    loadRelationshipsTable(),
    loadRiskSection()
  ]);
}

function clearActiveCase() {
  currentCaseId = null;
  currentCaseTitle = "";
  caseExplicitlyCleared = true;
  selectedEntityKey = null;

  // Close modals to prevent stale entity / evidence inspection
  $("entityDossierModal")?.classList.add("hidden");
  $("evidenceViewModal")?.classList.add("hidden");
  $("deleteEvidenceModal")?.classList.add("hidden");

  updateActiveCaseUi();

  const entityInfo = $("entityInfo");
  if (entityInfo) {
    entityInfo.innerHTML = `<div class="panel-title"><b>ENTITY INFORMATION</b><span>GLOBAL VIEW</span></div><p class="muted">Select a case to inspect scoped entity connections.</p>`;
  }
  const chat = $("chatLog");
  if (chat) {
    chat.innerHTML = `<div class="bot"><b>CrimeLens:</b><div>No active case selected. Global intelligence mode active. Select a case workspace to focus queries.</div></div>`;
  }

  refreshAll();
}

function openCaseSwitcherModal() {
  const modal = $("caseSwitcherModal");
  const list = $("caseSwitcherModalList");
  if (!modal || !list) return;

  modal.classList.remove("hidden");
  list.innerHTML = allCasesList.length ? allCasesList.map(c => `
    <div class="case-switcher-item ${currentCaseId !== null && Number(c.id) === Number(c.id) ? "active" : ""}" data-case-id="${escapeHtml(c.id)}">
      <div>
        <b>${escapeHtml(c.title)}</b>
        <div class="muted" style="font-size: 11px;">Ref: ${escapeHtml(c.reference_id || `#${c.id}`)} &bull; Status: ${escapeHtml(c.status || "Pending")}</div>
      </div>
      <button type="button" class="btn-micro ${currentCaseId !== null && Number(c.id) === Number(c.id) ? "active" : ""}">
        ${currentCaseId !== null && Number(c.id) === Number(c.id) ? "Selected" : "Select"}
      </button>
    </div>
  `).join("") : `<div class="muted">No cases available.</div>`;

  list.querySelectorAll(".case-switcher-item").forEach(item => {
    item.addEventListener("click", () => {
      selectCase(item.dataset.caseId);
      closeCaseSwitcherModal();
    });
  });
}

function closeCaseSwitcherModal() {
  $("caseSwitcherModal")?.classList.add("hidden");
}

/* ---------------------------------------------------------------------------
 * ENTITY MASTER TABLE & FORENSIC DOSSIER DRAWER
 * ------------------------------------------------------------------------- */

let allEntitiesList = [];
let currentEntityTableFilter = "ALL";
let entitySortKey = "risk";
let entitySortDir = "desc";

async function loadEntitiesTable() {
  const tbody = $("entitiesTableBody");
  if (!tbody) return;
  try {
    const response = await apiFetch(`/api/entities${caseQuery()}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    allEntitiesList = await response.json();
    renderEntitiesTable();
  } catch (error) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted text-center">Unable to load entity intelligence: ${escapeHtml(error.message)}</td></tr>`;
  }
}

function updateEntitySortIcons() {
  const map = {
    name: "sortIconName",
    type: "sortIconType",
    relationships: "sortIconRelationships",
    resolution: "sortIconResolution",
    risk: "sortIconRisk",
  };
  for (const [key, iconId] of Object.entries(map)) {
    const el = $(iconId);
    if (!el) continue;
    if (entitySortKey === key) {
      el.textContent = entitySortDir === "asc" ? " ▲" : " ▼";
    } else {
      el.textContent = "";
    }
  }
}

function renderEntitiesTable() {
  const tbody = $("entitiesTableBody");
  if (!tbody) return;

  updateEntitySortIcons();

  const searchVal = ($("entitiesSearchInput")?.value || "").toLowerCase().trim();

  const filtered = allEntitiesList.filter(e => {
    const matchesType = currentEntityTableFilter === "ALL" || e.label === currentEntityTableFilter;
    const matchesSearch = !searchVal ||
      (e.name || "").toLowerCase().includes(searchVal) ||
      (e.key || "").toLowerCase().includes(searchVal) ||
      (e.phone || "").toLowerCase().includes(searchVal) ||
      (e.email || "").toLowerCase().includes(searchVal) ||
      (e.account || "").toLowerCase().includes(searchVal) ||
      (e.vehicle || "").toLowerCase().includes(searchVal);
    return matchesType && matchesSearch;
  });

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted text-center">No entities found in current scope.</td></tr>`;
    return;
  }

  filtered.sort((a, b) => {
    let diff = 0;
    if (entitySortKey === "risk") {
      diff = Number(a.risk || 0) - Number(b.risk || 0);
    } else if (entitySortKey === "relationships") {
      diff = Number(a.relationships_count || 0) - Number(b.relationships_count || 0);
    } else if (entitySortKey === "name") {
      diff = String(a.name || a.key || "").localeCompare(String(b.name || b.key || ""), undefined, { sensitivity: "base" });
    } else if (entitySortKey === "type") {
      diff = String(a.label || "").localeCompare(String(b.label || ""), undefined, { sensitivity: "base" });
    } else if (entitySortKey === "resolution") {
      diff = String(a.resolution_status || "").localeCompare(String(b.resolution_status || ""), undefined, { sensitivity: "base" });
    }
    return entitySortDir === "desc" ? -diff : diff;
  });

  const icons = {
    "Person": "👤",
    "PhoneNumber": "📞",
    "BankAccount": "🏦",
    "Vehicle": "🚗",
    "Location": "📍",
    "Incident": "🚨"
  };

  tbody.innerHTML = filtered.map(e => {
    const icon = icons[e.label] || "📁";
    const resStatus = String(e.resolution_status || "NEW_ENTITY").toLowerCase();
    const resClass = resStatus.includes("exact") ? "exact" :
      resStatus.includes("probable") ? "probable" :
        resStatus.includes("ambiguous") ? "ambiguous" : "new";

    // Format identifiers
    const signals = [];
    if (e.phone) signals.push(`<span>📞 ${escapeHtml(e.phone)}</span>`);
    if (e.email) signals.push(`<span>✉️ ${escapeHtml(e.email)}</span>`);
    if (e.account) signals.push(`<span>🏦 ${escapeHtml(e.account)}</span>`);
    if (e.vehicle) signals.push(`<span>🚗 ${escapeHtml(e.vehicle)}</span>`);
    if (e.identifier) signals.push(`<span>🆔 ${escapeHtml(e.identifier)}</span>`);
    const signalsHtml = signals.length ? signals.join(" &bull; ") : `<span class="muted">No secondary identifiers</span>`;

    const riskScore = Number(e.risk || 0).toFixed(1);
    const relCount = Number(e.relationships_count || 0);

    return `
      <tr>
        <td>
          <div style="display: flex; align-items: center; gap: 10px;">
            <div style="font-size: 18px;">${icon}</div>
            <div>
              <b>${escapeHtml(e.name || e.key)}</b>
              <div class="muted" style="font-size: 10px; font-family: monospace;">${escapeHtml(e.key)}</div>
            </div>
          </div>
        </td>
        <td>
          <span class="entity-type-badge">${icon} ${escapeHtml(e.label)}</span>
        </td>
        <td>
          <div class="entity-signal-list">${signalsHtml}</div>
        </td>
        <td>
          <b style="font-family: monospace; color: var(--blue-bright);">${relCount}</b>
        </td>
        <td>
          <span class="entity-res-badge ${resClass}">${escapeHtml(e.resolution_status || "NEW_ENTITY")}</span>
          ${e.match_reason ? `<div class="entity-res-reason">${escapeHtml(e.match_reason)}</div>` : ""}
        </td>
        <td>
          <b style="color: ${Number(riskScore) >= 70 ? "var(--red)" : Number(riskScore) >= 40 ? "var(--gold)" : "var(--green)"}; font-family: monospace;">
            ${riskScore}
          </b>
        </td>
        <td>
          <button type="button" class="secondary btn-sm open-dossier-btn" data-entity-key="${escapeHtml(e.key)}">
            View Dossier
          </button>
        </td>
      </tr>
    `;
  }).join("");

  tbody.querySelectorAll(".open-dossier-btn").forEach(btn => {
    btn.addEventListener("click", () => openEntityDossier(btn.dataset.entityKey));
  });
}

async function openEntityDossier(entityKey) {
  const modal = $("entityDossierModal");
  const body = $("dossierEntityBody");
  const nameEl = $("dossierEntityName");
  const subEl = $("dossierEntitySubtitle");

  if (!modal || !body) return;
  modal.classList.remove("hidden");
  body.innerHTML = `<div class="loading-box">Loading entity dossier…</div>`;

  try {
    const response = await apiFetch(`/api/entity/${encodeURIComponent(entityKey)}${caseQuery()}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    const e = data.entity || {};
    if (nameEl) nameEl.textContent = e.name || e.key;
    if (subEl) subEl.textContent = `Type: ${e.label} · Key: ${e.key} · Scope: ${currentCaseId ? `Case #${currentCaseId}` : "Cross-Case"}`;

    const rels = data.relationships || [];
    const relRows = rels.map(r => `
      <div style="display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: var(--bg-canvas); border: 1px solid var(--line-subtle); border-radius: 6px; margin-bottom: 6px;">
        <div>
          <b>${escapeHtml(r.relation)}</b> ➔ <span>${escapeHtml(r.target_name || r.target)}</span>
        </div>
        <div class="muted" style="font-family: monospace; font-size: 11px;">
          ${r.amount ? `₹${Number(r.amount).toLocaleString("en-IN")}` : ""} ${r.timestamp || ""}
        </div>
      </div>
    `).join("");

    body.innerHTML = `
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
        <div style="background: var(--bg-canvas); padding: 14px; border: 1px solid var(--line-subtle); border-radius: 8px;">
          <span style="font-size: 10px; font-weight: 800; color: var(--gold); letter-spacing: 1px; display: block; margin-bottom: 8px;">IDENTITY SIGNALS</span>
          <div style="display: flex; flex-direction: column; gap: 6px; font-size: 12px;">
            <div><b>Phone:</b> ${escapeHtml(e.phone || "—")}</div>
            <div><b>Email:</b> ${escapeHtml(e.email || "—")}</div>
            <div><b>Bank Account:</b> ${escapeHtml(e.account || "—")}</div>
            <div><b>Vehicle Plate:</b> ${escapeHtml(e.vehicle || "—")}</div>
            <div><b>Govt ID:</b> ${escapeHtml(e.identifier || "—")}</div>
          </div>
        </div>

        <div style="background: var(--bg-canvas); padding: 14px; border: 1px solid var(--line-subtle); border-radius: 8px;">
          <span style="font-size: 10px; font-weight: 800; color: var(--blue-bright); letter-spacing: 1px; display: block; margin-bottom: 8px;">FORENSIC RESOLUTION</span>
          <div style="display: flex; flex-direction: column; gap: 6px; font-size: 12px;">
            <div><b>Resolution Status:</b> <span class="entity-res-badge ${String(e.resolution_status || "").toLowerCase().includes("exact") ? "exact" : "ambiguous"}">${escapeHtml(e.resolution_status || "NEW_ENTITY")}</span></div>
            <div><b>Match Reason:</b> <span class="muted">${escapeHtml(e.match_reason || "Deterministic single-candidate resolution")}</span></div>
            <div><b>Risk Score:</b> <b style="color: ${Number(e.risk || 0) >= 70 ? "var(--red)" : "var(--gold)"}">${Number(e.risk || 0).toFixed(1)} / 100</b> (${escapeHtml(data.risk_band || "UNSCORED")})</div>
          </div>
        </div>
      </div>

      <div>
        <span style="font-size: 11px; font-weight: 800; color: var(--text-secondary); letter-spacing: 1px; display: block; margin-bottom: 10px;">CONNECTED RELATIONSHIPS (${rels.length})</span>
        ${rels.length ? relRows : `<div class="muted">No relationships recorded for this entity in the active scope.</div>`}
      </div>
    `;
  } catch (error) {
    body.innerHTML = `<div class="muted">Unable to load entity details: ${escapeHtml(error.message)}</div>`;
  }
}

/* ---------------------------------------------------------------------------
 * RELATIONSHIPS TABLE
 * ------------------------------------------------------------------------- */

let allRelationshipsList = [];

async function loadRelationshipsTable() {
  const tbody = $("relationshipsTableBody");
  if (!tbody) return;
  try {
    const response = await apiFetch(`/api/relationships${caseQuery()}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    allRelationshipsList = await response.json();
    renderRelationshipsTable();
  } catch (error) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted text-center">Unable to load connections: ${escapeHtml(error.message)}</td></tr>`;
  }
}

function renderRelationshipsTable() {
  const tbody = $("relationshipsTableBody");
  if (!tbody) return;

  const searchVal = ($("relationshipSearchInput")?.value || "").toLowerCase().trim();

  const filtered = allRelationshipsList.filter(r => {
    if (!searchVal) return true;
    return (r.source || "").toLowerCase().includes(searchVal) ||
      (r.target || "").toLowerCase().includes(searchVal) ||
      (r.relation || "").toLowerCase().includes(searchVal) ||
      (r.source_info?.name || "").toLowerCase().includes(searchVal) ||
      (r.target_info?.name || "").toLowerCase().includes(searchVal);
  });

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted text-center">No relationships found in current scope.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map(r => `
    <tr>
      <td>
        <b>${escapeHtml(r.source_info?.name || r.source)}</b>
        <div class="muted" style="font-size: 10px; font-family: monospace;">${escapeHtml(r.source)}</div>
      </td>
      <td>
        <span class="entity-type-badge" style="color: var(--blue-bright);">➔ ${escapeHtml(r.relation)} ➔</span>
      </td>
      <td>
        <b>${escapeHtml(r.target_info?.name || r.target)}</b>
        <div class="muted" style="font-size: 10px; font-family: monospace;">${escapeHtml(r.target)}</div>
      </td>
      <td>
        ${r.amount != null ? `<b style="color: var(--gold); font-family: monospace;">₹${Number(r.amount).toLocaleString("en-IN")}</b>` : `<span class="muted">—</span>`}
      </td>
      <td>
        <span style="font-family: monospace; font-size: 11px;">${escapeHtml(r.timestamp || "—")}</span>
      </td>
      <td>
        <span class="case-ref-tag">${r.case_id ? `#${escapeHtml(r.case_id)}` : "GLOBAL"}</span>
      </td>
    </tr>
  `).join("");
}

/* ---------------------------------------------------------------------------
 * RISK ANALYSIS SECTION
 * ------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------
 * RISK ANALYSIS SECTION
 * ------------------------------------------------------------------------- */

let allRiskEntities = [];
let currentRiskFilter = "ALL";
let currentRiskSort = "riskDesc";

async function loadRiskSection() {
  const scoreNum = $("riskScoreNumber");
  const bandTag = $("riskBandTag");
  const basisNote = $("riskBasisNote");
  const factorsList = $("riskFactorsList");
  const caseBadge = $("riskActiveCaseBadge");

  if (caseBadge) {
    caseBadge.textContent = currentCaseTitle ? `${currentCaseTitle} (#${currentCaseId})` : "Global View";
  }

  try {
    const response = await apiFetch(`/api/risk${caseQuery()}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const report = await response.json();

    const caseData = report.case || {};
    const score = caseData.score != null ? Number(caseData.score).toFixed(1) : "—";
    const band = caseData.band || "UNSCORED";

    if (scoreNum) scoreNum.textContent = score;
    if (bandTag) {
      bandTag.textContent = band;
      bandTag.style.color = band === "HIGH" || band === "CRITICAL" ? "var(--red)" : band === "MEDIUM" || band === "MODERATE" ? "var(--gold)" : "var(--green)";
      bandTag.style.borderColor = bandTag.style.color;
    }
    if (basisNote) {
      basisNote.textContent = report.basis || (currentCaseId ? `Computed from Case #${currentCaseId} graph` : "Select a case for scoped analysis");
    }

    // Case Contributing Factors
    const factors = caseData.factors || [];
    if (factorsList) {
      if (factors.length) {
        factorsList.innerHTML = factors.map(f => `
          <div class="risk-factor-item">
            <span class="factor-desc">${escapeHtml(f.name || f.description || f)}</span>
            <span class="factor-weight">+${Number(f.weight || f.contribution || 10).toFixed(0)}</span>
          </div>
        `).join("");
      } else {
        factorsList.innerHTML = `<div class="muted" style="padding: 12px;">No high-risk contributing factors identified in this case.</div>`;
      }
    }

    // Entity Risk Leaderboard
    allRiskEntities = Object.entries(report.entities || {}).map(([key, data]) => ({ key, ...data }));
    renderRiskEntities();
  } catch (error) {
    if (factorsList) factorsList.innerHTML = `<div class="muted">Unable to load risk factors: ${escapeHtml(error.message)}</div>`;
  }
}

function renderRiskEntities() {
  const tbody = $("riskEntitiesTableBody");
  if (!tbody) return;

  const filtered = allRiskEntities.filter(e => {
    const score = Number(e.score || 0);
    if (currentRiskFilter === "HIGH") return score >= 70;
    if (currentRiskFilter === "MEDIUM") return score >= 40 && score < 70;
    if (currentRiskFilter === "LOW") return score < 40;
    return true;
  });

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted text-center">No entities found matching risk filter "${escapeHtml(currentRiskFilter)}".</td></tr>`;
    return;
  }

  filtered.sort((a, b) => {
    if (currentRiskSort === "riskDesc") return Number(b.score || 0) - Number(a.score || 0);
    if (currentRiskSort === "riskAsc") return Number(a.score || 0) - Number(b.score || 0);
    if (currentRiskSort === "relsDesc") {
      const aCount = a.counts?.investigative_relationships || a.counts?.relationships || 0;
      const bCount = b.counts?.investigative_relationships || b.counts?.relationships || 0;
      return bCount - aCount;
    }
    if (currentRiskSort === "nameAsc") {
      return String(a.name || a.key || "").localeCompare(String(b.name || b.key || ""));
    }
    return 0;
  });

  tbody.innerHTML = filtered.map(e => {
    const score = Number(e.score || 0).toFixed(1);
    const band = String(e.band || "LOW").toUpperCase();
    const bandColor = band === "CRITICAL" || band === "HIGH" ? "var(--red)" : band === "MODERATE" || band === "MEDIUM" ? "var(--gold)" : "var(--green)";
    const relCount = e.counts?.investigative_relationships ?? e.counts?.relationships ?? 0;

    const factorsHtml = (e.factors || []).length
      ? (e.factors || []).map(f => {
        const contrib = Number(f.contribution || 0).toFixed(0);
        return `<span class="risk-factor-tag">${escapeHtml(f.name || f.description || "Factor")}: +${contrib}</span>`;
      }).join(" ")
      : `<span class="muted" style="font-size: 11px;">Baseline connectivity</span>`;

    return `
      <tr>
        <td>
          <b>${escapeHtml(e.name || e.key)}</b>
          <div class="muted" style="font-size: 10px; font-family: monospace;">${escapeHtml(e.key)}</div>
        </td>
        <td><span class="entity-type-badge">${escapeHtml(e.label || "Entity")}</span></td>
        <td><b style="color: ${bandColor}; font-family: monospace; font-size: 14px;">${score}</b></td>
        <td><span class="status-badge ${band === "HIGH" || band === "CRITICAL" ? "failed" : band === "LOW" ? "verified" : "pending"}">${band}</span></td>
        <td><div style="display: flex; flex-wrap: wrap; gap: 4px;">${factorsHtml}</div></td>
        <td><b style="font-family: monospace; color: var(--blue-bright);">${relCount}</b></td>
        <td><button type="button" class="secondary btn-sm open-dossier-btn" data-entity-key="${escapeHtml(e.key)}">Inspect</button></td>
      </tr>
    `;
  }).join("");

  tbody.querySelectorAll(".open-dossier-btn").forEach(btn => {
    btn.addEventListener("click", () => openEntityDossier(btn.dataset.entityKey));
  });
}

/* ---------------------------------------------------------------------------
 * EVIDENCE LOCKER REPOSITORY
 * ------------------------------------------------------------------------- */

let allDocumentsList = [];
let docToDelete = null;

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

async function loadDocuments() {
  const container = $("documentList");
  if (!container) return;

  if ($("evidenceCaseContextBadge")) {
    $("evidenceCaseContextBadge").textContent = currentCaseTitle ? `${currentCaseTitle} (#${currentCaseId})` : "All Cases (Global)";
  }

  try {
    const response = await apiFetch(`/api/documents${caseQuery()}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const docs = await response.json();
    allDocumentsList = docs;

    if ($("evidenceTableCount")) {
      $("evidenceTableCount").textContent = `${docs.length} ARTIFACTS`;
    }

    renderDocumentsTable();
  } catch (error) {
    container.innerHTML = `<div class="muted">Unable to load evidence: ${escapeHtml(error.message)}</div>`;
    console.error(error);
  }
}

function renderDocumentsTable() {
  const container = $("documentList");
  if (!container) return;

  const searchVal = ($("evidenceSearchInput")?.value || "").toLowerCase().trim();
  const typeFilter = $("evidenceTypeFilter")?.value || "ALL";

  const filtered = allDocumentsList.filter(doc => {
    const matchesSearch = !searchVal ||
      (doc.filename || "").toLowerCase().includes(searchVal) ||
      (doc.doc_type || "").toLowerCase().includes(searchVal) ||
      (doc.sha256 || "").toLowerCase().includes(searchVal) ||
      (doc.case_reference || "").toLowerCase().includes(searchVal);
    const matchesType = typeFilter === "ALL" ||
      (doc.doc_type || "").toUpperCase() === typeFilter ||
      (doc.file_extension || "").toUpperCase().includes(typeFilter) ||
      (doc.data_category || "").toUpperCase() === typeFilter;
    return matchesSearch && matchesType;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="muted" style="padding: 24px; text-align: center;">No evidence documents found matching filter.</div>`;
    return;
  }

  const canVerifyEvidence = can("evidence:verify");
  const canDownloadEvidence = can("evidence:view");
  const canDeleteEvidence = can("evidence:ingest") || can("case:delete");

  container.innerHTML = `
    <div class="table-wrap">
      <table class="intel-table">
        <thead>
          <tr>
            <th>FILENAME</th>
            <th>CLASSIFICATION</th>
            <th>CASE</th>
            <th>FILE SIZE</th>
            <th>INTEGRITY</th>
            <th>RAG INDEX</th>
            <th>ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          ${filtered.map(doc => {
    const isVerified = (doc.integrity_status || "").toUpperCase() === "VERIFIED";
    const integrityCls = isVerified ? "verified" : (doc.integrity_status === "TAMPERED" ? "failed" : "pending");
    const ragCls = doc.rag_indexed ? "indexed" : "pending";
    return `
              <tr>
                <td>
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 16px;">📄</span>
                    <div>
                      <b title="${escapeHtml(doc.filename)}">${escapeHtml(doc.filename)}</b>
                      <div class="muted" style="font-family: monospace; font-size: 10px;">${escapeHtml((doc.sha256 || "").slice(0, 16))}…</div>
                    </div>
                  </div>
                </td>
                <td>
                  <span class="status-badge" style="background: rgba(148,163,184,0.1); border: 1px solid var(--line-subtle); color: var(--text-secondary);">
                    ${escapeHtml(doc.doc_type || "OTHER")}
                  </span>
                  <div class="muted" style="font-size: 10px; margin-top: 2px;">${escapeHtml(doc.data_category || "UNSTRUCTURED")}</div>
                </td>
                <td>
                  <span class="case-ref-tag">${escapeHtml(doc.case_reference || (doc.case_id ? `#${doc.case_id}` : "UNLINKED"))}</span>
                </td>
                <td>
                  <span style="font-family: monospace; font-size: 11px;">${formatBytes(doc.file_size)}</span>
                </td>
                <td>
                  <span class="status-badge ${integrityCls}">${escapeHtml(doc.integrity_status || "NOT_CHECKED")}</span>
                </td>
                <td>
                  <span class="status-badge ${ragCls}">${doc.rag_indexed ? "RAG INDEXED" : "NOT INDEXED"}</span>
                </td>
                <td>
                  <div style="display: flex; gap: 6px; align-items: center;">
                    ${canVerifyEvidence ? `<button type="button" class="secondary btn-xs" data-verify-id="${escapeHtml(doc.id)}">Verify</button>` : ""}
                    <button type="button" class="secondary btn-xs" data-view-id="${escapeHtml(doc.id)}">View</button>
                    ${canDownloadEvidence && doc.sha256 ? `<a class="secondary btn-xs" href="/api/evidence/${encodeURIComponent(doc.id)}/download${caseQuery()}">Download</a>` : ""}
                    ${canDeleteEvidence ? `<button type="button" class="danger-btn btn-xs" data-delete-id="${escapeHtml(doc.id)}" data-delete-name="${escapeHtml(doc.filename)}">Delete</button>` : ""}
                  </div>
                </td>
              </tr>
            `;
  }).join("")}
        </tbody>
      </table>
    </div>
  `;

  container.querySelectorAll("[data-verify-id]").forEach(btn => {
    btn.addEventListener("click", () => verifyEvidence(btn.dataset.verifyId, btn));
  });
  container.querySelectorAll("[data-view-id]").forEach(btn => {
    btn.addEventListener("click", () => viewEvidenceDocument(btn.dataset.viewId));
  });
  container.querySelectorAll("[data-delete-id]").forEach(btn => {
    btn.addEventListener("click", () => openDeleteEvidenceModal(btn.dataset.deleteId, btn.dataset.deleteName));
  });
}

async function viewEvidenceDocument(id) {
  const modal = $("evidenceViewModal");
  const filenameEl = $("evidenceViewFilename");
  const metaEl = $("evidenceViewMeta");
  const body = $("evidenceViewBody");

  if (!modal || !body) return;
  modal.classList.remove("hidden");
  body.innerHTML = `<div class="loading-box">Loading evidence details…</div>`;

  try {
    const response = await apiFetch(`/api/documents/${encodeURIComponent(id)}${caseQuery()}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const doc = await response.json();

    if (filenameEl) filenameEl.textContent = doc.filename || `Evidence #${doc.id}`;
    if (metaEl) metaEl.textContent = `${doc.doc_type} · ${formatBytes(doc.file_size)} · ${doc.case_reference || (doc.case_id ? `Case #${doc.case_id}` : "Unlinked")}`;

    body.innerHTML = `
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 16px;">
        <div class="posture-item">
          <span>SHA-256 FINGERPRINT</span>
          <b style="font-family: monospace; font-size: 10.5px; word-break: break-all;">${escapeHtml(doc.sha256 || "None")}</b>
        </div>
        <div class="posture-item">
          <span>INTEGRITY STATUS</span>
          <b class="status-badge ${doc.integrity_status === "VERIFIED" ? "verified" : "pending"}">${escapeHtml(doc.integrity_status || "NOT_CHECKED")}</b>
        </div>
        <div class="posture-item">
          <span>RAG VECTOR STATUS</span>
          <b class="status-badge ${doc.rag_indexed ? "indexed" : "pending"}">${doc.rag_indexed ? `${doc.rag_chunks_count} Chunks Indexed` : "Pending Indexing"}</b>
        </div>
      </div>
      <div class="panel-title" style="margin-bottom: 8px;"><b>EXTRACTED EVIDENCE CONTENT PREVIEW</b></div>
      <pre style="background: var(--bg-canvas); border: 1px solid var(--line-subtle); padding: 14px; border-radius: 6px; font-size: 11px; max-height: 280px; overflow-y: auto; color: var(--text-primary); white-space: pre-wrap;">${escapeHtml(doc.content_preview || doc.structured_preview || "No preview content extracted.")}</pre>
    `;
  } catch (error) {
    body.innerHTML = `<div class="muted">Unable to inspect evidence: ${escapeHtml(error.message)}</div>`;
  }
}

function openDeleteEvidenceModal(id, filename) {
  docToDelete = { id, filename };
  if ($("deleteEvidenceModalFilename")) $("deleteEvidenceModalFilename").textContent = filename || `#${id}`;
  if ($("deleteEvidenceError")) $("deleteEvidenceError").textContent = "";
  const confirmBtn = $("confirmDeleteEvidenceBtn");
  if (confirmBtn) {
    confirmBtn.disabled = false;
    confirmBtn.textContent = "REMOVE EVIDENCE";
  }
  $("deleteEvidenceModal")?.classList.remove("hidden");
}

function closeDeleteEvidenceModal() {
  docToDelete = null;
  $("deleteEvidenceModal")?.classList.add("hidden");
}

async function deleteEvidence() {
  if (!docToDelete || !docToDelete.id) return;
  const confirmBtn = $("confirmDeleteEvidenceBtn");
  const errBox = $("deleteEvidenceError");
  if (confirmBtn) {
    confirmBtn.disabled = true;
    confirmBtn.textContent = "REMOVING…";
  }
  if (errBox) errBox.textContent = "";

  try {
    const response = await apiFetch(`/api/documents/${encodeURIComponent(docToDelete.id)}${caseQuery()}`, {
      method: "DELETE"
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
    closeDeleteEvidenceModal();
    await loadDocuments();
    await loadStats();
    await loadLedger();
  } catch (error) {
    if (errBox) errBox.textContent = `Removal failed: ${error.message}`;
    if (confirmBtn) {
      confirmBtn.disabled = false;
      confirmBtn.textContent = "REMOVE EVIDENCE";
    }
  }
}

async function loadProvenance(id, button) {
  if (button) button.disabled = true;
  try {
    const response = await apiFetch(`/api/evidence/${encodeURIComponent(id)}/provenance${caseQuery()}`);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
    if ($("uploadResult")) $("uploadResult").textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    if ($("uploadResult")) $("uploadResult").textContent = `Provenance unavailable: ${error.message}`;
    console.error(error);
  } finally {
    if (button) button.disabled = false;
  }
}

async function uploadEvidence() {
  const input = $("evidenceFiles");
  const result = $("uploadResult");
  if (!input?.files?.length) {
    if (result) result.textContent = "Choose one or more evidence files first.";
    return;
  }
  const form = new FormData();
  const docType = $("docType")?.value || "AUTO";
  form.append("doc_type", docType);

  if (
    currentCaseId === null ||
    currentCaseId === undefined ||
    !Number.isFinite(Number(currentCaseId))
  ) {
    if (result) {
      result.textContent = "Please select a case before uploading evidence.";
    }
    updateActiveCaseUi();
    return;
  }

  form.append("case_id", String(currentCaseId));

  for (const file of input.files) {
    form.append("files", file);
  }

  try {
    if (result) result.textContent = "Ingesting evidence…";
    const response = await apiFetch("/api/upload", { method: "POST", body: form });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
    if (result) result.textContent = JSON.stringify(data, null, 2);
    input.value = "";
    await refreshAll();
  } catch (error) {
    if (result) result.textContent = `Upload failed: ${error.message}`;
  }
}

async function verifyEvidence(id, button) {
  if (button) button.disabled = true;
  try {
    const response = await apiFetch(`/api/evidence/${encodeURIComponent(id)}/verify${caseQuery()}`);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
    if ($("uploadResult")) $("uploadResult").textContent = JSON.stringify(data, null, 2);
    await loadDocuments();
    await loadStats();
  } catch (error) {
    if ($("uploadResult")) $("uploadResult").textContent = `Verification failed: ${error.message}`;
    console.error(error);
  } finally {
    if (button) button.disabled = false;
  }
}

async function loadSecuritySummary() {
  try {
    const response = await apiFetch("/api/security/overview");
    if (!response.ok) return;
    const data = await response.json();
    const secure = data.evidence_integrity?.status || "REVIEW";
    const ledger = data.ledger?.valid ? "VALID" : "REVIEW";
    if ($("integrityStatus")) $("integrityStatus").textContent = secure;
    if ($("ledgerStatus")) $("ledgerStatus").textContent = ledger;
    if ($("securityIntegrity")) $("securityIntegrity").textContent = secure;
    if ($("securityLedger")) $("securityLedger").textContent = ledger;
    if ($("failedLogins")) $("failedLogins").textContent = data.failed_logins ?? 0;
  } catch (error) {
    console.error("Security summary error:", error);
  }
}

let loadedLedgerBlocks = [];

async function loadSecurity() {
  await loadSecuritySummary();
  try {
    // Populate authenticated session posture
    if ($("securityUsername")) $("securityUsername").textContent = currentUser?.username || "—";
    if ($("securityUserRole")) $("securityUserRole").textContent = currentUser?.role ? currentUser.role.toUpperCase() : "—";
    if ($("securityActiveCaseScope")) {
      $("securityActiveCaseScope").textContent = currentCaseId
        ? `Case #${currentCaseId} — ${currentCaseTitle || "Active Context"}`
        : "Global / All Cases";
    }

    const permGrid = $("securityPermissionsGrid");
    if (permGrid) {
      if (permissions && permissions.size > 0) {
        permGrid.innerHTML = Array.from(permissions).map(p => `<span class="permission-chip">✓ ${escapeHtml(p)}</span>`).join("");
      } else {
        permGrid.innerHTML = `<span class="muted">No role permissions assigned</span>`;
      }
    }

    const [eventsResponse, auditResponse] = await Promise.all([
      apiFetch("/api/security/events"),
      apiFetch("/api/security/audit")
    ]);
    const events = eventsResponse.ok ? await eventsResponse.json() : [];
    const audit = auditResponse.ok ? await auditResponse.json() : [];
    if ($("securityAuditCount")) $("securityAuditCount").textContent = `${audit.length} EVENTS`;
    renderTable($("securityEvents"), events, ["created_at", "event_type", "severity", "username", "detail", "ip"]);
    renderTable($("auditEvents"), audit, ["created_at", "action", "username", "role", "resource", "detail", "ip"]);
  } catch (error) {
    console.error("Security center error:", error);
  }
}

function renderTable(container, rows, columns) {
  if (!container) return;
  if (!rows?.length) {
    container.innerHTML = `<div class="muted">No records available.</div>`;
    return;
  }
  const labels = { created_at: "TIME", event_type: "EVENT", severity: "SEVERITY", username: "USER", action: "ACTION", role: "ROLE", resource: "RESOURCE", detail: "DETAIL", ip: "IP" };
  container.innerHTML = `<table class="table"><thead><tr>${columns.map(c => `<th>${labels[c] || c.toUpperCase()}</th>`).join("")}</tr></thead><tbody>
    ${rows.map(row => `<tr>${columns.map(c => {
    const value = row[c] ?? "";
    const cls = c === "severity" ? ` class="severity-${String(value).toLowerCase()}"` : "";
    return `<td${cls}>${escapeHtml(value)}</td>`;
  }).join("")}</tr>`).join("")}
  </tbody></table>`;
}

async function loadLedger() {
  const list = $("ledgerList");
  if (!list) return;
  try {
    const response = await apiFetch("/api/security/ledger");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    loadedLedgerBlocks = await response.json();
    renderLedgerBlocks();
  } catch (error) {
    list.innerHTML = `<div class="muted">Unable to load ledger.</div>`;
  }
}

function renderLedgerBlocks() {
  const list = $("ledgerList");
  if (!list) return;
  const q = ($("ledgerSearchInput")?.value || "").trim().toLowerCase();
  const actionFilter = $("ledgerActionFilter")?.value || "ALL";

  let filtered = loadedLedgerBlocks;
  if (actionFilter !== "ALL") {
    filtered = filtered.filter(b => (b.event_type || "").toUpperCase() === actionFilter);
  }
  if (q) {
    filtered = filtered.filter(b => {
      const str = `${b.index ?? b.block_index ?? ""} ${b.event_type || ""} ${b.block_hash || ""} ${b.previous_hash || ""} ${JSON.stringify(b.payload || "")}`.toLowerCase();
      return str.includes(q);
    });
  }

  if ($("ledgerCount")) $("ledgerCount").textContent = `${filtered.length} BLOCKS`;

  if (!filtered.length) {
    list.innerHTML = `<div class="muted text-center" style="padding: 24px;">No ledger blocks matching criteria.</div>`;
    return;
  }

  list.innerHTML = filtered.map((block, idx) => {
    const blockIndex = block.index ?? block.block_index ?? idx;
    const eventType = block.event_type || "AUDIT_EVENT";
    const prevHash = block.previous_hash || "GENESIS";
    const blockHash = block.block_hash || "";
    const createdAt = block.created_at || "—";

    return `
      <div class="ledger-block" data-block-index="${blockIndex}">
        <div class="ledger-head">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="badge" style="background: var(--bg-hover); color: var(--gold); font-family: monospace; font-size: 11px;">BLOCK #${blockIndex}</span>
            <b style="color: var(--text-primary);">${escapeHtml(eventType)}</b>
          </div>
          <span class="muted" style="font-size: 11px;">${escapeHtml(createdAt)}</span>
        </div>
        <div class="ledger-hash" style="display: flex; justify-content: space-between; align-items: center; margin-top: 6px; gap: 8px;">
          <span><b>PREV HASH:</b> <code style="font-size: 10px; color: var(--text-secondary);">${escapeHtml(prevHash.substring(0, 24))}…</code></span>
          <button type="button" class="secondary btn-xs copy-hash-btn" data-hash="${escapeHtml(prevHash)}" style="padding: 2px 6px; font-size: 10px;">Copy Prev</button>
        </div>
        <div class="ledger-hash" style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px; gap: 8px;">
          <span><b>BLOCK HASH:</b> <code style="font-size: 10px; color: var(--gold);">${escapeHtml(blockHash.substring(0, 24))}…</code></span>
          <button type="button" class="secondary btn-xs copy-hash-btn" data-hash="${escapeHtml(blockHash)}" style="padding: 2px 6px; font-size: 10px;">Copy Hash</button>
        </div>
        <div style="margin-top: 8px; display: flex; justify-content: flex-end;">
          <button type="button" class="secondary btn-xs inspect-payload-btn" data-block-idx="${blockIndex}">Inspect Canonical Payload</button>
        </div>
      </div>
    `;
  }).join("");

  list.querySelectorAll(".copy-hash-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const hash = btn.dataset.hash;
      if (hash && navigator.clipboard) {
        navigator.clipboard.writeText(hash).then(() => {
          const orig = btn.textContent;
          btn.textContent = "Copied!";
          setTimeout(() => btn.textContent = orig, 1200);
        });
      }
    });
  });

  list.querySelectorAll(".inspect-payload-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const bIdx = Number(btn.dataset.blockIdx);
      const targetBlock = loadedLedgerBlocks.find(b => (b.index ?? b.block_index) === bIdx);
      if (targetBlock) {
        if ($("ledgerPayloadTitle")) $("ledgerPayloadTitle").textContent = `Block #${bIdx} Payload · ${targetBlock.event_type || ""}`;
        if ($("ledgerPayloadSubtitle")) $("ledgerPayloadSubtitle").textContent = `Hash: ${targetBlock.block_hash || "—"}`;
        if ($("ledgerPayloadJson")) $("ledgerPayloadJson").textContent = JSON.stringify(targetBlock.payload || {}, null, 2);
        $("ledgerPayloadModal")?.classList.remove("hidden");
      }
    });
  });
}

async function verifyLedger() {
  const box = $("ledgerVerifyResult");
  if (box) { box.className = "verify-result"; box.textContent = "Verifying ledger…"; }
  try {
    const response = await apiFetch("/api/security/verify", { method: "POST" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
    if (box) {
      box.className = `verify-result ${data.valid ? "ok" : "bad"}`;
      box.textContent = data.valid
        ? `✓ Ledger valid — ${data.checked_blocks} blocks verified.`
        : `⚠ Ledger verification failed — ${data.error || "mismatch detected"}`;
    }
    await loadLedger();
    await loadSecuritySummary();
  } catch (error) {
    if (box) { box.className = "verify-result bad"; box.textContent = `Verification failed: ${error.message}`; }
  }
}

async function createCase(event) {
  event.preventDefault();
  const errorBox = $("newCaseError");
  if (errorBox) errorBox.textContent = "";
  try {
    const response = await apiFetch("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: $("newCaseName")?.value.trim(),
        reference_id: $("newCaseId")?.value.trim(),
        risk: $("newCaseRisk")?.value,
        status: $("newCaseStatus")?.value,
        description: $("newCaseDescription")?.value.trim()
      })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Unable to create case.");
    $("newCaseModal")?.classList.add("hidden");
    $("newCaseForm")?.reset();
    await loadCases();
    // Make the newly created case the active investigation case.
    if (Number.isFinite(Number(data.id))) {
      await selectCase(data.id);
    } else {
      await loadStats();
    }
  } catch (error) {
    if (errorBox) errorBox.textContent = error.message;
  }
}

async function ask(question) {
  const input = $("question");
  const chat = $("chatLog");
  const text = (question || input?.value || "").trim();
  if (!text) return;
  if (input) input.value = "";
  if (chat) {
    chat.insertAdjacentHTML("beforeend", `<div class="user"><b>You:</b><div>${escapeHtml(text)}</div></div>`);
    chat.scrollTop = chat.scrollHeight;
  }
  try {
    const response = await apiFetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        question: text,
        case_id: currentCaseId
      })
    });
    const data = await response.json().catch(() => ({}));
    const answer = data.answer || data.response || data.message || data.error || data.detail || "No response available.";
    const mode = data.mode || "RAG";
    const sources = Array.isArray(data.sources) ? data.sources : [];
    const entities = Array.isArray(data.entities) ? data.entities : [];

    let modeBadge = "";
    if (mode === "RAG_PRETRAINED_MODEL") {
      modeBadge = `<span style="font-size: 10px; background: rgba(34,197,94,0.15); color: #4ade80; border: 1px solid rgba(74,222,128,0.3); padding: 2px 6px; border-radius: 4px; margin-left: 8px;">RAG + PRETRAINED MODEL</span>`;
    } else if (mode === "RAG_LOCAL_GROUNDED") {
      modeBadge = `<span style="font-size: 10px; background: rgba(56,189,248,0.15); color: #38bdf8; border: 1px solid rgba(56,189,248,0.3); padding: 2px 6px; border-radius: 4px; margin-left: 8px;">RAG + EVIDENCE GROUNDED</span>`;
    } else if (mode === "RAG_LOCAL_FALLBACK") {
      modeBadge = `<span style="font-size: 10px; background: rgba(245,158,11,0.15); color: #fbbf24; border: 1px solid rgba(251,191,36,0.3); padding: 2px 6px; border-radius: 4px; margin-left: 8px;">RAG + LOCAL FALLBACK</span>`;
    } else if (mode === "CASE_REQUIRED") {
      modeBadge = `<span style="font-size: 10px; background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(248,113,113,0.3); padding: 2px 6px; border-radius: 4px; margin-left: 8px;">CASE REQUIRED</span>`;
    }

    let sourcesHtml = "";
    if (sources.length > 0) {
      const sourceBadges = sources.map(s => {
        const fn = escapeHtml(s.filename || "Evidence");
        const loc = s.row ? `· Row ${s.row}` : (s.section ? `· Sec ${s.section}` : "");
        const prev = escapeHtml((s.preview || "").slice(0, 120));
        return `<span class="source-badge" title="${prev}" style="display:inline-flex; align-items:center; gap:4px; background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.15); padding:2px 6px; border-radius:4px; font-size:10px; color:#cbd5e1;">📄 <b>${fn}</b> ${loc}</span>`;
      }).join(" ");
      sourcesHtml = `
        <div class="assistant-sources" style="margin-top:8px; padding-top:6px; border-top:1px solid rgba(255,255,255,0.08);">
          <div style="font-size:10px; color:#94a3b8; margin-bottom:4px; font-weight:600; text-transform:uppercase;">Evidence Provenance:</div>
          <div style="display:flex; flex-wrap:wrap; gap:4px;">${sourceBadges}</div>
        </div>`;
    }

    let entitiesHtml = "";
    if (entities.length > 0) {
      const entityPills = entities.slice(0, 6).map(e => {
        const name = escapeHtml(e.name || e.key);
        const icon = entityIcon(e.label);
        return `<span style="background:rgba(99,102,241,0.15); color:#a5b4fc; border:1px solid rgba(165,180,252,0.3); padding:1px 5px; border-radius:3px; font-size:10px;">${icon} ${name}</span>`;
      }).join(" ");
      entitiesHtml = `
        <div style="margin-top:6px; display:flex; align-items:center; gap:4px; flex-wrap:wrap;">
          <span style="font-size:10px; color:#94a3b8;">Related:</span>
          ${entityPills}
        </div>`;
    }

    if (chat) {
      chat.insertAdjacentHTML(
        "beforeend",
        `<div class="bot">
           <b>CrimeLens:</b> ${modeBadge}
           <div class="assistant-answer" style="margin-top:4px; white-space:pre-wrap;">${escapeHtml(answer)}</div>
           ${sourcesHtml}
           ${entitiesHtml}
         </div>`
      );
      chat.scrollTop = chat.scrollHeight;
    }
  } catch (error) {
    if (chat) chat.insertAdjacentHTML("beforeend", `<div class="bot"><b>CrimeLens:</b><div>Unable to process the request.</div></div>`);
  }
}

function entityIcon(type) {
  return { Person: "👤", PhoneNumber: "📞", BankAccount: "🏦", Vehicle: "🚗", Location: "📍", Incident: "🚨", Case: "📁" }[type] || "●";
}

function createEntitySidebar(nodes) {

  const list = document.getElementById("entityList");
  const count = document.getElementById("entityCount");

  if (!list) {
    console.error("ERROR: #entityList not found");
    return;
  }

  /*
   * Make sure we always have an array.
   */
  const entityNodes = Array.isArray(nodes)
    ? nodes
    : [];

  console.log(
    "CrimeLens entities received:",
    entityNodes.length
  );

  /*
   * Update count
   */
  if (count) {
    count.textContent = entityNodes.length;
  }

  /*
   * Empty state
   */
  if (entityNodes.length === 0) {

    list.innerHTML = `
            <div class="empty-state">
                <strong>No entities available</strong>
                <span>
                    No entities were returned by the investigation graph.
                </span>
            </div>
        `;

    return;
  }

  /*
   * Build entity cards
   */
  list.innerHTML = entityNodes.map(node => {

    const d = node.data || {};

    const key = String(
      d.key ||
      d.id ||
      ""
    );

    const name = String(
      d.name ||
      d.label ||
      key ||
      "Unknown Entity"
    );

    const type = String(
      d.label ||
      d.type ||
      "Entity"
    );

    const risk = d.risk ?? 0;

    return `
            <button
                type="button"
                class="entity-card"
                data-entity-key="${escapeHtml(key)}"
                data-name="${escapeHtml(name.toLowerCase())}"
                data-key="${escapeHtml(key.toLowerCase())}"
                data-type="${escapeHtml(type)}"
            >

                <div class="entity-icon">
                    ${entityIcon(type)}
                </div>

                <div class="entity-details">

                    <b>
                        ${escapeHtml(name)}
                    </b>

                    <span>
                        ${escapeHtml(type)}
                    </span>

                    <small>
                        ${escapeHtml(key)}
                    </small>

                </div>

                <div class="entity-card-risk">
                    ${risk > 0 ? `Risk ${risk}` : ""}
                </div>

                <span class="entity-arrow">
                    ›
                </span>

            </button>
        `;

  }).join("");

  /*
   * Attach real click events.
   */
  list
    .querySelectorAll(".entity-card")
    .forEach(card => {

      card.addEventListener(
        "click",
        () => {

          const key =
            card.dataset.entityKey;

          if (!key) {
            return;
          }

          selectEntity(key);
        }
      );
    });

  /*
   * Apply current search/filter.
   */
  filterEntityList();
}

function selectEntity(entityKey) {

  if (!entityKey) {
    return;
  }

  /*
   * Allow either:
   *
   * selectEntity("PERSON:P001")
   *
   * OR
   *
   * selectEntity(entityObject)
   */

  let key = "";

  if (
    typeof entityKey ===
    "object"
  ) {

    key =
      entityKey.key ||
      entityKey.id ||
      "";

  } else {

    key =
      String(entityKey);
  }

  if (!key) {
    return;
  }

  console.log(
    "Selected entity:",
    key
  );

  /*
   * -------------------------------------------------------
   * FIND ENTITY NODE
   * -------------------------------------------------------
   */

  let node = null;

  if (cy) {

    node =
      cy.getElementById(
        key
      );

    /*
     * Some graphs may use a slightly different
     * identifier. Search by key as fallback.
     */

    if (
      (!node ||
        !node.length) &&
      cy.nodes().length
    ) {

      node =
        cy.nodes().filter(
          n =>
            String(
              n.data("key") ||
              n.id()
            ) === key
        );
    }
  }

  /*
   * -------------------------------------------------------
   * GET ENTITY DATA
   * -------------------------------------------------------
   */

  let entity = null;

  if (
    node &&
    node.length
  ) {

    entity = {
      id:
        node.data("id"),

      key:
        node.data("key") ||
        node.data("id"),

      name:
        node.data("name") ||
        node.data("id"),

      label:
        node.data("label") ||
        "Entity",

      risk:
        node.data("risk") || 0
    };

  } else {

    /*
     * Fallback to graphData
     */

    const found =
      graphData.nodes.find(
        n => {

          const d =
            n.data || {};

          return (
            String(
              d.id ||
              d.key ||
              ""
            ) === key
          );
        }
      );

    if (found) {

      const d =
        found.data || {};

      entity = {

        id:
          d.id,

        key:
          d.key ||
          d.id,

        name:
          d.name ||
          d.id,

        label:
          d.label ||
          "Entity",

        risk:
          d.risk || 0
      };
    }
  }

  if (!entity) {

    console.warn(
      "Entity not found:",
      key
    );

    return;
  }

  /*
   * -------------------------------------------------------
   * HIGHLIGHT SIDEBAR CARD
   * -------------------------------------------------------
   */

  document
    .querySelectorAll(
      ".entity-card"
    )
    .forEach(card => {

      card.classList.toggle(
        "selected",
        card.dataset.entityKey ===
        key
      );
    });

  /*
   * -------------------------------------------------------
   * HIGHLIGHT GRAPH NODE
   * -------------------------------------------------------
   */

  if (
    cy &&
    node &&
    node.length
  ) {

    cy.elements()
      .removeClass(
        "selected-node"
      );

    node.addClass(
      "selected-node"
    );

    cy.animate({

      center: {
        eles: node
      },

      zoom:
        1.25,

      duration:
        450
    });
  }

  /*
   * -------------------------------------------------------
   * FETCH AUTHORITATIVE EVIDENCE-BACKED ENTITY DETAILS
   * -------------------------------------------------------
   */

  selectedEntityKey = key;
  loadEntityDetails(key);
}

async function loadEntityDetails(entityKey) {
  const panel = $("entityInfo");
  if (!panel) return;

  panel.innerHTML = `
    <div class="panel-title">
      <b>ENTITY INFORMATION</b>
      <span>LOADING</span>
    </div>
    <p class="muted">Loading evidence-backed details…</p>
  `;

  try {
    const response = await apiFetch(`/api/entity/${encodeURIComponent(entityKey)}${caseQuery()}`);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || `HTTP ${response.status}`);
    }
    renderEntityInfo(data);
  } catch (error) {
    panel.innerHTML = `
      <div class="panel-title">
        <b>ENTITY INFORMATION</b>
        <span>UNAVAILABLE</span>
      </div>
      <p class="muted">${escapeHtml(error.message || "Unable to load entity details.")}</p>
    `;
  }
}

function renderEntityInfo(data) {
  const panel = $("entityInfo");
  if (!panel) return;

  const entity = data.entity || {};
  const key = entity.key || "N/A";
  const name = entity.name || key || "Unknown Entity";
  const label = entity.label || "Entity";
  const risk = entity.risk != null ? Number(entity.risk).toFixed(2) : "0.00";
  const band = entity.risk_band || "LOW";
  const connections = Array.isArray(data.connections) ? data.connections : [];
  const connectionCount = data.connection_count ?? connections.length;
  const cases = Array.isArray(data.cases) ? data.cases : [];
  const factors = Array.isArray(entity.risk_factors) ? entity.risk_factors : [];

  const iconHtml = entity.image
    ? `<img src="${escapeHtml(entity.image)}" alt="${escapeHtml(name)}" style="width:100%;height:100%;object-fit:cover;border-radius:14px;" />`
    : entityIcon(label);

  let factorsHtml = "";
  if (factors.length > 0) {
    factorsHtml = `
      <div class="detail-section">
        <div class="detail-heading">RISK FACTORS (${escapeHtml(band)})</div>
        ${factors.map(f => `
          <div class="detail-row" style="margin-bottom:6px;">
            <span>${escapeHtml(String(f.factor || "").replace(/_/g, " "))} <small class="muted">(${escapeHtml(String(f.value ?? ""))} ${escapeHtml(f.unit || "")})</small></span>
            <strong>+${Number(f.points || 0).toFixed(2)} pts</strong>
          </div>
        `).join("")}
      </div>
    `;
  }

  let casesHtml = "";
  if (cases.length > 0) {
    casesHtml = `
      <div class="detail-section">
        <div class="detail-heading">CASE MEMBERSHIP</div>
        ${cases.map(c => `
          <div class="detail-row">
            <span>Case</span>
            <strong>${escapeHtml(c.title || c.key)}</strong>
          </div>
        `).join("")}
      </div>
    `;
  }

  let connectionsHtml = "";
  if (connections.length > 0) {
    connectionsHtml = `
      <div class="detail-section">
        <div class="detail-heading">CONNECTED ENTITIES (${connectionCount})</div>
        <div id="entityConnections" class="connection-list">
          ${connections.map(c => `
            <button type="button" class="connection-row" data-target-key="${escapeHtml(c.key)}">
              <div class="connection-main">
                <b>${escapeHtml(c.name || c.key)}</b>
                <small>${escapeHtml(c.label || "Entity")} · ${escapeHtml(c.relation_display || c.relation)}${c.amount ? ` · ₹${Number(c.amount).toLocaleString('en-IN')}` : ""}</small>
              </div>
              <span class="connection-direction">${escapeHtml(c.direction || "")}</span>
            </button>
          `).join("")}
        </div>
      </div>
    `;
  } else {
    connectionsHtml = `
      <div class="detail-section">
        <div class="detail-heading">CONNECTED ENTITIES</div>
        <div class="muted">No evidence-backed connections in this case.</div>
      </div>
    `;
  }

  panel.innerHTML = `
    <div class="panel-title">
      <b>ENTITY INFORMATION</b>
      <span>SELECTED</span>
    </div>
    <div class="entity-profile">
      <div class="entity-profile-icon">
        ${iconHtml}
      </div>
      <div>
        <h3>${escapeHtml(name)}</h3>
        <div class="entity-key">${escapeHtml(key)}</div>
        <div class="muted">${escapeHtml(label)}</div>
      </div>
    </div>
    <div class="entity-metrics">
      <div>
        <span>ENTITY TYPE</span>
        <b>${escapeHtml(label)}</b>
      </div>
      <div>
        <span>RISK</span>
        <b>${risk} <small>(${escapeHtml(band)})</small></b>
      </div>
      <div>
        <span>CONNECTIONS</span>
        <b>${connectionCount}</b>
      </div>
    </div>
    <div class="detail-section">
      <div class="detail-heading">IDENTIFICATION</div>
      <div class="detail-row">
        <span>Entity Name</span>
        <strong>${escapeHtml(name)}</strong>
      </div>
      <div class="detail-row">
        <span>Entity Type</span>
        <strong>${escapeHtml(label)}</strong>
      </div>
      <div class="detail-row">
        <span>Entity Key</span>
        <strong>${escapeHtml(key)}</strong>
      </div>
      <div class="detail-row">
        <span>Risk Basis</span>
        <strong>${escapeHtml(entity.risk_basis || "COMPUTED")}</strong>
      </div>
    </div>
    ${factorsHtml}
    ${casesHtml}
    ${connectionsHtml}
    ${renderResolutionHtml(entity)}
  `;

  panel.querySelectorAll(".connection-row[data-target-key]").forEach(btn => {
    btn.addEventListener("click", () => {
      selectEntity(btn.dataset.targetKey);
    });
  });
}

function renderResolutionHtml(entity) {
  const res = entity.resolution || {};
  if (!res.status && !entity.resolution_status) return "";
  const resStatus = res.status || entity.resolution_status || "NEW_ENTITY";
  const resReason = res.reason || entity.match_reason || "Deterministic match";
  const statusCls = String(resStatus).toLowerCase();
  return `
    <div class="detail-section">
      <div class="detail-heading">ENTITY RESOLUTION</div>
      <div class="detail-row">
        <span>Resolution Status</span>
        <span class="entity-res-badge ${escapeHtml(statusCls)}">${escapeHtml(resStatus)}</span>
      </div>
      <div class="detail-row">
        <span>Match Reason</span>
        <strong>${escapeHtml(resReason)}</strong>
      </div>
      ${res.phone ? `<div class="detail-row"><span>Normalized Phone</span><strong>${escapeHtml(res.phone)}</strong></div>` : ""}
      ${res.email ? `<div class="detail-row"><span>Normalized Email</span><strong>${escapeHtml(res.email)}</strong></div>` : ""}
      ${res.account ? `<div class="detail-row"><span>Normalized Account</span><strong>${escapeHtml(res.account)}</strong></div>` : ""}
      ${res.identifier ? `<div class="detail-row"><span>Identifier</span><strong>${escapeHtml(res.identifier)}</strong></div>` : ""}
    </div>
  `;
}

function filterEntityList() {
  const query = ($("entitySearch")?.value || "").trim().toLowerCase();
  document.querySelectorAll(".entity-card").forEach(card => {
    const nameMatch = card.dataset.name && card.dataset.name.includes(query);
    const keyMatch = card.dataset.entityKey && card.dataset.entityKey.toLowerCase().includes(query);
    const matches = !query || nameMatch || keyMatch;
    const typeMatch = currentEntityType === "ALL" || card.dataset.type === currentEntityType;
    card.style.display = matches && typeMatch ? "flex" : "none";
  });
}

function filterGraph() {
  if (!cy) return;
  const q1 = ($("graphSearch")?.value || "").trim().toLowerCase();
  const q2 = ($("entitySearch")?.value || "").trim().toLowerCase();
  const query = q1 || q2;
  const relFilter = ($("graphRelTypeFilter")?.value || "ALL").toUpperCase();
  const riskFilter = ($("graphRiskFilter")?.value || "ALL").toUpperCase();

  cy.nodes().forEach(node => {
    const d = node.data();
    const matchQuery = !query ||
      String(d.name || "").toLowerCase().includes(query) ||
      String(d.id || "").toLowerCase().includes(query) ||
      String(d.label || "").toLowerCase().includes(query) ||
      String(d.key || "").toLowerCase().includes(query);

    const matchType = currentEntityType === "ALL" || (d.label || d.type) === currentEntityType;

    let matchRisk = true;
    const score = Number(d.risk ?? d.risk_score ?? 0);
    if (riskFilter === "HIGH") matchRisk = score >= 70;
    else if (riskFilter === "MODERATE") matchRisk = score >= 40 && score < 70;
    else if (riskFilter === "LOW") matchRisk = score < 40;

    if (matchQuery && matchType && matchRisk) {
      node.show();
    } else {
      node.hide();
    }
  });

  cy.edges().forEach(edge => {
    const d = edge.data();
    const rel = (d.relation || d.relationship || "").toUpperCase();
    const matchRel = relFilter === "ALL" || rel === relFilter;
    if (edge.source().visible() && edge.target().visible() && matchRel) {
      edge.show();
    } else {
      edge.hide();
    }
  });
}

function toggleGraphNodeLabels(show) {
  if (!cy) return;
  cy.style().selector("node").style({ "label": show ? "data(displayLabel)" : "" }).update();
}

function toggleGraphEdgeLabels(show) {
  if (!cy) return;
  cy.style().selector("edge").style({ "label": show ? "data(displayRelation)" : "" }).update();
}

function fitGraph() {
  if (!cy) return;
  cy.elements().show();
  cy.fit(cy.nodes(), 70);
}

async function loadGraph() {

  const container =
    document.getElementById("cy");

  if (!container) {
    console.error(
      "Graph container #cy not found"
    );
    return;
  }

  if (
    typeof window.cytoscape !==
    "function"
  ) {

    console.error(
      "Cytoscape library not loaded"
    );

    return;
  }

  try {

    const response =
      await apiFetch(
        `/api/graph${caseQuery()}`
      );

    if (!response.ok) {

      throw new Error(
        `Graph API returned HTTP ${response.status}`
      );
    }

    const data =
      await response.json();

    console.log(
      "CrimeLens graph API:",
      data
    );

    /*
     * --------------------------------------------------
     * STORE RAW GRAPH DATA
     * --------------------------------------------------
     */

    graphData = {

      nodes:
        Array.isArray(data.nodes)
          ? data.nodes
          : [],

      edges:
        Array.isArray(data.edges)
          ? data.edges
          : []
    };

    console.log(
      "Graph nodes:",
      graphData.nodes.length
    );

    console.log(
      "Graph edges:",
      graphData.edges.length
    );

    /*
     * --------------------------------------------------
     * NORMALIZE NODES ONCE
     * --------------------------------------------------
     */

    const normalizedNodes =
      graphData.nodes.map(
        (node, index) => {

          const d =
            node.data || {};

          const id =
            String(
              d.id ||
              d.key ||
              `entity-${index}`
            );

          const rawName = String(
            d.name ||
            d.label ||
            id
          );

          const labelType = String(
            d.label ||
            d.type ||
            "Entity"
          );

          const icon = entityIcon(labelType);
          const displayLabel = `${icon} ${rawName}`;

          return {
            group:
              "nodes",

            data: {
              ...d,
              id,
              key: String(d.key || id),
              name: rawName,
              label: labelType,
              displayLabel,
              risk: Number(d.risk || 0)
            }
          };
        }
      );

    /*
     * --------------------------------------------------
     * THIS IS THE IMPORTANT PART
     *
     * Sidebar receives the SAME nodes that
     * Cytoscape receives.
     * --------------------------------------------------
     */

    createEntitySidebar(
      normalizedNodes
    );

    /*
     * --------------------------------------------------
     * VALID NODE IDS
     * --------------------------------------------------
     */

    const nodeIds =
      new Set(
        normalizedNodes.map(
          node =>
            node.data.id
        )
      );

    /*
     * --------------------------------------------------
     * NORMALIZE ALL RELATIONSHIPS
     *
     * INCLUDING PART_OF_CASE
     * --------------------------------------------------
     */

    const normalizedEdges =
      graphData.edges
        .filter(edge => {

          const source =
            String(
              edge.data?.source ||
              ""
            );

          const target =
            String(
              edge.data?.target ||
              ""
            );

          return (
            nodeIds.has(
              source
            ) &&
            nodeIds.has(
              target
            )
          );
        })
        .map(
          (edge, index) => {

            const d =
              edge.data ||
              {};

            const relation =
              String(
                d.relation ||
                "RELATED_TO"
              ).toUpperCase();

            let displayRelation =
              relation.replaceAll(
                "_",
                " "
              );

            /*
             * Show amount on
             * financial edges.
             */
            if (
              relation ===
              "TRANSFERRED_FUNDS_TO" &&
              d.amount != null
            ) {
              displayRelation =
                `TRANSFERRED ₹${Number(
                  d.amount
                ).toLocaleString(
                  "en-IN"
                )}`;
            } else if (d.amount != null) {
              displayRelation +=
                ` ₹${Number(
                  d.amount
                ).toLocaleString(
                  "en-IN"
                )}`;
            }

            if (d.timestamp) {
              const tsShort = String(d.timestamp).split("T")[0] || String(d.timestamp).slice(0, 10);
              displayRelation += ` (${tsShort})`;
            }

            return {
              group:
                "edges",

              data: {
                ...d,
                id: String(d.id || `edge-${index}`),
                source: String(d.source),
                target: String(d.target),
                relation,
                displayRelation,
                amount: d.amount,
                timestamp: d.timestamp,
                document: d.document,
                case_id: d.case_id
              }
            };
          }
        );

    /*
     * --------------------------------------------------
     * DESTROY OLD GRAPH
     * --------------------------------------------------
     */

    if (cy) {

      cy.destroy();

      cy = null;
    }

    container.innerHTML = "";

    /*
     * --------------------------------------------------
     * FIND CASE NODE
     * --------------------------------------------------
     */

    const caseNode =
      normalizedNodes.find(
        node => {

          const d =
            node.data;

          return (
            String(
              d.label
            ).toLowerCase()
            === "case"
            ||
            String(
              d.type
            ).toLowerCase()
            === "case"
            ||
            String(
              d.id
            ).toUpperCase()
              .startsWith(
                "CASE:"
              )
          );
        }
      );

    /*
     * --------------------------------------------------
     * CREATE CYTOSCAPE
     * --------------------------------------------------
     */

    cy =
      window.cytoscape({

        container,

        elements: [
          ...normalizedNodes,
          ...normalizedEdges
        ],

        style: [

          {
            selector:
              "node",

            style: {
              label:
                "data(displayLabel)",

              "background-color":
                "#334155",

              color:
                "#ffffff",

              "text-valign":
                "bottom",

              "text-halign":
                "center",

              "text-margin-y":
                9,

              "font-size":
                11,

              "font-weight":
                700,

              width:
                60,

              height:
                60,

              "border-width":
                2.5,

              "border-color":
                "#94a3b8",

              "text-outline-width":
                3,

              "text-outline-color":
                "#0f172a",

              "text-wrap":
                "ellipsis",

              "text-max-width":
                110
            }
          },

          {
            selector:
              'node[label="Person"]',

            style: {
              "background-color":
                "#2563eb",

              "border-color":
                "#60a5fa",

              shape:
                "ellipse"
            }
          },

          {
            selector:
              'node[label="PhoneNumber"]',

            style: {
              "background-color":
                "#059669",

              "border-color":
                "#34d399",

              shape:
                "diamond",

              width:
                54,

              height:
                54
            }
          },

          {
            selector:
              'node[label="BankAccount"]',

            style: {
              "background-color":
                "#d97706",

              "border-color":
                "#fbbf24",

              shape:
                "rectangle",

              width:
                62,

              height:
                52
            }
          },

          {
            selector:
              'node[label="Vehicle"]',

            style: {
              "background-color":
                "#0891b2",

              "border-color":
                "#38bdf8",

              shape:
                "roundrectangle",

              width:
                62,

              height:
                50
            }
          },

          {
            selector:
              'node[label="Location"]',

            style: {
              "background-color":
                "#7c3aed",

              "border-color":
                "#c084fc",

              shape:
                "hexagon",

              width:
                58,

              height:
                58
            }
          },

          {
            selector:
              'node[label="Organization"], node[label="Company"]',

            style: {
              "background-color":
                "#475569",

              "border-color":
                "#cbd5e1",

              shape:
                "barrel",

              width:
                64,

              height:
                54
            }
          },

          {
            selector:
              'node[label="Incident"]',

            style: {
              "background-color":
                "#dc2626",

              "border-color":
                "#f87171",

              shape:
                "triangle",

              width:
                60,

              height:
                60
            }
          },

          {
            selector:
              'node[label="Case"]',

            style: {
              "background-color":
                "#0f766e",

              "border-color":
                "#2dd4bf",

              shape:
                "roundrectangle",

              width:
                120,

              height:
                66,

              "font-size":
                12,

              "font-weight":
                800,

              "border-width":
                3.5
            }
          },

          /*
           * ALL EDGES
           */

          {
            selector:
              "edge",

            style: {

              "curve-style":
                "bezier",

              width:
                2,

              "line-color":
                "#64748b",

              "target-arrow-color":
                "#64748b",

              "target-arrow-shape":
                "triangle",

              "arrow-scale":
                0.9,

              label:
                "data(displayRelation)",

              "font-size":
                8,

              "font-weight":
                600,

              color:
                "#475569",

              "text-rotation":
                "autorotate",

              "text-background-color":
                "#ffffff",

              "text-background-opacity":
                0.92,

              "text-background-padding":
                3
            }
          },

          /*
           * CASE CONNECTION
           */

          {
            selector:
              'edge[relation="PART_OF_CASE"]',

            style: {

              "curve-style":
                "straight",

              width:
                1.8,

              "line-color":
                "#94a3b8",

              "target-arrow-color":
                "#94a3b8",

              "target-arrow-shape":
                "triangle",

              "arrow-scale":
                0.75,

              label:
                "data(displayRelation)",

              "font-size":
                7,

              color:
                "#64748b"
            }
          },

          /*
           * CALLS
           */

          {
            selector:
              'edge[relation="CALL_MADE_TO"]',

            style: {

              "line-color":
                "#16a34a",

              "target-arrow-color":
                "#16a34a",

              width:
                3
            }
          },

          /*
           * FINANCIAL
           */

          {
            selector:
              'edge[relation="TRANSFERRED_FUNDS_TO"]',

            style: {

              "line-color":
                "#d97706",

              "target-arrow-color":
                "#d97706",

              width:
                3
            }
          },

          /*
           * SIGHTED
           */

          {
            selector:
              'edge[relation="SIGHTED_AT"]',

            style: {

              "line-color":
                "#7c3aed",

              "target-arrow-color":
                "#7c3aed",

              width:
                2.5
            }
          },

          /*
           * SELECTED
           */

          {
            selector:
              "node:selected",

            style: {

              "border-width":
                5,

              "border-color":
                "#111827"
            }
          }
        ],

        layout: {
          name:
            "cose",

          animate:
            true,

          animationDuration:
            600,

          fit:
            true,

          padding:
            50,

          randomize:
            false,

          componentSpacing:
            90,

          nodeRepulsion:
            function (node) {
              return 750000;
            },

          nodeOverlap:
            30,

          idealEdgeLength:
            function (edge) {
              const rel = edge.data("relation");
              if (rel === "PART_OF_CASE") return 140;
              return 85;
            },

          edgeElasticity:
            function (edge) {
              const rel = edge.data("relation");
              if (rel === "PART_OF_CASE") return 35;
              return 100;
            },

          nestingFactor:
            1.2,

          gravity:
            50,

          numIter:
            1000,

          initialTemp:
            200,

          coolingFactor:
            0.95,

          minTemp:
            1.0
        },

        minZoom:
          0.2,

        maxZoom:
          3,

        wheelSensitivity:
          0.15
      });

    /*
     * --------------------------------------------------
     * FIT
     * --------------------------------------------------
     */

    cy.fit(
      cy.nodes(),
      70
    );

    /*
     * --------------------------------------------------
     * NODE CLICK
     * --------------------------------------------------
     */

    cy.on(
      "tap",
      "node",
      event => {

        selectEntity(
          event.target.id()
        );
      }
    );

    /*
     * --------------------------------------------------
     * EDGE CLICK
     * --------------------------------------------------
     */

    cy.on(
      "tap",
      "edge",
      event => {

        const d =
          event.target.data();

        const box =
          document.getElementById(
            "entityInfo"
          );

        if (!box) {
          return;
        }

        box.innerHTML = `

                    <div class="panel-title">

                        <b>
                            RELATIONSHIP
                        </b>

                        <span>
                            SELECTED
                        </span>

                    </div>

                    <div class="detail-section">

                        <div class="detail-row">
                            <span>
                                Relationship
                            </span>

                            <strong>
                                ${escapeHtml(
          d.displayRelation ||
          d.relation ||
          "RELATED_TO"
        )}
                            </strong>
                        </div>

                        <div class="detail-row">
                            <span>
                                Source
                            </span>

                            <strong>
                                ${escapeHtml(
          d.source
        )}
                            </strong>
                        </div>

                        <div class="detail-row">
                            <span>
                                Target
                            </span>

                            <strong>
                                ${escapeHtml(
          d.target
        )}
                            </strong>
                        </div>

                        ${d.timestamp
            ? `
                                <div class="detail-row">
                                    <span>
                                        Timestamp
                                    </span>

                                    <strong>
                                        ${escapeHtml(
              d.timestamp
            )}
                                    </strong>
                                </div>
                                `
            : ""
          }

                        ${d.amount != null
            ? `
                                <div class="detail-row">
                                    <span>
                                        Amount
                                    </span>

                                    <strong>
                                        ₹${Number(
              d.amount
            ).toLocaleString(
              "en-IN"
            )}
                                    </strong>
                                </div>
                                `
            : ""
          }

                        ${d.document
            ? `
                                <div class="detail-row">
                                    <span>
                                        Evidence Document
                                    </span>

                                    <strong>
                                        ${escapeHtml(
              d.document
            )}
                                    </strong>
                                </div>
                                `
            : ""
          }

                        ${d.case_id
            ? `
                                <div class="detail-row">
                                    <span>
                                        Case ID
                                    </span>

                                    <strong>
                                        #${escapeHtml(
              d.case_id
            )}
                                    </strong>
                                </div>
                                `
            : ""
          }

                    </div>
                `;
      }
    );

  } catch (error) {

    console.error(
      "CrimeLens graph error:",
      error
    );

    container.innerHTML = `

            <div class="graph-error">

                <strong>
                    Unable to load investigation graph
                </strong>

                <span>
                    ${escapeHtml(
      error.message
    )}
                </span>

            </div>
        `;
  }
}


function initializeEventHandlers() {
  $("loginForm")?.addEventListener("submit", login);
  $("logoutButton")?.addEventListener("click", logout);
  $("refreshOverviewButton")?.addEventListener("click", refreshAll);
  $("uploadEvidenceButton")?.addEventListener("click", uploadEvidence);
  $("refreshSecurityButton")?.addEventListener("click", loadSecurity);
  $("verifyLedgerButton")?.addEventListener("click", verifyLedger);
  $("newCaseButton")?.addEventListener("click", () => $("newCaseModal")?.classList.remove("hidden"));
  $("dashboardNewCaseBtn")?.addEventListener("click", () => $("newCaseModal")?.classList.remove("hidden"));
  $("closeNewCaseButton")?.addEventListener("click", () => $("newCaseModal")?.classList.add("hidden"));
  $("cancelNewCaseButton")?.addEventListener("click", () => $("newCaseModal")?.classList.add("hidden"));
  $("newCaseForm")?.addEventListener("submit", createCase);

  // Active Case Switcher Modal
  $("headerChangeCaseBtn")?.addEventListener("click", openCaseSwitcherModal);
  $("switchCaseQuickBtn")?.addEventListener("click", openCaseSwitcherModal);
  $("closeCaseSwitcherButton")?.addEventListener("click", closeCaseSwitcherModal);
  $("clearCaseQuickBtn")?.addEventListener("click", clearActiveCase);
  $("clearCaseSelectionModalBtn")?.addEventListener("click", () => {
    clearActiveCase();
    closeCaseSwitcherModal();
  });
  $("createNewCaseFromSwitcherBtn")?.addEventListener("click", () => {
    closeCaseSwitcherModal();
    $("newCaseModal")?.classList.remove("hidden");
  });

  // Overview Dossier action buttons
  $("dossierExploreGraphBtn")?.addEventListener("click", () => showSection("graphSection"));
  $("dossierAskAssistantBtn")?.addEventListener("click", () => showSection("assistantSection"));

  // Entity Dossier Modal
  $("closeEntityDossierButton")?.addEventListener("click", () => $("entityDossierModal")?.classList.add("hidden"));

  // Case Management Filters
  $("caseSearchInput")?.addEventListener("input", renderCasesGrid);
  document.querySelectorAll("#caseStatusFilters .pill").forEach(pill => {
    pill.addEventListener("click", () => {
      document.querySelectorAll("#caseStatusFilters .pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      renderCasesGrid();
    });
  });

  // Entity Master Filters & Sortable Headers
  $("entitiesSearchInput")?.addEventListener("input", renderEntitiesTable);
  document.querySelectorAll(".entity-filter-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      currentEntityTableFilter = chip.dataset.type || "ALL";
      document.querySelectorAll(".entity-filter-chip").forEach(c => c.classList.remove("active"));
      chip.classList.add("active");
      renderEntitiesTable();
    });
  });
  document.querySelectorAll("#entitiesTable th.sortable-th").forEach(th => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (entitySortKey === key) {
        entitySortDir = entitySortDir === "asc" ? "desc" : "asc";
      } else {
        entitySortKey = key;
        entitySortDir = (key === "risk" || key === "relationships") ? "desc" : "asc";
      }
      updateEntitySortIcons();
      renderEntitiesTable();
    });
  });

  // Evidence Locker Controls
  $("evidenceSearchInput")?.addEventListener("input", renderDocumentsTable);
  $("evidenceTypeFilter")?.addEventListener("change", renderDocumentsTable);
  $("evidenceRefreshBtn")?.addEventListener("click", loadDocuments);
  $("triggerUploadEvidenceBtn")?.addEventListener("click", () => {
    $("evidenceUploadPanel")?.classList.toggle("hidden");
  });
  $("closeUploadPanelBtn")?.addEventListener("click", () => {
    $("evidenceUploadPanel")?.classList.add("hidden");
  });
  $("closeEvidenceViewModalBtn")?.addEventListener("click", () => {
    $("evidenceViewModal")?.classList.add("hidden");
  });
  $("closeDeleteEvidenceModalBtn")?.addEventListener("click", closeDeleteEvidenceModal);
  $("cancelDeleteEvidenceBtn")?.addEventListener("click", closeDeleteEvidenceModal);
  $("confirmDeleteEvidenceBtn")?.addEventListener("click", deleteEvidence);

  // Relationships Filter
  $("relationshipSearchInput")?.addEventListener("input", renderRelationshipsTable);

  // Risk Recompute Button, Filters & Sort
  $("refreshRiskButton")?.addEventListener("click", loadRiskSection);
  document.querySelectorAll("#riskLevelFilters .pill").forEach(pill => {
    pill.addEventListener("click", () => {
      currentRiskFilter = pill.dataset.risk || "ALL";
      document.querySelectorAll("#riskLevelFilters .pill").forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      renderRiskEntities();
    });
  });
  $("riskSortSelect")?.addEventListener("change", (e) => {
    currentRiskSort = e.target.value;
    renderRiskEntities();
  });

  // Graph Left Control Bar & Actions
  $("graphChangeCaseBtn")?.addEventListener("click", openCaseSwitcherModal);
  $("refreshGraphButton")?.addEventListener("click", loadGraph);
  $("graphRelTypeFilter")?.addEventListener("change", filterGraph);
  $("graphRiskFilter")?.addEventListener("change", filterGraph);
  $("toggleNodeLabels")?.addEventListener("change", (e) => toggleGraphNodeLabels(e.target.checked));
  $("toggleEdgeLabels")?.addEventListener("change", (e) => toggleGraphEdgeLabels(e.target.checked));
  $("entitySearch")?.addEventListener("input", () => {
    filterEntityList();
    filterGraph();
  });
  $("graphSearch")?.addEventListener("input", filterGraph);
  $("zoomInGraphButton")?.addEventListener("click", () => {
    if (cy) cy.zoom({ level: cy.zoom() * 1.25, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  });
  $("zoomOutGraphButton")?.addEventListener("click", () => {
    if (cy) cy.zoom({ level: cy.zoom() * 0.8, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  });
  $("fitGraphButton")?.addEventListener("click", fitGraph);
  $("resetGraphButton")?.addEventListener("click", () => {
    if (cy) {
      if ($("graphRelTypeFilter")) $("graphRelTypeFilter").value = "ALL";
      if ($("graphRiskFilter")) $("graphRiskFilter").value = "ALL";
      if ($("entitySearch")) $("entitySearch").value = "";
      if ($("graphSearch")) $("graphSearch").value = "";
      currentEntityType = "ALL";
      document.querySelectorAll(".entity-filter").forEach(b => b.classList.toggle("active", b.dataset.type === "ALL"));
      cy.elements().show();
      cy.fit(cy.nodes(), 60);
      const layout = cy.layout({
        name: "cose",
        animate: true,
        animationDuration: 500,
        fit: true,
        padding: 50,
        nodeRepulsion: () => 750000,
        idealEdgeLength: (e) => e.data("relation") === "PART_OF_CASE" ? 140 : 85
      });
      layout.run();
    }
  });

  // Ledger Toolbar & Modal
  $("ledgerSearchInput")?.addEventListener("input", renderLedgerBlocks);
  $("ledgerActionFilter")?.addEventListener("change", renderLedgerBlocks);
  $("refreshLedgerBtn")?.addEventListener("click", loadLedger);
  $("closeLedgerPayloadModalBtn")?.addEventListener("click", () => {
    $("ledgerPayloadModal")?.classList.add("hidden");
  });

  // Case Deletion Handlers
  $("closeDeleteCaseButton")?.addEventListener("click", closeDeleteCaseModal);
  $("cancelDeleteCaseButton")?.addEventListener("click", closeDeleteCaseModal);
  $("confirmDeleteCaseButton")?.addEventListener("click", deleteCase);

  // Assistant Query Handlers
  $("askButton")?.addEventListener("click", () => ask());
  $("question")?.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); ask(); } });

  // Navigation Links
  document.querySelectorAll(".nav[data-section],.sidebar-link[data-section]").forEach(btn => btn.addEventListener("click", () => showSection(btn.dataset.section)));
  document.querySelectorAll(".suggestions [data-question]").forEach(btn => btn.addEventListener("click", () => ask(btn.dataset.question)));

  // Graph Entity Filters
  document.querySelectorAll(".entity-filter").forEach(btn => btn.addEventListener("click", () => {
    currentEntityType = btn.dataset.type || "ALL";
    document.querySelectorAll(".entity-filter").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    filterEntityList();
    filterGraph();
  }));

  // Sidebar Dropdown Toggle
  document.querySelectorAll(".dropdown-toggle").forEach(btn => btn.addEventListener("click", () => {
    const target = $(btn.dataset.target);
    if (!target) return;
    target.classList.toggle("open");
    const chev = btn.querySelector(".chevron");
    if (chev) chev.textContent = target.classList.contains("open") ? "⌃" : "⌄";
  }));

  // Browser History Navigation (Back / Forward)
  window.addEventListener("popstate", (e) => {
    const s = e.state?.section || document.body.dataset.initialSection || "overview";
    showSection(s, false);
  });
}

function updateClock() {
  const el = $("clock");
  if (!el) return;
  el.textContent = new Date().toLocaleString("en-IN", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

document.addEventListener("DOMContentLoaded", () => {
  initializeEventHandlers();
  updateClock();
  setInterval(updateClock, 1000);

  const initial = document.body.dataset.initialSection || "overview";
  showSection(initial, false);

  checkSession();
});

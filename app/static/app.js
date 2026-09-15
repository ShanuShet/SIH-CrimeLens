/* CrimeLens secure frontend */
"use strict";

let cy = null;
let csrfToken = "";
let currentUser = null;
let graphData = {nodes: [], edges: []};
let currentEntityType = "ALL";

const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&","&amp;").replaceAll("<","&lt;")
    .replaceAll(">","&gt;").replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

async function apiFetch(url, options = {}) {
  const config = {...options, credentials:"same-origin"};
  const method = String(config.method || "GET").toUpperCase();
  const headers = new Headers(config.headers || {});
  if (!["GET","HEAD","OPTIONS"].includes(method) && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  config.headers = headers;
  const response = await fetch(url, config);
  if (response.status === 401 && !url.includes("/api/login")) {
    showLogin();
  }
  return response;
}

function showLogin() {
  $("loginOverlay")?.classList.remove("hidden");
  $("appShell")?.classList.add("hidden");
}

function showApp() {
  $("loginOverlay")?.classList.add("hidden");
  $("appShell")?.classList.remove("hidden");
}

async function checkSession() {
  try {
    const response = await fetch("/api/session", {credentials:"same-origin"});
    if (!response.ok) {
      showLogin();
      return;
    }
    const data = await response.json();
    csrfToken = data.csrf_token || "";
    currentUser = data.user || {username:data.username, role:data.role};
    setUser(currentUser);
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
      method:"POST",
      credentials:"same-origin",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        username:$("loginUsername")?.value.trim() || "",
        password:$("loginPassword")?.value || ""
      })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (errorBox) errorBox.textContent = data.detail || "Unable to sign in.";
      return;
    }
    csrfToken = data.csrf_token || "";
    currentUser = data.user;
    setUser(currentUser);
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
    await apiFetch("/api/logout", {method:"POST"});
  } catch (error) {
    console.error(error);
  }
  csrfToken = "";
  currentUser = null;
  showLogin();
}

function showSection(id) {
  document.querySelectorAll(".section").forEach(s => s.classList.add("hidden"));
  const section = $(id);
  if (section) section.classList.remove("hidden");

  document.querySelectorAll(".main-nav .nav").forEach(n => {
    n.classList.toggle("active", n.dataset.section === id);
  });

  if (id === "overview") refreshAll();
  if (id === "evidence") loadDocuments();
  if (id === "graph") setTimeout(loadGraph, 80);
  if (id === "security") loadSecurity();
  if (id === "ledger") loadLedger();
}

async function refreshAll() {
  await Promise.allSettled([loadStats(), loadCases(), loadDocuments(), loadSecuritySummary()]);
}

async function loadStats() {
  try {
    const response = await apiFetch("/api/stats");
    if (!response.ok) return;
    const s = await response.json();
    if ($("totalCases")) $("totalCases").textContent = s.total_cases ?? 0;
    if ($("evidenceDocuments")) $("evidenceDocuments").textContent = s.evidence_documents ?? s.evidenceDocuments ?? 0;
    if ($("entityTotal")) $("entityTotal").textContent = s.entity_total ?? s.entities ?? 0;
    if ($("activeLeads")) $("activeLeads").textContent = s.active_leads ?? 0;
    if ($("highRisk")) $("highRisk").textContent = s.high_risk_entities ?? 0;
    if ($("failedLogins")) $("failedLogins").textContent = s.failed_logins ?? 0;
    if ($("roleValue")) $("roleValue").textContent = s.role ?? currentUser?.role ?? "—";
  } catch (error) {
    console.error("Stats error:", error);
  }
}

async function loadCases() {
  try {
    const response = await apiFetch("/api/cases");
    if (!response.ok) return;
    const cases = await response.json();

    const main = $("cases");
    if (main) {
      main.innerHTML = cases.length ? cases.map(c => {
        const status = String(c.status || "Pending").toLowerCase();
        return `<div class="case">
          <div><b>${escapeHtml(c.title)}</b><small>${escapeHtml(c.description || "No description")}</small></div>
          <span class="badge ${escapeHtml(status)}">${escapeHtml(status.toUpperCase())}</span>
        </div>`;
      }).join("") : `<div class="muted">No cases available.</div>`;
    }

    const sidebar = $("sidebarCases");
    if (sidebar) {
      sidebar.innerHTML = cases.length ? cases.map(c => `
        <button class="case-side" data-case-id="${escapeHtml(c.id)}">
          <span class="case-dot"></span>${escapeHtml(c.title)}
        </button>
      `).join("") : `<div class="muted">No cases</div>`;
      sidebar.querySelectorAll(".case-side").forEach(button => {
        button.addEventListener("click", () => {
          sidebar.querySelectorAll(".case-side").forEach(b => b.classList.remove("active"));
          button.classList.add("active");
        });
      });
    }
  } catch (error) {
    console.error("Cases error:", error);
  }
}

async function loadDocuments() {
  const list = $("documentList");
  if (!list) return;
  try {
    const response = await apiFetch("/api/documents");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const docs = await response.json();
    if (!docs.length) {
      list.innerHTML = `<div class="muted">No evidence documents have been ingested.</div>`;
      return;
    }
    list.innerHTML = docs.map(doc => `
      <div class="document-item">
        <b title="${escapeHtml(doc.filename)}">${escapeHtml(doc.filename)}</b>
        <span>${escapeHtml(doc.doc_type || "OTHER")} · ${escapeHtml(doc.data_category || "")}</span>
        <small>${escapeHtml(doc.integrity_status || "NOT_CHECKED")}</small>
        <button class="secondary verify-button" data-verify-id="${escapeHtml(doc.id)}">VERIFY</button>
      </div>
    `).join("");
    list.querySelectorAll("[data-verify-id]").forEach(btn => {
      btn.addEventListener("click", () => verifyEvidence(btn.dataset.verifyId, btn));
    });
  } catch (error) {
    list.innerHTML = `<div class="muted">Unable to load evidence.</div>`;
    console.error(error);
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
  for (const file of input.files) form.append("files", file);

  try {
    if (result) result.textContent = "Ingesting evidence…";
    const response = await apiFetch("/api/upload", {method:"POST", body:form});
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
    const response = await apiFetch(`/api/evidence/${encodeURIComponent(id)}/verify`);
    const data = await response.json().catch(() => ({}));
    if ($("uploadResult")) $("uploadResult").textContent = JSON.stringify(data, null, 2);
    await loadDocuments();
    await loadStats();
  } catch (error) {
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

async function loadSecurity() {
  await loadSecuritySummary();
  try {
    const [eventsResponse, auditResponse] = await Promise.all([
      apiFetch("/api/security/events"),
      apiFetch("/api/security/audit")
    ]);
    const events = eventsResponse.ok ? await eventsResponse.json() : [];
    const audit = auditResponse.ok ? await auditResponse.json() : [];
    renderTable($("securityEvents"), events, ["created_at","event_type","severity","username","detail","ip"]);
    renderTable($("auditEvents"), audit, ["created_at","action","username","role","resource","detail","ip"]);
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
  const labels = {created_at:"TIME",event_type:"EVENT",severity:"SEVERITY",username:"USER",action:"ACTION",role:"ROLE",resource:"RESOURCE",detail:"DETAIL",ip:"IP"};
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
    const blocks = await response.json();
    if ($("ledgerCount")) $("ledgerCount").textContent = `${blocks.length} BLOCKS`;
    list.innerHTML = blocks.length ? blocks.map(block => `
      <div class="ledger-block">
        <div class="ledger-head"><b>BLOCK #${escapeHtml(block.index ?? block.block_index)}</b><span>${escapeHtml(block.event_type || "")}</span></div>
        <div class="ledger-hash">Previous: ${escapeHtml(block.previous_hash || "")}</div>
        <div class="ledger-hash">Hash: ${escapeHtml(block.block_hash || "")}</div>
        <div class="ledger-hash">Created: ${escapeHtml(block.created_at || "")}</div>
      </div>
    `).join("") : `<div class="muted">Ledger is empty.</div>`;
  } catch (error) {
    list.innerHTML = `<div class="muted">Unable to load ledger.</div>`;
  }
}

async function verifyLedger() {
  const box = $("ledgerVerifyResult");
  if (box) { box.className = "verify-result"; box.textContent = "Verifying ledger…"; }
  try {
    const response = await apiFetch("/api/security/verify", {method:"POST"});
    const data = await response.json().catch(() => ({}));
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
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        title:$("newCaseName")?.value.trim(),
        reference_id:$("newCaseId")?.value.trim(),
        risk:$("newCaseRisk")?.value,
        status:$("newCaseStatus")?.value,
        description:$("newCaseDescription")?.value.trim()
      })
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Unable to create case.");
    $("newCaseModal")?.classList.add("hidden");
    $("newCaseForm")?.reset();
    await loadCases();
    await loadStats();
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
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({question:text})
    });
    const data = await response.json().catch(() => ({}));
    const answer = data.answer || data.response || data.message || data.error || "No response available.";
    if (chat) {
      chat.insertAdjacentHTML("beforeend", `<div class="bot"><b>CrimeLens:</b><div class="assistant-answer">${escapeHtml(answer)}</div></div>`);
      chat.scrollTop = chat.scrollHeight;
    }
  } catch (error) {
    if (chat) chat.insertAdjacentHTML("beforeend", `<div class="bot"><b>CrimeLens:</b><div>Unable to process the request.</div></div>`);
  }
}

function entityIcon(type) {
  return {Person:"👤",PhoneNumber:"📞",BankAccount:"🏦",Vehicle:"🚗",Location:"📍",Incident:"🚨",Case:"📁"}[type] || "●";
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
     * SHOW INFORMATION
     * -------------------------------------------------------
     */

    renderEntityInfo(
        entity
    );
}

function renderEntityInfo(entity) {

    const panel =
        document.getElementById(
            "entityInfo"
        );

    if (!panel) {
        console.error(
            "entityInfo panel not found."
        );
        return;
    }

    const key =
        entity.key ||
        entity.id ||
        "N/A";

    const name =
        entity.name ||
        "Unknown Entity";

    const label =
        entity.label ||
        "Entity";

    const risk =
        entity.risk ??
        "Not assessed";

    let connectionCount = 0;

    if (cy) {

        const node =
            cy.getElementById(
                key
            );

        if (
            node &&
            node.length
        ) {

            connectionCount =
                node.connectedEdges()
                    .length;
        }
    }

    panel.innerHTML = `

        <div class="panel-title">

            <b>
                ENTITY INFORMATION
            </b>

            <span>
                SELECTED
            </span>

        </div>

        <div class="entity-profile">

            <div class="entity-profile-icon">
                ${entityIcon(label)}
            </div>

            <div>

                <h3>
                    ${escapeHtml(name)}
                </h3>

                <div class="entity-key">
                    ${escapeHtml(key)}
                </div>

                <div class="muted">
                    ${escapeHtml(label)}
                </div>

            </div>

        </div>

        <div class="entity-metrics">

            <div>
                <span>
                    ENTITY TYPE
                </span>

                <b>
                    ${escapeHtml(label)}
                </b>
            </div>

            <div>
                <span>
                    RISK
                </span>

                <b>
                    ${escapeHtml(
                        String(risk)
                    )}
                </b>
            </div>

            <div>
                <span>
                    CONNECTIONS
                </span>

                <b>
                    ${connectionCount}
                </b>
            </div>

        </div>

        <div class="detail-section">

            <div class="detail-heading">
                IDENTIFICATION
            </div>

            <div class="detail-row">
                <span>Entity Name</span>
                <strong>
                    ${escapeHtml(name)}
                </strong>
            </div>

            <div class="detail-row">
                <span>Entity Type</span>
                <strong>
                    ${escapeHtml(label)}
                </strong>
            </div>

            <div class="detail-row">
                <span>Entity Key</span>
                <strong>
                    ${escapeHtml(key)}
                </strong>
            </div>

            <div class="detail-row">
                <span>Risk Level</span>
                <strong>
                    ${escapeHtml(
                        String(risk)
                    )}
                </strong>
            </div>

        </div>

        <div class="detail-section">

            <div class="detail-heading">
                CONNECTED ENTITIES
            </div>

            <div
                id="entityConnections"
                class="connection-list"
            >
                Loading...
            </div>

        </div>
    `;

    renderEntityConnections(
        entity
    );
}

function renderEntityConnections(entity) {

    const container =
        document.getElementById(
            "entityConnections"
        );

    if (!container) {
        return;
    }

    container.innerHTML = "";

    if (!cy) {

        container.innerHTML = `
            <div class="muted">
                Graph is not loaded.
            </div>
        `;

        return;
    }

    const key =
        entity.key ||
        entity.id;

    const node =
        cy.getElementById(
            key
        );

    if (
        !node ||
        !node.length
    ) {

        container.innerHTML = `
            <div class="muted">
                Entity is not present in the graph.
            </div>
        `;

        return;
    }

    const edges =
        node.connectedEdges();

    if (!edges.length) {

        container.innerHTML = `
            <div class="muted">
                No evidence-backed connections found.
            </div>
        `;

        return;
    }

    edges.forEach(edge => {

        const source =
            edge.source();

        const target =
            edge.target();

        const otherNode =
            source.id() === key
                ? target
                : source;

        const d =
            otherNode.data();

        const relation =
            String(
                edge.data(
                    "relation"
                ) ||
                "ASSOCIATED_WITH"
            );

        const direction =
            source.id() === key
                ? "OUTGOING"
                : "INCOMING";

        const button =
            document.createElement(
                "button"
            );

        button.type =
            "button";

        button.className =
            "connection-row";

        button.innerHTML = `

            <div class="connection-main">

                <b>
                    ${escapeHtml(
                        d.name ||
                        d.id
                    )}
                </b>

                <small>
                    ${escapeHtml(
                        d.label ||
                        "Entity"
                    )}
                    ·
                    ${escapeHtml(
                        relation
                    )}
                </small>

            </div>

            <span
                class="connection-direction"
            >
                ${escapeHtml(
                    direction
                )}
            </span>
        `;

        button.addEventListener(
            "click",
            () => {

                selectEntity(
                    d.key ||
                    d.id
                );
            }
        );

        container.appendChild(
            button
        );
    });
}

function getEntityIcon(label) {

    const type = String(label || "").toLowerCase();

    if (type.includes("person")) {
        return "👤";
    }

    if (type.includes("phone")) {
        return "📞";
    }

    if (type.includes("vehicle")) {
        return "🚗";
    }

    if (
        type.includes("bank") ||
        type.includes("account")
    ) {
        return "🏦";
    }

    if (type.includes("location")) {
        return "📍";
    }

    if (type.includes("incident")) {
        return "🚨";
    }

    if (type.includes("case")) {
        return "📁";
    }

    return "🔎";
}

function escapeHtml(value) {

    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

async function loadEntityDetails(entityKey) {
  const box = $("entityInfo");
  if (!box) return;
  box.innerHTML = `<div class="panel-title"><b>ENTITY INFORMATION</b><span>LOADING</span></div><p class="muted">Loading evidence-backed details…</p>`;
  try {
    const response = await apiFetch(`/api/entity/${encodeURIComponent(entityKey)}`);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
    renderEntityInformation(data);
  } catch (error) {
    box.innerHTML = `<div class="panel-title"><b>ENTITY INFORMATION</b><span>ERROR</span></div><p class="muted">Unable to load entity details.</p><p class="error-text">${escapeHtml(error.message)}</p>`;
  }
}

function renderEntityList(entities) {

    const container =
        document.getElementById(
            "entityList"
        );

    if (!container) {
        console.error(
            "entityList element not found"
        );
        return;
    }

    container.innerHTML = "";

    if (
        !entities ||
        entities.length === 0
    ) {

        container.innerHTML = `
            <div class="empty-state">
                No entities found.
            </div>
        `;

        return;
    }

    entities.forEach(entity => {

        const button =
            document.createElement(
                "button"
            );

        button.type = "button";

        button.className =
            "entity-card";

        const key =
            entity.key ||
            entity.id ||
            "";

        button.dataset.entityKey =
            key;

        button.dataset.name =
            String(
                entity.name || ""
            ).toLowerCase();

        button.dataset.type =
            entity.label || "";

        button.innerHTML = `

            <div class="entity-icon">
                ${entityIcon(
                    entity.label
                )}
            </div>

            <div class="entity-details">

                <b>
                    ${escapeHtml(
                        entity.name ||
                        key
                    )}
                </b>

                <span>
                    ${escapeHtml(
                        entity.label ||
                        "Entity"
                    )}
                </span>

                <small>
                    ${escapeHtml(
                        key
                    )}
                </small>

            </div>

            <span class="entity-arrow">
                ›
            </span>
        `;

        button.addEventListener(
            "click",
            () => {

                selectEntity(
                    key
                );
            }
        );

        container.appendChild(
            button
        );
    });

    if ($("entityCount")) {
        $("entityCount").textContent =
            entities.length;
    }

    filterEntityList();
}

function filterEntityList() {
  const query = ($("entitySearch")?.value || "").trim().toLowerCase();
  document.querySelectorAll(".entity-card").forEach(card => {
    const matches = !query || card.dataset.name.includes(query) || card.dataset.key.includes(query);
    const typeMatch = currentEntityType === "ALL" || card.dataset.type === currentEntityType;
    card.style.display = matches && typeMatch ? "flex" : "none";
  });
}

function renderEntityInformation(entity) {
    const panel = document.getElementById("entityInformation");

    if (!panel) {
        console.error("entityInformation panel not found");
        return;
    }

    const name = entity.name || "Unknown Entity";
    const label = entity.label || "Entity";
    const key = entity.key || entity.id || "N/A";

    const risk = entity.risk || "Not assessed";

    let connectionCount = 0;

    if (cy) {
        const node = cy.getElementById(key);

        if (node && node.length > 0) {
            connectionCount = node.connectedEdges().length;
        }
    }

    panel.innerHTML = `
        <div class="entity-detail-header">

            <div class="entity-detail-icon">
                ${getEntityIcon(label)}
            </div>

            <div>
                <h2>${escapeHtml(name)}</h2>

                <div class="entity-detail-type">
                    ${escapeHtml(label)}
                </div>

                <div class="entity-detail-key">
                    ${escapeHtml(key)}
                </div>
            </div>

        </div>

        <div class="entity-detail-stats">

            <div class="detail-stat">
                <span class="detail-stat-label">ENTITY TYPE</span>
                <strong>${escapeHtml(label)}</strong>
            </div>

            <div class="detail-stat">
                <span class="detail-stat-label">RISK</span>
                <strong>${escapeHtml(risk)}</strong>
            </div>

            <div class="detail-stat">
                <span class="detail-stat-label">CONNECTIONS</span>
                <strong>${connectionCount}</strong>
            </div>

        </div>

        <div class="entity-detail-section">

            <div class="entity-detail-section-title">
                IDENTIFICATION
            </div>

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
                <span>Risk Level</span>
                <strong>${escapeHtml(risk)}</strong>
            </div>

        </div>

        <div class="entity-detail-section">

            <div class="entity-detail-section-title">
                CONNECTED ENTITIES
            </div>

            <div id="entityConnections">
                Loading connections...
            </div>

        </div>
    `;
}

function loadEntityConnections(entity) {
    const container = document.getElementById("entityConnections");

    if (!container) {
        return;
    }

    container.innerHTML = "";

    const key = entity.key || entity.id;

    if (!cy) {
        container.innerHTML = `
            <div class="empty-state">
                Graph is not available.
            </div>
        `;
        return;
    }

    const node = cy.getElementById(key);

    if (!node || node.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                No graph information available.
            </div>
        `;
        return;
    }

    const edges = node.connectedEdges();

    if (edges.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                No connected entities found.
            </div>
        `;
        return;
    }

    const connected = [];

    edges.forEach((edge) => {
        const source = edge.source();
        const target = edge.target();

        let otherNode;

        if (source.id() === key) {
            otherNode = target;
        } else {
            otherNode = source;
        }

        connected.push({
            node: otherNode,
            relation: edge.data("relation") || "ASSOCIATED_WITH",
            direction:
                source.id() === key
                    ? "OUTGOING"
                    : "INCOMING",
            timestamp: edge.data("timestamp"),
            amount: edge.data("amount")
        });
    });

    connected.forEach((item) => {
        const data = item.node.data();

        const row = document.createElement("button");

        row.type = "button";
        row.className = "connection-card";

        row.innerHTML = `
            <div class="connection-icon">
                ${getEntityIcon(data.label)}
            </div>

            <div class="connection-content">

                <div class="connection-name">
                    ${escapeHtml(data.name || data.id)}
                </div>

                <div class="connection-type">
                    ${escapeHtml(data.label || "Entity")}
                </div>

                <div class="connection-relation">
                    ${escapeHtml(item.direction)}
                    ·
                    ${escapeHtml(item.relation)}
                </div>

                ${
                    item.timestamp
                        ? `
                    <div class="connection-meta">
                        Time: ${escapeHtml(item.timestamp)}
                    </div>
                    `
                        : ""
                }

                ${
                    item.amount !== undefined &&
                    item.amount !== null &&
                    item.amount !== ""
                        ? `
                    <div class="connection-meta">
                        Amount: ${escapeHtml(item.amount)}
                    </div>
                    `
                        : ""
                }

            </div>
        `;

        row.addEventListener("click", () => {
            const connectedEntity = {
                id: data.id,
                key: data.key || data.id,
                name: data.name,
                label: data.label,
                risk: data.risk
            };

            selectEntity(connectedEntity);
        });

        container.appendChild(row);
    });
}

function showEntityInformation(node) {

    if (!node || !node.length) {
        return;
    }

    selectEntity(
        String(
            node.data("key") ||
            node.data("id") ||
            ""
        )
    );
}

function filterGraph() {
  if (!cy) return;
  const query = ($("graphSearch")?.value || "").trim().toLowerCase();
  cy.nodes().forEach(node => {
    const d = node.data();
    const match = !query || String(d.name||"").toLowerCase().includes(query) || String(d.id||"").toLowerCase().includes(query) || String(d.label||"").toLowerCase().includes(query);
    if (match) node.show(); else node.hide();
  });
  cy.edges().forEach(edge => {
    if (edge.source().visible() && edge.target().visible()) edge.show();
    else edge.hide();
  });
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
                "/api/graph"
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

                    return {

                        group:
                            "nodes",

                        data: {

                            ...d,

                            id,

                            key:
                                String(
                                    d.key ||
                                    id
                                ),

                            name:
                                String(
                                    d.name ||
                                    d.label ||
                                    id
                                ),

                            label:
                                String(
                                    d.label ||
                                    d.type ||
                                    "Entity"
                                ),

                            risk:
                                Number(
                                    d.risk || 0
                                )
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

                            displayRelation +=
                                `  ₹${Number(
                                    d.amount
                                ).toLocaleString(
                                    "en-IN"
                                )}`;
                        }

                        return {

                            group:
                                "edges",

                            data: {

                                ...d,

                                id:
                                    String(
                                        d.id ||
                                        `edge-${index}`
                                    ),

                                source:
                                    String(
                                        d.source
                                    ),

                                target:
                                    String(
                                        d.target
                                    ),

                                relation,

                                displayRelation
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
                                "data(name)",

                            "background-color":
                                "#334155",

                            color:
                                "#ffffff",

                            "text-valign":
                                "bottom",

                            "text-halign":
                                "center",

                            "text-margin-y":
                                10,

                            "font-size":
                                11,

                            "font-weight":
                                700,

                            width:
                                64,

                            height:
                                64,

                            "border-width":
                                2,

                            "border-color":
                                "#94a3b8",

                            "text-outline-width":
                                3,

                            "text-outline-color":
                                "#172033"
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
                                "diamond"
                        }
                    },

                    {
                        selector:
                            'node[label="BankAccount"]',

                        style: {

                            "background-color":
                                "#c28119",

                            "border-color":
                                "#fbbf24",

                            shape:
                                "rectangle"
                        }
                    },

                    {
                        selector:
                            'node[label="Vehicle"]',

                        style: {

                            "background-color":
                                "#287fa9",

                            "border-color":
                                "#38bdf8",

                            shape:
                                "roundrectangle"
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
                                "ellipse"
                        }
                    },

                    {
                        selector:
                            'node[label="Case"]',

                        style: {

                            "background-color":
                                "#0f766e",

                            "border-color":
                                "#5eead4",

                            shape:
                                "roundrectangle",

                            width:
                                110,

                            height:
                                72,

                            "font-size":
                                13,

                            "font-weight":
                                800,

                            "border-width":
                                4
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

                /*
                 * ------------------------------------------------
                 * CASE-CENTERED LAYOUT
                 * ------------------------------------------------
                 */

                layout: {

                    name:
                        "concentric",

                    concentric:
                        function(node) {

                            if (
                                caseNode &&
                                node.id() ===
                                    caseNode.data.id
                            ) {

                                return 1000;
                            }

                            return 100;
                        },

                    levelWidth:
                        function() {
                            return 1;
                        },

                    minNodeSpacing:
                        80,

                    avoidOverlap:
                        true,

                    padding:
                        80,

                    animate:
                        true,

                    animationDuration:
                        600
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

                        ${
                            d.timestamp
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

                        ${
                            d.amount != null
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
  $("closeNewCaseButton")?.addEventListener("click", () => $("newCaseModal")?.classList.add("hidden"));
  $("cancelNewCaseButton")?.addEventListener("click", () => $("newCaseModal")?.classList.add("hidden"));
  $("newCaseForm")?.addEventListener("submit", createCase);
  $("entitySearch")?.addEventListener("input", filterEntityList);
  $("graphSearch")?.addEventListener("input", filterGraph);
  $("fitGraphButton")?.addEventListener("click", fitGraph);
  $("resetGraphButton")?.addEventListener("click", loadGraph);
  $("askButton")?.addEventListener("click", () => ask());
  $("question")?.addEventListener("keydown", e => { if(e.key==="Enter"){e.preventDefault();ask();} });
  document.querySelectorAll(".nav[data-section],.sidebar-link[data-section]").forEach(btn => btn.addEventListener("click", () => showSection(btn.dataset.section)));
  document.querySelectorAll(".suggestions [data-question]").forEach(btn => btn.addEventListener("click", () => ask(btn.dataset.question)));
  document.querySelectorAll(".entity-filter").forEach(btn => btn.addEventListener("click", () => {
    currentEntityType = btn.dataset.type || "ALL";
    document.querySelectorAll(".entity-filter").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    filterEntityList();
  }));
  document.querySelectorAll(".dropdown-toggle").forEach(btn => btn.addEventListener("click", () => {
    const target = $(btn.dataset.target);
    if (!target) return;
    target.classList.toggle("open");
    const chev = btn.querySelector(".chevron");
    if (chev) chev.textContent = target.classList.contains("open") ? "⌃" : "⌄";
  }));
}

function updateClock() {
  const el = $("clock");
  if (!el) return;
  el.textContent = new Date().toLocaleString("en-IN",{day:"2-digit",month:"short",year:"numeric",hour:"2-digit",minute:"2-digit",second:"2-digit"});
}

document.addEventListener("DOMContentLoaded", () => {
  initializeEventHandlers();
  updateClock();
  setInterval(updateClock,1000);
  checkSession();
});

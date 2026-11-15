/* KosherGuard Admin - interface logic.
   Vanilla JavaScript; all data comes from the JSON API. Every value
   rendered from server data passes through escapeHtml first. */

"use strict";

// ---------- helpers ----------

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

async function api(method, path, body) {
  const options = {
    method: method,
    headers: { "Content-Type": "application/json", "X-KosherGuard-Request": "1" },
    credentials: "same-origin",
  };
  if (method !== "GET") options.body = JSON.stringify(body || {});
  const response = await fetch(path, options);
  let data = {};
  try { data = await response.json(); } catch (e) { /* non-JSON error body */ }
  if (response.status === 401 && path !== "/api/login") {
    showLogin();
    throw new Error((data && data.error) || "not signed in");
  }
  if (!response.ok) throw new Error((data && data.error) || ("Request failed (" + response.status + ")"));
  return data;
}

function el(id) { return document.getElementById(id); }

function showLogin() {
  el("app-shell").classList.add("hidden");
  el("login-view").classList.remove("hidden");
}

function showShell() {
  el("login-view").classList.add("hidden");
  el("app-shell").classList.remove("hidden");
}

function setTitle(text) { el("page-title").textContent = text; }

function statusBadge(enabled) {
  return enabled
    ? '<span class="badge badge-ok">Enabled</span>'
    : '<span class="badge badge-muted">Disabled</span>';
}

function ruleBadge(rule) {
  if (rule === "allow") return '<span class="badge badge-ok">Allow</span>';
  if (rule === "block") return '<span class="badge badge-danger">Block</span>';
  return '<span class="muted">-</span>';
}

function tags(list) {
  if (!list || !list.length) return '<span class="muted">none</span>';
  return list.map(function (x) { return '<span class="tag">' + escapeHtml(x) + "</span>"; }).join("");
}

// ---------- modal ----------

function openModal(html) {
  const modal = el("modal");
  modal.innerHTML = html;
  el("modal-backdrop").classList.remove("hidden");
  const first = modal.querySelector("input, select, textarea, button");
  if (first) first.focus();
  return modal;
}

function closeModal() {
  el("modal-backdrop").classList.add("hidden");
  el("modal").innerHTML = "";
}

function confirmDialog(title, message, confirmLabel, onConfirm) {
  const modal = openModal(
    "<h2>" + escapeHtml(title) + "</h2>" +
    "<p>" + escapeHtml(message) + "</p>" +
    '<div class="modal-actions">' +
    '<button class="btn" id="modal-cancel">Cancel</button>' +
    '<button class="btn btn-danger" id="modal-confirm">' + escapeHtml(confirmLabel) + "</button>" +
    "</div>"
  );
  modal.querySelector("#modal-cancel").addEventListener("click", closeModal);
  modal.querySelector("#modal-confirm").addEventListener("click", function () {
    onConfirm().then(closeModal).catch(showModalError);
  });
}

function showModalError(err) {
  let node = el("modal").querySelector(".form-error");
  if (!node) {
    node = document.createElement("p");
    node.className = "form-error";
    el("modal").appendChild(node);
  }
  node.textContent = err.message;
}

// ---------- overview ----------

async function renderOverview() {
  const counts = await api("GET", "/api/overview");
  const card = function (title, stat, sub) {
    return '<div class="card"><h3>' + escapeHtml(title) + '</h3>' +
      '<div class="stat">' + escapeHtml(stat) + '</div>' +
      '<div class="stat-sub">' + escapeHtml(sub) + "</div></div>";
  };
  el("content").innerHTML =
    '<div class="banner banner-info">Development environment. All figures are live counts from the local ' +
    "dashboard database. No devices are enrolled and no Apple MDM connection exists.</div>" +
    '<div class="card-grid">' +
    card("Policies", counts.policies, counts.enabled_policies + " enabled") +
    card("Categories", counts.categories, counts.enabled_categories + " enabled") +
    card("Domain records", counts.domains, "in the local database") +
    card("Devices", counts.devices, "none enrolled - MDM not available") +
    card("Audit events", counts.audit_events, "recorded administrative actions") +
    "</div>" +
    '<div class="card"><h3>What this dashboard is</h3>' +
    "<p>KosherGuard Admin manages filtering policies, categories, and domain records for the " +
    "KosherGuard filtering engine. It does not manage iPhones: device enrollment, push " +
    "notifications, and remote management require Apple MDM authorization that does not exist yet " +
    '(see the Devices section and <span class="mono">docs/MDM_ENROLLMENT_AND_PUSH.md</span>).</p></div>';
}

// ---------- policies ----------

function policyFormHtml(policy) {
  const p = policy || { name: "", description: "", default_policy: "allow", enabled: true,
    allowlist: [], blocklist: [], category_allow: [], category_block: [] };
  const lines = function (list) { return (list || []).join("\n"); };
  return (
    "<h2>" + (policy ? "Edit policy" : "New policy") + "</h2>" +
    '<div class="form-row"><label for="pf-name">Name</label>' +
    '<input type="text" id="pf-name" value="' + escapeHtml(p.name) + '"></div>' +
    '<div class="form-row"><label for="pf-desc">Description</label>' +
    '<input type="text" id="pf-desc" value="' + escapeHtml(p.description) + '"></div>' +
    '<div class="two-col">' +
    '<div class="form-row"><label for="pf-default">Default behavior</label>' +
    '<select id="pf-default">' +
    '<option value="allow"' + (p.default_policy === "allow" ? " selected" : "") + ">Allow (block only listed)</option>" +
    '<option value="block"' + (p.default_policy === "block" ? " selected" : "") + ">Block (allow only listed)</option>" +
    "</select></div>" +
    '<div class="form-row"><label for="pf-enabled">State</label>' +
    '<select id="pf-enabled">' +
    '<option value="true"' + (p.enabled ? " selected" : "") + ">Enabled</option>" +
    '<option value="false"' + (!p.enabled ? " selected" : "") + ">Disabled</option>" +
    "</select></div></div>" +
    '<div class="two-col">' +
    '<div class="form-row"><label for="pf-allow">Allowed domains (one per line)</label>' +
    '<textarea id="pf-allow" rows="4">' + escapeHtml(lines(p.allowlist)) + "</textarea></div>" +
    '<div class="form-row"><label for="pf-block">Blocked domains (one per line)</label>' +
    '<textarea id="pf-block" rows="4">' + escapeHtml(lines(p.blocklist)) + "</textarea></div></div>" +
    '<div class="two-col">' +
    '<div class="form-row"><label for="pf-callow">Allowed categories (one per line)</label>' +
    '<textarea id="pf-callow" rows="3">' + escapeHtml(lines(p.category_allow)) + "</textarea></div>" +
    '<div class="form-row"><label for="pf-cblock">Blocked categories (one per line)</label>' +
    '<textarea id="pf-cblock" rows="3">' + escapeHtml(lines(p.category_block)) + "</textarea></div></div>" +
    '<p class="muted small">Precedence: explicit allow, then explicit block, then blocked category, ' +
    "then allowed category, then default. A listed domain covers its subdomains.</p>" +
    '<div class="modal-actions">' +
    '<button class="btn" id="modal-cancel">Cancel</button>' +
    '<button class="btn btn-primary" id="pf-save">Save policy</button></div>'
  );
}

function readPolicyForm() {
  const lines = function (id) {
    return el(id).value.split("\n").map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length > 0; });
  };
  return {
    name: el("pf-name").value.trim(),
    description: el("pf-desc").value.trim(),
    default_policy: el("pf-default").value,
    enabled: el("pf-enabled").value === "true",
    allowlist: lines("pf-allow"),
    blocklist: lines("pf-block"),
    category_allow: lines("pf-callow"),
    category_block: lines("pf-cblock"),
  };
}

function openPolicyDialog(policy, onSaved) {
  const modal = openModal(policyFormHtml(policy));
  modal.querySelector("#modal-cancel").addEventListener("click", closeModal);
  modal.querySelector("#pf-save").addEventListener("click", function () {
    const payload = readPolicyForm();
    const request = policy
      ? api("PUT", "/api/policies/" + policy.id, payload)
      : api("POST", "/api/policies", payload);
    request.then(function () { closeModal(); onSaved(); }).catch(showModalError);
  });
}

function openPolicyDetail(policy, onChanged) {
  const modal = openModal(
    "<h2>" + escapeHtml(policy.name) + "</h2>" +
    '<dl class="kv">' +
    "<dt>Description</dt><dd>" + (escapeHtml(policy.description) || '<span class="muted">none</span>') + "</dd>" +
    "<dt>Status</dt><dd>" + statusBadge(policy.enabled) + "</dd>" +
    "<dt>Default</dt><dd>" + ruleBadge(policy.default_policy) + "</dd>" +
    "<dt>Allowed domains</dt><dd>" + tags(policy.allowlist) + "</dd>" +
    "<dt>Blocked domains</dt><dd>" + tags(policy.blocklist) + "</dd>" +
    "<dt>Allowed categories</dt><dd>" + tags(policy.category_allow) + "</dd>" +
    "<dt>Blocked categories</dt><dd>" + tags(policy.category_block) + "</dd>" +
    "</dl>" +
    '<h3 style="margin-top:1rem">Test a domain</h3>' +
    '<div class="toolbar"><input type="text" id="pt-domain" placeholder="example.com" style="max-width:280px">' +
    '<button class="btn btn-primary" id="pt-run">Evaluate</button></div>' +
    '<div id="pt-result"></div>' +
    '<h3 style="margin-top:1rem">Version history</h3>' +
    '<div id="pv-list"><span class="muted">Loading...</span></div>' +
    '<div class="modal-actions">' +
    (policy.enabled
      ? '<button class="btn" id="pv-select">Select for publication</button>'
      : '') +
    '<button class="btn" id="modal-cancel">Close</button></div>'
  );
  modal.querySelector("#modal-cancel").addEventListener("click", closeModal);
  const selectBtn = modal.querySelector("#pv-select");
  if (selectBtn) {
    selectBtn.addEventListener("click", function () {
      api("POST", "/api/policies/" + policy.id + "/select", {})
        .then(function () { closeModal(); onChanged(); })
        .catch(showModalError);
    });
  }
  api("GET", "/api/policies/" + policy.id + "/versions").then(function (data) {
    el("pv-list").innerHTML = '<div class="table-wrap"><table><thead><tr>' +
      '<th>Version</th><th>When (UTC)</th><th>By</th><th>Note</th><th></th>' +
      '</tr></thead><tbody>' +
      data.versions.map(function (v) {
        return '<tr><td class="mono">v' + escapeHtml(v.version) + '</td>' +
          '<td class="mono">' + escapeHtml(v.created_at) + '</td>' +
          '<td>' + escapeHtml(v.admin) + '</td>' +
          '<td class="muted small">' + escapeHtml(v.note || '') + '</td>' +
          '<td class="row-actions">' +
          (v.version === policy.current_version
            ? '<span class="muted small">current</span>'
            : '<button class="btn btn-sm" data-rollback="' + v.version + '">Roll back</button>') +
          '</td></tr>';
      }).join('') + '</tbody></table></div>';
    el("pv-list").querySelectorAll("button[data-rollback]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        api("POST", "/api/policies/" + policy.id + "/rollback",
            { version: Number(btn.getAttribute("data-rollback")) })
          .then(function () { closeModal(); onChanged(); })
          .catch(showModalError);
      });
    });
  }).catch(showModalError);
  modal.querySelector("#pt-run").addEventListener("click", function () {
    const domain = el("pt-domain").value.trim();
    api("POST", "/api/policies/" + policy.id + "/test", { domain: domain }).then(function (result) {
      const cls = result.action === "allow" ? "decision-allow" : "decision-block";
      el("pt-result").innerHTML =
        '<div class="card"><h3>Decision</h3>' +
        '<p><span class="' + cls + '">' + escapeHtml(result.action.toUpperCase()) + "</span> " +
        '<span class="mono">' + escapeHtml(result.domain) + "</span></p>" +
        '<dl class="kv">' +
        "<dt>Rule</dt><dd>" + escapeHtml(result.rule) + "</dd>" +
        "<dt>Reason</dt><dd>" + escapeHtml(result.reason) + "</dd>" +
        (result.category ? "<dt>Category</dt><dd>" + escapeHtml(result.category) + "</dd>" : "") +
        "</dl>" +
        '<p class="muted small">Evaluated by the filtering engine against policy "' +
        escapeHtml(result.policy_name) + '". This is a simulation; no device receives this policy.</p></div>';
    }).catch(showModalError);
  });
}

async function renderPolicies(params) {
  const search = (params && params.search) || "";
  const enabled = (params && params.enabled) || "";
  let url = "/api/policies?";
  if (search) url += "search=" + encodeURIComponent(search) + "&";
  if (enabled) url += "enabled=" + encodeURIComponent(enabled);
  const data = await api("GET", url);

  el("content").innerHTML =
    '<div class="toolbar">' +
    '<input type="search" id="policy-search" placeholder="Search policies" style="max-width:240px" value="' + escapeHtml(search) + '">' +
    '<select id="policy-enabled-filter" style="max-width:150px">' +
    '<option value="">All states</option>' +
    '<option value="true"' + (enabled === "true" ? " selected" : "") + ">Enabled</option>" +
    '<option value="false"' + (enabled === "false" ? " selected" : "") + ">Disabled</option></select>" +
    '<div class="spacer"></div>' +
    '<button class="btn btn-primary" id="policy-new">New policy</button></div>' +
    '<div class="table-wrap"><table><thead><tr>' +
    "<th>Name</th><th>Default</th><th>Rules</th><th>Status</th><th>Publication</th><th></th>" +
    "</tr></thead><tbody id=" + '"policy-rows"' + "></tbody></table>" +
    '<div class="empty-state' + (data.policies.length ? " hidden" : "") + '">No policies yet. Create one to get started.</div></div>';

  const rows = data.policies.map(function (p) {
    return "<tr>" +
      "<td><strong>" + escapeHtml(p.name) + "</strong>" +
      (p.description ? '<br><span class="muted small">' + escapeHtml(p.description) + "</span>" : "") + "</td>" +
      "<td>" + ruleBadge(p.default_policy) + "</td>" +
      '<td class="mono">' + escapeHtml(p.rule_count) + "</td>" +
      '<td><button class="toggle' + (p.enabled ? " on" : "") + '" data-action="toggle" data-id="' + p.id +
      '" data-enabled="' + p.enabled + '" aria-label="Toggle policy"></button></td>' +
      '<td>' + (p.selected_for_publication
        ? '<span class="badge badge-info">Selected for publication</span>'
        : '<span class="muted">-</span>') + '</td>' +
      '<td class="row-actions">' +
      '<button class="btn btn-sm" data-action="view" data-id="' + p.id + '">View / Test</button>' +
      '<button class="btn btn-sm" data-action="edit" data-id="' + p.id + '">Edit</button>' +
      '<button class="btn btn-sm" data-action="delete" data-id="' + p.id + '" data-name="' + escapeHtml(p.name) + '">Delete</button>' +
      "</td></tr>";
  }).join("");
  el("policy-rows").innerHTML = rows;

  const reload = function () { renderPolicies({ search: el("policy-search").value.trim(), enabled: el("policy-enabled-filter").value }); };
  el("policy-search").addEventListener("input", debounce(reload, 250));
  el("policy-enabled-filter").addEventListener("change", reload);
  el("policy-new").addEventListener("click", function () { openPolicyDialog(null, reload); });
  el("policy-rows").addEventListener("click", function (event) {
    const btn = event.target.closest("button[data-action]");
    if (!btn) return;
    const id = btn.getAttribute("data-id");
    const action = btn.getAttribute("data-action");
    if (action === "toggle") {
      api("POST", "/api/policies/" + id + "/enabled", { enabled: btn.getAttribute("data-enabled") !== "true" })
        .then(reload).catch(function (e) { alert(e.message); });
    } else if (action === "view") {
      api("GET", "/api/policies/" + id).then(function (p) { openPolicyDetail(p, reload); });
    } else if (action === "edit") {
      api("GET", "/api/policies/" + id).then(function (p) { openPolicyDialog(p, reload); });
    } else if (action === "delete") {
      confirmDialog("Delete policy", 'Delete "' + btn.getAttribute("data-name") + '"? This cannot be undone.',
        "Delete policy", function () { return api("DELETE", "/api/policies/" + id); });
      el("modal").querySelector("#modal-confirm").addEventListener("click", function () { setTimeout(reload, 50); });
    }
  });
}

// ---------- categories ----------

function categoryFormHtml(category) {
  const c = category || { name: "", display_name: "", description: "" };
  return (
    "<h2>" + (category ? "Edit category" : "New category") + "</h2>" +
    (category ? "" :
      '<div class="form-row"><label for="cf-name">Slug (lowercase, e.g. torah-study)</label>' +
      '<input type="text" id="cf-name" value="' + escapeHtml(c.name) + '"></div>') +
    '<div class="form-row"><label for="cf-display">Display name</label>' +
    '<input type="text" id="cf-display" value="' + escapeHtml(c.display_name) + '"></div>' +
    '<div class="form-row"><label for="cf-desc">Description</label>' +
    '<input type="text" id="cf-desc" value="' + escapeHtml(c.description) + '"></div>' +
    '<div class="modal-actions">' +
    '<button class="btn" id="modal-cancel">Cancel</button>' +
    '<button class="btn btn-primary" id="cf-save">Save category</button></div>'
  );
}

async function renderCategories(params) {
  const search = (params && params.search) || "";
  const data = await api("GET", "/api/categories" + (search ? "?search=" + encodeURIComponent(search) : ""));
  el("content").innerHTML =
    '<div class="toolbar">' +
    '<input type="search" id="cat-search" placeholder="Search categories" style="max-width:240px" value="' + escapeHtml(search) + '">' +
    '<div class="spacer"></div>' +
    '<button class="btn btn-primary" id="cat-new">New category</button></div>' +
    '<p class="muted small">Starting catalogue only - not a complete or continuously updated URL database. ' +
    'Disabled categories are excluded from domain evaluation.</p>' +
    '<div class="table-wrap"><table><thead><tr>' +
    "<th>Category</th><th>Description</th><th>Domains</th><th>Status</th><th></th>" +
    '</tr></thead><tbody id="cat-rows"></tbody></table></div>';
  el("cat-rows").innerHTML = data.categories.map(function (c) {
    return "<tr><td><strong>" + escapeHtml(c.display_name) + "</strong><br>" +
      '<span class="mono muted small">' + escapeHtml(c.name) + "</span></td>" +
      "<td>" + escapeHtml(c.description) + "</td>" +
      '<td class="mono">' + escapeHtml(c.domain_count) + "</td>" +
      '<td><button class="toggle' + (c.enabled ? " on" : "") + '" data-name="' + escapeHtml(c.name) +
      '" data-enabled="' + c.enabled + '" aria-label="Toggle category"></button></td>' +
      '<td class="row-actions"><button class="btn btn-sm" data-edit="' + escapeHtml(c.name) + '">Edit</button></td></tr>';
  }).join("");

  const reload = function () { renderCategories({ search: el("cat-search").value.trim() }); };
  el("cat-search").addEventListener("input", debounce(reload, 250));
  el("cat-new").addEventListener("click", function () {
    const modal = openModal(categoryFormHtml(null));
    modal.querySelector("#modal-cancel").addEventListener("click", closeModal);
    modal.querySelector("#cf-save").addEventListener("click", function () {
      api("POST", "/api/categories", {
        name: el("cf-name").value.trim(),
        display_name: el("cf-display").value.trim(),
        description: el("cf-desc").value.trim(),
      }).then(function () { closeModal(); reload(); }).catch(showModalError);
    });
  });
  el("cat-rows").addEventListener("click", function (event) {
    const toggle = event.target.closest("button.toggle");
    if (toggle) {
      api("POST", "/api/categories/" + toggle.getAttribute("data-name") + "/enabled",
        { enabled: toggle.getAttribute("data-enabled") !== "1" && toggle.getAttribute("data-enabled") !== "true" })
        .then(reload).catch(function (e) { alert(e.message); });
      return;
    }
    const edit = event.target.closest("button[data-edit]");
    if (edit) {
      const name = edit.getAttribute("data-edit");
      api("GET", "/api/categories").then(function (data) {
        const category = data.categories.find(function (c) { return c.name === name; });
        const modal = openModal(categoryFormHtml(category));
        modal.querySelector("#modal-cancel").addEventListener("click", closeModal);
        modal.querySelector("#cf-save").addEventListener("click", function () {
          api("PUT", "/api/categories/" + name, {
            display_name: el("cf-display").value.trim(),
            description: el("cf-desc").value.trim(),
          }).then(function () { closeModal(); reload(); }).catch(showModalError);
        });
      });
    }
  });
}

// ---------- domains ----------

async function domainFormHtml(domain, categories) {
  const d = domain || { domain: "", categories: [], rule: null };
  const checks = categories.map(function (c) {
    const checked = d.categories.indexOf(c.name) !== -1 ? " checked" : "";
    return '<label style="font-weight:400;margin:0.15rem 0"><input type="checkbox" class="df-cat" value="' +
      escapeHtml(c.name) + '"' + checked + "> " + escapeHtml(c.display_name) +
      ' <span class="mono muted small">' + escapeHtml(c.name) + "</span></label>";
  }).join("");
  return (
    "<h2>" + (domain ? "Edit domain" : "Add domain") + "</h2>" +
    (domain ? '<p class="mono">' + escapeHtml(d.domain) + "</p>" :
      '<div class="form-row"><label for="df-domain">Domain</label>' +
      '<input type="text" id="df-domain" placeholder="example.com" value="' + escapeHtml(d.domain) + '"></div>') +
    '<div class="form-row"><label>Categories</label>' + checks + "</div>" +
    '<div class="form-row"><label for="df-rule">Explicit rule (administrative designation)</label>' +
    '<select id="df-rule">' +
    '<option value=""' + (!d.rule ? " selected" : "") + ">None</option>" +
    '<option value="allow"' + (d.rule === "allow" ? " selected" : "") + ">Allow</option>" +
    '<option value="block"' + (d.rule === "block" ? " selected" : "") + ">Block</option></select>" +
    '<p class="muted small">An explicit rule here records intent only. Filtering decisions come from ' +
    "policies; add the domain to a policy's allow or block list to enforce it.</p></div>" +
    '<div class="modal-actions">' +
    '<button class="btn" id="modal-cancel">Cancel</button>' +
    '<button class="btn btn-primary" id="df-save">Save domain</button></div>'
  );
}

function readDomainForm() {
  const cats = Array.prototype.map.call(
    document.querySelectorAll(".df-cat:checked"), function (cb) { return cb.value; });
  const rule = el("df-rule").value;
  return { categories: cats, rule: rule || null };
}

async function renderDomains(params) {
  const search = (params && params.search) || "";
  const category = (params && params.category) || "";
  const rule = (params && params.rule) || "";
  const catData = await api("GET", "/api/categories");
  let url = "/api/domains?";
  if (search) url += "search=" + encodeURIComponent(search) + "&";
  if (category) url += "category=" + encodeURIComponent(category) + "&";
  if (rule) url += "rule=" + encodeURIComponent(rule);
  const data = await api("GET", url);

  const catOptions = ['<option value="">All categories</option>'].concat(
    catData.categories.map(function (c) {
      return '<option value="' + escapeHtml(c.name) + '"' + (category === c.name ? " selected" : "") + ">" +
        escapeHtml(c.display_name) + "</option>";
    })).join("");

  el("content").innerHTML =
    '<div class="toolbar">' +
    '<input type="search" id="dom-search" placeholder="Search domains" style="max-width:220px" value="' + escapeHtml(search) + '">' +
    '<select id="dom-cat-filter" style="max-width:180px">' + catOptions + "</select>" +
    '<select id="dom-rule-filter" style="max-width:140px">' +
    '<option value="">Any rule</option>' +
    '<option value="allow"' + (rule === "allow" ? " selected" : "") + ">Allow</option>" +
    '<option value="block"' + (rule === "block" ? " selected" : "") + ">Block</option></select>" +
    '<div class="spacer"></div>' +
    '<button class="btn" id="dom-import">Import</button>' +
    '<button class="btn btn-primary" id="dom-new">Add domain</button></div>' +
    '<div class="table-wrap"><table><thead><tr>' +
    "<th>Domain</th><th>Categories</th><th>Explicit rule</th><th></th>" +
    '</tr></thead><tbody id="dom-rows"></tbody></table>' +
    '<div class="empty-state' + (data.domains.length ? " hidden" : "") + '">No domain records. Add domains or import a validated list.</div></div>';

  el("dom-rows").innerHTML = data.domains.map(function (d) {
    return "<tr><td class=\"mono\">" + escapeHtml(d.domain) + "</td>" +
      "<td>" + tags(d.categories) + "</td>" +
      "<td>" + ruleBadge(d.rule) + "</td>" +
      '<td class="row-actions">' +
      '<button class="btn btn-sm" data-edit="' + escapeHtml(d.domain) + '">Edit</button>' +
      '<button class="btn btn-sm" data-delete="' + escapeHtml(d.domain) + '">Delete</button></td></tr>';
  }).join("");

  const reload = function () {
    renderDomains({ search: el("dom-search").value.trim(),
      category: el("dom-cat-filter").value, rule: el("dom-rule-filter").value });
  };
  el("dom-search").addEventListener("input", debounce(reload, 250));
  el("dom-cat-filter").addEventListener("change", reload);
  el("dom-rule-filter").addEventListener("change", reload);

  el("dom-new").addEventListener("click", function () {
    domainFormHtml(null, catData.categories).then(function (html) {
      const modal = openModal(html);
      modal.querySelector("#modal-cancel").addEventListener("click", closeModal);
      modal.querySelector("#df-save").addEventListener("click", function () {
        const payload = readDomainForm();
        payload.domain = el("df-domain").value.trim();
        api("POST", "/api/domains", payload)
          .then(function () { closeModal(); reload(); }).catch(showModalError);
      });
    });
  });

  el("dom-import").addEventListener("click", function () {
    const modal = openModal(
      "<h2>Import domain records</h2>" +
      '<p class="muted small">One JSON object per line: {"domain": "example.com", "categories": ["news"]}. ' +
      "Every line is validated before anything is applied; a bad line aborts the whole import. " +
      "Categories must already exist.</p>" +
      '<textarea id="import-jsonl" rows="8" placeholder=\'{"domain": "example.com", "categories": ["news"]}\'></textarea>' +
      '<div id="import-result"></div>' +
      '<div class="modal-actions"><button class="btn" id="modal-cancel">Cancel</button>' +
      '<button class="btn btn-primary" id="import-run">Validate and import</button></div>'
    );
    modal.querySelector("#modal-cancel").addEventListener("click", closeModal);
    modal.querySelector("#import-run").addEventListener("click", function () {
      api("POST", "/api/domains/import", { jsonl: el("import-jsonl").value }).then(function (result) {
        el("import-result").innerHTML = '<p class="form-error" style="color:var(--ok)">Imported ' +
          escapeHtml(result.records) + " records: " + escapeHtml(result.added) + " added, " +
          escapeHtml(result.updated) + " updated.</p>";
        setTimeout(function () { closeModal(); reload(); }, 900);
      }).catch(showModalError);
    });
  });

  el("dom-rows").addEventListener("click", function (event) {
    const edit = event.target.closest("button[data-edit]");
    const del = event.target.closest("button[data-delete]");
    if (edit) {
      const domain = edit.getAttribute("data-edit");
      api("GET", "/api/domains/" + encodeURIComponent(domain)).then(function (record) {
        domainFormHtml(record, catData.categories).then(function (html) {
          const modal = openModal(html);
          modal.querySelector("#modal-cancel").addEventListener("click", closeModal);
          modal.querySelector("#df-save").addEventListener("click", function () {
            api("PUT", "/api/domains/" + encodeURIComponent(domain), readDomainForm())
              .then(function () { closeModal(); reload(); }).catch(showModalError);
          });
        });
      });
    } else if (del) {
      const domain = del.getAttribute("data-delete");
      confirmDialog("Delete domain", 'Delete "' + domain + '"?', "Delete domain",
        function () { return api("DELETE", "/api/domains/" + encodeURIComponent(domain)); });
      el("modal").querySelector("#modal-confirm").addEventListener("click", function () { setTimeout(reload, 50); });
    }
  });
}

// ---------- applications (planning catalogue only) ----------

function renderApplications() {
  const groups = [
    ["Social media", "App restrictions in this area are a future MDM capability."],
    ["Video and streaming", "App restrictions in this area are a future MDM capability."],
    ["Games", "App restrictions in this area are a future MDM capability."],
    ["Messaging", "App restrictions in this area are a future MDM capability."],
  ];
  el("content").innerHTML =
    '<div class="banner banner-warn">Planning catalogue only. KosherGuard cannot block or manage apps: ' +
    "there is no Apple MDM authorization, no enrolled device, and no app-level restriction exists. " +
    "This page only reserves where app policy planning will live.</div>" +
    '<div class="table-wrap"><table><thead><tr><th>App area</th><th>Status</th></tr></thead><tbody>' +
    groups.map(function (g) {
      return "<tr><td><strong>" + escapeHtml(g[0]) + "</strong><br>" +
        '<span class="muted small">' + escapeHtml(g[1]) + "</span></td>" +
        '<td><span class="badge badge-muted">Not available</span></td></tr>';
    }).join("") + "</tbody></table></div>";
}

// ---------- devices (nothing enrolled) ----------

function renderDevices() {
  el("content").innerHTML =
    '<div class="banner banner-warn"><strong>No devices are connected.</strong> ' +
    "This dashboard does not control any iPhone.</div>" +
    '<div class="card"><h3>Device management status</h3><ul>' +
    "<li>No devices are enrolled in KosherGuard.</li>" +
    "<li>No Apple MDM connection is operational.</li>" +
    "<li>No remote policy push is available.</li>" +
    "<li>No iPhone filtering is being controlled by this dashboard.</li>" +
    "</ul>" +
    '<p class="muted">Device enrollment requires Apple MDM authorization and an approved test device. ' +
    'The exact prerequisites and blockers are documented in <span class="mono">docs/MDM_ENROLLMENT_AND_PUSH.md</span>.</p></div>';
}

// ---------- activity logs ----------

async function renderActivity() {
  const data = await api("GET", "/api/audit?limit=300");
  el("content").innerHTML =
    '<p class="page-sub">Every administrative change is recorded. Most recent first.</p>' +
    '<div class="table-wrap"><table><thead><tr>' +
    "<th>Time (UTC)</th><th>Admin</th><th>Action</th><th>Detail</th>" +
    '</tr></thead><tbody id="audit-rows"></tbody></table>' +
    '<div class="empty-state' + (data.entries.length ? " hidden" : "") + '">No activity recorded yet.</div></div>';
  el("audit-rows").innerHTML = data.entries.map(function (e) {
    return '<tr><td class="mono">' + escapeHtml(e.created_at) + "</td>" +
      "<td>" + escapeHtml(e.admin) + "</td>" +
      '<td><span class="badge badge-info">' + escapeHtml(e.action) + "</span></td>" +
      "<td>" + escapeHtml(e.detail) + "</td></tr>";
  }).join("");
}

// ---------- settings ----------

function renderSettings() {
  el("content").innerHTML =
    '<div class="card" style="max-width:560px"><h3>Account</h3>' +
    '<p>Signed in as <strong id="settings-user"></strong></p>' +
    '<label for="sp-current">Current password</label><input type="password" id="sp-current" autocomplete="current-password">' +
    '<label for="sp-new">New password (at least 12 characters)</label><input type="password" id="sp-new" autocomplete="new-password">' +
    '<p id="sp-error" class="form-error hidden"></p>' +
    '<p id="sp-ok" class="hidden" style="color:var(--ok)">Password changed. Please sign in again.</p>' +
    '<div class="modal-actions" style="justify-content:flex-start">' +
    '<button class="btn btn-primary" id="sp-save">Change password</button></div></div>' +
    '<div class="card" style="max-width:560px;margin-top:1rem"><h3>Environment</h3>' +
    '<dl class="kv">' +
    "<dt>Mode</dt><dd>Development (localhost)</dd>" +
    "<dt>Storage</dt><dd>Local SQLite database</dd>" +
    "<dt>Devices</dt><dd>None connected; no Apple MDM connection</dd>" +
    "<dt>Deployment</dt><dd>Not deployed. A future deployment can use any free tier that runs Python " +
    "(see dashboard README); nothing here is live.</dd>" +
    "</dl></div>";
  el("settings-user").textContent = currentUser || "";
  el("sp-save").addEventListener("click", function () {
    el("sp-error").classList.add("hidden");
    api("POST", "/api/change-password", {
      current_password: el("sp-current").value,
      new_password: el("sp-new").value,
    }).then(function () {
      el("sp-ok").classList.remove("hidden");
      setTimeout(showLogin, 1200);
    }).catch(function (err) {
      el("sp-error").textContent = err.message;
      el("sp-error").classList.remove("hidden");
    });
  });
}


// ---------- publication (Stage 10) ----------

async function renderPublication() {
  const status = await api('GET', '/api/config/status');
  const revData = await api('GET', '/api/config/revisions');

  const sel = status.selected_policy;
  const active = status.active_revision;
  const engine = status.engine;

  let banner;
  if (!sel) {
    banner = '<div class="banner banner-warn">No policy is selected for publication. ' +
      'Open a policy and choose Select for publication.</div>';
  } else if (status.unpublished_changes) {
    banner = '<div class="banner banner-warn">The dashboard has <strong>unpublished changes</strong>. ' +
      'The published revision below is still the previous configuration. ' +
      'Publishing writes a new configuration revision for the filtering engine.</div>';
  } else if (active && engine && status.engine_matches_active_revision === true) {
    banner = '<div class="banner banner-info">The published configuration is live: the engine ' +
      'reports it is enforcing revision ' + escapeHtml(active.revision) + '.</div>';
  } else if (active) {
    banner = '<div class="banner banner-info">Revision ' + escapeHtml(active.revision) +
      ' is published to the engine configuration directory. The engine has not confirmed ' +
      'a reload through its status file, so it is not shown as live.</div>';
  } else {
    banner = '<div class="banner banner-info">Nothing has been published yet.</div>';
  }

  const selectedCard = sel
    ? '<dt>Policy</dt><dd><strong>' + escapeHtml(sel.name || ('id ' + sel.id)) + '</strong>' +
      (sel.missing ? ' <span class="badge badge-danger">deleted</span>' : '') +
      (sel.enabled === false ? ' <span class="badge badge-muted">disabled</span>' : '') + '</dd>' +
      '<dt>Current draft version</dt><dd class="mono">v' + escapeHtml(sel.current_version || '-') + '</dd>' +
      '<dt>Selected by</dt><dd>' + escapeHtml(sel.selected_by || '-') + ' at ' +
      escapeHtml(sel.selected_at || '-') + '</dd>'
    : '<dt>Policy</dt><dd><span class="muted">none selected</span></dd>';

  const activeCard = active
    ? '<dt>Revision</dt><dd class="mono">' + escapeHtml(active.revision) + '</dd>' +
      '<dt>Policy</dt><dd>' + escapeHtml(active.policy_name) + ' (v' + escapeHtml(active.policy_version) + ')</dd>' +
      '<dt>Published by</dt><dd>' + escapeHtml(active.admin) + ' at ' + escapeHtml(active.created_at) + '</dd>' +
      '<dt>Generation</dt><dd class="mono">' + escapeHtml(active.generation) + '</dd>' +
      '<dt>Policy SHA-256</dt><dd class="mono small">' + escapeHtml(active.policy_sha256) + '</dd>' +
      '<dt>Categories SHA-256</dt><dd class="mono small">' + escapeHtml(active.categories_sha256) + '</dd>'
    : '<dd><span class="muted">no published revision</span></dd>';

  let engineCard;
  if (!engine) {
    engineCard = '<dd><span class="muted">Unknown - the engine has not written a status file ' +
      'to this publication directory. Only the engine\'s own report counts as live.</span></dd>';
  } else {
    engineCard =
      '<dt>State</dt><dd>' + escapeHtml(engine.state) + '</dd>' +
      '<dt>Active revision</dt><dd class="mono">' + escapeHtml(engine.revision == null ? '-' : engine.revision) + '</dd>' +
      '<dt>Generation</dt><dd class="mono">' + escapeHtml(engine.generation || '-') + '</dd>' +
      '<dt>Loaded at</dt><dd class="mono">' + escapeHtml(engine.loaded_at || '-') + '</dd>' +
      '<dt>Trigger</dt><dd>' + escapeHtml(engine.trigger || '-') + '</dd>' +
      '<dt>Reloads</dt><dd class="mono">' + escapeHtml(engine.reload_count) + '</dd>' +
      '<dt>Policy SHA-256</dt><dd class="mono small">' + escapeHtml(engine.policy_sha256 || '-') + '</dd>' +
      (engine.last_error
        ? '<dt>Last rejected reload</dt><dd>' + escapeHtml(engine.last_error.error) +
          ' (' + escapeHtml(engine.last_error.at) + ')</dd>'
        : '');
  }

  el('content').innerHTML =
    '<p class="page-sub">Dashboard edits are drafts. An edit reaches the filtering engine only ' +
    'after an explicit publish of the selected policy, and it is live only after the engine ' +
    'confirms a successful reload.</p>' +
    banner +
    '<div class="card-grid">' +
    '<div class="card"><h3>Selected for publication</h3><dl class="kv">' + selectedCard + '</dl>' +
    '<div class="modal-actions" style="justify-content:flex-start">' +
    '<button class="btn btn-primary" id="pub-publish"' + (sel ? '' : ' disabled') +
    '>Publish now</button></div></div>' +
    '<div class="card"><h3>Published to disk</h3><dl class="kv">' + activeCard + '</dl></div>' +
    '<div class="card"><h3>Enforced by the engine</h3><dl class="kv">' + engineCard + '</dl></div>' +
    '</div>' +
    '<h3>Published configuration history</h3>' +
    '<div class="table-wrap"><table><thead><tr>' +
    '<th>Revision</th><th>Policy</th><th>Published by</th><th>At (UTC)</th><th>Status</th><th></th>' +
    '</tr></thead><tbody id="rev-rows"></tbody></table>' +
    '<div class="empty-state' + (revData.revisions.length ? ' hidden' : '') +
    '">Nothing published yet.</div></div>';

  el('rev-rows').innerHTML = revData.revisions.map(function (r) {
    return '<tr><td class="mono">' + escapeHtml(r.revision) + '</td>' +
      '<td>' + escapeHtml(r.policy_name) + ' <span class="muted small">v' + escapeHtml(r.policy_version) + '</span></td>' +
      '<td>' + escapeHtml(r.admin) + '</td>' +
      '<td class="mono">' + escapeHtml(r.created_at) + '</td>' +
      '<td>' + (r.status === 'published'
        ? '<span class="badge badge-ok">Published</span>'
        : r.status === 'failed'
          ? '<span class="badge badge-danger">Failed</span>'
          : '<span class="badge badge-muted">' + escapeHtml(r.status) + '</span>') +
      (r.detail ? '<br><span class="muted small">' + escapeHtml(r.detail) + '</span>' : '') + '</td>' +
      '<td class="row-actions">' +
      (r.status === 'published' && (!active || active.revision !== r.revision)
        ? '<button class="btn btn-sm" data-rollback="' + r.revision + '">Roll back to this</button>'
        : '') +
      '</td></tr>';
  }).join('');

  const publishBtn = el('pub-publish');
  if (publishBtn && sel) {
    publishBtn.addEventListener('click', function () {
      publishBtn.disabled = true;
      api('POST', '/api/config/publish', {})
        .then(renderPublication)
        .catch(function (e) { alert(e.message); renderPublication(); });
    });
  }
  el('rev-rows').addEventListener('click', function (event) {
    const btn = event.target.closest('button[data-rollback]');
    if (!btn) return;
    const rev = btn.getAttribute('data-rollback');
    confirmDialog(
      'Roll back configuration',
      'Publish a new revision with the exact content of revision ' + rev +
      '? The engine will enforce it after its next reload. History is never modified.',
      'Roll back',
      function () { return api('POST', '/api/config/rollback', { revision: Number(rev) }); });
    el('modal').querySelector('#modal-confirm').addEventListener('click', function () {
      setTimeout(renderPublication, 50);
    });
  });
}

// ---------- router ----------

var currentUser = null;

var ROUTES = {
  overview: { title: "Overview", render: function () { return renderOverview(); } },
  policies: { title: "Policies", render: function () { return renderPolicies(); } },
  publication: { title: "Publication", render: function () { return renderPublication(); } },
  categories: { title: "Categories", render: function () { return renderCategories(); } },
  domains: { title: "Domain Management", render: function () { return renderDomains(); } },
  applications: { title: "Applications", render: function () { renderApplications(); return Promise.resolve(); } },
  devices: { title: "Devices", render: function () { renderDevices(); return Promise.resolve(); } },
  activity: { title: "Activity Logs", render: function () { return renderActivity(); } },
  settings: { title: "Settings", render: function () { renderSettings(); return Promise.resolve(); } },
};

function currentRoute() {
  const hash = window.location.hash.replace(/^#\//, "");
  return ROUTES[hash] ? hash : "overview";
}

function route() {
  const name = currentRoute();
  document.querySelectorAll(".nav-link").forEach(function (link) {
    link.classList.toggle("active", link.getAttribute("data-route") === name);
  });
  setTitle(ROUTES[name].title);
  el("sidebar").classList.remove("open");
  ROUTES[name].render().catch(function (err) {
    if (err && err.message !== "not signed in") {
      el("content").innerHTML = '<div class="banner banner-warn">' + escapeHtml(err.message) + "</div>";
    }
  });
}

function debounce(fn, ms) {
  let timer = null;
  return function () {
    clearTimeout(timer);
    timer = setTimeout(fn, ms);
  };
}

// ---------- boot ----------

window.addEventListener("hashchange", route);

el("modal-backdrop").addEventListener("click", function (event) {
  if (event.target === el("modal-backdrop")) closeModal();
});

el("nav-toggle").addEventListener("click", function () {
  el("sidebar").classList.toggle("open");
});

el("logout-btn").addEventListener("click", function () {
  api("POST", "/api/logout", {}).catch(function () {}).finally(showLogin);
});

el("login-form").addEventListener("submit", function (event) {
  event.preventDefault();
  el("login-error").classList.add("hidden");
  api("POST", "/api/login", {
    username: el("login-username").value,
    password: el("login-password").value,
  }).then(function (data) {
    currentUser = data.username;
    el("current-user").textContent = data.username;
    showShell();
    route();
  }).catch(function (err) {
    el("login-error").textContent = err.message;
    el("login-error").classList.remove("hidden");
  });
});

api("GET", "/api/me").then(function (data) {
  currentUser = data.username;
  el("current-user").textContent = data.username;
  showShell();
  route();
}).catch(showLogin);

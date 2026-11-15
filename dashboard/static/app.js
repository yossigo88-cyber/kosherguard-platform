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

// ---------- devices (Stage 11B: device-registry management interface) ----------

// Honest-labeling constants. These strings are mandated UI wording for
// Stage 11B: bindings are routing hints, never identity, and no engine
// has confirmed enforcement while none is connected.
var BINDING_HINT_LABEL = "Network/group binding — routing hint only, not verified device identity.";
var ENFORCEMENT_UNAVAILABLE_LABEL = "Enforcement unavailable — no connected filtering engine has confirmed this policy.";
var DEVICE_STATE_LIST = ["active", "inactive", "disabled", "removed"];
var DEVICE_TYPE_SUGGESTIONS = ["iphone", "ipad", "android", "mac", "windows", "linux", "router", "network", "other"];

function deviceStateBadge(state) {
  var map = {
    active: ["badge-ok", "Active"],
    inactive: ["badge-muted", "Inactive"],
    disabled: ["badge-warn", "Disabled"],
    removed: ["badge-danger", "Removed"],
  };
  var m = map[state] || ["badge-muted", String(state)];
  return '<span class="badge ' + m[0] + '">' + escapeHtml(m[1]) + "</span>";
}

function entryKindBadge(entryKind) {
  if (entryKind === "network_or_group") {
    return '<span class="badge badge-info">Network / group entry</span>';
  }
  return '<span class="badge badge-muted">Device entry</span>';
}

function deviceTypeOptions(current) {
  var seen = {};
  var opts = DEVICE_TYPE_SUGGESTIONS.map(function (t) {
    seen[t] = true;
    return '<option value="' + escapeHtml(t) + '"' + (current === t ? " selected" : "") + ">" +
      escapeHtml(t) + "</option>";
  });
  if (current && !seen[current]) {
    opts.push('<option value="' + escapeHtml(current) + '" selected>' + escapeHtml(current) + "</option>");
  }
  return opts.join("");
}

function bindingKindLabel(kind) {
  if (kind === "ipv4") return "IPv4 address";
  if (kind === "ipv6_prefix") return "IPv6 /64 prefix";
  return String(kind);
}

function bindingSummaryHtml(device) {
  const total = device.live_associations || 0;
  if (!total) return '<span class="muted">none</span>';
  const byKind = device.live_associations_by_kind || {};
  const parts = [];
  if (byKind.ipv4) parts.push(byKind.ipv4 + " IPv4");
  if (byKind.ipv6_prefix) parts.push(byKind.ipv6_prefix + " IPv6 /64");
  return escapeHtml(total + " binding" + (total === 1 ? "" : "s")) +
    (parts.length ? '<br><span class="muted small">' + escapeHtml(parts.join(", ")) + "</span>" : "");
}

function assignedPolicySummary(device) {
  const a = device.active_assignment;
  if (!a) return '<span class="muted">Default policy</span>';
  return "<strong>" + escapeHtml(a.policy_name || ("policy id " + a.policy_id)) + "</strong>" +
    '<br><span class="muted small">assigned at v' + escapeHtml(a.policy_version_at_assignment) + "</span>";
}

function lastSeenHtml(device) {
  // Stage 11A never populates last_seen_at; last-seen reporting is a
  // later stage (plan 7.5). Never invent observation data.
  if (device.last_seen_at) {
    return '<span class="mono">' + escapeHtml(device.last_seen_at) + "</span>" +
      '<br><span class="muted small">binding observed, not a verified device sighting</span>';
  }
  return '<span class="muted">Not tracked</span><br>' +
    '<span class="muted small">last-seen reporting is a future stage</span>';
}

function devicesTableHtml(devices) {
  const rows = devices.map(function (d) {
    return "<tr>" +
      '<td data-label="Name"><strong>' + escapeHtml(d.name) + "</strong> " + entryKindBadge(d.entry_kind) +
      (d.description ? '<br><span class="muted small">' + escapeHtml(d.description) + "</span>" : "") + "</td>" +
      '<td data-label="Type / OS">' + escapeHtml(d.device_type) +
      (d.os ? '<br><span class="muted small">' + escapeHtml(d.os) + "</span>" : "") + "</td>" +
      '<td data-label="State">' + deviceStateBadge(d.state) + "</td>" +
      '<td data-label="Assigned policy">' + assignedPolicySummary(d) + "</td>" +
      '<td data-label="Bindings">' + bindingSummaryHtml(d) + "</td>" +
      '<td data-label="Management"><span class="badge badge-muted">' + escapeHtml(d.management_status) + "</span></td>" +
      '<td data-label="Last seen">' + lastSeenHtml(d) + "</td>" +
      '<td class="row-actions" data-label="Actions">' +
      '<button class="btn btn-sm" data-action="view" data-id="' + escapeHtml(d.id) + '">Open</button></td>' +
      "</tr>";
  }).join("");
  return '<div class="table-wrap"><table class="responsive-table"><thead><tr>' +
    "<th>Name</th><th>Type / OS</th><th>State</th><th>Assigned policy</th>" +
    "<th>Bindings</th><th>Management</th><th>Last seen</th><th></th>" +
    '</tr></thead><tbody id="dv-rows">' + rows + "</tbody></table>" +
    '<div class="empty-state' + (devices.length ? " hidden" : "") + '" id="dv-empty"></div></div>';
}

async function renderDevices(params) {
  params = params || {};
  const search = params.search || "";
  const state = params.state || "";
  el("content").innerHTML = '<div class="empty-state">Loading registry entries...</div>';
  let url = "/api/devices?";
  if (search) url += "search=" + encodeURIComponent(search) + "&";
  if (state) url += "state=" + encodeURIComponent(state);
  const data = await api("GET", url);
  const devices = data.devices || [];

  el("content").innerHTML =
    '<div class="page-head"><h2>Devices</h2></div>' +
    '<p class="page-sub">Administrative registry of devices and network/groups, with per-entry ' +
    "policy assignments and network bindings.</p>" +
    '<div class="banner banner-info">' + escapeHtml(data.note ||
      "Registry entries are administrative records, not enrolled or connected phones.") + "</div>" +
    '<div class="toolbar">' +
    '<input type="search" id="dv-search" class="w-240" placeholder="Search name or description" value="' + escapeHtml(search) + '">' +
    '<select id="dv-state-filter" class="w-150">' +
    '<option value="">All states</option>' +
    DEVICE_STATE_LIST.map(function (s) {
      return '<option value="' + s + '"' + (state === s ? " selected" : "") + ">" +
        s.charAt(0).toUpperCase() + s.slice(1) + "</option>";
    }).join("") +
    "</select>" +
    '<div class="spacer"></div>' +
    '<button class="btn btn-primary" id="dv-register">Register Device</button></div>' +
    devicesTableHtml(devices);

  const emptyBox = el("dv-empty");
  if (!devices.length) {
    emptyBox.textContent = (search || state)
      ? "No registry entries match this search/filter. Adjust the search or state filter."
      : "No registry entries yet. Use Register Device to create the first administrative record. " +
        "Registering a record does not enroll or connect any phone.";
  }

  const reload = function () {
    renderDevices({ search: el("dv-search").value.trim(), state: el("dv-state-filter").value });
  };
  el("dv-search").addEventListener("input", debounce(reload, 250));
  el("dv-state-filter").addEventListener("change", reload);
  el("dv-register").addEventListener("click", function () { openRegisterDialog(reload); });
  el("dv-rows").addEventListener("click", function (event) {
    const btn = event.target.closest("button[data-action='view']");
    if (!btn) return;
    window.location.hash = "#/devices/" + btn.getAttribute("data-id");
  });
}

// -- registration --------------------------------------------------------

function bindingRowHtml() {
  return '<div class="binding-row rf-binding-row">' +
    '<select class="rf-binding-kind" aria-label="Binding type">' +
    '<option value="ipv4">IPv4 address</option>' +
    '<option value="ipv6_prefix">IPv6 /64 prefix</option></select>' +
    '<input type="text" class="rf-binding-value" placeholder="192.168.1.50 or 2001:db8::/64" aria-label="Binding value">' +
    '<button type="button" class="btn btn-sm rf-binding-remove" aria-label="Remove binding">Remove</button>' +
    "</div>";
}

function registerFormHtml(policies) {
  const policyOptions = ['<option value="">No assignment - the default policy applies</option>'].concat(
    (policies || []).map(function (p) {
      return '<option value="' + escapeHtml(p.id) + '">' + escapeHtml(p.name) + "</option>";
    })).join("");
  return (
    "<h2>Register Device</h2>" +
    '<p class="muted small">Creates an administrative registry record. This does not enroll, ' +
    "connect, or manage any phone; every entry stays management_status unmanaged.</p>" +
    '<div class="form-row"><label for="rf-name">Name (required)</label>' +
    '<input type="text" id="rf-name" maxlength="80"></div>' +
    '<div class="form-row"><label for="rf-desc">Description</label>' +
    '<input type="text" id="rf-desc"></div>' +
    '<div class="two-col">' +
    '<div class="form-row"><label for="rf-type">Device type</label>' +
    '<select id="rf-type">' + deviceTypeOptions("other") + "</select></div>" +
    '<div class="form-row"><label for="rf-os">Operating system</label>' +
    '<input type="text" id="rf-os" placeholder="e.g. iOS 18.1"></div></div>' +
    '<div class="form-row"><label for="rf-notes">Notes</label>' +
    '<textarea id="rf-notes" rows="2"></textarea></div>' +
    '<div class="form-row"><label for="rf-policy">Initial policy assignment (optional)</label>' +
    '<select id="rf-policy">' + policyOptions + "</select>" +
    '<p class="muted small">The server checks the tighten-only security rule before accepting ' +
    "an assignment and rejects anything less restrictive than the default policy.</p></div>" +
    '<div class="form-row"><label>Initial network bindings (optional)</label>' +
    '<div id="rf-bindings"></div>' +
    '<button type="button" class="btn btn-sm" id="rf-add-binding">Add binding</button>' +
    '<p class="muted small binding-hint">' + escapeHtml(BINDING_HINT_LABEL) + "</p>" +
    '<p class="muted small">A public IP or shared network address may represent many devices ' +
    "(NAT, a shared IPv6 /64). A binding never proves which physical device sent a query. " +
    "Token credentials are reserved for a future stage and are not offered here.</p></div>" +
    '<div class="modal-actions">' +
    '<button class="btn" id="modal-cancel">Cancel</button>' +
    '<button class="btn btn-primary" id="rf-save">Register Device</button></div>'
  );
}

function readRegisterForm() {
  const bindings = Array.prototype.map.call(
    document.querySelectorAll(".rf-binding-row"), function (row) {
      return {
        kind: row.querySelector(".rf-binding-kind").value,
        value: row.querySelector(".rf-binding-value").value.trim(),
      };
    }).filter(function (b) { return b.value.length > 0; });
  const policyVal = el("rf-policy").value;
  return {
    name: el("rf-name").value.trim(),
    description: el("rf-desc").value.trim(),
    device_type: el("rf-type").value,
    os: el("rf-os").value.trim(),
    notes: el("rf-notes").value.trim(),
    bindings: bindings,
    policy_id: policyVal ? Number(policyVal) : null,
  };
}

function openRegisterDialog(onSaved) {
  api("GET", "/api/policies").then(function (data) {
    const modal = openModal(registerFormHtml(data.policies));
    modal.querySelector("#modal-cancel").addEventListener("click", closeModal);
    modal.querySelector("#rf-add-binding").addEventListener("click", function () {
      el("rf-bindings").insertAdjacentHTML("beforeend", bindingRowHtml());
    });
    el("rf-bindings").addEventListener("click", function (event) {
      const btn = event.target.closest(".rf-binding-remove");
      if (btn) btn.closest(".rf-binding-row").remove();
    });
    const save = modal.querySelector("#rf-save");
    save.addEventListener("click", function () {
      save.disabled = true;
      save.textContent = "Registering...";
      api("POST", "/api/devices", readRegisterForm()).then(function (device) {
        closeModal();
        onSaved();
        window.location.hash = "#/devices/" + device.id;
      }).catch(function (err) {
        save.disabled = false;
        save.textContent = "Register Device";
        showModalError(err);
      });
    });
  }).catch(function (err) { alert(err.message); });
}

// -- editing --------------------------------------------------------------

function editDeviceFormHtml(device) {
  return (
    "<h2>Edit registry entry</h2>" +
    '<div class="form-row"><label for="ef-name">Name (required)</label>' +
    '<input type="text" id="ef-name" maxlength="80" value="' + escapeHtml(device.name) + '"></div>' +
    '<div class="form-row"><label for="ef-desc">Description</label>' +
    '<input type="text" id="ef-desc" value="' + escapeHtml(device.description) + '"></div>' +
    '<div class="two-col">' +
    '<div class="form-row"><label for="ef-type">Device type</label>' +
    '<select id="ef-type">' + deviceTypeOptions(device.device_type) + "</select></div>" +
    '<div class="form-row"><label for="ef-os">Operating system</label>' +
    '<input type="text" id="ef-os" value="' + escapeHtml(device.os) + '"></div></div>' +
    '<div class="form-row"><label for="ef-notes">Notes</label>' +
    '<textarea id="ef-notes" rows="2">' + escapeHtml(device.notes) + "</textarea></div>" +
    '<p class="muted small">State changes use the state controls on the details page. ' +
    "Management status and identity class are server-controlled and cannot be edited.</p>" +
    '<div class="modal-actions">' +
    '<button class="btn" id="modal-cancel">Cancel</button>' +
    '<button class="btn btn-primary" id="ef-save">Save changes</button></div>'
  );
}

function openEditDialog(device, onSaved) {
  const modal = openModal(editDeviceFormHtml(device));
  modal.querySelector("#modal-cancel").addEventListener("click", closeModal);
  const save = modal.querySelector("#ef-save");
  save.addEventListener("click", function () {
    save.disabled = true;
    save.textContent = "Saving...";
    api("PUT", "/api/devices/" + device.id, {
      name: el("ef-name").value.trim(),
      description: el("ef-desc").value.trim(),
      device_type: el("ef-type").value,
      os: el("ef-os").value.trim(),
      notes: el("ef-notes").value.trim(),
    }).then(function () { closeModal(); onSaved(); }).catch(function (err) {
      save.disabled = false;
      save.textContent = "Save changes";
      showModalError(err);
    });
  });
}

// -- details page ---------------------------------------------------------

function bindingsTableHtml(device) {
  const rows = (device.associations || []).map(function (a) {
    const live = !a.retired_at;
    return "<tr>" +
      '<td data-label="Type">' + escapeHtml(bindingKindLabel(a.kind)) + "</td>" +
      '<td data-label="Canonical value" class="mono">' + escapeHtml(a.value) + "</td>" +
      '<td data-label="Identity class"><span class="badge badge-info">network binding</span>' +
      '<br><span class="muted small">routing hint, not verified identity</span></td>' +
      '<td data-label="Created (UTC)" class="mono small">' + escapeHtml(a.created_at) + "</td>" +
      '<td data-label="Status">' + (live
        ? '<span class="badge badge-ok">Active</span>'
        : '<span class="badge badge-muted">Retired</span><br><span class="muted small mono">' +
          escapeHtml(a.retired_at) + "</span>") + "</td>" +
      '<td class="row-actions" data-label="Actions">' + (live
        ? '<button class="btn btn-sm" data-retire="' + escapeHtml(a.id) + '">Retire</button>'
        : "") + "</td>" +
      "</tr>";
  }).join("");
  return '<div class="table-wrap"><table class="responsive-table"><thead><tr>' +
    "<th>Type</th><th>Canonical value</th><th>Identity class</th><th>Created (UTC)</th>" +
    "<th>Status</th><th></th>" +
    '</tr></thead><tbody id="dv-binding-rows">' + rows + "</tbody></table>" +
    '<div class="empty-state' + ((device.associations || []).length ? " hidden" : "") +
    '">No bindings. Add one below to associate this entry with a network address or prefix.</div></div>';
}

function assignmentCardHtml(device, policies) {
  const a = device.active_assignment;
  const current = a
    ? "<strong>" + escapeHtml(a.policy_name || ("policy id " + a.policy_id)) + "</strong>" +
      '<dl class="kv">' +
      "<dt>Version at assignment</dt><dd class=\"mono\">v" + escapeHtml(a.policy_version_at_assignment) + "</dd>" +
      "<dt>Current policy version</dt><dd class=\"mono\">v" + escapeHtml(a.policy_current_version) + "</dd>" +
      "<dt>Assigned by</dt><dd>" + escapeHtml(a.assigned_by) + " at " + escapeHtml(a.assigned_at) + " (UTC)</dd>" +
      "</dl>"
    : '<p class="muted">No assignment - the default policy applies to this entry.</p>';
  const options = (policies || []).map(function (p) {
    return '<option value="' + escapeHtml(p.id) + '"' +
      (a && a.policy_id === p.id ? " selected" : "") + ">" + escapeHtml(p.name) + "</option>";
  }).join("");
  const historyRows = (device.assignment_history || []).map(function (h) {
    return "<tr>" +
      '<td data-label="Policy"><strong>' + escapeHtml(h.policy_name || ("policy id " + h.policy_id)) + "</strong></td>" +
      '<td data-label="Version at assignment" class="mono">v' + escapeHtml(h.policy_version_at_assignment) + "</td>" +
      '<td data-label="Assigned by">' + escapeHtml(h.assigned_by) + "</td>" +
      '<td data-label="Assigned at (UTC)" class="mono small">' + escapeHtml(h.assigned_at) + "</td>" +
      '<td data-label="Status">' + (h.active
        ? '<span class="badge badge-ok">Current</span>'
        : '<span class="badge badge-muted">Superseded</span>') + "</td>" +
      "</tr>";
  }).join("");
  const removed = device.state === "removed";
  return '<div class="card"><h3>Policy assignment</h3>' +
    current +
    (removed
      ? '<p class="muted small">Removed entries hold no assignment; reactivate the entry to assign a policy.</p>'
      : '<div class="toolbar">' +
        '<select id="dv-policy-select" class="w-240" aria-label="Policy to assign">' +
        (options || '<option value="">No policies exist</option>') + "</select>" +
        '<button class="btn btn-primary btn-sm" id="dv-assign"' + (options ? "" : " disabled") + ">Assign policy</button>" +
        (a ? '<button class="btn btn-sm" id="dv-unassign">Unassign (use default)</button>' : "") +
        "</div>" +
        '<p id="dv-assign-error" class="form-error hidden"></p>' +
        '<p class="muted small">The server applies the tighten-only security rule and its verdict ' +
        "is shown verbatim above; this page never pre-judges the comparison.</p>") +
    "<h4>Assignment history</h4>" +
    '<div class="table-wrap"><table class="responsive-table"><thead><tr>' +
    "<th>Policy</th><th>Version at assignment</th><th>Assigned by</th><th>Assigned at (UTC)</th><th>Status</th>" +
    '</tr></thead><tbody>' + historyRows + "</tbody></table>" +
    '<div class="empty-state' + ((device.assignment_history || []).length ? " hidden" : "") +
    '">No assignment history.</div></div></div>';
}

function effectivePolicyCardHtml(eff, device) {
  let assignedHtml;
  if (eff.assigned === "default" || !eff.assigned) {
    assignedHtml = '<span class="muted">Default policy' +
      (eff.default_policy ? " (" + escapeHtml(eff.default_policy.policy_name) + ")" : "") +
      " - no device-specific assignment saved</span>";
  } else {
    const a = eff.assigned;
    assignedHtml = "<strong>" + escapeHtml(a.policy_name || ("policy id " + a.policy_id)) + "</strong>" +
      ' <span class="muted small">assigned at v' + escapeHtml(a.policy_version_at_assignment) +
      ", current v" + escapeHtml(a.policy_current_version) + "</span>";
  }
  if (eff.assigned && eff.assigned !== "default" && !eff.assigned_applies_to_live_queries) {
    assignedHtml += '<br><span class="badge badge-warn">Not applied to live queries</span> ' +
      '<span class="muted small">this entry is ' + escapeHtml(eff.device_state) +
      "; live queries receive the default policy</span>";
  }

  let publishedHtml;
  if (eff.published && typeof eff.published === "object") {
    publishedHtml = '<span class="badge badge-ok">Published</span> <span class="mono">revision ' +
      escapeHtml(eff.published.revision) + "</span>";
  } else {
    publishedHtml = '<span class="badge badge-muted">Unavailable</span><br>' +
      '<span class="muted small">' + escapeHtml(eff.published_note ||
        "the API does not report per-assignment publication in Stage 11A") + "</span>";
  }

  let enforcedHtml;
  if (eff.enforced === "unavailable") {
    enforcedHtml = '<span class="badge badge-muted">Unavailable</span><br>' +
      '<span class="muted small">' + escapeHtml(ENFORCEMENT_UNAVAILABLE_LABEL) + "</span>";
  } else if (eff.enforced === "stale") {
    enforcedHtml = '<span class="badge badge-warn">Stale</span><br>' +
      '<span class="muted small">The connected engine has not confirmed the latest published revision.</span>';
  } else if (eff.enforced === "rejected") {
    enforcedHtml = '<span class="badge badge-danger">Rejected</span><br>' +
      '<span class="muted small">The connected engine rejected the latest generation.</span>';
  } else if (eff.enforced && typeof eff.enforced === "object") {
    enforcedHtml = '<span class="badge badge-ok">Confirmed by engine</span><br>' +
      '<span class="muted small mono">revision ' + escapeHtml(eff.enforced.revision) +
      ", generation " + escapeHtml(eff.enforced.generation) +
      (eff.enforced.confirmed_at ? ", confirmed " + escapeHtml(eff.enforced.confirmed_at) : "") + "</span>" +
      (eff.enforced.covers ? '<br><span class="muted small">' + escapeHtml(eff.enforced.covers) + "</span>" : "");
  } else {
    enforcedHtml = '<span class="badge badge-muted">Unavailable</span>';
  }

  return '<div class="card"><h3>Effective policy status</h3>' +
    '<p class="muted small">Three separate facts. A saved assignment never implies publication, ' +
    "and publication never implies a running engine has loaded it.</p>" +
    '<div class="eff-grid">' +
    '<div class="eff-cell"><h4>1. Assigned</h4><p class="muted small">Saved in the registry.</p>' +
    assignedHtml + "</div>" +
    '<div class="eff-cell"><h4>2. Published</h4><p class="muted small">Included in a successfully published configuration.</p>' +
    publishedHtml + "</div>" +
    '<div class="eff-cell"><h4>3. Enforced</h4><p class="muted small">Confirmed loaded by a running engine.</p>' +
    enforcedHtml + "</div>" +
    "</div>" +
    (eff.enforced_note ? '<p class="muted small">' + escapeHtml(eff.enforced_note) + "</p>" : "") +
    "</div>";
}

function stateControlsHtml(device) {
  const actions = [
    ["active", "Set active", "Reactivate this entry: its bindings and assignment apply again."],
    ["inactive", "Set inactive", "Mark temporarily out of use; live queries receive the default policy."],
    ["disabled", "Disable", "Administratively turn off; bindings are kept for audit, the default policy applies."],
    ["removed", "Remove", "Soft removal: bindings are retired and any assignment deactivated. " +
      "The record and its history are kept. This does not wipe, contact, or affect a physical device."],
  ];
  const buttons = actions.filter(function (x) { return x[0] !== device.state; }).map(function (x) {
    const cls = (x[0] === "removed" || x[0] === "disabled") ? "btn-danger" : "";
    return '<button class="btn btn-sm ' + cls + '" data-state-action="' + x[0] + '">' + x[1] + "</button>";
  }).join("");
  return '<div class="card"><h3>Device state</h3>' +
    "<p>Current state: " + deviceStateBadge(device.state) + "</p>" +
    '<div class="toolbar">' + buttons + "</div>" +
    '<p class="muted small">State changes take effect in the registry immediately and are ' +
    "recorded in the audit history. Removal is soft: nothing is hard-deleted and no physical " +
    "device is wiped.</p></div>";
}

function deviceAuditHtml(entries) {
  const rows = (entries || []).map(function (e) {
    return "<tr>" +
      '<td data-label="Time (UTC)" class="mono small">' + escapeHtml(e.created_at) + "</td>" +
      '<td data-label="Admin">' + escapeHtml(e.admin) + "</td>" +
      '<td data-label="Action"><span class="badge badge-info">' + escapeHtml(e.action) + "</span></td>" +
      '<td data-label="Detail">' + escapeHtml(e.detail) + "</td>" +
      "</tr>";
  }).join("");
  return '<div class="card"><h3>Activity and history</h3>' +
    '<div class="table-wrap"><table class="responsive-table"><thead><tr>' +
    "<th>Time (UTC)</th><th>Admin</th><th>Action</th><th>Detail</th>" +
    '</tr></thead><tbody>' + rows + "</tbody></table>" +
    '<div class="empty-state' + ((entries || []).length ? " hidden" : "") +
    '">No recorded activity for this entry.</div></div></div>';
}

function deviceOverviewHtml(device) {
  const groupNote = device.entry_kind === "network_or_group"
    ? '<div class="banner banner-info">This entry represents a network or group (for example a ' +
      "router or shared Wi-Fi). Its bindings apply one policy to the whole group; it is never an " +
      "authenticated individual phone.</div>"
    : "";
  return groupNote +
    '<div class="card"><h3>Overview</h3>' +
    '<dl class="kv">' +
    "<dt>Description</dt><dd>" + (escapeHtml(device.description) || '<span class="muted">none</span>') + "</dd>" +
    "<dt>Device type</dt><dd>" + escapeHtml(device.device_type) + "</dd>" +
    "<dt>Operating system</dt><dd>" + (escapeHtml(device.os) || '<span class="muted">unspecified</span>') + "</dd>" +
    "<dt>State</dt><dd>" + deviceStateBadge(device.state) + "</dd>" +
    "<dt>Management status</dt><dd><span class=\"badge badge-muted\">" + escapeHtml(device.management_status) +
    "</span> <span class=\"muted small\">no Apple MDM enrollment exists; this dashboard does not manage any phone</span></dd>" +
    "<dt>Registered</dt><dd class=\"mono\">" + escapeHtml(device.registered_at) + " (UTC)</dd>" +
    "<dt>Last updated</dt><dd class=\"mono\">" + escapeHtml(device.updated_at) + " (UTC)</dd>" +
    "<dt>Notes</dt><dd>" + (escapeHtml(device.notes) || '<span class="muted">none</span>') + "</dd>" +
    "<dt>Live bindings</dt><dd>" + bindingSummaryHtml(device) + "</dd>" +
    "</dl>" +
    '<div class="modal-actions actions-start">' +
    '<button class="btn" id="dv-edit">Edit</button></div></div>';
}

async function renderDeviceDetail(id) {
  if (!/^\d+$/.test(String(id))) {
    el("content").innerHTML = '<div class="banner banner-warn">Invalid registry entry id.</div>';
    return;
  }
  el("content").innerHTML = '<div class="empty-state">Loading registry entry...</div>';
  const device = await api("GET", "/api/devices/" + encodeURIComponent(id));
  const results = await Promise.all([
    api("GET", "/api/devices/" + device.id + "/effective-policy"),
    api("GET", "/api/devices/" + device.id + "/audit?limit=200"),
    api("GET", "/api/policies"),
  ]);
  const eff = results[0];
  const audit = results[1];
  const policies = results[2].policies || [];

  el("content").innerHTML =
    '<p><a href="#/devices" class="muted">&larr; All registry entries</a></p>' +
    '<div class="page-head"><h2>' + escapeHtml(device.name) + "</h2>" +
    entryKindBadge(device.entry_kind) + " " + deviceStateBadge(device.state) + "</div>" +
    '<p class="page-sub">Registry record only - not an enrolled, connected, or remotely managed device. ' +
    "Network bindings are routing hints, not verified device identity.</p>" +
    deviceOverviewHtml(device) +
    '<div class="card"><h3>Network bindings</h3>' +
    '<p class="muted small binding-hint">' + escapeHtml(BINDING_HINT_LABEL) + "</p>" +
    '<p class="muted small">A public IP or shared network address may represent many devices. ' +
    "Bindings are canonicalized and validated by the server.</p>" +
    bindingsTableHtml(device) +
    (device.state === "removed"
      ? '<p class="muted small">This entry is removed; it cannot receive new bindings.</p>'
      : '<div class="toolbar">' +
        '<select id="dv-binding-kind" class="w-170" aria-label="Binding type">' +
        '<option value="ipv4">IPv4 address</option>' +
        '<option value="ipv6_prefix">IPv6 /64 prefix</option></select>' +
        '<input type="text" id="dv-binding-value" placeholder="192.168.1.50 or 2001:db8::/64" class="w-240" aria-label="Binding value">' +
        '<button class="btn btn-sm" id="dv-binding-add">Add binding</button></div>' +
        '<p id="dv-binding-error" class="form-error hidden"></p>') +
    "</div>" +
    assignmentCardHtml(device, policies) +
    effectivePolicyCardHtml(eff, device) +
    stateControlsHtml(device) +
    deviceAuditHtml(audit.entries);

  const reload = function () { return renderDeviceDetail(String(device.id)); };

  el("dv-edit").addEventListener("click", function () { openEditDialog(device, reload); });

  const addBtn = el("dv-binding-add");
  if (addBtn) {
    addBtn.addEventListener("click", function () {
      const errBox = el("dv-binding-error");
      errBox.classList.add("hidden");
      addBtn.disabled = true;
      api("POST", "/api/devices/" + device.id + "/associations", {
        kind: el("dv-binding-kind").value,
        value: el("dv-binding-value").value.trim(),
      }).then(reload).catch(function (err) {
        addBtn.disabled = false;
        errBox.textContent = err.message;
        errBox.classList.remove("hidden");
      });
    });
  }

  el("dv-binding-rows").addEventListener("click", function (event) {
    const btn = event.target.closest("button[data-retire]");
    if (!btn) return;
    const aid = btn.getAttribute("data-retire");
    confirmDialog(
      "Retire binding",
      "Retire this network binding? The association stops applying; the record stays in history. " +
      "This does not affect any physical device.",
      "Retire binding",
      function () {
        return api("DELETE", "/api/devices/" + device.id + "/associations/" + aid).then(reload);
      });
  });

  const assignBtn = el("dv-assign");
  if (assignBtn) {
    assignBtn.addEventListener("click", function () {
      const errBox = el("dv-assign-error");
      errBox.classList.add("hidden");
      assignBtn.disabled = true;
      api("POST", "/api/devices/" + device.id + "/assign-policy",
          { policy_id: Number(el("dv-policy-select").value) })
        .then(reload)
        .catch(function (err) {
          assignBtn.disabled = false;
          errBox.textContent = err.message;  // server tighten-only verdict, verbatim
          errBox.classList.remove("hidden");
        });
    });
  }
  const unassignBtn = el("dv-unassign");
  if (unassignBtn) {
    unassignBtn.addEventListener("click", function () {
      confirmDialog(
        "Unassign policy",
        "Remove the current assignment? The default policy applies to this entry instead.",
        "Unassign",
        function () {
          return api("POST", "/api/devices/" + device.id + "/assign-policy",
            { policy_id: null }).then(reload);
        });
    });
  }

  document.querySelectorAll("button[data-state-action]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      const target = btn.getAttribute("data-state-action");
      const labels = { active: "Set active", inactive: "Set inactive",
        disabled: "Disable", removed: "Remove" };
      const extra = target === "removed"
        ? " Removal is soft: bindings are retired and any assignment deactivated, but the record " +
          "and its history are kept. It does not wipe, contact, or affect a physical device."
        : target === "disabled"
          ? " The entry's bindings and assignment stop applying; records stay for audit."
          : "";
      confirmDialog(
        labels[target] + " registry entry",
        'Change "' + device.name + '" to state "' + target + '"?' + extra,
        labels[target],
        function () {
          return api("POST", "/api/devices/" + device.id + "/state",
            { state: target }).then(reload);
        });
    });
  });
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
  devices: { title: "Devices", render: function (param) {
    return param ? renderDeviceDetail(param) : renderDevices();
  } },
  activity: { title: "Activity Logs", render: function () { return renderActivity(); } },
  settings: { title: "Settings", render: function () { renderSettings(); return Promise.resolve(); } },
};

function currentRoute() {
  const hash = window.location.hash.replace(/^#\//, "");
  const parts = hash.split("/");
  const base = parts[0] || "overview";
  const param = parts.length > 1 ? parts.slice(1).join("/") : null;
  return ROUTES[base] ? { name: base, param: param } : { name: "overview", param: null };
}

function route() {
  const r = currentRoute();
  document.querySelectorAll(".nav-link").forEach(function (link) {
    link.classList.toggle("active", link.getAttribute("data-route") === r.name);
  });
  setTitle(ROUTES[r.name].title);
  el("sidebar").classList.remove("open");
  ROUTES[r.name].render(r.param).catch(function (err) {
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

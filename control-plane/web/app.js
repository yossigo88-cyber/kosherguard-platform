function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

const HDR = {"X-KosherGuard-Request": "1", "Content-Type": "application/json"};
const $ = (id) => document.getElementById(id);
let policyList = [];

async function api(path, opts) {
  const r = await fetch(path, opts);
  return {status: r.status, body: await r.json().catch(() => ({}))};
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {email: email.value, password: password.value};
  if (totp.value) payload.totp_code = totp.value;
  const r = await api("/api/auth/login", {method: "POST", headers: HDR, body: JSON.stringify(payload)});
  if (r.status !== 200) { $("login-error").textContent = r.body.error || "Sign-in failed"; return; }
  showApp();
});

async function showApp() {
  ["login-panel", "accept-panel"].forEach(id => $(id).classList.add("hidden"));
  ["overview-panel", "policies-panel", "schedules-panel", "devices-panel", "mdm-panel", "categories-panel", "customers-panel", "credentials-panel", "guardians-panel", "account-panel", "apps-panel", "audit-logs-panel", "signout-panel"].forEach(id => $(id).classList.remove("hidden"));
  const me = await api("/api/auth/me");
  $("who").textContent = me.body.email || "";
  await refresh();
}

async function refresh() {
  refreshOverview();
  refreshCategories();
  refreshCustomers();
  refreshCredentials();
  refreshGuardians();
  refreshMfaState();
  refreshAuditLogs();
  const policies = await api("/api/policies");
  policyList = policies.body.policies || [];
  refreshSchedules();
  document.querySelector("#policies tbody").innerHTML = policyList.map(p =>
    `<tr><td>${esc(p.name)}</td><td>${esc(p.default_policy)}</td><td>${esc(p.blocklist.join(", "))}</td>` +
    `<td>${p.versions}</td><td><button class="link" data-select="${p.id}">make default</button></td></tr>`).join("");
  const devices = await api("/api/devices");
  document.querySelector("#devices tbody").innerHTML = (devices.body.devices || []).map(d =>
    `<tr><td>${esc(d.name)}</td><td>${esc(d.state)}</td><td><select data-device="${d.id}">` +
    policyList.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join("") +
    `</select><button class="link" data-assign="${d.id}">assign</button></td></tr>`).join("");
  deviceList = devices.body.devices || [];
  await refreshAppsPanel();
  await refreshMdm();
}

function escIds(text) {
  return text.split("\n").map(s => s.trim()).filter(Boolean);
}

async function refreshAppsPanel() {
  const sel = $("app-device");
  sel.innerHTML = deviceList.map(d =>
    `<option value="${d.id}">${esc(d.name)}</option>`).join("");
  if (!deviceList.length) return;
  await loadAppPolicy();
}

async function loadAppPolicy() {
  $("app-error").textContent = ""; $("app-ok").textContent = "";
  const id = $("app-device").value;
  if (!id) return;
  const r = await api(`/api/devices/${id}/app-policy`);
  if (r.status !== 200) {
    $("app-error").textContent = r.body.error || "Could not load policy";
    return;
  }
  $("app-mode").value = r.body.mode || "blocklist";
  $("app-bundle-ids").value = (r.body.bundle_ids || []).join("\n");
}

function showAppCmd(r) {
  const box = $("app-cmd-result");
  if (r.status === 200) {
    box.innerHTML = `<p class="ok">Queued ${esc(r.body.command)} ` +
      `(command #${r.body.id}, status ${esc(r.body.status)}). ` +
      `Delivery needs the device to check in.</p>`;
  } else {
    box.innerHTML = `<p class="error">${esc(r.body.error || "Failed")}</p>`;
  }
}

$("app-device").addEventListener("change", loadAppPolicy);
$("app-save").addEventListener("click", async () => {
  $("app-error").textContent = ""; $("app-ok").textContent = "";
  const id = $("app-device").value;
  const r = await api(`/api/devices/${id}/app-policy`,
    {method: "PUT", headers: HDR, body: JSON.stringify({
      mode: $("app-mode").value,
      bundle_ids: escIds($("app-bundle-ids").value)})});
  if (r.status === 200) $("app-ok").textContent = "Saved.";
  else $("app-error").textContent = r.body.error || "Save failed";
});
$("app-apply").addEventListener("click", async () => {
  const id = $("app-device").value;
  showAppCmd(await api(`/api/devices/${id}/app-policy/apply`,
    {method: "POST", headers: HDR, body: "{}"}));
});
$("app-install").addEventListener("click", async () => {
  const id = $("app-device").value;
  const storeId = parseInt($("app-store-id").value, 10);
  showAppCmd(await api(`/api/devices/${id}/app-commands`,
    {method: "POST", headers: HDR, body: JSON.stringify({
      action: "install", itunes_store_id: isNaN(storeId) ? null : storeId})}));
});
$("app-remove").addEventListener("click", async () => {
  const id = $("app-device").value;
  const bid = $("app-remove-id").value.trim();
  if (!window.confirm(
      "Remove managed app " + (bid || "(no bundle ID entered)") + "?\n\n" +
      "This erases the app's data on the device. Only managed apps " +
      "(installed through KosherGuard) can be removed. Continue?")) {
    $("app-cmd-result").innerHTML =
      '<p class="muted">Removal cancelled; nothing was queued.</p>';
    return;
  }
  showAppCmd(await api(`/api/devices/${id}/app-commands`,
    {method: "POST", headers: HDR, body: JSON.stringify({
      action: "remove", bundle_id: bid})}));
});
$("app-list").addEventListener("click", async () => {
  const id = $("app-device").value;
  showAppCmd(await api(`/api/devices/${id}/app-commands`,
    {method: "POST", headers: HDR, body: JSON.stringify({action: "list"})}));
});
$("app-managed-list").addEventListener("click", async () => {
  const id = $("app-device").value;
  showAppCmd(await api(`/api/devices/${id}/app-commands`,
    {method: "POST", headers: HDR, body: JSON.stringify({action: "managed-list"})}));
});

async function refreshAuditLogs() {
  const status = $("audit-logs-status");
  const table = $("audit-logs-table");
  const r = await api("/api/audit-logs");
  if (r.status !== 200) {
    status.textContent = "Could not load logs.";
    table.classList.add("hidden");
    return;
  }
  const events = r.body.events || [];
  if (!events.length) {
    status.textContent = "No activity recorded yet.";
    table.classList.add("hidden");
    return;
  }
  status.textContent = "";
  table.classList.remove("hidden");
  table.querySelector("tbody").innerHTML = events.map(e => {
    const when = e.created_at ? new Date(e.created_at).toLocaleString() : "";
    return `<tr><td>${esc(when)}</td><td>${esc(e.action || "")}</td>` +
      `<td>${esc(e.actor || "")}</td><td>${esc(e.detail || "")}</td></tr>`;
  }).join("");
}

let deviceList = [];
let enrollmentList = [];

async function refreshMdm() {
  $("e-device").innerHTML = deviceList.map(d =>
    `<option value="${d.id}">${esc(d.name)}</option>`).join("");
  const enr = await api("/api/mdm/enrollments");
  enrollmentList = enr.body.enrollments || [];
  const deviceName = (id) => {
    const d = deviceList.find(x => x.id === id);
    return d ? d.name : `#${id}`;
  };
  document.querySelector("#enrollments tbody").innerHTML = enrollmentList.map(e =>
    `<tr><td>${esc(deviceName(e.device_id))}</td><td>${esc(e.enrollment_id)}</td>` +
    `<td>${esc(e.state)}</td><td>${e.supervision_requested ? "yes" : "no"}</td>` +
    `<td>${e.supervision_verified ? "yes" : "no"}</td>` +
    `<td>${esc(e.last_seen_at || "never")}</td>` +
    `<td><button class="link" data-history="${e.id}">history</button></td></tr>`).join("");
  $("c-enrollment").innerHTML = enrollmentList.map(e =>
    `<option value="${e.id}">${esc(deviceName(e.device_id))} (${esc(e.state)})</option>`).join("");
}

$("enroll-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const r = await api("/api/mdm/enrollments", {method: "POST", headers: HDR,
    body: JSON.stringify({device_id: Number($("e-device").value),
                          supervision_requested: $("e-supervised").checked})});
  $("enroll-error").textContent = r.status === 200 ? "" : (r.body.error || "failed");
  if (r.status === 200) await refreshMdm();
});

$("command-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const enrId = $("c-enrollment").value;
  if (!enrId) { $("command-error").textContent = "no enrollment"; return; }
  const r = await api(`/api/mdm/enrollments/${enrId}/commands`, {method: "POST",
    headers: HDR, body: JSON.stringify({command: $("c-command").value, payload: {}})});
  $("command-error").textContent = r.status === 200 ? "" : (r.body.error || "failed");
  $("command-ok").textContent = r.status === 200
    ? `queued (${r.body.status}; applied: ${r.body.applied ? "yes" : "no"})` : "";
  if (r.status === 200) await loadHistory(enrId);
});

document.addEventListener("click", async (e) => {
  const hist = e.target.dataset && e.target.dataset.history;
  if (hist) await loadHistory(hist);
});

async function loadHistory(enrId) {
  const r = await api(`/api/mdm/enrollments/${enrId}/commands`);
  document.querySelector("#commands tbody").innerHTML = (r.body.commands || []).map(c =>
    `<tr><td>${c.id}</td><td>${esc(c.command)}</td><td>${esc(c.status)}</td>` +
    `<td>${c.applied ? "yes" : "no"}</td><td>${esc(c.result_detail || "")}</td></tr>`).join("");
}

document.addEventListener("click", async (e) => {
  const sel = e.target.dataset && e.target.dataset.select;
  const asg = e.target.dataset && e.target.dataset.assign;
  if (sel) {
    const r = await api(`/api/policies/${sel}/select`, {method: "POST", headers: HDR, body: "{}"});
    $("policy-ok").textContent = r.status === 200 ? "Default updated" : "";
    $("policy-error").textContent = r.status === 200 ? "" : (r.body.error || "refused");
  }
  if (asg) {
    const select = document.querySelector(`select[data-device="${asg}"]`);
    const r = await api(`/api/devices/${asg}/assignment`, {method: "POST", headers: HDR, body: JSON.stringify({policy_id: Number(select.value)})});
    $("device-error").textContent = r.status === 200 ? "" : (r.body.error || "refused");
  }
});

$("policy-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const split = (v) => v.split(",").map(s => s.trim()).filter(Boolean);
  const payload = {name: $("p-name").value, default_policy: $("p-default").value,
    blocklist: split($("p-blocklist").value), category_block: split($("p-catblock").value),
    allowlist: [], category_allow: []};
  const r = await api("/api/policies", {method: "POST", headers: HDR, body: JSON.stringify(payload)});
  $("policy-error").textContent = r.status === 200 ? "" : (r.body.error || "failed");
  $("policy-ok").textContent = r.status === 200 ? "Policy created" : "";
  if (r.status === 200) { $("p-name").value = ""; await refresh(); }
});

$("device-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const r = await api("/api/devices", {method: "POST", headers: HDR, body: JSON.stringify({name: $("d-name").value})});
  $("device-error").textContent = r.status === 200 ? "" : (r.body.error || "failed");
  if (r.status === 200) { $("d-name").value = ""; await refresh(); }
});

$("signout").addEventListener("click", async () => {
  await api("/api/auth/logout", {method: "POST", headers: HDR});
  location.reload();
});

async function refreshCategories() {
  const err = $("cat-error"), ok = $("cat-ok");
  err.textContent = ""; ok.textContent = "";
  const r = await api("/api/admin/categories");
  if (r.status === 403) {
    $("categories-panel").querySelector("p").textContent =
      "Platform-admin only. This account does not manage the category dataset.";
    $("category-form").classList.add("hidden");
    return;
  }
  const body = r.body;
  const tbody = $("cat-table").querySelector("tbody");
  tbody.innerHTML = "";
  for (const rule of body.rules || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(rule.domain)}</td><td>${esc(rule.category)}</td>` +
      `<td>${esc(rule.verdict)}</td><td>${esc(rule.source)}</td>` +
      `<td>${rule.active ? "yes" : "no"}</td>`;
    if (rule.active) {
      const td = document.createElement("td");
      const btn = document.createElement("button");
      btn.className = "link";
      btn.textContent = "deactivate";
      btn.onclick = async () => {
        await api(`/api/admin/categories/${rule.id}`,
                  {method: "DELETE", headers: {"X-KosherGuard-Request": "1"}});
        refreshCategories();
      };
      td.appendChild(btn);
      tr.appendChild(td);
    } else {
      tr.appendChild(document.createElement("td"));
    }
    tbody.appendChild(tr);
  }
}

$("category-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("cat-error"), ok = $("cat-ok");
  err.textContent = ""; ok.textContent = "";
  const r = await api("/api/admin/categories", {
    method: "POST",
    headers: {"Content-Type": "application/json",
              "X-KosherGuard-Request": "1"},
    body: JSON.stringify({
      domain: $("cat-domain").value,
      category: $("cat-category").value,
      verdict: $("cat-verdict").value,
      source: $("cat-source").value,
    }),
  });
  if (r.status === 200) {
    ok.textContent = "Rule saved.";
    $("cat-domain").value = "";
    refreshCategories();
  } else {
    err.textContent = r.body.detail || r.body.error || `Error ${r.status}`;
  }
});



$("password-change-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("pc-error"), ok = $("pc-ok");
  err.textContent = ""; ok.textContent = "";
  const r = await api("/api/auth/password-change", {
    method: "POST",
    headers: {"Content-Type": "application/json",
              "X-KosherGuard-Request": "1"},
    body: JSON.stringify({current_password: $("pc-current").value,
                          new_password: $("pc-new").value}),
  });
  if (r.status === 200) {
    ok.textContent = "Password changed.";
    $("pc-current").value = ""; $("pc-new").value = "";
  } else {
    err.textContent = (r.body && r.body.error) || "Change failed.";
  }
});

async function refreshMfaState() {
  const r = await api("/api/auth/me");
  if (r.status !== 200) return;
  const enrolled = r.body.mfa_enabled;
  $("mfa-state").textContent = enrolled
    ? "Two-factor authentication is ON for your account."
    : "Two-factor authentication is off.";
  $("mfa-start").classList.toggle("hidden", enrolled);
}

$("mfa-start").addEventListener("click", async () => {
  const r = await api("/api/auth/mfa/enroll-start", {
    method: "POST", headers: {"X-KosherGuard-Request": "1"}});
  if (r.status !== 200) return;
  $("mfa-uri").value = r.body.provisioning_uri;
  $("mfa-enroll-box").classList.remove("hidden");
  $("mfa-start").classList.add("hidden");
});

$("mfa-confirm-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("mfa-error"), ok = $("mfa-ok");
  err.textContent = ""; ok.textContent = "";
  const r = await api("/api/auth/mfa/enroll-confirm", {
    method: "POST",
    headers: {"Content-Type": "application/json",
              "X-KosherGuard-Request": "1"},
    body: JSON.stringify({code: $("mfa-code").value,
                          password: $("mfa-password").value}),
  });
  if (r.status === 200) {
    ok.textContent = "Two-factor authentication enabled.";
    $("mfa-enroll-box").classList.add("hidden");
    refreshMfaState();
    refreshGuardians();
  } else {
    err.textContent = (r.body && r.body.error) || "Confirmation failed.";
  }
});

async function refreshGuardians() {
  const r = await api("/api/guardians");
  const tbody = $("guardians-table").querySelector("tbody");
  tbody.innerHTML = "";
  if (r.status !== 200) return;
  for (const g of r.body.guardians || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(g.email)}</td><td>${esc(g.role)}</td>` +
      `<td>${g.mfa_enrolled ? "enrolled" : "not enrolled"}</td>` +
      `<td>${esc((g.created_at || "").slice(0, 10))}</td>`;
    const td = document.createElement("td");
    const roleBtn = document.createElement("button");
    roleBtn.className = "link";
    roleBtn.textContent = "change role";
    roleBtn.onclick = async () => {
      const role = prompt("New role for " + g.email +
                          " (guardian, viewer, owner):");
      if (!role) return;
      const rr = await api(`/api/guardians/${g.id}/role`, {
        method: "PUT",
        headers: {"Content-Type": "application/json",
                  "X-KosherGuard-Request": "1"},
        body: JSON.stringify({role}),
      });
      const err = $("guardian-error");
      err.textContent = rr.status === 200 ? "" :
        ((rr.body && rr.body.error) || "Role change failed.");
      refreshGuardians();
    };
    const mfaBtn = document.createElement("button");
    mfaBtn.className = "link";
    mfaBtn.textContent = "reset MFA";
    mfaBtn.onclick = async () => {
      const password = prompt(
        "Your password (fresh authentication) to reset MFA for " +
        g.email + ":");
      if (!password) return;
      const rr = await api(`/api/guardians/${g.id}/mfa-reset`, {
        method: "POST",
        headers: {"Content-Type": "application/json",
                  "X-KosherGuard-Request": "1"},
        body: JSON.stringify({password}),
      });
      const err = $("guardian-error");
      err.textContent = rr.status === 200 ? "" :
        ((rr.body && rr.body.error) || "MFA reset failed.");
      refreshGuardians();
    };
    td.appendChild(roleBtn);
    td.appendChild(document.createTextNode(" "));
    td.appendChild(mfaBtn);
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
}

$("guardian-invite-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("guardian-error"), ok = $("guardian-ok");
  err.textContent = ""; ok.textContent = "";
  const r = await api("/api/guardians/invite", {
    method: "POST",
    headers: {"Content-Type": "application/json",
              "X-KosherGuard-Request": "1"},
    body: JSON.stringify({email: $("g-email").value,
                          role: $("g-role").value}),
  });
  if (r.status === 200) {
    ok.textContent = "Invite created for " + r.body.invited +
      " (expires " + r.body.expires_at.slice(0, 10) + ").";
    const link = location.origin + location.pathname + "?invite=" + r.body.invite_token;
    $("invite-link").value = link;
    $("invite-result").classList.remove("hidden");
    $("g-email").value = "";
  } else {
    $("invite-result").classList.add("hidden");
    err.textContent = (r.body && r.body.error) || "Invite failed.";
  }
});

$("invite-accept-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("accept-error"), ok = $("accept-ok");
  err.textContent = ""; ok.textContent = "";
  const r = await api("/api/invites/accept", {
    method: "POST",
    headers: {"Content-Type": "application/json",
              "X-KosherGuard-Request": "1"},
    body: JSON.stringify({token: $("a-token").value,
                          password: $("a-password").value}),
  });
  if (r.status === 200) {
    ok.textContent = "Invite accepted for " + r.body.accepted +
      " - sign in above.";
    $("a-token").value = ""; $("a-password").value = "";
  } else {
    err.textContent = (r.body && r.body.error) || "Accept failed.";
  }
});

// Prefill the accept form when arriving via an invite link.
(function () {
  const t = new URLSearchParams(location.search).get("invite");
  if (t) { $("a-token").value = t; }
})();

async function refreshOverview() {
  const r = await api("/api/overview");
  if (r.status !== 200) return;
  const b = r.body;
  $("overview-table").querySelector("tbody").innerHTML =
    [["Devices", b.devices], ["Enrollments", b.enrollments],
     ["Policies", b.policies], ["Guardians", b.guardians]]
      .map(([k, v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join("");
  const tbody = $("activity-table").querySelector("tbody");
  tbody.innerHTML = "";
  for (const a of b.recent_activity || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(a.at)}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td>`;
    tbody.appendChild(tr);
  }
}

async function refreshCustomers() {
  const r = await api("/api/admin/tenants");
  const panel = $("customers-panel");
  if (r.status === 403) { panel.classList.add("hidden"); return; }
  if (r.status !== 200) return;
  const tbody = $("customers-table").querySelector("tbody");
  tbody.innerHTML = "";
  for (const t of r.body.tenants || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(t.name)}</td><td>${t.devices}</td>` +
      `<td>${t.guardians}</td><td>${esc(t.created_at.slice(0, 10))}</td>`;
    tbody.appendChild(tr);
  }
}

// -- Filtering schedules --------------------------------------------------

const DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
let scheduleList = [];

function fmtMin(m) {
  return String(Math.floor(m / 60)).padStart(2, "0") + ":" +
         String(m % 60).padStart(2, "0");
}

function selectedSchedulePolicy() {
  const id = Number($("s-policy").value);
  return policyList.find(p => p.id === id) || null;
}

function renderSchedules() {
  const p = selectedSchedulePolicy();
  scheduleList = p ? (p.schedules || []) : [];
  document.querySelector("#schedules tbody").innerHTML = scheduleList.map(sc =>
    `<tr><td>${esc(sc.name)}</td>` +
    `<td>${sc.days.map(d => DAY_NAMES[d]).join(" ")}</td>` +
    `<td>${fmtMin(sc.start)}-${fmtMin(sc.end)}</td>` +
    `<td>${esc(sc.timezone)}</td>` +
    `<td>${esc([...sc.block_categories, ...sc.block_domains].join(", "))}</td>` +
    `<td>${sc.enabled ? "yes" : "no"}</td>` +
    `<td><button class="link" data-rmsched="${esc(sc.name)}">remove</button></td></tr>`
  ).join("");
}

function refreshSchedules() {
  $("s-policy").innerHTML = policyList.map(p =>
    `<option value="${p.id}">${esc(p.name)}</option>`).join("");
  renderSchedules();
}

async function putSchedules(list) {
  const p = selectedSchedulePolicy();
  if (!p) { $("schedule-error").textContent = "no policy selected"; return false; }
  const r = await api(`/api/policies/${p.id}/schedules`, {method: "PUT",
    headers: HDR, body: JSON.stringify({schedules: list})});
  $("schedule-error").textContent = r.status === 200 ? "" : (r.body.error || "refused");
  $("schedule-ok").textContent = r.status === 200 ? "Saved" : "";
  if (r.status === 200) {
    p.schedules = r.body.schedules;
    renderSchedules();
    return true;
  }
  return false;
}

$("s-policy").addEventListener("change", renderSchedules);

$("schedule-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const split = (v) => v.split(",").map(s => s.trim()).filter(Boolean);
  const entry = {name: $("s-name").value.trim(),
    days: split($("s-days").value).map(Number),
    start: $("s-start").value, end: $("s-end").value,
    timezone: $("s-tz").value.trim(),
    block_categories: split($("s-cats").value),
    block_domains: split($("s-doms").value),
    enabled: $("s-enabled").checked};
  const others = scheduleList.filter(sc => sc.name !== entry.name);
  if (await putSchedules([...others, entry])) {
    $("s-name").value = "";
  }
});

document.addEventListener("click", async (e) => {
  const name = e.target.dataset && e.target.dataset.rmsched;
  if (name) {
    await putSchedules(scheduleList.filter(sc => sc.name !== name));
  }
});

async function refreshCredentials() {
  const r = await api("/api/credentials");
  const banner = $("cred-env-banner");
  if (r.status !== 200) {
    banner.textContent = "";
    return;
  }
  banner.textContent = r.body.fixture_only
    ? "DEVELOPMENT BUILD - fixture credentials only. Never upload production secrets here."
    : "";
  const tbody = $("cred-table").querySelector("tbody");
  tbody.innerHTML = "";
  for (const c of r.body.credentials || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(c.kind)}</td><td>${esc(c.label)}</td>` +
      `<td>${esc(c.sha256.slice(0, 12))}...</td><td>${c.byte_size}</td>` +
      `<td>${esc(c.environment)}</td><td>${c.version}</td><td>${esc(c.status)}</td>`;
    const td = document.createElement("td");
    if (c.status === "active") {
      const rot = document.createElement("button");
      rot.className = "link";
      rot.textContent = "rotate";
      rot.onclick = async () => {
        const content = prompt("New content (base64) for " + c.label + ":");
        if (!content) return;
        await api(`/api/credentials/${c.id}/rotate`, {
          method: "POST",
          headers: {"Content-Type": "application/json",
                    "X-KosherGuard-Request": "1"},
          body: JSON.stringify({kind: c.kind, label: c.label,
                                content_base64: content}),
        });
        refreshCredentials();
      };
      const rev = document.createElement("button");
      rev.className = "link";
      rev.textContent = "revoke";
      rev.onclick = async () => {
        await api(`/api/credentials/${c.id}`,
                  {method: "DELETE", headers: {"X-KosherGuard-Request": "1"}});
        refreshCredentials();
      };
      td.appendChild(rot);
      td.appendChild(document.createTextNode(" "));
      td.appendChild(rev);
    }
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
}

$("cred-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("cred-error"), ok = $("cred-ok");
  err.textContent = ""; ok.textContent = "";
  const r = await api("/api/credentials", {
    method: "POST",
    headers: {"Content-Type": "application/json",
              "X-KosherGuard-Request": "1"},
    body: JSON.stringify({
      kind: $("cred-kind").value,
      label: $("cred-label").value,
      content_base64: $("cred-content").value,
    }),
  });
  if (r.status === 200) {
    ok.textContent = "Credential stored (metadata only is shown).";
    $("cred-label").value = "";
    $("cred-content").value = "";
    refreshCredentials();
  } else {
    err.textContent = (r.body && r.body.error) || "Upload failed.";
  }
});

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

const HDR = {"X-KosherGuard-Request": "1", "Content-Type": "application/json"};
const $ = (id) => document.getElementById(id);
let policyList = [];
let accountInfo = {};

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
  ["groups-panel", "exceptions-panel", "policy-preview-panel", "publication-jobs-panel", "overview-panel", "policies-panel", "schedules-panel", "devices-panel", "mdm-panel", "categories-panel", "customers-panel", "credentials-panel", "guardians-panel", "approvals-panel", "staff-panel", "account-panel", "filtering-panel", "apps-panel", "audit-logs-panel", "signout-panel"].forEach(id => $(id).classList.remove("hidden"));
  const me = await api("/api/auth/me");
  accountInfo = me.body;
  // read_only staff: viewing only - hide every mutation control outside
  // account self-service; the backend rejects mutations independently.
  document.body.classList.toggle("ro", me.body.staff_role === "read_only");
  $("who").textContent = me.body.email || "";
  if (me.body.privileged && !me.body.mfa_verified) {
    document.querySelectorAll("section.panel").forEach(p => p.classList.add("hidden"));
    ["account-panel", "signout-panel"].forEach(id => $(id).classList.remove("hidden"));
    $("mfa-state").textContent = "Two-factor authentication is required before administrative access. Enroll below, then sign in again with a code.";
    $("mfa-start").classList.toggle("hidden", me.body.mfa_enabled);
    return;
  }
  await refresh();
}

async function refresh() {
  refreshOverview();
  refreshCategories();
  refreshCustomers();
  refreshCredentials();
  refreshGuardians();
  refreshApprovals();
  refreshStaff();
  refreshMfaState();
  refreshAuditLogs();
  const policies = await api("/api/policies");
  policyList = policies.body.policies || [];
  $("preview-policy").innerHTML = policyList.map(p =>
    `<option value="${p.id}">${esc(p.name)}</option>`).join("");
  refreshSchedules();
  document.querySelector("#policies tbody").innerHTML = policyList.map(p =>
    `<tr><td>${esc(p.name)}</td><td>${esc(p.default_policy)}</td><td>${esc(p.blocklist.join(", "))}</td>` +
    `<td>${p.versions}</td><td>${p.protected_baseline ? "protected baseline" : (accountInfo.role === "owner" ? `<button class="link" data-select="${p.id}">make protected baseline</button>` : "owner-controlled baseline")}</td></tr>`).join("");
  const devices = await api("/api/devices");
  document.querySelector("#devices tbody").innerHTML = (devices.body.devices || []).map(d =>
    `<tr><td>${esc(d.name)}</td><td>${esc(d.state)}</td><td><select data-device="${d.id}">` +
    policyList.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join("") +
    `</select><button class="link" data-assign="${d.id}">assign</button></td></tr>`).join("");
  deviceList = devices.body.devices || [];
  refreshFiltering();
  await refreshGroups();
  await refreshExceptions();
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
$("app-unapply").addEventListener("click", async () => {
  const id = $("app-device").value;
  if (!window.confirm(
      "Unapply the app policy from this device?\n\n" +
      "This queues a RemoveProfile command that lifts the app " +
      "allow/block restrictions from the device. The saved policy " +
      "stays and can be re-applied. Continue?")) {
    $("app-cmd-result").innerHTML =
      '<p class="muted">Unapply cancelled; nothing was queued.</p>';
    return;
  }
  showAppCmd(await api(`/api/devices/${id}/app-policy/unapply`,
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

async function refreshEdgeStatus() {
  const box = $("filtering-edge-status");
  const r = await api("/api/filter-status");
  if (r.status !== 200) {
    box.textContent = "Edge status unavailable.";
    return;
  }
  const s = r.body;
  const cfg = s.configured || {};
  const rep = s.reported || {};
  const lines = [
    "Proxy/DNS edge status",
    "Configured: " + (cfg.policy_selected
      ? "a filtering policy is selected (publication revision " +
        (cfg.publication_revision || 0) + ")"
      : "no filtering policy selected yet"),
    "Reported: " + (rep.decision_count
      ? rep.decision_count + " decision(s) received from: " +
        (rep.sources || []).join(", ") + "; latest " +
        (rep.latest_received_at
          ? new Date(rep.latest_received_at).toLocaleString() : "?")
      : "no decisions reported yet"),
    "DNS decision reporting: " + (s.dns_reporting || "not connected"),
    "Health: UNKNOWN - " + (s.health_note || ""),
  ];
  box.innerHTML = lines.map(l => "<p>" + esc(l) + "</p>").join("");
}

async function refreshFiltering() {
  const retention = await api("/api/privacy/retention");
  if (retention.status === 200) $("retention-days").value = retention.body.blocked_days;
  refreshEdgeStatus();
  const status = $("filtering-status");
  const table = $("filtering-table");
  const r = await api("/api/filter-logs");
  if (r.status !== 200) {
    status.textContent = "Could not load filtering activity.";
    table.querySelector("tbody").innerHTML = "";
    table.classList.add("hidden");
    return;
  }
  const rows = r.body.decisions || [];
  if (!rows.length) {
    status.textContent = "No blocked activity retained.";
    table.querySelector("tbody").innerHTML = "";
    table.classList.add("hidden");
    return;
  }
  status.textContent = "";
  table.classList.remove("hidden");
  table.querySelector("tbody").innerHTML = rows.map(d => {
    const when = d.received_at ? new Date(d.received_at).toLocaleString() : "";
    return `<tr><td>${esc(when)}</td><td>${esc(d.device || "")}</td>` +
      `<td>${esc(d.domain)}</td><td>${esc(d.action)}</td>` +
      `<td>${esc(d.rule || d.reason || "")}</td></tr>`;
  }).join("");
}

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
    $("mfa-ok").textContent = "MFA enabled. Sign out, then sign in with your password and authenticator code for administrative access.";
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
      const totp_code = prompt("Your current authenticator code:");
      if (!totp_code) return;
      const confirm = prompt("Type mfa-reset to reset MFA for " + g.email +
        ". This revokes their sessions and requires MFA enrollment again.");
      if (confirm !== "mfa-reset") return;
      const rr = await api(`/api/guardians/${g.id}/mfa-reset`, {
        method: "POST",
        headers: {"Content-Type": "application/json",
                  "X-KosherGuard-Request": "1"},
        body: JSON.stringify({password, totp_code, confirm}),
      });
      const err = $("guardian-error");
      err.textContent = rr.status === 200 ? "" :
        ((rr.body && rr.body.error) || "MFA reset failed.");
      refreshGuardians();
    };
    td.appendChild(roleBtn);
    td.appendChild(document.createTextNode(" "));
    td.appendChild(mfaBtn);
    if (g.role === "guardian" && accountInfo.role === "owner") {
      const grantBtn=document.createElement("button");grantBtn.className="link";
      grantBtn.textContent="delegated settings";
      grantBtn.onclick=async()=>{
        const text=prompt("Explicit capabilities: policies, schedules, devices, groups, apps (inventory only), publish. Empty revokes all. No baseline/category/protection-removal grant.",(g.delegated_settings||[]).join(","));
        if(text===null)return;
        const capabilities=text.split(",").map(x=>x.trim()).filter(Boolean);
        const rr=await api(`/api/guardians/${g.id}/delegation`,{method:"PUT",headers:HDR,body:JSON.stringify({capabilities})});
        $("guardian-error").textContent=rr.status===200?"Delegation saved":(rr.body.error||"Failed");
        refreshGuardians();
      };
      td.appendChild(grantBtn);
    }

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
    `<td>${esc(sc.timezone)}<br><small>${sc.start_date || sc.end_date ? `${esc(sc.start_date || "any start")} to ${esc(sc.end_date || "no end")}` : "weekly"}</small></td>` +
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
  if ($("s-first-date").value) entry.start_date = $("s-first-date").value;
  if ($("s-last-date").value) entry.end_date = $("s-last-date").value;
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

let publicationJobId = null;
let publicationRequestKey = null;
async function showPublicationJob(r) {
  if (r.status !== 200) {
    $("publication-job-status").textContent = r.body.error || "Job unavailable";
    return;
  }
  publicationJobId = r.body.id;
  $("publication-job-status").textContent = `Job ${r.body.id}: ${r.body.status}; attempts ${r.body.attempts}. ` +
    (r.body.status === "completed" ? "Files published; device enforcement is not verified." :
     "Requires the separately running publication worker.");
  if (r.body.status === "completed" || r.body.status === "failed") publicationRequestKey = null;
}
$("publication-queue").addEventListener("click", async () => {
  // Retain this key across transient client retries, not one job per click.
  publicationRequestKey = publicationRequestKey || crypto.randomUUID();
  await showPublicationJob(await api("/api/publications/jobs", {method: "POST",
    headers: HDR, body: JSON.stringify({request_key: publicationRequestKey})}));
});
$("publication-check").addEventListener("click", async () => {
  if (publicationJobId) await showPublicationJob(await api(`/api/publications/jobs/${publicationJobId}`));
});

$("policy-preview-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = Number($("preview-policy").value);
  if (!id) { $("preview-result").textContent = "Choose a policy first"; return; }
  const body = {domain: $("preview-domain").value.trim()};
  if ($("preview-at").value.trim()) body.at = $("preview-at").value.trim();
  const r = await api(`/api/policies/${id}/preview`, {
    method: "POST", headers: HDR, body: JSON.stringify(body)});
  $("preview-result").textContent = r.status === 200 ?
    `${r.body.action}: ${r.body.rule}. ${r.body.reason}. ${r.body.scope}` :
    (r.body.error || "Preview unavailable");
});

$("p-template").addEventListener("change", async () => {
  const r = await api("/api/policy-templates");
  const template = r.status === 200 && r.body.templates[$("p-template").value];
  if (!template) { $("policy-error").textContent = "Template unavailable; form unchanged"; return; }
  $("p-default").value = template.rules.default_policy;
  $("p-blocklist").value = template.rules.blocklist.join(", ");
  $("p-catblock").value = template.rules.category_block.join(", ");
});

$("retention-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const r = await api("/api/privacy/retention", {method:"PUT", headers:HDR,
    body:JSON.stringify({days:Number($("retention-days").value)})});
  $("retention-result").textContent = r.status === 200 ?
    `Saved ${r.body.blocked_days} days; physically deleted ${r.body.deleted} records.` :
    (r.body.error || r.body.detail || "Save failed");
  if (r.status === 200) refreshFiltering();
});

// No persistent browser history cache. Refresh visible blocked activity so
// an open page stops showing rows removed by retention.
setInterval(() => {
  if (!$("filtering-panel").classList.contains("hidden")) refreshFiltering();
}, 60000);

async function refreshGroups(){
  const r=await api("/api/groups");
  const groups=r.status===200?r.body.groups:[];
  $("group-policy").innerHTML='<option value="">Use protected baseline</option>'+policyList.map(p=>`<option value="${p.id}">${esc(p.name)}</option>`).join("");
  $("group-select").innerHTML=groups.map(g=>`<option value="${g.id}">${esc(g.name)}</option>`).join("");
  $("group-device").innerHTML=deviceList.map(d=>`<option value="${d.id}">${esc(d.name)}</option>`).join("");
  $("groups-table").querySelector("tbody").innerHTML=groups.map(g=>`<tr><td>${esc(g.name)}</td><td>${esc((policyList.find(p=>p.id===g.policy_id)||{}).name||"protected baseline")}</td><td>${g.device_ids.map(id=>esc((deviceList.find(d=>d.id===id)||{}).name||id)).join(", ")}</td></tr>`).join("");
}
async function refreshExceptions(){
  const r=await api("/api/exceptions");
  const ex=r.status===200?r.body.exceptions:[];
  $("ex-device").innerHTML=deviceList.map(d=>`<option value="${d.id}">${esc(d.name)}</option>`).join("");
  const g=await api("/api/groups");
  const groups=g.status===200?g.body.groups:[];
  $("ex-group").innerHTML=groups.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join("");
  $("exceptions-table").querySelector("tbody").innerHTML=ex.map(x=>`<tr><td>${esc(x.kind)}</td><td>${esc(x.scope_type)} ${esc(String(x.device_id||x.group_id||""))}</td><td>${esc((x.domains||[]).join(", "))}</td><td>${esc(x.starts_at.slice(0,16))} - ${esc(x.expires_at.slice(0,16))}</td><td>${esc(x.reason)}</td><td>${x.revoked_at?"revoked":(x.active?"window open (applies once published)":"expired")}</td><td>${x.revoked_at?"":`<button data-revoke="${x.id}">Revoke</button>`}</td></tr>`).join("");
  $("exceptions-table").querySelectorAll("[data-revoke]").forEach(b=>b.addEventListener("click",async()=>{
    const rr=await api(`/api/exceptions/${b.dataset.revoke}`,{method:"DELETE",headers:HDR});
    $("exception-result").textContent=rr.status===200?"Revoked; republication queued automatically":(rr.body.error||"Failed");
    if(rr.status===200)await refreshExceptions();
  }));
}
$("exception-form").addEventListener("submit",async e=>{
  e.preventDefault();
  const body={kind:$("ex-kind").value,scope_type:$("ex-scope-type").value,
    reason:$("ex-reason").value,
    expires_at:new Date(Date.now()+Number($("ex-hours").value)*3600000).toISOString()};
  if(body.scope_type==="device")body.device_id=Number($("ex-device").value);else body.group_id=Number($("ex-group").value);
  if(body.kind==="allow_domains")body.domains=$("ex-domains").value.split(",").map(d=>d.trim()).filter(Boolean);
  const r=await api("/api/exceptions",{method:"POST",headers:HDR,body:JSON.stringify(body)});
  $("exception-result").textContent=r.status===200?"Exception saved; publish to distribute":(r.body.error||"Failed");
  if(r.status===200)await refreshExceptions();
});
$("group-form").addEventListener("submit",async e=>{
  e.preventDefault();
  const r=await api("/api/groups",{method:"POST",headers:HDR,body:JSON.stringify({name:$("group-name").value,policy_id:Number($("group-policy").value)||null})});
  $("group-result").textContent=r.status===200?"Group saved; publish to distribute":(r.body.error||"Failed");
  if(r.status===200)await refreshGroups();
});
async function groupMembership(remove){
  const gid=$("group-select").value,did=$("group-device").value;
  if(!gid||!did)return;
  const r=await api(`/api/groups/${gid}/devices/${did}`,{method:remove?"DELETE":"PUT",headers:HDR});
  $("group-result").textContent=r.status===200?"Membership saved; publish to distribute":(r.body.error||"Failed");
  if(r.status===200)await refreshGroups();
}
$("group-member-form").addEventListener("submit",async e=>{e.preventDefault();await groupMembership(false);});
$("group-remove-member").addEventListener("click",()=>groupMembership(true));

async function refreshApprovals() {
  const panel = $("approvals-panel");
  const r = await api("/api/mdm/sensitive-approvals");
  if (r.status === 403) { panel.classList.add("hidden"); return; }
  const rows = r.body.approvals || [];
  document.querySelector("#approvals-table tbody").innerHTML = rows.map(a =>
    `<tr><td>${a.id}</td><td>${esc(a.operation)}</td><td>${esc(a.device || "-")}</td>` +
    `<td>${esc(a.requested_by_email || "user " + a.requested_by_user_id)}</td>` +
    `<td>${esc(a.status)}${a.decision_detail ? `<br><small>${esc(a.decision_detail)}</small>` : ""}</td>` +
    `<td>${esc(a.reason || "")}</td><td>${esc(a.expires_at.slice(0, 16).replace("T", " "))}</td>` +
    `<td>${a.status === "pending" ? `<button class="link" data-decide="${a.id}" data-op="${esc(a.operation)}" data-device="${esc(a.device || "-")}" data-by="${esc(a.requested_by_email || "user " + a.requested_by_user_id)}">decide</button>` : ""}</td></tr>`).join("");
}

document.querySelector("#approvals-table tbody").addEventListener("click", (e) => {
  const b = e.target.closest("[data-decide]");
  if (!b) return;
  $("ap-id").textContent = b.dataset.decide + " (" + b.dataset.op + " on " + b.dataset.device + ", requested by " + b.dataset.by + ")";
  $("ap-confirm").value = "";
  $("ap-totp").value = "";
  $("approval-act").classList.remove("hidden");
  $("approval-form").dataset.approvalId = b.dataset.decide;
});

$("approval-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("approval-error"), ok = $("approval-ok");
  err.textContent = ""; ok.textContent = "";
  const id = e.target.dataset.approvalId;
  const decision = e.submitter ? e.submitter.value : "approve";
  const r = await api(`/api/mdm/sensitive-approvals/${id}/${decision}`, {
    method: "POST", headers: HDR,
    body: JSON.stringify({totp_code: $("ap-totp").value,
                          confirm: $("ap-confirm").value,
                          reason: $("ap-reason").value}),
  });
  if (r.status === 200) {
    if (decision === "approve") {
      const d = (r.body && r.body.decision_detail) || "recorded";
      ok.textContent = "Approved: " + d +
        (d.indexOf("queued") >= 0 ? " Queue insertion is not device execution - the device has not necessarily completed the operation." : "");
    } else {
      ok.textContent = "Rejected.";
    }
    $("approval-act").classList.add("hidden");
    refreshApprovals();
  } else {
    err.textContent = (r.body && r.body.error) || "Decision failed.";
  }
});

async function refreshStaff() {
  const panel = $("staff-panel");
  const r = await api("/api/staff");
  if (r.status === 403) { panel.classList.add("hidden"); return; }
  const rows = r.body.staff || [];
  document.querySelector("#staff-table tbody").innerHTML = rows.map(u =>
    `<tr><td>${u.id}</td><td>${esc(u.email)}</td><td>${esc(u.staff_role || "")}</td>` +
    `<td>${u.mfa_enrolled ? "enrolled" : "NOT enrolled"}</td></tr>`).join("");
}

$("staff-role-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("staff-error"), ok = $("staff-ok");
  err.textContent = ""; ok.textContent = "";
  const r = await api(`/api/staff/${$("sf-user-id").value}/role`, {
    method: "POST", headers: HDR,
    body: JSON.stringify({staff_role: $("sf-role").value || null}),
  });
  if (r.status === 200) {
    ok.textContent = "Staff role updated for " + r.body.email + ".";
    refreshStaff();
  } else {
    err.textContent = (r.body && r.body.error) || "Role change failed.";
  }
});

$("tenant-onboard-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = $("to-error");
  err.textContent = "";
  $("to-result").classList.add("hidden");
  const r = await api("/api/staff/tenants", {
    method: "POST", headers: HDR,
    body: JSON.stringify({tenant_name: $("to-name").value,
                          owner_email: $("to-email").value}),
  });
  if (r.status !== 200) {
    err.textContent = r.body.error || "Could not create the customer.";
    return;
  }
  $("to-tenant").textContent = r.body.tenant_id;
  $("to-expires").textContent = r.body.expires_at;
  $("to-token").textContent = r.body.invite_token;
  $("to-result").classList.remove("hidden");
  $("to-name").value = "";
  $("to-email").value = "";
});

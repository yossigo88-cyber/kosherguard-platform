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
  ["login-panel"].forEach(id => $(id).classList.add("hidden"));
  ["policies-panel", "devices-panel", "mdm-panel", "categories-panel", "signout-panel"].forEach(id => $(id).classList.remove("hidden"));
  const me = await api("/api/auth/me");
  $("who").textContent = me.body.email || "";
  await refresh();
}

async function refresh() {
  refreshCategories();
  const policies = await api("/api/policies");
  policyList = policies.body.policies || [];
  document.querySelector("#policies tbody").innerHTML = policyList.map(p =>
    `<tr><td>${esc(p.name)}</td><td>${esc(p.default_policy)}</td><td>${esc(p.blocklist.join(", "))}</td>` +
    `<td>${p.versions}</td><td><button class="link" data-select="${p.id}">make default</button></td></tr>`).join("");
  const devices = await api("/api/devices");
  document.querySelector("#devices tbody").innerHTML = (devices.body.devices || []).map(d =>
    `<tr><td>${esc(d.name)}</td><td>${esc(d.state)}</td><td><select data-device="${d.id}">` +
    policyList.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join("") +
    `</select><button class="link" data-assign="${d.id}">assign</button></td></tr>`).join("");
  deviceList = devices.body.devices || [];
  await refreshMdm();
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
  const body = await r.json();
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
  if (r.ok) {
    ok.textContent = "Rule saved.";
    $("cat-domain").value = "";
    refreshCategories();
  } else {
    const body = await r.json().catch(() => ({}));
    err.textContent = body.detail || body.message || `Error ${r.status}`;
  }
});

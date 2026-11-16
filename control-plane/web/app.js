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
  ["policies-panel", "devices-panel", "signout-panel"].forEach(id => $(id).classList.remove("hidden"));
  const me = await api("/api/auth/me");
  $("who").textContent = me.body.email || "";
  await refresh();
}

async function refresh() {
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

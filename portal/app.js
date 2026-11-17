function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

const HDR = {"X-KosherGuard-Request": "1", "Content-Type": "application/json"};
let ME = null;
let DEVICES = [];
let GROUPS = [];

async function api(path, opts) {
  const r = await fetch(path, opts);
  return {status: r.status, body: await r.json().catch(() => ({}))};
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const totp = document.getElementById("totp").value;
  const payload = {email: email, password: password};
  if (totp) payload.totp_code = totp;
  const r = await api("/api/auth/login", {method: "POST", headers: HDR, body: JSON.stringify(payload)});
  if (r.status !== 200) {
    document.getElementById("login-error").textContent = r.body.error || "Sign-in failed";
    return;
  }
  showApp();
});

const CONNECTIVITY_LABELS = {
  recently_reporting: "Reported within the hour",
  stale: "Last report 1-24h ago",
  no_report_over_24h: "No report for over 24h",
  never_reported: "Never reported"
};

function enrollmentLabel(enr) {
  if (!enr) return "Not enrolled";
  let s = esc(enr.state);
  if (enr.supervision_verified) s += ", supervised (verified)";
  else if (enr.supervision_requested) s += ", supervision requested";
  return s;
}

const REPORTED_LABELS = {
  all_served_reported_applied: "Device reported all served policies applied (receipt only)",
  served_not_fully_reported: "Not all served policies reported applied",
  no_report_received: "No device report received yet",
  no_declarations_served: "No policy declarations served yet",
  comparison_unavailable: "Comparison unavailable (server could not evaluate)",
  no_enrollment: "Not enrolled"
};

function renderDevices() {
  document.querySelector("#devices tbody").innerHTML = DEVICES.map(d => {
    const chain = d.push_chain || {};
    const latest = chain.latest_command
      ? `${esc(chain.latest_command.command)}: ${esc(chain.latest_command.status)} (command ledger)`
      : "none";
    const apns = chain.apns === "unavailable"
      ? `<br><span class="note">APNs push: unavailable (not observed by this server)</span>`
      : (chain.apns ? `<br><span class="note">APNs push: ${esc(chain.apns)}</span>` : "");
    return `<tr><td>${esc(d.name)}</td><td>${esc(d.state)}</td>` +
      `<td>${enrollmentLabel(d.enrollment)}</td>` +
      `<td>${esc(CONNECTIVITY_LABELS[d.connectivity] || d.connectivity)}</td>` +
      `<td>${esc(REPORTED_LABELS[d.reported_vs_published] || d.reported_vs_published)}</td>` +
      `<td>${d.last_device_receipt ? esc(new Date(d.last_device_receipt).toLocaleString()) : "none yet"}</td>` +
      `<td>${latest}${chain.pending ? ` (${chain.pending} pending)` : ""}${apns}</td></tr>`;
  }).join("");
}

function renderSchedules(schedules) {
  if (!schedules || !schedules.length) return "";
  const DAYNAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const fmt = t => (typeof t === "number")
    ? String(Math.floor(t / 60)).padStart(2, "0") + ":" + String(t % 60).padStart(2, "0")
    : String(t);
  return schedules.map(s => {
    const days = (s.days || []).map(d => DAYNAMES[d] !== undefined ? DAYNAMES[d] : d).join(", ");
    const what = (s.block_categories && s.block_categories.length)
      ? "blocks categories: " + esc(s.block_categories.join(", "))
      : "blocks domains: " + esc((s.block_domains || []).join(", "));
    return `<div class="sched">${esc(s.name)}: ${esc(days)} ${esc(fmt(s.start))}-${esc(fmt(s.end))} ` +
      `(${esc(s.timezone || "policy timezone")}) ${what}${s.enabled === false ? " [disabled]" : ""}</div>`;
  }).join("");
}

async function loadPolicies() {
  const policies = await api("/api/policies");
  document.getElementById("policies").innerHTML = (policies.body.policies || []).map(p =>
    `<h3>${esc(p.name)}${p.protected_baseline ? ' <span class="badge">protected baseline</span>' : ""}</h3>` +
    `<div>Default action: ${esc(p.default_policy)} - ${p.enabled ? "enabled" : "disabled"}</div>` +
    (p.schedules && p.schedules.length
      ? `<div><strong>Schedules</strong>${renderSchedules(p.schedules)}</div>`
      : `<div class="note">No filtering schedules.</div>`)
  ).join("") || "<p>No policies yet.</p>";
}

function canDecideExceptions() {
  if (!ME) return false;
  return ME.role === "owner" ||
    (ME.role === "guardian" && (ME.delegated_settings || []).includes("exceptions"));
}

async function loadExceptions() {
  const r = await api("/api/exception-requests");
  const rows = r.body.requests || [];
  const decide = canDecideExceptions();
  document.querySelector("#exceptions tbody").innerHTML = rows.map(q => {
    const what = `${esc(q.kind)} on ${esc(q.scope_type)} ${q.device_id || q.group_id}` +
      (q.domains && q.domains.length ? ` (${esc(q.domains.join(", "))})` : "");
    const status = esc(q.status) + (q.decided_by_email ? ` by ${esc(q.decided_by_email)}` : "");
    const actions = (decide && q.status === "pending")
      ? `<button class="small" data-approve="${q.id}">Approve</button> ` +
        `<button class="small reject" data-reject="${q.id}">Reject</button>` : "";
    return `<tr><td>${what}</td><td>${esc(q.reason)}</td><td>${q.duration_minutes} min</td>` +
      `<td>${esc(q.requested_by_email || "")}</td><td>${status}</td><td>${actions}</td></tr>`;
  }).join("");
  document.querySelectorAll("[data-approve]").forEach(b => b.addEventListener("click", async () => {
    const rr = await api(`/api/exception-requests/${b.dataset.approve}/approve`,
      {method: "POST", headers: HDR, body: "{}"});
    if (rr.status !== 200) alert(rr.body.error || "Could not approve");
    loadExceptions();
  }));
  document.querySelectorAll("[data-reject]").forEach(b => b.addEventListener("click", async () => {
    const rr = await api(`/api/exception-requests/${b.dataset.reject}/reject`,
      {method: "POST", headers: HDR, body: "{}"});
    if (rr.status !== 200) alert(rr.body.error || "Could not reject");
    loadExceptions();
  }));
}

async function loadSupport() {
  const r = await api("/api/support/requests");
  document.querySelector("#support-requests tbody").innerHTML =
    (r.body.requests || []).map(q => `<tr><td>${esc(q.subject)}</td><td>${esc(q.status)}</td></tr>`).join("");
}

async function showApp() {
  document.getElementById("login-panel").classList.add("hidden");
  ["devices-panel", "policies-panel", "exceptions-panel", "support-panel", "signout-panel"]
    .forEach(id => document.getElementById(id).classList.remove("hidden"));
  const me = await api("/api/auth/me");
  ME = me.body;
  document.getElementById("who").textContent = ME.email || "";
  const roleLabels = {owner: "family owner", guardian: "guardian", viewer: "read-only viewer"};
  const delegated = (ME.delegated_settings || []);
  document.getElementById("permitted").textContent =
    `You are signed in as ${roleLabels[ME.role] || ME.role}. ` +
    (ME.role === "owner" ? "All policy settings are available to you."
      : delegated.length
        ? `Settings the owner delegated to you: ${delegated.join(", ")}.`
        : "No policy settings have been delegated to you; you can view everything and request exceptions or changes.");
  const devices = await api("/api/devices");
  DEVICES = devices.body.devices || [];
  renderDevices();
  document.getElementById("ex-device").innerHTML =
    DEVICES.map(d => `<option value="${d.id}">${esc(d.name)}</option>`).join("");
  const groups = await api("/api/groups");
  GROUPS = groups.body.groups || [];
  document.getElementById("ex-group").innerHTML =
    GROUPS.map(g => `<option value="${g.id}">${esc(g.name)}</option>`).join("");
  loadPolicies();
  loadExceptions();
  loadSupport();
}

document.getElementById("ex-scope").addEventListener("change", (e) => {
  const device = e.target.value === "device";
  document.getElementById("ex-device-row").classList.toggle("hidden", !device);
  document.getElementById("ex-group-row").classList.toggle("hidden", device);
});
document.getElementById("ex-kind").addEventListener("change", (e) => {
  document.getElementById("ex-domains-row").classList.toggle("hidden",
    e.target.value !== "allow_domains");
});

document.getElementById("exception-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const scope = document.getElementById("ex-scope").value;
  const kind = document.getElementById("ex-kind").value;
  const payload = {
    kind: kind,
    scope_type: scope,
    device_id: scope === "device" ? Number(document.getElementById("ex-device").value) : null,
    group_id: scope === "group" ? Number(document.getElementById("ex-group").value) : null,
    domains: kind === "allow_domains"
      ? document.getElementById("ex-domains").value.split("\n").map(s => s.trim()).filter(Boolean)
      : [],
    reason: document.getElementById("ex-reason").value,
    duration_minutes: Number(document.getElementById("ex-duration").value)
  };
  const r = await api("/api/exception-requests", {method: "POST", headers: HDR, body: JSON.stringify(payload)});
  const msg = document.getElementById("ex-error");
  msg.style.color = r.status === 200 ? "#2a6b2a" : "";
  msg.textContent =
    r.status === 200 ? "Request submitted for approval." : (r.body.error || "Could not submit the request.");
  if (r.status === 200) {
    document.getElementById("ex-reason").value = "";
    loadExceptions();
  }
});

document.getElementById("support-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const r = await api("/api/support/requests", {method: "POST", headers: HDR,
    body: JSON.stringify({kind: document.getElementById("support-kind").value,
      subject: document.getElementById("support-subject").value,
      body: document.getElementById("support-body").value})});
  document.getElementById("support-msg").textContent =
    r.status === 200 ? "Request sent. Staff will review it." : (r.body.error || "Could not send the request.");
  if (r.status === 200) {
    document.getElementById("support-subject").value = "";
    document.getElementById("support-body").value = "";
    loadSupport();
  }
});

document.getElementById("signout").addEventListener("click", async () => {
  await api("/api/auth/logout", {method: "POST", headers: HDR});
  location.reload();
});

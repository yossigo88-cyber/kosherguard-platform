function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

const HDR = {"X-KosherGuard-Request": "1", "Content-Type": "application/json"};

async function api(path, opts) {
  const r = await fetch(path, opts);
  return {status: r.status, body: await r.json().catch(() => ({}))};
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {email: email.value, password: password.value};
  if (totp.value) payload.totp_code = totp.value;
  const r = await api("/api/auth/login", {method: "POST", headers: HDR, body: JSON.stringify(payload)});
  if (r.status !== 200) {
    document.getElementById("login-error").textContent = r.body.error || "Sign-in failed";
    return;
  }
  showApp();
});

async function showApp() {
  document.getElementById("login-panel").classList.add("hidden");
  document.getElementById("devices-panel").classList.remove("hidden");
  document.getElementById("policies-panel").classList.remove("hidden");
  const me = await api("/api/auth/me");
  document.getElementById("who").textContent = me.body.email || "";
  const devices = await api("/api/devices");
  document.querySelector("#devices tbody").innerHTML =
    (devices.body.devices || []).map(d => `<tr><td>${esc(d.name)}</td><td>${esc(d.state)}</td></tr>`).join("");
  const policies = await api("/api/policies");
  document.querySelector("#policies tbody").innerHTML =
    (policies.body.policies || []).map(p => `<tr><td>${esc(p.name)}</td><td>${esc(p.default_policy)}</td><td>${p.enabled ? "yes" : "no"}</td></tr>`).join("");
}

document.getElementById("signout").addEventListener("click", async () => {
  await api("/api/auth/logout", {method: "POST", headers: HDR});
  location.reload();
});

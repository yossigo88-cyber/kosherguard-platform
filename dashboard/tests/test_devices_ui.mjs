// Stage 11B UI tests for the devices registry interface.
//
// Runs the REAL dashboard/static/app.js in a vm context with a minimal
// DOM/fetch shim (no external dependencies) and asserts on rendered HTML,
// outgoing API payloads, escaping, confirmation flows, and the honest
// assigned/published/enforced display. Run: node --test tests/test_devices_ui.mjs
// from the dashboard/ directory.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import vm from "node:vm";

const APP_JS = join(dirname(fileURLToPath(import.meta.url)), "..", "static", "app.js");

// ---------- minimal DOM/fetch shim ----------

class StubClassList {
  constructor() { this._set = new Set(); }
  add(c) { this._set.add(c); }
  remove(c) { this._set.delete(c); }
  toggle(c, force) {
    const on = force === undefined ? !this._set.has(c) : force;
    if (on) this._set.add(c); else this._set.delete(c);
  }
  contains(c) { return this._set.has(c); }
}

class StubElement {
  constructor(doc, key) {
    this._doc = doc;
    this._key = key;
    this.innerHTML = "";
    this.textContent = "";
    this.value = "";
    this.disabled = false;
    this.classList = new StubClassList();
    this.listeners = {};
    this.inserted = [];
  }
  addEventListener(type, fn) {
    (this.listeners[type] = this.listeners[type] || []).push(fn);
  }
  click() { (this.listeners.click || []).forEach((f) => f({ target: this })); }
  querySelector(sel) { return this._doc.element(this._key + " " + sel); }
  querySelectorAll(sel) { return this._doc.querySelectorAll(sel); }
  insertAdjacentHTML(pos, html) { this.inserted.push(html); }
  closest() { return null; }
  focus() {}
  remove() {}
  getAttribute(name) { return this._attrs ? this._attrs[name] : null; }
  setAttribute(name, v) { (this._attrs = this._attrs || {})[name] = v; }
}

class StubDocument {
  constructor() { this._els = new Map(); this._qs = new Map(); }
  element(key) {
    if (!this._els.has(key)) this._els.set(key, new StubElement(this, key));
    return this._els.get(key);
  }
  getElementById(id) { return this.element("#" + id); }
  querySelectorAll(sel) { return this._qs.get(sel) || []; }
  setQuerySelectorAll(sel, els) { this._qs.set(sel, els); }
  createElement() { return new StubElement(this, "created"); }
}

function makeResponse(status, obj) {
  return { status, ok: status >= 200 && status < 300, json: async () => obj };
}

// Load app.js fresh with a fetch responder: (url, options) => {status, body}.
function loadApp(responder) {
  const document = new StubDocument();
  const calls = [];
  const alerts = [];
  const sandbox = {
    document,
    window: { addEventListener() {}, location: { hash: "" } },
    fetch: (url, options) => {
      const parsed = options && options.body ? JSON.parse(options.body) : undefined;
      calls.push({ url, method: options ? options.method : "GET", body: parsed });
      const r = responder(url, options ? options.method : "GET", parsed);
      return Promise.resolve(makeResponse(r.status, r.body));
    },
    alert: (msg) => alerts.push(msg),
    setTimeout: (fn) => { fn(); return 0; },  // run debounced callbacks immediately
    clearTimeout: () => {},
    console,
    Promise,
    Number,
    Array,
    Object,
    String,
    JSON,
    RegExp,
    encodeURIComponent,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(readFileSync(APP_JS, "utf8"), sandbox, { filename: "app.js" });
  return { ctx: sandbox, document, calls, alerts };
}

function lastCall(calls, method, urlPrefix) {
  return [...calls].reverse().find((c) => c.method === method && c.url.startsWith(urlPrefix));
}

// ---------- fixtures ----------

const DEVICES = [
  {
    id: 1, name: "Living Room iPad", description: "kids tablet", device_type: "ipad",
    os: "iOS 18.1", state: "active", entry_kind: "device", management_status: "unmanaged",
    created_at: "2026-11-15T10:00:00Z", registered_at: "2026-11-15T10:00:00Z",
    updated_at: "2026-11-15T10:00:00Z", last_seen_at: null, notes: "",
    live_associations: 2, live_associations_by_kind: { ipv4: 1, ipv6_prefix: 1 },
    active_assignment: { id: 3, device_id: 1, policy_id: 5, policy_name: "Strict Kids",
      policy_version_at_assignment: 4, policy_current_version: 6,
      assigned_by: "admin", assigned_at: "2026-11-15T10:05:00Z", active: true },
  },
  {
    id: 2, name: "Home Wi-Fi", description: "whole household", device_type: "network",
    os: "", state: "disabled", entry_kind: "network_or_group", management_status: "unmanaged",
    created_at: "2026-11-15T11:00:00Z", registered_at: "2026-11-15T11:00:00Z",
    updated_at: "2026-11-15T11:00:00Z", last_seen_at: null, notes: "",
    live_associations: 0, live_associations_by_kind: {}, active_assignment: null,
  },
];

const LIST_NOTE = "Registry entries are administrative records (management_status unmanaged); " +
  "network bindings are routing hints, not authenticated device identity.";

const DEVICE_DETAIL = Object.assign({}, DEVICES[0], {
  associations: [
    { id: 11, kind: "ipv4", identity_class: "network_binding", value: "192.168.1.50",
      created_at: "2026-11-15T10:01:00Z", retired_at: null },
    { id: 12, kind: "ipv6_prefix", identity_class: "network_binding", value: "2001:db8::/64",
      created_at: "2026-11-15T10:02:00Z", retired_at: "2026-11-15T12:00:00Z" },
  ],
  assignment_history: [
    { id: 3, device_id: 1, policy_id: 5, policy_name: "Strict Kids",
      policy_version_at_assignment: 4, policy_current_version: 6,
      assigned_by: "admin", assigned_at: "2026-11-15T10:05:00Z", active: true },
    { id: 1, device_id: 1, policy_id: 2, policy_name: "Old Policy",
      policy_version_at_assignment: 1, policy_current_version: 2,
      assigned_by: "admin", assigned_at: "2026-11-15T09:00:00Z", active: false },
  ],
});

const EFFECTIVE_NO_ENGINE = {
  device_id: 1, device_name: "Living Room iPad", device_state: "active", entry_kind: "device",
  assigned: DEVICE_DETAIL.active_assignment, assigned_applies_to_live_queries: true,
  default_policy: { policy_id: 1, policy_name: "Default Family", current_version: 9 },
  published: null,
  published_note: "device assignments are not part of published configuration generations " +
    "until Stage 11D; a saved assignment changes nothing an engine does",
  enforced: "unavailable",
  enforced_note: "enforcement is only ever reported from a connected engine's own status output",
};

const POLICIES = [
  { id: 1, name: "Default Family" }, { id: 5, name: "Strict Kids" },
];

function detailResponder(overrides) {
  const o = overrides || {};
  return (url, method) => {
    if (url === "/api/me") return { status: 401, body: { error: "not signed in" } };
    if (url.startsWith("/api/devices/1/effective-policy")) {
      return { status: 200, body: o.effective || EFFECTIVE_NO_ENGINE };
    }
    if (url.startsWith("/api/devices/1/audit")) {
      return { status: 200, body: { entries: o.audit || [] } };
    }
    if (url === "/api/devices/1" && method === "GET") {
      return { status: 200, body: o.device || DEVICE_DETAIL };
    }
    if (url.startsWith("/api/policies")) return { status: 200, body: { policies: POLICIES } };
    if (url.startsWith("/api/devices")) return { status: 200, body: { devices: DEVICES, note: LIST_NOTE } };
    return { status: 404, body: { error: "not found: " + url } };
  };
}

// ---------- router ----------

test("router keeps existing routes and adds /devices/<id>", () => {
  const { ctx } = loadApp(() => ({ status: 401, body: {} }));
  const routeOf = (hash) => {
    ctx.window.location.hash = hash;
    const r = ctx.currentRoute();
    return [r.name, r.param];
  };
  // cross-context objects fail deepStrictEqual prototype checks; compare fields
  assert.deepEqual(routeOf("#/policies"), ["policies", null]);
  assert.deepEqual(routeOf("#/devices"), ["devices", null]);
  assert.deepEqual(routeOf("#/devices/42"), ["devices", "42"]);
  assert.deepEqual(routeOf("#/nonsense"), ["overview", null]);
  assert.deepEqual(routeOf(""), ["overview", null]);
});

// ---------- list page ----------

test("devices list renders entries, badges, and honest note", async () => {
  const { ctx, document } = loadApp(detailResponder());
  await ctx.renderDevices();
  const html = document.getElementById("content").innerHTML;
  assert.match(html, /Living Room iPad/);
  assert.match(html, /Home Wi-Fi/);
  assert.match(html, /Network \/ group entry/);
  assert.match(html, />Active</);
  assert.match(html, /Disabled/);
  assert.match(html, /Strict Kids/);
  assert.match(html, /Default policy/);
  assert.match(html, /2 bindings/);
  assert.match(html, /unmanaged/);
  assert.match(html, /Not tracked/);
  assert.match(html, /routing hints, not authenticated device identity/);
  assert.match(html, /Register Device/);
});

test("list search and state filter reach the API as query params", async () => {
  const { ctx, calls, document } = loadApp(detailResponder());
  await ctx.renderDevices({ search: "ipad", state: "active" });
  const first = lastCall(calls, "GET", "/api/devices?");
  assert.match(first.url, /search=ipad/);
  assert.match(first.url, /state=active/);
  // Changing the filter control reloads through the API.
  document.getElementById("dv-state-filter").value = "disabled";
  (document.getElementById("dv-state-filter").listeners.change || []).forEach((f) => f());
  await Promise.resolve();
  const second = lastCall(calls, "GET", "/api/devices?");
  assert.match(second.url, /state=disabled/);
});

test("list empty state explains the next step", async () => {
  const { ctx, document } = loadApp((url) => {
    if (url === "/api/me") return { status: 401, body: {} };
    if (url.startsWith("/api/devices")) return { status: 200, body: { devices: [], note: LIST_NOTE } };
    return { status: 404, body: {} };
  });
  await ctx.renderDevices();
  assert.match(document.getElementById("dv-empty").textContent, /No registry entries yet/);
  assert.match(document.getElementById("dv-empty").textContent, /Register Device/);
  assert.ok(!document.getElementById("dv-empty").classList.contains("hidden"));
});

// ---------- registration ----------

test("registration sends the exact API payload including bindings and policy", async () => {
  const { ctx, document, calls } = loadApp(detailResponder());
  let saved = false;
  await new Promise((resolve) => {
    ctx.openRegisterDialog(() => { saved = true; resolve(); });
    setImmediate(resolve);
  });
  document.getElementById("rf-name").value = "Yossi iPhone";
  document.getElementById("rf-desc").value = "main phone";
  document.getElementById("rf-type").value = "iphone";
  document.getElementById("rf-os").value = "iOS 26";
  document.getElementById("rf-notes").value = "note";
  document.getElementById("rf-policy").value = "5";
  const row = {
    querySelector: (sel) =>
      sel === ".rf-binding-kind" ? { value: "ipv4" } : { value: "192.168.1.77" },
  };
  document.setQuerySelectorAll(".rf-binding-row", [row]);
  document.getElementById("modal #rf-save").click();
  await new Promise((r) => setImmediate(r));
  const post = lastCall(calls, "POST", "/api/devices");
  assert.ok(post, "expected a POST /api/devices");
  assert.equal(post.url, "/api/devices");
  assert.deepEqual(post.body, {
    name: "Yossi iPhone", description: "main phone", device_type: "iphone",
    os: "iOS 26", notes: "note",
    bindings: [{ kind: "ipv4", value: "192.168.1.77" }],
    policy_id: 5,
  });
  assert.equal(saved, true);
});

test("registration form carries the mandated binding wording and no token option", async () => {
  const { ctx } = loadApp(detailResponder());
  const html = ctx.registerFormHtml(POLICIES);
  assert.match(html, /Network\/group binding — routing hint only, not verified device identity\./);
  assert.match(html, /may represent many devices/);
  assert.match(html, /No assignment - the default policy applies/);
  assert.doesNotMatch(html, /token_hash/);
  assert.deepEqual(
    [...html.matchAll(/<option value="([^"]*)">/g)].map((m) => m[1]).filter((v) => v === "token_hash"),
    []);
});

test("registration API errors are shown and no success is claimed", async () => {
  const { ctx, document, calls } = loadApp((url, method) => {
    if (url === "/api/me") return { status: 401, body: {} };
    if (url.startsWith("/api/policies")) return { status: 200, body: { policies: POLICIES } };
    if (url === "/api/devices" && method === "POST") {
      return { status: 409, body: { error: "a registry entry named 'Yossi iPhone' already exists" } };
    }
    return { status: 404, body: {} };
  });
  await new Promise((resolve) => { ctx.openRegisterDialog(() => resolve()); setImmediate(resolve); });
  document.getElementById("rf-name").value = "Yossi iPhone";
  document.getElementById("rf-policy").value = "";
  document.setQuerySelectorAll(".rf-binding-row", []);
  document.getElementById("modal #rf-save").click();
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  const errNode = document.getElementById("modal .form-error");
  assert.match(errNode.textContent, /already exists/);
  assert.equal(document.getElementById("modal #rf-save").disabled, false);
  assert.equal(lastCall(calls, "GET", "/api/devices?"), undefined,
    "list must not reload as if registration succeeded");
});

// ---------- details page ----------

test("device details render all sections", async () => {
  const { ctx, document } = loadApp(detailResponder({
    audit: [{ id: 9, admin: "admin", action: "device.create",
      detail: "device 'Living Room iPad' (id 1): registered device", created_at: "2026-11-15T10:00:00Z" }],
  }));
  await ctx.renderDeviceDetail("1");
  const html = document.getElementById("content").innerHTML;
  assert.match(html, /Living Room iPad/);
  assert.match(html, /192\.168\.1\.50/);
  assert.match(html, /2001:db8::\/64/);
  assert.match(html, /network binding/);
  assert.match(html, /Retired/);
  assert.match(html, /Strict Kids/);
  assert.match(html, /assigned at v4/);
  assert.match(html, /Old Policy/);
  assert.match(html, /Superseded/);
  assert.match(html, /Effective policy status/);
  assert.match(html, /Device state/);
  assert.match(html, /device\.create/);
  assert.match(html, /Network\/group binding — routing hint only, not verified device identity\./);
  assert.match(html, /not an enrolled, connected, or remotely managed device/);
});

test("editing sends only the editable fields via PUT", async () => {
  const { ctx, document, calls } = loadApp(detailResponder());
  let saved = false;
  ctx.openEditDialog(DEVICE_DETAIL, () => { saved = true; });
  document.getElementById("ef-name").value = "Renamed iPad";
  document.getElementById("ef-desc").value = "new desc";
  document.getElementById("ef-type").value = "ipad";
  document.getElementById("ef-os").value = "iOS 26";
  document.getElementById("ef-notes").value = "n";
  document.getElementById("modal #ef-save").click();
  await new Promise((r) => setImmediate(r));
  const put = lastCall(calls, "PUT", "/api/devices/1");
  assert.ok(put, "expected PUT /api/devices/1");
  assert.deepEqual(put.body, {
    name: "Renamed iPad", description: "new desc", device_type: "ipad", os: "iOS 26", notes: "n",
  });
  assert.ok(!("management_status" in put.body) && !("state" in put.body));
  assert.equal(saved, true);
});

test("adding a binding posts kind and value only", async () => {
  const { ctx, document, calls } = loadApp((url, method, body) => {
    if (url === "/api/devices/1/associations" && method === "POST") return { status: 201, body: {} };
    return detailResponder()(url, method, body);
  });
  await ctx.renderDeviceDetail("1");
  document.getElementById("dv-binding-kind").value = "ipv6_prefix";
  document.getElementById("dv-binding-value").value = "2001:db8:1::/64";
  document.getElementById("dv-binding-add").click();
  await new Promise((r) => setImmediate(r));
  const post = lastCall(calls, "POST", "/api/devices/1/associations");
  assert.deepEqual(post.body, { kind: "ipv6_prefix", value: "2001:db8:1::/64" });
  assert.ok(!("identity_class" in post.body), "client never sends identity_class");
});

test("binding add errors surface server validation verbatim", async () => {
  const { ctx, document } = loadApp((url, method, body) => {
    if (url === "/api/devices/1/associations" && method === "POST") {
      return { status: 400, body: { error: "binding.value: invalid IPv4 address '999.1.1.1'" } };
    }
    return detailResponder()(url, method, body);
  });
  await ctx.renderDeviceDetail("1");
  document.getElementById("dv-binding-value").value = "999.1.1.1";
  document.getElementById("dv-binding-add").click();
  await new Promise((r) => setImmediate(r));
  const errBox = document.getElementById("dv-binding-error");
  assert.match(errBox.textContent, /invalid IPv4 address/);
  assert.ok(!errBox.classList.contains("hidden"));
});

test("retiring a binding requires confirmation before the DELETE", async () => {
  const { ctx, document, calls } = loadApp((url, method, body) => {
    if (method === "DELETE") return { status: 200, body: {} };
    return detailResponder()(url, method, body);
  });
  await ctx.renderDeviceDetail("1");
  const fakeBtn = {
    getAttribute: () => "11",
    closest(sel) { return sel === "button[data-retire]" ? this : null; },
  };
  const rows = document.getElementById("dv-binding-rows");
  (rows.listeners.click || []).forEach((f) => f({ target: fakeBtn }));
  // Confirmation dialog is up; nothing deleted yet.
  assert.match(document.getElementById("modal").innerHTML, /Retire binding/);
  assert.equal(lastCall(calls, "DELETE", "/api/devices/1/associations"), undefined);
  document.getElementById("modal #modal-confirm").click();
  await new Promise((r) => setImmediate(r));
  const del = lastCall(calls, "DELETE", "/api/devices/1/associations");
  assert.ok(del, "DELETE sent only after confirmation");
  assert.match(del.url, /\/associations\/11$/);
});

test("policy assignment posts policy_id and shows the tighten-only verdict verbatim", async () => {
  const verdict = "assignment rejected: policy 'Lenient' is not proven at least as " +
    "restrictive as the default policy 'Default Family' (tighten-only rule)";
  const { ctx, document, calls } = loadApp((url, method, body) => {
    if (url === "/api/devices/1/assign-policy" && method === "POST") {
      return { status: 409, body: { error: verdict } };
    }
    return detailResponder()(url, method, body);
  });
  await ctx.renderDeviceDetail("1");
  document.getElementById("dv-policy-select").value = "2";
  document.getElementById("dv-assign").click();
  await new Promise((r) => setImmediate(r));
  const post = lastCall(calls, "POST", "/api/devices/1/assign-policy");
  assert.deepEqual(post.body, { policy_id: 2 });
  const errBox = document.getElementById("dv-assign-error");
  assert.equal(errBox.textContent, verdict);
  assert.ok(!errBox.classList.contains("hidden"));
});

test("unassign sends policy_id null", async () => {
  const { ctx, document, calls } = loadApp((url, method, body) => {
    if (url === "/api/devices/1/assign-policy" && method === "POST") {
      return { status: 200, body: { unassigned: true, device_id: 1 } };
    }
    return detailResponder()(url, method, body);
  });
  await ctx.renderDeviceDetail("1");
  document.getElementById("dv-unassign").click();
  document.getElementById("modal #modal-confirm").click();
  await new Promise((r) => setImmediate(r));
  const post = lastCall(calls, "POST", "/api/devices/1/assign-policy");
  assert.deepEqual(post.body, { policy_id: null });
});

// ---------- effective policy honesty ----------

test("assigned, published, and enforced are three distinct cells", () => {
  const { ctx } = loadApp(() => ({ status: 401, body: {} }));
  const html = ctx.effectivePolicyCardHtml(EFFECTIVE_NO_ENGINE, DEVICE_DETAIL);
  assert.match(html, /1\. Assigned/);
  assert.match(html, /2\. Published/);
  assert.match(html, /3\. Enforced/);
  assert.match(html, /Strict Kids/);
  // With no engine connected, enforcement is unavailable - never green.
  assert.match(html, /Enforcement unavailable — no connected filtering engine has confirmed this policy\./);
  const enforcedCell = html.split("3. Enforced")[1];
  assert.doesNotMatch(enforcedCell, /badge-ok/);
  // Publication is honestly unavailable in Stage 11A, with the server's reason.
  assert.match(html, /not part of published configuration generations until Stage 11D/);
});

test("engine-confirmed enforcement is the only green path", () => {
  const { ctx } = loadApp(() => ({ status: 401, body: {} }));
  const confirmed = Object.assign({}, EFFECTIVE_NO_ENGINE, {
    enforced: { revision: 12, generation: "g12", confirmed_at: "2026-11-15T13:00:00Z",
      covers: "the default policy only; device assignments are not published in Stage 11A" },
  });
  const html = ctx.effectivePolicyCardHtml(confirmed, DEVICE_DETAIL);
  assert.match(html, /Confirmed by engine/);
  assert.match(html, /revision 12/);
  const stale = ctx.effectivePolicyCardHtml(
    Object.assign({}, EFFECTIVE_NO_ENGINE, { enforced: "stale" }), DEVICE_DETAIL);
  assert.match(stale, /Stale/);
  assert.doesNotMatch(stale.split("3. Enforced")[1], /badge-ok/);
  const rejected = ctx.effectivePolicyCardHtml(
    Object.assign({}, EFFECTIVE_NO_ENGINE, { enforced: "rejected" }), DEVICE_DETAIL);
  assert.match(rejected, /Rejected/);
});

test("inactive device assignment is flagged as not applied to live queries", () => {
  const { ctx } = loadApp(() => ({ status: 401, body: {} }));
  const eff = Object.assign({}, EFFECTIVE_NO_ENGINE, {
    device_state: "inactive", assigned_applies_to_live_queries: false });
  const html = ctx.effectivePolicyCardHtml(eff, DEVICE_DETAIL);
  assert.match(html, /Not applied to live queries/);
  assert.match(html, /live queries receive the default policy/);
});

// ---------- state controls ----------

test("state changes and removal require confirmation before the API call", async () => {
  const { ctx, document, calls } = loadApp((url, method, body) => {
    if (url === "/api/devices/1/state" && method === "POST") {
      return { status: 200, body: DEVICE_DETAIL };
    }
    return detailResponder()(url, method, body);
  });
  const stateBtn = new StubElement(document, "fake-state-btn");
  stateBtn.setAttribute("data-state-action", "removed");
  const dc = document;
  await (async () => {
    dc.setQuerySelectorAll("button[data-state-action]", [stateBtn]);
    await ctx.renderDeviceDetail("1");
  })();
  stateBtn.click();
  // A confirmation dialog appeared and NO state call was made yet.
  assert.match(document.getElementById("modal").innerHTML, /soft/);
  assert.match(document.getElementById("modal").innerHTML, /does not wipe/);
  assert.equal(lastCall(calls, "POST", "/api/devices/1/state"), undefined);
  document.getElementById("modal #modal-confirm").click();
  await new Promise((r) => setImmediate(r));
  const post = lastCall(calls, "POST", "/api/devices/1/state");
  assert.ok(post, "state change sent only after confirmation");
  assert.deepEqual(post.body, { state: "removed" });
});

test("state controls omit the current state", async () => {
  const { ctx, document, calls } = loadApp(detailResponder());
  const seen = [];
  const doc = document;
  doc.setQuerySelectorAll("button[data-state-action]", []);
  await ctx.renderDeviceDetail("1");
  const html = doc.getElementById("content").innerHTML;
  assert.ok(html.indexOf('data-state-action="active"') === -1, "current state not offered");
  assert.ok(html.indexOf('data-state-action="inactive"') !== -1);
  assert.ok(html.indexOf('data-state-action="disabled"') !== -1);
  assert.ok(html.indexOf('data-state-action="removed"') !== -1);
  assert.equal(seen.length, 0);
  void calls;
});

// ---------- escaping ----------

test("server-provided malicious HTML is escaped everywhere it renders", async () => {
  const evil = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
  const badDevice = Object.assign({}, DEVICE_DETAIL, { name: evil, description: evil, notes: evil });
  const badAudit = [{ id: 1, admin: "ad<script>min", action: "device.update",
    detail: evil, created_at: "2026-11-15T10:00:00Z" }];
  const { ctx, document } = loadApp(detailResponder({ device: badDevice, audit: badAudit }));
  await ctx.renderDeviceDetail("1");
  const html = document.getElementById("content").innerHTML;
  assert.ok(!html.includes("<script>alert(2)"), "no raw script tag from server data");
  assert.ok(!html.includes('<img src=x'), "no raw img tag from server data");
  assert.match(html, /&lt;script&gt;/);
  await ctx.renderDevices();
  void 0;
});

test("list rows escape server data", async () => {
  const evil = '"><script>alert(1)</script>';
  const bad = Object.assign({}, DEVICES[0], { name: evil, os: evil });
  const { ctx, document } = loadApp((url) => {
    if (url === "/api/me") return { status: 401, body: {} };
    if (url.startsWith("/api/devices")) {
      return { status: 200, body: { devices: [bad], note: LIST_NOTE } };
    }
    return { status: 404, body: {} };
  });
  await ctx.renderDevices();
  const html = document.getElementById("content").innerHTML;
  assert.ok(!html.includes("<script>alert(1)"));
  assert.match(html, /&lt;script&gt;/);
});

// ---------- API shape the UI relies on ----------

test("removed entries hide binding and assignment controls", () => {
  const { ctx } = loadApp(() => ({ status: 401, body: {} }));
  const removedDevice = Object.assign({}, DEVICE_DETAIL, { state: "removed",
    active_assignment: null, assignment_history: DEVICE_DETAIL.assignment_history });
  const html = ctx.assignmentCardHtml(removedDevice, POLICIES);
  assert.match(html, /Removed entries hold no assignment/);
  assert.ok(html.indexOf('id="dv-assign"') === -1);
});

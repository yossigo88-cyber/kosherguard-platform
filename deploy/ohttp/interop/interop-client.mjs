// KosherGuard OHTTP interop check: a real RFC 9458 round trip against a
// locally running pinned gateway with EPHEMERAL FIXTURE KEYS.
// Usage: node interop-client.mjs <gateway-base-url> <expected-body>
// Exits non-zero on any failure. Run from the pinned gateway checkout
// (it imports the gateway's own runtime dependencies).
import { CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM } from "hpke";
import { KeyConfig, MediaType, OHTTPClient } from "ohttp-ts";

const [base, expected] = process.argv.slice(2);
if (!base || !expected) {
	console.error("usage: node interop-client.mjs <base-url> <expected-body>");
	process.exit(2);
}

const keysRes = await fetch(`${base}/.well-known/ohttp-gateway`);
if (keysRes.status !== 200) throw new Error(`key config fetch: ${keysRes.status}`);
if (keysRes.headers.get("content-type") !== MediaType.KEYS)
	throw new Error("key config content-type mismatch");
const configs = KeyConfig.parseMultiple(new Uint8Array(await keysRes.arrayBuffer()));
const x25519 = configs.find((c) => c.kemId === 0x20);
if (!x25519) throw new Error("no X25519 key config published");

const suite = new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM);
const client = new OHTTPClient(suite, x25519);
const { init, context } = await client.encapsulateRequest(new Request(`${base}/`));
const res = await fetch(`${base}/ohttp`, init);
if (res.status !== 200) throw new Error(`gateway POST: ${res.status}`);
const inner = await context.decapsulateResponse(res);
const body = await inner.text();
if (inner.status !== 200 || body !== expected)
	throw new Error(`round trip mismatch: status=${inner.status} body=${JSON.stringify(body)}`);
console.log("INTEROP PASS: decapsulated request reached target and response decapsulated intact");

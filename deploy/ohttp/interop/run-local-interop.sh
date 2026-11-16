#!/usr/bin/env bash
# KosherGuard OHTTP gateway local interop test.
#
# Fetches the PINNED gateway (../PINNED), installs runtime deps, starts
# it with an EPHEMERAL FIXTURE SEED (generated per run, never stored)
# against a local stub target, and proves a full RFC 9458 round trip:
# key-config fetch -> encapsulate -> gateway decapsulate/forward ->
# stub target -> encapsulated response -> client decapsulate.
#
# No production secrets participate; the fixture seed dies with the run.
set -euo pipefail

COMMIT=$(awk '/^commit:/{print $2}' "$(dirname "$0")/../PINNED")
WORK=$(mktemp -d)
trap 'kill ${GW_PID:-0} ${STUB_PID:-0} 2>/dev/null || true; rm -rf "$WORK"' EXIT

EXPECTED="kosherguard-fixture-target-response"
GW_PORT=${GW_PORT:-3999}
STUB_PORT=${STUB_PORT:-3998}

echo "== fetching pinned gateway ${COMMIT:0:12} =="
curl -fsSL "https://codeload.github.com/thibmeu/ohttp-gateway/tar.gz/$COMMIT" \
  -o "$WORK/gw.tar.gz"
mkdir "$WORK/gw" && tar xzf "$WORK/gw.tar.gz" -C "$WORK/gw" --strip-components=1

cd "$WORK/gw"
npm ci --omit=dev --no-audit --no-fund --loglevel=error

cp "$(dirname "$0")/interop-client.mjs" "$WORK/gw/interop-client.mjs"

echo "== generating ephemeral fixture seed (not stored, not logged) =="
FIXTURE_SEED=$(node -e 'console.log(require("crypto").randomBytes(32).toString("base64"))')

echo "== starting stub target :$STUB_PORT =="
EXPECTED="$EXPECTED" STUB_PORT="$STUB_PORT" node -e '
  require("http").createServer((req, res) => {
    res.writeHead(200, {"content-type": "text/plain"});
    res.end(process.env.EXPECTED);
  }).listen(Number(process.env.STUB_PORT), "127.0.0.1");' &
STUB_PID=$!

echo "== starting gateway :$GW_PORT =="
OHTTP_KEY_SEED="$FIXTURE_SEED" TARGET_URL="http://127.0.0.1:$STUB_PORT" \
  PORT="$GW_PORT" node --experimental-strip-types src/server.ts &
GW_PID=$!

for i in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$GW_PORT/health" >/dev/null 2>&1 && break
  sleep 0.2
  if [ "$i" = 50 ]; then echo "FAIL: gateway never became healthy"; exit 1; fi
done

echo "== running RFC 9458 round trip =="
node interop-client.mjs "http://127.0.0.1:$GW_PORT" "$EXPECTED"
echo "== interop test complete =="

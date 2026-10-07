#!/bin/bash
# Repository CI operator check. No deployment or publisher credential.
set -euo pipefail
mode=${1:?pinned, release or dependencies}
case "$mode" in pinned|release|dependencies) ;; *) exit 2;; esac
exec 9>/run/lock/novis-assurance-lab-live.lock
flock -w 30 9
umask 077
maint=${LOGIN_CSP_MAINTENANCE:?}
workspace=${LOGIN_CSP_WORKSPACE:?}
reports=${LOGIN_CSP_REPORTS:?}
mkdir -p "$workspace" "$reports"
chmod 0755 "$reports"
cleanup(){
  status=$?
  [[ -z ${server:-} ]] || kill "$server" 2>/dev/null || true
  [[ -z ${daemon:-} ]] || kill "$daemon" 2>/dev/null || true
  chmod 0644 "$reports"/* 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM INT
bound(){ [[ $(du -s "$workspace" | cut -f1) -lt 12582912 ]]; }
export GOMAXPROCS=2 GOMEMLIMIT=1500MiB GOPATH="$workspace/go" GOCACHE="$workspace/go-cache" GOMODCACHE="$workspace/go-mod"
export NODE_OPTIONS=--max-old-space-size=2048 NX_DAEMON=false NX_NO_CLOUD=true NEXT_TELEMETRY_DISABLED=1 NX_PARALLEL=2
ref=v4.19.2
if [[ $mode == release ]]; then
  ref=$(curl --max-time 30 -fsSL https://api.github.com/repos/zitadel/zitadel/releases/latest | python3 -c 'import json,sys;print(json.load(sys.stdin)["tag_name"])')
fi
[[ $ref =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
printf 'mode=%s\nsource=%s\nbackend remains v4.19.2; candidate only, never automatic deployment\n' "$mode" "$ref" > "$reports/candidate.txt"
git clone --depth 1 --branch "$ref" https://github.com/zitadel/zitadel.git "$workspace/source"
cd "$workspace/source"
if [[ ${LOGIN_CSP_FAILURE:-} == patch ]]; then
  # A changed supplier context must cause ordinary patch application to fail.
  sed -i 's/export function buildCSP/export function incompatibleBuildCSP/' apps/login/src/lib/csp.ts
fi
git apply --check "$maint/v4.19.2.patch"
git apply "$maint/v4.19.2.patch"
pnpm install --filter '@zitadel/login...' --frozen-lockfile --store-dir "$workspace/pnpm-store" --network-concurrency 4 --child-concurrency 2
bound
if [[ $mode == dependencies ]]; then
  status=0
  pnpm --filter '@zitadel/login...' outdated --format json > "$reports/dependencies.json" || status=$?
  [[ $status == 0 || $status == 1 ]]
  pnpm --filter '@zitadel/login...' update --latest --network-concurrency 4 --child-concurrency 2
  git diff -- apps/login/package.json packages/client/package.json packages/proto/package.json pnpm-lock.yaml > "$reports/dependency-update.patch"
  bound
fi
pnpm nx run --nxBail @zitadel/login:build --parallel=2 --skip-nx-cache
pnpm --filter @zitadel/login exec vitest run src/lib/csp.test.ts src/proxy.test.ts --maxWorkers=2
bound
npm install --prefix "$workspace/browser" --ignore-scripts --no-audit --no-fund playwright@1.55.0
export PLAYWRIGHT_BROWSERS_PATH="$workspace/browsers"
"$workspace/browser/node_modules/.bin/playwright" install --with-deps chromium
cp -r apps/login/.next/static apps/login/.next/standalone/apps/login/.next/
cp -r apps/login/public apps/login/.next/standalone/apps/login/
strict=true
[[ ${LOGIN_CSP_FAILURE:-} != test ]] || strict=false
(cd apps/login/.next/standalone; CSP_NONCE_ENABLED="$strict" PORT=13000 HOSTNAME=127.0.0.1 ZITADEL_API_URL=http://127.0.0.1:9 ZITADEL_SERVICE_USER_TOKEN=synthetic-noncredential OTEL_SDK_DISABLED=true node apps/login/server.js) > "$workspace/server.log" 2>&1 &
server=$!
for _ in {1..30}; do curl -fsS --max-time 2 http://127.0.0.1:13000/ui/v2/login/healthy >/dev/null && break; sleep 1; done
LOGIN_CSP_PACKAGE_JSON="$workspace/browser/package.json" LOGIN_CSP_BASE=http://127.0.0.1:13000 node "$maint/login-csp.mjs" > "$reports/browser.txt" 2>&1
kill "$server"; wait "$server" || true; server=
cp "$maint/Dockerfile" apps/login/Dockerfile.csp
mkdir -p "$workspace/tools"
curl --max-time 180 -fsSL https://github.com/moby/buildkit/releases/download/v0.28.0/buildkit-v0.28.0.linux-amd64.tar.gz -o "$workspace/tools/buildkit.tgz"
tar -xzf "$workspace/tools/buildkit.tgz" -C "$workspace/tools"
"$workspace/tools/bin/buildkitd" --root "$workspace/buildkit" --addr unix:///run/novis-login-check.sock --oci-worker-binary "$workspace/tools/bin/buildkit-runc" --oci-worker-snapshotter native --containerd-worker=false > "$workspace/buildkit.log" 2>&1 &
daemon=$!
for _ in {1..20}; do "$workspace/tools/bin/buildctl" --addr unix:///run/novis-login-check.sock debug workers >/dev/null 2>&1 && break; kill -0 "$daemon"; sleep 1; done
"$workspace/tools/bin/buildctl" --addr unix:///run/novis-login-check.sock build --frontend dockerfile.v0 --local context=apps/login --local dockerfile=apps/login --opt filename=Dockerfile.csp --output type=oci,name=ghcr.io/sglanzer/zitadel-login-csp:candidate,dest="$workspace/candidate.oci.tar" --metadata-file "$reports/image-digest.json"
bound
printf 'CSP and production checks passed. Candidate digest requires configured private-stack Go/human e2e and review before a profile update. No deployment occurred.\n' >> "$reports/candidate.txt"

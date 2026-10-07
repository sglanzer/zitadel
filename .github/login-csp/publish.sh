#!/bin/bash
set -euo pipefail
exec 9>/run/lock/novis-assurance-lab-live.lock
flock -w 30 9
umask 077
publish_root=${LOGIN_CSP_PUBLISH_ROOT:?}
export REGISTRY_AUTH_FILE="$publish_root/registry-auth.json"
trap 'rm -f "$REGISTRY_AUTH_FILE" "$publish_root/login-csp-candidate.oci.tar" "$publish_root/publisher-token"' EXIT
trap 'exit 143' TERM INT
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q skopeo
export GH_TOKEN=$(cat "$publish_root/publisher-token")
gh run download "$LOGIN_CSP_ARTIFACT_RUN" --repo sglanzer/zitadel --name "login-csp-image-pinned-$LOGIN_CSP_ARTIFACT_RUN" --dir "$publish_root"
[[ $(stat -c%s "$publish_root/login-csp-candidate.oci.tar") -lt 536870912 ]]
printf '%s  %s\n' "$LOGIN_CSP_ARTIFACT_SHA256" "$publish_root/login-csp-candidate.oci.tar" | sha256sum -c -
digest=$(skopeo inspect --raw "oci-archive:$publish_root/login-csp-candidate.oci.tar" | sha256sum | cut -d' ' -f1)
[[ "$digest" == 92aa17e11a9c06ce64cb75cbc931d8aead5ffa04fc0f1f3b463c0cd52ba43048 ]]
printf '%s' "$GH_TOKEN" | skopeo login --authfile "$REGISTRY_AUTH_FILE" --username "$LOGIN_CSP_PUBLISH_ACTOR" --password-stdin ghcr.io
skopeo copy --preserve-digests --authfile "$REGISTRY_AUTH_FILE" "oci-archive:$publish_root/login-csp-candidate.oci.tar" docker://ghcr.io/sglanzer/zitadel-login-csp:2026-10-07-v4.19.2-r2
echo "Published ghcr.io/sglanzer/zitadel-login-csp@sha256:$digest"

#!/usr/bin/env bash
set -euo pipefail

readonly candidate="25ec7901796208785ec25f20b5fc4c0d7bc05eba"
readonly service_sha="598adbc49a727bffef773d97e724c915960e8404509e3b9d6941dd447040720c"
readonly bootstrap_sha="73f59bec1ea4fd76baa6b3b637859e08fd88fe7ca0cb7530d59f85380214c923"
readonly output="${1:?usage: build-primitives-oci.sh OUTPUT_DIRECTORY}"

if [[ -e "$output" ]]; then
  echo "OCI output already exists" >&2
  exit 1
fi
if [[ "$(go env GOOS)/$(go env GOARCH)" != "linux/amd64" ]] ||
  [[ "$(go version)" != go\ version\ go1.26.5\ linux/amd64 ]]; then
  echo "OCI build requires exact Go 1.26.5 linux/amd64" >&2
  exit 1
fi

work="$(mktemp -d)"
cleanup() {
  chmod -R u+w "$work" 2>/dev/null || true
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir -p "$work/rootfs/usr/local/bin" "$work/rootfs/etc" "$work/rootfs/var/empty"

service_revision="yukh-coordination-revision:$candidate"
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags "-buildid= -X main.buildRevision=$service_revision" \
  -o "$work/rootfs/usr/local/bin/yukh-coordination-primitives" \
  ./internal/primitivesstaging/cmd/yukh-coordination-primitives
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -ldflags "-buildid= -X main.buildRevision=$candidate" \
  -o "$work/rootfs/usr/local/bin/yukh-coordination-primitives-bootstrap" \
  ./internal/primitivesbootstrap/cmd/yukh-coordination-primitives-bootstrap
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-buildid=" \
  -o "$work/rootfs/usr/local/bin/yukh-coordination-secret-launcher" \
  ./internal/primitiveslauncher/cmd/yukh-coordination-secret-launcher

printf '%s  %s\n' "$service_sha" \
  "$work/rootfs/usr/local/bin/yukh-coordination-primitives" | sha256sum --check --status
printf '%s  %s\n' "$bootstrap_sha" \
  "$work/rootfs/usr/local/bin/yukh-coordination-primitives-bootstrap" | sha256sum --check --status
launcher_sha="$(sha256sum "$work/rootfs/usr/local/bin/yukh-coordination-secret-launcher" | cut -d' ' -f1)"

printf '%s\n' 'nonroot:x:65532:65532:nonroot:/var/empty:/sbin/nologin' >"$work/rootfs/etc/passwd"
printf '%s\n' 'nonroot:x:65532:' >"$work/rootfs/etc/group"
chmod 0555 "$work/rootfs/usr/local/bin/yukh-coordination-primitives" \
  "$work/rootfs/usr/local/bin/yukh-coordination-primitives-bootstrap" \
  "$work/rootfs/usr/local/bin/yukh-coordination-secret-launcher"
chmod 0444 "$work/rootfs/etc/passwd" "$work/rootfs/etc/group"
chmod 0555 "$work/rootfs/usr" "$work/rootfs/usr/local" "$work/rootfs/usr/local/bin" \
  "$work/rootfs/etc" "$work/rootfs/var" "$work/rootfs/var/empty"

tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
  --format=posix --pax-option=delete=atime,delete=ctime \
  -C "$work/rootfs" -cf "$work/layer.tar" .
layer_digest="$(sha256sum "$work/layer.tar" | cut -d' ' -f1)"
layer_size="$(stat -c '%s' "$work/layer.tar")"

cat >"$work/config.json" <<EOF
{"architecture":"amd64","config":{"Entrypoint":["/usr/local/bin/yukh-coordination-secret-launcher"],"Labels":{"io.nomed.yukh.launcher.profile":"yukh-coordination/private-primitives-descriptor-launcher-v1","org.opencontainers.image.revision":"$candidate","org.opencontainers.image.title":"yukh-coordination-private-primitives-staging","org.opencontainers.image.version":"yukh-coordination/private-primitives-staging-v1"},"User":"65532:65532","WorkingDir":"/var/empty"},"history":[{"comment":"reproducible RFC-0022 scratch image"}],"os":"linux","rootfs":{"diff_ids":["sha256:$layer_digest"],"type":"layers"}}
EOF
config_digest="$(sha256sum "$work/config.json" | cut -d' ' -f1)"
config_size="$(stat -c '%s' "$work/config.json")"

cat >"$work/manifest.json" <<EOF
{"config":{"digest":"sha256:$config_digest","mediaType":"application/vnd.oci.image.config.v1+json","size":$config_size},"layers":[{"digest":"sha256:$layer_digest","mediaType":"application/vnd.oci.image.layer.v1.tar","size":$layer_size}],"mediaType":"application/vnd.oci.image.manifest.v1+json","schemaVersion":2}
EOF
manifest_digest="$(sha256sum "$work/manifest.json" | cut -d' ' -f1)"
manifest_size="$(stat -c '%s' "$work/manifest.json")"

mkdir -p "$output/blobs/sha256"
cp "$work/layer.tar" "$output/blobs/sha256/$layer_digest"
cp "$work/config.json" "$output/blobs/sha256/$config_digest"
cp "$work/manifest.json" "$output/blobs/sha256/$manifest_digest"
printf '%s\n' '{"imageLayoutVersion":"1.0.0"}' >"$output/oci-layout"
cat >"$output/index.json" <<EOF
{"manifests":[{"annotations":{"org.opencontainers.image.ref.name":"private-primitives-staging-v1"},"digest":"sha256:$manifest_digest","mediaType":"application/vnd.oci.image.manifest.v1+json","platform":{"architecture":"amd64","os":"linux"},"size":$manifest_size}],"schemaVersion":2}
EOF
cat >"$output/sbom.spdx.json" <<EOF
{"SPDXID":"SPDXRef-DOCUMENT","creationInfo":{"created":"1970-01-01T00:00:00Z","creators":["Tool: yukh-coordination-build-primitives-oci-v1"]},"dataLicense":"CC0-1.0","documentNamespace":"https://nomed.invalid/yukh-coordination/rfc-0022/$manifest_digest","files":[{"SPDXID":"SPDXRef-Service","checksums":[{"algorithm":"SHA256","checksumValue":"$service_sha"}],"fileName":"/usr/local/bin/yukh-coordination-primitives"},{"SPDXID":"SPDXRef-Bootstrap","checksums":[{"algorithm":"SHA256","checksumValue":"$bootstrap_sha"}],"fileName":"/usr/local/bin/yukh-coordination-primitives-bootstrap"},{"SPDXID":"SPDXRef-Launcher","checksums":[{"algorithm":"SHA256","checksumValue":"$launcher_sha"}],"fileName":"/usr/local/bin/yukh-coordination-secret-launcher"}],"name":"yukh-coordination-private-primitives-staging","packages":[],"relationships":[{"relatedSpdxElement":"SPDXRef-Service","relationshipType":"DESCRIBES","spdxElementId":"SPDXRef-DOCUMENT"},{"relatedSpdxElement":"SPDXRef-Bootstrap","relationshipType":"DESCRIBES","spdxElementId":"SPDXRef-DOCUMENT"},{"relatedSpdxElement":"SPDXRef-Launcher","relationshipType":"DESCRIBES","spdxElementId":"SPDXRef-DOCUMENT"}],"spdxVersion":"SPDX-2.3"}
EOF
sbom_digest="$(sha256sum "$output/sbom.spdx.json" | cut -d' ' -f1)"

printf 'manifest=sha256:%s\nconfig=sha256:%s\nlayer=sha256:%s\nsbom=sha256:%s\nlauncher=sha256:%s\n' \
  "$manifest_digest" "$config_digest" "$layer_digest" "$sbom_digest" "$launcher_sha" \
  >"$output/digests.txt"

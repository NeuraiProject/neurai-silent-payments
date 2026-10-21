#!/bin/sh
# Runs every test in Docker: unit tests, the determinism digest on several
# Node.js versions and, when NEURAID_DIR is set, the regtest integration test
# against a real node.
#
#   NEURAID_DIR=/directory/with/neuraid scripts/test-in-docker.sh
set -eu
cd "$(dirname "$0")/.."
ROOT=$PWD
IMAGE=node:22-bookworm-slim

docker run --rm -v "$ROOT":/work -w /work "$IMAGE" sh -c "npm ci --no-audit --no-fund && npm test"

for image in node:20-alpine node:22-alpine node:24-alpine "$IMAGE"; do
  echo "== determinism on $image"
  docker run --rm -v "$ROOT":/work:ro -w /work "$image" node test/determinism.mjs 300
done

if [ -n "${NEURAID_DIR:-}" ]; then
  echo "== regtest integration"
  docker run --rm --network none -v "$ROOT":/work -v "$NEURAID_DIR":/neurai:ro -e NEURAID=/neurai/neuraid -w /work "$IMAGE" \
    node test/regtest/run.mjs
fi

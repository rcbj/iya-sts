#!/usr/bin/env bash
#
# File: docker-npm-test.sh
#
# ---------------------------------------------------------------------------
# `npm test`, IN THE TESTS IMAGE (#50, 2026-09-16).
#
# Since part of this service is TypeScript, and TypeScript is compiled only
# inside an image build (issue #50), the in-process suite cannot run on a
# checkout — `tests/run.js` refuses there and says so. This builds the tests
# image from this tree (`tests/Dockerfile`, which compiles it) and runs
# `npm test` in a throwaway container of it. Arguments go to `tests/run.js`:
#
#   ./docker-npm-test.sh                       every in-process test
#   ./docker-npm-test.sh --only=typecheck      the files whose name matches
#
# The image is tagged for this script alone, so it never replaces the one
# `./run-tests.sh` builds, and no compose project is involved: nothing
# listens, nothing is left running, and nothing is written to the host.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

TAG="${STS_NPM_TEST_IMAGE:-iya-sts-npm-test:local}"

echo "docker-npm-test.sh: building ${TAG} from tests/Dockerfile"
# The test corpora are a PRIVATE image on ghcr.io (#253); a missing login is
# said in a sentence rather than as a pull error.
tests/tools/corpora-preflight.sh
docker build -f tests/Dockerfile -t "${TAG}" .

echo "docker-npm-test.sh: npm test $*"
exec docker run --rm "${TAG}" npm test -- "$@"

#!/usr/bin/env bash
#
# File: build-typescript.sh
#
# ---------------------------------------------------------------------------
# COMPILE THE TYPESCRIPT, INSIDE AN IMAGE BUILD AND NOWHERE ELSE (#50).
#
# rcbj's rules for the conversion (issue #50, 2026-09-16):
#
#   * transpiling happens in a container build step;
#   * no compiled artifact is ever written to the host's filesystem;
#   * the original .ts files are not in the service's final image.
#
# So this script is run by `Dockerfile` (in its `typescript` stage) and by
# `tests/Dockerfile`, never by hand on a checkout — and it refuses to run
# outside a container, because a `.js` it wrote beside a `.ts` on the host
# would be exactly the artifact the rules forbid, and would then shadow nothing
# and confuse everything.
#
# WHAT IT DOES:
#
#   1. `tsc -p tsconfig.json` — the type check, the same one
#      `tests/typecheck.js` runs on the host. It writes nothing.
#   2. `tsc -p tsconfig.build.json` — emits `x.js` BESIDE each `x.ts`. Beside
#      and not into a dist/ tree, because this service reads files relative to
#      its own modules (`__dirname`, 158 uses), forks workers by path, and is
#      required by path from the tests and from the parent project; an emitted
#      tree in the same place keeps every one of those working unchanged.
#      Skipped when there is no .ts to compile (tsc refuses an empty input).
#   3. With `--strip`: deletes every `.ts`, `types/` and the two tsconfig
#      files, for the service image's final stage to copy the tree without
#      them. The tests image does NOT strip: `tests/typecheck.js` checks a
#      pristine copy of the sources there (STS_TYPECHECK_ROOT).
#
# The compiler is `tests/node_modules/.bin/tsc`, a dependency of
# `tests/package.json` for `.npmrc`'s reason; the caller installs it first.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

STRIP=false
for arg in "$@"; do
  case "$arg" in
    --strip) STRIP=true ;;
    *) echo "build-typescript.sh: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ ! -f /.dockerenv ] && [ -z "${STS_IN_IMAGE_BUILD:-}" ]; then
  echo "build-typescript.sh: this runs inside an image build only (issue #50:" \
       "no compiled files on the host). Use ./docker-npm-test.sh or" \
       "./docker-run-tests.sh." >&2
  exit 1
fi

TSC=tests/node_modules/.bin/tsc
if [ ! -x "$TSC" ]; then
  echo "build-typescript.sh: $TSC is missing; install tests/package.json" \
       "first (npm install --prefix tests)." >&2
  exit 1
fi

# The sources to compile: every .ts that is not a declaration, outside the
# trees that are not ours. The same exclusions as tsconfig.build.json.
sources() {
  find . \( -path ./node_modules -o -path ./tests -o -path ./node-ldapjs \
            -o -path ./xacml-pep -o -path ./common/vendored \
            -o -path ./debugger/embedded -o -path ./.git \) -prune \
         -o -type f -name '*.ts' ! -name '*.d.ts' -print
}

echo "build-typescript.sh: type-checking (tsc -p tsconfig.json)"
"$TSC" -p tsconfig.json --pretty false

COUNT="$(sources | wc -l | tr -d ' ')"
if [ "$COUNT" -gt 0 ]; then
  echo "build-typescript.sh: compiling $COUNT file(s)" \
       "(tsc -p tsconfig.build.json)"
  "$TSC" -p tsconfig.build.json --pretty false
  # Every source must now have its .js beside it; a missing one is a module
  # the service would fail to require at start, so it fails the build here.
  missing=0
  while IFS= read -r ts; do
    if [ ! -f "${ts%.ts}.js" ]; then
      echo "build-typescript.sh: no output for $ts" >&2
      missing=1
    fi
  done < <(sources)
  [ "$missing" -eq 0 ]
else
  echo "build-typescript.sh: no .ts sources; nothing to compile"
fi

if [ "$STRIP" = true ]; then
  # The list is taken BEFORE anything is deleted, so the count is honest.
  STRIPPED="$(sources | wc -l | tr -d ' ')"
  sources | xargs -r rm -f
  rm -rf ./types ./tsconfig.json ./tsconfig.build.json
  echo "build-typescript.sh: stripped $STRIPPED .ts source(s), types/ and" \
       "the tsconfig files"
fi

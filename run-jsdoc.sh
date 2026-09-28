#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
#
# run-jsdoc.sh — generate the API reference from the JSDoc in the source
# (2026-09-27).
#
# Output (gitignored):
#   ./apidocs/index.html   a page per module, class, function and variable of
#                          every service directory, from the /** */ blocks
#                          on them, with the TypeScript types beside each
#
# The documentation site publishes the same pages under /iya-sts/api/:
# .github/workflows/pages.yml runs this script in a job of its own and copies
# the result into the built site. It is modeled on ./run-coverage.sh, and it
# differs from that script in the ways worth knowing:
#
#   THE GENERATOR IS TypeDoc, NOT THE `jsdoc` TOOL. 317 of the service's
#   source files are TypeScript, which jsdoc cannot parse; TypeDoc reads the
#   same /** */ blocks from the .ts files and the .js ones alike (allowJs) and
#   keeps the types the TypeScript states. rcbj's choice, 2026-09-27.
#
#   IT HAS A PACKAGE OF ITS OWN, tests/tools/jsdoc/ (TypeDoc and TypeScript 6,
#   pinned by that directory's lockfile). The repository's TypeScript is 7,
#   the native compiler, which has no JavaScript API for TypeDoc to call, and
#   .npmrc's `omit=dev` rules out a devDependency (run-coverage.sh's header).
#
#   IT COMPILES NOTHING. TypeDoc reads the sources and writes HTML; no .js is
#   written beside a .ts, which is the rule that keeps the service's own build
#   inside an image (#50). Its type checking is off (`skipErrorChecking`), so
#   a type the TypeScript 6 parser reads differently from 7 cannot fail a run;
#   `tests/typecheck.js` is what checks the types.
#
#   BY DEFAULT IT RUNS IN A CONTAINER, and the host needs docker and nothing
#   else: the mirrored node image (.github/image-mirror.txt), this checkout
#   mounted read-only, the output directory mounted writable, running as this
#   user so the output is not root's. --no-docker runs on this machine and
#   needs node and npm; the Pages job uses it, on a runner that has both.
#
# What is documented is tests/tools/jsdoc/typedoc.json: server.js,
# sts_metadata.ts and every service directory, never the vendored copies (the
# eight Kerberos codec copies, common/vendored/, debugger/embedded/).
#
# Options:
#   --out=DIR               where the pages go (default ./apidocs). Emptied
#                           first.
#   --docker / --no-docker  where the run happens. Default: docker, with a loud
#                           fallback to the host when there is none.
#   --open                  open the index in a browser afterwards.
#   -h|--help
#
set -u -o pipefail
CURRENT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
cd "${CURRENT_DIR}" || exit 1

OUT="${CURRENT_DIR}/apidocs"
WHERE="auto"
OPEN=0
TOOLS="tests/tools/jsdoc"
IMAGE="${IMAGE_MIRROR:-ghcr.io/rcbj/iya-sts/mirror}/node:24.16.0-bookworm-slim"

usage()
{
  sed -n '2,/^set -u/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

for arg in "$@";
do
  case "${arg}" in
    --out=*)      OUT="$(realpath -m "${arg#--out=}")" ;;
    --docker)     WHERE="docker" ;;
    --no-docker)  WHERE="host" ;;
    --open)       OPEN=1 ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "run-jsdoc.sh: unknown option ${arg}" >&2; exit 2 ;;
  esac
done

if [ "${WHERE}" = "auto" ];
then
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1;
  then
    WHERE="docker"
  else
    echo "run-jsdoc.sh: no docker here — generating on this machine instead."
    WHERE="host"
  fi
fi

# THE OUTPUT IS EMPTIED FIRST, because TypeDoc adds to a directory rather than
# replacing it, and a page for a module that has since been removed would
# otherwise survive in the published site.
rm -rf "${OUT}"
mkdir -p "${OUT}" || exit 1

runOnHost()
{
  echo "Entering runOnHost()."
  if ! command -v npm >/dev/null 2>&1;
  then
    echo "run-jsdoc.sh: --no-docker needs node and npm on this machine." >&2
    echo "Leaving runOnHost(). No npm."
    return 1
  fi
  # `npm ci` into the tools directory: its node_modules is gitignored, and a
  # lockfile install is the same TypeDoc every time.
  (cd "${TOOLS}" && npm ci --no-audit --no-fund --ignore-scripts \
                          --loglevel=error) || {
    echo "Leaving runOnHost(). npm ci failed."
    return 1
  }
  (cd "${TOOLS}" && node_modules/.bin/typedoc --options typedoc.json \
                                              --out "${OUT}")
  local rc=$?
  echo "Leaving runOnHost(). typedoc exited ${rc}."
  return ${rc}
}

runInDocker()
{
  echo "Entering runInDocker()."
  # The tools are installed in the CONTAINER's /tmp, not in the mounted
  # checkout, which is read-only: nothing this run does reaches the tree but
  # the pages themselves.
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e npm_config_cache=/tmp/npm-cache \
    -v "${CURRENT_DIR}:/src:ro" \
    -v "${OUT}:/out" \
    -w /tmp \
    "${IMAGE}" \
    sh -c 'set -e
      mkdir -p /tmp/tools
      cp /src/'"${TOOLS}"'/package.json /src/'"${TOOLS}"'/package-lock.json \
         /tmp/tools/
      cd /tmp/tools
      npm ci --no-audit --no-fund --ignore-scripts --loglevel=error
      cd /src/'"${TOOLS}"'
      /tmp/tools/node_modules/.bin/typedoc --options typedoc.json \
        --out /out'
  local rc=$?
  echo "Leaving runInDocker(). docker exited ${rc}."
  return ${rc}
}

if [ "${WHERE}" = "docker" ];
then
  # The mirror is a private package on ghcr.io: a missing login is said in a
  # sentence rather than as a pull error.
  tests/tools/corpora-preflight.sh || exit 1
  runInDocker
  rc=$?
else
  runOnHost
  rc=$?
fi

if [ "${rc}" -ne 0 ] || [ ! -f "${OUT}/index.html" ];
then
  echo "run-jsdoc.sh: TypeDoc did not write ${OUT}/index.html." >&2
  exit 1
fi
echo "API reference: ${OUT}/index.html ($(find "${OUT}" -name '*.html' |
  wc -l) pages)"
if [ "${OPEN}" = "1" ];
then
  xdg-open "${OUT}/index.html" >/dev/null 2>&1 || true
fi

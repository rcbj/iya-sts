#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: .github/scripts/api-references.sh
#
# ---------------------------------------------------------------------------
# ONE API REFERENCE PER DOCUMENTATION VERSION (rcbj, 2026-11-17).
#
#   .github/scripts/api-references.sh <out-dir> [--docker]
#
# For each row of docs/_data/versions.yml it writes <out-dir>/<folder>/, the
# TypeDoc reference of that version's source: the latest row (the one with
# no `ref`) from this checkout, every other from its `ref`, a release tag,
# checked out into a temporary worktree. Each tree is documented by ITS OWN
# run-jsdoc.sh, so a release's reference is what that release's tools made
# of that release's source. pages.yml copies <out-dir>/<folder>/ to
# /<folder>/api/ in the built site.
#
# --no-docker is the default, which is what the Pages job uses (a runner with
# node and npm); --docker passes through to run-jsdoc.sh for a run on a
# machine that has docker and no node.
#
# The rows are read with a pattern, not a YAML parser: versions.yml keeps
# one version per line as a flow mapping, and its header says so. A row
# this does not understand fails the run rather than being skipped.
# ---------------------------------------------------------------------------
set -u -o pipefail

OUT="${1:?usage: api-references.sh <out-dir> [--docker]}"
WHERE="--no-docker"
if [ "${2:-}" = "--docker" ];
then
  WHERE="--docker"
fi

ROOT="$(git rev-parse --show-toplevel)" || exit 1
cd "${ROOT}" || exit 1
mkdir -p "${OUT}" || exit 1
OUT="$(realpath "${OUT}")"
WORK="$(mktemp -d)"
trap 'git worktree prune; rm -rf "${WORK}"' EXIT

ROWS="$(grep -E '^- *\{' docs/_data/versions.yml)"
if [ -z "${ROWS}" ];
then
  echo "api-references.sh: no version rows in docs/_data/versions.yml" >&2
  exit 1
fi

status=0
while IFS= read -r row;
do
  folder="$(sed -nE 's/.*folder: *"?([A-Za-z0-9._-]+)"?.*/\1/p' <<< "${row}")"
  ref="$(sed -nE 's/.*ref: *"?([A-Za-z0-9._\/-]+)"?.*/\1/p' <<< "${row}")"
  if [ -z "${folder}" ];
  then
    echo "api-references.sh: cannot read the folder of: ${row}" >&2
    status=1
    continue
  fi
  if [ -z "${ref}" ];
  then
    tree="${ROOT}"
    echo "== ${folder}: from this checkout"
  else
    tree="${WORK}/${folder}"
    echo "== ${folder}: from ${ref}"
    if ! git worktree add -q --detach "${tree}" "${ref}";
    then
      echo "api-references.sh: cannot check out ${ref}" >&2
      status=1
      continue
    fi
  fi
  if ! (cd "${tree}" && ./run-jsdoc.sh "${WHERE}" --out="${OUT}/${folder}");
  then
    echo "api-references.sh: run-jsdoc.sh failed for ${folder}" >&2
    status=1
    continue
  fi
  if [ ! -f "${OUT}/${folder}/index.html" ];
  then
    echo "api-references.sh: ${folder} has no index.html" >&2
    status=1
    continue
  fi
  echo "   $(find "${OUT}/${folder}" -name '*.html' | wc -l) page(s)"
done <<< "${ROWS}"

exit ${status}

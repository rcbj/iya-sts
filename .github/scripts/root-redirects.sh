#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: .github/scripts/root-redirects.sh
#
# ---------------------------------------------------------------------------
# THE ADDRESSES THE UNVERSIONED SITE PUBLISHED KEEP WORKING (rcbj,
# 2026-11-17).
#
#   .github/scripts/root-redirects.sh <site-dir>
#
# Until the site was versioned every page was at the top level
# (/iya-sts/configure-oauth2-grants.html), and bookmarks, other sites and
# every running 1.0.0 service's console, portal and front door link there.
# After the move those addresses would answer 404. This writes, into a
# BUILT site (Jekyll's _site), one small page at each such address that
# sends the reader to the same page in the newest documentation version
# that has it: the latest for almost every page, an older version only for
# a page the latest dropped.
#
# Generated at deploy rather than committed, so nothing is kept in step by
# hand: a page added to the latest version gets its top-level address too.
# A path that already exists at the top level (the landing page, /api/,
# the stylesheet) is never overwritten, and a version's API reference
# (/<folder>/api/, TypeDoc) is not mirrored: /api/ itself redirects.
#
# No script: a meta refresh, a canonical link and a plain link, the same
# shape as docs/api/index.html. The versions and their order are read from
# docs/_data/versions.yml (newest first), the base URL from _config.yml.
# ---------------------------------------------------------------------------
set -u -o pipefail

SITE="${1:?usage: root-redirects.sh <site-dir>}"
# Not `git rev-parse`: pages.yml runs this under sudo, because Jekyll's
# container wrote _site as root, and git refuses a root-run in a checkout
# owned by the runner's user.
ROOT="$(cd "$(dirname "$(realpath "$0")")/../.." && pwd)" || exit 1
SITE="$(realpath "${SITE}")" || exit 1

BASEURL="$(sed -nE 's/^baseurl: *"?([^"]*)"?.*/\1/p' \
             "${ROOT}/docs/_config.yml")"
FOLDERS="$(grep -E '^- *\{' "${ROOT}/docs/_data/versions.yml" |
           sed -nE 's/.*folder: *"?([A-Za-z0-9._-]+)"?.*/\1/p')"
if [ -z "${FOLDERS}" ];
then
  echo "root-redirects.sh: no versions in docs/_data/versions.yml" >&2
  exit 1
fi

written=0
kept=0
while IFS= read -r folder;
do
  if [ ! -d "${SITE}/${folder}" ];
  then
    echo "root-redirects.sh: ${folder} is not in the built site" >&2
    exit 1
  fi
  while IFS= read -r rel;
  do
    target="${SITE}/${rel}"
    if [ -e "${target}" ];
    then
      # The top level has it already: a real page, or the redirect a newer
      # version wrote a moment ago.
      kept=$((kept + 1))
      continue
    fi
    to="${BASEURL}/${folder}/${rel}"
    mkdir -p "$(dirname "${target}")" || exit 1
    cat > "${target}" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Moved to ${folder}</title>
<meta http-equiv="refresh" content="0; url=${to}">
<link rel="canonical" href="${to}">
</head>
<body>
<p>The documentation is kept per version. This page is now at
<a href="${to}">${to}</a>.</p>
</body>
</html>
EOF
    written=$((written + 1))
  done < <(cd "${SITE}/${folder}" &&
           find . -name '*.html' -not -path './api/*' | sed 's|^\./||' | sort)
done <<< "${FOLDERS}"

echo "Top-level redirects: ${written} written, ${kept} already present."

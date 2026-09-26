#!/usr/bin/env bash
# ===========================================================================
# tests/tools/fetch-xml-schemas.sh — THE PUBLISHED XML SCHEMAS, FETCHED AND
# PINNED (#188).
#
#   tests/tools/fetch-xml-schemas.sh <output directory>
#
# Reads tests/xml-schemas/SCHEMAS, downloads every file it names into the
# output directory, and REFUSES (exit 1, naming the file) when one does not
# hash to the digest written there. Then it derives the one file the
# published set cannot be used without (below), and copies catalog.xml and
# all.xsd beside them. tests/vendored/sts_xml_schema_validation.js validates
# with `xmllint --nonet` against that directory, so nothing is fetched while
# the suite runs: this runs when the tests image is BUILT (tests/Dockerfile),
# and by hand for a run outside that image.
#
# WHY A SECOND ADDRESS. www.w3.org answers a scripted HTTPS request with a
# Cloudflare challenge (HTTP 429, measured 2026-09-24) — SCHEMAS names its
# files over plain http, which it still serves — and a build that depends on
# one host fails on a schedule nothing here controls. Every file is
# therefore asked for at its publisher first and, if that fails, at the
# Internet Archive's raw capture of the SAME URL (`id_`: the bytes as
# served). What makes the second answer acceptable is the digest, not the
# host: it is the same check either way.
#
# THE ONE DERIVED FILE: ws-trust-1.3-ns.xsd. The OASIS Standard's schema
# (ws-trust-1.3.xsd) declares targetNamespace
# `http://docs.oasis-open.org/ws-sx/ws-trust/200512/` — WITH a trailing
# slash — while the specification's namespace table, the
# OASIS 1.4 schema's own `xmlns:wst`, and every implementation use it
# without. A document in the specification's namespace therefore matches no
# declaration in the published file at all. The derived copy changes that
# one string and nothing else; the original is kept beside it, the digest
# check is of the original, and tests/xml-schemas/all.xsd says which it
# imports and why. It is recorded on #188 as a schema/specification
# conflict.
# ===========================================================================
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(cd "$here/../xml-schemas" && pwd)"
out="${1:-}"
if [ -z "$out" ]; then
  echo "usage: $0 <output directory>" >&2
  exit 2
fi
mkdir -p "$out"

# One URL, three tries a few seconds apart. `--compressed` because the
# Archive serves some captures gzip-encoded; a body that is STILL gzip after
# that (a capture of a gzip-encoded answer) is inflated below.
fetch_one()
{
  local url="$1" dest="$2" try
  for try in 1 2 3; do
    if curl -sSfL --compressed --connect-timeout 20 --max-time 120 \
         -A "iya-sts tests image build (schema fetch)" \
         -o "$dest" "$url" 2>/dev/null; then
      if [ "$(head -c 2 "$dest" | od -An -tx1 | tr -d ' ')" = "1f8b" ]; then
        mv "$dest" "$dest.gz"
        gunzip -f "$dest.gz"
      fi
      return 0
    fi
    sleep $((try * 5))
  done
  return 1
}

failed=0
while read -r name digest url _rest; do
  case "$name" in
    ''|'#'*) continue ;;
  esac
  dest="$out/$name"
  ok=""
  for candidate in "$url" "https://web.archive.org/web/2024id_/$url"; do
    if fetch_one "$candidate" "$dest"; then
      got="$(sha256sum "$dest" | cut -c1-64)"
      if [ "$got" = "$digest" ]; then
        echo "  $name  ($candidate)"
        ok=yes
        break
      fi
      echo "  $name: $candidate answered a DIFFERENT file (sha256 $got," \
           "expected $digest)" >&2
    else
      echo "  $name: $candidate did not answer" >&2
    fi
  done
  if [ -z "$ok" ]; then
    echo "FAILED: $name could not be fetched with the pinned digest." >&2
    rm -f "$dest"
    failed=1
  fi
done < "$source_dir/SCHEMAS"

if [ "$failed" != 0 ]; then
  echo "One or more XML Schemas could not be fetched and verified;" \
       "see tests/xml-schemas/SCHEMAS." >&2
  exit 1
fi

# The derived WS-Trust 1.3 file — see the header.
wst13="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
sed "s#${wst13}/'#${wst13}'#g" \
  "$out/ws-trust-1.3.xsd" > "$out/ws-trust-1.3-ns.xsd"
if grep -q "ws-trust/200512/'" "$out/ws-trust-1.3-ns.xsd"; then
  echo "FAILED: the WS-Trust 1.3 namespace was not rewritten." >&2
  exit 1
fi

cp "$source_dir/catalog.xml" "$source_dir/all.xsd" "$out/"
echo "XML Schemas ready in $out ($(ls "$out" | wc -l) files)."

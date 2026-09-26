#!/bin/bash
#
# File: tests/tools/fetch-w3c-xmlsec.sh
#
# ===========================================================================
# THE W3C XML SIGNATURE AND XML ENCRYPTION INTEROP CASES, FETCHED AT
# TESTS-IMAGE BUILD TIME AND PINNED BY SHA-256 (#193).
#
# The cases carry PRIVATE KEYS — PKCS#8 and PKCS#12 files for the decryption
# cases, and the signers' keys beside the signature cases — and nothing with
# key material in it is committed to this repository. So the list of URLs and
# their digests is committed (tests/tools/w3c-xmlsec.sha256) and the files are
# downloaded into the tests image by one layer of tests/Dockerfile.
#
# A file whose digest differs from the pinned one FAILS THE BUILD. A W3C page
# is not supposed to change, and if one did the cases the harness asserts
# about would no longer be the ones this list names; a build that went on
# with a different file would report a different corpus under the same name.
#
# **W3C'S EDGE RATE-LIMITS A BURST** (HTTP 429 from Cloudflare, measured on
# 2026-09-24 after about three hundred requests in a minute), so the requests
# are PACED — FETCH_PAUSE seconds apart, one by default — and a refused one is
# retried with a long back-off rather than the usual few seconds. Slow is the
# cost of a layer that is built once and then cached.
#
# Archives (.tar.gz, .tgz, .zip) are checked FIRST and then unpacked beside
# themselves, into the directory their own paths name.
#
# Usage: fetch-w3c-xmlsec.sh <list> <destination directory>
# Provenance and licence: tests/tools/W3C-XMLSEC-PROVENANCE.md.
# ===========================================================================
set -euo pipefail

LIST="${1:?usage: fetch-w3c-xmlsec.sh <list> <destination>}"
DEST="${2:?usage: fetch-w3c-xmlsec.sh <list> <destination>}"

mkdir -p "$DEST"
count=0
PAUSE="${FETCH_PAUSE:-1}"
while read -r sum rel url; do
  case "$sum" in
    ''|'#'*) continue ;;
  esac
  target="$DEST/$rel"
  mkdir -p "$(dirname "$target")"
  curl -fsSL --retry 8 --retry-all-errors --retry-delay 45 \
       -o "$target" "$url"
  sleep "$PAUSE"
  got="$(sha256sum "$target" | cut -d' ' -f1)"
  if [ "$got" != "$sum" ]; then
    echo "fetch-w3c-xmlsec: $url" >&2
    echo "  expected sha256 $sum" >&2
    echo "  got      sha256 $got" >&2
    echo "The published file changed, or the download is not the file the" >&2
    echo "list pins. Nothing is unpacked from a file that does not match." >&2
    exit 1
  fi
  case "$target" in
    *.tar.gz|*.tgz)
      tar -xzf "$target" -C "$(dirname "$target")" ;;
    *.zip)
      # phaos-xmlenc-3 has no top directory of its own, so every zip is
      # unpacked into one named after it.
      unzip -qo "$target" -d "${target%.zip}" ;;
  esac
  count=$((count + 1))
done < "$LIST"
echo "fetch-w3c-xmlsec: $count files fetched and verified into $DEST"

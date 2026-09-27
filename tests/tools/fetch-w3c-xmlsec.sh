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
# **AND WHEN W3C STILL REFUSES, THE SAME BYTES COME FROM ELSEWHERE**
# (2026-09-26, after a tests-image build failed on a 429 despite the pacing).
# Each file is tried at its published https URL, then over plain http (the
# edge rate-limits the two separately, which is how fetch-xml-schemas.sh
# gets W3C's schemas), then from the Internet Archive's raw capture of the
# same URL (`id_`: the bytes as published). A copy from anywhere is accepted
# ONLY at the pinned digest, so where it came from cannot change what the
# harness runs; an Archive body still gzip-encoded is decoded first.
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
  got=""
  for candidate in "$url" "$(printf '%s' "$url" | sed 's#^https://www\.w3\.org/#http://www.w3.org/#')" \
                   "https://web.archive.org/web/2024id_/$url"; do
    if curl -fsSL --retry 4 --retry-all-errors --retry-delay 30 \
         -o "$target" "$candidate"; then
      if [ "$(head -c2 "$target" | od -An -tx1 | tr -d ' ')" = "1f8b" ] &&
         ! printf '%s' "$rel" | grep -q -E '\.(tar\.gz|tgz|gz)$'; then
        mv "$target" "$target.gz" && gunzip -f "$target.gz"
      fi
      got="$(sha256sum "$target" | cut -d' ' -f1)"
      if [ "$got" = "$sum" ]; then
        break
      fi
      echo "fetch-w3c-xmlsec: $candidate answered a different file" >&2
    else
      echo "fetch-w3c-xmlsec: $candidate did not answer" >&2
    fi
    sleep "$PAUSE"
  done
  sleep "$PAUSE"
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

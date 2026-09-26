#!/bin/bash
# HEIMDAL'S CLIENT TOOLS, AND A curl ON HEIMDAL'S GSSAPI (#205).
#
# Run in the `heimdal` stage of tests/Dockerfile, never on a host. Heimdal is
# BSD-3-Clause and curl is the curl licence (MIT-style); neither is vendored:
# both are fetched here at a pinned commit or release, checked by sha256, and
# built into ONE prefix, /opt/heimdal, which the runner copies whole. Nothing
# of it goes on the PATH there — the runner already has MIT's kinit, and the
# jobs call /opt/heimdal/bin/<tool> by name so a reader never wonders which
# implementation answered.
#
# WHY A COMMIT OF master AND NOT THE 7.8.0 RELEASE. 7.8.0 (2022-11-15) is the
# last release Heimdal tagged, and it has no `gss-token` — the one GSSAPI
# command line #205 names, added to master afterwards. The commit below is
# master as of 2026-09-18. Bumping it: change HEIMDAL_COMMIT, fetch the
# archive, write its sha256 here, rebuild the tests image, run
# sts_kerberos_heimdal.js in both modes.
#
# curl is built against that prefix's krb5-config (`--with-gssapi`), so
# `curl --negotiate` goes through Heimdal's GSSAPI and its Kerberos library —
# which is the point: the MIT curl in every other job answers the same
# challenge through a different implementation.
set -euo pipefail
OUT="${1:-/opt/heimdal}"
HEIMDAL_COMMIT=c4971f73f1afdaf186f867249bcf8b1f87a454ac
HEIMDAL_SHA256=bc4064dcc07fad5c1da676e6c13bac11c4f7fbc4eb5f71187ed076f8625d00d1
CURL_VERSION=8.22.0
CURL_SHA256=f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7
WORK="$(mktemp -d)"
cd "$WORK"
curl -fsSL --retry 5 --retry-all-errors -o heimdal.tgz \
  "https://github.com/heimdal/heimdal/archive/${HEIMDAL_COMMIT}.tar.gz"
echo "${HEIMDAL_SHA256}  heimdal.tgz" | sha256sum -c -
tar xzf heimdal.tgz
cd "heimdal-${HEIMDAL_COMMIT}"
./autogen.sh >/dev/null
./configure --prefix="$OUT" --disable-static --enable-shared \
  --without-openldap --without-x --disable-heimdal-documentation \
  --with-openssl=/usr \
  LDFLAGS="-Wl,-rpath,$OUT/lib" >/dev/null
# lib/wind's generated tables race under -j: map_table.c and map_table.h
# are made by one rule written twice, and two jobs can run it at once and
# leave a half-written file (seen 2026-09-26: undefined _wind_map_table). A
# serial pass after a failed parallel one finishes exactly what the race
# left; a real compile error fails it again.
make -j"$(nproc)" >/dev/null 2>&1 || make >/dev/null
make install >/dev/null
mkdir -p "$OUT/licenses"
cp LICENSE "$OUT/licenses/heimdal.LICENSE"
echo "$HEIMDAL_COMMIT" > "$OUT/HEIMDAL_COMMIT"
cd "$WORK"
curl -fsSL --retry 5 --retry-all-errors -o curl.txz \
  "https://curl.se/download/curl-${CURL_VERSION}.tar.xz"
echo "${CURL_SHA256}  curl.txz" | sha256sum -c -
tar xJf curl.txz
cd "curl-${CURL_VERSION}"
./configure --prefix="$OUT" --with-gssapi="$OUT" --with-openssl \
  --without-libpsl --disable-ldap --disable-manual --disable-docs \
  LDFLAGS="-Wl,-rpath,$OUT/lib" >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
cp COPYING "$OUT/licenses/curl.COPYING"
"$OUT/bin/curl" --version | grep -i 'GSS-API\|Kerberos\|SPNEGO'
"$OUT/bin/kinit" --version
test -x "$OUT/bin/gss-token" || test -x "$OUT/libexec/gss-token"
rm -rf "$WORK"

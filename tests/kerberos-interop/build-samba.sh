#!/bin/bash
# SAMBA, BUILT FOR ITS RAW KERBEROS TESTS (#204).
#
# Run in the `samba-krb5` stage of tests/Dockerfile, never on a host. Samba is
# GPL-3.0, so it is NEVER VENDORED here: the release tarball is fetched at a
# pinned version, checked by sha256, built into /opt/samba, and the runner
# copies that prefix whole. Nothing of Samba is in git.
#
# WHY A BUILD AND NOT ubuntu's python3-samba: the distribution package ships
# the Python bindings without python/samba/tests/krb5, and the test tree must
# match the bindings it imports (samba.dcerpc.krb5pac and friends change
# between releases). So the pair comes from one tarball.
#
# The AD DC is built too (the default), because kdc_base_test.py imports
# samba.samdb, samba.dsdb and samba.join at load; without them not one of the
# KDCBaseTest classes could even be imported to establish that it does not
# apply. Nothing here RUNS a DC.
set -euo pipefail
OUT="${1:-/opt/samba}"
SAMBA_VERSION=4.25.0
SAMBA_SHA256=2e2cb7296833b35b8f7a7fb76045e0c57adc0c2cd03264b37df5d58e40f28437
WORK="$(mktemp -d)"
cd "$WORK"
curl -fsSL --retry 5 --retry-all-errors -o samba.tgz \
  "https://download.samba.org/pub/samba/stable/samba-${SAMBA_VERSION}.tar.gz"
echo "${SAMBA_SHA256}  samba.tgz" | sha256sum -c -
tar xzf samba.tgz
cd "samba-${SAMBA_VERSION}"
./configure --prefix="$OUT" --without-systemd --disable-cups \
  --disable-iprint --disable-glusterfs --disable-cephfs --disable-cephrgw \
  --without-gpgme --without-pam --without-libunwind --disable-spotlight \
  --disable-avahi --without-regedit --disable-wsp --without-winexe \
  >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
mkdir -p "$OUT/licenses"
cp COPYING "$OUT/licenses/samba.COPYING"
echo "$SAMBA_VERSION" > "$OUT/SAMBA_VERSION"
PY="$(ls -d "$OUT"/lib/python3*/site-packages)"
test -f "$PY/samba/tests/krb5/raw_testcase.py"
PYTHONPATH="$PY" python3 -c 'import samba.tests.krb5.kdc_base_test'
rm -rf "$WORK"

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/client-lab/build-cards.sh
#
# ---------------------------------------------------------------------------
# THE CLIENT LAB'S CARDS, BUILT FROM SOURCE (#2056), in the Dockerfile's
# `cards` stage and nowhere else:
#
#   jcardsim   licel/jcardsim          Apache-2.0   mvn package
#   SmartPGP   ANSSI-FR/SmartPGP       GPL-2.0      javac against jcardsim
#   PivApplet  arekinath/PivApplet     MPL-2.0      its jpp preprocessor,
#                                                   then javac
#
# Each is fetched at the commit the Dockerfile pins (a fetch by commit, so a
# moved tag or branch changes nothing). jcardsim compiles against Oracle's
# Java Card 3.0.5 classic API jar, which is checked against its pinned
# SHA-256 before it is used. The output, under $1:
#
#   jcardsim.jar        the simulator, with its own dependencies
#   smartpgp/           SmartPGP's class files
#   pivapplet-yubikey/  PivApplet's class files, patched to attest as a
#                       YubiKey 5 (patches/pivapplet-yubikey-attestation.patch)
#   pivapplet-stock/    PivApplet's class files as published
#   PINS                what was built, from which commit
# ---------------------------------------------------------------------------
set -euo pipefail

OUT="$1"
mkdir -p "${OUT}"

# One repository at one commit, into a directory of its own.
fetch() {
  local repo="$1" commit="$2" dir="$3"
  git init -q "${dir}"
  git -C "${dir}" remote add origin "https://github.com/${repo}.git"
  git -C "${dir}" fetch -q --depth 1 origin "${commit}"
  git -C "${dir}" checkout -q FETCH_HEAD
  echo "${repo} ${commit}" >> "${OUT}/PINS"
}

: > "${OUT}/PINS"

# Oracle's Java Card classic API, which jcardsim's pom installs from
# ${JC_CLASSIC_HOME}/lib/api_classic.jar.
mkdir -p jcsdk/lib
curl -fsSL -o jcsdk/lib/api_classic.jar \
  "https://github.com/martinpaljak/oracle_javacard_sdks/raw/${JCSDK_COMMIT}/jc305u3_kit/lib/api_classic.jar"
echo "${JCSDK_API_SHA256}  jcsdk/lib/api_classic.jar" | sha256sum -c -
echo "martinpaljak/oracle_javacard_sdks ${JCSDK_COMMIT} jc305u3_kit/lib/api_classic.jar sha256:${JCSDK_API_SHA256}" >> "${OUT}/PINS"

fetch licel/jcardsim "${JCARDSIM_COMMIT}" jcardsim
# ONE CHANGE TO jcardsim: SEED ITS KEY-GENERATION RANDOMNESS. Its
# SecureRandomNullProvider (key pairs, signature nonces) is a SHA-1
# DigestRandomGenerator that is never seeded, so every factory-fresh card
# generates the same keys in the same order on every start — keys anyone
# with jcardsim could make — and an ECDSA nonce from the same stream (the
# first attestation's r was the 9a key's x). An instance initializer seeds
# it from the platform's SecureRandom; nothing else in jcardsim changes.
nullrng=jcardsim/src/main/java/com/licel/jcardsim/crypto/SecureRandomNullProvider.java
sed -i 's|RandomGenerator engine = new DigestRandomGenerator(new SHA1Digest());|& { engine.addSeedMaterial(new SecureRandom().generateSeed(32)); }|' \
  "${nullrng}"
grep -q 'engine.addSeedMaterial(new SecureRandom().generateSeed(32))' \
  "${nullrng}"
echo "  patched: SecureRandomNullProvider seeded from SecureRandom" >> "${OUT}/PINS"
# Its pom installs the API jar in the `initialize` phase, which one `mvn
# package` resolves dependencies before; jcardsim's own README runs
# `mvn initialize` first for that reason.
(cd jcardsim && JC_CLASSIC_HOME=/build/jcsdk mvn -B -q initialize \
   && JC_CLASSIC_HOME=/build/jcsdk mvn -B -q -DskipTests \
        -Dmaven.javadoc.skip=true package)
cp "$(ls jcardsim/target/jcardsim-*.jar | grep -v -e sources -e javadoc -e android -e original \
      | head -1)" "${OUT}/jcardsim.jar"

fetch ANSSI-FR/SmartPGP "${SMARTPGP_COMMIT}" smartpgp
mkdir -p "${OUT}/smartpgp"
# shellcheck disable=SC2046
javac -nowarn --release 11 -cp "${OUT}/jcardsim.jar" -d "${OUT}/smartpgp" \
  $(find smartpgp/src -name '*.java')

fetch arekinath/PivApplet "${PIVAPPLET_COMMIT}" pivapplet
# Its own build preprocesses the sources (the feature flags in build.xml,
# YKPIV_ATTESTATION among them, all as shipped) and then converts them to a
# CAP; only the first step is needed for jcardsim. TWICE: stock, and with
# patches/pivapplet-yubikey-attestation.patch, which makes its attestation
# a YubiKey 5's (the patch's header says field by field). The lab runs the
# patched one by default and the stock one on request (bin/lab-piv-card),
# so the service's refusal of a non-YubiKey attestation stays asserted.
(cd pivapplet && ant -q preprocess)
mkdir -p "${OUT}/pivapplet-stock"
# shellcheck disable=SC2046
javac -nowarn --release 11 -cp "${OUT}/jcardsim.jar" \
  -d "${OUT}/pivapplet-stock" $(find pivapplet/src-gen -name '*.java')
rm -rf pivapplet/src-gen
git -C pivapplet apply /build/patches/pivapplet-yubikey-attestation.patch
grep -q 'MODIFIED (#2056)' pivapplet/src/net/cooperi/pivapplet/PivApplet.java
(cd pivapplet && ant -q preprocess)
mkdir -p "${OUT}/pivapplet-yubikey"
# shellcheck disable=SC2046
javac -nowarn --release 11 -cp "${OUT}/jcardsim.jar" \
  -d "${OUT}/pivapplet-yubikey" $(find pivapplet/src-gen -name '*.java')
echo "  patched: patches/pivapplet-yubikey-attestation.patch (pivapplet-yubikey/; pivapplet-stock/ is unpatched)" >> "${OUT}/PINS"

cat "${OUT}/PINS"

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# tests/tools/keycloak-uma-driver/build.sh — KEYCLOAK'S UMA 2.0 CLIENT, BUILT
# FOR THE TESTS IMAGE (#1196, 2026-10-30). Run by the `uma-java` stage of
# tests/Dockerfile (a Maven + Temurin image), jscep-driver/build.sh's steps
# for keycloak-authz-client:
#
#   1. Maven resolves the pom's dependencies; every jar is held to its sha256
#      in jars.sha256, and the directory to exactly that list.
#   2. javac compiles the one source file against them (release 17, every
#      lint as an error).
#   3. jlink makes the smallest runtime the driver needs, so the runner
#      carries no JDK.
#   4. The licences: each jar's own LICENSE/NOTICE where it carries one, and
#      Keycloak's LICENSE.txt at the release tag, pinned by sha256 — the
#      Keycloak and JBoss Logging jars carry none, and all are Apache-2.0.
#   5. A launcher, `keycloak-uma-driver <command> < request.json`.
#
# Usage: build.sh <source dir> <output dir>
set -euo pipefail

SRC="${1:?usage: build.sh <source dir> <output dir>}"
OUT="${2:?usage: build.sh <source dir> <output dir>}"
M2="${MAVEN_REPO:-/tmp/m2}"
KEYCLOAK_LICENCE_URL="https://raw.githubusercontent.com/keycloak/keycloak-client/26.0.12/LICENSE.txt"
KEYCLOAK_LICENCE_SHA256="cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

mkdir -p "${OUT}/lib" "${OUT}/licenses"
mvn -B -q -f "${SRC}/pom.xml" -Dmaven.repo.local="${M2}" \
  org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies \
  -DincludeScope=runtime -DoutputDirectory="${OUT}/lib"
(cd "${OUT}/lib" && sha256sum -c --strict "${SRC}/jars.sha256")
expected="$(awk '{print $2}' "${SRC}/jars.sha256" | sort)"
present="$(cd "${OUT}/lib" && ls -1 | sort)"
if [ "${expected}" != "${present}" ];
then
  echo "keycloak-uma-driver: the resolved jars are not the pinned list." >&2
  diff <(echo "${expected}") <(echo "${present}") >&2 || true
  exit 1
fi

work="$(mktemp -d)"
javac --release 17 -Xlint:all -Werror -cp "${OUT}/lib/*" -d "${work}/classes" \
  "${SRC}/src/main/java/net/iyasec/sts/tests/KeycloakUmaDriver.java"
jar --create --file "${OUT}/keycloak-uma-driver.jar" -C "${work}/classes" .

modules="$(jdeps --print-module-deps --ignore-missing-deps \
             --multi-release 21 -cp "${OUT}/lib/*" \
             "${OUT}/keycloak-uma-driver.jar")"
jlink --add-modules "${modules},jdk.crypto.ec,java.naming" --strip-debug \
      --no-man-pages --no-header-files --compress=zip-6 --output "${OUT}/jre"

for j in "${OUT}"/lib/*.jar; do
  name="$(basename "${j}" .jar)"
  rm -rf "${work}/x" && mkdir -p "${work}/x"
  (cd "${work}/x" && jar xf "${j}" META-INF/LICENSE META-INF/NOTICE \
     META-INF/LICENSE.txt META-INF/NOTICE.txt)
  for f in LICENSE NOTICE LICENSE.txt NOTICE.txt; do
    if [ -f "${work}/x/META-INF/${f}" ];
    then
      cp "${work}/x/META-INF/${f}" "${OUT}/licenses/${name}.${f}"
    fi
  done
done
curl -fsSL --retry 5 --retry-all-errors \
  -o "${OUT}/licenses/keycloak.LICENSE.txt" "${KEYCLOAK_LICENCE_URL}"
echo "${KEYCLOAK_LICENCE_SHA256}  ${OUT}/licenses/keycloak.LICENSE.txt" \
  | sha256sum -c -
cat > "${OUT}/licenses/apache-2.0-without-a-file.NOTICE.txt" <<'NOTICE'
keycloak-authz-client, keycloak-client-common-synced, jboss-logging and
commons-logging-jboss-logging carry no licence file in their jars. Each is
released under the Apache License, Version 2.0, whose text is
keycloak.LICENSE.txt beside this file.
NOTICE

cat > "${OUT}/keycloak-uma-driver" <<'LAUNCH'
#!/bin/sh
here="$(dirname "$(readlink -f "$0")")"
exec "${here}/jre/bin/java" \
  -cp "${here}/keycloak-uma-driver.jar:${here}/lib/*" \
  net.iyasec.sts.tests.KeycloakUmaDriver "$@"
LAUNCH
chmod 755 "${OUT}/keycloak-uma-driver"
usage="$("${OUT}/keycloak-uma-driver" 2>&1 || true)"
echo "${usage}" | grep -q '^usage: keycloak-uma-driver'
rm -rf "${work}"

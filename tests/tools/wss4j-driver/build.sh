#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# tests/tools/wss4j-driver/build.sh — APACHE WSS4J, BUILT FOR THE TESTS
# IMAGE (#1917, #1918, 2026-11-23). Run by the `wss4j-java` stage of
# tests/Dockerfile (a Maven + Temurin image), keycloak-uma-driver/build.sh's
# steps for wss4j-ws-security-dom:
#
#   1. Maven resolves the pom's dependencies; every jar is held to its sha256
#      in jars.sha256, and the directory to exactly that list.
#   2. javac compiles the one source file against them (release 17, every
#      lint as an error).
#   3. jlink makes the smallest runtime the driver needs, so the runner
#      carries no JDK.
#   4. The licences: each jar's own LICENSE/NOTICE where it carries one, and
#      the list of those that carry none, so a reader of the image sees
#      which.
#   5. A launcher, `wss4j-driver sign|verify < request.json`.
#
# Usage: build.sh <source dir> <output dir>
set -euo pipefail

SRC="${1:?usage: build.sh <source dir> <output dir>}"
OUT="${2:?usage: build.sh <source dir> <output dir>}"
M2="${MAVEN_REPO:-/tmp/m2}"

mkdir -p "${OUT}/lib" "${OUT}/licenses"
mvn -B -q -f "${SRC}/pom.xml" -Dmaven.repo.local="${M2}" \
  org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies \
  -DincludeScope=runtime -DoutputDirectory="${OUT}/lib"
(cd "${OUT}/lib" && sha256sum -c --strict "${SRC}/jars.sha256")
expected="$(awk '{print $2}' "${SRC}/jars.sha256" | sort)"
present="$(cd "${OUT}/lib" && ls -1 | sort)"
if [ "${expected}" != "${present}" ];
then
  echo "wss4j-driver: the resolved jars are not the pinned list." >&2
  diff <(echo "${expected}") <(echo "${present}") >&2 || true
  exit 1
fi

work="$(mktemp -d)"
javac --release 17 -Xlint:all,-classfile,-processing -Werror \
  -cp "${OUT}/lib/*" -d "${work}/classes" \
  "${SRC}/src/main/java/net/iyasec/sts/tests/Wss4jDriver.java"
jar --create --file "${OUT}/wss4j-driver.jar" -C "${work}/classes" .

modules="$(jdeps --print-module-deps --ignore-missing-deps \
             --multi-release 21 -cp "${OUT}/lib/*" \
             "${OUT}/wss4j-driver.jar")"
jlink --add-modules \
      "${modules},java.xml.crypto,jdk.crypto.ec,java.naming,java.sql" \
      --strip-debug --no-man-pages --no-header-files --compress=zip-6 \
      --output "${OUT}/jre"

: > "${OUT}/licenses/no-licence-file-in-the-jar.txt"
for j in "${OUT}"/lib/*.jar; do
  name="$(basename "${j}" .jar)"
  rm -rf "${work}/x" && mkdir -p "${work}/x"
  (cd "${work}/x" && jar xf "${j}" META-INF/LICENSE META-INF/NOTICE \
     META-INF/LICENSE.txt META-INF/NOTICE.txt META-INF/LICENSE.md)
  found=0
  for f in LICENSE NOTICE LICENSE.txt NOTICE.txt LICENSE.md; do
    if [ -f "${work}/x/META-INF/${f}" ];
    then
      cp "${work}/x/META-INF/${f}" "${OUT}/licenses/${name}.${f}"
      found=1
    fi
  done
  if [ "${found}" = 0 ];
  then
    echo "${name}" >> "${OUT}/licenses/no-licence-file-in-the-jar.txt"
  fi
done

cat > "${OUT}/wss4j-driver" <<'LAUNCH'
#!/bin/sh
here="$(dirname "$(readlink -f "$0")")"
exec "${here}/jre/bin/java" \
  -cp "${here}/wss4j-driver.jar:${here}/lib/*" \
  net.iyasec.sts.tests.Wss4jDriver "$@"
LAUNCH
chmod 755 "${OUT}/wss4j-driver"
usage="$("${OUT}/wss4j-driver" 2>&1 || true)"
echo "${usage}" | grep -q '^usage: wss4j-driver'
rm -rf "${work}"

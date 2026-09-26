#!/usr/bin/env bash
#
# tests/tools/jscep-driver/build.sh — THE jscep CLIENT, BUILT FOR THE TESTS
# IMAGE (#250, 2026-09-26). Run by the `enroll-java` stage of tests/Dockerfile
# (a Maven + Temurin 21 image) as `build.sh <this directory> <output>`; the
# runner copies only <output>: the driver's jar, the ten runtime jars, a
# jlink'd Java runtime, the licences and a launcher.
#
# 1. Maven RESOLVES jscep 3.0.1 and its runtime dependencies from Maven
#    Central (pom.xml says which, and why nothing is overridden).
# 2. EVERY JAR IS HELD TO jars.sha256, and the directory to exactly that list:
#    a jar that changed, or one that appeared (a transitive dependency Maven
#    resolved differently), fails the build. Maven's own .sha1 check is not
#    the pin; this is. To re-pin after a version change, build once without
#    the check, read `sha256sum lib/*.jar`, and edit the list.
# 3. javac compiles the one source file; jar packs it.
# 4. jlink makes a runtime of only the modules jdeps finds the driver needs,
#    plus jdk.crypto.ec (TLS key exchange over the main port) — about a fifth
#    of a JRE, so the runner carries no JDK. jlink copies the runtime's own
#    legal/ notices into it.
# 5. The licences: each jar's own where it has one, jscep's LICENCE.txt and
#    Bouncy Castle's LICENSE.html fetched at pinned commits and sha256-checked
#    (neither jar carries its licence as a file), and a note for
#    jcip-annotations, whose jar and pom carry none.
#
# Nothing here is key material and nothing is vendored.

set -euo pipefail

SRC="${1:?usage: build.sh <source dir> <output dir>}"
OUT="${2:?usage: build.sh <source dir> <output dir>}"
M2="${MAVEN_REPO:-/tmp/m2}"

JSCEP_LICENCE_URL="https://raw.githubusercontent.com/jscep/jscep/f2bae83a066a19cd99ccc0a9cf284de9c43823ac/LICENCE.txt"
JSCEP_LICENCE_SHA256="bda00b27a36405997831d7896b7d2e7a58b80b0071896d6f8aeede56a5a35ea8"
BC_LICENCE_URL="https://raw.githubusercontent.com/bcgit/bc-java/b6cb37c83caabba2f3a6b87787dd08a51124dffe/LICENSE.html"
BC_LICENCE_SHA256="edbbb10380b1271998b867a2e36b1cbee226e03d438726e1a91f80c5dde11849"

mkdir -p "${OUT}/lib" "${OUT}/licenses"
mvn -B -q -f "${SRC}/pom.xml" -Dmaven.repo.local="${M2}" \
  org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies \
  -DincludeScope=runtime -DoutputDirectory="${OUT}/lib"

# The pin: every listed jar present and unchanged, and nothing else.
(cd "${OUT}/lib" && sha256sum -c --strict "${SRC}/jars.sha256")
expected="$(awk '{print $2}' "${SRC}/jars.sha256" | sort)"
present="$(cd "${OUT}/lib" && ls -1 | sort)"
if [ "${expected}" != "${present}" ];
then
  echo "jscep-driver: the resolved jars are not the pinned list." >&2
  diff <(echo "${expected}") <(echo "${present}") >&2 || true
  exit 1
fi

work="$(mktemp -d)"
javac --release 17 -Xlint:all -Werror -cp "${OUT}/lib/*" -d "${work}/classes" \
  "${SRC}/src/main/java/net/iyasec/sts/tests/JscepDriver.java"
jar --create --file "${OUT}/jscep-driver.jar" -C "${work}/classes" .

modules="$(jdeps --print-module-deps --ignore-missing-deps \
             --multi-release 21 -cp "${OUT}/lib/*" "${OUT}/jscep-driver.jar")"
jlink --add-modules "${modules},jdk.crypto.ec" --strip-debug --no-man-pages \
      --no-header-files --compress=zip-6 --output "${OUT}/jre"

# `jar`, not unzip, which the Maven image does not have.
for j in "${OUT}"/lib/*.jar; do
  name="$(basename "${j}" .jar)"
  rm -rf "${work}/x" && mkdir -p "${work}/x"
  (cd "${work}/x" && jar xf "${j}" META-INF/LICENSE.txt META-INF/NOTICE.txt)
  for f in LICENSE.txt NOTICE.txt; do
    if [ -f "${work}/x/META-INF/${f}" ];
    then
      cp "${work}/x/META-INF/${f}" "${OUT}/licenses/${name}.${f}"
    fi
  done
done
curl -fsSL --retry 5 --retry-all-errors -o "${OUT}/licenses/jscep.LICENCE.txt" \
  "${JSCEP_LICENCE_URL}"
echo "${JSCEP_LICENCE_SHA256}  ${OUT}/licenses/jscep.LICENCE.txt" | sha256sum -c -
curl -fsSL --retry 5 --retry-all-errors \
  -o "${OUT}/licenses/bouncycastle.LICENSE.html" "${BC_LICENCE_URL}"
echo "${BC_LICENCE_SHA256}  ${OUT}/licenses/bouncycastle.LICENSE.html" \
  | sha256sum -c -
cat > "${OUT}/licenses/jcip-annotations.NOTICE.txt" <<'EOF'
jcip-annotations 1.0 (net.jcip), the annotations of "Java Concurrency in
Practice" by Brian Goetz and Tim Peierls, are released under the Creative
Commons Attribution License (http://creativecommons.org/licenses/by/2.5),
as stated at http://jcip.net/. The jar carries no licence file.
EOF

cat > "${OUT}/jscep-driver" <<'EOF'
#!/bin/sh
# jscep, through tests/tools/jscep-driver (#250). slf4j-simple prints jscep's
# log on stderr at the level STS_JSCEP_LOG_LEVEL names (info by default).
here="$(dirname "$(readlink -f "$0")")"
exec "${here}/jre/bin/java" \
  -Dorg.slf4j.simpleLogger.defaultLogLevel="${STS_JSCEP_LOG_LEVEL:-info}" \
  -Dorg.slf4j.simpleLogger.showDateTime=true \
  -cp "${here}/jscep-driver.jar:${here}/lib/*" \
  net.iyasec.sts.tests.JscepDriver "$@"
EOF
chmod 755 "${OUT}/jscep-driver"
"${OUT}/jscep-driver" 2>&1 | head -1
rm -rf "${work}"

# tests/Dockerfile — THE TEST RUNNER AS A CONTAINER.
#
# This is the image `docker-compose-run-tests.yml` builds for the `tests`
# service: node, a Chrome, this whole repository, and both node_modules trees.
# It runs tests/run-tests-in-container.sh, which drives EVERY job
# (tests/vendored/MANIFEST.js is the count and no number is written here —
# one was, said twenty-three, and was wrong within a fortnight)
# against the `sts` service beside it on the compose network and writes the
# report to a bind mount. Nothing on the host is needed but docker.
#
# It is this repository's answer to ../id-proto-debugger/tests/Dockerfile, and
# it is about eight hundred lines shorter for one reason: that image is
# assembled COPY by COPY out of a repository whose tests, borrowed modules and
# vendored client files live in five directories, and it hit Docker's 125-layer
# limit doing it. Here the tests ARE this repository — tests/ and tests/vendored/
# are committed files of this checkout — so one `COPY . ./` is the whole of it.
#
# ---------------------------------------------------------------------------
# WHY THE WHOLE REPOSITORY AND NOT JUST tests/.
#
# Three of the four kinds of job in this image reach outside that directory:
#
#   * the IN-PROCESS jobs (tests/*.js) require the service's own modules —
#     common/crypto.js, common/realms.js, the two map renderers, the Kerberos
#     codecs — because asserting a module contract is what they are for;
#   * several of the VENDORED protocol jobs load service modules too, and
#     find them through MOCK_STS_DIR, which run-report.js sets to the
#     repository root;
#   * `npm install` at the root needs package.json, package-lock.json, .npmrc
#     AND the node-ldapjs SUBMODULE, since `"ldapjs": "file:node-ldapjs"`.
#
# So this image is the source tree plus a browser. What it is NOT is the SERVICE
# under test: that is the `sts` container, built from the repository root's own
# Dockerfile, and the two are deliberately separate images so that a job here
# cannot accidentally drive an in-process copy of the code it is meant to be
# testing over HTTP.
#
# ---------------------------------------------------------------------------
# THE IGNORE FILE IS THE ROOT'S, SHARED WITH THE SERVICE IMAGE, AND THAT IS
# WHY THE SERVICE IMAGE DELETES tests/ IN ITS OWN Dockerfile.
#
# One build context serves both images and a context has exactly one ignore
# file. BuildKit would allow two — it prefers <dockerfile>.dockerignore beside
# the Dockerfile — and that WAS the arrangement here for exactly one build: the
# legacy builder ignores such a file completely, so on a machine whose docker
# has no buildx plugin this image failed with `COPY failed: no source files
# were specified` on a directory sitting right there in the checkout. A message
# naming neither the builder nor the ignore file.
#
# So `tests` is in the context for both, and ../Dockerfile removes it from the
# service image with an `rm` that carries its own reason. The guard after the
# COPY below is what a context missing the suite says instead of failing later
# inside node.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# THE FIVE CERTIFICATE ENROLLMENT CLIENTS (#207-#211, 2026-09-26), BUILT IN
# STAGES OF THEIR OWN AND COPIED INTO THE RUNNER BELOW.
#
# The ACME, EST and SCEP servers were only ever driven by this suite's own
# clients (tests/vendored/acme_client.js, est_client.js, scep_client.js),
# second readings of the RFCs written here. These are the real ones, each
# the client an operator of that protocol actually runs, each at ONE pinned
# version and each checked before it is built:
#
#   certbot 5.8.0        EFF, Apache-2.0. pip, every package hash-pinned in
#                        tests/tools/certbot-requirements.txt; installed in
#                        the runner itself (it is Python, not one binary).
#   lego v5.5.2          go-acme, MIT. `go install`, verified against the Go
#                        checksum database (sum.golang.org) — GOFLAGS leaves
#                        GONOSUMDB and GOFLAGS=-insecure unset on purpose.
#   scepclient v2.3.0    micromdm/scep, MIT. The same.
#   estclient a464ba8    cisco/libest, BSD-3-Clause. The head of `main`
#                        (2022-09-22; there is no later release). It does NOT
#                        build against OpenSSL 3 — FIPS_mode() is gone — so it
#                        is linked statically against OpenSSL 1.1.1w, the last
#                        1.1.1 release, whose tarball is sha256-checked too.
#                        `--disable-safec` (safeclib is not packaged);
#                        `--with-uriparser-dir` because without uriparser it
#                        ignores `--path-seg`, the EST label; and
#                        `--allow-multiple-definition` because its example
#                        client and its library both define
#                        ossl_dump_ssl_errors().
#   sscep cb3e539        certnanny, BSD-style. The head of `master`
#                        (2024-08-14): v0.10.0 (2021) cannot GetCert or GetCRL
#                        from a CA with a separate RA, fixed upstream in
#                        354acb8 after the tag. Built against the base's
#                        OpenSSL 3.
#
# AND TWO MORE SCEP CLIENTS (#249, #250, 2026-09-26):
#
#   certmonger 0.79.21   Red Hat, GPL-2.0+. The certificate-tracking daemon
#                        and its scep-submit helper, from Ubuntu 26.04's own
#                        package (universe), fetched from the archive's pool
#                        and held to its sha256 before apt installs it and
#                        its dependencies. Run, never vendored. Installed in
#                        the runner, below, because the job starts the daemon
#                        itself on a private socket (no D-Bus).
#   jscep 3.0.1          MIT (its pom; the ticket said Apache-2.0). A Java
#                        LIBRARY, so tests/tools/jscep-driver is a thin
#                        command line over it, built in the `enroll-java`
#                        stage: Maven resolves the jars, build.sh holds each
#                        to jars.sha256 and compiles the driver, and jlink
#                        makes a runtime of only the modules it uses — the
#                        runner gets that, the jars and the licences, and
#                        no JDK or Maven.
#
# NOTHING OF THEIRS IS VENDORED: each is fetched from its publisher at build
# time, each archive is held to a sha256 here, and a GitHub archive of a
# commit is byte-stable. Their licences are copied beside the binaries, into
# /opt/enroll-clients/licenses, since the image redistributes them.
# STAGES rather than layers of the runner so that the compilers, OpenSSL 1.1
# and the Go toolchain stay out of it; the legacy builder (no BuildKit here)
# builds every stage every time the cache misses, and each is cached like
# any other layer. tests/CLAUDE.md, *THE CERTIFICATE ENROLLMENT CLIENTS*,
# argues why here rather than a compose profile.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# THE THIRD-PARTY TEST CORPORA, BY DIGEST (#253, 2026-09-26). Five corpora
# this image used to fetch on nearly every build — the schemas, x509-limbo,
# NIST PKITS, the W3C XML security interop cases and Wycheproof with ACVP —
# come out of ONE image built by tests/corpora/Dockerfile (the same fetch
# scripts, the same sha256 checks) and kept PRIVATE on GitHub Container
# Registry. A build needs `docker login ghcr.io` with read:packages; CI logs
# in with GITHUB_TOKEN. Pinned by DIGEST, so what a run reads is exactly
# what was verified when the image was built; tests/tools/build-corpora-image.sh
# rebuilds it after a pin changes and rewrites this line.
# ---------------------------------------------------------------------------
ARG STS_CORPORA_IMAGE=ghcr.io/rcbj/iya-sts-test-corpora@sha256:ef3797760cc8b1bc414ffcc9130aadd132e9a2f8bc0f950c75275ebbb3b92838
FROM ${STS_CORPORA_IMAGE} AS corpora

FROM golang:1.26.8-bookworm AS enroll-go
ENV CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local
RUN go install github.com/go-acme/lego/v5@v5.5.2 \
 && go install github.com/micromdm/scep/v2/cmd/scepclient@v2.3.0 \
 && mkdir -p /out/licenses \
 && cp /go/bin/lego /go/bin/scepclient /out/ \
 && cp /go/pkg/mod/github.com/go-acme/lego/v5@v5.5.2/LICENSE \
       /out/licenses/lego.LICENSE \
 && cp /go/pkg/mod/github.com/micromdm/scep/v2@v2.3.0/LICENSE \
       /out/licenses/micromdm-scep.LICENSE \
 && /out/lego --version

FROM ubuntu:latest AS enroll-c
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        ca-certificates curl gcc make perl autoconf automake libtool \
        pkg-config libc6-dev liburiparser-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ENV OPENSSL_SHA256=cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8
ENV LIBEST_COMMIT=a464ba8a66717419ba71d289ef82c7b2315b2006
ENV LIBEST_SHA256=2e5c46610f6a3c12c1916c8a84de77421a88c9722e776e862a716f4a48220f2a
ENV SSCEP_COMMIT=cb3e539818fdab46bf3812f44730d0999d3cc9b3
ENV SSCEP_SHA256=98eeb34e1bba453f6457d1f716a8694f15e1b4bd353bbd54ad6e0a3125099026
RUN curl -fsSL --retry 5 --retry-all-errors -o openssl.tgz \
        https://www.openssl.org/source/openssl-1.1.1w.tar.gz \
 && echo "${OPENSSL_SHA256}  openssl.tgz" | sha256sum -c - \
 && tar xzf openssl.tgz && cd openssl-1.1.1w \
 && ./config --prefix=/opt/openssl11 no-shared no-tests \
 && make -j"$(nproc)" >/dev/null && make install_sw >/dev/null
RUN curl -fsSL --retry 5 --retry-all-errors -o libest.tgz \
        https://github.com/cisco/libest/archive/${LIBEST_COMMIT}.tar.gz \
 && echo "${LIBEST_SHA256}  libest.tgz" | sha256sum -c - \
 && tar xzf libest.tgz && cd libest-${LIBEST_COMMIT} \
 && ./configure --prefix=/opt/libest --with-ssl-dir=/opt/openssl11 \
      --disable-safec --with-uriparser-dir=/usr --enable-static \
      --disable-shared LDFLAGS="-Wl,--allow-multiple-definition" \
      LIBS="-ldl -lpthread" >/dev/null \
 && make -j"$(nproc)" >/dev/null && make install >/dev/null \
 && mkdir -p /out/licenses && cp /opt/libest/bin/estclient /out/ \
 && cp LICENSE /out/licenses/libest.LICENSE
RUN curl -fsSL --retry 5 --retry-all-errors -o sscep.tgz \
        https://github.com/certnanny/sscep/archive/${SSCEP_COMMIT}.tar.gz \
 && echo "${SSCEP_SHA256}  sscep.tgz" | sha256sum -c - \
 && tar xzf sscep.tgz && cd sscep-${SSCEP_COMMIT} \
 && (./bootstrap.sh || autoreconf -fi) >/dev/null \
 && ./configure --prefix=/opt/sscep >/dev/null \
 && make -j"$(nproc)" >/dev/null && cp sscep /out/ \
 && cp COPYING /out/licenses/sscep.COPYING

# jscep, THROUGH ITS DRIVER (#250): see the header and
# tests/tools/jscep-driver/build.sh, which argues every step. The Maven image
# is pinned by tag; what reaches the runner is pinned by sha256.
FROM maven:3.9.16-eclipse-temurin-21-noble AS enroll-java
COPY tests/tools/jscep-driver /usr/src/jscep-driver
RUN /usr/src/jscep-driver/build.sh /usr/src/jscep-driver /out/jscep

# THE SECOND SCIM HARNESS, COMPILED IN A STAGE OF ITS OWN (#206).
# scim2/test-suite is Go, and a Go toolchain in the runner image would be
# ~600 MB for one binary; so it is fetched at a pinned commit, checked by
# sha256 and compiled here, and the runner below copies only the binary, its
# LICENSE and its COMMIT. tests/scim-conformance/build-test-suite.sh argues
# the pin; tests/CLAUDE.md, *The SCIM conformance harnesses*, is the
# provenance. The golang image is Debian, whose glibc is older than
# ubuntu:latest's, so the binary (cgo, for a store only its built-in server
# uses) runs in the runner unchanged.
# THE W3C VERIFIABLE CREDENTIALS AND DID TEST SUITES (#194-#199), each
# fetched at a pinned commit, checked by sha256 and installed from its own
# lockfile by tests/vc-suites/fetch-suites.sh (which argues the pins and why
# the suites' `pretest` is not run). A stage of their own, on the same node
# as the runner, because the install needs git (two lockfile dependencies
# are GitHub commits) and the runner has none; the runner copies only
# /opt/vc-suites. Several carry test PRIVATE keys, which is why they are
# fetched here and never committed. tests/CLAUDE.md, *The W3C VC and DID
# suites*, is the provenance.
FROM node:24.16.0-bookworm AS vc-suites
COPY tests/vc-suites/fetch-suites.sh /usr/src/fetch-suites.sh
RUN /usr/src/fetch-suites.sh /opt/vc-suites

FROM golang:1.26 AS scim2-test-suite
COPY tests/scim-conformance/build-test-suite.sh /usr/src/build-test-suite.sh
RUN /usr/src/build-test-suite.sh /opt/scim2-test-suite

FROM ubuntu:latest

# replace shell with bash so we can source files (the nvm install below needs it)
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# apt-get update and apt-get install are ONE RUN on purpose, and splitting them
# apart breaks this build on a schedule nothing in this repository controls. A
# `RUN apt-get update` of its own is a LAYER, and Docker reuses it for as long
# as every instruction above it is unchanged — so the package index baked into
# that layer goes on naming versions that archive.ubuntu.com has already
# dropped from the pool, and every -updates/-security package in the list 404s
# at once. The step that fails is the INSTALL, which reads as a broken mirror
# and is not one. Joined, the two cannot disagree.
#
# WHAT EACH GROUP IS FOR:
#
#   curl, wget, unzip   fetching nvm and Chrome below, and the readiness probe
#                       in run-tests-in-container.sh.
#   ca-certificates     TLS to the download hosts; ubuntu:latest has it, and
#                       naming it means a slimmer base later cannot silently
#                       take it away.
#   libnss3 … xdg-utils Chrome's own shared-library dependencies. Chrome for
#                       Testing is a ZIP rather than a .deb, so nothing pulls
#                       them in for us: without them the browser exits before
#                       it prints anything and selenium reports only that the
#                       session could not be created.
#   fonts-liberation    metric-compatible Arial. The console job asserts
#                       nothing about geometry today, but a headless Chrome
#                       with NO font package at all renders boxes, and a
#                       screenshot taken to read a failure is then unreadable.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install curl \
        wget \
        unzip \
        jq \
        ca-certificates \
        fonts-liberation \
        libatomic1 \
        libasound2t64 \
        libatk-bridge2.0-0 \
        libgtk-4-1 \
        libnss3 \
        xdg-utils

# The same WORKDIR as the service image, so a path read out of a log here means
# the same thing as one read out of the `sts` container's log.
WORKDIR /usr/src/sts

# Install NVM, and the SAME node the service image installs. That is the point
# of naming a version rather than taking a node: base image — a suite that runs
# on a different node from the service it drives can pass on a syntax the
# service cannot parse.
ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION=24.16.0
RUN mkdir -p ${NVM_DIR}
RUN set -o pipefail && curl -fsSL --retry 5 --retry-all-errors --retry-delay 10 https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.5/install.sh | bash
RUN . $NVM_DIR/nvm.sh && nvm version && echo -e ". $NVM_DIR/nvm.sh\nexport PATH=\$NVM_DIR/versions/node/\$(nvm version)/bin:\$PATH" >> ~/.bashrc
RUN source $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default
ENV NODE_PATH $NVM_DIR/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH
RUN node -v && npm -v

# ---------------------------------------------------------------------------
# CHROME AND CHROMEDRIVER, PINNED, AND INSTALLED ABOVE THE SOURCE COPY.
#
# Above it because a layer's cache key includes its parent: with this below the
# COPY, editing one line of one test would re-download ~200 MB of browser.
#
# THE VERSION IS NOT THE PARENT PROJECT'S, AND THAT IS DELIBERATE. That image
# pins 121.0.6167.85, and its own comments explain what it works around there
# (Web Crypto Ed25519 behind a flag). The browser jobs here drive this
# service's console, and tests/vendored/sts_admin_console.js reads status codes
# and headers through WEBDRIVER BiDi (`network.responseCompleted`), because
# `default-src 'none'` on the console is the thing under test and blocks a
# `fetch()` from the page. BiDi network events are a recent Chrome, so this
# pins a current stable one instead.
# The version and the driver version are the SAME string on purpose: a
# chromedriver that does not match its browser fails at session creation with a
# message about a version, which is at least the truth, and a mismatch of one
# major is the commonest way a browser job "suddenly" stops working.
#
# The download host is Google's own Chrome-for-Testing bucket. The parent uses
# edgedl.me.gvt1.com, which redirects here.
ENV CHROME_VERSION=152.0.7977.64
RUN wget -q -O chrome-linux64.zip https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chrome-linux64.zip && \
    unzip -q chrome-linux64.zip && \
    rm chrome-linux64.zip && \
    mv chrome-linux64 /opt/chrome/ && \
    ln -s /opt/chrome/chrome /usr/local/bin/chrome && \
    ln -s /opt/chrome/chrome /usr/local/bin/google-chrome && \
    wget -q -O chromedriver-linux64.zip https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VERSION}/linux64/chromedriver-linux64.zip && \
    unzip -q -j chromedriver-linux64.zip chromedriver-linux64/chromedriver && \
    rm chromedriver-linux64.zip && \
    mv chromedriver /usr/local/bin/ && \
    chrome --version && chromedriver --version

# ---------------------------------------------------------------------------
# THE TWO node_modules TREES, AND THEY ARE TWO FOR THE REASON tests/package.json
# ARGUES AT LENGTH.
#
# The root package carries `omit=dev` in .npmrc — it is what keeps ldapjs's ~200
# test packages out of the service image — so a devDependency added there for
# the suite would be SILENTLY not installed. The test dependencies (commander,
# selenium-webdriver, the @noble pins the vendored wallet modules verify
# against) therefore live in tests/package.json, one directory down, where
# `omit=dev` does not reach them.
#
# Both installs happen BEFORE the source copy so that editing a test does not
# reinstall either tree. node-ldapjs is copied first for the same reason and
# because `"ldapjs": "file:node-ldapjs"` cannot resolve without it: an
# uninitialised submodule is an EMPTY DIRECTORY, npm installs a package with no
# `main`, and the failure arrives much later as `Cannot find module 'ldapjs'` —
# a message naming a package rather than a checkout. The guard after the copy
# is what turns that into a sentence.
# A C COMPILER FOR build-native.sh (#40, 2026-09-21), in a layer of its own
# BELOW the source copy and ABOVE nothing that downloads a browser, so that
# adding it cost no cached Chrome layer. See the service Dockerfile.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
# MIT KERBEROS FOR sts_kerberos_keytab.js (#59, 2026-09-22): `kinit -k -t` and
# `klist -k` against a keytab the service handed out, so the file is used by
# the client every other Kerberos deployment uses rather than only by this
# suite's own. Its own layer below the source copy, for the compiler's
# reason; noninteractive, because the package otherwise asks for a default
# realm.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        krb5-user \
    && rm -rf /var/lib/apt/lists/*
# THE CERTIFICATE ENROLLMENT CLIENTS (#207-#211), from the two stages at the
# top of this file, and certbot, which is Python and is installed here into
# a venv of its own from the hash-pinned list. liburiparser1 is estclient's
# one shared library beyond libc; sscep links the base's OpenSSL 3, which
# ca-certificates already brought in, and the `openssl` command the jobs
# make their keys and requests with at run time.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        python3 python3-venv liburiparser1 openssl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=enroll-go /out/ /opt/enroll-clients/
COPY --from=enroll-c /out/ /opt/enroll-clients/
COPY tests/tools/certbot-requirements.txt /opt/enroll-clients/certbot-requirements.txt
RUN python3 -m venv /opt/certbot \
 && /opt/certbot/bin/pip install --no-cache-dir --require-hashes --no-deps \
      -r /opt/enroll-clients/certbot-requirements.txt \
 && ln -s /opt/certbot/bin/certbot /usr/local/bin/certbot \
 && for b in lego scepclient estclient sscep; do \
      ln -s /opt/enroll-clients/$b /usr/local/bin/$b; done \
 && certbot --version && lego --version && (sscep 2>&1 | head -2) \
 && ldd /opt/enroll-clients/estclient
# THE PUBLISHED XML SCHEMAS AND A VALIDATOR FOR THEM (#188, 2026-09-24):
# libxml2's `xmllint`, and every OASIS and W3C schema
# tests/vendored/sts_xml_schema_validation.js validates this service's SAML,
# WS-Trust and WS-Federation documents against — FETCHED here, each checked
# against the sha256 in tests/xml-schemas/SCHEMAS (the build fails on a
# single differing byte), with the catalogue that lets the job run
# `xmllint --nonet` so nothing is fetched while the suite runs. Nothing is
# vendored: the list, the catalogue and the driver schema are this
# repository's, the schemas are their publishers'. Its own layers below the
# compiler's, and above the source copy so that editing a test re-fetches
# nothing; only the two paths the fetch reads are copied first.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        libxml2-utils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=corpora /opt/xml-schemas /opt/xml-schemas
ENV STS_XML_SCHEMA_DIR=/opt/xml-schemas
# THE FIRST SCIM HARNESS (#206): python-scim's scim2-tester, into a virtual
# environment of its own, every package pinned to a version AND a sha256
# (--require-hashes; tests/scim-conformance/requirements.txt says how to
# re-pin). And the second, compiled in the stage at the top of this file.
# tests/vendored/sts_scim_conformance.js runs both. Above the source copy,
# for the schemas' reason.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
COPY tests/scim-conformance/requirements.txt /usr/src/scim2-tester/requirements.txt
RUN python3 -m venv /opt/scim2-tester \
    && /opt/scim2-tester/bin/pip install --no-cache-dir --require-hashes \
        -r /usr/src/scim2-tester/requirements.txt
ENV STS_SCIM2_TESTER_PYTHON=/opt/scim2-tester/bin/python
COPY --from=scim2-test-suite /opt/scim2-test-suite /opt/scim2-test-suite
ENV STS_SCIM2_TEST_SUITE=/opt/scim2-test-suite/scim-compliance
COPY package*.json ./
COPY .npmrc ./
COPY node-ldapjs ./node-ldapjs
RUN if [ ! -f node-ldapjs/package.json ]; then \
      echo "node-ldapjs/ is EMPTY in the build context. It is a git submodule," >&2; \
      echo "and this repository is itself one, so it needs:" >&2; \
      echo "    git submodule update --init --recursive" >&2; \
      echo "Without it npm installs a package with no main and the jobs that" >&2; \
      echo "load the directory die with Cannot find module 'ldapjs'." >&2; \
      exit 1; \
    fi
RUN npm install --omit=dev && npm cache clean --force
COPY tests/package*.json ./tests/
RUN npm install --prefix ./tests && npm cache clean --force

# ---------------------------------------------------------------------------
# C2SP x509-LIMBO FOR tests/x509_limbo.js (#201), FETCHED HERE AND NEVER
# COMMITTED: about two hundred of its cases carry a leaf's private key, and
# this repository commits no key material. The script pins a commit and the
# SHA-256 of what it fetches, and fails the build on anything else. Its own
# layer above the source copy, so editing a test does not download forty
# megabytes again; outside /usr/src/sts, so neither copy of the tree holds it.
# ---------------------------------------------------------------------------
COPY --from=corpora /usr/src/corpora/x509-limbo /usr/src/corpora/x509-limbo
ENV STS_X509_LIMBO_DIR=/usr/src/corpora/x509-limbo
# NIST PKITS FOR tests/nist_pkits.js (#201), from csrc.nist.gov, with the test
# table BoringSSL transcribed from PKITS.pdf — each pinned by SHA-256, never
# committed (the data carries a PKCS #12 of every private key; only certs/
# and crls/ are unpacked).
COPY --from=corpora /usr/src/corpora/nist-pkits /usr/src/corpora/nist-pkits
ENV STS_NIST_PKITS_DIR=/usr/src/corpora/nist-pkits

# THE W3C XML SIGNATURE AND XML ENCRYPTION INTEROP CASES (#193), for
# tests/w3c_xmlsec.js. They carry PRIVATE KEYS, so they are never committed:
# the script downloads a fixed list, each file pinned by sha256, and FAILS
# THE BUILD on a mismatch. Above the source copy, with only its two inputs
# copied first, so that editing a test does not fetch ~340 paced requests
# again. tests/tools/W3C-XMLSEC-PROVENANCE.md says where they come from.
COPY --from=corpora /usr/src/corpora/w3c-xmlsec /usr/src/corpora/w3c-xmlsec
ENV STS_W3C_XMLSEC_DIR=/usr/src/corpora/w3c-xmlsec

# THE EXTERNAL TEST VECTORS (#202, #203): C2SP Wycheproof (Apache-2.0) and
# NIST ACVP (public domain), for tests/wycheproof.js and tests/acvp_pqc.js.
# Fetched HERE, at a pinned commit, each checked against
# tests/tools/vectors.sha256 — a mismatch fails the build — because both
# carry test keys and this repository commits no key material. Above the
# source copy so the ~130 MB is fetched once and cached until the script or
# the checksums change; tests/vectors is in .dockerignore, so `COPY . ./`
# below cannot replace it with a host copy. tests/CLAUDE.md, *The external
# test vectors*, is the provenance.
COPY --from=corpora /usr/src/sts/tests/vectors /usr/src/sts/tests/vectors

# The W3C VC and DID suites (#194-#199), from their stage above. Here, just
# above the source copy, rather than beside the other harnesses: this layer
# changes only when fetch-suites.sh does, and every layer above it stays the
# one other checkouts' builds of this file already cached.
COPY --from=vc-suites /opt/vc-suites /opt/vc-suites
ENV STS_VC_SUITES_DIR=/opt/vc-suites

# THE LAST TWO SCEP CLIENTS (#249, #250), here rather than beside the other
# three so that adding them rebuilt no layer above. certmonger is Ubuntu's
# own package, pinned by its archive path and sha256 and installed with apt
# so its libraries come from the same release; its postinst cannot start a
# service in a container and does not need to — the job runs the daemon.
# jscep is its driver, runtime and licences from the `enroll-java` stage.
ENV CERTMONGER_DEB=certmonger_0.79.21-1_amd64.deb
ENV CERTMONGER_SHA256=75180fdc2eef1d94f1dfe63703671ed599fe58b654257fb8a792153481ec842e
RUN curl -fsSL --retry 5 --retry-all-errors -o /tmp/${CERTMONGER_DEB} \
        http://archive.ubuntu.com/ubuntu/pool/universe/c/certmonger/${CERTMONGER_DEB} \
 && echo "${CERTMONGER_SHA256}  /tmp/${CERTMONGER_DEB}" | sha256sum -c - \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        /tmp/${CERTMONGER_DEB} \
 && rm -rf /var/lib/apt/lists/* /tmp/${CERTMONGER_DEB} \
 && certmonger -v && test -x /usr/lib/certmonger/scep-submit
COPY --from=enroll-java /out/jscep /opt/enroll-clients/jscep
RUN ln -s /opt/enroll-clients/jscep/jscep-driver /usr/local/bin/jscep-driver \
 && (jscep-driver 2>&1 | head -1)

# The repository. The root .dockerignore decides what is in it — see the header
# — and the guard is what a context missing the suite says instead of failing
# eighty lines later inside node with a message about a module.
COPY . ./
RUN if [ ! -f tests/tools/run-report.js ]; then \
      echo "tests/ is missing from the build context, so there is nothing" >&2; \
      echo "for this image to run. Something has put tests/ back into the" >&2; \
      echo "repository root's .dockerignore — it must NOT be there: that file" >&2; \
      echo "is shared with the service image, which removes the directory" >&2; \
      echo "itself instead (see ../Dockerfile's rm and .dockerignore's own" >&2; \
      echo "comment for the builder reason)." >&2; \
      exit 1; \
    fi

# ---------------------------------------------------------------------------
# THE TYPESCRIPT, COMPILED IN THIS IMAGE AND KEPT BESIDE ITS OUTPUT (#50).
#
# The jobs require the service's modules by path from /usr/src/sts, so the
# tree here is compiled in place — `build-typescript.sh` emits each `x.js`
# beside its `x.ts` — exactly as the service image's `typescript` stage does.
# Unlike that stage it does NOT strip the sources: this is a test harness, not
# the shipped image, and `tests/typecheck.js` has to read them.
#
# **IT READS A PRISTINE COPY, /usr/src/sts-source**, taken before compiling.
# In the compiled tree a `.ts` has a `.js` twin, which that test treats as a
# compiled artifact where none may be (the host rule), and which would itself
# be type-checked as a second copy of the module. The copy borrows this
# tree's two `node_modules` by link, for the types.
# ---------------------------------------------------------------------------
COPY . /usr/src/sts-source/
RUN ln -s /usr/src/sts/node_modules /usr/src/sts-source/node_modules \
 && ln -s /usr/src/sts/tests/node_modules \
          /usr/src/sts-source/tests/node_modules \
 && STS_IN_IMAGE_BUILD=1 ./build-typescript.sh \
 && STS_IN_IMAGE_BUILD=1 ./build-native.sh
ENV STS_TYPECHECK_ROOT=/usr/src/sts-source

# The report is written here and bind-mounted out by the compose file. Created
# in the image so that a run with NO mount still writes somewhere real rather
# than failing at the end of a passing suite.
RUN mkdir -p tests/report

# ---------------------------------------------------------------------------
# The jobs' own settings, as environment rather than as arguments, so that
# `docker compose run tests <anything>` still gets them.
#
# CONFIG_FILE is the appconfig layer the JOBS read for a log level, not the
# service's — run-report.js overrides it per protocol job to ./env/local.js
# relative to tests/vendored/. This one is for the runner itself.
ENV CONFIG_FILE=./env/local.js
# Where the service is, on the compose network. run-tests-in-container.sh passes
# it to run-report.js as --service-url and waits for it first; the compose file
# sets it too, and this default is what makes a hand-run `docker run` on the
# same network work with nothing else said.
# https since 2026-08-30: the service's main port is TLS on every stack in this
# repository. The certificate is regenerated on every start of that service, so
# there is deliberately no anchor for it in this image — run-report.js fetches
# it once the service answers and hands it to each job as NODE_EXTRA_CA_CERTS
# and STS_SPKI_PIN (tests/tools/trust.js). Baking one in would be a truststore
# that is wrong for every run after the one that built it.
ENV STS_TEST_SERVICE_URL=https://sts:8081
# The directory's own socket, for sts_directory_bulk_load_ldap.js. It exists
# for the reason the line above does: a hand-run `docker run` on the same
# network needs no environment, and a rename needs one edit. Nothing is
# published anywhere in that stack — this container is on the bridge with the
# service and reaches 389 directly, which is why the local launcher, whose
# runner is a host process, has to layer a compose file to get the same thing.
ENV STS_LDAP_URL=ldap://sts:389

CMD [ "./tests/run-tests-in-container.sh" ]

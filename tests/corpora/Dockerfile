# File: tests/corpora/Dockerfile
#
# ===========================================================================
# THE THIRD-PARTY TEST CORPORA, AS ONE IMAGE (#253, 2026-09-26).
#
# tests/Dockerfile fetched five corpora on every build that changed anything
# above them — and the package files, node-ldapjs and both npm installs ARE
# above them, so nearly every build: the OASIS/W3C XML schemas (#188),
# x509-limbo and NIST PKITS (#201), the ~340 W3C XML Signature and XML
# Encryption interop files (#193), and Wycheproof and NIST ACVP (#202, #203).
# On 2026-09-26 w3.org answered 429 to every build for an hour and no test
# run could start.
#
# So they are fetched HERE, once per change to a pin, by the SAME scripts
# with the SAME sha256 checks — a file that does not match fails this build
# exactly as it failed that one — and the result is pushed to GitHub
# Container Registry, PRIVATE, as ghcr.io/rcbj/iya-sts-test-corpora
# (tests/tools/build-corpora-image.sh). tests/Dockerfile copies them out of
# that image pinned by DIGEST, so what a test run reads is byte for byte what
# was verified here.
#
# PRIVATE, NOT PUBLIC: the W3C cases and the PKI corpora carry the published
# test PRIVATE KEYS of their suites. Nothing in this image is committed to
# git (the no-key-material rule), and the registry package stays private
# (rcbj, 2026-09-26: "keep everything private").
#
# The final stage is `scratch`: the image holds the files and nothing that
# runs, because it is only ever a source for `COPY --from`.
#
# Build context: the repository root (only the fetch scripts, their lists and
# tests/xml-schemas are copied).
# ===========================================================================

FROM debian:bookworm-slim AS fetch
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        ca-certificates curl unzip gzip tar coreutils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build

# The layout the scripts expect: fetch-xml-schemas.sh reads its local schema
# files from ../xml-schemas beside itself, and fetch-vectors.sh its list from
# its own directory.
COPY tests/xml-schemas ./tests/xml-schemas
COPY tests/tools/fetch-xml-schemas.sh tests/tools/fetch-x509-limbo.sh \
     tests/tools/fetch-nist-pkits.sh tests/tools/fetch-w3c-xmlsec.sh \
     tests/tools/w3c-xmlsec.sha256 tests/tools/fetch-vectors.sh \
     tests/tools/vectors.sha256 ./tests/tools/

# One RUN per corpus, so a pin changed in one list refetches that corpus and
# no other.
RUN ./tests/tools/fetch-xml-schemas.sh /out/opt/xml-schemas
RUN ./tests/tools/fetch-x509-limbo.sh /out/usr/src/corpora/x509-limbo
RUN ./tests/tools/fetch-nist-pkits.sh /out/usr/src/corpora/nist-pkits
RUN ./tests/tools/fetch-w3c-xmlsec.sh ./tests/tools/w3c-xmlsec.sha256 \
      /out/usr/src/corpora/w3c-xmlsec
RUN ./tests/tools/fetch-vectors.sh /out/usr/src/sts/tests/vectors

FROM scratch
COPY --from=fetch /out/ /

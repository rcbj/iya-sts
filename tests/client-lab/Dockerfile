# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# ===========================================================================
# sts-client-lab (#2056, umbrella #2055): REAL CLIENT SOFTWARE AND VIRTUAL
# SMART CARDS standing in for a YubiKey, for the realistic jobs #2057-#2062.
# tests/CLAUDE.md, *THE CLIENT LAB*, argues it.
#
# **A TEST IMAGE, AND NOTHING OF IT REACHES THE PRODUCT IMAGE** (rcbj,
# 2026-11-23). It lives under tests/, which the product Dockerfile deletes
# from its tree, and it is built only by docker-compose-run-tests.yml and by
# hand; tests/client_lab_isolation.js fails if the product Dockerfile's
# final stage could carry this directory or any package installed here.
#
# Two cards, each a jcardsim (Apache-2.0) process holding one applet, each
# plugged into its own slot of vsmartcard's vpcd (GPL-3.0), the PC/SC
# driver pcscd loads:
#
#   slot 0, port 35963  SmartPGP (ANSSI-FR, GPL-2.0)  an OpenPGP card 3.4
#   slot 1, port 35964  PivApplet (arekinath, MPL-2.0) YubiKey-style PIV,
#                       attestation (slot f9) included
#
# The applets and jcardsim are BUILT FROM SOURCE here, each at the commit
# pinned below; nothing of theirs is in this repository. jcardsim compiles
# against Oracle's Java Card 3.0.5 classic API jar, fetched from
# martinpaljak/oracle_javacard_sdks at a pinned commit and checked against a
# pinned SHA-256 (it is the only binary the build takes as given).
#
# NOTHING HERE IS A KEY: every key, certificate, PIN and card serial is made
# when the container starts or when a job asks (`bin/`).
# ===========================================================================

# ---------------------------------------------------------------------------
# THE CARDS: jcardsim and the two applets, compiled to class files. jcardsim
# runs a Java Card applet from its class files without converting it to a
# CAP, so no Java Card converter (and no ant-javacard) is needed.
# ---------------------------------------------------------------------------
FROM maven:3.9.16-eclipse-temurin-21-noble AS cards

# THE PINS (tests/CLAUDE.md, *THE CLIENT LAB*, lists them with their dates).
ARG JCARDSIM_COMMIT=7cd4b51db322e9b7f8bb883e3832197892504b99
ARG SMARTPGP_COMMIT=da52ec4d6baa2b8f5bf8de35e7932572bb96b161
ARG PIVAPPLET_COMMIT=5cb14a9e8d16e92fbad73dcad86a219a9210554f
ARG JCSDK_COMMIT=700ec80afdda210a0e62fb6a151a9cddc1acd244
ARG JCSDK_API_SHA256=686c789a2a7a0176366b45dbe1971c02b4d24f8a185ae0aee7c67fedfaed4bc0

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        git ant ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY build-cards.sh ./
COPY patches/ ./patches/
RUN JCARDSIM_COMMIT="${JCARDSIM_COMMIT}" SMARTPGP_COMMIT="${SMARTPGP_COMMIT}" \
    PIVAPPLET_COMMIT="${PIVAPPLET_COMMIT}" JCSDK_COMMIT="${JCSDK_COMMIT}" \
    JCSDK_API_SHA256="${JCSDK_API_SHA256}" bash ./build-cards.sh /opt/cards

# ---------------------------------------------------------------------------
# THE LAB: the clients, pcscd and vpcd, a Java runtime for the cards, and
# node for the agent a job drives the lab through (lab_agent.js). The node
# image the test peer is built on, from the ghcr.io mirror.
# ---------------------------------------------------------------------------
FROM node:24.22.1-bookworm-slim

# postfix asks its questions through debconf; the answers are set first so
# the install does not stop. The mail name is replaced at start.
RUN echo "postfix postfix/main_mailer_type select Local only" \
      | debconf-set-selections \
 && echo "postfix postfix/mailname string client-lab" \
      | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        openjdk-17-jre-headless \
        pcscd vsmartcard-vpcd libccid pcsc-tools \
        opensc yubico-piv-tool \
        gnupg scdaemon gpg-agent dirmngr \
        openssh-client openssh-server \
        postfix bsd-mailx \
        oathtool libpam-yubico pamtester \
        krb5-user \
        ldap-utils \
        curl openssl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*

COPY --from=cards /opt/cards /opt/cards
WORKDIR /opt/client-lab
COPY lab-start.sh card-lib.sh lab_agent.js ./
COPY bin/ ./bin/
RUN chmod 0755 lab-start.sh bin/*

# ROOT, ON PURPOSE: pcscd, sshd and postfix are system daemons, and the lab
# writes into the shared volume another container may have created (the
# test peer's reason). It listens on an unpublished port of a private
# bridge and holds nothing but keys it made for this run.
ENV CLIENT_LAB_PORT=9610
EXPOSE 9610
CMD ["/opt/client-lab/lab-start.sh"]

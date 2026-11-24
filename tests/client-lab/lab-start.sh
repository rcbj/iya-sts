#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: tests/client-lab/lab-start.sh
#
# ---------------------------------------------------------------------------
# THE CLIENT LAB'S START (#2056): pcscd with vpcd's two slots, the OpenPGP
# card and the PIV card plugged in (card-lib.sh), and then the agent a job
# drives the lab through (lab_agent.js), in the foreground. sshd and postfix
# are installed and NOT started: the job that needs one configures it (its
# CA, its relay) and starts it, so no job inherits another's daemon.
#
# EVERY CARD IS NEW AT EVERY START: a factory-fresh OpenPGP card (PINs
# 123456 and 12345678, a random serial) and a factory-fresh PIV card (PIN
# 123456, PUK 12345678, the well-known management key, a random serial, a
# self-signed f9 attestation key until a job certifies one).
#
#   CLIENT_LAB_CARDS=none     start no card (the agent and the clients only)
#   CLIENT_LAB_PIV=stock      start the PIV card as stock PivApplet; the
#                             default is `yubikey` (bin/lab-piv-card
#                             switches a running lab)
#
# Log lines go to stdout, which compose captures (00-client-lab.log).
# ---------------------------------------------------------------------------
set -euo pipefail

# shellcheck source=tests/client-lab/card-lib.sh
. /opt/client-lab/card-lib.sh
mkdir -p "${RUN}"

# pcscd in the foreground of its own, so its log is ours; it loads vpcd,
# which listens on 35963 and 35964 for a card to connect.
say "starting pcscd"
pcscd --foreground --error > "${RUN}/pcscd.log" 2>&1 &
echo $! > "${RUN}/pcscd.pid"
for i in $(seq 1 40); do
  if opensc-tool -l > /dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

if [ "${CLIENT_LAB_CARDS:-all}" != "none" ]; then
  start_openpgp_card
  start_piv_card "${CLIENT_LAB_PIV:-yubikey}"
  say "both cards are in their readers"
fi

say "the agent listens on ${CLIENT_LAB_PORT:-9610}"
exec node "${LAB}/lab_agent.js"

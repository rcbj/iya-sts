#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# run.sh — load people into 8081's default realm. See load-users.js for settings.
#   ./run.sh                 1,000,000 people, 8 connections
#   COUNT=10000 ./run.sh     a smaller run
# Safe to stop with Ctrl-C and run again: it resumes from load-users.state.json.
cd "$(dirname "$0")" || exit 1
# hostPath(): node.exe reads C:/..., not /cygdrive/c/... (#512).
. ../tests/tools/host-platform.sh
export NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-$(hostPath "$PWD/ca.pem")}"
exec node load-users.js "$@" 2>&1 | tee -a load-users.log

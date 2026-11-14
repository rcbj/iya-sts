#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# run-sessions.sh — node sessions.js with the service's Root trusted; output to sessions.log.
cd "$(dirname "$0")" || exit 1
# hostPath(): node.exe reads C:/..., not /cygdrive/c/... (#512).
. ../../tests/tools/host-platform.sh
export NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-$(hostPath "$PWD/../ca.pem")}"
exec node --no-warnings=ExperimentalWarning sessions.js "$@" 2>&1 | tee -a sessions.log

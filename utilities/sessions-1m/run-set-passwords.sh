#!/bin/bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# run-set-passwords.sh — node set-passwords.js with the service's Root trusted; output to set-passwords.log.
cd "$(dirname "$0")" || exit 1
export NODE_EXTRA_CA_CERTS="${NODE_EXTRA_CA_CERTS:-$PWD/../ca.pem}"
exec node --no-warnings=ExperimentalWarning set-passwords.js "$@" 2>&1 | tee -a set-passwords.log

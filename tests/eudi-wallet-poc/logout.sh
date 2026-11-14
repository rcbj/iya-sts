#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# Global logout of whoever is signed in to the 8081 portal in the headless Chrome.
S=$(dirname "$0"); C="node $S/cdp.js"
$C goto https://localhost:8081/logout >/dev/null
$C wait "[...document.querySelectorAll('button')].find(b=>/Global logout/.test(b.textContent)) || /signed out/i.test(document.body.innerText)" 15000 >/dev/null
$C eval "(()=>{const b=[...document.querySelectorAll('button')].find(b=>/Global logout/.test(b.textContent)); b&&b.click(); return 1})()" >/dev/null
sleep 3; $C eval "/Signed out everywhere|You are signed out/.test(document.body.innerText)"

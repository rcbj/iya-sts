#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# Ends only the browser sign-on session (and its RP sessions) at /logout,
# leaving issued credentials alone.
S=$(dirname "$0"); C="node $S/cdp.js"
$C goto https://localhost:8081/logout >/dev/null
$C wait "document.querySelector('input[value^=\"session:\"]')" 15000 >/dev/null
$C eval "(()=>{const f=[...document.querySelectorAll('form')].find(f=>f.querySelector('input[value^=\"session:\"]')); f.querySelectorAll('input[type=checkbox]').forEach(c=>c.checked=true); [...f.querySelectorAll('button')].find(b=>/ticked/.test(b.textContent)).click(); return 1})()" >/dev/null
sleep 3; $C eval "/Signed out of what was ticked/.test(document.body.innerText)"

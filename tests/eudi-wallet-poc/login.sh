#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# Password sign-in to the 8081 portal as $WUSER (default walletuser2) in the
# running headless Chrome; the password is read from $WUSER.pw beside this file.
S=$(dirname "$0"); C="node $S/cdp.js"
$C goto https://localhost:8081/portal >/dev/null
$C wait "document.querySelector('input[name=realm]') || document.querySelector('#username')" 15000 >/dev/null
$C eval "(()=>{const r=document.querySelector('input[name=realm]'); if(!r) return 0; r.value='default'; [...document.querySelectorAll('button')].find(b=>/Continue/.test(b.textContent)).click(); return 1})()" >/dev/null
$C wait "document.querySelector('#username')" 15000 >/dev/null
$C eval "(()=>{document.querySelector('#username').value='${WUSER:-walletuser2}'; document.querySelector('#password').value=$(jq -Rn --rawfile p $S/${WUSER:-walletuser2}.pw '$p'); document.querySelector('#kc-login').click(); return 1})()" >/dev/null
sleep 4; $C eval "location.href"

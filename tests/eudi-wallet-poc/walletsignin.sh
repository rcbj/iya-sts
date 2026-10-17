#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# Signed out: open /portal, choose the realm, pick the sign-in option $1
# (wallet-signin or siop-signin, or a full /authn/wallet URL), follow "Open
# your web wallet" to the eudi wallet and print its consent dialog.
S=$(dirname "$0"); C="node $S/cdp.js"; OPT="${1:-wallet-signin}"
if [[ "$OPT" == https://* ]]; then
  $C goto "$OPT" >/dev/null
else
  $C goto https://localhost:8081/portal >/dev/null
  $C wait "document.querySelector('input[name=realm]') || document.querySelector('#$OPT')" 15000 >/dev/null
  $C eval "(()=>{const r=document.querySelector('input[name=realm]'); if(!r) return 0; r.value='default'; [...document.querySelectorAll('button')].find(b=>/Continue/.test(b.textContent)).click(); return 1})()" >/dev/null
  $C wait "document.querySelector('#$OPT')" 15000 >/dev/null
  $C eval "document.querySelector('#$OPT').click()" >/dev/null
fi
$C wait "document.querySelector('#wallet-web')" 15000 >/dev/null
$C eval "document.querySelector('#wallet-web').getAttribute('href')" | jq -r . > $S/vp-weblink.txt
$C goto "$(cat $S/vp-weblink.txt)" >/dev/null
$C wait "document.querySelector('#consent-approve') && document.querySelector('#consent-approve').offsetParent" 20000 >/dev/null
$C eval "(()=>{const d=document.querySelector('#consent-approve').closest('dialog,[role=dialog]')||document.querySelector('#consent-approve').parentElement.parentElement.parentElement; return d.innerText.replace(/\n+/g,' | ').slice(0,700)})()"

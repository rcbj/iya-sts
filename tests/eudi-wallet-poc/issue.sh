#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
# From a signed-in portal: make an IdentityCredential offer on /portal/wallet,
# follow "Open in web wallet" to the eudi wallet on 8085, type the
# transaction code into its consent dialog and approve.
S=$(dirname "$0"); C="node $S/cdp.js"; CONF="${1:-IdentityCredential}"
$C goto https://localhost:8081/portal/wallet >/dev/null
$C wait "document.querySelector('#wallet-make')" 20000 >/dev/null
$C eval "(()=>{document.querySelector('input[name=configuration][value=$CONF]').click(); document.querySelector('#wallet-make').click(); return 1})()" >/dev/null
$C wait "document.querySelector('#offer_uri')" 15000 >/dev/null
$C eval "({tx:document.querySelector('#tx_code').textContent, uri:document.querySelector('#offer_uri').textContent, web:document.querySelector('#open_in_web_wallet').getAttribute('href')})" > $S/offer.json
TX=$(jq -r .tx $S/offer.json); echo "offer made, tx_code $TX"
$C goto "$(jq -r .web $S/offer.json)" >/dev/null
$C wait "document.querySelector('#offer-tx-code-input') && document.querySelector('#offer-tx-code-input').offsetParent" 20000 >/dev/null
$C eval "(()=>{const i=document.querySelector('#offer-tx-code-input'); i.focus(); i.value='$TX'; i.dispatchEvent(new Event('input',{bubbles:true})); document.querySelector('#consent-approve').click(); return 1})()" >/dev/null
sleep 6

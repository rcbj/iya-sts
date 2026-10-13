// @ts-check
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: spnego.js
//
// NOTE ON THE NAME. The RFC 4178 codec beside this file is krb5_spnego.js and
// is VENDORED — a byte-identical copy of common/krb5/krb5_spnego.js in the
// parent project, kept honest by that project's tests/krb5_codec_sync.js.
// This file is the mock's own, so it is named for the protocol like wsfed.js
// and wstrust.js rather than for the codec. Do not merge the two: one is
// somebody else's file.
//
// ---------------------------------------------------------------------------
// The SPNEGO sign-in's page shell (#595; until then also a SPNEGO-protected
// web page): Kerberos over HTTP, RFC 4559 and RFC 4178.
//
// krb5_service.js's header said, when it was written, that this would come —
// "an HTTP service wrapping the same token in a `Negotiate` header is SPNEGO,
// which is the next phase; the acceptor logic here is written as its own
// function so that phase adds a transport and no protocol code". This is that
// phase, and the promise held:
// every Kerberos check still happens in krb5_service.js's accept(), and what is
// here is the negotiation around it and the HTTP that carries it.
//
// ---------------------------------------------------------------------------
// THE EXCHANGE, which is two round trips and looks like one.
//
//   GET /spnego/protected                          (no Authorization)
//   401 WWW-Authenticate: Negotiate                (the bare challenge)
//
//   GET /spnego/protected
//   Authorization: Negotiate <NegTokenInit>        mechTypes + an AP-REQ
//   200 WWW-Authenticate: Negotiate <NegTokenResp> accept-completed + AP-REP
//
// The first 401 carries NO token. That is RFC 4559 section 4: the server says
// only that it will negotiate, and the client — which already knows the SPN
// from the URL — goes to the KDC by itself. Nothing about which KDC, which
// realm or which SPN is in this exchange at all, which is why a SPNEGO failure
// so often turns out to be a DNS or SPN problem with no evidence on the wire.
//
// ---------------------------------------------------------------------------
// WHAT THIS ACCEPTOR IS DELIBERATELY STRICT ABOUT, AND WHAT IT IS NOT.
//
// Strict: the mechanism list must contain Kerberos, the mechListMIC is verified
// when one is sent, and a MIC that does not verify is a REJECT rather than a
// warning. That last one is the whole point of RFC 4178 section 5 — the MIC is
// what makes a mechanism list unforgeable, so an acceptor that logs a bad MIC
// and continues has implemented the syntax and none of the protection.
//
// Not strict: it accepts a BARE Kerberos InitialContextToken (no negotiation at
// all), because real clients send one and a debugger that refused it would be
// teaching something false. It says so in the response body rather than hiding
// the difference.
//
// ---------------------------------------------------------------------------
// THE KEY THE mechListMIC IS COMPUTED WITH, which is the one thing here nobody
// can guess and every implementation has to agree on.
//
// The two MICs use DIFFERENT keys, and the asymmetry is forced by when each one
// is computed rather than chosen:
//
//  * The INITIATOR's mechListMIC travels in the NegTokenInit, which is built
//    before any answer exists. The only context key that exists at that moment
//    is the subkey in its own Authenticator (or, if it sent none, the ticket's
//    session key). So that is the key, with the initiator's key usage, 25.
//  * The ACCEPTOR's mechListMIC travels beside the AP-REP, by which point the
//    acceptor has offered a subkey of its own — and RFC 4121 makes THAT the
//    context key once it is offered. So the acceptor's MIC uses the acceptor
//    subkey, with the acceptor's key usage, 23.
//
// Both are over the DER of the MechTypeList — the SEQUENCE, not the `[0]`
// wrapper it sits behind inside NegTokenInit (RFC 4178 section 5). Both use
// sequence number 0. Getting any of that wrong produces a MIC that verifies
// against nothing, and an error naming a checksum.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// THE EXCHANGE ITSELF MOVED OUT ON 2026-08-26, AND THE PAGES MOVED OUT ON
// 2026-10-12 (#595). WHAT IS LEFT IS THE SIGN-IN'S PAGE SHELL.
//
// Everything above this line still describes what happens at the sign-in
// door `/authn/spnego`; `spnego_exchange.js` is where it happens. Until #595
// this file also drew the demonstration pages `/spnego` and
// `/spnego/protected` — a renderer over `negotiate()`'s verdict, with three
// knobs that made the negotiation fail in one chosen way. rcbj's decision 1
// on #591: the click-through demonstrations leave the runtime, and the
// Kerberos-protected page is now the development companion's
// (`companion/demo_kerberos.js`), a Kerberos service with its own principal
// and keytab and MIT Kerberos as its acceptor.
//
// So this file registers NOTHING since #595. It keeps `page()` and
// `checksTable()`, which `spnego_authn.ts` draws the sign-in's continuation
// and terminal-refusal 401s with, and it stays a file of its own — rather
// than moving the two into `spnego_authn.ts` — because it is in the parent
// project's COPY closure (`kerberos/CLAUDE.md`): removing code from it owes
// the parent nothing, and a new file would.
// ---------------------------------------------------------------------------
const { log, xmlEscape } = require('../common/helpers');

// ---------------------------------------------------------------------------
// The HTML the sign-in's pages are drawn in. A local copy of wsfed.js's
// page() rather than a require of it: the require order in
// common/protocol_stack.js IS the route order and the modules deliberately
// do not reach sideways into each other (the root CLAUDE.md, rule 1), so a
// shared page helper would belong in helpers.js and moving it there means
// touching five protocols for one new page.
//
// `framing` (#539, 2026-10-09; a change made HERE with rcbj's leave, who
// reconciles it with the parent project): the `<html>` attributes, a block
// drawn first in the card and extra CSS, from a caller that draws the page in
// another language — `kerberos/spnego_authn.ts`'s sign-in. Absent, the page is
// byte-for-byte what it was. Strings rather than a translator, so this file
// requires nothing new and the parent's COPY closure does not grow.
// ---------------------------------------------------------------------------
function page(title, inner, framing) {
  log.debug('Entering page().');
  const frame = framing || {};
  log.debug('Leaving page().');
  return '<!DOCTYPE html>\n<html' + (frame.htmlAttributes || ' lang="en"') +
    '><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>' + xmlEscape(title) +
    '</title><style>body{font-family:system-ui,-apple-system,"Segoe UI",' +
    'Arial,sans-serif;background:#f4f4f7;margin:0;padding:2rem;color:#222;' +
    'line-height:1.45}.card{background:#fff;border:1px solid ' +
    '#d5d5dd;border-radius:10px;padding:24px 28px;max-width:52rem;margin:0 ' +
    'auto;box-shadow:0 6px 24px rgba(0,0,0,.08)}h1{font-size:1.3em;margin:0 ' +
    '0 4px;color:#12107c}h2{font-size:1em;margin:1.4em 0 ' +
    '.4em}p.sub{color:#666;font-size:.85em;margin:0 0 ' +
    '18px}table{border-collapse:collapse;width:100%;margin:.5rem 0 ' +
    '1rem;font-size:.85em}th,td{border:1px solid #ddd;padding:.35rem .55rem;' +
    'text-align:left;vertical-align:top}th{background:#f0f0f5}' +
    '.pass{color:#0b6b4f;font-weight:600;white-space:nowrap}' +
    '.fail{color:#b00020;font-weight:600;white-space:nowrap}' +
    '.err{background:#fdecea;border:1px solid ' +
    '#f5c6c2;color:#b00020;padding:8px 10px;border-radius:5px;font-size:.9em;' +
    'margin-bottom:12px}.ok{background:#e8f5e9;border:1px solid ' +
    '#a5d6a7;padding:8px 10px;border-radius:5px;font-size:.9em;' +
    'margin-bottom:12px}pre{background:#f4f4f8;border:1px solid #e2e2ea;' +
    'border-radius:5px;padding:.6rem;font-size:.75rem;overflow-x:auto;' +
    'white-space:pre-wrap;word-break:break-all}code{font-family:ui-monospace,' +
    'SFMono-Regular,Menlo,monospace;font-size:.85em;background:#f4f4f8;' +
    'padding:.1rem .25rem;border-radius:3px;word-break:break-all}' +
    'a{color:#12107c}ul{margin:.3em 0;padding-left:1.2em}li{margin:.2em ' +
    '0}' + (frame.style || '') + '</style></head><body><div ' +
    'class="card">' + (frame.top || '') + inner + '</div></body></html>\n';
}

function checksTable(checks) {
  log.debug('Entering checksTable().');
  const rows = (checks || []).map(function (c) {
    return '<tr><td>' + xmlEscape(c.name) + '</td><td class="' +
      (c.ok ? 'pass">passed' : 'fail">FAILED') + '</td><td>' +
      xmlEscape(c.detail == null ? '' : String(c.detail)) + '</td></tr>';
  }).join('');
  log.debug('Leaving checksTable().');
  return '<table><tr><th>Check</th><th>Result</th><th>Detail</th></tr>' +
    rows + '</table>';
}

module.exports = {
  // THE SHELL AND THE CHECK TABLE, for `spnego_authn.ts` and for nothing else.
  //
  // Exported rather than copied, and the choice of WHICH look the sign-in door
  // wears is the reason. Its pages could have been drawn in `authn.js`'s
  // CARD_CSS — they are met mid-sign-in, and that is the stylesheet a person
  // has just been looking at. They are drawn in THIS one because of what has
  // to be on them: when a Kerberos sign-in fails, what the person needs is the
  // nine checks `krb5_service.js` made and the sentence saying which one did
  // not pass, and that is a table rather than a card.
  page: page,
  checksTable: checksTable
};

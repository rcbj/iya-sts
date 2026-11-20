// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: kerberos_tokens.js
// ===========================================================================
// KERBEROS TOKENS IN WS-TRUST AND THE RFC 8693 TOKEN EXCHANGE (#658).
//
// The Web Services Security Kerberos Token Profile 1.1's AP-REQ, with real
// tickets from the in-process KDC (`kdc.handleMessage()`, through the suite's
// own client `tests/protocol/krb5_wire.js`), in development mode where the
// fixture services exist:
//   W. WS-TRUST, THE REQUESTER: a person's GSS and bare AP-REQ for this
//      service's SPN issue a SAML assertion about them with the Kerberos
//      authentication class; a replay, a ticket for another service and a
//      mislabelled form are refused (0056); an application's own ticket is
//      a token about the application and signs nobody in;
//      `wstrust.acceptKerberos` off refuses (0054).
//   D. WS-TRUST, DELEGATED: an S4U2Proxy ticket to this service inside
//      ActAs is a token about the user with the front end acting (its
//      `del:Delegate`); the same ticket from another requester (0060), a
//      plain ticket (0059, rcbj's D2), a forwarded one from a requester not
//      trusted for delegation (0061) and the same once it is trusted.
//   O. WS-TRUST, ISSUED: a GSS and a bare Kerberos token for the AppliesTo's
//      Kerberos service — the ticket opened with that service's key names
//      the subject, the Authenticator's subkey is the proof token — an
//      ActAs's PAC naming the front end in S4U_DELEGATION_INFO; a token for
//      this service itself accepted back as a credential; off (0062), not
//      over TLS (0063), no Kerberos target (0064), wst:Delegatable to a
//      target not trusted (0065) and to one that is (a KRB-CRED in the
//      0x8003 checksum); Validate valid, Renew refused (0067).
//   X. RFC 8693: an S4U2Proxy subject_token exchanged for an access token
//      with the front end in `act`, and for a Kerberos token naming it in
//      S4U_DELEGATION_INFO (issued_token_type, token_type N_A, the session
//      key); a Kerberos actor_token of the client's own; refusals 0987,
//      0991, 0993, 0994.
//   S. A SIGNATURE WITH THE TOKEN'S SESSION KEY (rcbj's D7): an
//      HMAC-SHA256 WS-Security signature keyed by the Authenticator's
//      subkey, naming the token by Reference and by #Kerberosv5APREQSHA1,
//      authenticates its holder; a Body altered after signing and a
//      truncated HMAC (0045), a token the header does not carry (0069) and
//      HMAC-SHA1 under the SHA-1 policy (0040) are refused.
//   R. ACROSS A TRUST (rcbj's D8): a Kerberos token for a service of a
//      paired trust realm, minted by walking the trust through that realm's
//      KDC, opened with the far service's key.
//
// IN A CHILD PROCESS, for `wstrust_message_signature.js`'s reason: it loads
// the whole stack and creates realms, process state `run.js` shares.
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const http = require('http');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHILD_FLAG = 'STS_KERBEROS_TOKENS_CHILD';
const MARK = 'KERBEROS-TOKENS-CHILD ';
const WST = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const WST14 = 'http://docs.oasis-open.org/ws-sx/ws-trust/200802';
const WSSE = 'http://docs.oasis-open.org/wss/2004/01/' +
  'oasis-200401-wss-wssecurity-secext-1.0.xsd';
const PROFILE = 'http://docs.oasis-open.org/wss/' +
  'oasis-wss-kerberos-token-profile-1.1';
const GSS = PROFILE + '#GSS_Kerberosv5_AP_REQ';
const BARE = PROFILE + '#Kerberosv5_AP_REQ';
const JWT_TYPE = 'urn:ietf:params:oauth:token-type:jwt';
const ACCESS_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const BASE = 'https://kt-sts.example';
const BACK = 'https://kt-back.example';
const SELF = 'https://kt-self.example';
const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';

const log = require('bunyan').createLogger({
  name: 'kerberos_tokens', level: process.env.LOG_LEVEL || 'info' });

function recorder() {
  log.debug("Entering recorder().");
  const rows = [];
  log.debug("Leaving recorder().");
  return {
    rows: rows,
    check: function (ok, what, detail) {
      log.debug("Entering check().");
      rows.push({ ok: !!ok, what: what,
                  detail: detail === undefined ? '' : String(detail) });
      log.debug("Leaving check().");
    }
  };
}

function bst(valueType, bytes) {
  log.debug("Entering bst().");
  log.debug("Leaving bst().");
  return '<wsse:BinarySecurityToken xmlns:wsse="' + WSSE + '" ValueType="' +
    valueType + '">' + Buffer.from(bytes).toString('base64') +
    '</wsse:BinarySecurityToken>';
}

// An RST: `security` in the header, `inner` in the RST.
function rst(opts) {
  log.debug("Entering rst().");
  const o = opts || {};
  log.debug("Leaving rst().");
  return '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">' +
    '<s:Header><wsse:Security xmlns:wsse="' + WSSE + '">' +
    (o.security || '') + '</wsse:Security></s:Header><s:Body>' +
    '<wst:RequestSecurityToken xmlns:wst="' + WST + '">' +
    '<wst:RequestType>' + WST + '/' + (o.op || 'Issue') +
    '</wst:RequestType>' +
    (o.tokenType ? '<wst:TokenType>' + o.tokenType + '</wst:TokenType>'
                 : '') +
    (o.appliesTo === null ? '' :
      '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
      'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/' +
      '08/addressing"><wsa:Address>' + (o.appliesTo || BACK) +
      '</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>') +
    (o.inner || '') + '</wst:RequestSecurityToken></s:Body></s:Envelope>';
}

function faultCode(result) {
  log.debug("Entering faultCode().");
  log.debug("Leaving faultCode().");
  return result ? String(result.errorCode || '') : '';
}

async function childBody() {
  log.debug("Entering childBody().");
  const t = recorder();
  require(ROOT + '/common/protocol_stack');
  const app = require(ROOT + '/common/app');
  const keystore = require(ROOT + '/common/keystore');
  const config = require(ROOT + '/common/config');
  const realms = require(ROOT + '/common/realms');
  const applications = require(ROOT + '/common/applications');
  const principals = require(ROOT + '/kerberos/krb5_principals.js');
  const kdc = require(ROOT + '/kerberos/krb5_kdc.js');
  const kcrypto = require(ROOT + '/kerberos/krb5_crypto.js');
  const kpac = require(ROOT + '/kerberos/krb5_pac.js');
  const gss = require(ROOT + '/kerberos/krb5_gss.js');
  const trusts = require(ROOT + '/kerberos/krb5_trusts');
  const krb5Tokens = require(ROOT + '/kerberos/krb5_tokens');
  const wire = require(ROOT + '/tests/protocol/krb5_wire.js');
  const grants = require(ROOT + '/tests/tools/cross_realm_grants');
  const xmldom = require('@xmldom/xmldom');
  const wstrustModule = require(ROOT + '/ws-trust/wstrust');
  const wstrust = new wstrustModule.WsTrust(
    wstrustModule.WsTrust.defaultDeps());
  const OAuthModel = require(ROOT + '/oauth-oidc/oauth_model');
  const modelHold = require(ROOT + '/tests/tools/oauth_model_hold');
  const msgs = wire.msgs;
  await keystore.start();

  const REALM = principals.REALM;
  const DOMAIN = REALM.toLowerCase();
  const T = {
    label: 'in-process',
    send: function (bytes) {
      log.debug("Entering send().");
      log.debug("Leaving send().");
      return kdc.handleMessage(bytes);
    }
  };
  const spn = function (host) {
    log.debug("Entering spn().");
    log.debug("Leaving spn().");
    return { type: 3, name: ['HTTP', host + '.' + DOMAIN] };
  };
  const STS = { type: 3, name: principals.servicePrincipal() };
  const stsId = STS.name.join('/') + '@' + REALM;
  const frontId = 'HTTP/frontend.' + DOMAIN + '@' + REALM;
  const notrustedId = 'HTTP/notrusted.' + DOMAIN + '@' + REALM;
  const backId = 'HTTP/backend.' + DOMAIN + '@' + REALM;
  const set = function (id, attribute, mode, value) {
    log.debug("Entering set(). " + id + " " + attribute);
    const r = applications.updateApplication(id, { attribute: attribute,
                                                   mode: mode, value: value });
    log.debug("Leaving set().");
    return r;
  };
  const tgtOf = async function (name, password) {
    log.debug("Entering tgtOf(). " + name);
    const got = await wire.asExchange(T, REALM, name, { password: password });
    t.check(!!got.tgt, 'precondition: a TGT for ' + name,
            JSON.stringify(got.second || got.first));
    log.debug("Leaving tgtOf().");
    return got.tgt;
  };
  // A fresh AP-REQ for this service, from a service ticket.
  const apFor = async function (ticket) {
    log.debug("Entering apFor().");
    const built = await wire.apRequest(ticket);
    log.debug("Leaving apFor().");
    return built;
  };
  const ask = async function (xml, opts) {
    log.debug("Entering ask().");
    const o = opts || {};
    const result = await wstrust.handleRst(xml, 'application/soap+xml', {
      base: o.base || BASE,
      connection: { socket: null, revocation: null, signature: null } });
    log.debug("Leaving ask().");
    return result;
  };
  const bodyOf = function (result) {
    log.debug("Entering bodyOf().");
    log.debug("Leaving bodyOf().");
    return new xmldom.DOMParser().parseFromString(String(result.body || ''),
                                                  'text/xml');
  };
  const textOf = function (doc, local) {
    log.debug("Entering textOf().");
    const found = doc.getElementsByTagNameNS('*', local);
    log.debug("Leaving textOf().");
    return found.length ? String(found[0].textContent || '').trim() : '';
  };
  // Opens an issued Kerberos token: the ticket with the target's key, the
  // Authenticator with the ticket's session key.
  const openToken = async function (b64, valueType, target, inRealm) {
    log.debug("Entering openToken().");
    const decoded = krb5Tokens.decode(b64, valueType);
    if (!decoded.ok) {
      log.debug("Leaving openToken(). Undecodable.");
      return { problem: decoded.reason };
    }
    const apReq = msgs.readApReq(decoded.apReq);
    const run = async function () {
      log.debug("Entering run().");
      const service = principals.find(target.name, principals.REALM);
      const profile = kcrypto.etypeById(apReq.ticket.encPart.etype);
      const key = await principals.longTermKey(service,
                                               apReq.ticket.encPart.etype);
      const part = msgs.readEncTicketPart(await profile.decrypt(key,
        kcrypto.KEY_USAGE.KDC_REP_TICKET, apReq.ticket.encPart.cipher));
      const authenticator = msgs.readAuthenticator(await kcrypto.etypeById(
        apReq.authenticator.etype).decrypt(part.key.key,
        kcrypto.KEY_USAGE.AP_REQ_AUTH, apReq.authenticator.cipher));
      const pacs = kpac.findPacs(part.authorizationData || []);
      const info = pacs.length ? kpac.bufferOfType(kpac.parsePac(
        pacs[0].bytes), kpac.TYPE.DELEGATION_INFO) : null;
      log.debug("Leaving run().");
      return { part: part, authenticator: authenticator,
               delegation: info ? info.parsed : null,
               gss: authenticator.cksum &&
                 authenticator.cksum.type === gss.CHECKSUM_TYPE_GSS
                 ? gss.parseGssChecksum(authenticator.cksum.checksum) : null,
               sname: apReq.ticket.sname.name.join('/') };
    };
    const out = inRealm ? await realms.run(inRealm, run) : await run();
    log.debug("Leaving openToken().");
    return out;
  };

  // --- the fixtures ---------------------------------------------------
  require(ROOT + '/kerberos/krb5_delegation').ensureSeeded();
  t.check(!!applications.get(frontId) && !!applications.get(backId) &&
          !!applications.get(stsId),
          'precondition: the fixture services have entries',
          [frontId, backId, stsId].join(' '));
  // The front end may delegate to THIS service by S4U2Proxy (the KDC's
  // classic constrained delegation), and the back end and this service are
  // WS-Trust relying parties.
  set(frontId, 'appAllowedToDelegateTo', 'add', stsId);
  set(notrustedId, 'appAllowedToDelegateTo', 'add', stsId);
  set(backId, 'wstrustAppliesTo', 'add', BACK);
  set(stsId, 'wstrustAppliesTo', 'add', SELF);
  const userPassword = String(config.value('krb5.userPassword'));
  const tgts = {
    alice: await tgtOf('alice', userPassword),
    front: await tgtOf('HTTP/frontend.' + DOMAIN,
                       'frontend-service-password'),
    notrusted: await tgtOf('HTTP/notrusted.' + DOMAIN,
                           'notrusted-service-password')
  };
  if (!tgts.alice || !tgts.front || !tgts.notrusted) {
    log.debug("Leaving childBody(). No TGTs.");
    return t.rows;
  }
  const ticketTo = async function (tgt, target, opts) {
    log.debug("Entering ticketTo().");
    const r = await wire.tgsExchange(T, tgt, target, REALM, opts);
    t.check(r.ok, 'precondition: a ticket for ' + target.name.join('/'),
            String(r.error || ''));
    log.debug("Leaving ticketTo().");
    return r;
  };
  // S4U2Self for alice by the front end, then S4U2Proxy to this service.
  const delegatedToSts = async function (front) {
    log.debug("Entering delegatedToSts().");
    const self = await wire.tgsExchange(T, front, front.client, REALM, {
      padata: async function () {
        return [await wire.paForUser(front, 'alice', REALM)];
      } });
    t.check(self.ok && self.flagNames.indexOf('forwardable') >= 0,
            'precondition: a forwardable S4U2Self ticket for alice',
            String(self.error || self.flagNames));
    const proxy = await wire.tgsExchange(T, front, STS, REALM, {
      kdcOptions: [msgs.KDC_OPTION.CNAME_IN_ADDL_TKT],
      additionalTickets: [self.ticket] });
    t.check(proxy.ok, 'precondition: S4U2Proxy by ' +
            front.client.name.join('/') + ' to this service for alice',
            String(proxy.error || ''));
    log.debug("Leaving delegatedToSts().");
    return proxy;
  };

  // --- W. the requester -------------------------------------------------
  let aliceSts = await ticketTo(tgts.alice, STS);
  let ap = await apFor(aliceSts);
  let r = await ask(rst({ security: bst(GSS, ap.token) }));
  let doc = bodyOf(r);
  t.check(r.status === 200 && textOf(doc, 'NameID') === 'alice' &&
          textOf(doc, 'AuthnContextClassRef') === krb5Tokens.AUTHN_CONTEXT,
          'W1. a GSS AP-REQ for this service as the requester\'s credential ' +
          'issues an assertion about alice with the Kerberos class',
          r.status + ' ' + faultCode(r) + ' ' + textOf(doc, 'NameID') + ' ' +
          textOf(doc, 'AuthnContextClassRef'));
  r = await ask(rst({ security: bst(GSS, ap.token) }));
  t.check(faultCode(r) === 'STS-WSTRUST-0056',
          'W2. the same AP-REQ again is a replay (0056)', faultCode(r));
  ap = await apFor(aliceSts);
  r = await ask(rst({ security: bst(BARE, ap.apReq) }));
  t.check(r.status === 200 && textOf(bodyOf(r), 'NameID') === 'alice',
          'W3. the bare form (#Kerberosv5_AP_REQ) is accepted too',
          r.status + ' ' + faultCode(r));
  ap = await apFor(aliceSts);
  r = await ask(rst({ security: bst(BARE, ap.token) }));
  t.check(faultCode(r) === 'STS-WSTRUST-0056' &&
          /not an RFC 4120 AP-REQ/.test(String(r.body)),
          'W4. a GSS token declared bare is refused (0056, STS-KRB-0249\'s ' +
          'reason)', faultCode(r));
  const aliceBack = await ticketTo(tgts.alice, spn('backend'));
  ap = await apFor(aliceBack);
  r = await ask(rst({ security: bst(GSS, ap.token) }));
  t.check(faultCode(r) === 'STS-WSTRUST-0056',
          'W5. a ticket for another service is refused: the acceptor holds ' +
          'its own key alone (0056)', faultCode(r));
  const frontSts = await ticketTo(tgts.front, STS);
  ap = await apFor(frontSts);
  r = await ask(rst({ security: bst(GSS, ap.token), tokenType: JWT_TYPE }));
  doc = bodyOf(r);
  let jwt = textOf(doc, 'BinarySecurityToken');
  let claims = {};
  try {
    claims = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url')
                          .toString('utf8'));
  } catch (e) {
    log.debug("Caught in childBody(): " + ((e && e.message) || e));
    claims = {};
  }
  t.check(r.status === 200 && !r.signIn && !!claims.sub,
          'W6. an application\'s own Kerberos token is a token about the ' +
          'application (its client_id the application\'s), and signs ' +
          'nobody in', r.status + ' ' + faultCode(r) +
          ' ' + JSON.stringify(claims.sub) + ' ' + JSON.stringify(r.signIn));
  config.setOverride('wstrust.acceptKerberos', false);
  ap = await apFor(aliceSts);
  r = await ask(rst({ security: bst(GSS, ap.token) }));
  config.clearOverride('wstrust.acceptKerberos');
  t.check(faultCode(r) === 'STS-WSTRUST-0054',
          'W7. wstrust.acceptKerberos off refuses the credential (0054)',
          faultCode(r));

  // --- D. delegated --------------------------------------------------
  let proxy = await delegatedToSts(tgts.front);
  const frontCred = async function () {
    log.debug("Entering frontCred().");
    const built = await apFor(await ticketTo(tgts.front, STS));
    log.debug("Leaving frontCred().");
    return bst(GSS, built.token);
  };
  ap = await apFor(proxy);
  r = await ask(rst({ security: await frontCred(),
    inner: '<wst14:ActAs xmlns:wst14="' + WST14 + '">' + bst(GSS, ap.token) +
           '</wst14:ActAs>' }));
  doc = bodyOf(r);
  t.check(r.status === 200 && textOf(doc, 'NameID') === 'alice' &&
          /frontend/.test(textOf(doc, 'Delegate')),
          'D1. an S4U2Proxy ticket to this service inside ActAs, presented ' +
          'by the front end that obtained it, is an assertion about alice ' +
          'naming the front end as a delegate', r.status + ' ' +
          faultCode(r) + ' ' + textOf(doc, 'NameID') + ' ' +
          textOf(doc, 'Delegate'));
  ap = await apFor(proxy);
  const notCred = bst(GSS, (await apFor(await ticketTo(tgts.notrusted,
                                                       STS))).token);
  r = await ask(rst({ security: notCred,
    inner: '<wst14:ActAs xmlns:wst14="' + WST14 + '">' + bst(GSS, ap.token) +
           '</wst14:ActAs>' }));
  t.check(faultCode(r) === 'STS-WSTRUST-0060',
          'D2. the same ticket from another requester is refused: its ' +
          'S4U_DELEGATION_INFO names the front end (0060)', faultCode(r));
  ap = await apFor(aliceSts);
  r = await ask(rst({ security: await frontCred(),
    inner: '<wst14:ActAs xmlns:wst14="' + WST14 + '">' + bst(GSS, ap.token) +
           '</wst14:ActAs>' }));
  t.check(faultCode(r) === 'STS-WSTRUST-0059',
          'D3. a ticket alice made for this service, handed over, is not ' +
          'delegation (0059, rcbj\'s D2)', faultCode(r));
  const forwardedTgt = await wire.tgsExchange(T, tgts.alice,
    { type: 2, name: ['krbtgt', REALM] }, REALM,
    { kdcOptions: [msgs.KDC_OPTION.FORWARDED] });
  t.check(forwardedTgt.ok &&
          forwardedTgt.flagNames.indexOf('forwarded') >= 0,
          'precondition: alice forwards her TGT', String(
            forwardedTgt.error || forwardedTgt.flagNames));
  const fromForwarded = await ticketTo(forwardedTgt, STS);
  t.check(fromForwarded.flagNames.indexOf('forwarded') >= 0,
          'precondition: a ticket bought with it is FORWARDED',
          fromForwarded.flagNames);
  ap = await apFor(fromForwarded);
  r = await ask(rst({ security: bst(GSS, (await apFor(await ticketTo(
                                  tgts.notrusted, STS))).token),
    inner: '<wst14:ActAs xmlns:wst14="' + WST14 + '">' + bst(GSS, ap.token) +
           '</wst14:ActAs>' }));
  t.check(faultCode(r) === 'STS-WSTRUST-0061',
          'D4. a forwarded ticket from a requester not trusted for ' +
          'unconstrained delegation is refused (0061)', faultCode(r));
  // The front end is trusted for it by its seed (ok-as-delegate).
  ap = await apFor(fromForwarded);
  r = await ask(rst({ security: await frontCred(),
    inner: '<wst14:ActAs xmlns:wst14="' + WST14 + '">' + bst(GSS, ap.token) +
           '</wst14:ActAs>' }));
  t.check(r.status === 200 && textOf(bodyOf(r), 'NameID') === 'alice',
          'D5. and accepted from the front end, which is trusted for it ' +
          '(krb5TrustedForDelegation)', r.status + ' ' + faultCode(r));

  // --- O. issued -------------------------------------------------------
  config.setOverride('wstrust.issueKerberos', true);
  const ut = '<wsse:UsernameToken><wsse:Username>alice</wsse:Username>' +
    '<wsse:Password>x</wsse:Password></wsse:UsernameToken>';
  r = await ask(rst({ security: ut, tokenType: GSS }));
  doc = bodyOf(r);
  let token = textOf(doc, 'BinarySecurityToken');
  let opened = token ? await openToken(token, GSS, spn('backend')) : {};
  const proof = textOf(doc, 'BinarySecret');
  t.check(r.status === 200 && opened.part &&
          opened.part.cname.name.join('/') === 'alice' &&
          opened.sname === 'HTTP/backend.' + DOMAIN &&
          opened.authenticator.subkey && proof ===
            Buffer.from(opened.authenticator.subkey.key).toString('base64') &&
          !!textOf(doc, 'KeyIdentifier'),
          'O1. wst:TokenType GSS is a Kerberos token for the AppliesTo\'s ' +
          'service: its ticket opens with that service\'s key and names ' +
          'alice, the proof token is the Authenticator\'s subkey, and the ' +
          'references carry the Kerberosv5APREQSHA1 key identifier',
          r.status + ' ' + faultCode(r) + ' ' + (opened.problem ||
            (opened.part && opened.part.cname.name.join('/'))));
  t.check(opened.part && (opened.part.flags || []).indexOf(
            msgs.TICKET_FLAG.PRE_AUTHENT) < 0,
          'O1b. the minted ticket does not claim pre-authentication',
          opened.part && msgs.ticketFlagNames(opened.part.flags));
  r = await ask(rst({ security: ut, tokenType: BARE }));
  token = textOf(bodyOf(r), 'BinarySecurityToken');
  opened = token ? await openToken(token, BARE, spn('backend')) : {};
  t.check(r.status === 200 && opened.part && !opened.gss,
          'O2. the bare form is an AP-REQ with no GSS wrapping or 0x8003 ' +
          'checksum', r.status + ' ' + faultCode(r));
  proxy = await delegatedToSts(tgts.front);
  ap = await apFor(proxy);
  r = await ask(rst({ security: await frontCred(), tokenType: GSS,
    inner: '<wst14:ActAs xmlns:wst14="' + WST14 + '">' + bst(GSS, ap.token) +
           '</wst14:ActAs>' }));
  token = textOf(bodyOf(r), 'BinarySecurityToken');
  opened = token ? await openToken(token, GSS, spn('backend')) : {};
  t.check(r.status === 200 && opened.delegation &&
          opened.delegation.s4u2proxyTarget === 'HTTP/backend.' + DOMAIN &&
          (opened.delegation.transitedServices || []).join(' ') === frontId,
          'O3. an ActAs Kerberos token names the front end in its PAC\'s ' +
          'S4U_DELEGATION_INFO, the back end as its target',
          r.status + ' ' + faultCode(r) + ' ' +
          JSON.stringify(opened.delegation));
  r = await ask(rst({ security: ut, tokenType: GSS, appliesTo: SELF }));
  token = textOf(bodyOf(r), 'BinarySecurityToken');
  r = token ? await ask(rst({ security: bst(GSS, Buffer.from(token,
                                                            'base64')) }))
            : { status: 0 };
  t.check(r.status === 200 && textOf(bodyOf(r), 'NameID') === 'alice',
          'O4. a Kerberos token issued for this service itself is accepted ' +
          'back as a credential', r.status + ' ' + faultCode(r));
  r = await ask(rst({ security: ut, tokenType: GSS }),
                { base: 'http://kt-sts.example' });
  t.check(faultCode(r) === 'STS-WSTRUST-0063',
          'O5. not over TLS: refused, the proof token is a key (0063)',
          faultCode(r));
  r = await ask(rst({ security: ut, tokenType: GSS,
                      appliesTo: 'https://kt-nobody.example' }));
  t.check(faultCode(r) === 'STS-WSTRUST-0064',
          'O6. an AppliesTo that is no Kerberos service (0064)', faultCode(r));
  r = await ask(rst({ security: ut, tokenType: GSS,
                      inner: '<wst:Delegatable>true</wst:Delegatable>' }));
  t.check(faultCode(r) === 'STS-WSTRUST-0065',
          'O7. wst:Delegatable to a target not trusted for delegation (0065)',
          faultCode(r));
  // An xs:boolean (rcbj on #1579): `1` asks for delegation as `true` does;
  // until 2026-11-11 it read as false and the ticket was issued without it.
  r = await ask(rst({ security: ut, tokenType: GSS,
                      inner: '<wst:Delegatable>1</wst:Delegatable>' }));
  t.check(faultCode(r) === 'STS-WSTRUST-0065',
          'O7. wst:Delegatable written 1 is a request for delegation too ' +
          '(0065)', faultCode(r));
  set(backId, 'krb5TrustedForDelegation', 'set', 'TRUE');
  r = await ask(rst({ security: ut, tokenType: GSS,
                      inner: '<wst:Delegatable>true</wst:Delegatable>' }));
  token = textOf(bodyOf(r), 'BinarySecurityToken');
  opened = token ? await openToken(token, GSS, spn('backend')) : {};
  let cred = null;
  if (opened.gss && opened.gss.delegation) {
    try {
      const read = msgs.readKrbCred(opened.gss.delegation.credential);
      const sub = opened.authenticator.subkey;
      const enc = msgs.readEncKrbCredPart(await kcrypto.etypeById(sub.etype)
        .decrypt(sub.key, 14, read.encPart.cipher));
      cred = { tickets: read.tickets.length, info: enc.ticketInfo[0] };
    } catch (e) {
      log.debug("Caught in childBody(): " + ((e && e.message) || e));
      cred = { problem: String((e && e.message) || e) };
    }
  }
  t.check(r.status === 200 && opened.gss &&
          (opened.gss.flags & gss.GSS_FLAG.DELEG) && cred && cred.info &&
          cred.info.sname.name.join('/') === 'krbtgt/' + REALM &&
          msgs.ticketFlagNames(cred.info.flags).indexOf('forwarded') >= 0,
          'O8. to a target trusted for it, wst:Delegatable puts a forwarded ' +
          'TGT for alice in a KRB-CRED in the 0x8003 checksum, sealed under ' +
          'the subkey', r.status + ' ' + faultCode(r) + ' ' +
          JSON.stringify(cred));
  set(backId, 'krb5TrustedForDelegation', 'set', 'FALSE');
  config.setOverride('wstrust.issueKerberos', false);
  r = await ask(rst({ security: ut, tokenType: GSS }));
  t.check(faultCode(r) === 'STS-WSTRUST-0062',
          'O9. wstrust.issueKerberos off refuses (0062)', faultCode(r));
  config.clearOverride('wstrust.issueKerberos');
  ap = await apFor(aliceSts);
  r = await ask(rst({ security: ut, op: 'Validate', appliesTo: null,
    inner: '<wst:ValidateTarget>' + bst(GSS, ap.token) +
           '</wst:ValidateTarget>' }));
  t.check(r.status === 200 && /status\/valid/.test(textOf(bodyOf(r), 'Code')),
          'O10. Validate of a Kerberos token for this service is valid',
          textOf(bodyOf(r), 'Code'));
  ap = await apFor(aliceSts);
  r = await ask(rst({ security: ut, op: 'Renew',
    inner: '<wst:RenewTarget>' + bst(GSS, ap.token) + '</wst:RenewTarget>' }));
  t.check(faultCode(r) === 'STS-WSTRUST-0067',
          'O11. Renew of a Kerberos token is refused (0067)', faultCode(r));

  // --- X. RFC 8693 ---------------------------------------------------
  config.setOverride('global.publicBaseUrl', BASE);
  const fixed = [
    set(frontId, 'oauthClientId', 'add', 'kt-frontend')];
  fixed.push(set(frontId, 'oauthClientSecret', 'set',
                 'kt-frontend-secret-0123456789abcdef0123'));
  fixed.push(set(frontId, 'oauthTokenEndpointAuthMethod', 'add',
                 'client_secret_post'));
  fixed.push(set(frontId, 'oauthGrantType', 'add', EXCHANGE));
  fixed.push(set(backId, 'oauthAudience', 'add', BACK));
  t.check(fixed.every(function (one) { return one && one.ok; }) &&
          !!applications.forClientId('kt-frontend'),
          'precondition: the front end is the OAuth client kt-frontend and ' +
          'the back end the audience ' + BACK, JSON.stringify(fixed.map(
            function (one) { return one && one.errors; })));
  const server = http.createServer(app);
  await new Promise(function (resolve) {
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const exchange = function (form) {
    log.debug("Entering exchange().");
    const body = new URLSearchParams(Object.assign({
      grant_type: EXCHANGE, client_id: 'kt-frontend',
      client_secret: 'kt-frontend-secret-0123456789abcdef0123',
      audience: BACK }, form)).toString();
    log.debug("Leaving exchange().");
    return new Promise(function (resolve) {
      const req = http.request({ host: '127.0.0.1', port: port,
        path: '/oauth2/token', method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded',
                   'content-length': Buffer.byteLength(body) } },
      function (res) {
        let text = '';
        res.on('data', function (c) { text += c; });
        res.on('end', function () {
          let json = {};
          try {
            json = JSON.parse(text);
          } catch (e) {
            json = { parseError: String((e && e.message) || e) };
          }
          resolve({ status: res.statusCode, json: json });
        });
      });
      req.end(body);
    });
  };
  // A refusal's code is recorded, never sent: it is on the audit ring.
  const audit = require(ROOT + '/common/audit');
  const codeRecorded = function (code) {
    log.debug("Entering codeRecorded(). " + code);
    log.debug("Leaving codeRecorded().");
    return audit.list().some(function (row) {
      return row.errorCode === code;
    });
  };
  const b64u = function (bytes) {
    log.debug("Entering b64u().");
    log.debug("Leaving b64u().");
    return Buffer.from(bytes).toString('base64url');
  };
  proxy = await delegatedToSts(tgts.front);
  let x = await exchange({ subject_token: b64u((await apFor(proxy)).token),
                           subject_token_type: GSS });
  claims = {};
  try {
    claims = JSON.parse(Buffer.from(String(x.json.access_token).split('.')[1],
                                    'base64url').toString('utf8'));
  } catch (e) {
    log.debug("Caught in childBody(): " + ((e && e.message) || e));
    claims = {};
  }
  t.check(x.status === 200 && x.json.issued_token_type === ACCESS_TYPE &&
          claims.act && /kt-frontend/.test(String(claims.act.sub || '')),
          'X1. an S4U2Proxy subject_token is exchanged for an access token ' +
          'about alice with the front end in act', x.status + ' ' +
          JSON.stringify(x.json).slice(0, 300));
  config.setOverride('oauth2.tokenExchangeKerberosOutput', true);
  proxy = await delegatedToSts(tgts.front);
  // INTO THE NEXT SECOND before the exchange. X1's Token Request filed a
  // development sighting under the bare client_id `kt-frontend`, so two
  // entries register it, and `list()` orders them by their last activity at
  // one-second resolution: the KDC's sighting of the front end just now, and
  // the token endpoint's of `kt-frontend` in the exchange below. Across a
  // second boundary the sighting is the newer, and `forClientId()` answered
  // it — the PAC named `kt-frontend` rather than the front end's principal
  // (run 19, single-node). Crossing the boundary every time makes that the
  // case X2 always holds rather than one in however many runs.
  await new Promise(function (resolve) {
    setTimeout(resolve, 1020 - (Date.now() % 1000));
  });
  x = await exchange({ subject_token: b64u((await apFor(proxy)).token),
                       subject_token_type: GSS, requested_token_type: GSS });
  opened = x.json.access_token
    ? await openToken(x.json.access_token, GSS, spn('backend')) : {};
  t.check(x.status === 200 && x.json.issued_token_type === GSS &&
          x.json.token_type === 'N_A' && !!x.json.session_key &&
          opened.part && opened.part.cname.name.join('/') === 'alice' &&
          opened.delegation &&
          (opened.delegation.transitedServices || []).indexOf(frontId) >= 0,
          'X2. requested_token_type GSS answers a Kerberos token for the ' +
          'back end (issued_token_type, token_type N_A, session_key) whose ' +
          'PAC names the front end', x.status + ' ' +
          JSON.stringify(x.json).slice(0, 300) + ' ' +
          JSON.stringify(opened.delegation));
  // The Kerberos token's answer is the model's (#658's `session_key` and
  // `session_key_etype`, this service's own; #1579's gap scan found both
  // undeclared in token-response, logged under STS-OAUTH-1005), and the
  // model without `session_key` names it.
  const krbHeld = modelHold.hold(OAuthModel, 'token-response', x.json,
                                 'session_key');
  t.check(!!x.json.session_key &&
          Number.isInteger(x.json.session_key_etype) &&
          krbHeld.gaps.length === 0 && krbHeld.caught,
          'X2a. the Kerberos token\'s token response is the model\'s ' +
          '(token-response declares session_key and session_key_etype; ' +
          'without session_key, a gap)',
          krbHeld.gaps.concat(krbHeld.mutated).join('; '));
  config.clearOverride('oauth2.tokenExchangeKerberosOutput');
  x = await exchange({ subject_token: b64u((await apFor(proxy)).token),
                       subject_token_type: GSS, requested_token_type: GSS });
  t.check(x.status === 400 && codeRecorded('STS-OAUTH-0994'),
          'X3. output off (the default) refuses a Kerberos requested type ' +
          '(0994)', x.status + ' ' + JSON.stringify(x.json));
  x = await exchange({ subject_token: b64u((await apFor(aliceSts)).token),
                       subject_token_type: GSS });
  t.check(x.status === 400 && codeRecorded('STS-OAUTH-0991'),
          'X4. a plain ticket alice made for this server is not delegation ' +
          '(0991)', x.status + ' ' + JSON.stringify(x.json));
  proxy = await delegatedToSts(tgts.front);
  x = await exchange({ subject_token: b64u((await apFor(proxy)).token),
                       subject_token_type: GSS,
                       actor_token: b64u((await apFor(await ticketTo(
                         tgts.front, STS))).token),
                       actor_token_type: GSS });
  t.check(x.status === 200,
          'X5. a Kerberos actor_token of the client\'s own service principal ' +
          'is accepted', x.status + ' ' + JSON.stringify(x.json).slice(0, 200));
  proxy = await delegatedToSts(tgts.front);
  x = await exchange({ subject_token: b64u((await apFor(proxy)).token),
                       subject_token_type: GSS,
                       actor_token: b64u((await apFor(await ticketTo(
                         tgts.notrusted, STS))).token),
                       actor_token_type: GSS });
  t.check(x.status === 400 && codeRecorded('STS-OAUTH-0993'),
          'X6. a Kerberos actor_token of another service is refused (0993)',
          x.status + ' ' + JSON.stringify(x.json));
  config.setOverride('oauth2.tokenExchangeKerberosInput', false);
  x = await exchange({ subject_token: b64u((await apFor(proxy)).token),
                       subject_token_type: GSS });
  config.clearOverride('oauth2.tokenExchangeKerberosInput');
  t.check(x.status === 400 && codeRecorded('STS-OAUTH-0987'),
          'X7. input off refuses a Kerberos subject_token_type (0987)',
          x.status + ' ' + JSON.stringify(x.json));
  await new Promise(function (resolve) { server.close(resolve); });
  config.clearOverride('global.publicBaseUrl');

  // --- S. a signature with the token's session key (D7) ---------------
  const xmldsig = require(ROOT + '/common/crypto_impl/xmldsig.js');
  const nodeCrypto = require('crypto');
  const WSU = 'http://docs.oasis-open.org/wss/2004/01/' +
    'oasis-200401-wss-wssecurity-utility-1.0.xsd';
  const HMAC_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256';
  const signedWithKerberos = function (built, o) {
    log.debug("Entering signedWithKerberos().");
    const opts = o || {};
    const now = Date.now();
    const xml = '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-' +
      'envelope" xmlns:wsse="' + WSSE + '" xmlns:wsu="' + WSU + '">' +
      '<s:Header><wsse:Security><wsu:Timestamp wsu:Id="ts"><wsu:Created>' +
      new Date(now).toISOString() + '</wsu:Created><wsu:Expires>' +
      new Date(now + 300000).toISOString() + '</wsu:Expires>' +
      '</wsu:Timestamp><wsse:BinarySecurityToken wsu:Id="krb" ValueType="' +
      GSS + '">' + Buffer.from(built.token).toString('base64') +
      '</wsse:BinarySecurityToken></wsse:Security></s:Header>' +
      '<s:Body wsu:Id="body"><wst:RequestSecurityToken xmlns:wst="' + WST +
      '"><wst:RequestType>' + WST + '/Issue</wst:RequestType>' +
      '<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/' +
      'policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/' +
      '08/addressing"><wsa:Address>' + BACK + '</wsa:Address>' +
      '</wsa:EndpointReference></wsp:AppliesTo>' +
      '</wst:RequestSecurityToken></s:Body></s:Envelope>';
    const keyInfo = opts.byIdentifier
      ? '<wsse:SecurityTokenReference xmlns:wsse="' + WSSE + '">' +
        '<wsse:KeyIdentifier ValueType="' + krb5Tokens.KEY_IDENTIFIER +
        '" EncodingType="' + krb5Tokens.BASE64_ENCODING + '">' +
        (opts.identifier || krb5Tokens.keyIdentifierOf(built.token)) +
        '</wsse:KeyIdentifier></wsse:SecurityTokenReference>'
      : '<wsse:SecurityTokenReference xmlns:wsse="' + WSSE + '">' +
        '<wsse:Reference URI="#krb" ValueType="' + GSS + '"/>' +
        '</wsse:SecurityTokenReference>';
    const hash = opts.sha1 ? 'sha1' : 'sha256';
    let signed = xmldsig.signWsSecurity(xml, {
      sigAlg: opts.sha1 ? 'http://www.w3.org/2000/09/xmldsig#hmac-sha1'
                        : HMAC_SHA256,
      signTimestamp: true, keyInfoXml: keyInfo,
      signer: function (octets) {
        return nodeCrypto.createHmac(hash, Buffer.from(built.subkey.key))
          .update(Buffer.from(String(octets), 'binary')).digest();
      } });
    if (opts.after) {
      signed = opts.after(signed);
    }
    log.debug("Leaving signedWithKerberos().");
    return signed;
  };
  r = await ask(signedWithKerberos(await apFor(aliceSts)));
  t.check(r.status === 200 && textOf(bodyOf(r), 'NameID') === 'alice',
          'S1. an HMAC-SHA256 signature over the Body and Timestamp, keyed ' +
          'by the Kerberos token\'s subkey and naming it by Reference, ' +
          'authenticates alice', r.status + ' ' + faultCode(r));
  r = await ask(signedWithKerberos(await apFor(aliceSts),
                                   { byIdentifier: true }));
  t.check(r.status === 200 && textOf(bodyOf(r), 'NameID') === 'alice',
          'S2. and naming it by its #Kerberosv5APREQSHA1 key identifier',
          r.status + ' ' + faultCode(r));
  r = await ask(signedWithKerberos(await apFor(aliceSts), {
    after: function (xml) {
      return xml.replace(BACK, 'https://kt-elsewhere.example');
    } }));
  t.check(faultCode(r) === 'STS-WSTRUST-0045',
          'S3. a Body altered after signing is refused (0045)', faultCode(r));
  r = await ask(signedWithKerberos(await apFor(aliceSts), {
    after: function (xml) {
      return xml.replace('#hmac-sha256"/>', '#hmac-sha256">' +
        '<ds:HMACOutputLength>80</ds:HMACOutputLength>' +
        '</ds:SignatureMethod>');
    } }));
  t.check(faultCode(r) === 'STS-WSTRUST-0045' &&
          /HMACOutputLength/.test(String(r.body)),
          'S4. a truncated HMAC (HMACOutputLength, CVE-2009-0217) is refused ' +
          '(0045)', faultCode(r));
  r = await ask(signedWithKerberos(await apFor(aliceSts), {
    byIdentifier: true, identifier: 'bm90LXRoZS10b2tlbg==' }));
  t.check(faultCode(r) === 'STS-WSTRUST-0069',
          'S5. a key identifier naming no token in the header (0069)',
          faultCode(r));
  r = await ask(signedWithKerberos(await apFor(aliceSts), { sha1: true }));
  t.check(faultCode(r) === 'STS-WSTRUST-0040',
          'S6. HMAC-SHA1 is SHA-1 to the algorithm policy: refused while ' +
          'saml.allowSha1Signatures is off (0040)', faultCode(r));

  // --- R. across a trust (D8) ------------------------------------------
  const ALPHA = 'KTALPHA.TEST';
  const BETA = 'KTBETA.TEST';
  const IDS = { 'KTALPHA.TEST': 'kt-a', 'KTBETA.TEST': 'kt-b' };
  const SID = { 'KTALPHA.TEST': 'S-1-5-21-6501-6502-6503',
                'KTBETA.TEST': 'S-1-5-21-6601-6602-6603' };
  [ALPHA, BETA].forEach(function (name) {
    realms.remove(IDS[name]);
    const made = realms.create({ id: IDS[name], name: IDS[name],
      description: 'Created by ' + __filename,
      overrides: { 'krb5.realm': name, 'krb5.domainSid': SID[name],
                   'krb5.enabled': 'true' } });
    t.check(made.ok, 'precondition: trust realm ' + IDS[name] + ' for ' +
            name, JSON.stringify(made.errors || []));
  });
  const paired = realms.run(realms.get(IDS[ALPHA]), function () {
    return trusts.pair(IDS[BETA], { password: 'a shared kt trust password',
      attributes: [], suffixes: ['ktbeta.test'] });
  });
  const admitted = grants.admitPartners(realms.get(IDS[BETA]), [SID[ALPHA]],
    ['HTTP/backend.ktbeta.test'], BETA);
  t.check(paired.ok && !admitted.length, 'precondition: ' + ALPHA + ' <-> ' +
          BETA + ' paired, and ' + BETA + '\'s back end admits ' + ALPHA,
          JSON.stringify([paired.errors, admitted]));
  const across = await realms.run(realms.get(IDS[ALPHA]), function () {
    return krb5Tokens.issue({ valueType: GSS,
      subject: { name: 'alice' },
      target: { spn: 'HTTP/backend.ktbeta.test', realm: BETA },
      delegationInfo: { s4u2proxyTarget: 'HTTP/backend.ktbeta.test',
                        transitedServices: ['HTTP/frontend.ktalpha.test@' +
                                            ALPHA] },
      forwardable: true });
  });
  opened = across.ok ? await openToken(across.token, GSS,
    { name: ['HTTP', 'backend.ktbeta.test'] }, realms.get(IDS[BETA])) : {};
  t.check(across.ok && opened.part &&
          opened.part.cname.name.join('/') === 'alice' &&
          opened.part.crealm === ALPHA && opened.delegation &&
          (opened.delegation.transitedServices || []).indexOf(
            'HTTP/frontend.ktalpha.test@' + ALPHA) >= 0,
          'R1. a Kerberos token for a service of the paired realm, minted by ' +
          'walking the trust through its KDC: the far service\'s key opens ' +
          'it, alice@' + ALPHA + ' is its client and the PAC keeps ' +
          'S4U_DELEGATION_INFO', JSON.stringify(across.ok ? {
            cname: opened.part && opened.part.cname.name,
            crealm: opened.part && opened.part.crealm,
            delegation: opened.delegation } : across));
  const nowhere = await realms.run(realms.get(IDS[ALPHA]), function () {
    return krb5Tokens.issue({ valueType: GSS, subject: { name: 'alice' },
      target: { spn: 'HTTP/x.nowhere.test', realm: 'NOWHERE.TEST' } });
  });
  t.check(!nowhere.ok && nowhere.errorCode === 'STS-KRB-0251',
          'R2. a realm no trust routes to is refused (STS-KRB-0251)',
          JSON.stringify(nowhere));
  [ALPHA, BETA].forEach(function (name) {
    realms.remove(IDS[name]);
  });
  log.debug("Leaving childBody().");
  return t.rows;
}

function spawnChild() {
  log.debug("Entering spawnChild().");
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|LDAPS_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  clean[CHILD_FLAG] = '1';
  clean.LOG_LEVEL = process.env.KT_CHILD_LOG_LEVEL || 'fatal';
  clean.STS_HTTPS = 'false';
  const result = childProcess.spawnSync(process.execPath, [__filename], {
    cwd: ROOT, env: clean, encoding: 'utf8', timeout: 300000,
    maxBuffer: 64 * 1024 * 1024
  });
  const line = String(result.stdout || '').split('\n').filter(function (one) {
    return one.indexOf(MARK) === 0;
  })[0];
  if (!line) {
    log.debug("Leaving spawnChild(). No result.");
    return { error: 'the child produced no result (exit ' + result.status +
                    '): ' + String(result.stderr || '').slice(-3000) };
  }
  log.debug("Leaving spawnChild().");
  return { rows: JSON.parse(line.slice(MARK.length)) };
}

function run(t) {
  log.debug("Entering run().");
  const got = spawnChild();
  if (got.error) {
    log.debug("Leaving run(). The child failed.");
    throw new Error(got.error);
  }
  got.rows.forEach(function (row) {
    t.check(row.ok, row.what, row.detail);
  });
  log.debug("Leaving run().");
}

if (process.env[CHILD_FLAG] === '1' && require.main === module) {
  childBody().then(function (rows) {
    process.stdout.write('\n' + MARK + JSON.stringify(rows) + '\n');
    process.exit(0);
  }, function (e) {
    process.stderr.write('child failed: ' + String((e && e.stack) || e) +
                         '\n');
    process.exit(1);
  });
}

module.exports = {
  name: 'kerberos_tokens',
  describe: 'Kerberos tokens (the Kerberos Token Profile 1.1\'s AP-REQ) in ' +
            'WS-Trust and the RFC 8693 token exchange: accepted by the ' +
            'acceptor as the requester and in Kerberos\'s own delegation ' +
            'syntax, issued by the KDC, across a trust (#658)',
  run: run
};

// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
// File: pac_claims.js
// ===========================================================================
// KERBEROS PAC CLIENT CLAIMS (#493, 2026-10-06): PAC_CLIENT_CLAIMS_INFO
// ([MS-PAC] 2.11, buffer type 13) in the tickets this KDC issues, from the
// sixth claim set, `kerberos-pac`.
//
//   A. THE ROWS: the set's own rules — a name that makes a claim id, one of
//      the four PAC types, a fixed value held to its type, no catalogue half
//      — and the claim id's derivation.
//   B. OFF: with `krb5.pacClaims` off a TGT carries no claims buffer at all.
//   C. A TGT: the realm's set, typed, the person's roles as a string claim,
//      a directory attribute, a placeholder; every PAC signature verifies.
//   D. A SERVICE TICKET carries its TGT's claims — read out of the TGT, not
//      re-evaluated: a change to the set after the TGT is not in it — and
//      the application override applies to THAT SPN's tickets only, adding
//      a claim and replacing one by name.
//   E. S4U2SELF carries the IMPERSONATED person's claims (not the service's)
//      and S4U2PROXY carries the evidence's, with the target's override.
//   F. A CROSS-REALM RE-SIGN (EXAMPLE.COM to PARTNER.COM) carries the
//      claims buffer byte for byte, under new signatures that verify.
//
// In process, through `kdc.handleMessage()` and the local client
// `tests/vendored/krb5_wire.js`, because every assertion opens a ticket with
// its service's key — which only the inside holds. Development mode, so the
// fixture principals and the trusted realm exist.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const config = require('../common/config');
require('../common/app');
require('../ldap/ldap_server');
const stats = require('../common/admin_stats');
const roles = require('../common/roles');
const applications = require('../common/applications');
const adminActions = require('../admin-core/admin_actions');
const principals = require('../kerberos/krb5_principals.js');
const kdc = require('../kerberos/krb5_kdc.js');
const kcrypto = require('../kerberos/krb5_crypto.js');
const kpac = require('../kerberos/krb5_pac.js');
const wire = require('./vendored/krb5_wire.js');

const log = require('bunyan').createLogger({ name: 'pac_claims',
  level: process.env.LOG_LEVEL || 'info' });

const msgs = wire.msgs;
const REALM = principals.REALM;
const DOMAIN = REALM.toLowerCase();
const PARTNER = 'PARTNER.COM';
const RUN = nodeCrypto.randomBytes(3).toString('hex');
const ROLE = 'pac-role-' + RUN;
const T = {
  label: 'in-process',
  send: function (bytes) {
    log.debug("Entering send().");
    log.debug("Leaving send().");
    return kdc.handleMessage(bytes);
  }
};

function spn(host, domain) {
  log.debug("Entering spn().");
  log.debug("Leaving spn().");
  return { type: 3, name: ['HTTP', host + '.' + (domain || DOMAIN)] };
}

function idOf(name) {
  log.debug("Entering idOf().");
  const hex = nodeCrypto.createHash('sha256').update(name, 'utf8')
    .digest('hex').slice(0, 16);
  log.debug("Leaving idOf().");
  return 'ad://ext/' + name + ':' + hex;
}

// A ticket opened with its service's key the way the service would, and its
// PAC parsed; the claims as `{ id: values }`, and whether every signature
// this side can check verifies.
async function opened(ticket, name, realm) {
  log.debug("Entering opened(). " + name.join('/') + '@' + realm);
  const service = principals.find(name, realm);
  const etype = ticket.encPart.etype;
  const serverKey = { etype: etype,
                      key: await principals.longTermKey(service, etype) };
  const part = msgs.readEncTicketPart(await kcrypto.etypeById(etype).decrypt(
    serverKey.key, kcrypto.KEY_USAGE.KDC_REP_TICKET, ticket.encPart.cipher));
  const pacs = kpac.findPacs(part.authorizationData || []);
  const out = { pac: null, buffer: null, claims: null, signatures: null };
  if (!pacs.length) {
    log.debug("Leaving opened(). No PAC.");
    return out;
  }
  out.pac = kpac.parsePac(pacs[0].bytes);
  out.buffer = kpac.bufferOfType(out.pac, kpac.TYPE.CLIENT_CLAIMS);
  if (out.buffer && out.buffer.parsed) {
    out.claims = {};
    out.buffer.parsed.claims.forEach(function (claim) {
      out.claims[claim.id] = { type: claim.typeName, values: claim.values };
    });
  }
  const kdcSig = kpac.bufferOfType(out.pac, kpac.TYPE.KDC_CHECKSUM);
  const kdcEtype = kpac.profileForSignatureType(
    kdcSig.parsed.signatureType).id;
  const krbtgt = principals.find(['krbtgt', realm], realm);
  const results = await kpac.verifySignatures(out.pac, {
    serverKey: serverKey,
    kdcKey: { etype: kdcEtype,
              key: await principals.longTermKey(krbtgt, kdcEtype) } });
  out.signatures = results.every(function (r) {
    return r.verified !== false;
  }) && results.some(function (r) {
    return r.type === kpac.TYPE.SERVER_CHECKSUM && r.verified === true;
  }) && results.some(function (r) {
    return r.type === kpac.TYPE.KDC_CHECKSUM && r.verified === true;
  });
  log.debug("Leaving opened().");
  return out;
}

function valuesOf(seen, name) {
  log.debug("Entering valuesOf().");
  const claim = seen.claims ? seen.claims[idOf(name)] : null;
  log.debug("Leaving valuesOf().");
  return claim ? JSON.stringify([claim.type, claim.values]) : 'none';
}

async function tgtOf(t, name, password) {
  log.debug("Entering tgtOf(). " + name);
  const got = await wire.asExchange(T, REALM, name, { password: password });
  t.check(!!got.tgt, 'precondition: a TGT for ' + name,
          JSON.stringify(got.second || got.first));
  log.debug("Leaving tgtOf().");
  return got.tgt;
}

function act(body) {
  log.debug("Entering act(). " + body.action);
  log.debug("Leaving act().");
  return adminActions.claimsAction(Object.assign({ set: 'kerberos-pac' },
                                                 body), [],
                                   stats.KERBEROS_CLAIM_SET_IDS);
}

// An application's own PAC rows, on the entry of the application that
// registered `name`, made when there is none.
function override(name, rows) {
  log.debug("Entering override(). " + name);
  const identifier = name;
  if (!applications.get(identifier)) {
    applications.createApplication({
      identifier: identifier, kind: 'kerberos-service', protocols: ['krb5'],
      fields: { krb5ServicePrincipalName: [identifier] },
      actor: 'pac_claims.js' });
  }
  const write = applications.updateApplication(identifier, {
    attribute: 'krb5ClaimsPac', mode: 'set',
    value: rows.length ? JSON.stringify(rows) : '',
    actor: 'pac_claims.js' });
  log.debug("Leaving override().");
  return write;
}

function theRows(t) {
  log.debug("Entering theRows().");
  t.log.info('=== A. the rows ===');
  const refusals = [
    [{ action: 'add', name: 'has space', value: 'x' }, 'STS-REG-0336'],
    [{ action: 'add', name: 'level', type: 'number', value: '1' },
     'STS-REG-0337'],
    [{ action: 'add', name: 'level', type: 'int64', value: 'ten' },
     'STS-REG-0338'],
    [{ action: 'add', name: 'big', type: 'uint64', value: '-1' },
     'STS-REG-0338'],
    [{ action: 'add', name: 'flag', type: 'boolean', value: 'yes' },
     'STS-REG-0338'],
    [{ action: 'attributes', attributes: ['mail'] }, 'STS-ADMIN-0848']
  ];
  refusals.forEach(function (pair, at) {
    const r = act(pair[0]);
    const code = require('../common/error_codes').codeOf(r);
    t.check(r.ok === false && code === pair[1], 'A' + (at + 1) + '. ' +
            JSON.stringify(pair[0]) + ' is refused, ' + pair[1],
            JSON.stringify([r.ok, code, r.errors]));
  });
  t.check(act({ action: 'add', name: 'ad://ext/Dept:0123abcd',
                value: 'whole id' }).ok === true &&
          stats.pacClaimId('ad://ext/Dept:0123abcd') ===
            'ad://ext/Dept:0123abcd' &&
          act({ action: 'remove', name: 'ad://ext/Dept:0123abcd' }).ok,
          'A7. a whole ad://ext/<name>:<hex> id is taken as written');
  t.check(stats.pacClaimId('department') === idOf('department'),
          'A8. a claim id is ad://ext/<name>:<the first 16 hex of SHA-256 ' +
          'over the name>', stats.pacClaimId('department'));
  const replaced = act({ action: 'replace', claims: [
    { name: 'department', type: 'string', value: 'Engineering' },
    { name: 'level', type: 'int64', value: '-5' },
    { name: 'clearance', type: 'uint64', value: '18446744073709551615' },
    { name: 'active', type: 'boolean', value: 'true' },
    { name: 'who', type: 'string', value: '${username}' },
    { name: 'badge', type: 'int64', value: '${username}' },
    { name: 'mailclaim', attribute: 'mail', type: 'string' }
  ] });
  t.check(replaced.ok === true, 'A9. a whole set of every type, a ' +
          'placeholder and an attribute row is accepted',
          JSON.stringify(replaced.errors || ''));
  log.debug("Leaving theRows().");
}

async function run(t) {
  log.debug("Entering run().");
  const userPassword = String(config.value('krb5.userPassword'));
  theRows(t);
  const role = roles.write(ROLE, { users: ['alice'] });
  t.check(role.ok === true, 'precondition: alice holds ' + ROLE,
          JSON.stringify(role));

  // B. OFF.
  t.log.info('=== B. off ===');
  config.setOverride('krb5.pacClaims', false);
  let tgt = await tgtOf(t, 'alice', userPassword);
  let seen = tgt ? await opened(tgt.ticket, ['krbtgt', REALM], REALM) : {};
  t.check(!!seen.pac && seen.buffer === null, 'B1. krb5.pacClaims off: the ' +
          'TGT has a PAC and no claims buffer');
  const sidsOff = seen.pac ? JSON.stringify(kpac.bufferOfType(seen.pac,
    kpac.TYPE.LOGON_INFO).parsed.extraSids) : '';

  // C. A TGT.
  t.log.info('=== C. a TGT ===');
  config.setOverride('krb5.pacClaims', true);
  // An application for the krbtgt SPN with rows of its own: a TGT carries the
  // realm's set ALONE (rcbj's decision 1), so these must not reach it.
  const krbtgtSpn = 'krbtgt/' + REALM + '@' + REALM;
  const tgtOverride = override(krbtgtSpn, [
    { name: 'tgtonly', type: 'string', value: 'never' }]);
  tgt = await tgtOf(t, 'alice', userPassword);
  if (!tgt) {
    log.debug("Leaving run(). No TGT.");
    return;
  }
  seen = await opened(tgt.ticket, ['krbtgt', REALM], REALM);
  t.check(valuesOf(seen, 'department') === '["STRING",["Engineering"]]' &&
          valuesOf(seen, 'level') === '["INT64",["-5"]]' &&
          valuesOf(seen, 'clearance') ===
            '["UINT64",["18446744073709551615"]]' &&
          valuesOf(seen, 'active') === '["BOOLEAN",[true]]',
          'C1. the TGT\'s PAC decodes with the four typed claims, by their ' +
          'derived ids', JSON.stringify(seen.claims));
  t.check(valuesOf(seen, 'who') === '["STRING",["alice"]]' &&
          /^\["STRING",\["[^"]+@[^"]+"\]\]$/.test(
            valuesOf(seen, 'mailclaim')),
          'C2. a placeholder is expanded and a directory attribute is read',
          JSON.stringify(seen.claims));
  t.check(valuesOf(seen, 'badge') === 'none',
          'C3. a placeholder that is not its type (int64 "alice") leaves ' +
          'that claim out, and only that one (STS-KRB-0200)');
  const roleClaim = String(config.value('roles.claimName') || 'roles');
  t.check(seen.claims && seen.claims[idOf(roleClaim)] &&
          seen.claims[idOf(roleClaim)].values.indexOf(ROLE) >= 0,
          'C4. the person\'s roles are a STRING claim (decision 3)',
          JSON.stringify(seen.claims && seen.claims[idOf(roleClaim)]));
  t.check(JSON.stringify(kpac.bufferOfType(seen.pac,
    kpac.TYPE.LOGON_INFO).parsed.extraSids) === sidsOff,
          'C5. and the logon information\'s extraSids are what they were ' +
          'with claims off: nothing is added for a role');
  t.check(seen.signatures === true, 'C6. the TGT\'s PAC signatures verify ' +
          'over the claims buffer');
  t.check(seen.buffer.parsed.compressionName === 'COMPRESSION_FORMAT_NONE',
          'C7. never compressed (decision 4)');
  t.check(!!(tgtOverride && tgtOverride.ok) &&
          valuesOf(seen, 'tgtonly') === 'none',
          'C8. an application registered for the krbtgt SPN adds nothing to ' +
          'a TGT: the override is a service ticket\'s',
          JSON.stringify(tgtOverride));
  override(krbtgtSpn, []);

  // D. A SERVICE TICKET.
  t.log.info('=== D. a service ticket ===');
  const changed = act({ action: 'add', name: 'department', type: 'string',
                        value: 'Changed' });
  // `add` of an existing name is refused as a duplicate; replace the row.
  const rows = stats.claimSet('kerberos-pac').map(function (row) {
    return row.name === 'department' ? Object.assign({}, row,
      { value: 'Changed' }) : row;
  });
  t.check(changed.ok === false && stats.setClaimSet('kerberos-pac',
          rows).ok === true, 'precondition: the realm set changes AFTER ' +
          'the TGT was issued');
  override('HTTP/web.' + DOMAIN + '@' + REALM, [
    { name: 'department', type: 'string', value: 'Web team' },
    { name: 'webonly', type: 'boolean', value: 'true' }]);
  let r = await wire.tgsExchange(T, tgt, spn('backend'), REALM, {});
  seen = r.ok ? await opened(r.ticket, spn('backend').name, REALM) : {};
  t.check(r.ok && valuesOf(seen, 'department') ===
            '["STRING",["Engineering"]]' &&
          valuesOf(seen, 'who') === '["STRING",["alice"]]' &&
          valuesOf(seen, 'webonly') === 'none',
          'D1. a service ticket for a service with no override carries its ' +
          'TGT\'s claims — the old department, NOT re-evaluated',
          JSON.stringify(r.ok ? seen.claims : String(r.error)));
  t.check(seen.signatures === true, 'D2. its four-signature PAC verifies');
  r = await wire.tgsExchange(T, tgt, spn('web'), REALM, {});
  seen = r.ok ? await opened(r.ticket, spn('web').name, REALM) : {};
  t.check(r.ok && valuesOf(seen, 'department') === '["STRING",["Web team"]]' &&
          valuesOf(seen, 'webonly') === '["BOOLEAN",[true]]' &&
          valuesOf(seen, 'level') === '["INT64",["-5"]]',
          'D3. for the SPN whose application has rows of its own: those ' +
          'added and winning by name, the rest the TGT\'s',
          JSON.stringify(r.ok ? seen.claims : String(r.error)));

  // E. S4U.
  t.log.info('=== E. S4U2Self and S4U2Proxy ===');
  const front = await tgtOf(t, 'HTTP/frontend.' + DOMAIN,
                            'frontend-service-password');
  if (front) {
    r = await wire.tgsExchange(T, front, front.client, REALM, {
      padata: async function () {
        return [await wire.paForUser(front, 'alice', REALM)];
      } });
    seen = r.ok ? await opened(r.ticket, front.client.name, REALM) : {};
    t.check(r.ok && valuesOf(seen, 'who') === '["STRING",["alice"]]' &&
            valuesOf(seen, 'department') === '["STRING",["Changed"]]',
            'E1. S4U2Self carries the IMPERSONATED person\'s claims, ' +
            'evaluated now — not the service\'s own', JSON.stringify(
              r.ok ? seen.claims : String(r.error)));
    const evidence = r.ticket;
    override('HTTP/backend.' + DOMAIN + '@' + REALM, [
      { name: 'proxied', type: 'string', value: 'via ${username}' }]);
    r = await wire.tgsExchange(T, front, spn('backend'), REALM, {
      kdcOptions: [msgs.KDC_OPTION.CNAME_IN_ADDL_TKT],
      additionalTickets: [evidence] });
    seen = r.ok ? await opened(r.ticket, spn('backend').name, REALM) : {};
    t.check(r.ok && valuesOf(seen, 'who') === '["STRING",["alice"]]' &&
            valuesOf(seen, 'proxied') === '["STRING",["via alice"]]' &&
            seen.signatures === true,
            'E2. S4U2Proxy carries the evidence\'s claims, with the back ' +
            'end\'s own rows merged, re-signed and verifying',
            JSON.stringify(r.ok ? seen.claims : String(r.error)));
    override('HTTP/backend.' + DOMAIN + '@' + REALM, []);
  }

  // F. CROSS-REALM.
  t.log.info('=== F. a cross-realm re-sign ===');
  const target = spn('app', PARTNER.toLowerCase());
  const referral = await wire.tgsExchange(T, tgt, target, REALM, {});
  t.check(referral.ok && referral.sname.name.join('/') ===
            'krbtgt/' + PARTNER,
          'precondition: a referral to ' + PARTNER,
          JSON.stringify(referral.ok ? referral.sname : String(
            referral.error)));
  if (referral.ok) {
    const tgtSeen = await opened(tgt.ticket, ['krbtgt', REALM], REALM);
    r = await wire.tgsExchange(T, referral, target, PARTNER, {});
    seen = r.ok ? await opened(r.ticket, target.name, PARTNER) : {};
    t.check(r.ok && !!seen.buffer && !!tgtSeen.buffer &&
            Buffer.from(seen.buffer.bytes).equals(
              Buffer.from(tgtSeen.buffer.bytes)),
            'F1. ' + PARTNER + ' re-signs the PAC and carries the claims ' +
            'buffer BYTE FOR BYTE', String(r.error || ''));
    t.check(seen.signatures === true, 'F2. under ' + PARTNER + '\'s keys, ' +
            'every signature it checks verifies');
  }

  // Cleanup: the set and the override, so a later file meets a clean realm.
  override('HTTP/web.' + DOMAIN + '@' + REALM, []);
  stats.setClaimSet('kerberos-pac', []);
  roles.remove(ROLE);
  config.setOverride('krb5.pacClaims', false);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pac_claims',
  describe: 'Kerberos PAC client claims (#493): the kerberos-pac set\'s ' +
            'rows, a TGT\'s claims, a service ticket\'s carried claims and ' +
            'its application override, S4U2Self / S4U2Proxy and a ' +
            'cross-realm re-sign, every PAC signature verifying',
  run: run
};

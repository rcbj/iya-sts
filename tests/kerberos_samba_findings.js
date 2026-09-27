'use strict';
//
// File: kerberos_samba_findings.js
//
// ===========================================================================
// WHAT SAMBA'S RAW KERBEROS TESTS FOUND IN THE KDC, HELD IN PROCESS (#204).
//
// tests/vendored/sts_kerberos_samba.js runs Samba's python/samba/tests/krb5
// against a running KDC and is the whole of the check; this file holds the
// fixes that are cheapest to break without noticing, in a development child
// whose KDC is driven by `tests/vendored/krb5_wire.js` over an in-process
// transport that also keeps the raw replies:
//
//   1. ETYPE-INFO2 in KDC_ERR_PREAUTH_REQUIRED lists the request's own
//      enctypes in its order; PA-ETYPE-INFO and PA-PW-SALT come with it only
//      when no newer enctype was asked for (RFC 4120 3.1.3, 5.2.7.5).
//   2. The AS-REP carries one PA-ETYPE-INFO2 entry and the client key's kvno
//      in its enc-part (5.2.7.5, 5.2.9) — none for an rc4-hmac reply.
//   3. The TGT is sealed with the krbtgt's strongest key whatever the client
//      listed first, and carries enc-pa-rep (RFC 6806 section 11).
//   4. A service ticket presented in a PA-TGS-REQ buys nothing:
//      KRB_AP_ERR_NOT_US, STS-KRB-0166 (RFC 4120 3.3.3).
//   5. A service ticket's PAC carries neither PAC_ATTRIBUTES_INFO nor
//      PAC_REQUESTOR; the TGT's does.
//
// FAST in the TGS exchange, hide-client-names, user-to-user and RFC 6806's
// checksum need a client this suite does not have; Samba's tests over TCP are
// their check (the job's passing tests are listed in its log).
// ===========================================================================

delete process.env.CONFIG_FILE;

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'kerberos_samba_findings',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

/* eslint-disable no-undef */
// THE CHILD'S PROGRAM. Serialised with toString() and run with `node -e`,
// which the code style exempts from the Entering/Leaving lines.
async function child() {
  const R = process.env.KS_ROOT;
  const out = {};
  const config = require(R + '/common/config');
  const principals = require(R + '/kerberos/krb5_principals.js');
  const kdc = require(R + '/kerberos/krb5_kdc.js');
  const msgs = require(R + '/kerberos/krb5_messages.js');
  const kcrypto = require(R + '/kerberos/krb5_crypto.js');
  const kpac = require(R + '/kerberos/krb5_pac.js');
  const wire = require(R + '/tests/vendored/krb5_wire.js');
  const replies = [];
  const recorded = [];
  const inproc = { label: 'in-process', send: async function (bytes) {
    const reply = await kdc.handleMessage(bytes);
    replies.push(reply);
    Object.getOwnPropertySymbols(reply).forEach(function (sym) {
      if (reply[sym] && reply[sym].code) {
        recorded.push(reply[sym].code);
      }
    });
    return reply;
  } };
  const REALM = principals.REALM;
  const PW = String(config.value('krb5.userPassword'));
  const krbtgt = principals.find(['krbtgt', REALM], REALM);
  out.krbtgtStrongest = principals.supportedEtypes(krbtgt)[0];

  // The padata of a KRB-ERROR's e-data: types, and ETYPE-INFO2's entries.
  const errorPadata = function (bytes) {
    const e = msgs.readKrbError(bytes);
    const pads = e.eDataPaData || [];
    const info2 = pads.filter(function (pa) {
      return pa.type === 19;
    })[0];
    return { types: pads.map(function (pa) {
      return pa.type;
    }), info2: info2 ? msgs.readEtypeInfo2(info2.value).map(function (x) {
      return x.etype;
    }) : null };
  };
  const firstError = async function (etypes) {
    replies.length = 0;
    await wire.asExchange(inproc, REALM, 'samba-findings',
                          { password: PW, etypes: etypes });
    return errorPadata(replies[0]);
  };
  out.pre23 = await firstError([23]);
  out.pre17 = await firstError([17, 23]);
  out.pre18 = await firstError([18, 17]);

  const asRep = async function (etypes) {
    replies.length = 0;
    const r = await wire.asExchange(inproc, REALM, 'samba-findings',
                                    { password: PW, etypes: etypes });
    const rep = msgs.readKdcResponse(replies[replies.length - 1]).rep;
    const pads = rep.padata || [];
    return { tgt: r.tgt, rep: rep, padTypes: pads.map(function (pa) {
      return pa.type;
    }), info2: pads.filter(function (pa) {
      return pa.type === 19;
    }).map(function (pa) {
      return msgs.readEtypeInfo2(pa.value).map(function (x) {
        return x.etype;
      });
    })[0] || null };
  };
  const aes128 = await asRep([17]);
  out.aes128 = { ok: !!aes128.tgt, padTypes: aes128.padTypes,
                 info2: aes128.info2, kvno: aes128.rep.encPart.kvno,
                 replyEtype: aes128.rep.encPart.etype,
                 ticketEtype: aes128.rep.ticket.encPart.etype,
                 flags: aes128.tgt ? aes128.tgt.flagNames : null };
  const rc4 = await asRep([23]);
  out.rc4 = { ok: !!rc4.tgt, padTypes: rc4.padTypes,
              replyEtype: rc4.rep.encPart.etype,
              ticketEtype: rc4.rep.ticket.encPart.etype };
  out.clientKvno = principals.find(['samba-findings'], REALM).kvno;

  // 4 and 5: a service ticket, then that ticket presented as a TGT.
  const aes = await asRep([18]);
  const sname = { type: 3, name: ['HTTP', 'web.' + REALM.toLowerCase()] };
  const ticket = await wire.tgsExchange(inproc, aes.tgt, sname);
  out.serviceTicket = ticket.ok;
  const pacTypes = async function (tkt, principal) {
    const key = await principals.longTermKey(principal, tkt.encPart.etype);
    const part = msgs.readEncTicketPart(
      await kcrypto.etypeById(tkt.encPart.etype).decrypt(key,
        kcrypto.KEY_USAGE.KDC_REP_TICKET, tkt.encPart.cipher));
    const pac = kpac.findPacs(part.authorizationData || [])[0];
    return pac ? kpac.parsePac(pac.bytes).buffers.map(function (b) {
      return b.type;
    }) : null;
  };
  out.tgtPac = await pacTypes(aes.rep.ticket, krbtgt);
  if (ticket.ok) {
    out.servicePac = await pacTypes(ticket.ticket,
                                    principals.find(sname.name, REALM));
    recorded.length = 0;
    const reused = await wire.tgsExchange(inproc, ticket,
      { type: 3, name: ['HTTP', 'frontend.' + REALM.toLowerCase()] });
    out.reused = { ok: reused.ok, code: reused.ok ? null : reused.error.code,
                   codes: recorded.slice() };
  }
  return out;
}
/* eslint-enable no-undef */

function inAChild(t) {
  log.debug("Entering inAChild().");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krb5-samba-'));
  const outFile = path.join(dir, 'report.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(KRB5_|STS_|LDAP_|SCIM_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const script = 'delete process.env.CONFIG_FILE;' +
    '(' + child.toString() + ')().then(function (r) ' +
    '{require("fs").writeFileSync(process.env.KS_OUT, JSON.stringify(r)); ' +
    'process.exit(0); }).catch(function (e) { ' +
    'require("fs").writeFileSync(process.env.KS_OUT, JSON.stringify({ ' +
    'crashed: e.stack || e.message })); process.exit(0); });';
  const run = childProcess.spawnSync(process.execPath, ['-e', script], {
    env: Object.assign(clean, { LOG_LEVEL: 'warn', STS_LOG_LEVEL: 'warn',
                                KS_ROOT: ROOT, KS_OUT: outFile }),
    encoding: 'utf8', timeout: 240000, cwd: ROOT,
    maxBuffer: 64 * 1024 * 1024
  });
  let report = null;
  try {
    report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one; said below.
    report = null;
  }
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    // A temporary directory left behind is litter, not a failure.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  t.check(report !== null && !report.crashed, 'the development child ran ' +
          'to the end', 'exit ' + run.status + ' ' +
          (report && report.crashed) + ' ' +
          String(run.stderr || '').slice(-1200));
  log.debug("Leaving inAChild().");
  return report || {};
}

async function run(t) {
  log.debug("Entering run().");
  const r = inAChild(t);
  const j = JSON.stringify;
  t.log.info('=== 1. the salt hints follow the request ===');
  t.check(r.pre23 && j(r.pre23.info2) === j([23]) &&
          r.pre23.types.indexOf(11) >= 0 && r.pre23.types.indexOf(3) >= 0,
          'rc4-hmac alone: ETYPE-INFO2 names 23 only, and PA-ETYPE-INFO and ' +
          'PA-PW-SALT come with it', j(r.pre23));
  t.check(r.pre17 && j(r.pre17.info2) === j([17, 23]) &&
          r.pre17.types.indexOf(11) < 0 && r.pre17.types.indexOf(3) < 0,
          'aes128 then rc4-hmac: ETYPE-INFO2 is [17, 23] in the request\'s ' +
          'order, with neither PA-ETYPE-INFO nor PA-PW-SALT', j(r.pre17));
  t.check(r.pre18 && j(r.pre18.info2) === j([18, 17]),
          'aes256 then aes128: [18, 17]', j(r.pre18));
  t.log.info('=== 2. the AS-REP says which key sealed it ===');
  t.check(r.aes128 && r.aes128.ok && j(r.aes128.info2) === j([17]) &&
          j(r.aes128.padTypes) === j([19]) && r.aes128.replyEtype === 17 &&
          r.aes128.kvno === r.clientKvno && typeof r.clientKvno === 'number',
          'an aes128 AS-REP carries one PA-ETYPE-INFO2 entry of 17 and the ' +
          'client key\'s kvno in its enc-part', j([r.aes128, r.clientKvno]));
  t.check(r.rc4 && r.rc4.ok && j(r.rc4.padTypes) === j([]) &&
          r.rc4.replyEtype === 23,
          'an rc4-hmac AS-REP carries no salt hint', j(r.rc4));
  t.log.info('=== 3. the TGT is sealed with the krbtgt\'s strongest key ===');
  t.check(r.aes128.ticketEtype === r.krbtgtStrongest &&
          r.rc4.ticketEtype === r.krbtgtStrongest &&
          r.krbtgtStrongest === 18,
          'asked for 17 or 23, the TGT is sealed with 18', j([r.aes128,
                                                              r.rc4]));
  t.check(Array.isArray(r.aes128.flags) &&
          r.aes128.flags.indexOf('enc-pa-rep') >= 0,
          'the TGT carries enc-pa-rep (RFC 6806 section 11)',
          j(r.aes128.flags));
  t.log.info('=== 4. a service ticket buys nothing ===');
  t.check(r.serviceTicket === true && r.reused && r.reused.ok === false &&
          r.reused.code === 35 &&
          r.reused.codes.indexOf('STS-KRB-0166') >= 0,
          'a service ticket in a PA-TGS-REQ is KRB_AP_ERR_NOT_US ' +
          '(STS-KRB-0166)', j(r.reused));
  t.log.info('=== 5. the TGT-only PAC buffers ===');
  t.check(Array.isArray(r.tgtPac) && r.tgtPac.indexOf(17) >= 0 &&
          r.tgtPac.indexOf(18) >= 0,
          'the TGT\'s PAC carries PAC_ATTRIBUTES_INFO and PAC_REQUESTOR',
          j(r.tgtPac));
  t.check(Array.isArray(r.servicePac) && r.servicePac.indexOf(17) < 0 &&
          r.servicePac.indexOf(18) < 0 && r.servicePac.indexOf(1) >= 0,
          'a service ticket\'s PAC carries neither', j(r.servicePac));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'kerberos_samba_findings',
  describe: '#204: what Samba\'s raw Kerberos tests found — ETYPE-INFO2 in ' +
            'the request\'s order with PA-ETYPE-INFO and PA-PW-SALT only ' +
            'beside no newer enctype, the AS-REP\'s salt hint and kvno, the ' +
            'TGT under the krbtgt\'s strongest key with enc-pa-rep, a ' +
            'service ticket refused in a PA-TGS-REQ, and the TGT-only PAC ' +
            'buffers',
  run: run
};

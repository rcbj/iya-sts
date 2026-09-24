'use strict';
//
// File: caep_credential_units.js
//
// ===========================================================================
// THE PURE HALVES OF #145 (CAEP from every door, 2026-09-22), in process:
//
//   A. `common/crypto.js`'s certificateIdentifiers(): the issuer as an RFC
//      4514 string (most specific RDN first, the comma in "Acme, Inc" kept
//      escaped once), the serial as lower-case hex, the subject too, and
//      empty strings for something that is not a certificate.
//   B. userAgentFingerprint(): the base64url SHA-256 of the header, and ''
//      for none — a fingerprint, never the header.
//   C. `Credentials.aaguidString()` and `AccountSignals.keyCredentialType()`:
//      a UUID from 32 hex digits, none for all zeros, and platform against
//      roaming from the recorded attachment.
//   D. `AccountSignals.certificateChanged()` hands SSF an `x509` change with
//      the certificate's issuer and serial, and never the PEM.
//   E. `CaepRegister.claimsChangeFor()`: only a claim that moved, its new
//      value, `null` for one emptied, a nested claim nested, the groups
//      claim as the whole list for a membership or memberOf change, and
//      nothing for a write that moved no claim.
//   F. `admin_stats.holdsLiveIssuance()`: a valid token that names the person
//      counts, somebody else's does not, and a revoked one does not.
//
// `sts_caep_credential_changes.js` holds the same over the wire. In a child
// process, because it loads the protocol stack.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'caep_credential_units',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

// A self-signed P-256 certificate, subject and issuer
// "C=US, O=Acme, Inc, CN=Test CA", serial 0x0a1b2c3d, valid for a century.
const FIXTURE_PEM =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIBrTCCAVOgAwIBAgIEChssPTAKBggqhkjOPQQDAjAzMQswCQYDVQQGEwJVUzES\n' +
  'MBAGA1UECgwJQWNtZSwgSW5jMRAwDgYDVQQDDAdUZXN0IENBMCAXDTI2MDkyMjIy\n' +
  'MzA0NloYDzIxMjYwODI5MjIzMDQ2WjAzMQswCQYDVQQGEwJVUzESMBAGA1UECgwJ\n' +
  'QWNtZSwgSW5jMRAwDgYDVQQDDAdUZXN0IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n' +
  'AQcDQgAEgWvwNM/eryjY8T8aGnR8y2nBCOxGbSEBtztieF9FhQkpuZ2iD6YFZBk4\n' +
  'YwI1C0ZeYcBXKfytA3Je/XEP+a95paNTMFEwHQYDVR0OBBYEFJKGplHZESOx55nV\n' +
  'eRe+kYi63MiMMB8GA1UdIwQYMBaAFJKGplHZESOx55nVeRe+kYi63MiMMA8GA1Ud\n' +
  'EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAOFiQ4cMm/50xeQheZDDmOLM\n' +
  'Kckza2eEKA1EJtEtsZvhAiBxhbO+RuVdVZUUyXlQhSLtHqz5Px84Hq2AyMPzAFYy\n' +
  '6w==\n' +
  '-----END CERTIFICATE-----\n';

function childMain() {
  const ROOT = process.env.CCU_ROOT;
  const OUT = process.env.CCU_OUT;
  const PEM = process.env.CCU_PEM;
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
    return !!ok;
  }
  function eq(got, want, what) {
    return note(JSON.stringify(got) === JSON.stringify(want), what,
                'expected ' + JSON.stringify(want) + ', got ' +
                JSON.stringify(got));
  }
  try {
    require(ROOT + '/common/protocol_stack');
    const stsCrypto = require(ROOT + '/common/crypto');
    const credentials = require(ROOT + '/common/credentials');
    const accountSignals = require(ROOT + '/ssf/account_signals');
    const caep = require(ROOT + '/ssf/caep');
    const helpers = require(ROOT + '/common/helpers');
    const stats = require(ROOT + '/common/admin_stats');

    // --- A -------------------------------------------------------------
    const ids = stsCrypto.certificateIdentifiers(PEM);
    eq(ids.issuer, 'CN=Test CA,O=Acme\\, Inc,C=US',
       'A. the issuer is RFC 4514, most specific first, escaped once');
    eq(ids.subject, 'CN=Test CA,O=Acme\\, Inc,C=US',
       'A. and the subject the same way');
    eq(ids.serial, '0a1b2c3d', 'A. the serial is lower-case hex');
    eq(stsCrypto.certificateIdentifiers('not a certificate'),
       { issuer: '', serial: '', subject: '' },
       'A. something that is not a certificate names nothing');

    // --- B -------------------------------------------------------------
    eq(stsCrypto.userAgentFingerprint('Agent/1.0'),
       nodeCrypto.createHash('sha256').update('Agent/1.0', 'utf8')
         .digest('base64url'),
       'B. fp_ua is the base64url SHA-256 of the User-Agent');
    eq(stsCrypto.userAgentFingerprint(''), '', 'B. and nothing for none');

    // --- C -------------------------------------------------------------
    eq(credentials.Credentials.aaguidString(
         'ADCE000235BCC60A648B0B25F1F05503'),
       'adce0002-35bc-c60a-648b-0b25f1f05503',
       'C. an AAGUID is a UUID string');
    eq(credentials.Credentials.aaguidString('0'.repeat(32)), '',
       'C. all zeros is no AAGUID');
    eq(accountSignals.keyCredentialType({ attachment: 'platform' }),
       'fido2-platform', 'C. a platform authenticator is fido2-platform');
    eq(accountSignals.keyCredentialType({ attachment: 'cross-platform' }),
       'fido2-roaming', 'C. a cross-platform one is fido2-roaming');
    eq(accountSignals.keyCredentialType({}), 'fido2-roaming',
       'C. and a key with no recorded attachment reads as it always did');

    // --- D -------------------------------------------------------------
    const sent = [];
    const signals = new accountSignals.AccountSignals({ log: helpers.log,
      findSsf: function () {
        return { emitCredentialChange: function (notice) {
          sent.push(notice);
          return { sent: 1, streams: 1 };
        } };
      } });
    signals.certificateChanged({ username: 'alice', pem: PEM,
                                 changeType: 'revoke' });
    const d = sent[0] || {};
    note(d.credentialType === 'x509' && d.changeType === 'revoke' &&
         d.x509Issuer === ids.issuer && d.x509Serial === '0a1b2c3d' &&
         !('pem' in d),
         'D. certificateChanged() sends x509 with issuer and serial, and ' +
         'not the certificate', JSON.stringify(d));

    // --- E -------------------------------------------------------------
    const register = new caep.CaepRegister(Object.assign({},
      caep.CaepRegister.defaultDeps(), {
        groupClaims: { groupsOf: function () {
          return { enabled: true, claim: 'groups', values: ['a', 'b'] };
        } } }));
    eq(register.claimsChangeFor({ kind: 'updated', username: 'alice',
         before: { sn: ['Before'], mail: ['x@y'] },
         after: { sn: ['After'], mail: ['x@y'] } }),
       { claims: { family_name: 'After' } },
       'E. only the claim that moved, with its new value');
    eq(register.claimsChangeFor({ kind: 'updated', username: 'alice',
         before: { mail: ['x@y'] }, after: {} }),
       { claims: { email: null } }, 'E. an emptied claim is null');
    const nested = register.claimsChangeFor({ kind: 'updated',
      username: 'alice', before: { l: ['Old'] }, after: { l: ['New'] } });
    note(!!nested && nested.claims.address &&
         nested.claims.address.locality === 'New',
         'E. a nested claim is nested', JSON.stringify(nested));
    eq(register.claimsChangeFor({ kind: 'membership', username: 'alice' }),
       { claims: { groups: ['a', 'b'] } },
       'E. a membership change is the whole groups list');
    eq(register.claimsChangeFor({ kind: 'updated', username: 'alice',
         before: { memberof: [] }, after: { memberof: ['cn=a'] } }),
       { claims: { groups: ['a', 'b'] } }, 'E. and so is memberOf');
    eq(register.claimsChangeFor({ kind: 'updated', username: 'alice',
         before: { modifytimestamp: ['20260922000000Z'] },
         after: { modifytimestamp: ['20260922000001Z'] } }),
       null, 'E. a write that moved no claim — only its own timestamp, which ' +
       'every write moves — is nothing');

    // --- F -------------------------------------------------------------
    const now = helpers.nowSec();
    helpers.signJwt({ iss: 'https://sts.example', sub: 'urn:uuid:f-live',
      aud: 'c', typ: 'Bearer', jti: 'ccu-live', username: 'f-live',
      iat: now, exp: now + 300 }, {});
    note(stats.holdsLiveIssuance('f-live', ''),
         'F. a valid access token naming the person counts');
    note(!stats.holdsLiveIssuance('f-nobody', 'urn:uuid:f-nobody'),
         'F. somebody else\'s does not');
    stats.revoke('ccu-live', 'caep_credential_units');
    note(!stats.holdsLiveIssuance('f-live', ''),
         'F. and a revoked one does not');
  } catch (e) {
    note(false, 'the test itself threw', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'caep-credential-units-' + process.pid +
                        '-' + require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|CONFIG_FILE$)/.test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', CCU_ROOT: ROOT,
                                  CCU_OUT: out, CCU_PEM: FIXTURE_PEM }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings),
               'the child process reported its findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-1200))) {
    log.debug("Leaving run().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving run().");
}

module.exports = {
  name: 'caep_credential_units',
  describe: 'CAEP from every door (#145): certificate identifiers, the ' +
            'user-agent fingerprint, AAGUIDs and key types, the x509 ' +
            'change, which claims a directory write moved, and live ' +
            'issuance',
  run: run
};

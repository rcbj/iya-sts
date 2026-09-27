'use strict';
//
// File: caep_claims_doors.js
//
// ===========================================================================
// CAEP token-claims-change AND assurance-level-change FROM THE DOORS THAT ARE
// NOT A DIRECTORY ATTRIBUTE (#238, #243), in process:
//
//   A. `IdentityAssurance.assuranceOf()`: `none` with nothing recorded,
//      `verified` for a verification stating no level, a stated level in
//      `urn:sts:ial` as recorded, and `NIST-IAL` only for `nist_800_63A`
//      with IAL1–3; the newest stated level decides.
//   B. A ROLE's members moving tells the directory's account observer, kind
//      `roles`, once per person it moved — a named user and a member of a
//      named group — and a description edited moves nobody; a delete moves
//      everybody who held it.
//   C. A group a role names changing its members says `rolesMoved`.
//   D. `claimsChangeFor()`: the roles claim as `roles.claimFor()` builds it,
//      `null` for nobody's, `email_verified` from the address proved, and a
//      notice that already names its claims (a function answered lazily).
//   E. `writeMailFlag('stsMailVerified')` tells the observer, so
//      `email_verified` moving on its own is seen.
//   F. `identity_assurance.ts`: recording and removing send `verified_claims`
//      (framework, level and the claims still current; never `evidence`) and
//      the IAL change with previous level and direction where they apply; a
//      sign-in rewriting its own automatic record with the same claims sends
//      neither.
//   G. `claims_providers.ts`: an unlink sends `_claim_names` and
//      `_claim_sources` gone, and never a source's value.
//   H. The fan-out doors: live holders listed with their newest artifact,
//      a claim set changed, a protected scope withdrawn from a client, a
//      roles claim renamed — each hands `claimsFanOut()` a match and the
//      values the holder's artifact would carry now.
//
// `sts_caep_claims_doors.js` holds the delivery over the wire. In a child
// process, because it loads the protocol stack.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const log = require('bunyan').createLogger({ name: 'caep_claims_doors',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.resolve(__dirname, '..');

function childMain() {
  const ROOT = process.env.CCD_ROOT;
  const OUT = process.env.CCD_OUT;
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
    const ldap = require(ROOT + '/ldap/ldap_server');
    const roles = require(ROOT + '/common/roles');
    const caep = require(ROOT + '/ssf/caep');
    const ssf = require(ROOT + '/ssf/ssf');
    const config = require(ROOT + '/common/config');
    const helpers = require(ROOT + '/common/helpers');
    const stats = require(ROOT + '/common/admin_stats');
    const applications = require(ROOT + '/common/applications');
    const ida = require(ROOT + '/common/identity_assurance');
    const claimsProviders = require(ROOT + '/oauth-oidc/claims_providers');
    const mail = require(ROOT + '/common/mail');

    // What the account observer is told, and what SSF is handed through
    // `ssf/account_signals.ts` — its emitters replaced on the loaded module,
    // which is where that library looks them up at the moment of a call.
    const told = [];
    ldap.addAccountObserver(function (event) {
      told.push(event);
    });
    const handed = [];
    ['emitClaimsChange', 'claimsFanOut', 'emitIdentityAssuranceChange']
      .forEach(function (name) {
        ssf[name] = function (notice) {
          handed.push({ via: name, notice: notice });
          return { sent: 0, streams: 0 };
        };
      });
    const kinds = function (kind) {
      return told.filter(function (one) {
        return one.kind === kind;
      }).map(function (one) {
        return one.username;
      }).sort();
    };
    const via = function (name) {
      return handed.filter(function (one) {
        return one.via === name;
      }).map(function (one) {
        return one.notice;
      });
    };
    const clear = function () {
      told.length = 0;
      handed.length = 0;
    };

    // --- A -------------------------------------------------------------
    const of = ida.assuranceOf;
    eq(of([]), { namespace: 'urn:sts:ial', level: 'none', rank: 0 },
       'A. nothing recorded is none');
    eq(of([{ verification: { trust_framework: 'urn:x' } }]),
       { namespace: 'urn:sts:ial', level: 'verified', rank: 1 },
       'A. a verification stating no level is verified');
    eq(of([{ verification: { trust_framework: 'eidas',
                             assurance_level: 'substantial' } }]),
       { namespace: 'urn:sts:ial', level: 'substantial', rank: 2 },
       'A. a stated level is carried as recorded in urn:sts:ial');
    eq(of([{ verification: { trust_framework: 'nist_800_63A',
                             assurance_level: 'ial2' } }]),
       { namespace: 'NIST-IAL', level: 'IAL2', rank: 2 },
       'A. nist_800_63A with an 800-63 level is NIST-IAL');
    eq(of([{ verification: { trust_framework: 'eidas',
                             assurance_level: 'IAL2' } }]).namespace,
       'urn:sts:ial', 'A. and an IAL-looking level under another framework ' +
       'is not');
    eq(of([{ verification: { trust_framework: 'urn:x' } },
           { verification: { trust_framework: 'nist_800_63A',
                             assurance_level: 'IAL3' } },
           { verification: { trust_framework: 'nist_800_63A',
                             assurance_level: 'IAL1' } }]).level,
       'IAL3', 'A. the newest STATED level decides');

    // --- B -------------------------------------------------------------
    const ALICE = 'ccd-alice';
    const BOB = 'ccd-bob';
    const CAROL = 'ccd-carol';
    [ALICE, BOB, CAROL].forEach(function (name) {
      ldap.createUser(name, { invent: false, attributes: {
        givenName: 'Given ' + name, sn: 'Family', mail: name + '@ccd.test' } });
    });
    ldap.createGroup('ccd-group');
    ldap.addGroupMember('ccd-group', BOB);
    clear();
    note(roles.write('ccd-role', { users: [ALICE], groups: ['ccd-group'] })
      .ok, 'B. a role is written');
    eq(kinds('roles'), [ALICE, BOB],
       'B. a role created tells its named user and its group\'s member');
    clear();
    roles.write('ccd-role', { users: [ALICE], groups: [],
                              description: 'narrowed' });
    eq(kinds('roles'), [BOB], 'B. a group taken off tells only its members');
    clear();
    roles.write('ccd-role', { users: [ALICE], groups: [],
                              description: 'reworded' });
    eq(kinds('roles'), [], 'B. a description edited tells nobody');
    note(told.every(function (one) {
      return one.kind !== 'updated';
    }), 'B. and a role write is never a person\'s own write, which RISC ' +
         'would read');
    clear();
    roles.remove('ccd-role');
    eq(kinds('roles'), [ALICE], 'B. a role deleted tells everybody who ' +
       'held it');

    // --- C -------------------------------------------------------------
    roles.write('ccd-role2', { groups: ['ccd-group'] });
    clear();
    ldap.addGroupMember('ccd-group', CAROL);
    const joined = told.filter(function (one) {
      return one.kind === 'membership' && one.username === CAROL;
    })[0];
    note(joined && joined.rolesMoved === true,
         'C. a group a role names says rolesMoved', JSON.stringify(joined));
    ldap.createGroup('ccd-plain');
    clear();
    ldap.addGroupMember('ccd-plain', CAROL);
    const plain = told.filter(function (one) {
      return one.kind === 'membership' && one.username === CAROL;
    })[0];
    note(plain && plain.rolesMoved === false,
         'C. and a group no role names does not', JSON.stringify(plain));

    // --- D -------------------------------------------------------------
    const rolesName = String(config.value('roles.claimName') || 'roles');
    const byRoles = caep.claimsChangeFor({ kind: 'roles', username: CAROL });
    note(byRoles && JSON.stringify(byRoles.claims[rolesName]) ===
         JSON.stringify(['ccd-role2']),
         'D. a roles notice carries the roles claim as it is now',
         JSON.stringify(byRoles));
    const none = caep.claimsChangeFor({ kind: 'roles', username: ALICE });
    note(none && none.claims[rolesName] === null,
         'D. and null for somebody who holds no configured role now',
         JSON.stringify(none));
    const moved = caep.claimsChangeFor({ kind: 'membership',
      username: CAROL, rolesMoved: true });
    note(moved && Array.isArray(moved.claims[rolesName]) &&
         Object.keys(moved.claims).length === 2,
         'D. a membership that moved a role names groups and roles',
         JSON.stringify(moved));
    eq(caep.claimsChangeFor({ kind: 'updated', username: ALICE,
         before: { mail: ['a@x'] },
         after: { mail: ['a@x'], stsmailverified: ['A@x'] } }),
       { claims: { email_verified: true } },
       'D. the address proved moves email_verified alone');
    eq(caep.claimsChangeFor({ kind: 'claims', username: ALICE,
         claims: function () {
           return { verified_claims: null };
         } }),
       { claims: { verified_claims: null } },
       'D. a notice that names its claims is taken as it is, lazily');
    eq(caep.claimsChangeFor({ kind: 'claims', username: ALICE,
                              claims: {} }),
       null, 'D. and one naming nothing is nothing');

    // --- E -------------------------------------------------------------
    clear();
    mail.directory().writeMailFlag(ALICE, 'stsMailVerified', ALICE +
                                   '@ccd.test');
    const proved = told.filter(function (one) {
      return one.kind === 'updated' && one.username === ALICE;
    })[0];
    note(proved && (proved.after.stsmailverified || [])[0] ===
         ALICE + '@ccd.test',
         'E. writeMailFlag(stsMailVerified) tells the observer',
         JSON.stringify(proved && proved.after));

    // --- F -------------------------------------------------------------
    config.setOverride('oauth2.idaTrustFrameworks',
                       'urn:sts:local,nist_800_63A');
    config.setOverride('oauth2.idaAutomaticVerifications', true);
    clear();
    const first = ida.record(ALICE, { verification: {
      trust_framework: 'urn:sts:local' }, claims: ['given_name'] }, 'test');
    note(first.ok, 'F. a verification is recorded', JSON.stringify(first));
    const claimNotice = via('emitClaimsChange')[0];
    const value = claimNotice && typeof claimNotice.claims === 'function'
      ? claimNotice.claims() : null;
    eq(value, { verified_claims: [{
         verification: { trust_framework: 'urn:sts:local' },
         claims: { given_name: 'Given ' + ALICE } }] },
       'F. verified_claims: framework and claims, lazily, no evidence');
    const ial1 = via('emitIdentityAssuranceChange')[0] || {};
    eq([ial1.namespace, ial1.current, ial1.previous, ial1.direction],
       ['urn:sts:ial', 'verified', 'none', 'increase'],
       'F. the first verification moves the level from none to verified');
    clear();
    const nist2 = ida.record(ALICE, { verification: {
      trust_framework: 'nist_800_63A', assurance_level: 'IAL2' },
      claims: ['family_name'] }, 'test');
    const ial2 = via('emitIdentityAssuranceChange')[0] || {};
    eq([ial2.namespace, ial2.current, ial2.previous, ial2.direction],
       ['NIST-IAL', 'IAL2', '', ''],
       'F. into NIST-IAL: no previous level from another namespace, no ' +
       'direction');
    clear();
    const nist3 = ida.record(ALICE, { verification: {
      trust_framework: 'nist_800_63A', assurance_level: 'IAL3' },
      claims: ['family_name'] }, 'test');
    const ial3 = via('emitIdentityAssuranceChange')[0] || {};
    eq([ial3.current, ial3.previous, ial3.direction],
       ['IAL3', 'IAL2', 'increase'], 'F. IAL2 to IAL3 is an increase');
    clear();
    ida.remove(ALICE, nist3.record && nist3.record.id);
    const back = via('emitIdentityAssuranceChange')[0] || {};
    eq([back.current, back.previous, back.direction],
       ['IAL2', 'IAL3', 'decrease'], 'F. and removing it a decrease');
    note(via('emitClaimsChange').length === 1,
         'F. a removal moves verified_claims too');
    note(!!nist2.ok, 'F. (the IAL2 verification was recorded)');
    clear();
    const auto1 = ida.recordAutomatic(ALICE, 'wallet',
      { claims: { given_name: 'Given ' + ALICE }, format: 'dc+sd-jwt' });
    note(auto1.ok && via('emitClaimsChange').length === 1 &&
         via('emitIdentityAssuranceChange').length === 0,
         'F. an automatic record moves verified_claims and not a stated ' +
         'level', JSON.stringify(handed.map(function (one) {
           return one.via;
         })));
    clear();
    ida.recordAutomatic(ALICE, 'wallet',
      { claims: { given_name: 'Given ' + ALICE }, format: 'dc+sd-jwt' });
    eq(handed.length, 0, 'F. the same sign-in again rewrites its record ' +
       'and says nothing');
    config.clearOverride('oauth2.idaAutomaticVerifications');

    // --- G -------------------------------------------------------------
    const links = { 'ccd-prov': { access_token: 'SECRET-AT', sub: 's',
                                  linked_at: 1 } };
    const provider = { id: 'ccd-prov', claims: ['credit_score'] };
    const cp = new claimsProviders.ClaimsProviders(Object.assign({},
      claimsProviders.ClaimsProviders.defaultDeps(), {
        store: function (operation) {
          if (operation === 'readClaimSourceTokens') {
            return JSON.stringify(links);
          }
          if (operation === 'listClaimProviderEntries') {
            return [{ attributes: { stsclaimproviderdata:
                                      [JSON.stringify(provider)] } }];
          }
          return true;
        } }));
    clear();
    note(cp.unlink(ALICE, 'ccd-prov', 'user'), 'G. the link is removed');
    const gone = via('emitClaimsChange')[0] || {};
    eq(gone.claims, { _claim_sources: { 'ccd-prov': null },
                      _claim_names: { credit_score: null } },
       'G. an unlink sends the source and its claim names gone');
    note(gone.initiatingEntity === 'user' &&
         JSON.stringify(gone).indexOf('SECRET-AT') < 0,
         'G. initiated by the person, and never the source\'s token');

    // --- H -------------------------------------------------------------
    const now = helpers.nowSec();
    helpers.signJwt({ iss: 'https://sts.example', sub: 'urn:uuid:ccd',
      aud: 'https://ccd-api.test/', typ: 'Bearer', jti: 'ccd-at-1',
      username: ALICE, client_id: 'ccd-client', scope: 'openid ssf:read',
      iat: now, exp: now + 300 }, {});
    const bearers = stats.liveClaimBearers(function (token) {
      return token.client_id === 'ccd-client';
    });
    note(bearers.length === 1 && bearers[0].username === ALICE &&
         bearers[0].claimSet === 'access_token',
         'H. the live holder is listed with the set of their artifact',
         JSON.stringify(bearers.map(function (one) {
           return [one.username, one.claimSet];
         })));
    clear();
    stats.setClaimSet('access_token', [{ name: 'ccd_dept',
                                         value: '${username}-dept' }]);
    const reshaped = via('claimsFanOut')[0];
    note(reshaped && reshaped.match(Object.assign({}, bearers[0].record,
                                                  { claimSet: 'access_token' })),
         'H. a claim set changed fans out to its holders');
    eq(reshaped && reshaped.claimsFor(bearers[0]),
       { ccd_dept: ALICE + '-dept' },
       'H. with the value their token would carry now');
    clear();
    stats.setClaimSet('access_token', []);
    eq(via('claimsFanOut')[0] && via('claimsFanOut')[0].claimsFor(bearers[0]),
       { ccd_dept: null }, 'H. and null once it is gone');
    applications.createApplication({ identifier: 'ccd-client',
      protocols: ['oauth2'], fields: { oauthClientId: 'ccd-client',
        oauthAllowedScope: ['openid', 'ssf:read'] } });
    clear();
    applications.updateApplication('ccd-client', {
      attribute: 'oauthAllowedScope', mode: 'remove', value: 'ssf:read' });
    const withdrawn = via('claimsFanOut')[0];
    note(withdrawn && withdrawn.match(Object.assign({},
      bearers[0].record, { claimSet: 'access_token' })),
         'H. a protected scope withdrawn from the client fans out to its ' +
         'token holders');
    eq(withdrawn && withdrawn.claimsFor(bearers[0]), { scope: 'openid' },
       'H. with the scope less what went');
    clear();
    applications.updateApplication('ccd-client', {
      attribute: 'oauthAllowedScope', mode: 'add', value: 'ssf:read' });
    eq(via('claimsFanOut').length, 0,
       'H. a scope added moves no token already issued');
    clear();
    config.setOverride('roles.claimName', 'ccd_roles');
    const renamed = via('claimsFanOut')[0];
    note(renamed && JSON.stringify(Object.keys(renamed.claimsFor(bearers[0])))
         === JSON.stringify(['roles', 'ccd_roles']),
         'H. a roles claim renamed names it as it was and as it is',
         renamed && JSON.stringify(renamed.claimsFor(bearers[0])));
    config.clearOverride('roles.claimName');
  } catch (e) {
    note(false, 'the test itself threw', e && e.stack);
  }
  require('fs').writeFileSync(OUT, JSON.stringify(findings));
  process.exit(0);
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'caep-claims-doors-' + process.pid +
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
      env: Object.assign(clean, { LOG_LEVEL: 'fatal', CCD_ROOT: ROOT,
                                  CCD_OUT: out }),
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
  name: 'caep_claims_doors',
  describe: 'CAEP from the doors that are not a directory attribute (#238, ' +
            '#243): roles, email_verified, verified_claims and the identity ' +
            'assurance level, claims providers, and the fan-out of a ' +
            'configuration change',
  run: run
};

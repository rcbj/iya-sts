// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: gnap_delegation.js
//
// ===========================================================================
// WHO MAY ACT FOR WHOM IN GNAP (#432 PHASE 1), IN PROCESS.
//
// GNAP's two ways of obtaining a token about somebody else ask #186's
// delegation policy (`gnap/gnap_delegation.ts`), and this file drives both
// through the real grant endpoint, in BOTH modes:
//
//   I. IMPERSONATION BY ASSERTION — a `gnapSkipInteraction` client with a
//      verified ID Token: refused in product and recorded "would have been
//      refused" in development when impersonation is not in the client's
//      allowed semantics (STS-GNAP-0772); allowed when it is and the client
//      reaches R; refused with no relationship to R (0770); a protected
//      subject (0771); a may_act naming somebody else, in EVERY mode (0774);
//      appDelegationSubjectGroup, and a may_act naming the client standing
//      in for it; the client acting as ITSELF asking nothing and releasing no
//      subject; `appAllowedProtocol` without GNAP refused at issuance in
//      product;
//  II. DERIVATION (RFC 9767 section 4) — refused in product with no
//      relationship (0776) and recorded in development; allowed by
//      appAllowedToDelegateTo, with the `act` chain on the token; a wider
//      derivation refused in every mode (0513); the depth cap (0782); the
//      chain nested on a second hop and kept by introspection;
// III. THE CHAIN IN EVERY FORMAT — each of the five formats minted for a
//      derivation and verified back by `gnap_tokens.verify()`, its model's
//      `act` naming the deriving resource server;
//  IV. THE REGISTER — every act a GNAP row on the delegation register, and
//      the map drawing them.
//
// The token formats' own round trip of `act` is `tests/gnap_token_formats.js`;
// the wire, verified by code that is not the service's, is
// `tests/vendored/sts_gnap_rs.js`, and impersonation over HTTP is
// `tests/vendored/sts_gnap_delegation.js`.
//
// IN A CHILD PROCESS, `cluster_single_use_protocols.js`'s arrangement: it
// loads the whole stack and serves the shared app on a port of its own, and
// `run.js` runs every file in one process.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const log = require('bunyan').createLogger({ name: 'gnap_delegation',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// The child's program. It runs under `node -e`, so the code style's
// Entering/Leaving lines do not apply to it (root CLAUDE.md, Code style).
function childMain() {
  const ROOT = process.env.GD_ROOT;
  const OUT = process.env.GD_OUT;
  const http = require('http');
  const nodeCrypto = require('crypto');
  const findings = [];
  function note(ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  }

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const helpers = require(ROOT + '/common/helpers');
    const errorCodes = require(ROOT + '/common/error_codes');
    const applications = require(ROOT + '/common/applications');
    const credentials = require(ROOT + '/common/credentials');
    const delegation = require(ROOT + '/common/delegation');
    const dir = require(ROOT + '/ldap/ldap_server');
    const oauth2 = require(ROOT + '/oauth-oidc/oauth2');
    const tokens = require(ROOT + '/gnap/gnap_tokens');
    const gnapDelegation = require(ROOT + '/gnap/gnap_delegation');
    const gnap = require(ROOT + '/tests/vendored/gnap_client.js');

    // The code each response was marked with, by request path — read off
    // the response object, which is where `errorCodes.mark()` puts it and
    // never the wire.
    const codes = [];
    const server = http.createServer(function (req, res) {
      res.on('finish', function () {
        codes.push(errorCodes.codeOf(res) || '');
      });
      app(req, res);
    });
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;
    const base = 'http://127.0.0.1:' + port;
    const GRANT = base + '/gnap';
    const lastCode = function () { return codes[codes.length - 1] || ''; };
    const product = function (on) {
      if (on) {
        config.setOverride('global.mode', 'product');
      } else {
        config.clearOverride('global.mode');
      }
    };
    config.setOverride('gnap.continueWaitS', 0);

    // ---------------------------------------------------------------- setup
    ['gd-alice', 'gd-bob', 'gd-carol'].forEach(function (name) {
      dir.createUser(name, { invent: false });
    });
    const staff = dir.createGroup('gd-staff', { origin: 'test' });
    dir.addGroupMember('gd-staff', 'gd-carol', { origin: 'test' });
    credentials.setNotDelegated('gd-bob', true);
    const RS = { a: 'https://rs-a.gd.test/api', b: 'https://rs-b.gd.test/api',
                 c: 'https://rs-c.gd.test/api' };
    const keys = {};
    const made = [];
    const client = function (id, fields, protocols) {
      keys[id] = new gnap.Client({ key: gnap.newKey('ES256') });
      made.push(applications.createApplication({ identifier: id,
        kind: 'gnap-client', protocols: protocols || ['gnap'],
        fields: Object.assign({
          gnapKey: JSON.stringify(keys[id].keyObject()),
          gnapSkipInteraction: 'TRUE' }, fields || {}) }));
    };
    const rs = function (id, uri, fields) {
      keys[id] = new gnap.Client({ key: gnap.newKey('ES256') });
      made.push(applications.createApplication({ identifier: id,
        kind: 'gnap-resource-server', protocols: ['gnap'],
        fields: Object.assign({
          gnapKey: JSON.stringify(keys[id].keyObject()),
          gnapResourceServerUri: uri }, fields || {}) }));
    };
    rs('gd-rs-a', RS.a, { appAllowedToDelegateTo: ['gd-rs-b'] });
    rs('gd-rs-b', RS.b);
    rs('gd-rs-c', RS.c);
    // No impersonation in its semantics: delegation only, the default.
    client('gd-plain');
    // Impersonation allowed, reaching the three resource servers.
    client('gd-imp', { appDelegationSemantics: ['impersonation'],
                       appAllowedToDelegateTo: ['gd-rs-a', 'gd-rs-b',
                                                'gd-rs-c'] });
    // Impersonation allowed, reaching nothing but itself.
    client('gd-imp-self', { appDelegationSemantics: ['impersonation'] });
    // Impersonation allowed for the staff group only.
    client('gd-imp-staff', { appDelegationSemantics: ['impersonation'],
                             appAllowedToDelegateTo: ['gd-rs-a'],
                             appDelegationSubjectGroup: [staff.dn] });
    // Declared for OAuth only, not GNAP.
    client('gd-imp-oauth', { appDelegationSemantics: ['impersonation'],
                             appAllowedToDelegateTo: ['gd-rs-a'] },
           ['oauth2']);
    note(made.every(function (one) { return one && one.ok; }),
         '0. the fixtures were created',
         JSON.stringify(made.filter(function (one) { return !one.ok; })));

    const issuer = oauth2.issuerOf(base);
    const idToken = function (who, extra) {
      const now = helpers.nowSec();
      return helpers.signJwtAs(Object.assign({
        iss: issuer, sub: helpers.userFor(who).sub, aud: 'gd-rp',
        preferred_username: who, iat: now, exp: now + 300 }, extra || {}),
                               'RS256', null, {});
    };
    const right = function (uris, actions) {
      return { type: 'gd-photos', actions: actions || ['read'],
               locations: uris };
    };
    const impersonate = function (id, who, access, extra) {
      return keys[id].send('POST', GRANT, { json: {
        client: { key: keys[id].keyObject() },
        access_token: { access: access },
        user: { assertions: [{ format: 'id_token',
                               value: idToken(who, extra) }] } } });
    };
    const newestAct = function () {
      return delegation.list()[0] || {};
    };
    const claimsOf = function (value) {
      return JSON.parse(Buffer.from(String(value).split('.')[1],
                                    'base64url').toString('utf8'));
    };

    // ===================================================== I. IMPERSONATION
    let r = await impersonate('gd-plain', 'gd-alice', [right([RS.a])]);
    let act = newestAct();
    note(r.status === 200 && r.json && r.json.access_token,
         'I1. development: a client whose semantics do not include ' +
         'impersonation is still issued the token', r.status + ' ' + r.text);
    note(act.type === 'gnap-impersonation' && act.protocol === 'GNAP' &&
         act.outcome === 'issued' &&
         /WOULD HAVE BEEN REFUSED/.test(act.authorizedBy) &&
         act.intermediary.application === 'gd-plain' &&
         act.target.application === 'gd-rs-a' &&
         act.produced.length === 1,
         'I2. …and the act is a GNAP impersonation row saying it WOULD HAVE ' +
         'BEEN REFUSED, actor the client, R the resource server',
         JSON.stringify(act));
    if (r.json && r.json.access_token) {
      const claims = claimsOf(r.json.access_token.value);
      note(claims.sub === helpers.userFor('gd-alice').sub && !claims.act,
           'I3. the token is the person\'s, and names no actor ' +
           '(impersonation)', JSON.stringify(claims));
    }
    product(true);
    r = await impersonate('gd-plain', 'gd-alice', [right([RS.a])]);
    act = newestAct();
    note(r.status === 403 && r.json && r.json.error &&
         r.json.error.code === 'request_denied' &&
         lastCode() === 'STS-GNAP-0772',
         'I4. product: refused request_denied, STS-GNAP-0772 (the semantics)',
         r.status + ' ' + lastCode() + ' ' + r.text);
    note(act.type === 'gnap-impersonation' && act.outcome === 'refused' &&
         /refused by the delegation policy/.test(act.authorizedBy),
         'I5. …and recorded as a REFUSED act', JSON.stringify(act));
    r = await impersonate('gd-imp', 'gd-alice', [right([RS.a])]);
    act = newestAct();
    note(r.status === 200 && r.json && r.json.access_token &&
         act.outcome === 'issued' &&
         /allowed impersonation/.test(act.authorizedBy),
         'I6. product: impersonation in the client\'s semantics and R on its ' +
         'appAllowedToDelegateTo — issued, and the row says what allowed it',
         r.status + ' ' + r.text + ' ' + JSON.stringify(act));
    r = await impersonate('gd-imp-self', 'gd-alice', [right([RS.a])]);
    note(r.status === 403 && lastCode() === 'STS-GNAP-0770',
         'I7. product: impersonation allowed but R not reachable by the ' +
         'client — STS-GNAP-0770', r.status + ' ' + lastCode());
    r = await impersonate('gd-imp-self', 'gd-alice', ['gd-unregistered']);
    act = newestAct();
    note(r.status === 200 && r.json && r.json.access_token &&
         act.target.application === 'gd-imp-self',
         'I8. product: rights naming no resource server — R is the client ' +
         'itself (S4U2Self\'s ticket to yourself), allowed with impersonation',
         r.status + ' ' + r.text + ' ' + JSON.stringify(act.target));
    r = await impersonate('gd-imp', 'gd-bob', [right([RS.a])]);
    note(r.status === 403 && lastCode() === 'STS-GNAP-0771',
         'I9. product: a subject carrying stsNotDelegated — STS-GNAP-0771',
         r.status + ' ' + lastCode());
    r = await impersonate('gd-imp-staff', 'gd-alice', [right([RS.a])]);
    note(r.status === 403 && lastCode() === 'STS-GNAP-0771',
         'I10. product: a subject outside appDelegationSubjectGroup — 0771',
         r.status + ' ' + lastCode());
    r = await impersonate('gd-imp-staff', 'gd-carol', [right([RS.a])]);
    note(r.status === 200,
         'I11. …and a member of the group is allowed', r.status + ' ' + r.text);
    r = await impersonate('gd-imp-staff', 'gd-alice', [right([RS.a])],
                          { may_act: { sub: 'gd-imp-staff' } });
    note(r.status === 200,
         'I12. a may_act naming the client stands in for the subject group ' +
         '(#186)', r.status + ' ' + r.text);
    product(false);
    r = await impersonate('gd-imp', 'gd-alice', [right([RS.a])],
                          { may_act: { sub: 'somebody-else' } });
    note(r.status === 403 && lastCode() === 'STS-GNAP-0774',
         'I13. a may_act naming somebody else is refused IN DEVELOPMENT TOO ' +
         '— STS-GNAP-0774', r.status + ' ' + lastCode());
    product(true);
    r = await keys['gd-plain'].send('POST', GRANT, { json: {
      client: { key: keys['gd-plain'].keyObject() },
      access_token: { access: ['gd-read'] } } });
    note(r.status === 200 && r.json && r.json.access_token &&
         !r.json.subject && !claimsOf(r.json.access_token.value).sub,
         'I14. the client acting as itself asks nothing (product, delegation ' +
         'only) and releases no subject', r.status + ' ' + r.text);
    r = await impersonate('gd-imp-oauth', 'gd-alice', [right([RS.a])]);
    note(r.status === 200 && r.json && !r.json.access_token,
         'I15. product: a client declared for OAuth only is refused the ' +
         'token by the issuance gate (appAllowedProtocol)',
         r.status + ' ' + r.text);

    // ======================================================== II. DERIVATION
    r = await impersonate('gd-imp', 'gd-alice', [right([RS.a, RS.b, RS.c])]);
    const original = r.json && r.json.access_token
      ? r.json.access_token.value : '';
    note(!!original, 'II0. product: a token about gd-alice for A, B and C',
         r.status + ' ' + r.text);
    const derive = function (id, existing, access) {
      return keys[id].send('POST', GRANT, { json: {
        client: { key: keys[id].keyObject() },
        existing_access_token: existing,
        access_token: { access: access } } });
    };
    r = await derive('gd-rs-c', original, [right([RS.b])]);
    act = newestAct();
    note(r.status === 403 && lastCode() === 'STS-GNAP-0776' &&
         act.type === 'gnap-derivation' && act.outcome === 'refused' &&
         act.intermediary.application === 'gd-rs-c' &&
         act.target.application === 'gd-rs-b',
         'II1. product: C derives for B with no relationship — 0776, a ' +
         'REFUSED derivation row', r.status + ' ' + lastCode() + ' ' +
         JSON.stringify(act));
    product(false);
    r = await derive('gd-rs-c', original, [right([RS.b])]);
    act = newestAct();
    note(r.status === 200 && act.outcome === 'issued' &&
         /WOULD HAVE BEEN REFUSED/.test(act.authorizedBy),
         'II2. development: issued, and the row says it would have been ' +
         'refused', r.status + ' ' + JSON.stringify(act));
    product(true);
    r = await derive('gd-rs-a', original, [right([RS.b])]);
    act = newestAct();
    const derived = r.json && r.json.access_token
      ? r.json.access_token.value : '';
    note(r.status === 200 && !!derived && act.outcome === 'issued' &&
         act.produced.length === 1,
         'II3. product: A derives for B — A\'s appAllowedToDelegateTo names B',
         r.status + ' ' + r.text);
    if (derived) {
      const claims = claimsOf(derived);
      note(claims.act && claims.act.sub === 'gd-rs-a' && !claims.act.act &&
           claims.sub === helpers.userFor('gd-alice').sub &&
           claims.aud === 'gd-rs-b',
           'II4. the derived token is about gd-alice, for B, and its act ' +
           'names A (RFC 8693 section 4.1)', JSON.stringify(claims));
    }
    r = await derive('gd-rs-a', original, [right([RS.b], ['read', 'write'])]);
    note(r.status === 403 && lastCode() === 'STS-GNAP-0513',
         'II5. a derivation asking for more than the original carries — ' +
         'STS-GNAP-0513, whatever is registered downstream',
         r.status + ' ' + lastCode());
    product(false);
    r = await derive('gd-rs-a', original, [right([RS.b], ['read', 'write'])]);
    note(r.status === 403 && lastCode() === 'STS-GNAP-0513',
         'II6. …in development too: the subset rule is the format\'s',
         r.status + ' ' + lastCode());
    product(true);
    config.setOverride('gnap.maxDerivationDepth', 1);
    r = await derive('gd-rs-b', derived, [right([RS.b])]);
    note(r.status === 403 && lastCode() === 'STS-GNAP-0782',
         'II7. with gnap.maxDerivationDepth 1, deriving from a derived token ' +
         'is STS-GNAP-0782', r.status + ' ' + lastCode());
    config.clearOverride('gnap.maxDerivationDepth');
    r = await derive('gd-rs-b', derived, [right([RS.b])]);
    const second = r.json && r.json.access_token
      ? r.json.access_token.value : '';
    act = newestAct();
    note(r.status === 200 && !!second &&
         /nothing was needed/.test(act.authorizedBy),
         'II8. at the default depth, B narrowing for itself is a self act',
         r.status + ' ' + r.text + ' ' + JSON.stringify(act));
    if (second) {
      const claims = claimsOf(second);
      note(claims.act && claims.act.sub === 'gd-rs-b' && claims.act.act &&
           claims.act.act.sub === 'gd-rs-a' && !claims.act.act.act,
           'II9. the chain NESTS: B outermost, A under it',
           JSON.stringify(claims.act));
      r = await derive('gd-rs-b', second, [right([RS.b])]);
      note(r.status === 403 && lastCode() === 'STS-GNAP-0782',
           'II10. a third link is past the default depth of 2',
           r.status + ' ' + lastCode());
      r = await keys['gd-rs-b'].send('POST', base + '/gnap/introspect',
        { json: { access_token: second,
                  resource_server: { key: keys['gd-rs-b'].keyObject() } } });
      note(r.status === 200 && r.json && r.json.active &&
           JSON.stringify(r.json.act) ===
           JSON.stringify({ sub: 'gd-rs-b', act: { sub: 'gd-rs-a' } }),
           'II11. introspection returns the chain', r.text);
    }

    // ========================================= III. THE CHAIN IN EVERY FORMAT
    const pub = keys['gd-rs-a'].key.publicJwk;
    const jkt = nodeCrypto.createHash('sha256')
      .update(JSON.stringify({ crv: pub.crv, kty: pub.kty, x: pub.x,
                               y: pub.y }))
      .digest('base64url');
    for (const format of tokens.FORMATS) {
      config.setOverride('gnap.accessTokenFormat', format);
      r = await derive('gd-rs-a', original, [right([RS.b])]);
      const value = r.json && r.json.access_token
        ? r.json.access_token.value : '';
      let verified = null;
      if (value) {
        verified = await tokens.verify(format, value, {
          base: base, rsIdentity: 'gd-rs-b', presentedKey: { jkt: jkt } });
      }
      note(!!verified && verified.ok && verified.model &&
           JSON.stringify(verified.model.act) ===
           JSON.stringify({ sub: 'gd-rs-a' }),
           'III. ' + format + ': the derived token, verified back by its ' +
           'format, carries act naming the deriving resource server',
           r.status + ' ' + JSON.stringify(verified && (verified.model ?
             verified.model.act : verified)));
    }
    config.clearOverride('gnap.accessTokenFormat');

    // ========================================================= IV. REGISTER
    const rows = delegation.list().filter(function (one) {
      return one.protocol === 'GNAP';
    });
    const ofType = function (type) {
      return rows.some(function (one) { return one.type === type; });
    };
    note(ofType('gnap-impersonation') && ofType('gnap-derivation'),
         'IV1. the register holds GNAP impersonation and derivation rows',
         rows.length);
    const summary = delegation.summary();
    note(summary.byType['gnap-impersonation'] > 0 &&
         summary.byType['gnap-derivation'] > 0 && summary.byProtocol.GNAP > 0,
         'IV2. the summary counts them by type and by protocol',
         JSON.stringify(summary.byProtocol));
    const picture = delegation.graph(rows);
    note(picture.edges && picture.edges.length > 0 &&
         picture.nodes.some(function (one) {
           return /gd-rs-a/.test(JSON.stringify(one));
         }),
         'IV3. the map draws the GNAP acts', JSON.stringify(
           (picture.edges || []).slice(0, 2)));
    note(gnapDelegation.derivableBeyond([right([RS.a])], right([RS.b]), {})
         === false,
         'IV4. the catalogue\'s extension point allows nothing yet');

    product(false);
    server.close();
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  })().catch(function (e) {
    findings.push({ ok: false, what: 'the child ran to the end',
                    detail: e && e.stack });
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function inAChild(t) {
  log.debug("Entering inAChild().");
  const out = path.join(os.tmpdir(), 'gnap-delegation-' + process.pid + '-' +
                        require('crypto').randomBytes(8).toString('hex') +
                        '.json');
  const clean = {};
  Object.keys(process.env).forEach(function (key) {
    if (!/^(STS_|OID4VC|OID4VP|OAUTH2_|LDAP_|KRB5_|GNAP_|SAML|CONFIG_FILE$)/
        .test(key)) {
      clean[key] = process.env[key];
    }
  });
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      env: Object.assign(clean,
                         { LOG_LEVEL: 'fatal', GD_ROOT: ROOT, GD_OUT: out }),
      encoding: 'utf8', timeout: 300000, cwd: ROOT
    });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
    // No report: the child died before writing one. Reported below with its
    // exit status and stderr, which is where the reason is.
    findings = null;
  }
  try {
    fs.unlinkSync(out);
  } catch (e) {
    // Never written, which the read above has already reported.
    log.debug("Caught in inAChild(): " + ((e && e.message) || e));
  }
  if (!t.check(Array.isArray(findings), 'the child process reported its ' +
                                        'findings',
               'exit ' + result.status + ' ' +
               String(result.stderr || '').slice(-800))) {
    log.debug("Leaving inAChild().");
    return;
  }
  findings.forEach(function (one) {
    t.check(one.ok, one.what, one.detail);
  });
  log.debug("Leaving inAChild().");
}

async function run(t) {
  log.debug("Entering run().");
  t.log.info('=== GNAP impersonation by assertion and RFC 9767 derivation ' +
             'under the delegation policy (#432), in a child process ===');
  inAChild(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'gnap_delegation',
  describe: 'issue #432 phase 1: GNAP impersonation by user assertion and ' +
            'RFC 9767 derivation asked of the delegation policy in both ' +
            'modes, the subset rule, the act chain in every format, the ' +
            'depth cap and the register',
  run: run
};

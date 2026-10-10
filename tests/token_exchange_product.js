// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: tests/token_exchange_product.js
//
// ===========================================================================
// PRODUCT MODE EXCHANGES ONLY A TOKEN IT CAN VERIFY (2026-09-21).
//
// RFC 8693's token exchange took a `subject_token`, tried to verify it, and
// — when that failed — read the name out of it unverified and EXCHANGED IT
// ANYWAY, in every mode. That is development's intent (a client under test
// drives the grant with a token from any issuer), and product had no check of
// its own: any client that could authenticate could write
// `{"sub": <anybody>}` into a JWT signed with nothing and be handed a token
// this realm signed for that person. The `actor_token` was never verified at
// all, so the `act` claim in the token that came out could name anybody too.
// `common/mode.js`'s `exchangesUnverifiedTokens()` is the switch now, and
// `oauth-oidc/oauth2.ts`'s exchange branch asks it.
//
// Asserted, in a CHILD PROCESS (it flips `global.mode` for the process,
// `public_clients_product.js`'s reason):
//   1. PRODUCT: a subject_token this realm signed is exchanged — the control,
//      without which every refusal below could be a grant that never works;
//   2. PRODUCT: an UNSIGNED (`alg: none`) subject_token naming somebody else
//      is refused invalid_request with STS-OAUTH-0555, and no token issued;
//   3. PRODUCT: one SIGNED WITH ANOTHER KEY is refused the same way;
//   4. PRODUCT: a subject_token this realm REVOKED is refused (0557);
//   5. PRODUCT: a verified subject with a FORGED actor_token is refused
//      (0556), and with a verified one the `act` claim is the actor's sub;
//   6. DEVELOPMENT is unchanged: the forged token is still exchanged, and
//      says whose it claimed to be — the behaviour a client under test uses.
//
// AND WHO MAY ACT FOR WHOM, AND AS WHAT (#108, #186), at the endpoint — the
// issuance policy's answer spoken as RFC 8693 section 2.2.2 says:
//   7. PRODUCT: delegation by S, by R, and by an actor R accepts — `act`
//      naming the actor; no relationship (invalid_target, 0619);
//      impersonation asked of an actor allowing delegation only
//      (invalid_request, 0790) and of one allowing it (issued, no `act`);
//      an unusable exchange_semantics (0795, every mode); a protected
//      subject (0618); an unregistered, two, or no audience (0793, 0792,
//      0794); a self exchange; may_act naming somebody else (0620, every
//      mode); `act` NESTING, beginning with the ORIGINAL CLIENT where the
//      subject token carries no `act` and that client is not the actor
//      (#443); a wider scope (0621) and a narrower one; and stsMayAct
//      putting may_act on the token issued.
//   8. DEVELOPMENT: the same, each refusal ISSUED and the act's row saying
//      it WOULD have been refused — except 0795 and 0620, refused all the
//      same — and a wider scope issued.
//   In both: every `act` entry carries the token's `iss`, a prior entry
//   keeping its own (#471); a client named as an actor takes its subject's
//   form in the mode, `urn:sts:client:<id>` in product (#471).
//   9. RFC 9700 MODE in development (#471): a policy-chosen delegation
//      without an actor_token names the client `urn:sts:client:<id>`, on the
//      token and in the register, the original client beneath it in the
//      same form; may_act names the client in either spelling, in both
//      modes.
// ===========================================================================

delete process.env.CONFIG_FILE;

const path = require('path');
const os = require('os');
const fs = require('fs');
const childProcess = require('child_process');

const log = require('bunyan').createLogger({ name: 'token_exchange_product',
  level: process.env.LOG_LEVEL || 'info' });

const ROOT = path.join(__dirname, '..');

// Runs in the child. Stringified, so it may use nothing from this file's
// scope, and — code in a `node -e` child — is exempt from the Entering/Leaving
// rule (root CLAUDE.md, *Code style*).
function childMain() {
  const ROOT = process.env.TXP_ROOT;
  const OUT = process.env.TXP_OUT;
  const http = require('http');
  const crypto = require('crypto');
  const findings = [];
  const note = function (ok, what, detail) {
    findings.push({ ok: !!ok, what: what,
                    detail: detail === undefined ? '' : String(detail) });
  };
  const post = function (port, form, at) {
    return new Promise(function (resolve) {
      // A value that is an array is sent as the parameter repeated.
      const params = new URLSearchParams();
      Object.keys(form).forEach(function (k) {
        [].concat(form[k]).forEach(function (v) {
          params.append(k, v);
        });
      });
      const body = params.toString();
      const req = http.request({ host: '127.0.0.1', port: port,
        path: at || '/oauth2/token', method: 'POST',
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
            json = { parseError: e.message };
          }
          resolve({ status: res.statusCode, json: json, text: text });
        });
      });
      req.end(body);
    });
  };
  const b64u = function (o) {
    return Buffer.from(JSON.stringify(o), 'utf8').toString('base64url');
  };
  const claimsOf = function (jwt) {
    return JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url')
                            .toString('utf8'));
  };

  (async function () {
    require(ROOT + '/common/protocol_stack');
    const app = require(ROOT + '/common/app');
    const config = require(ROOT + '/common/config');
    const applications = require(ROOT + '/common/applications');
    const stats = require(ROOT + '/common/admin_stats');
    const audit = require(ROOT + '/common/audit');

    const server = http.createServer(app);
    await new Promise(function (r) { server.listen(0, '127.0.0.1', r); });
    const port = server.address().port;

    const SECRET = 'txp-confidential-secret-0123456789abcdef';
    const EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
    const ACCESS = 'urn:ietf:params:oauth:token-type:access_token';
    // Made in DEVELOPMENT, because product mode creates nothing because it
    // was named — the fixture has to exist before the mode is switched.
    applications.createApplication({ identifier: 'txp-client',
      protocols: ['oauth2'],
      fields: { oauthClientId: 'txp-client', oauthClientSecret: SECRET,
                oauthTokenEndpointAuthMethod: 'client_secret_post',
                oauthGrantType: ['client_credentials', EXCHANGE] } });
    const auth = { client_id: 'txp-client', client_secret: SECRET };
    const exchange = function (subjectToken, extra) {
      return post(port, Object.assign({ grant_type: EXCHANGE,
        subject_token: subjectToken, subject_token_type: ACCESS }, auth,
      extra || {}));
    };
    const codeRecorded = function (code) {
      return audit.list().some(function (row) {
        return row.errorCode === code;
      });
    };
    // Somebody the forger would like to be.
    const forgedClaims = { iss: 'https://127.0.0.1:' + port,
      sub: 'urn:uuid:00000000-0000-4000-8000-00000000a11c',
      username: 'txp-admin', scope: 'openid',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600,
      jti: 'txp-forged-' + crypto.randomBytes(6).toString('hex') };
    const unsigned = b64u({ alg: 'none', typ: 'JWT' }) + '.' +
                     b64u(forgedClaims) + '.';
    const stranger = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const signingInput = b64u({ alg: 'RS256', typ: 'JWT' }) + '.' +
                         b64u(forgedClaims);
    const foreignSigned = signingInput + '.' +
      crypto.sign('sha256', Buffer.from(signingInput), stranger.privateKey)
        .toString('base64url');

    // --- #186's fixtures, made in DEVELOPMENT for the reason above ---------
    // S is the application a subject_token was issued for (its `client_id`
    // here, its `aud` being this realm), R the one audience asked for.
    const helpers = require(ROOT + '/common/helpers');
    const dir = require(ROOT + '/ldap/ldap_server');
    const credentials = require(ROOT + '/common/credentials');
    const delegation = require(ROOT + '/common/delegation');
    const BACK = 'https://txp-back.example';
    dir.createUser('txp-alice', { invent: false });
    dir.createUser('txp-bob', { invent: false });
    credentials.setNotDelegated('txp-bob', true);
    const aliceSub = helpers.subjectForName('txp-alice');
    const bobSub = helpers.subjectForName('txp-bob');
    const confidential = function (identifier, fields) {
      // OIDC too: in product an `openid` scope is an OpenID Connect
      // issuance, refused for an application not declared for it.
      return applications.createApplication({ identifier: identifier,
        protocols: ['oauth2', 'oidc'],
        fields: Object.assign({ oauthClientId: identifier,
          oauthClientSecret: identifier + '-secret-0123456789abcdef0123',
          oauthTokenEndpointAuthMethod: 'client_secret_post',
          oauthGrantType: ['client_credentials', EXCHANGE],
          oauthAllowedScope: ['openid', 'api'] }, fields || {}) });
    };
    // R; a client too, so that it can be the actor.
    confidential('txp-back', { oauthAudience: [BACK],
                               appAllowedToActOnBehalfOf: ['txp-rbcd'] });
    // S delegating to R.
    confidential('txp-front', { appAllowedToDelegateTo: ['txp-back'] });
    // An actor allowing both semantics, S for its own tokens.
    confidential('txp-imp', { appAllowedToDelegateTo: ['txp-back'],
      appDelegationSemantics: ['delegation', 'impersonation'] });
    // R accepts it by name (resource-based).
    confidential('txp-rbcd', {});
    const as = function (identifier) {
      return { client_id: identifier,
               client_secret: identifier + '-secret-0123456789abcdef0123' };
    };
    // A token this realm signed about `who`, as `forApp`'s grant would have
    // produced it; `extra` adds `act`, `may_act`, a scope.
    const tokenAbout = function (sub, username, forApp, extra) {
      const now = Math.floor(Date.now() / 1000);
      return helpers.signJwt(Object.assign({
        iss: 'https://127.0.0.1:' + port, sub: sub,
        username: username, client_id: forApp, typ: 'Bearer',
        aud: 'https://127.0.0.1:' + port, scope: 'api',
        iat: now, nbf: now, exp: now + 600,
        jti: 'txp-' + crypto.randomBytes(6).toString('hex') },
      extra || {}));
    };
    const aliceToken = function (forApp, extra) {
      return tokenAbout(aliceSub, 'txp-alice', forApp || 'txp-front', extra);
    };
    const by = function (actor, subjectToken, extra) {
      return post(port, Object.assign({ grant_type: EXCHANGE,
        subject_token: subjectToken, subject_token_type: ACCESS },
      actor === 'txp-client' ? auth : as(actor), extra || {}));
    };
    // The newest act of a type: `delegation.list()` is newest first.
    const lastAct = function (type) {
      return delegation.list().filter(function (row) {
        return row.type === type;
      })[0] || null;
    };
    // A refusal, as each mode speaks it: product refuses with `error` and
    // records `code`; development issues and writes "would have been
    // refused" on the act's row of `type`.
    const refusedAs = function (m, r, error, code, type) {
      if (m === 'product') {
        return r.status === 400 && r.json.error === error &&
               !r.json.access_token && codeRecorded(code);
      }
      const row = lastAct(type);
      return r.status === 200 && !!row &&
             /WOULD HAVE BEEN REFUSED/.test(row.authorizedBy);
    };
    // A client named as an actor, in the one form its subject takes in the
    // mode (#471): `urn:sts:client:<id>` in RFC 9700 mode, which product
    // implies, and the bare client_id otherwise.
    const clientSubIn = function (m, id) {
      return m === 'product' ? 'urn:sts:client:' + id : id;
    };
    // Every entry of an `act` chain carries `iss` equal to `iss` (#471).
    const issOnEvery = function (act, iss) {
      let level = act;
      let depth = 0;
      while (level && typeof level === 'object') {
        if (level.iss !== iss) {
          return false;
        }
        level = level.act;
        depth += 1;
      }
      return depth > 0;
    };
    const policyChecks = async function (m) {
      const P = m === 'product' ? '7' : '8';
      const says = m === 'product' ? 'refused' : 'issued, would-have-been ' +
        'refused';
      // a. A DELEGATION: actor = S, S delegates to R; `act` names the actor.
      // No actor_token: the issuance policy chose the delegation, and the
      // actor is the exchanging client — named, since #471, in the form its
      // subject takes in the mode (it was the bare client_id in product too,
      // beside a namespaced original client in the same chain), and the
      // register's intermediary names it the same way.
      let r = await by('txp-front', aliceToken(), { audience: BACK });
      let claims = r.json.access_token ? claimsOf(r.json.access_token) : {};
      let row = lastAct('oauth-delegation');
      note(r.status === 200 && claims.act &&
           claims.act.sub === clientSubIn(m, 'txp-front') &&
           claims.act.iss === claims.iss && !!claims.iss &&
           [].concat(claims.aud).indexOf(BACK) >= 0 && row &&
           /issuance policy allowed delegation/.test(row.authorizedBy) &&
           row.intermediary &&
           row.intermediary.presented === clientSubIn(m, 'txp-front'),
           P + 'a. DELEGATION by S to R it delegates to, with no ' +
           'actor_token: issued, `act` naming the actor as ' +
           clientSubIn(m, 'txp-front') + ' with the token\'s `iss` (#471), ' +
           'for R, and the act says what allowed it and names the same actor',
           r.status + ' ' + JSON.stringify([claims.act, claims.iss,
                                            claims.aud,
                                            row && row.authorizedBy,
                                            row && row.intermediary]));
      // a2. The actor named by a VERIFIED actor_token: the client's own
      // client_credentials token, which since #550 is addressed to the
      // client itself (it declares no oauthAudience, so its client_id).
      const frontCc = await post(port, Object.assign(
        { grant_type: 'client_credentials', scope: 'api' },
        as('txp-front')));
      const frontClaims = frontCc.json.access_token
        ? claimsOf(frontCc.json.access_token) : {};
      const frontSub = frontClaims.sub || '';
      note(frontCc.status === 200 && frontClaims.aud === 'txp-front',
           P + 'a2-aud. a client_credentials token asking for nothing else ' +
           'is addressed to the client itself (#550)',
           frontCc.status + ' ' + JSON.stringify(frontClaims.aud));
      r = await by('txp-front', aliceToken(), { audience: BACK,
        actor_token: String(frontCc.json.access_token || ''),
        actor_token_type: ACCESS });
      claims = r.json.access_token ? claimsOf(r.json.access_token) : {};
      note(r.status === 200 && claims.act && frontSub &&
           claims.act.sub === frontSub && frontSub ===
             clientSubIn(m, 'txp-front') && claims.act.iss === claims.iss,
           P + 'a2. the actor_token\'s subject is the actor: S presenting ' +
           'its own token — `act.sub` is its sub',
           r.status + ' ' + JSON.stringify([claims.act, frontSub]));
      // a3. The original client is not nested beneath ITSELF (#443): S
      // exchanged the token it was issued, so the chain begins with S.
      note(r.status === 200 && claims.act && !claims.act.act,
           P + 'a3. the actor IS the client the subject token was issued ' +
           'to: nothing nested beneath it (#443)',
           r.status + ' ' + JSON.stringify(claims.act));
      // a2-bound. #550, in every mode: ANOTHER client presenting S's token
      // as its actor_token is refused — the actor is the caller's own.
      r = await by('txp-imp', aliceToken(), { audience: BACK,
        actor_token: String(frontCc.json.access_token || ''),
        actor_token_type: ACCESS });
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           !r.json.access_token && codeRecorded('STS-OAUTH-0955'),
           P + 'a2-bound. another client presenting S\'s token as its ' +
           'actor_token: refused (invalid_request, 0955) (#550)',
           r.status + ' ' + JSON.stringify(r.json));
      // a2-person. A person's token issued to another client is not this
      // client's actor either.
      r = await by('txp-imp', aliceToken(), { audience: BACK,
        actor_token: aliceToken('txp-front'), actor_token_type: ACCESS });
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           /issued to .txp-front./.test(String(r.json.error_description)),
           P + 'a2-person. a token issued to another client, about a ' +
           'person, as the actor_token: refused (0955) (#550)',
           r.status + ' ' + JSON.stringify(r.json));
      // a2-aud. S's own token, but addressed to another resource — the
      // kind that resource holds and could replay: refused (0956).
      const nowS = Math.floor(Date.now() / 1000);
      const forBack = helpers.signJwt({ iss: 'https://127.0.0.1:' + port,
        sub: frontSub, client_id: 'txp-front', typ: 'Bearer', aud: BACK,
        scope: 'api', iat: nowS, nbf: nowS, exp: nowS + 600,
        jti: 'txp-' + crypto.randomBytes(6).toString('hex') });
      r = await by('txp-front', aliceToken(), { audience: BACK,
        actor_token: forBack, actor_token_type: ACCESS });
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           !r.json.access_token && codeRecorded('STS-OAUTH-0956'),
           P + 'a2-aud. S\'s own token addressed to another resource as ' +
           'its actor_token: refused (invalid_request, 0956) (#550)',
           r.status + ' ' + JSON.stringify(r.json));
      // b. The same, actor = R holding the token S was handed — and the
      // chain BEGINS with S, the client that token was issued to (#443), in
      // the form a client's subject takes in the mode.
      r = await by('txp-back', aliceToken(), { audience: BACK });
      claims = r.json.access_token ? claimsOf(r.json.access_token) : {};
      // Both entries in the one form (#471): R had been the bare client_id
      // in product above a namespaced S — and both carry `iss`.
      const originalS = clientSubIn(m, 'txp-front');
      note(r.status === 200 && claims.act &&
           claims.act.sub === clientSubIn(m, 'txp-back') &&
           JSON.stringify(claims.act.act) ===
             JSON.stringify({ sub: originalS, iss: claims.iss }) &&
           issOnEvery(claims.act, claims.iss),
           P + 'b. DELEGATION by R, holding the token S was handed: issued, ' +
           '`act` naming R with the original client ' + originalS +
           ' nested beneath it (#443), each entry with the token\'s `iss` ' +
           '(#471)', r.status + ' ' +
           JSON.stringify(claims.act) + ' ' + r.text.slice(0, 300));
      // c. RESOURCE-BASED: R accepts the actor by name.
      r = await by('txp-rbcd', aliceToken('txp-rbcd'), { audience: BACK });
      note(r.status === 200, P + 'c. appAllowedToActOnBehalfOf on R allows ' +
           'an actor = S that names nothing itself', r.status + ' ' +
           r.text.slice(0, 300));
      // d. No relationship.
      r = await by('txp-client', aliceToken('txp-client'), { audience: BACK });
      note(refusedAs(m, r, 'invalid_target', 'STS-OAUTH-0619',
                     'oauth-delegation'),
           P + 'd. no relationship between S and R: ' + says +
           ' (invalid_target, 0619)', r.status + ' ' + r.text.slice(0, 300));
      // e. Impersonation asked by an actor allowing delegation only.
      r = await by('txp-front', aliceToken(), { audience: BACK,
        exchange_semantics: 'impersonation' });
      note(refusedAs(m, r, 'invalid_request', 'STS-OAUTH-0790',
                     'oauth-impersonation'),
           P + 'e. exchange_semantics=impersonation by an actor allowing ' +
           'delegation only: ' + says + ' (invalid_request, 0790)',
           r.status + ' ' + r.text.slice(0, 300));
      // f. ... and by one allowing it: no `act`.
      r = await by('txp-imp', aliceToken('txp-imp'), { audience: BACK,
        exchange_semantics: 'impersonation' });
      claims = r.json.access_token ? claimsOf(r.json.access_token) : {};
      note(r.status === 200 && !claims.act &&
           claims.sub === aliceSub,
           P + 'f. IMPERSONATION by an actor allowing it: issued, about the ' +
           'subject, with no `act`', r.status + ' ' + JSON.stringify(claims));
      // g. An unusable exchange_semantics: every mode.
      r = await by('txp-front', aliceToken(), { audience: BACK,
        exchange_semantics: 'sideways' });
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           codeRecorded('STS-OAUTH-0795'),
           P + 'g. exchange_semantics that is neither: invalid_request ' +
           '(0795) in ' + m, r.status + ' ' + r.text.slice(0, 300));
      // h. A protected subject.
      r = await by('txp-front', tokenAbout(bobSub, 'txp-bob', 'txp-front'),
                   { audience: BACK });
      note(refusedAs(m, r, 'invalid_request', 'STS-OAUTH-0618',
                     'oauth-delegation'),
           P + 'h. a subject carrying stsNotDelegated: ' + says +
           ' (invalid_request, 0618)', r.status + ' ' + r.text.slice(0, 300));
      // i. An unregistered audience.
      r = await by('txp-front', aliceToken(),
                   { audience: 'https://nowhere.example' });
      note(refusedAs(m, r, 'invalid_target', 'STS-OAUTH-0793',
                     'oauth-delegation'),
           P + 'i. an audience no application registers: ' + says +
           ' (invalid_target, 0793)', r.status + ' ' + r.text.slice(0, 300));
      // j. Two audiences.
      r = await by('txp-front', aliceToken(),
                   { audience: [BACK, 'txp-imp'] });
      // In development the policy only records it, and RFC 9068 section 3
      // refuses the ambiguous token anyway: invalid_target in both modes.
      note(r.status === 400 && r.json.error === 'invalid_target' &&
           !r.json.access_token &&
           (m !== 'product' || codeRecorded('STS-OAUTH-0792')),
           P + 'j. two audiences: invalid_target' +
           (m === 'product' ? ' (0792)' : ' (RFC 9068 section 3)'),
           r.status + ' ' + r.text.slice(0, 300));
      // k. No audience, not self.
      r = await by('txp-imp', aliceToken());
      note(refusedAs(m, r, 'invalid_target', 'STS-OAUTH-0794',
                     'oauth-delegation'),
           P + 'k. no audience by an actor that is not S: ' + says +
           ' (invalid_target, 0794)', r.status + ' ' + r.text.slice(0, 300));
      // l. Self, no audience: the subject_token's own.
      r = await by('txp-front', aliceToken());
      claims = r.json.access_token ? claimsOf(r.json.access_token) : {};
      note(r.status === 200 && !claims.act,
           P + 'l. S itself with no audience: a self exchange, no `act`',
           r.status + ' ' + JSON.stringify(claims.act || null));
      // m. may_act naming somebody else — every mode.
      r = await by('txp-front', aliceToken('txp-front',
        { may_act: { sub: 'somebody-else' } }), { audience: BACK });
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           codeRecorded('STS-OAUTH-0620'),
           P + 'm. a subject_token whose may_act names somebody else is ' +
           'refused (0620) in ' + m, r.status + ' ' + r.text.slice(0, 300));
      // n. act nests.
      r = await by('txp-front', aliceToken('txp-front',
        { act: { sub: 'txp-prior-actor' } }), { audience: BACK });
      claims = r.json.access_token ? claimsOf(r.json.access_token) : {};
      // The prior entry carries no `iss`; the subject_token is this
      // realm's own, so it is given that token's issuer (#471).
      note(r.status === 200 && claims.act &&
           claims.act.sub === clientSubIn(m, 'txp-front') &&
           claims.act.act && claims.act.act.sub === 'txp-prior-actor' &&
           !claims.act.act.act && issOnEvery(claims.act, claims.iss),
           P + 'n. `act` NESTS: the new actor outermost, the ' +
           'subject_token\'s actor beneath it (RFC 8693 section 4.1), and ' +
           'no original client added under a chain already there (#443); ' +
           'the prior entry, with no `iss` of its own, given the issuer of ' +
           'the token this realm signed (#471)',
           r.status + ' ' + JSON.stringify(claims.act));
      // n2. A prior entry that carries an `iss` keeps it (#471).
      r = await by('txp-front', aliceToken('txp-front',
        { act: { sub: 'txp-far-actor', iss: 'https://far.example',
                 act: { sub: 'txp-farther' } } }), { audience: BACK });
      claims = r.json.access_token ? claimsOf(r.json.access_token) : {};
      note(r.status === 200 && claims.act &&
           claims.act.iss === claims.iss &&
           claims.act.act && claims.act.act.sub === 'txp-far-actor' &&
           claims.act.act.iss === 'https://far.example' &&
           claims.act.act.act && claims.act.act.act.sub === 'txp-farther' &&
           claims.act.act.act.iss === claims.iss,
           P + 'n2. a prior entry\'s own `iss` is kept as it came; one ' +
           'without is given this realm\'s (#471)',
           r.status + ' ' + JSON.stringify(claims.act));
      // o. A wider scope.
      r = await by('txp-front', aliceToken('txp-front', { scope: 'api' }),
                   { audience: BACK, scope: 'api openid' });
      note(m === 'product' ? (r.status === 400 &&
                              r.json.error === 'invalid_scope' &&
                              codeRecorded('STS-OAUTH-0621'))
                           : r.status === 200,
           P + 'o. a scope WIDER than the subject_token\'s is ' +
           (m === 'product' ? 'invalid_scope (0621)'
                            : 'issued in development'),
           r.status + ' ' + r.text.slice(0, 300));
      r = await by('txp-front', aliceToken('txp-front',
        { scope: 'api openid' }), { audience: BACK, scope: 'api' });
      note(r.status === 200, P + 'p. and a narrower one is issued',
           r.status + ' ' + r.text.slice(0, 300));
      // q. stsMayAct puts may_act on what is issued about her.
      credentials.setMayAct('txp-alice', applications.get('txp-imp').dn);
      r = await by('txp-front', aliceToken(), { audience: BACK });
      const claim = r.json.access_token
        ? claimsOf(r.json.access_token).may_act : null;
      credentials.setMayAct('txp-alice', '');
      note(r.status === 200 && claim && claim.sub === 'txp-imp',
           P + 'q. stsMayAct on the person puts may_act naming that party ' +
           'on the access token issued about them', r.status + ' ' +
           JSON.stringify(claim));
      return true;
    };

    config.setOverride('oauth2.consentRequired', false);
    config.setOverride('global.mode', 'product');
    try {
      // 1. The control: a token this realm signed.
      const cc = await post(port, Object.assign(
        { grant_type: 'client_credentials' }, auth));
      note(cc.status === 200 && cc.json.access_token,
           'precondition: product mode issues the client a token by ' +
           'client_credentials', cc.status + ' ' + cc.text.slice(0, 200));
      const real = String(cc.json.access_token || '');
      let r = await exchange(real);
      note(r.status === 200 && r.json.access_token,
           '1. PRODUCT: a subject_token this realm signed IS exchanged — the ' +
           'control that makes every refusal below mean something',
           r.status + ' ' + r.text.slice(0, 200));

      // 2. Unsigned.
      r = await exchange(unsigned);
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           !r.json.access_token,
           '2a. PRODUCT: an UNSIGNED subject_token naming somebody else is ' +
           'refused invalid_request and NOTHING is issued — it was ' +
           'exchanged for a token this realm signed for that person',
           r.status + ' ' + r.text.slice(0, 200));
      note(codeRecorded('STS-OAUTH-0555'), '2b. with STS-OAUTH-0555');

      // 3. Signed by a stranger.
      r = await exchange(foreignSigned);
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           !r.json.access_token,
           '3. PRODUCT: a subject_token SIGNED WITH ANOTHER KEY is refused ' +
           'the same way', r.status + ' ' + r.text.slice(0, 200));

      // 4. Revoked.
      const again = await post(port, Object.assign(
        { grant_type: 'client_credentials' }, auth));
      const revoked = String(again.json.access_token || '');
      stats.revoke(claimsOf(revoked).jti, 'token_exchange_product fixture');
      r = await exchange(revoked);
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           codeRecorded('STS-OAUTH-0557'),
           '4. PRODUCT: a subject_token this realm REVOKED is refused, with ' +
           'STS-OAUTH-0557', r.status + ' ' + r.text.slice(0, 200));

      // 5. The actor.
      r = await exchange(real, { actor_token: unsigned,
                                 actor_token_type: ACCESS });
      note(r.status === 400 && r.json.error === 'invalid_request' &&
           codeRecorded('STS-OAUTH-0556'),
           '5a. PRODUCT: a verified subject with a FORGED actor_token is ' +
           'refused with STS-OAUTH-0556 — the actor was never verified in ' +
           'any mode, so `act` could name anybody',
           r.status + ' ' + r.text.slice(0, 200));
      r = await exchange(real, { actor_token: real,
                                 actor_token_type: ACCESS });
      const act = r.json.access_token ? claimsOf(r.json.access_token).act
                                       : null;
      note(r.status === 200 && !act,
           '5b. and with a VERIFIED actor_token the exchange succeeds — the ' +
           'actor IS the subject, a self exchange, so no `act` (#186)',
           r.status + ' ' + JSON.stringify(act));

      // 7. The delegation policy (#108).
      const policyIssued = await policyChecks('product');
      note(policyIssued, '7. PRODUCT: the delegation policy checks ran');
    } finally {
      config.clearOverride('global.mode');
    }
    const devRan = await policyChecks('development');
    note(devRan, '8. DEVELOPMENT: the delegation policy checks ran');

    // 9. RFC 9700 MODE WITHOUT PRODUCT (#471): the namespace is the mode's,
    // not product's, so a delegation the policy chose without an
    // actor_token names its actor `urn:sts:client:<id>` with the mode on in
    // development too — and the original client beneath it in the same
    // form, each entry carrying the token's `iss`. Before #471 the actor
    // was the bare client_id here, above a namespaced original client.
    // `oauth2.rfc9700` is restart-only for the process and settable on a
    // realm, so the mode is a realm's, with the fixtures made inside it.
    const realms = require(ROOT + '/common/realms');
    const R9 = 'txp-rfc9700';
    const made = realms.create({ id: R9, name: R9,
      description: 'token_exchange_product.js, #471',
      overrides: { 'oauth2.rfc9700': true,
                   'oauth2.consentRequired': false } });
    note(made && made.ok !== false, 'precondition: a realm in RFC 9700 ' +
         'mode was created', JSON.stringify(made && made.errors));
    const realm9 = realms.get(R9);
    const at9 = '/realm/' + R9 + '/oauth2/token';
    let fixtures9 = null;
    await realms.run(realm9, async function () {
      dir.createUser('txp-alice', { invent: false });
      confidential('txp-back', { oauthAudience: [BACK] });
      confidential('txp-front', { appAllowedToDelegateTo: ['txp-back'] });
      const sub9 = helpers.subjectForName('txp-alice');
      const now9 = Math.floor(Date.now() / 1000);
      const about9 = function (extra) {
        return helpers.signJwt(Object.assign({
          iss: 'http://127.0.0.1:' + port + '/realm/' + R9, sub: sub9,
          username: 'txp-alice', client_id: 'txp-front', typ: 'Bearer',
          aud: 'http://127.0.0.1:' + port + '/realm/' + R9, scope: 'api',
          iat: now9, nbf: now9, exp: now9 + 600,
          jti: 'txp9-' + crypto.randomBytes(6).toString('hex') },
        extra || {}));
      };
      fixtures9 = { plain: about9(),
                    mayActBare: about9({ may_act: { sub: 'txp-front' } }),
                    mayActSub: about9({ may_act:
                                        { sub: 'urn:sts:client:txp-front' } }),
                    plain2: about9() };
    });
    const by9 = function (actor, subjectToken) {
      return post(port, Object.assign({ grant_type: EXCHANGE,
        subject_token: subjectToken, subject_token_type: ACCESS,
        audience: BACK }, as(actor)), at9);
    };
    let r9 = await by9('txp-front', fixtures9.plain);
    let c9 = r9.json.access_token ? claimsOf(r9.json.access_token) : {};
    const row9 = await realms.run(realm9, function () {
      return lastAct('oauth-delegation');
    });
    note(r9.status === 200 && c9.act &&
         c9.act.sub === 'urn:sts:client:txp-front' && !c9.act.act &&
         c9.act.iss === c9.iss && !!c9.iss && row9 &&
         row9.intermediary.presented === 'urn:sts:client:txp-front',
         '9a. RFC 9700 MODE in development: a policy-chosen delegation ' +
         'with no actor_token names the client urn:sts:client:txp-front, ' +
         'with the token\'s `iss`, on the token and in the register',
         r9.status + ' ' + JSON.stringify([c9.act, c9.iss,
           row9 && row9.intermediary]) + ' ' + r9.text.slice(0, 300));
    r9 = await by9('txp-back', fixtures9.plain2);
    c9 = r9.json.access_token ? claimsOf(r9.json.access_token) : {};
    note(r9.status === 200 && JSON.stringify(c9.act) ===
           JSON.stringify({ sub: 'urn:sts:client:txp-back', iss: c9.iss,
                            act: { sub: 'urn:sts:client:txp-front',
                                   iss: c9.iss } }),
         '9b. and R holding the token S was handed: both entries ' +
         'urn:sts:client:, the original client nested, `iss` on each',
         r9.status + ' ' + JSON.stringify(c9.act) + ' ' +
         r9.text.slice(0, 300));
    // 9c. may_act naming the client by its bare client_id — the form
    // stsMayAct puts on a token — still names the namespaced actor.
    r9 = await by9('txp-front', fixtures9.mayActBare);
    c9 = r9.json.access_token ? claimsOf(r9.json.access_token) : {};
    note(r9.status === 200 && c9.act &&
         c9.act.sub === 'urn:sts:client:txp-front',
         '9c. may_act naming the client by its client_id still names it ' +
         'when it acts as urn:sts:client:txp-front',
         r9.status + ' ' + r9.text.slice(0, 300));
    // 9d. and naming it by its subject does too.
    r9 = await by9('txp-front', fixtures9.mayActSub);
    note(r9.status === 200,
         '9d. may_act naming the client by urn:sts:client:txp-front ' +
         'names it', r9.status + ' ' + r9.text.slice(0, 300));
    realms.remove(R9);
    // 9e. and with the mode off, may_act by the subject form still names
    // the client acting under its bare client_id.
    const r9e = await by('txp-front', aliceToken('txp-front',
      { may_act: { sub: 'urn:sts:client:txp-front' } }), { audience: BACK });
    note(r9e.status === 200, '9e. with RFC 9700 mode off, may_act naming ' +
         'urn:sts:client:txp-front names the client acting as txp-front',
         r9e.status + ' ' + r9e.text.slice(0, 300));

    // 6. Development is what it was.
    const dev = await exchange(unsigned);
    note(dev.status === 200 && dev.json.access_token &&
         claimsOf(dev.json.access_token).sub === forgedClaims.sub,
         '6. DEVELOPMENT is unchanged: the unsigned token is still exchanged ' +
         'and the result names whom it claimed — the behaviour a client ' +
         'under test drives the grant with',
         dev.status + ' ' + dev.text.slice(0, 200));
    server.close();
  })().catch(function (e) {
    note(false, 'the child ran to the end', e && e.stack);
  }).then(function () {
    require('fs').writeFileSync(OUT, JSON.stringify(findings));
    process.exit(0);
  });
}

function run(t) {
  log.debug("Entering run().");
  const out = path.join(os.tmpdir(), 'sts-txp-' + process.pid + '-' +
                                     Date.now() + '.json');
  const env = Object.assign({}, process.env, { TXP_OUT: out, TXP_ROOT: ROOT,
    STS_HTTPS: 'false' });
  delete env.CONFIG_FILE;
  const result = childProcess.spawnSync(process.execPath,
    ['-e', '(' + childMain.toString() + ')()'], {
      cwd: ROOT, env: env, encoding: 'utf8', timeout: 180000,
      maxBuffer: 256 * 1024 * 1024 });
  let findings = null;
  try {
    findings = JSON.parse(fs.readFileSync(out, 'utf8'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    // The child died before writing a report; said below with its status.
    findings = null;
  }
  try {
    fs.rmSync(out, { force: true });
  } catch (e) {
    // A temporary file left behind is not a failed assertion.
    log.debug("Caught in run(): " + ((e && e.message) || e));
  }
  if (t.check(Array.isArray(findings),
              'the child process reported its findings',
              'status=' + result.status + ' ' +
              String(result.stderr || '').slice(-2000))) {
    findings.forEach(function (one) {
      t.check(one.ok, one.what, one.detail);
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'token_exchange_product',
  describe: 'product mode exchanges only a subject_token and actor_token ' +
            'this realm can verify',
  run: run
};

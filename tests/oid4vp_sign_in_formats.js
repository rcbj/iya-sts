'use strict';

// ===========================================================================
// tests/oid4vp_sign_in_formats.js — EVERY CREDENTIAL FORMAT THIS ISSUER
// MINTS CAN SIGN SOMEBODY IN, WITH THE SAME GUARANTEE (#38's follow-ups).
//
// #38 shipped with one format: only a `dc+sd-jwt` could sign in, because it
// was the only one whose presentation carried a FRESH HOLDER PROOF this
// service checked. The other two now do, and this file is the contract —
// driven over HTTP against the whole stack, with the wallet in
// `tests/wallet_kit.js`:
//
//   1. each format is issued, recorded in the sign-in register, and signs its
//      person in — amr ["pop"], acr "1", the entry's urn:uuid subject;
//   2. each is refused, with its code, without a holder proof, with the
//      wrong nonce, the wrong audience, the wrong key, on a token this realm
//      did not verify, and from another realm;
//   3. a POST-QUANTUM holder key (ML-DSA-44) signs in in every format, and a
//      credential signed with a post-quantum ISSUER key (ML-DSA-44) is
//      accepted as this realm's;
//   4. `oid4vp.signInFormats` decides which queries the request carries, and
//      a format left out cannot answer;
//   5. THE PARENT PROJECT'S WALLET SHAPES: a Key Binding JWT and a VP JWT
//      built exactly as `client/src/sd_jwt_vp.js` builds them, signed through
//      the VENDORED `tests/vendored/jws.js` that wallet signs with, sign in;
//      its `ldp_vc` envelope — a bare bbs-2023 derived proof, no holder proof
//      at all — is refused by name.
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'oid4vp_sign_in_formats',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');
  const FORMATS = ['dc+sd-jwt', 'jwt_vc_json', 'ldp_vc'];

  walletKit.boot().then(async function (w) {
    const note = w.note;
    const m = w.m;
    try {
      await sections(w, note, m);
    } catch (e) {
      note(false, 'the child ran to the end', e && (e.stack || e.message));
    }
    await w.finish(OUT);
    process.exit(0);
  }).catch(function (e) {
    require('fs').writeFileSync(OUT, JSON.stringify([
      { ok: false, what: 'the child booted', detail: e && e.stack }]));
    process.exit(0);
  });

  async function sections(w, note, m) {
    await w.inRealm(function () {
      w.provision();
      m.ldap.createUser('fmt-alice', { invent: false });
      m.ldap.createUser('fmt-bob', { invent: false });
    });
    const aliceSub = await w.inRealm(function () {
      return m.helpers.subjectForName('fmt-alice');
    });
    const aud = await w.inRealm(function () {
      return m.config.value('oid4vp.clientId');
    });

    // One sign-in attempt, end to end: `{ ok, code, session, page }`.
    async function attempt(format, credential, holder, opts) {
      const o = opts || {};
      const who = w.browser();
      const one = await w.start(who, w.pendingSignIn());
      const presentation = await w.present(format, credential, holder,
        o.nonce === undefined ? one.requestObject.nonce : o.nonce,
        o.aud === undefined ? aud : o.aud, o);
      const answered = await w.respond(one, presentation, { format: format });
      const page = await w.request('GET', one.waitPath, { browser: who });
      const session = w.sessionOf(who);
      if (session) {
        await w.inRealm(function () {
          m.authn.endSessionById(session.id, 'the test, tidying up');
        });
      }
      return { ok: page.status === 303, code: page.code, page: page,
               answered: answered, session: session };
    }

    // ==================================================================
    // 1 AND 2. EVERY FORMAT, AND EVERY REFUSAL
    // ==================================================================
    for (const format of FORMATS) {
      const holder = w.holderKey();
      const issued = await w.issue('fmt-alice', holder, { format: format });
      note(!!issued.credential, '1a[' + format + ']. a credential is issued',
           issued.error);
      const row = await w.inRealm(function () {
        return format === 'ldp_vc'
          ? m.issued.lookupHolder(m.stsCrypto.jwkThumbprint(holder.jwk, {}))[0]
          : m.issued.lookup(issued.credential);
      });
      note(row && row.subject === aliceSub && row.format === format &&
           !('credential' in row),
           '1b[' + format + ']. and recorded in the sign-in register under ' +
           'her subject, by ' + (format === 'ldp_vc' ? 'holder key' :
                                 'digest') + ' and never the credential',
           row && JSON.stringify({ kind: row.kind, format: row.format }));

      const signedIn = await attempt(format, issued.credential, holder);
      note(signedIn.ok && signedIn.session &&
           signedIn.session.user.username === 'fmt-alice' &&
           signedIn.session.user.sub === aliceSub &&
           JSON.stringify(signedIn.session.amr) === '["pop"]' &&
           signedIn.session.acr === '1',
           '1c[' + format + ']. it signs fmt-alice in, amr ["pop"], acr "1"',
           signedIn.page.status + ' ' + signedIn.code +
           (signedIn.session ? ' ' + JSON.stringify(signedIn.session.amr) :
            ''));

      const noProof = await attempt(format, issued.credential, holder,
                                    { noProof: true });
      note(!noProof.ok && noProof.code === 'STS-VC-0061',
           '2a[' + format + ']. with no holder proof it signs nobody in, ' +
           'STS-VC-0061', noProof.code);
      const wrongNonce = await attempt(format, issued.credential, holder,
                                       { nonce: 'not-this-nonce',
                                         challenge: 'not-this-nonce',
                                         bbsNonce: 'not-this-nonce' });
      note(!wrongNonce.ok && wrongNonce.code === 'STS-VC-0061',
           '2b[' + format + ']. with another request\'s nonce, STS-VC-0061',
           wrongNonce.code);
      const wrongAud = await attempt(format, issued.credential, holder,
                                     { aud: 'https://somebody.else' });
      note(!wrongAud.ok && wrongAud.code === 'STS-VC-0061',
           '2c[' + format + ']. made for another audience, STS-VC-0061',
           wrongAud.code);
      const otherKey = w.holderKey();
      const wrongKey = await attempt(format, issued.credential, holder,
                                     { key: otherKey });
      note(!wrongKey.ok && wrongKey.code === 'STS-VC-0061',
           '2d[' + format + ']. proved with a key the credential is not ' +
           'bound to, STS-VC-0061', wrongKey.code);

      // A credential this realm SIGNED on an access token it did not verify.
      const forgedKey = w.holderKey();
      const forged = m.stsCrypto.signJws(
        { sub: aliceSub, scope: 'identity_credential ' +
          'identity_credential_jwt identity_credential_ldp',
          iss: 'https://elsewhere.example',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 300 },
        require('crypto').generateKeyPairSync('rsa',
          { modulusLength: 2048 }).privateKey,
        { algorithm: 'RS256', header: { typ: 'at+jwt' } });
      const onForeign = await w.issue('fmt-alice', forgedKey,
                                      { format: format, token: forged });
      const foreignAttempt = onForeign.credential
        ? await attempt(format, onForeign.credential, forgedKey) : null;
      note(!!onForeign.credential && foreignAttempt &&
           !foreignAttempt.ok && foreignAttempt.code === 'STS-VC-0059',
           '2e[' + format + ']. issued on a token this realm did not verify, ' +
           'it VERIFIES and signs nobody in, STS-VC-0059',
           (onForeign.error || '') + ' ' +
           (foreignAttempt && foreignAttempt.code));
    }

    // ==================================================================
    // 2f. ANOTHER REALM'S CREDENTIAL, in every format
    // ==================================================================
    await w.inRealm(function () {
      m.realms.create({ id: 'fmt-other', name: 'fmt-other', overrides: {} });
    });
    const other = m.realms.get('fmt-other');
    await w.inRealm(function () {
      w.provision();
      m.ldap.createUser('fmt-alice', { invent: false });
    }, other);
    for (const format of FORMATS) {
      const holder = w.holderKey();
      const elsewhere = await w.issue('fmt-alice', holder,
        { format: format, prefix: '/realm/fmt-other', realm: other });
      const here = elsewhere.credential
        ? await attempt(format, elsewhere.credential, holder) : null;
      note(!!elsewhere.credential && here && !here.ok &&
           here.code === 'STS-VC-0061',
           '2f[' + format + ']. another realm\'s credential signs nobody in ' +
           'here, STS-VC-0061 — for ldp_vc the disclosed issuer is that ' +
           'realm\'s, which is what tells them apart when the BBS key ' +
           'cannot', (elsewhere.error || '') + ' ' + (here && here.code));
    }

    // ==================================================================
    // 3. POST-QUANTUM: the holder's key, and the issuer's
    // ==================================================================
    for (const format of FORMATS) {
      const pqHolder = w.holderKey('ML-DSA-44');
      const issued = await w.issue('fmt-alice', pqHolder, { format: format });
      const signedIn = issued.credential
        ? await attempt(format, issued.credential, pqHolder) : null;
      note(!!issued.credential && signedIn && signedIn.ok,
           '3a[' + format + ']. an ML-DSA-44 holder key is bound at ' +
           'issuance and proves the presentation, in the worker pool\'s ' +
           'place', (issued.error || '') + ' ' + (signedIn && signedIn.code));
    }
    await w.inRealm(function () {
      m.config.setOverride('oid4vci.credentialSigningAlgorithm', 'ML-DSA-44');
    });
    for (const format of ['dc+sd-jwt', 'jwt_vc_json']) {
      const holder = w.holderKey();
      const issued = await w.issue('fmt-alice', holder, { format: format });
      const header = issued.credential
        ? JSON.parse(Buffer.from(String(issued.credential).split('.')[0],
                                 'base64url').toString('utf8')) : {};
      const signedIn = issued.credential
        ? await attempt(format, issued.credential, holder) : null;
      note(!!issued.credential && header.alg === 'ML-DSA-44' &&
           signedIn && signedIn.ok,
           '3b[' + format + ']. a credential signed with this realm\'s ' +
           'ML-DSA-44 key is accepted as this realm\'s and signs her in',
           (issued.error || '') + ' ' + header.alg + ' ' +
           (signedIn && signedIn.code));
    }
    await w.inRealm(function () {
      m.config.clearOverride('oid4vci.credentialSigningAlgorithm');
    });

    // ==================================================================
    // 4. WHICH FORMATS THE REQUEST ASKS FOR
    // ==================================================================
    await w.inRealm(function () {
      m.config.setOverride('oid4vp.signInFormats', 'jwt_vc_json');
    });
    const narrowed = await w.start(w.browser(), w.pendingSignIn());
    const queries = (narrowed.requestObject.dcql_query || {}).credentials ||
                    [];
    note(queries.length === 1 && queries[0].format === 'jwt_vc_json' &&
         !(narrowed.requestObject.dcql_query || {}).credential_sets,
         '4a. oid4vp.signInFormats narrows the request to the formats it ' +
         'names, and one query needs no credential set',
         JSON.stringify(queries.map(function (q) { return q.format; })));
    const sdHolder = w.holderKey();
    const sdIssued = await w.issue('fmt-alice', sdHolder,
                                   { format: 'dc+sd-jwt' });
    const wrongFormat = await w.respond(narrowed,
      w.presentSdJwt(sdIssued.credential, sdHolder,
                     narrowed.requestObject.nonce, aud),
      { format: 'dc+sd-jwt' });
    note(wrongFormat.status === 400,
         '4b. an SD-JWT answering a query that was not sent is refused: the ' +
         'vp_token names a credential query this request does not have',
         wrongFormat.status + ' ' + wrongFormat.text.slice(0, 120));
    // A SIGN-IN'S TRANSACTION IS ANSWERED ONCE, so this needs one of its own.
    const narrowedAgain = await w.start(w.browser(), w.pendingSignIn());
    const wrongUnderId = await w.respond(narrowedAgain,
      w.presentSdJwt(sdIssued.credential, sdHolder,
                     narrowedAgain.requestObject.nonce, aud),
      { format: 'jwt_vc_json' });
    note(wrongUnderId.status === 400 &&
         /jwt_vc_json/.test(wrongUnderId.text),
         '4c. and an SD-JWT sent under the jwt_vc_json query id is refused ' +
         'for being the wrong format, not read by the other code path',
         wrongUnderId.status + ' ' + wrongUnderId.text.slice(0, 160));
    await w.inRealm(function () {
      m.config.clearOverride('oid4vp.signInFormats');
    });

    // ==================================================================
    // 5. THE PARENT PROJECT'S WALLET SHAPES
    //
    // `client/src/sd_jwt_vp.js` signs a Key Binding JWT with
    // `{ typ: "kb+jwt", alg: "ES256" }` over `{ iat, aud, nonce, sd_hash }`,
    // and a VP JWT with `{ typ: "JWT", alg: "ES256" }` over `{ iss, aud,
    // nonce, iat, vp }` — through `jws.signJwsAsync()`, which is VENDORED
    // here byte for byte. Both are built with that module below, so this is
    // the parent wallet's signing code and its exact payloads.
    // ==================================================================
    const vendoredJws = require(ROOT + '/tests/vendored/jws.js');
    const parentKey = w.holderKey();
    const parentCred = await w.issue('fmt-alice', parentKey,
                                     { format: 'dc+sd-jwt' });
    const parentWho = w.browser();
    const parentOne = await w.start(parentWho, w.pendingSignIn());
    const prefix = String(parentCred.credential).split('~')[0] + '~';
    const sdHash = require('crypto').createHash('sha256')
      .update(prefix, 'ascii').digest('base64url');
    const kb = await vendoredJws.signJwsAsync({
      algId: 'ES256',
      protectedHeader: { typ: 'kb+jwt', alg: 'ES256' },
      payload: { iat: Math.floor(Date.now() / 1000), aud: aud,
                 nonce: parentOne.requestObject.nonce, sd_hash: sdHash },
      privateKey: { jwk: parentKey.privateJwk },
      backend: 'js'
    });
    await w.respond(parentOne, prefix + kb.serialized,
                    { format: 'dc+sd-jwt' });
    const parentPage = await w.request('GET', parentOne.waitPath,
                                       { browser: parentWho });
    note(parentPage.status === 303 && w.sessionOf(parentWho) &&
         w.sessionOf(parentWho).user.username === 'fmt-alice',
         '5a. the parent wallet\'s SD-JWT+KB shape, signed with its own ' +
         'vendored jws.js, signs in', parentPage.status + ' ' +
         parentPage.code);

    const parentJwtKey = w.holderKey();
    const parentJwtCred = await w.issue('fmt-alice', parentJwtKey,
                                        { format: 'jwt_vc_json' });
    const jwtWho = w.browser();
    const jwtOne = await w.start(jwtWho, w.pendingSignIn());
    const vp = await vendoredJws.signJwsAsync({
      algId: 'ES256',
      protectedHeader: { typ: 'JWT', alg: 'ES256' },
      payload: { iss: 'urn:ietf:params:oauth:jwk-thumbprint:holder',
                 aud: aud, nonce: jwtOne.requestObject.nonce,
                 iat: Math.floor(Date.now() / 1000),
                 vp: { '@context': ['https://www.w3.org/2018/credentials/v1'],
                       type: ['VerifiablePresentation'],
                       verifiableCredential: [parentJwtCred.credential] } },
      privateKey: { jwk: parentJwtKey.privateJwk },
      backend: 'js'
    });
    await w.respond(jwtOne, vp.serialized, { format: 'jwt_vc_json' });
    const jwtPage = await w.request('GET', jwtOne.waitPath,
                                    { browser: jwtWho });
    note(jwtPage.status === 303 && w.sessionOf(jwtWho) &&
         w.sessionOf(jwtWho).user.username === 'fmt-alice',
         '5b. and its VP JWT shape — iss, aud, nonce, iat and vp — signs in ' +
         'too', jwtPage.status + ' ' + jwtPage.code);

    const bareKey = w.holderKey();
    const bareCred = await w.issue('fmt-alice', bareKey, { format: 'ldp_vc' });
    const bare = await attempt('ldp_vc', bareCred.credential, bareKey,
                               { bare: true });
    note(!bare.ok && bare.code === 'STS-VC-0061' &&
         /Holder binding/.test(bare.page.text),
         '5c. the parent wallet\'s ldp_vc envelope — a bare derived proof, ' +
         'with no holder proof at all — is refused BY NAME: that shape ' +
         'proves the nonce and nothing about who presented it',
         bare.code);

  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'oid4vp-sign-in-formats');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oid4vp sign-in formats',
  describe: 'every credential format this issuer mints signs its person in ' +
            'with a fresh holder proof, post-quantum keys included, and ' +
            'each is refused without one',
  run: run
};

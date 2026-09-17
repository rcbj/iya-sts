'use strict';

// ===========================================================================
// tests/oid4vp_dc_api.js — THE WALLET SIGN-IN THROUGH THE W3C DIGITAL
// CREDENTIALS API (#38's follow-ups, OpenID4VP 1.0 Appendix A).
//
// The relay a plain QR code allows — somebody starts a sign-in in their own
// browser and shows the code to a victim — is what this path answers: the
// browser that asked is the one the answer comes back to, and a wallet on
// another device is reached over a transport that proves proximity to it. So
// the request has to name the origin it may be used from, the answer has to
// come back to the page that asked, and this file is the contract:
//
//   1. the wait page carries a signed `openid4vp-v1-signed` request whose
//      `expected_origins` is this service's origin, whose `response_mode` is
//      `dc_api.jwt`, which carries an encryption key and no response_uri,
//      redirect_uri or state;
//   2. an encrypted answer posted by that page signs the browser in, with the
//      audience `origin:<origin>` the specification requires;
//   3. an answer whose presentation names the Client Identifier as its
//      audience — a direct_post presentation replayed here — is refused;
//   4. an answer posted from another origin is refused (STS-VC-0074), as is
//      one posted by another browser (STS-VC-0055), one for a transaction
//      that was already answered (STS-VC-0057), an unencrypted answer to an
//      encrypted request and a wrong protocol (STS-VC-0073);
//   5. the no-script path: the form submitted with no answer says so and
//      offers the same-device link (STS-VC-0081);
//   6. `oid4vp.signInDcApiResponseMode` = `dc_api` asks for an unencrypted
//      answer, and that answer signs in.
//
// In a CHILD PROCESS, for `admin_credential_controls.js`'s reason.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./wallet_kit');

const log = require('bunyan').createLogger({ name: 'oid4vp_dc_api',
  level: process.env.LOG_LEVEL || 'info' });

function childMain() {
  /* eslint-disable no-console */
  const ROOT = process.env.WSI_ROOT;
  const OUT = process.env.WSI_OUT;
  const walletKit = require(ROOT + '/tests/wallet_kit');

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
      m.ldap.createUser('dc-alice', { invent: false });
    });
    const aliceSub = await w.inRealm(function () {
      return m.helpers.subjectForName('dc-alice');
    });
    const clientId = await w.inRealm(function () {
      return m.config.value('oid4vp.clientId');
    });
    const dcAud = 'origin:' + w.origin;

    // ==================================================================
    // 1. THE REQUEST
    // ==================================================================
    const holder = w.holderKey();
    const issued = await w.issue('dc-alice', holder);
    note(!!issued.credential, '0a. a credential is issued to dc-alice',
         issued.error);
    const who = w.browser();
    const one = await w.start(who, w.pendingSignIn());
    const payload = one.dcPayload || {};
    note(one.dcRequest && one.dcRequest.protocol === 'openid4vp-v1-signed' &&
         typeof one.dcRequest.data.request === 'string',
         '1a. the page carries one request for the Digital Credentials API, ' +
         'in the signed protocol (Appendix A.1), as { request: <JWS> }',
         one.dcRequest && one.dcRequest.protocol);
    note(JSON.stringify(payload.expected_origins) ===
           JSON.stringify([w.origin]) &&
         payload.client_id === clientId &&
         payload.response_mode === 'dc_api.jwt' &&
         payload.response_uri === undefined &&
         payload.redirect_uri === undefined &&
         payload.state === undefined,
         '1b. it names this service\'s origin in expected_origins, carries ' +
         'the client_id a signed request must (A.2), and has no ' +
         'response_uri, redirect_uri or state',
         JSON.stringify({ origins: payload.expected_origins,
                          mode: payload.response_mode }));
    const jwks = (payload.client_metadata || {}).jwks || { keys: [] };
    note(jwks.keys.length === 1 && jwks.keys[0].alg === 'ECDH-ES' &&
         jwks.keys[0].use === 'enc' && !!jwks.keys[0].kid &&
         JSON.stringify(
           payload.client_metadata.encrypted_response_enc_values_supported)
           === JSON.stringify(['A128GCM', 'A256GCM']),
         '1c. and an encryption key of its own, with the enc values section ' +
         '8.3 asks for', JSON.stringify(jwks.keys[0] || {}));
    note(payload.nonce === one.requestObject.nonce &&
         JSON.stringify(payload.dcql_query) ===
           JSON.stringify(one.requestObject.dcql_query),
         '1d. it is the SAME transaction as the same-device request: one ' +
         'nonce, one query, answered once');

    // ==================================================================
    // 2. AN ANSWER, ENCRYPTED, WITH THE origin: AUDIENCE
    // ==================================================================
    const presentation = w.presentSdJwt(issued.credential, holder,
                                        payload.nonce, dcAud);
    const answered = await w.answerDcApi(who, one, presentation);
    const session = w.sessionOf(who);
    note(answered.status === 303 && session &&
         session.user.username === 'dc-alice' &&
         session.user.sub === aliceSub,
         '2a. the answer the page posts signs that browser in, and nobody ' +
         'else', answered.status + ' ' + answered.code);
    note(answered.headers.location === '/wsi/after',
         '2b. and the request that was waiting carries on',
         answered.headers.location);
    await w.inRealm(function () {
      m.authn.endSessionById(session.id, 'the test, tidying up');
    });

    // ==================================================================
    // 3. THE AUDIENCE IS THE ORIGIN, NOT THE CLIENT IDENTIFIER
    // ==================================================================
    const wrongAudWho = w.browser();
    const wrongAudOne = await w.start(wrongAudWho, w.pendingSignIn());
    const forClient = w.presentSdJwt(issued.credential, holder,
      wrongAudOne.dcPayload.nonce, clientId);
    const wrongAud = await w.answerDcApi(wrongAudWho, wrongAudOne, forClient);
    note(wrongAud.status === 403 && wrongAud.code === 'STS-VC-0061' &&
         !w.sessionOf(wrongAudWho),
         '3a. a presentation whose audience is the Client Identifier — one ' +
         'made for the direct_post path — signs nobody in here: Appendix ' +
         'A.4 fixes the audience at origin:<origin>',
         wrongAud.status + ' ' + wrongAud.code);

    // ==================================================================
    // 4. WHERE THE ANSWER MAY COME FROM
    // ==================================================================
    const otherOriginWho = w.browser();
    const otherOriginOne = await w.start(otherOriginWho, w.pendingSignIn());
    const elsewhere = await w.answerDcApi(otherOriginWho, otherOriginOne,
      w.presentSdJwt(issued.credential, holder,
                     otherOriginOne.dcPayload.nonce, dcAud),
      { origin: 'https://attacker.example' });
    note(elsewhere.status === 403 && elsewhere.code === 'STS-VC-0074' &&
         !w.sessionOf(otherOriginWho),
         '4a. an answer posted from another origin is refused, STS-VC-0074',
         elsewhere.status + ' ' + elsewhere.code);
    const stranger = w.browser();
    const strangerPost = await w.answerDcApi(stranger, otherOriginOne,
      w.presentSdJwt(issued.credential, holder,
                     otherOriginOne.dcPayload.nonce, dcAud));
    note(strangerPost.status === 403 && strangerPost.code === 'STS-VC-0055' &&
         !w.sessionOf(stranger),
         '4b. and one posted by a browser that did not start the sign-in is ' +
         'refused, STS-VC-0055 — the binding cookie, exactly as on the wait ' +
         'page', strangerPost.status + ' ' + strangerPost.code);
    const good = await w.answerDcApi(otherOriginWho, otherOriginOne,
      w.presentSdJwt(issued.credential, holder,
                     otherOriginOne.dcPayload.nonce, dcAud));
    const twice = await w.answerDcApi(otherOriginWho, otherOriginOne,
      w.presentSdJwt(issued.credential, holder,
                     otherOriginOne.dcPayload.nonce, dcAud));
    note(good.status === 303 && twice.status === 400 &&
         twice.code === 'STS-VC-0062',
         '4c. the answer and the session are ONE request here, so a second ' +
         'answer meets the finished sign-in, STS-VC-0062',
         good.status + ' ' + twice.status + ' ' + twice.code);
    // AND A TRANSACTION ANSWERED THE OTHER WAY IS ANSWERED: a direct_post
    // presentation and then a Digital Credentials API answer for the same
    // sign-in is the swap a sign-in must not allow.
    const mixedWho = w.browser();
    const mixedOne = await w.start(mixedWho, w.pendingSignIn());
    await w.respond(mixedOne, w.presentSdJwt(issued.credential, holder,
      mixedOne.requestObject.nonce, clientId), { format: 'dc+sd-jwt' });
    const mixed = await w.answerDcApi(mixedWho, mixedOne,
      w.presentSdJwt(issued.credential, holder, mixedOne.dcPayload.nonce,
                     dcAud));
    note(mixed.status === 400 && mixed.code === 'STS-VC-0057',
         '4c-ii. a sign-in already answered by direct_post refuses a ' +
         'Digital Credentials API answer, STS-VC-0057',
         mixed.status + ' ' + mixed.code);
    const sessionAgain = w.sessionOf(otherOriginWho);
    if (sessionAgain) {
      await w.inRealm(function () {
        m.authn.endSessionById(sessionAgain.id, 'the test, tidying up');
      });
    }

    const clearWho = w.browser();
    const clearOne = await w.start(clearWho, w.pendingSignIn());
    const unencrypted = await w.answerDcApi(clearWho, clearOne,
      w.presentSdJwt(issued.credential, holder, clearOne.dcPayload.nonce,
                     dcAud), { encrypt: false });
    note(unencrypted.status === 400 && unencrypted.code === 'STS-VC-0073' &&
         !w.sessionOf(clearWho),
         '4d. an unencrypted answer to a dc_api.jwt request is refused, ' +
         'STS-VC-0073 — a response mode is not the wallet\'s to choose',
         unencrypted.status + ' ' + unencrypted.code);
    const badProtocolWho = w.browser();
    const badProtocolOne = await w.start(badProtocolWho, w.pendingSignIn());
    const badProtocol = await w.answerDcApi(badProtocolWho, badProtocolOne,
      w.presentSdJwt(issued.credential, holder,
                     badProtocolOne.dcPayload.nonce, dcAud),
      { protocol: 'openid4vp-v1-unsigned' });
    note(badProtocol.status === 400 && badProtocol.code === 'STS-VC-0073',
         '4e. an answer naming another exchange protocol is refused, ' +
         'STS-VC-0073', badProtocol.status + ' ' + badProtocol.code);

    // ==================================================================
    // 5. THE NO-SCRIPT PATH
    // ==================================================================
    const noScriptWho = w.browser();
    const noScriptOne = await w.start(noScriptWho, w.pendingSignIn());
    const empty = await w.answerDcApi(noScriptWho, noScriptOne, '',
                                      { noResponse: true });
    note(empty.status === 400 && empty.code === 'STS-VC-0081' &&
         /id="wallet-dcapi-noscript"/.test(empty.text) &&
         /id="wallet-open"/.test(empty.text),
         '5a. the form submitted with no answer — the script did not run — ' +
         'says so and offers the same-device link, STS-VC-0081',
         empty.status + ' ' + empty.code);
    const sameDevice = /id="wallet-open" href="([^"]+)"/.exec(empty.text);
    const sameDeviceUrl = sameDevice ? w.unescapeHtml(sameDevice[1]) : '';
    note(/request_uri=/.test(sameDeviceUrl) && /client_id=/.test(
           sameDeviceUrl),
         '5b. and that link is the wallet\'s own address carrying the ' +
         'signed request by reference, which needs no script at all',
         sameDeviceUrl.slice(0, 90));

    // ==================================================================
    // 6. THE UNENCRYPTED RESPONSE MODE
    // ==================================================================
    await w.inRealm(function () {
      m.config.setOverride('oid4vp.signInDcApiResponseMode', 'dc_api');
    });
    const plainWho = w.browser();
    const plainOne = await w.start(plainWho, w.pendingSignIn());
    note(plainOne.dcPayload.response_mode === 'dc_api' &&
         !(plainOne.dcPayload.client_metadata || {}).jwks,
         '6a. oid4vp.signInDcApiResponseMode dc_api asks for an answer in ' +
         'the clear, and publishes no encryption key',
         plainOne.dcPayload.response_mode);
    const plain = await w.answerDcApi(plainWho, plainOne,
      w.presentSdJwt(issued.credential, holder, plainOne.dcPayload.nonce,
                     dcAud));
    note(plain.status === 303 && w.sessionOf(plainWho),
         '6b. and that answer signs the browser in', plain.status + ' ' +
         plain.code);
    const plainSession = w.sessionOf(plainWho);
    if (plainSession) {
      await w.inRealm(function () {
        m.authn.endSessionById(plainSession.id, 'the test, tidying up');
      });
    }
    await w.inRealm(function () {
      m.config.clearOverride('oid4vp.signInDcApiResponseMode');
    });

    // AND THE OTHER FORMATS COME BACK THIS WAY TOO.
    for (const format of ['jwt_vc_json', 'ldp_vc']) {
      const fmtHolder = w.holderKey();
      const fmtCred = await w.issue('dc-alice', fmtHolder,
                                    { format: format });
      const fmtWho = w.browser();
      const fmtOne = await w.start(fmtWho, w.pendingSignIn());
      const fmtPresentation = await w.present(format, fmtCred.credential,
        fmtHolder, fmtOne.dcPayload.nonce, dcAud);
      const fmtAnswer = await w.answerDcApi(fmtWho, fmtOne, fmtPresentation,
                                            { format: format });
      note(fmtAnswer.status === 303 && w.sessionOf(fmtWho),
           '6c[' + format + ']. it answers the Digital Credentials API too, ' +
           'with origin:<origin> as its audience or domain',
           fmtAnswer.status + ' ' + fmtAnswer.code);
      const fmtSession = w.sessionOf(fmtWho);
      if (fmtSession) {
        await w.inRealm(function () {
          m.authn.endSessionById(fmtSession.id, 'the test, tidying up');
        });
      }
    }
  }
}

async function run(t) {
  log.debug("Entering run().");
  kit.inAChild(t, childMain, 'oid4vp-dc-api');
  log.debug("Leaving run().");
}

module.exports = {
  name: 'oid4vp sign-in over the Digital Credentials API',
  describe: 'a signed openid4vp-v1-signed request naming this origin, an ' +
            'encrypted answer posted by the page that asked, and every way ' +
            'one is refused',
  run: run
};

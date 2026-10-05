// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: saml_artifact_and_simplesign.js
//
// ===========================================================================
// WHO MAY RESOLVE AN ARTIFACT, AND THE HTTP-POST-SimpleSign BINDING
// (2026-09-17, #37 follow-up).
//
//   B. ARTIFACT RESOLUTION AUTHENTICATES ITS CALLER. On /saml2/ars: an
//      ArtifactResolve signed by the service provider's registered key (EC)
//      resolves; unsigned where signatures are required (STS-SAML-0077),
//      signed by another key (STS-SAML-0061), SHA-1 (STS-SAML-0073) or from
//      a DIFFERENT service provider than the artifact's (STS-SAML-0078) is
//      refused and the artifact is NOT spent; the service provider's
//      registered certificate presented as the TLS client certificate
//      authenticates an unsigned request, and another certificate does not;
//      expired metadata refuses (STS-SAML-0074); development accepts an
//      unsigned caller by default. On /saml11/responder: the same for a
//      SAML 1.1 <samlp:Request>, and a responder path naming another
//      relying party is refused (STS-SAML-0078).
//   B1b. A RESOLVER ANSWERS ONLY FOR ITS OWN SourceID (#160). An artifact
//      minted under a per-application entityID, presented at the unscoped
//      /saml2/ars or at another service provider's resolver, is answered
//      with Success and no message (STS-SAML-0098) and NOT spent; its own
//      resolver then resolves it under an envelope naming the same entity.
//      With saml2.perApplicationEntityId off, the unscoped resolver answers.
//      Every refusal above and below is that same EMPTY response (section
//      3.5.3; saml-bindings-1.1 4.1.1.6 for the responder) — never Requester —
//      and SAML 1.1's responder holds the same SourceID rule.
//   C. HTTP-POST-SimpleSign. A signed AuthnRequest, LogoutRequest and
//      LogoutResponse over it are verified (and tampered ones refused); a
//      Response is SENT over it to a service provider whose consumed
//      AssertionConsumerService declares it — form fields SigAlg and
//      Signature that verify over the SimpleSign octets, and no enveloped
//      Response signature; a request asking for it as ProtocolBinding is
//      answered on it; and the identity provider's metadata advertises it
//      for SingleSignOnService and SingleLogoutService.
//
// WHY IN PROCESS: the artifact store is filled directly (as
// `tests/cluster_single_use_protocols.js` does), a TLS client certificate is
// a stub on the request's socket, and the settings change mid-run.
// ===========================================================================

delete process.env.CONFIG_FILE;

const kit = require('./tools/saml_signing_kit');

const log = require('bunyan').createLogger({
  name: 'saml_artifact_and_simplesign',
  level: process.env.LOG_LEVEL || 'info' });

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_SAMLP11 = 'urn:oasis:names:tc:SAML:1.0:protocol';
const NS_MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/';
const B_SIMPLESIGN =
  'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign';

function soap(inner) {
  log.debug("Entering soap().");
  log.debug("Leaving soap().");
  return '<soap:Envelope xmlns:soap="' + NS_SOAP + '"><soap:Body>' + inner +
    '</soap:Body></soap:Envelope>';
}

function artifactResolve(issuer, artifact, id) {
  log.debug("Entering artifactResolve().");
  log.debug("Leaving artifactResolve().");
  return '<samlp:ArtifactResolve xmlns:samlp="' + NS_SAMLP + '" ' +
    'xmlns:saml="' + NS_SAML + '" ID="' + id + '" Version="2.0" ' +
    'IssueInstant="' + new Date().toISOString() + '">' +
    (issuer ? '<saml:Issuer>' + issuer + '</saml:Issuer>' : '') +
    '<samlp:Artifact>' + artifact + '</samlp:Artifact>' +
    '</samlp:ArtifactResolve>';
}

function request11(artifact, id) {
  log.debug("Entering request11().");
  log.debug("Leaving request11().");
  return '<samlp:Request xmlns:samlp="' + NS_SAMLP11 + '" MajorVersion="1" ' +
    'MinorVersion="1" RequestID="' + id + '" IssueInstant="' +
    new Date().toISOString() + '"><samlp:AssertionArtifact>' + artifact +
    '</samlp:AssertionArtifact></samlp:Request>';
}

async function run(t) {
  log.debug("Entering run().");
  const config = require('../common/config');
  const errorCodes = require('../common/error_codes');
  const stsCrypto = require('../common/crypto');
  const helpers = require('../common/helpers');
  const realms = require('../common/realms');
  const app = require('../common/app');
  require('../ldap/ldap_server');
  const applications = require('../common/applications');
  const saml2sso = require('../saml/saml2_sso');
  const saml11sso = require('../saml/saml11_sso');
  const spMetadata = require('../saml/sp_metadata');
  const requestSignature = require('../saml/request_signature');
  saml2sso.registerRoutes(app);
  saml11sso.registerRoutes(app);
  const ars = kit.handlerFor(app, 'post', '/saml2/ars');
  const responder = kit.handlerFor(app, 'post', '/saml11/responder');
  const scopedResponder = kit.handlerFor(app, 'post',
                                         '/saml11/responder/:rp');
  const ssoPost = kit.handlerFor(app, 'post', '/saml2/sso');
  const sso = kit.handlerFor(app, 'get', '/saml2/sso');
  const sloPost = kit.handlerFor(app, 'post', '/saml2/slo');
  const direct = new saml2sso.Saml2Sso(saml2sso.Saml2Sso.defaultDeps());
  const artifacts2 = realms.handleFor('saml2_sso.artifacts');
  const artifacts11 = realms.handleFor('saml11_sso.artifacts');
  const stamp = String(Date.now());
  const created = [];
  const family = function (name) {
    log.debug("Entering family().");
    log.debug("Leaving family().");
    return kit.FAMILIES.filter(function (row) {
      return row[0] === name;
    })[0];
  };
  const ec = kit.keyFor(family('ecdsa-p256-sha256'));
  const other = kit.keyFor(family('ed25519'));
  const sha1 = kit.keyFor(['sha1'].concat(kit.SHA1.ecdsa));
  const codeOf = function (res) {
    log.debug("Entering codeOf().");
    log.debug("Leaving codeOf().");
    return errorCodes.codeOf(res) || '';
  };
  const fieldsOf = function (id) {
    log.debug("Entering fieldsOf().");
    log.debug("Leaving fieldsOf().");
    return (applications.get(id) || {}).fields || {};
  };
  const newParty = function (name, kind, certs) {
    log.debug("Entering newParty().");
    const id = 'https://' + name + '-' + stamp + '.art.test/saml';
    const made = applications.createApplication({
      identifier: id, kind: kind, protocol: 'SAML 2.0',
      fields: { samlEntityId: id } });
    t.check(made.ok, 'created ' + name, JSON.stringify(made.errors || ''));
    (certs || []).forEach(function (b64) {
      applications.updateApplication(id, {
        attribute: 'samlSigningCertificate', mode: 'add', value: b64 });
    });
    created.push(id);
    log.debug("Leaving newParty().");
    return id;
  };
  const held2 = function (sp, marker) {
    log.debug("Entering held2().");
    log.debug("Leaving held2().");
    return { expires: Date.now() + 300000, spEntityId: sp,
             issuer: 'https://idp.test/saml2/metadata',
             xml: '<samlp:Response xmlns:samlp="' + NS_SAMLP + '" ID="' +
                  marker + '"/>' };
  };
  const resolve2 = async function (body, socket) {
    log.debug("Entering resolve2().");
    const res = kit.fakeRes();
    const req = kit.fakeReq('POST', '/saml2/ars', {}, '', body,
                            socket ? { socket: socket } : {});
    ars(req, res);
    await res.done;
    // RESOLVED is Success WITH the message; a refusal is the EMPTY response
    // saml-core-2.0-os 3.5.3 requires since #160 — Success, nothing
    // embedded, no StatusMessage.
    res.success = /status:Success/.test(res.body) &&
                  /<samlp:Response\b/.test(res.body);
    res.empty = /status:Success/.test(res.body) &&
                !/<samlp:Response\b/.test(res.body) &&
                !/StatusMessage/.test(res.body);
    log.debug("Leaving resolve2().");
    return res;
  };
  const tlsSocket = function (cert) {
    log.debug("Entering tlsSocket().");
    log.debug("Leaving tlsSocket().");
    return {
      authorized: false,
      getPeerCertificate: function () {
        log.debug("Entering getPeerCertificate().");
        log.debug("Leaving getPeerCertificate().");
        return { raw: cert.der };
      }
    };
  };

  try {
    // -----------------------------------------------------------------------
    t.log.info('B1. SAML 2.0 artifact resolution');
    // -----------------------------------------------------------------------
    const sp = newParty('ars', 'saml2-service-provider', [ec.cert.b64]);
    const stranger = newParty('ars-other', 'saml2-service-provider',
                              [other.cert.b64]);
    const required = { 'saml2.requireSignedAuthnRequests': 'on' };
    const sign = function (xml, key) {
      log.debug("Entering sign().");
      log.debug("Leaving sign().");
      return kit.signEnveloped(stsCrypto, xml, key);
    };

    artifacts2.restore(realms.DEFAULT_ID, 'ART-UNSIGNED', held2(sp, '_m1'));
    const unsigned = await kit.withSettings(config, required, function () {
      return resolve2(soap(artifactResolve(sp, 'ART-UNSIGNED', '_a1')));
    });
    t.check(unsigned.empty && codeOf(unsigned) === 'STS-SAML-0077',
            'an UNSIGNED ArtifactResolve where signatures are required is ' +
            'answered with the EMPTY response (Success, nothing embedded, no ' +
            'StatusMessage — section 3.5.3), STS-SAML-0077',
            codeOf(unsigned) + ' ' + unsigned.body.slice(0, 200));
    const wrongKey = await resolve2(soap(sign(
      artifactResolve(sp, 'ART-UNSIGNED', '_a2'), other)));
    t.check(!wrongKey.success && codeOf(wrongKey) === 'STS-SAML-0061',
            'one signed by ANOTHER key is refused, STS-SAML-0061',
            codeOf(wrongKey));
    const sha1Signed = await resolve2(soap(sign(
      artifactResolve(sp, 'ART-UNSIGNED', '_a3'), sha1)));
    t.check(!sha1Signed.success && codeOf(sha1Signed) === 'STS-SAML-0073',
            'one signed with SHA-1 is refused, STS-SAML-0073',
            codeOf(sha1Signed));
    const wrongSp = await resolve2(soap(sign(
      artifactResolve(stranger, 'ART-UNSIGNED', '_a4'), other)));
    t.check(wrongSp.empty && codeOf(wrongSp) === 'STS-SAML-0078',
            'a validly signed request from a DIFFERENT service provider is ' +
            'refused, STS-SAML-0078', codeOf(wrongSp));
    const noIssuer = await resolve2(soap(artifactResolve('', 'ART-UNSIGNED',
                                                         '_a5')));
    t.equal(codeOf(noIssuer), 'STS-SAML-0078',
            'and so is one naming no Issuer');
    const good = await kit.withSettings(config, required, function () {
      return resolve2(soap(sign(artifactResolve(sp, 'ART-UNSIGNED', '_a6'),
                                ec)));
    });
    t.check(good.success && /_m1/.test(good.body),
            'NONE OF THOSE SPENT IT: the service provider\'s own EC-signed ' +
            'ArtifactResolve then resolves it', good.body.slice(0, 200));
    const again = await resolve2(soap(sign(
      artifactResolve(sp, 'ART-UNSIGNED', '_a7'), ec)));
    t.check(again.empty && codeOf(again) === 'STS-SAML-0018',
            'and it is one-shot after that: the empty response', codeOf(again));
    const neverMinted = await resolve2(soap(sign(
      artifactResolve(sp, 'ART-NEVER-' + stamp, '_a7'), ec)));
    const shape = function (body) {
      log.debug("Entering shape().");
      log.debug("Leaving shape().");
      return String(body).replace(/ID="[^"]*"/g, '')
                         .replace(/IssueInstant="[^"]*"/g, '')
                         .replace(/InResponseTo="[^"]*"/g, '');
    };
    t.check(neverMinted.empty &&
            shape(neverMinted.body) === shape(again.body) &&
            shape(unsigned.body) === shape(again.body) &&
            shape(wrongSp.body) === shape(again.body),
            'a refused caller, a replay and an artifact never minted get the ' +
            'SAME answer — no oracle for whether an artifact exists',
            neverMinted.body.slice(0, 300));

    artifacts2.restore(realms.DEFAULT_ID, 'ART-SHA1', held2(sp, '_m2'));
    applications.updateApplication(sp, { attribute: 'samlSigningCertificate',
      mode: 'add', value: sha1.cert.b64 });
    const sha1On = await kit.withSettings(config,
      { 'saml.allowSha1Signatures': true },
      function () {
        return resolve2(soap(sign(artifactResolve(sp, 'ART-SHA1', '_b1'),
                                  sha1)));
      });
    t.check(sha1On.success, 'with saml.allowSha1Signatures on, a SHA-1 ' +
            'ArtifactResolve resolves', codeOf(sha1On));

    artifacts2.restore(realms.DEFAULT_ID, 'ART-TLS', held2(sp, '_m3'));
    const foreignTls = await kit.withSettings(config, required, function () {
      return resolve2(soap(artifactResolve(sp, 'ART-TLS', '_c1')),
                      tlsSocket(other.cert));
    });
    t.equal(codeOf(foreignTls), 'STS-SAML-0077',
            'a TLS client certificate that is NOT the service provider\'s ' +
            'authenticates nothing');
    const mappedTls = await kit.withSettings(config, required, function () {
      return resolve2(soap(artifactResolve(sp, 'ART-TLS', '_c2')),
                      tlsSocket(ec.cert));
    });
    t.check(mappedTls.success && /_m3/.test(mappedTls.body),
            'its REGISTERED certificate as the TLS client certificate ' +
            'authenticates an unsigned ArtifactResolve',
            codeOf(mappedTls) + ' ' + mappedTls.body.slice(0, 200));

    artifacts2.restore(realms.DEFAULT_ID, 'ART-DEV', held2(sp, '_m4'));
    const devUnsigned = await resolve2(soap(artifactResolve(sp, 'ART-DEV',
                                                            '_d1')));
    t.check(devUnsigned.success, 'development, by default: an unsigned ' +
            'caller is accepted (and recorded)', codeOf(devUnsigned));
    artifacts2.restore(realms.DEFAULT_ID, 'ART-PROD', held2(sp, '_m5'));
    const prodUnsigned = await kit.withSettings(config,
      { 'global.mode': 'product' },
      function () {
        return resolve2(soap(artifactResolve(sp, 'ART-PROD', '_d2')));
      });
    t.equal(codeOf(prodUnsigned), 'STS-SAML-0077',
            'product, by default: an unsigned caller is refused');

    const spOld = newParty('ars-expired', 'saml2-service-provider',
                           [ec.cert.b64]);
    spMetadata.upload(spOld, '<md:EntityDescriptor xmlns:md="' + NS_MD +
      '" entityID="' + spOld + '" validUntil="' +
      new Date(Date.now() + 3600000).toISOString() + '">' +
      '<md:SPSSODescriptor protocolSupportEnumeration="' + NS_SAMLP + '">' +
      '<md:AssertionConsumerService ' +
      'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" ' +
      'Location="https://old.test/acs" index="0"/></md:SPSSODescriptor>' +
      '</md:EntityDescriptor>');
    applications.replaceSamlMetadataFields(spOld, {
      samlSpMetadataValidUntil: new Date(Date.now() - 1000).toISOString()
    }, { how: 'test' });
    artifacts2.restore(realms.DEFAULT_ID, 'ART-OLD', held2(spOld, '_m6'));
    const expired = await resolve2(soap(sign(
      artifactResolve(spOld, 'ART-OLD', '_e1'), ec)));
    t.equal(codeOf(expired), 'STS-SAML-0074',
            'a service provider whose metadata EXPIRED is refused');

    // -----------------------------------------------------------------------
    t.log.info('B1b. a resolver answers only for its own SourceID (#160)');
    // -----------------------------------------------------------------------
    const scopedArs = kit.handlerFor(app, 'post', '/saml2/ars/:sp');
    const resolveScoped = async function (segment, body) {
      log.debug("Entering resolveScoped().");
      const res = kit.fakeRes();
      scopedArs(kit.fakeReq('POST', '/saml2/ars/' +
                            encodeURIComponent(segment), {}, '', body,
                            { params: { sp: segment } }), res);
      await res.done;
      // RESOLVED is Success WITH the message; a refusal is the EMPTY response
      // saml-core-2.0-os 3.5.3 requires since #160 — Success, nothing
      // embedded, no StatusMessage.
      res.success = /status:Success/.test(res.body) &&
                    /<samlp:Response\b/.test(res.body);
      res.empty = /status:Success/.test(res.body) &&
                  !/<samlp:Response\b/.test(res.body) &&
                  !/StatusMessage/.test(res.body);
      log.debug("Leaving resolveScoped().");
      return res;
    };
    const ownIdp = direct.idpEntityIdFor(sp);
    t.check(ownIdp !== direct.idpEntityIdFor(''),
            'with saml2.perApplicationEntityId on (the default) the service ' +
            'provider has an entityID of its own', ownIdp);
    const perApp = direct['mintArtifact'](ownIdp, 0);
    artifacts2.restore(realms.DEFAULT_ID, perApp,
                       Object.assign(held2(sp, '_m7'), { issuer: ownIdp }));
    const atUnscoped = await resolve2(soap(artifactResolve(sp, perApp,
                                                           '_f1')));
    t.check(atUnscoped.empty && !/_m7/.test(atUnscoped.body) &&
            codeOf(atUnscoped) === 'STS-SAML-0098',
            'an artifact whose SourceID is a per-application entity, ' +
            'presented at the UNSCOPED /saml2/ars, is answered with Success ' +
            'and no message, STS-SAML-0098',
            codeOf(atUnscoped) + ' ' + atUnscoped.body.slice(0, 300));
    const otherSlug = direct.slugOf(stranger);
    const atStranger = await resolveScoped(otherSlug,
      soap(artifactResolve(sp, perApp, '_f2')));
    t.check(atStranger.empty && !/_m7/.test(atStranger.body) &&
            codeOf(atStranger) === 'STS-SAML-0098',
            'and so is one presented at ANOTHER service provider\'s resolver',
            codeOf(atStranger));
    const atOwn = await resolveScoped(direct.slugOf(sp),
      soap(artifactResolve(sp, perApp, '_f3')));
    t.check(atOwn.success && /_m7/.test(atOwn.body) &&
            atOwn.body.indexOf('<saml:Issuer>' + ownIdp + '</saml:Issuer>') >=
              0,
            'NEITHER SPENT IT: its own resolver then resolves it, under an ' +
            'ArtifactResponse naming the same entity',
            codeOf(atOwn) + ' ' + atOwn.body.slice(0, 300));
    await kit.withSettings(config,
      { 'saml2.perApplicationEntityId': false },
      async function () {
        log.debug("Entering the shared-entityID control.");
        const shared = direct['mintArtifact'](direct.idpEntityIdFor(sp), 0);
        artifacts2.restore(realms.DEFAULT_ID, shared, held2(sp, '_m8'));
        const atShared = await resolve2(soap(artifactResolve(sp, shared,
                                                             '_f4')));
        t.check(atShared.success && /_m8/.test(atShared.body),
                'with it off, every service provider shares the one ' +
                'entityID and the unscoped resolver answers (the control)',
                codeOf(atShared));
        log.debug("Leaving the shared-entityID control.");
      });

    // -----------------------------------------------------------------------
    t.log.info('B2. the SAML 1.1 responder');
    // -----------------------------------------------------------------------
    const rp = newParty('rp11', saml11sso.RP_KIND, [ec.cert.b64]);
    const rpOther = newParty('rp11-other', saml11sso.RP_KIND, []);
    const held11 = function (marker) {
      log.debug("Entering held11().");
      log.debug("Leaving held11().");
      return { expires: Date.now() + 300000, rpId: rp,
               assertion: '<saml:Assertion ' +
                 'xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" ' +
                 'AssertionID="' + marker + '"/>' };
    };
    const resolve11 = async function (body, segment, socket) {
      log.debug("Entering resolve11().");
      const res = kit.fakeRes();
      const req = kit.fakeReq('POST', '/saml11/responder', {}, '', body,
                              socket ? { socket: socket } : {});
      if (segment) {
        req.params = { rp: segment };
        scopedResponder(req, res);
      } else {
        responder(req, res);
      }
      await res.done;
      // RESOLVED is Success WITH an assertion; a refusal is the response
      // with no assertions saml-bindings-1.1 4.1.1.6 requires (#160).
      res.success = /samlp:Success/.test(res.body) &&
                    /<saml:Assertion\b/.test(res.body);
      res.empty = /samlp:Success/.test(res.body) &&
                  !/<saml:Assertion\b/.test(res.body) &&
                  !/StatusMessage/.test(res.body);
      log.debug("Leaving resolve11().");
      return res;
    };
    artifacts11.restore(realms.DEFAULT_ID, 'ART11-A', held11('_s1'));
    const unsigned11 = await kit.withSettings(config, required, function () {
      return resolve11(soap(request11('ART11-A', '_q1')));
    });
    t.check(unsigned11.empty && codeOf(unsigned11) === 'STS-SAML-0077',
            'SAML 1.1: an unsigned artifact Request where signatures are ' +
            'required is refused, STS-SAML-0077', codeOf(unsigned11));
    const elsewhere = await resolve11(soap(kit.signEnveloped(stsCrypto,
      request11('ART11-A', '_q2'), ec)), saml2sso.slugOf(rpOther));
    t.check(elsewhere.empty && codeOf(elsewhere) === 'STS-SAML-0078',
            'SAML 1.1: at ANOTHER relying party\'s responder it is refused, ' +
            'STS-SAML-0078', codeOf(elsewhere));
    const wrong11 = await resolve11(soap(kit.signEnveloped(stsCrypto,
      request11('ART11-A', '_q3'), other)));
    t.equal(codeOf(wrong11), 'STS-SAML-0061',
            'SAML 1.1: a Request signed by another key is refused');
    const good11 = await kit.withSettings(config, required, function () {
      return resolve11(soap(kit.signEnveloped(stsCrypto,
        request11('ART11-A', '_q4'), ec)));
    });
    t.check(good11.success && /_s1/.test(good11.body),
            'SAML 1.1: the relying party\'s own EC-signed Request resolves ' +
            'the artifact none of those spent', good11.body.slice(0, 200));
    artifacts11.restore(realms.DEFAULT_ID, 'ART11-B', held11('_s2'));
    const tls11 = await kit.withSettings(config, required, function () {
      return resolve11(soap(request11('ART11-B', '_q5')), '',
                       tlsSocket(ec.cert));
    });
    t.check(tls11.success, 'SAML 1.1: the registered certificate as the TLS ' +
            'client certificate authenticates an unsigned Request',
            codeOf(tls11));
    artifacts11.restore(realms.DEFAULT_ID, 'ART11-C', held11('_s3'));
    const dev11 = await resolve11(soap(request11('ART11-C', '_q6')));
    t.check(dev11.success, 'SAML 1.1: development accepts an unsigned ' +
            'caller by default', codeOf(dev11));
    const again11 = await resolve11(soap(request11('ART11-C', '_q6b')));
    t.check(again11.empty && codeOf(again11) === 'STS-SAML-0037',
            'SAML 1.1: a replay gets Success with no assertion ' +
            '(saml-bindings-1.1 4.1.1.6), STS-SAML-0037', codeOf(again11));

    // A RESPONDER ANSWERS ONLY FOR ITS OWN SourceID (#160), SAML 1.1.
    const direct11 = new saml11sso.Saml11Sso(
      saml11sso.Saml11Sso.defaultDeps());
    const own11 = direct11.providerIdFor(rp);
    t.check(own11 !== direct11.providerIdFor(''),
            'SAML 1.1: with saml11.perApplicationProviderId on (the default) ' +
            'the relying party has a providerID of its own', own11);
    const perApp11 = direct11['mintArtifact'](own11);
    artifacts11.restore(realms.DEFAULT_ID, perApp11, held11('_s6'));
    const unscoped11 = await resolve11(soap(request11(perApp11, '_q6c')));
    t.check(unscoped11.empty && codeOf(unscoped11) === 'STS-SAML-0098',
            'SAML 1.1: an artifact under a per-relying-party providerID at ' +
            'the UNSCOPED responder is answered with no assertion, ' +
            'STS-SAML-0098', codeOf(unscoped11));
    const own11Res = await resolve11(soap(request11(perApp11, '_q6d')),
                                     saml2sso.slugOf(rp));
    t.check(own11Res.success && /_s6/.test(own11Res.body),
            'SAML 1.1: NOT SPENT — its own responder then resolves it',
            codeOf(own11Res) + ' ' + own11Res.body.slice(0, 200));

    // -----------------------------------------------------------------------
    // A RELYING PARTY WITH TWO NAMES, which is the ordinary case for anything
    // that is not this service's own mock service provider and was refused
    // outright until 2026-09-18.
    //
    // `relyingPartyFor()` takes the audience from the `providerId` PARAMETER
    // in preference to the `{rp}` path segment, so a caller that does what
    // this service's own error message tells it to — *"Send providerId, or
    // use /saml11/sso/{rp}"* — and does BOTH is minted an artifact whose
    // `rpId` is its entity ID while its responder is reached at the segment.
    // Every one of those artifacts was refused STS-SAML-0078, and nothing
    // here caught it because every fixture above sets `rpId` alone: with no
    // `scopedId` the comparison is the one it always was, which is exactly
    // why those cases kept passing through the defect.
    //
    // So the artifact records BOTH names and the segment has to match one.
    // Asserted in both directions, because an exemption that only ever says
    // yes is not a check: the segment it was minted at resolves it, and a
    // THIRD party's responder is still refused.
    // -----------------------------------------------------------------------
    const heldTwoNames = function (marker) {
      log.debug("Entering heldTwoNames().");
      const one = held11(marker);
      // What `deliver()` stashes: the audience from providerId, and the path
      // segment the browser actually arrived on.
      one.rpId = 'https://sp.example.com/saml/sp';
      one.scopedId = rp;
      log.debug("Leaving heldTwoNames().");
      return one;
    };
    artifacts11.restore(realms.DEFAULT_ID, 'ART11-D', heldTwoNames('_s4'));
    const twoNames = await resolve11(soap(request11('ART11-D', '_q7')),
                                     saml2sso.slugOf(rp));
    t.check(twoNames.success && /_s4/.test(twoNames.body),
            'SAML 1.1: an artifact whose audience is a providerId resolves ' +
            'at the responder of the path segment it was minted on',
            codeOf(twoNames) + ' ' + twoNames.body.slice(0, 120));
    artifacts11.restore(realms.DEFAULT_ID, 'ART11-E', heldTwoNames('_s5'));
    const twoNamesElsewhere = await resolve11(
      soap(request11('ART11-E', '_q8')), saml2sso.slugOf(rpOther));
    t.check(twoNamesElsewhere.empty &&
            codeOf(twoNamesElsewhere) === 'STS-SAML-0078',
            'SAML 1.1: and at a THIRD party\'s responder it is still ' +
            'refused, STS-SAML-0078', codeOf(twoNamesElsewhere));

    // -----------------------------------------------------------------------
    t.log.info('C. HTTP-POST-SimpleSign');
    // -----------------------------------------------------------------------
    const ssp = newParty('simplesign', 'saml2-service-provider',
                         [ec.cert.b64]);
    // THE SIGNED OCTETS ARE THE RAW XML (the SimpleSign binding, section
    // 2.5, step 2) — `overBase64` signs the base64 text instead, which is
    // what this service did until #189 and what no other implementation
    // verifies.
    const simpleForm = function (field, xml, relayState, key, tamper,
                                 overBase64) {
      log.debug("Entering simpleForm().");
      const value = Buffer.from(xml, 'utf8').toString('base64');
      const octets = field + '=' + (overBase64 ? value : xml) +
        (relayState !== undefined ? '&RelayState=' + relayState : '') +
        '&SigAlg=' + key.uri;
      const form = new URLSearchParams();
      form.set(field, value);
      if (relayState !== undefined) {
        form.set('RelayState', tamper ? relayState + 'X' : relayState);
      }
      form.set('SigAlg', key.uri);
      form.set('Signature', kit.signatureValue(key, Buffer.from(octets,
        'utf8')).toString('base64'));
      log.debug("Leaving simpleForm().");
      return form.toString();
    };
    const postSimple = function (handler, path, body) {
      log.debug("Entering postSimple().");
      const res = kit.fakeRes();
      handler(kit.fakeReq('POST', path, {}, '', body), res);
      if (res.statusCode === 303 && /\?rid=/.test(res.location)) {
        const rid = res.location.split('?rid=')[1];
        const next = kit.fakeRes();
        sso(kit.fakeReq('GET', '/saml2/sso',
                        { rid: decodeURIComponent(rid) }, 'rid=' + rid),
            next);
        log.debug("Leaving postSimple(). Followed the hold.");
        return next;
      }
      log.debug("Leaving postSimple().");
      return res;
    };
    const authn = '<samlp:AuthnRequest xmlns:samlp="' + NS_SAMLP + '" ' +
      'xmlns:saml="' + NS_SAML + '" ID="_ss1" Version="2.0" IssueInstant="' +
      new Date().toISOString() + '" Destination="https://idp.test/saml2/' +
      'sso"><saml:Issuer>' + ssp + '</saml:Issuer>' +
      '</samlp:AuthnRequest>';
    const simple = postSimple(ssoPost, '/saml2/sso',
                              simpleForm('SAMLRequest', authn, 'r/s+1', ec));
    t.check(simple.statusCode === 303 && /authn/.test(simple.location) &&
            String(fieldsOf(ssp).samlAuthnRequestVerification)
              .indexOf('verified simplesign ' + ec.uri) === 0,
            'a SimpleSign AuthnRequest is VERIFIED (over the form values, ' +
            'unencoded) and goes on to the sign-in screen',
            simple.statusCode + ' ' + codeOf(simple) + ' ' +
            fieldsOf(ssp).samlAuthnRequestVerification);
    const tampered = postSimple(ssoPost, '/saml2/sso',
      simpleForm('SAMLRequest', authn, 'r/s+1', ec, true));
    t.check(tampered.statusCode === 403 &&
            codeOf(tampered) === 'STS-SAML-0061',
            'a SimpleSign AuthnRequest whose RelayState was changed is ' +
            'REFUSED, STS-SAML-0061',
            tampered.statusCode + ' ' + codeOf(tampered));
    const forged = postSimple(ssoPost, '/saml2/sso',
      simpleForm('SAMLRequest', authn, undefined, other));
    t.equal(codeOf(forged), 'STS-SAML-0061',
            'and one signed by another key is refused');
    const overBase64 = postSimple(ssoPost, '/saml2/sso',
      simpleForm('SAMLRequest', authn, 'r/s+1', ec, false, true));
    t.check(overBase64.statusCode === 403 &&
            codeOf(overBase64) === 'STS-SAML-0061',
            'a SimpleSign AuthnRequest signed over the BASE64 text rather ' +
            'than the raw XML is REFUSED, STS-SAML-0061 (#189)',
            overBase64.statusCode + ' ' + codeOf(overBase64));
    const repeated = requestSignature.simpleSignOctets(
      { SAMLRequest: 'x', SigAlg: ['a', 'b'], Signature: 'y' },
      'SAMLRequest');
    t.equal(repeated, '', 'a repeated SimpleSign form control makes the ' +
            'octets uncheckable');

    const logout = '<samlp:LogoutRequest xmlns:samlp="' + NS_SAMLP + '" ' +
      'xmlns:saml="' + NS_SAML + '" ID="_sl1" Version="2.0" IssueInstant="' +
      new Date().toISOString() + '" Destination="https://idp.test/saml2/' +
      'slo"><saml:Issuer>' + ssp + '</saml:Issuer>' +
      '<saml:NameID>alice</saml:NameID></samlp:LogoutRequest>';
    applications.updateApplication(ssp, {
      attribute: 'samlSingleLogoutService', mode: 'add',
      value: 'https://simplesign.test/slo' });
    const sloOk = postSimple(sloPost, '/saml2/slo',
                             simpleForm('SAMLRequest', logout, 'lo', ec));
    t.check(sloOk.statusCode !== 403,
            'a SimpleSign LogoutRequest is accepted',
            sloOk.statusCode + ' ' + codeOf(sloOk));
    const sloBad = postSimple(sloPost, '/saml2/slo',
      simpleForm('SAMLRequest', logout, 'lo', ec, true));
    t.check(sloBad.statusCode === 403 && codeOf(sloBad) === 'STS-SAML-0061',
            'a tampered SimpleSign LogoutRequest is refused',
            sloBad.statusCode + ' ' + codeOf(sloBad));
    const answer = '<samlp:LogoutResponse xmlns:samlp="' + NS_SAMLP + '" ' +
      'xmlns:saml="' + NS_SAML + '" ID="_sr1" Version="2.0" IssueInstant="' +
      new Date().toISOString() + '"><saml:Issuer>' + ssp + '</saml:Issuer>' +
      '<samlp:Status><samlp:StatusCode ' +
      'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
      '</samlp:LogoutResponse>';
    const lrOk = postSimple(sloPost, '/saml2/slo',
                            simpleForm('SAMLResponse', answer, undefined, ec));
    t.check(lrOk.statusCode === 200 && /verified/.test(lrOk.body),
            'a SimpleSign LogoutResponse is verified',
            lrOk.statusCode + ' ' + codeOf(lrOk));
    const lrBad = postSimple(sloPost, '/saml2/slo',
                             simpleForm('SAMLResponse', answer, undefined,
                                        other));
    t.equal(codeOf(lrBad), 'STS-SAML-0061',
            'and one signed by another key is refused');

    // The Response, sent on SimpleSign.
    const acsSp = newParty('simplesign-acs', 'saml2-service-provider', []);
    const consumed = spMetadata.upload(acsSp, '<md:EntityDescriptor ' +
      'xmlns:md="' + NS_MD + '" entityID="' + acsSp + '">' +
      '<md:SPSSODescriptor protocolSupportEnumeration="' + NS_SAMLP + '">' +
      '<md:AssertionConsumerService Binding="' + B_SIMPLESIGN + '" ' +
      'Location="https://simplesign.test/acs" index="0"/>' +
      '</md:SPSSODescriptor></md:EntityDescriptor>');
    t.check(consumed.ok, 'metadata whose only ACS is SimpleSign is consumed',
            JSON.stringify(consumed.errors || ''));
    const chosen = direct.registeredAcsFor(
      direct.readAuthnRequest(authn.replace(ssp, acsSp)),
      fieldsOf(acsSp));
    t.check(chosen.ok && chosen.binding === B_SIMPLESIGN,
            'the SimpleSign endpoint is DELIVERABLE and chosen',
            JSON.stringify(chosen));
    t.equal(direct.responseBindingFor({ protocolBinding: B_SIMPLESIGN })
      .binding, B_SIMPLESIGN,
            'and a request asking for SimpleSign as ProtocolBinding is ' +
            'answered on it');
    const cookieJar = [];
    const session = require('../authn/authn').startSession({
      req: null,
      getHeader: function () {
        log.debug("Entering getHeader().");
        log.debug("Leaving getHeader().");
        return cookieJar.slice();
      },
      setHeader: function (name, value) {
        log.debug("Entering setHeader().");
        cookieJar.length = 0;
        [].concat(value).forEach(function (v) {
          cookieJar.push(v);
        });
        log.debug("Leaving setHeader().");
      }
    }, 'alice', [], '1', 'Test', {});
    const sent = kit.fakeRes();
    kit.withSettings(config, { 'saml2.signResponse': true }, function () {
      direct.issueSignInResponse(sent, {
        request: direct.readAuthnRequest(authn.replace(ssp, acsSp)),
        session: session, spEntityId: acsSp,
        idpEntityId: 'https://idp.test/saml2/metadata',
        acsUrl: 'https://simplesign.test/acs', binding: B_SIMPLESIGN,
        relayState: 'state 1'
      });
    });
    const field = function (name) {
      log.debug("Entering field().");
      const m = new RegExp('name="' + name + '" value="([^"]*)"')
        .exec(sent.body);
      log.debug("Leaving field().");
      return m ? m[1].replace(/&amp;/g, '&').replace(/&quot;/g, '"') : '';
    };
    const responseB64 = field('SAMLResponse');
    const responseXml = Buffer.from(responseB64, 'base64').toString('utf8');
    t.check(/action="https:\/\/simplesign.test\/acs"/.test(sent.body) &&
            /<samlp:Response\b/.test(responseXml) &&
            field('SigAlg') && field('Signature'),
            'the Response is POSTed with SigAlg and Signature form fields',
            sent.body.slice(0, 200));
    const responseRoot = responseXml.slice(0, responseXml.indexOf(
      '<saml:Assertion') >= 0 ? responseXml.indexOf('<saml:Assertion')
                              : responseXml.length);
    t.check(!/<ds:Signature\b/.test(responseRoot),
            'with NO enveloped signature on the Response itself',
            responseRoot.slice(0, 300));
    const octets = 'SAMLResponse=' + responseXml + '&RelayState=state 1' +
                   '&SigAlg=' + field('SigAlg');
    t.check(stsCrypto.verifyQueryString(octets, {
              signature: field('Signature'), sigAlg: field('SigAlg'),
              certPem: helpers.STS.xml.certPem }).ok &&
            !stsCrypto.verifyQueryString(octets.replace('state 1', 'state 2'),
              { signature: field('Signature'), sigAlg: field('SigAlg'),
                certPem: helpers.STS.xml.certPem }).ok,
            'and the Signature verifies over the SimpleSign octets — the ' +
            'RAW XML, not its base64 (#189) — with this service\'s ' +
            'certificate');
    t.check(!stsCrypto.verifyQueryString('SAMLResponse=' + responseB64 +
              '&RelayState=state 1&SigAlg=' + field('SigAlg'), {
              signature: field('Signature'), sigAlg: field('SigAlg'),
              certPem: helpers.STS.xml.certPem }).ok,
            'and NOT over the base64 text, which is what it signed until ' +
            '#189');

    const idpMetadata = direct.metadataFor('https://idp.test', '');
    t.check(new RegExp('<md:SingleSignOnService Binding="' + B_SIMPLESIGN)
              .test(idpMetadata) &&
            new RegExp('<md:SingleLogoutService Binding="' + B_SIMPLESIGN)
              .test(idpMetadata),
            'the identity provider\'s metadata ADVERTISES SimpleSign for ' +
            'SingleSignOnService and SingleLogoutService');
  } finally {
    created.forEach(function (id) {
      if (applications.get(id)) {
        applications.deleteApplication(id);
      }
    });
  }
  log.debug("Leaving run().");
}

module.exports = {
  name: 'saml_artifact_and_simplesign',
  describe: 'artifact resolution authenticates its caller (SAML 2.0 and ' +
            '1.1) and the HTTP-POST-SimpleSign binding in both directions ' +
            '(#37 follow-up)',
  run: run
};

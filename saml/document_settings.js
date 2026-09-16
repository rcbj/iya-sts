// @ts-check
'use strict';
//
// File: document_settings.js
//
// ===========================================================================
// THE TWO THINGS EVERY SIGNED SAML-SHAPED DOCUMENT HERE ASKS THE CONFIGURATION,
// ANSWERED IN ONE PLACE (2026-09-12).
//
//   signatureOptions()     `{ sigAlg, c14nAlg }` for `common/crypto.js`'s
//                          signXml(), and `sigAlg` alone for the HTTP Redirect
//                          binding's query-string signature.
//   organizationElement()  the <md:Organization> of a SAML metadata document,
//                          or '' when there is none to publish.
//
// **WHY A MODULE RATHER THAN TWO LINES AT EACH SIGNER.** There are ten signers
// across `saml/`, `ws-federation/` and `federation/` — two assertion builders,
// two Responses, a LogoutRequest and a LogoutResponse, two metadata documents,
// the WS-Federation metadata and a federated AuthnRequest. Until this date not
// one of them passed an algorithm to `signXml()`, which has always accepted
// one, so RSA-SHA256 and exclusive c14n were chosen by an ABSENCE — the one
// kind of decision `common/crypto.js`'s header says must not exist, because
// `/admin/crypto-metadata` cannot see it. Ten copies of the translation from a
// setting to a URI would be ten places for the SigAlg a verifier is TOLD and
// the algorithm actually USED to drift apart, which on the Redirect binding is
// a signature that verifies nowhere.
//
// A LIBRARY (rule 3): it registers no route and requires `config`, `helpers`
// and `crypto`, none of which requires it back.
// ===========================================================================

const config = require('../common/config');
const { log, xmlEscape } = require('../common/helpers');
const stsCrypto = require('../common/crypto');

// The URIs, taken from the vendored engine's own names where it has them so
// there is one spelling in the process. RSA only: the key every one of these
// documents is signed with is this realm's RSA key, and the vendored enveloped
// signer's digest table (`sigAlgSpec()`) is the RSA family.
const XMLDSIG_MORE = 'http://www.w3.org/2001/04/xmldsig-more#';

const SIGNATURE_ALGORITHMS = {
  'rsa-sha256': stsCrypto.SIG_RSA_SHA256,
  'rsa-sha384': XMLDSIG_MORE + 'rsa-sha384',
  'rsa-sha512': XMLDSIG_MORE + 'rsa-sha512',
  'rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
};

// EXCLUSIVE ONLY, and `saml.canonicalizationAlgorithm`'s description says why:
// an assertion is signed standalone and then embedded under ancestors that
// declare prefixes of their own.
const CANONICALIZATIONS = {
  'exclusive': stsCrypto.C14N_EXCLUSIVE,
  'exclusive-with-comments': stsCrypto.C14N_EXCLUSIVE + 'WithComments'
};

// The configured pair, as URIs. A value the table does not know falls back to
// today's pair with a warning rather than throwing into a sign-in — the enum
// on the setting already refuses one at the door, so this is reachable only by
// a table and a setting that disagree, which is a bug worth a log line and not
// worth a failed assertion.
function signatureOptions() {
  log.debug("Entering signatureOptions().");
  const sigName = String(config.value('saml.signatureAlgorithm') ||
                         'rsa-sha256');
  const c14nName = String(config.value('saml.canonicalizationAlgorithm') ||
                          'exclusive');
  let sigAlg = SIGNATURE_ALGORITHMS[sigName];
  let c14nAlg = CANONICALIZATIONS[c14nName];
  if (!sigAlg) {
    log.warn('saml: saml.signatureAlgorithm is "' + sigName + '", which this ' +
             'service cannot sign with; RSA-SHA256 is used instead.');
    sigAlg = SIGNATURE_ALGORITHMS['rsa-sha256'];
  }
  if (!c14nAlg) {
    log.warn('saml: saml.canonicalizationAlgorithm is "' + c14nName + '", ' +
             'which this service does not offer; exclusive c14n is used ' +
             'instead.');
    c14nAlg = CANONICALIZATIONS.exclusive;
  }
  log.debug("Leaving signatureOptions(). " + sigName + ", " + c14nName + ".");
  return { sigAlg: sigAlg, c14nAlg: c14nAlg, sigName: sigName,
           c14nName: c14nName };
}

// ---------------------------------------------------------------------------
// <md:Organization>, which was the literal "mock-sts" / "Mock security token
// service" in two signed metadata documents.
//
// EMPTY OMITS THE ELEMENT, IN EITHER MODE. saml-metadata-2.0-os section 2.3.2.1
// makes OrganizationName, OrganizationDisplayName and OrganizationURL each
// one-or-more, so half an Organization is a schema-invalid document; an
// operator who empties the name has said there is no organisation to publish,
// and the element is optional. The URL defaults to the base URL as before.
//
// WHY NOT OMIT IT IN PRODUCT MODE AUTOMATICALLY: a setting whose value is
// silently ignored in one mode is a setting that lies on the console. The
// default is the name this service always published, product mode included,
// and README says to set or empty it.
// ---------------------------------------------------------------------------
function organizationElement(base) {
  log.debug("Entering organizationElement().");
  const name = String(config.value('saml.organizationName') || '').trim();
  const display = String(config.value('saml.organizationDisplayName') ||
                         '').trim();
  if (!name || !display) {
    log.debug("Leaving organizationElement(). Omitted: no name or no display " +
              "name.");
    return '';
  }
  const url = String(config.value('saml.organizationUrl') || '').trim() ||
    (String(base || '') + '/');
  log.debug("Leaving organizationElement().");
  return '<md:Organization>' +
    '<md:OrganizationName xml:lang="en">' + xmlEscape(name) +
    '</md:OrganizationName><md:OrganizationDisplayName ' +
    'xml:lang="en">' + xmlEscape(display) +
    '</md:OrganizationDisplayName>' +
    '<md:OrganizationURL xml:lang="en">' + xmlEscape(url) +
    '</md:OrganizationURL></md:Organization>';
}

module.exports = {
  SIGNATURE_ALGORITHMS: SIGNATURE_ALGORITHMS,
  CANONICALIZATIONS: CANONICALIZATIONS,
  signatureOptions: signatureOptions,
  organizationElement: organizationElement
};

'use strict';
//
// File: document_settings.ts
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

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `DocumentSettings` takes `config`, the logger, `xmlEscape` and the
// two URI tables through its constructor; the tables are its static members.
// Since #50's R2 the composition root builds the instance; the module's old
// four names are FACADES forwarding to it, for the unconverted modules that
// require it, and a process without the root builds a default at load.
// ---------------------------------------------------------------------------

import config = require('../common/config');
import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import stsCrypto = require('../common/crypto');

// What `signatureOptions()` answers.
interface SignatureOptions {
  sigAlg: string;
  c14nAlg: string;
  sigName: string;
  c14nName: string;
}

interface DocumentSettingsDeps {
  config: { value(key: string): unknown };
  log: { debug(message: string): void; warn(message: string): void };
  xmlEscape(value: unknown): string;
}

// The URIs, taken from the vendored engine's own names where it has them so
// there is one spelling in the process. RSA only: the key every one of these
// documents is signed with is this realm's RSA key, and the vendored enveloped
// signer's digest table (`sigAlgSpec()`) is the RSA family.
const XMLDSIG_MORE = 'http://www.w3.org/2001/04/xmldsig-more#';

class DocumentSettings {
  static readonly SIGNATURE_ALGORITHMS: Record<string, string> = {
    'rsa-sha256': stsCrypto.SIG_RSA_SHA256,
    'rsa-sha384': XMLDSIG_MORE + 'rsa-sha384',
    'rsa-sha512': XMLDSIG_MORE + 'rsa-sha512',
    'rsa-sha1': 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  };

  // EXCLUSIVE ONLY, and `saml.canonicalizationAlgorithm`'s description says
  // why: an assertion is signed standalone and then embedded under ancestors
  // that declare prefixes of their own.
  static readonly CANONICALIZATIONS: Record<string, string> = {
    'exclusive': stsCrypto.C14N_EXCLUSIVE,
    'exclusive-with-comments': stsCrypto.C14N_EXCLUSIVE + 'WithComments'
  };

  constructor(private readonly deps: DocumentSettingsDeps) {
    deps.log.debug("Entering DocumentSettings.constructor().");
    deps.log.debug("Leaving DocumentSettings.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): DocumentSettingsDeps {
    helpers.log.debug("Entering DocumentSettings.defaultDeps().");
    helpers.log.debug("Leaving DocumentSettings.defaultDeps().");
    return {
      config: config,
      log: helpers.log,
      xmlEscape: helpers.xmlEscape
    };
  }

  // The configured pair, as URIs. A value the table does not know falls back
  // to today's pair with a warning rather than throwing into a sign-in — the
  // enum on the setting already refuses one at the door, so this is reachable
  // only by a table and a setting that disagree, which is a bug worth a log
  // line and not worth a failed assertion.
  signatureOptions(): SignatureOptions {
    const { log, config } = this.deps;
    const SIGNATURE_ALGORITHMS = DocumentSettings.SIGNATURE_ALGORITHMS;
    const CANONICALIZATIONS = DocumentSettings.CANONICALIZATIONS;
    log.debug("Entering DocumentSettings.signatureOptions().");
    const sigName = String(config.value('saml.signatureAlgorithm') ||
                           'rsa-sha256');
    const c14nName = String(config.value('saml.canonicalizationAlgorithm') ||
                            'exclusive');
    let sigAlg = SIGNATURE_ALGORITHMS[sigName];
    let c14nAlg = CANONICALIZATIONS[c14nName];
    if (!sigAlg) {
      log.warn('saml: saml.signatureAlgorithm is "' + sigName + '", which ' +
               'this service cannot sign with; RSA-SHA256 is used instead.');
      sigAlg = SIGNATURE_ALGORITHMS['rsa-sha256'];
    }
    if (!c14nAlg) {
      log.warn('saml: saml.canonicalizationAlgorithm is "' + c14nName + '", ' +
               'which this service does not offer; exclusive c14n is used ' +
               'instead.');
      c14nAlg = CANONICALIZATIONS.exclusive;
    }
    log.debug("Leaving DocumentSettings.signatureOptions(). " + sigName +
              ", " + c14nName + ".");
    return { sigAlg: sigAlg, c14nAlg: c14nAlg, sigName: sigName,
             c14nName: c14nName };
  }

  // -------------------------------------------------------------------------
  // <md:Organization>, which was the literal "mock-sts" / "Mock security
  // token service" in two signed metadata documents.
  //
  // EMPTY OMITS THE ELEMENT, IN EITHER MODE. saml-metadata-2.0-os section
  // 2.3.2.1 makes OrganizationName, OrganizationDisplayName and
  // OrganizationURL each one-or-more, so half an Organization is a
  // schema-invalid document; an operator who empties the name has said there
  // is no organisation to publish, and the element is optional. The URL
  // defaults to the base URL as before.
  //
  // WHY NOT OMIT IT IN PRODUCT MODE AUTOMATICALLY: a setting whose value is
  // silently ignored in one mode is a setting that lies on the console. The
  // default is the name this service always published, product mode
  // included, and README says to set or empty it.
  // -------------------------------------------------------------------------
  organizationElement(base?: unknown): string {
    const { log, config, xmlEscape } = this.deps;
    log.debug("Entering DocumentSettings.organizationElement().");
    const name = String(config.value('saml.organizationName') || '').trim();
    const display = String(config.value('saml.organizationDisplayName') ||
                           '').trim();
    if (!name || !display) {
      log.debug("Leaving DocumentSettings.organizationElement(). Omitted: " +
                "no name or no display name.");
      return '';
    }
    const url = String(config.value('saml.organizationUrl') || '').trim() ||
      (String(base || '') + '/');
    log.debug("Leaving DocumentSettings.organizationElement().");
    return '<md:Organization>' +
      '<md:OrganizationName xml:lang="en">' + xmlEscape(name) +
      '</md:OrganizationName><md:OrganizationDisplayName ' +
      'xml:lang="en">' + xmlEscape(display) +
      '</md:OrganizationDisplayName>' +
      '<md:OrganizationURL xml:lang="en">' + xmlEscape(url) +
      '</md:OrganizationURL></md:Organization>';
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds
// no instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when the module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<DocumentSettings>(
  'saml/document_settings',
  () => new DocumentSettings(DocumentSettings.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  DocumentSettings: DocumentSettings,
  installInstance: (instance: DocumentSettings): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  SIGNATURE_ALGORITHMS: DocumentSettings.SIGNATURE_ALGORITHMS,
  CANONICALIZATIONS: DocumentSettings.CANONICALIZATIONS,
  signatureOptions: slot.forward('signatureOptions'),
  organizationElement: slot.forward('organizationElement')
};

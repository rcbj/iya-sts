'use strict';
// ===========================================================================
// THE CERTIFICATE THE SAML BACK CHANNEL PRESENTS, AS A METADATA KEY (#248).
//
// rcbj's decision on #189, 2026-09-26: the identity provider's metadata
// publishes the TLS certificate its SOAP endpoints present — artifact
// resolution and the attribute authority, in both profiles — so a service
// provider that authenticates the back-channel peer FROM METADATA can do so
// without being handed a key some other way. That is what the Shibboleth SP's
// ExplicitKey trust engine does, and what SimpleSAMLphp's SOAP client does
// when it pins the server to the metadata's keys. Until #248 neither could:
// the listener's certificate is not the XML signing key, and the peer
// harnesses handed the service's TLS anchor over by hand.
//
// WHY `use="signing"` AND A DESCRIPTOR OF ITS OWN, rather than `use` omitted:
//
//   * saml-metadata-2.0-os section 2.4.1.1 has two uses, `signing` and
//     `encryption`, and "omitted" means BOTH. A TLS key is not a key anybody
//     may encrypt to — this service never decrypts with it — so a descriptor
//     with no `use` would invite a service provider to encrypt an EncryptedID
//     or a NameID to a key whose holder does not open XML Encryption, and the
//     failure would read as a broken decryption rather than a wrong key.
//   * TLS authentication is a SIGNING use of a key: the handshake is a
//     signature by the server's private key. The SAML V2.0 Metadata
//     Interoperability Profile and every implementation that reads metadata
//     for TLS (Shibboleth's ExplicitKey and PKIX engines, SimpleSAMLphp's
//     SOAP client) look for it among the `signing` and unqualified keys, and
//     nowhere else.
//   * A DESCRIPTOR OF ITS OWN, LAST among the KeyDescriptors, rather than a
//     second X509Certificate inside a signing descriptor: section 2.4.1.1's
//     KeyInfo describes ONE key, and a consumer that takes "the first signing
//     certificate" to verify this service's XML signatures — several do —
//     still finds the XML key first.
//
// WHAT IT COSTS, SAID RATHER THAN LEFT TO BE FOUND: a consumer that verifies
// XML signatures against every signing key would accept one made with the
// listener's key too. That key is this service's own, held by the process
// that holds the XML key — except where an operator supplied the certificate
// (`tls.certificateFile`) and shares its key with something in front of this
// service, which then holds a key this metadata vouches for. The listener
// certificate an operator supplies is theirs to keep as close as the XML key.
//
// WHICH CERTIFICATES: every leaf the main port presents (with
// `tls.certificateAlgorithms` naming two, OpenSSL picks per client), as the
// SOCKET presents them — `tls_server.presentedCertificatePems()` answers that
// in a request worker too — and, in a cluster, every live node's
// (`cluster/cluster.js` carries them on each node's heartbeat), because a
// service provider behind a balancer resolves an artifact at whichever node it
// reaches. NONE when the main port is plain HTTP (`global.https` off): there
// is no certificate on that back channel to authenticate.
//
// IT FOLLOWS THE CERTIFICATE: nothing here is cached. Every metadata document
// is built per request and asks again, so after `build-root` re-issues the
// listener (`tls/CLAUDE.md`) the next document names the new leaf — a
// consumer that cached the old document has to fetch it again, which is what
// the documents' `no-store` already tells it.
//
// A LIBRARY: registers nothing. `tls/tls_server.js` is JavaScript and registers
// its routes when required, and it is required at 20, after both profiles; so
// it is reached LAZILY, when a document is built, which is always after the
// whole stack has loaded.
// ===========================================================================

import config = require('../common/config');
import helpers = require('../common/helpers');
import errorCodes = require('../common/error_codes');
import stsCrypto = require('../common/crypto');
import cluster = require('../cluster/cluster');
import InstanceSlot = require('../common/instance_slot');

const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

interface ListenerKeysDeps {
  log: { debug(message: string): void; warn(message: string): void };
  config: { value(key: string): unknown };
  errorCodes: { tag(code: string): string };
  stripPem(pem: string): string;
  loadTlsServer(): { presentedCertificatePems(): string[] };
  cluster: { listenerCertificatesOfLiveNodes(): string[] };
}

class ListenerKeys {
  constructor(private readonly deps: ListenerKeysDeps) {
    deps.log.debug("Entering ListenerKeys.constructor().");
    deps.log.debug("Leaving ListenerKeys.constructor().");
  }

  static defaultDeps(): ListenerKeysDeps {
    helpers.log.debug("Entering ListenerKeys.defaultDeps().");
    helpers.log.debug("Leaving ListenerKeys.defaultDeps().");
    return {
      log: helpers.log,
      config: config,
      errorCodes: errorCodes,
      stripPem: stsCrypto.stripPem,
      loadTlsServer: function () {
        return require('../tls/tls_server');
      },
      cluster: cluster
    };
  }

  // The certificates, base64 DER, this process's own first; empty when the
  // main port is not TLS. A certificate that cannot be read is a document
  // without it, logged under STS-SAML-0097 — never a document refused.
  certificates(): string[] {
    const { log, config, errorCodes, stripPem } = this.deps;
    log.debug("Entering ListenerKeys.certificates().");
    if (!config.value('global.https')) {
      log.debug("Leaving ListenerKeys.certificates(). The main port is " +
                "plain HTTP.");
      return [];
    }
    const out: string[] = [];
    const add = function (b64: string) {
      log.debug("Entering add().");
      if (b64 && out.indexOf(b64) < 0) {
        out.push(b64);
      }
      log.debug("Leaving add().");
    };
    try {
      this.deps.loadTlsServer().presentedCertificatePems()
        .forEach(function (pem) {
          add(stripPem(String(pem || '')));
        });
    } catch (e) {
      log.debug("Caught in ListenerKeys.certificates(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-SAML-0097') + 'saml: the certificate the ' +
               'back channel presents could not be read, so this metadata ' +
               'document goes out without it: ' + ((e && e.message) || e));
    }
    try {
      this.deps.cluster.listenerCertificatesOfLiveNodes().forEach(add);
    } catch (e) {
      log.debug("Caught in ListenerKeys.certificates(): " +
                ((e && e.message) || e));
      log.warn(errorCodes.tag('STS-SAML-0097') + 'saml: the other cluster ' +
               'nodes\' listener certificates could not be read, so this ' +
               'metadata document names this node\'s alone: ' +
               ((e && e.message) || e));
    }
    log.debug("Leaving ListenerKeys.certificates(). " + out.length + ".");
    return out;
  }

  // One `<md:KeyDescriptor use="signing">` per certificate, for the end of a
  // role descriptor's KeyDescriptor list (see the header for why there).
  keyDescriptors(): string {
    const { log } = this.deps;
    log.debug("Entering ListenerKeys.keyDescriptors().");
    const xml = this.certificates().map(function (b64) {
      return '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="' +
        NS_DS + '"><ds:X509Data><ds:X509Certificate>' + b64 +
        '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>' +
        '</md:KeyDescriptor>';
    }).join('');
    log.debug("Leaving ListenerKeys.keyDescriptors().");
    return xml;
  }
}

const slot = new InstanceSlot<ListenerKeys>(
  'saml/listener_keys',
  () => new ListenerKeys(ListenerKeys.defaultDeps()),
  null,
  helpers.log);

slot.buildNowUnlessDeferred();

export = {
  ListenerKeys: ListenerKeys,
  installInstance: (instance: ListenerKeys): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  certificates: slot.forward('certificates'),
  keyDescriptors: slot.forward('keyDescriptors')
};

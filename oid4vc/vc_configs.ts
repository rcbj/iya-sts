'use strict';
//
// File: vc_configs.ts
//
// ---------------------------------------------------------------------------
// Every credential this issuer offers, by credential_configuration_id.
//
// One module, because "is this a configuration I offer" is asked from five
// places — the credential endpoint, authorization_details, the offer builder,
// the DID decision and the metadata — and a list that disagrees with itself
// between them is an issuer that advertises what it will then refuse.
//
// It is also the bottom of the dependency graph: it names the credentials
// without knowing how any of them is built, which is what lets both the OID4VCI
// module and the authorization server read it without requiring each other.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape: `VcConfigs` takes the logger and the settings reader through its
// constructor, and the constants are its static members. The module still
// exports every old name, as ONE `export =` at the bottom where
// `module.exports` was, with every constant computed at load as before — this
// file breaks require cycles (root `CLAUDE.md` rule 2), and what an early
// caller sees must not change. Since #50's R2 the composition root builds the
// instance and the functions are FACADES forwarding to it, which an early
// caller may hold without building anything; a process without the root
// builds a default at load.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');

// One credential configuration.
interface VciConfig {
  format: string;
  scope: string;
  issuerDid?: boolean;
  basedOn?: string;
}

interface VcConfigsDeps {
  log: { debug(message: string): void };
  config: { value(key: string): any };
}

const VCI_CONFIG_ID = 'IdentityCredential';

const VCI_VCT = 'urn:idptools:sd-jwt-vc:identity';

const VCI_SCOPE = 'identity_credential';

// ---------------------------------------------------------------------------
// A second credential format: jwt_vc_json (OID4VCI Appendix A.1.1).
//
// The same End-User facts, issued as a W3C Verifiable Credential secured as a
// JWT instead of as an SD-JWT VC. It is here because the two formats differ in
// the one way this workflow is about: jwt_vc_json has NO selective disclosure.
// The whole credentialSubject is in the JWT, so a holder presenting it hands
// over everything in it — there are no Disclosures to choose between, and the
// holder binding that an SD-JWT does with a Key Binding JWT is done instead by
// signing a Verifiable Presentation JWT around the credential.
//
// Everything else is deliberately identical: the same proof of possession, the
// same batch and deferred paths, the same response encryption, the same
// notification ids. Only the artefact at the end is a different shape.
// ---------------------------------------------------------------------------
const VCI_JWT_CONFIG_ID = 'IdentityCredentialJwtVcJson';

const VCI_JWT_SCOPE = 'identity_credential_jwt';

const VCI_JWT_TYPES = ['VerifiableCredential', 'IdentityCredential'];

const VCI_LDP_CONFIG_ID = 'IdentityCredentialLdpVc';

const VCI_LDP_SCOPE = 'identity_credential_ldp';

const VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1';

// Every credential this issuer offers, by credential_configuration_id — the
// one list the header argues for.
const VCI_CONFIGS: Record<string, VciConfig> = {};
VCI_CONFIGS[VCI_CONFIG_ID] = { format: 'dc+sd-jwt', scope: VCI_SCOPE };
VCI_CONFIGS[VCI_JWT_CONFIG_ID] = { format: 'jwt_vc_json',
                                   scope: VCI_JWT_SCOPE };
// The third format: a W3C credential secured by an EMBEDDED Data Integrity
// proof (bbs-2023) rather than by a JWS. This is the only one of the three that
// can carry BBS at all — the other two are JOSE-secured and BBS is not a JOSE
// alg — and it is the only one offering unlinkable selective disclosure: the
// holder derives a fresh proof per presentation instead of replaying the
// issuer's signature.
VCI_CONFIGS[VCI_LDP_CONFIG_ID] = { format: 'ldp_vc', scope: VCI_LDP_SCOPE };

// ---------------------------------------------------------------------------
// Two more configurations, identical to their siblings above except that the
// issuer names ITSELF by a did:web instead of by its https identifier. See
// vc_did.ts for what that DID is and what serves its document.
//
// Two configurations rather than one server-wide switch, and the reason is
// coverage: with a switch, a run exercises the DID route or the URL route but
// never both, and for dc+sd-jwt the URL route is the one the specification
// actually defines (/.well-known/jwt-vc-issuer). Offering both side by side
// lets one run cover both, lets a wallet SEE the difference in the metadata
// rather than being told out of band, and makes "which mechanism am I looking
// at" a choice the person driving the debugger makes deliberately.
//
// `issuerDid: true` is the whole of the difference. Everything else about these
// configurations — claims, proof types, batch, deferral, encryption — is
// inherited from the sibling, so there is no second definition to drift.
// ---------------------------------------------------------------------------
const VCI_DID_CONFIG_ID = 'IdentityCredentialDid';

const VCI_DID_SCOPE = 'identity_credential_did';

const VCI_LDP_DID_CONFIG_ID = 'IdentityCredentialLdpVcDid';

const VCI_LDP_DID_SCOPE = 'identity_credential_ldp_did';
VCI_CONFIGS[VCI_DID_CONFIG_ID] =
  { format: 'dc+sd-jwt', scope: VCI_DID_SCOPE, issuerDid: true,
    basedOn: VCI_CONFIG_ID };
VCI_CONFIGS[VCI_LDP_DID_CONFIG_ID] =
  { format: 'ldp_vc', scope: VCI_LDP_DID_SCOPE, issuerDid: true,
    basedOn: VCI_LDP_CONFIG_ID };

class VcConfigs {
  static readonly VCI_CONFIG_ID = VCI_CONFIG_ID;
  static readonly VCI_VCT = VCI_VCT;
  static readonly VCI_SCOPE = VCI_SCOPE;
  static readonly VCI_JWT_CONFIG_ID = VCI_JWT_CONFIG_ID;
  static readonly VCI_JWT_SCOPE = VCI_JWT_SCOPE;
  static readonly VCI_JWT_TYPES = VCI_JWT_TYPES;
  static readonly VCI_LDP_CONFIG_ID = VCI_LDP_CONFIG_ID;
  static readonly VCI_LDP_SCOPE = VCI_LDP_SCOPE;
  static readonly VCI_DID_CONFIG_ID = VCI_DID_CONFIG_ID;
  static readonly VCI_DID_SCOPE = VCI_DID_SCOPE;
  static readonly VCI_LDP_DID_CONFIG_ID = VCI_LDP_DID_CONFIG_ID;
  static readonly VCI_LDP_DID_SCOPE = VCI_LDP_DID_SCOPE;
  static readonly VC_CONTEXT = VC_CONTEXT;
  static readonly VCI_CONFIGS = VCI_CONFIGS;

  constructor(private readonly deps: VcConfigsDeps) {
    deps.log.debug("Entering VcConfigs.constructor().");
    deps.log.debug("Leaving VcConfigs.constructor().");
  }

  // What the composition root passes, from the real modules — what
  // loading this module passed before #50's R2.
  static defaultDeps(): VcConfigsDeps {
    helpers.log.debug("Entering VcConfigs.defaultDeps().");
    helpers.log.debug("Leaving VcConfigs.defaultDeps().");
    return { log: helpers.log, config: config };
  }

  // A FUNCTION rather than the constant this was, so that /admin/config can
  // change it and the next metadata document says so. Same for every
  // runtime-settable value in this service; the ones that are still constants
  // are the ones config.js marks restart-only.
  vciAuthorizationServer(): any {
    const { log, config } = this.deps;
    log.debug("Entering VcConfigs.vciAuthorizationServer().");
    log.debug("Leaving VcConfigs.vciAuthorizationServer().");
    return config.value('oid4vci.authorizationServer');
  }

  // The most proofs this issuer will take in one Credential Request, and so
  // the most credentials it will return (OID4VCI section 14.6).
  vciBatchSize(): any {
    const { log, config } = this.deps;
    log.debug("Entering VcConfigs.vciBatchSize().");
    log.debug("Leaving VcConfigs.vciBatchSize().");
    return config.value('oid4vci.batchSize');
  }

  vciConfigIds(): string[] {
    const { log } = this.deps;
    log.debug("Entering VcConfigs.vciConfigIds().");
    log.debug("Leaving VcConfigs.vciConfigIds().");
    return Object.keys(VCI_CONFIGS);
  }

  vciFormatOf(configId: string): string {
    const { log } = this.deps;
    log.debug("Entering VcConfigs.vciFormatOf().");
    const c = VCI_CONFIGS[configId];
    log.debug("Leaving VcConfigs.vciFormatOf().");
    return c ? c.format : '';
  }

  // Whether credentials from this configuration name the issuer by DID. Asked
  // by the credential builders and by the metadata, which must advertise the
  // same answer the credential will carry — an issuer whose metadata and
  // credentials disagree about who issued them is the bug this keeps in one
  // place.
  vciUsesIssuerDid(configId: string): boolean {
    const { log } = this.deps;
    log.debug("Entering VcConfigs.vciUsesIssuerDid().");
    const c = VCI_CONFIGS[configId];
    log.debug("Leaving VcConfigs.vciUsesIssuerDid().");
    return !!(c && c.issuerDid);
  }

  // A credential_identifier is minted as "<configId>:<hash>", so the
  // configuration it belongs to is the part before the colon. Used to route a
  // section 8.2 identifier request to the right format.
  configIdOfIdentifier(identifier: unknown): string {
    const { log } = this.deps;
    log.debug("Entering VcConfigs.configIdOfIdentifier().");
    const prefix = String(identifier || '').split(':')[0];
    log.debug("Leaving VcConfigs.configIdOfIdentifier().");
    return VCI_CONFIGS[prefix] ? prefix : '';
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
const slot = new InstanceSlot<VcConfigs>(
  'oid4vc/vc_configs',
  () => new VcConfigs(VcConfigs.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  VcConfigs: VcConfigs,
  installInstance: (instance: VcConfigs): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  vciAuthorizationServer: slot.forward('vciAuthorizationServer'),
  VCI_CONFIG_ID: VcConfigs.VCI_CONFIG_ID,
  vciBatchSize: slot.forward('vciBatchSize'),
  VCI_VCT: VcConfigs.VCI_VCT,
  VCI_SCOPE: VcConfigs.VCI_SCOPE,
  VCI_JWT_CONFIG_ID: VcConfigs.VCI_JWT_CONFIG_ID,
  VCI_JWT_SCOPE: VcConfigs.VCI_JWT_SCOPE,
  VCI_JWT_TYPES: VcConfigs.VCI_JWT_TYPES,
  VCI_LDP_CONFIG_ID: VcConfigs.VCI_LDP_CONFIG_ID,
  VCI_LDP_SCOPE: VcConfigs.VCI_LDP_SCOPE,
  VCI_DID_CONFIG_ID: VcConfigs.VCI_DID_CONFIG_ID,
  VCI_DID_SCOPE: VcConfigs.VCI_DID_SCOPE,
  VCI_LDP_DID_CONFIG_ID: VcConfigs.VCI_LDP_DID_CONFIG_ID,
  VCI_LDP_DID_SCOPE: VcConfigs.VCI_LDP_DID_SCOPE,
  VC_CONTEXT: VcConfigs.VC_CONTEXT,
  VCI_CONFIGS: VcConfigs.VCI_CONFIGS,
  vciConfigIds: slot.forward('vciConfigIds'),
  vciFormatOf: slot.forward('vciFormatOf'),
  vciUsesIssuerDid: slot.forward('vciUsesIssuerDid'),
  configIdOfIdentifier: slot.forward('configIdOfIdentifier')
};

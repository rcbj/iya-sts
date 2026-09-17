'use strict';
//
// File: id_token_encryption.ts
//
// ===========================================================================
// ENCRYPTED ID TOKENS — OPENID CONNECT CORE SECTION 10.2 AND DYNAMIC CLIENT
// REGISTRATION SECTION 2 (2026-09-17, #36 follow-up).
//
// A client may register two members about the ID Tokens it is sent:
//
//   id_token_encrypted_response_alg   the JWE key management algorithm
//   id_token_encrypted_response_enc   the content encryption; A128CBC-HS256
//                                     when an `alg` is registered without one,
//                                     and it MUST NOT be registered alone
//
// and an ID Token issued to it is then a NESTED JWT: signed exactly as it
// would have been (`id_token_signed_response_alg`, RS256 by default, the whole
// post-quantum table included), and that JWS encrypted to the client's own
// key, with `cty: "JWT"` on the outer header (Core section 10.2: "signed and
// then encrypted ... the result is a Nested JWT, as defined in [JWT]").
//
// **UNTIL THIS FILE NO ID TOKEN HERE WAS ENCRYPTED**, and the discovery
// document said so by leaving `id_token_encryption_alg_values_supported` out.
// UserInfo responses (section 5.3.2) and RFC 9701 introspection responses were
// already encrypted to a client's key; the ID Token, which is the one artifact
// every OpenID Connect client receives, was not. Back-Channel Logout 1.0
// section 2.4 says a Logout Token is encrypted "the same way as ID Tokens" for
// a client that registered encryption, so the Logout Token needed this first —
// and an optional feature of the specification is a feature this service
// offers.
//
// **THE FOUR DECISIONS**, each the one the two responses above already made:
//
//   * **THE ASYMMETRIC FAMILIES ONLY** (`common/crypto.js`'s
//     `JWE_ASYMMETRIC_ALGS`: RSA-OAEP, RSA-OAEP-256, ECDH-ES and its three
//     key-wrap forms). Core section 10.2 allows the symmetric ones keyed from
//     the client secret; this service's symmetric table exists for documents
//     encrypted TO it, and an ID Token is encrypted to a key the CLIENT holds.
//     A client registering `dir` or `A128KW` is refused at registration with
//     `invalid_client_metadata`, naming the list.
//   * **AN INLINE `jwks` ONLY.** A `jwks_uri` is never fetched while answering
//     a request — the root CLAUDE.md's non-goal about dialling a URL a caller
//     supplied — so a client that registers an algorithm and only a
//     `jwks_uri` is refused at registration, by name, rather than accepted and
//     then failed at every authorization response.
//   * **REFUSED, NEVER DOWNGRADED.** A registration this service cannot honour
//     is refused where it is made; one that became unusable afterwards (a key
//     removed by hand) fails the issuance with the sentence, because an ID
//     Token sent in the clear to a client that asked for encryption is a token
//     the client may reject, log, or worse, accept.
//   * **NO POST-QUANTUM KEY ENCAPSULATION.** The SIGNATURE inside may be any
//     algorithm of the JWS table, ML-DSA, SLH-DSA and the composites included;
//     the JWE around it uses what `common/crypto.js` can encrypt with, which
//     has no ML-KEM family. The JOSE registration of ML-KEM is a draft, no
//     other surface here offers it, and adding a key-encapsulation family to
//     the one crypto module is a change to every encrypted response at once
//     rather than to this one — `oauth-oidc/CLAUDE.md` records it as not done.
//
// A LIBRARY (rule 3). It registers no route and requires `helpers.js`,
// `common/crypto.js`, `common/applications.js`, `error_codes.js` and
// `introspection_jwt.ts` (for `recipientKey()`, the one key selection all
// three encrypted responses share), none of which requires it back.
// `oauth2.ts` (the ID Token) and `backchannel_logout.ts` (the Logout Token)
// require it.
//
// TYPESCRIPT, AS A CLASS (#50) — `IdTokenEncryption` takes its collaborators
// through its constructor; the exports are facades over the instance the
// composition root builds and installs.
// ===========================================================================

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import stsCrypto = require('../common/crypto');
import applications = require('../common/applications');
import errorCodes = require('../common/error_codes');
import introspectionJwt = require('./introspection_jwt');

// A registration document.
type Json = any;

interface IdTokenEncryptionDeps {
  log: typeof helpers.log;
  stsCrypto: typeof stsCrypto;
  applications: typeof applications;
  errorCodes: typeof errorCodes;
  introspectionJwt: typeof introspectionJwt;
}

// What `protectionFor()` answers.
interface Protection {
  ok: boolean;
  alg?: string;
  enc?: string;
  description?: string;
}

// The two lists discovery advertises, read off the registry, which reads
// `common/crypto.js`'s own tables — one list for the metadata, the
// registration check and the encryptor.
const ALGS = applications.ID_TOKEN_ENCRYPTION_ALGS;
const ENCS = applications.ID_TOKEN_ENCRYPTION_ENCS;
const DEFAULT_ENC = applications.ID_TOKEN_DEFAULT_ENC;

// The member a refusal names.
const ALG_MEMBER = 'id_token_encrypted_response_alg';

class IdTokenEncryption {
  static readonly ALGS = ALGS;
  static readonly ENCS = ENCS;
  static readonly DEFAULT_ENC = DEFAULT_ENC;

  constructor(private readonly deps: IdTokenEncryptionDeps) {
    deps.log.debug("Entering IdTokenEncryption.constructor().");
    deps.log.debug("Leaving IdTokenEncryption.constructor().");
  }

  // What the composition root passes, from the real modules.
  static defaultDeps(): IdTokenEncryptionDeps {
    helpers.log.debug("Entering IdTokenEncryption.defaultDeps().");
    helpers.log.debug("Leaving IdTokenEncryption.defaultDeps().");
    return {
      log: helpers.log,
      stsCrypto: stsCrypto,
      applications: applications,
      errorCodes: errorCodes,
      introspectionJwt: introspectionJwt
    };
  }

  // -------------------------------------------------------------------------
  // WHAT A CLIENT REGISTERED, with the registration specification's default
  // applied. `{ ok: true }` with no `alg` is "not encrypted", which is every
  // client that registered neither member.
  // -------------------------------------------------------------------------
  protectionFor(registered: Json): Protection {
    const { log, applications } = this.deps;
    log.debug("Entering IdTokenEncryption.protectionFor().");
    const doc = registered || {};
    const problem = applications.idTokenEncryptionMetadataProblem(doc);
    if (problem) {
      log.debug("Leaving IdTokenEncryption.protectionFor(). Refused.");
      return { ok: false, description: problem.description };
    }
    const alg = String(doc.id_token_encrypted_response_alg || '').trim();
    if (!alg) {
      log.debug("Leaving IdTokenEncryption.protectionFor(). Not encrypted.");
      return { ok: true };
    }
    const enc = String(doc.id_token_encrypted_response_enc || '').trim() ||
                DEFAULT_ENC;
    log.debug("Leaving IdTokenEncryption.protectionFor(). " + alg + " " +
              enc);
    return { ok: true, alg: alg, enc: enc };
  }

  // -------------------------------------------------------------------------
  // THE REGISTRATION ENDPOINT'S SECOND QUESTION: is there a key to encrypt
  // to? The grammar is the registry's (`applications.js`, asked by every write
  // door); the KEY is asked here because `recipientKey()` is this family's,
  // and `applications.js` cannot require it without a cycle. Null, or an RFC
  // 7591 section 3.2.2 refusal with its code.
  // -------------------------------------------------------------------------
  registrationKeyProblem(metadata: Json): Json {
    const { log, introspectionJwt, errorCodes } = this.deps;
    log.debug("Entering IdTokenEncryption.registrationKeyProblem().");
    const protection = this.protectionFor(metadata);
    if (!protection.ok || !protection.alg) {
      log.debug("Leaving IdTokenEncryption.registrationKeyProblem(). " +
                "Nothing to check.");
      return null;
    }
    try {
      introspectionJwt.recipientKey(metadata, protection.alg, ALG_MEMBER);
    } catch (e) {
      log.debug("Caught in IdTokenEncryption.registrationKeyProblem(): " +
                ((e && e.message) || e));
      log.debug("Leaving IdTokenEncryption.registrationKeyProblem(). No " +
                "usable key.");
      return errorCodes.mark({
        errorCode: 'STS-REG-0165', error: 'invalid_client_metadata',
        member: ALG_MEMBER,
        description: ALG_MEMBER + ': ' + ((e && e.message) || e) +
          ' An ID Token (and a back-channel Logout Token) would be encrypted ' +
          'to that key, so the registration is refused rather than accepted ' +
          'and failed at every authorization response.'
      }, 'STS-REG-0165');
    }
    log.debug("Leaving IdTokenEncryption.registrationKeyProblem(). A key.");
    return null;
  }

  // -------------------------------------------------------------------------
  // ENCRYPT A SIGNED TOKEN FOR THE CLIENT THAT REGISTERED IT, or hand it back
  // unchanged when nothing was registered. `typ` is the INNER token's type
  // (`JWT` for an ID Token, `logout+jwt` for a Logout Token), repeated on the
  // outer header so a recipient that checks the type before it decrypts sees
  // the one it must check — RFC 7519 section 5.1 leaves it to the
  // application, and Back-Channel Logout section 2.4 asks for it.
  //
  // Throws with a sentence fit for an error_description or a dead letter.
  // -------------------------------------------------------------------------
  protect(signed: string, registered: Json, typ?: string): Json {
    const { log, stsCrypto, introspectionJwt, errorCodes } = this.deps;
    log.debug("Entering IdTokenEncryption.protect().");
    const protection = this.protectionFor(registered);
    if (!protection.ok) {
      log.debug("Leaving IdTokenEncryption.protect(). Refused.");
      throw errorCodes.mark(new Error('This client\'s ID Token encryption ' +
        'cannot be honoured: ' + protection.description), 'STS-OAUTH-0546');
    }
    if (!protection.alg) {
      log.debug("Leaving IdTokenEncryption.protect(). Not encrypted.");
      return { token: signed, encrypted: false, alg: '', enc: '' };
    }
    let jwk = null;
    try {
      jwk = introspectionJwt.recipientKey(registered, protection.alg,
                                          ALG_MEMBER);
    } catch (e) {
      log.debug("Caught in IdTokenEncryption.protect(): " +
                ((e && e.message) || e));
      log.debug("Leaving IdTokenEncryption.protect(). No key.");
      throw errorCodes.mark(new Error(String((e && e.message) || e)),
                            'STS-OAUTH-0546');
    }
    const jwe = stsCrypto.encryptJweCompact(signed, {
      alg: protection.alg,
      enc: protection.enc,
      jwk: jwk,
      // RFC 7519 section 5.2: a Nested JWT says so.
      cty: 'JWT',
      typ: typ || 'JWT'
    });
    log.debug("Leaving IdTokenEncryption.protect(). " + protection.alg +
              " " + protection.enc + ", kid=" + ((jwk && jwk.kid) || ''));
    return { token: jwe, encrypted: true, alg: protection.alg,
             enc: protection.enc };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<IdTokenEncryption>(
  'oauth-oidc/id_token_encryption',
  () => new IdTokenEncryption(IdTokenEncryption.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading a module always did.
slot.buildNowUnlessDeferred();

export = {
  IdTokenEncryption: IdTokenEncryption,
  installInstance: (instance: IdTokenEncryption): void =>
    slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  ALGS: IdTokenEncryption.ALGS,
  ENCS: IdTokenEncryption.ENCS,
  DEFAULT_ENC: IdTokenEncryption.DEFAULT_ENC,
  protectionFor: slot.forward('protectionFor'),
  registrationKeyProblem: slot.forward('registrationKeyProblem'),
  protect: slot.forward('protect')
};

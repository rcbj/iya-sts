'use strict';
//
// File: jwt_access_token.ts
//
// ===========================================================================
// RFC 9068 — THE JSON WEB TOKEN PROFILE FOR OAUTH 2.0 ACCESS TOKENS, BOTH
// HALVES (2026-09-13).
//
// Every access token this service issues has been a JWT since the first day,
// and until this file it was a JWT that RFC 9068 would not recognise: its
// protected header said `typ: "JWT"`, exactly as the ID Token beside it did,
// and the only thing that told the two apart was a `typ` CLAIM (`Bearer`,
// `ID`) that no specification defines. A resource server following section 4
// refused every one of them at step one, and one that did not follow it could
// be handed an ID Token — signed by the same key, verified by the same JWKS —
// and take it for an access token. That is the cross-JWT confusion section 5
// exists for, and the header is the defence the profile chose.
//
// It holds the three decisions this service makes about an access token as a
// FORMAT, so that the authorization server that mints one and the resource
// servers here that check one cannot come to disagree about any of them:
//
//   * THE HEADER — `header()` for the minter, `isAccessTokenType()` for the
//     checker (section 2.1, and section 4 step 1).
//   * WHO ISSUED IT AND WHO IT IS FOR — `issuerFor()` and
//     `defaultAudienceFor()` for the minter, `isHostedIssuer()` and
//     `isOwnResourceAudience()` for the checker (section 2.2, and section 4
//     steps 3 and 4). `issuerFor()` was `issuerOf()` in `oauth2.ts` and MOVED
//     here, because `dpop.ts` — where the resource-server check lives — cannot
//     require that module, and a second copy of "what is this service's issuer
//     identifier" is the one fact a check like this must not have two of.
//   * WHICH SCOPES A TOKEN MAY CARRY FOR WHICH AUDIENCES — `audiencePlan()`,
//     section 2.2.3's "all the individual scope strings in the scope claim MUST
//     have meaning for the resources indicated in the aud claim" and section
//     3's "MUST NOT issue a JWT access token if the authorization granted by
//     the token would be ambiguous".
//
// **IN EVERY MODE, AND THAT WAS ASKED FOR.** rcbj, 2026-09-13, choosing
// between gating these refusals on `oauth2.rfc9700` and not: *"RFC 9068 checks
// in every mode"*. So nothing here reads a mode. That is the opposite of this
// repository's standing rule for refusals and it is a decision rather than an
// oversight: RFC 9068 is not a hardening a deployment opts into, it is what
// the token IS, and a service that published a JWT access token some resource
// servers could validate and others could not depending on a restart-only
// flag would be two token formats under one name.
//
// **A LIBRARY (rule 3).** It registers nothing, and requires `helpers.js`,
// `config.js`, `error_codes.js` and `authorization_servers.ts` — the last of
// which requires only `common/` modules — so it cannot join a cycle and its
// place in the require order is not a place. `oauth2.ts` and `dpop.ts` both
// require it, and `mgmt-api/admin_api.ts` reaches it for its own check.
//
// **WHAT IT DOES NOT DO.** It does not verify a signature or `exp`: every
// caller already verifies with `common/crypto.js` before it gets here, and a
// second verifier would be the thing `crypto.js` was written to end. And it
// judges only a token this service VERIFIED: an access token another
// authorization server issued — which the OID4VCI credential endpoints accept
// by design, see `dpop.ts` — has a header, an issuer and an audience this
// service has no configuration for, so none of the three checks can be asked
// of it honestly.
// ===========================================================================

// ---------------------------------------------------------------------------
// TYPESCRIPT, AS A CLASS (#50, 2026-09-16) — `common/realm_chooser.ts`'s
// shape. `JwtAccessTokens` takes the logger, `jsonFromB64u`, `config`,
// `error_codes` and `authorization_servers` through its constructor. The
// module still exports the four constants and the nine functions it always
// did, the functions as FACADES over the instance the composition root
// builds and installs (R2); a process without the root builds a default one
// at load.
// ---------------------------------------------------------------------------

import helpers = require('../common/helpers');
import InstanceSlot = require('../common/instance_slot');
import config = require('../common/config');
// The registry of error codes: a leaf. A refusal carries its code under the
// Symbol `mark()` sets, so a caller that answers it can mark the response
// without the code ever being serialised.
import errorCodes = require('../common/error_codes');
// For ONE value: the shape of a named authorization server's id, so that an
// issuer or an audience under `<base>/<id>` is recognised as one this process
// publishes. It requires only `common/` modules, so this is still a leaf.
import authorizationServers = require('./authorization_servers');

// A JSON-shaped value: claims, a plan's input, a refusal.
type Json = any;

// What a resource-server check or a plan refuses with.
interface Refusal {
  error: string;
  description: string;
}

// What `audiencePlan()` answers. A caller may add members of its own to it
// (`oauth2.ts` records `derived`), hence the index signature.
interface AudiencePlan {
  audiences: string[];
  scope: string;
  stripped: string[];
  refusal: Refusal | null;
  [member: string]: any;
}

interface JwtAccessTokensDeps {
  log: typeof helpers.log;
  jsonFromB64u: typeof helpers.jsonFromB64u;
  config: typeof config;
  errorCodes: typeof errorCodes;
  authorizationServers: typeof authorizationServers;
}

// Section 2.1: "JWT access tokens MUST include this media type in the typ
// header parameter", and "it is RECOMMENDED that the application/ prefix be
// omitted". The short form is what is minted; either is accepted, because RFC
// 7515 section 4.1.9 says a recipient MUST treat the two as the same.
const TYP = 'at+jwt';
const MEDIA_TYPE = 'application/at+jwt';

// The path of the default resource indicator an access token names when the
// request named none (section 3's "the authorization server MUST use a default
// resource indicator in the aud claim"). `<asBase>/resource` has been that
// indicator since the audience check was written; what is new is that it is
// spelt in ONE place.
const RESOURCE_PATH = '/resource';

// OpenID Connect Core 1.0 section 5.4, plus section 11's offline_access. These
// are requests for THIS SERVICE — the UserInfo endpoint and the refresh token —
// so they are the scopes that have meaning for this service's own resource
// server and for no other. `oauth2.ts`'s `protocolScopes()` lists the same six
// as words no application may take over as an audience; the two lists answer
// different questions and are compared by `tests/rfc9068_access_tokens.js`.
const OIDC_SCOPES = ['openid', 'profile', 'email', 'address', 'phone',
                     'offline_access'];

class JwtAccessTokens {
  static readonly TYP = TYP;
  static readonly MEDIA_TYPE = MEDIA_TYPE;
  static readonly RESOURCE_PATH = RESOURCE_PATH;
  static readonly OIDC_SCOPES = OIDC_SCOPES;

  constructor(private readonly deps: JwtAccessTokensDeps) {
    deps.log.debug("Entering JwtAccessTokens.constructor().");
    deps.log.debug("Leaving JwtAccessTokens.constructor().");
  }

  // What the composition root passes: the deps the module built its
  // own instance from before R2, from the same imports.
  static defaultDeps(): JwtAccessTokensDeps {
    helpers.log.debug("Entering JwtAccessTokens.defaultDeps().");
    helpers.log.debug("Leaving JwtAccessTokens.defaultDeps().");
    return {
      log: helpers.log,
      jsonFromB64u: helpers.jsonFromB64u,
      config: config,
      errorCodes: errorCodes,
      authorizationServers: authorizationServers
    };
  }

  header(): { typ: string } {
    const { log } = this.deps;
    log.debug("Entering JwtAccessTokens.header().");
    log.debug("Leaving JwtAccessTokens.header().");
    return { typ: TYP };
  }

  // RFC 7515 section 4.1.9: media type names are compared case-insensitively,
  // and `application/` may be omitted — so `AT+JWT` and `application/at+jwt`
  // are this profile's type and `JWT` is not.
  isAccessTokenType(typ: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering JwtAccessTokens.isAccessTokenType().");
    const text = String(typ || '').trim().toLowerCase();
    log.debug("Leaving JwtAccessTokens.isAccessTokenType().");
    return text === TYP || text === MEDIA_TYPE;
  }

  // The protected header's `typ`, or '' for anything that is not a compact
  // JWS. Read from the token rather than from `common/crypto.js`'s verifier,
  // which hands back the payload: the header is what section 4 step 1 is
  // about, and it is integrity-protected by the signature every caller has
  // already checked.
  typOf(token: unknown): string {
    const { log, jsonFromB64u } = this.deps;
    log.debug("Entering JwtAccessTokens.typOf().");
    try {
      const first = String(token || '').split('.')[0];
      const parsed: Json = jsonFromB64u(first) || {};
      log.debug("Leaving JwtAccessTokens.typOf().");
      return typeof parsed.typ === 'string' ? parsed.typ : '';
    } catch (e) {
      log.debug("Caught in JwtAccessTokens.typOf(): " +
                ((e && e.message) || e));
      log.debug("Leaving JwtAccessTokens.typOf(). Not a JWS header.");
      return '';
    }
  }

  // -------------------------------------------------------------------------
  // THE ISSUER IDENTIFIER OF THE AUTHORIZATION SERVER AT `base`.
  //
  // MOVED FROM `oauth2.ts`'s `issuerOf()`, which now calls it — the body and
  // the reasoning are unchanged. A PINNED `oauth2.issuer` wins; otherwise the
  // issuer is the base the request arrived on, which a named authorization
  // server extends with its own path.
  //
  // The one exception is an `http://` pin on an HTTPS port, upgraded and
  // logged: a client MUST reject a document whose issuer is not the
  // identifier it fetched from, and that failure names the issuer rather than
  // the scheme.
  // -------------------------------------------------------------------------
  issuerFor(base: string): string {
    const { log, config } = this.deps;
    log.debug("Entering JwtAccessTokens.issuerFor().");
    const pinned = config.value('oauth2.issuer');
    if (!pinned) {
      log.debug("Leaving JwtAccessTokens.issuerFor().");
      return base;
    }
    if (config.value('global.https') && /^http:\/\//i.test(pinned)) {
      const upgraded = pinned.replace(/^http:\/\//i, 'https://');
      log.info('oauth2.issuer is pinned to ' + pinned + ', and this port is ' +
               'an HTTPS listener (global.https), so the issuer identifier ' +
               'is served as ' + upgraded + '. A client MUST reject a ' +
               'document whose issuer is not the identifier it fetched ' +
               'from, and the scheme is part of that identifier.');
      log.debug("Leaving JwtAccessTokens.issuerFor().");
      return upgraded;
    }
    log.debug("Leaving JwtAccessTokens.issuerFor().");
    return pinned;
  }

  // The default resource indicator of the authorization server at `asBase`.
  defaultAudienceFor(asBase: unknown): string {
    const { log } = this.deps;
    log.debug("Entering JwtAccessTokens.defaultAudienceFor().");
    log.debug("Leaving JwtAccessTokens.defaultAudienceFor().");
    return String(asBase || '') + RESOURCE_PATH;
  }

  // `value` itself when it is the base of an authorization server this
  // process publishes at `base` — the default one, or a named one one path
  // segment below it — and '' otherwise. The id is checked against the SAME
  // shape `authorization_servers.ts` refuses a name by, so a string that could
  // never have selected an authorization server cannot be read as one.
  private hostedBaseOf(value: unknown, base: unknown): string {
    const { log, authorizationServers } = this.deps;
    log.debug("Entering JwtAccessTokens.hostedBaseOf().");
    const text = String(value || '');
    const root = String(base || '');
    if (!root) {
      log.debug("Leaving JwtAccessTokens.hostedBaseOf(). No base to compare " +
                "against.");
      return '';
    }
    if (text === root) {
      log.debug("Leaving JwtAccessTokens.hostedBaseOf(). The default " +
                "authorization server.");
      return text;
    }
    if (text.indexOf(root + '/') !== 0) {
      log.debug("Leaving JwtAccessTokens.hostedBaseOf(). Not under this " +
                "base.");
      return '';
    }
    const id = text.slice(root.length + 1);
    if (!authorizationServers.ID_SHAPE.test(id)) {
      log.debug("Leaving JwtAccessTokens.hostedBaseOf(). Not an " +
                "authorization server's id.");
      return '';
    }
    log.debug("Leaving JwtAccessTokens.hostedBaseOf(). The named " +
              "authorization server " + id + ".");
    return text;
  }

  // -------------------------------------------------------------------------
  // SECTION 4 STEP 3: "the issuer identifier for the authorization server ...
  // MUST exactly match the value of the iss claim".
  //
  // **THE RESOURCE SERVERS HERE TRUST EVERY AUTHORIZATION SERVER THIS PROCESS
  // PUBLISHES AT THE ADDRESS THE REQUEST ARRIVED ON**, which is several
  // issuers rather than one — the default one and each named one under
  // `/{id}` — and that is a configuration RFC 9068 permits rather than a
  // loosening of it: the section's own words are "the issuer identifier for
  // the authorization server (which is typically obtained during discovery)",
  // and a resource server that trusts several has several to match exactly.
  // What it refuses is everything else: a token another trust realm's key
  // could not have signed anyway, and — the case the check is actually for —
  // one carrying an issuer this process does not answer to at this address.
  //
  // **AN ADDRESS IS PART OF AN ISSUER**, so a token minted at `localhost` and
  // presented at `127.0.0.1` is refused. `dpop.ts`'s audience check used to
  // match on the PATH precisely to accept that, and RFC 9068 does not: an
  // identifier that is not the one the resource server was configured with is
  // not the one it was configured with. `global.publicBaseUrl` is how a
  // deployment reached under several names gives this service one.
  // -------------------------------------------------------------------------
  isHostedIssuer(iss: unknown, base: string): boolean {
    const { log } = this.deps;
    log.debug("Entering JwtAccessTokens.isHostedIssuer().");
    const text = String(iss || '');
    if (!text) {
      log.debug("Leaving JwtAccessTokens.isHostedIssuer(). No issuer.");
      return false;
    }
    if (text === this.issuerFor(base)) {
      log.debug("Leaving JwtAccessTokens.isHostedIssuer(). The default " +
                "authorization server.");
      return true;
    }
    const asBase = this.hostedBaseOf(text, base);
    const hosted = !!asBase && this.issuerFor(asBase) === text;
    log.debug("Leaving JwtAccessTokens.isHostedIssuer(). hosted=" + hosted);
    return hosted;
  }

  // SECTION 4 STEP 4: the aud claim "contains a resource indicator value
  // corresponding to an identifier the resource server expects for itself" —
  // here, the default resource indicator of an authorization server this
  // process publishes at `base`, compared WHOLE. It was a test that the path
  // ended in `/resource` until this file, which accepted
  // `https://api.partner.example/resource` — somebody else's server, narrowed
  // to by RFC 8707 — as this one.
  isOwnResourceAudience(aud: unknown, base: unknown): boolean {
    const { log } = this.deps;
    log.debug("Entering JwtAccessTokens.isOwnResourceAudience().");
    const text = String(aud || '');
    if (text.length <= RESOURCE_PATH.length ||
        text.slice(-RESOURCE_PATH.length) !== RESOURCE_PATH) {
      log.debug("Leaving JwtAccessTokens.isOwnResourceAudience(). Not a " +
                "default resource indicator.");
      return false;
    }
    const asBase = text.slice(0, -RESOURCE_PATH.length);
    const own = !!this.hostedBaseOf(asBase, base);
    log.debug("Leaving JwtAccessTokens.isOwnResourceAudience(). own=" + own);
    return own;
  }

  private audiencesOf(aud: unknown): string[] {
    const { log } = this.deps;
    log.debug("Entering JwtAccessTokens.audiencesOf().");
    if (aud === undefined || aud === null || aud === '') {
      log.debug("Leaving JwtAccessTokens.audiencesOf(). None.");
      return [];
    }
    log.debug("Leaving JwtAccessTokens.audiencesOf().");
    return (Array.isArray(aud) ? aud : [aud]).map(String);
  }

  private refusal(code: string, description: string): Refusal {
    const { log, errorCodes } = this.deps;
    log.debug("Entering JwtAccessTokens.refusal(). code=" + code);
    const out = { error: 'invalid_token', description: description };
    errorCodes.mark(out, code);
    log.debug("Leaving JwtAccessTokens.refusal().");
    return out;
  }

  // -------------------------------------------------------------------------
  // SECTION 4, FOR A TOKEN THIS SERVICE VERIFIED, AT A RESOURCE SERVER HERE.
  //
  // Steps 1, 3 and 4 in the section's own order — the type, the issuer, the
  // audience. Step 2 (decryption) does not arise: no access token here is
  // encrypted. Steps 5 to 7 (signature, `alg`, `exp`) are the caller's verify,
  // made before this is reached. Step 8, the authorization claims, is each
  // endpoint's own scope check.
  //
  // `null` means accept. A refusal is `{ error, description }` with its code
  // under the Symbol, and `error` is always `invalid_token`: RFC 6750 section
  // 3.1's code for a token that is "expired, revoked, malformed, or invalid
  // for other reasons", which is what section 4's last step says to use.
  //
  // **`options.audience` REPLACES STEP 4 AND NOTHING ELSE** (2026-09-13): RFC
  // 9470's stand-in resource answers for a REGISTERED application rather than
  // for this service, so the identifier it "expects for itself" is that
  // application's — `{ names(audiences) -> boolean, label }`. Steps 1 and 3
  // are the same for every resource server here, because the authorization
  // servers it trusts are the same.
  // -------------------------------------------------------------------------
  resourceServerRefusal(token: unknown, claims: Json, base: string,
                        options?: Json): Refusal | null {
    const { log } = this.deps;
    const self = this;
    log.debug("Entering JwtAccessTokens.resourceServerRefusal().");
    const audience = (options && options.audience) || null;
    const typ = this.typOf(token);
    if (!this.isAccessTokenType(typ)) {
      log.debug("Leaving JwtAccessTokens.resourceServerRefusal(). typ=" +
                (typ || '(none)'));
      return this.refusal('STS-OAUTH-0247',
        'RFC 9068 section 4: a resource server MUST verify that the typ ' +
        'header of a JWT access token is "at+jwt", and this token\'s is ' +
        (typ ? '"' + typ + '"' : 'absent') + '. Every token this service ' +
        'signs is signed with the same key, so the header is what tells an ' +
        'access token apart from an ID Token, a logout token or a Security ' +
        'Event Token. An access token minted before this service issued ' +
        'at+jwt is refused too; ask the token endpoint for a new one.');
    }
    const claimsIn = claims || {};
    if (!this.isHostedIssuer(claimsIn.iss, base)) {
      log.debug("Leaving JwtAccessTokens.resourceServerRefusal(). iss=" +
                (claimsIn.iss || '(none)'));
      return this.refusal('STS-OAUTH-0248',
        'RFC 9068 section 4: the iss claim MUST exactly match the issuer ' +
        'identifier of the authorization server, and this token names ' +
        (claimsIn.iss ? '"' + claimsIn.iss + '"' : 'no issuer') + ' where ' +
        'the authorization servers this service publishes at ' + base +
        ' are "' + this.issuerFor(base) + '" and the named ones under it. ' +
        'An issuer is an address as well as a name, so a token minted under ' +
        'one host name and presented under another is refused; ' +
        'global.publicBaseUrl gives a deployment reached by several names ' +
        'one.');
    }
    const held = this.audiencesOf(claimsIn.aud);
    if (audience) {
      if (!audience.names(held)) {
        log.debug("Leaving JwtAccessTokens.resourceServerRefusal(). aud=" +
                  held.join(', ') + " does not name " + audience.label + ".");
        return this.refusal('STS-OAUTH-0506',
          'RFC 9068 section 4: an access token is audience-restricted, and ' +
          'this resource answers for ' + audience.label + '. This token ' +
          'names ' +
          (held.length ? held.map(function (one) {
            return '"' + one + '"';
          }).join(', ') : 'no audience') + '. Ask for a token addressed to ' +
          'it — a resource parameter or a scope naming the application.');
      }
      log.debug("Leaving JwtAccessTokens.resourceServerRefusal(). Accepted " +
                "for " + audience.label + ".");
      return null;
    }
    if (!held.some(function (one) {
      return self.isOwnResourceAudience(one, base);
    })) {
      log.debug("Leaving JwtAccessTokens.resourceServerRefusal(). aud=" +
                held.join(', '));
      return this.refusal('STS-OAUTH-0114',
        'RFC 9068 section 4 and RFC 9700 section 2.3: an access token is ' +
        'audience-restricted, and a resource server MUST refuse one whose ' +
        'aud does not name it. This token names ' +
        (held.length ? held.map(function (one) {
          return '"' + one + '"';
        }).join(', ') : 'no audience') + ', and the endpoints here are the ' +
        'resource server "' + this.defaultAudienceFor(base) + '" (or that ' +
        'of a named authorization server under ' + base + '). A token ' +
        'narrowed with RFC 8707\'s resource parameter, or addressed to an ' +
        'API by a scope naming it, is usable at THAT resource server and ' +
        'nowhere else.');
    }
    log.debug("Leaving JwtAccessTokens.resourceServerRefusal(). Accepted.");
    return null;
  }

  // -------------------------------------------------------------------------
  // WHICH AUDIENCES AN ACCESS TOKEN IS ADDRESSED TO, AND WHICH SCOPES IT MAY
  // CARRY FOR THEM — section 2.2.3 and section 3, as ONE decision.
  //
  // The input is what the request amounted to, already classified by the
  // authorization server (which alone knows the applications registry):
  //
  //   ownResource   this authorization server's default resource indicator
  //   explicit      audiences the request NAMED — RFC 8707 `resource` values,
  //                 RFC 8693 `audience` values, what a refresh token remembers
  //   scopes        one row per scope value, in request order, each one of
  //                   { value, kind: 'audience' }        a client_id naming an
  //                                                      application; it IS
  //                                                      the audience
  //                   { value, kind: 'permission',
  //                     name, audience }                 a delegated
  //                                                      permission of the
  //                                                      API `audience`
  //                   { value, kind: 'oidc' }            OIDC_SCOPES
  //                   { value, kind: 'ordinary' }        anything else
  //
  // The output is `{ audiences, scope, stripped, refusal }`. **THREE REFUSALS
  // AND ONE REWRITE, AND EACH IS A SENTENCE OF THE RFC:**
  //
  //   1. SCOPES NAMING TWO APIs — section 3: "if the values in the scope
  //      parameter refer to different default resource indicator values, the
  //      authorization server SHOULD reject the request with invalid_scope".
  //      `STS-OAUTH-0244`.
  //   2. A SCOPE NAMING AN API THE REQUEST DID NOT ADDRESS — `resource=A` with
  //      a scope naming B. The token would be for A and carry a permission
  //      that means something only at B, which is section 2.2.3's MUST read
  //      as a refusal: nothing the token could say about that scope is true
  //      of its audience. `invalid_scope`, `STS-OAUTH-0245`.
  //   3. SEVERAL AUDIENCES AND A SCOPE THAT CANNOT BE TIED TO ONE OF THEM —
  //      section 3's "MUST NOT issue a JWT access token if the authorization
  //      granted by the token would be ambiguous", and section 5's "each
  //      scope string included in the resulting JWT access token ... can be
  //      unambiguously correlated to a specific resource". A delegated
  //      permission correlates to its API, an OIDC scope to this service's
  //      own resource server, and an ordinary scope to NOTHING in particular
  //      — which is fine for a token with one audience and ambiguous for a
  //      token with two. `invalid_target`, RFC 8707 section 2's code for a
  //      requested resource the authorization server will not issue for, and
  //      the one thing the client can change is the resource list.
  //      `STS-OAUTH-0246`.
  //
  //   * AND THE REWRITE: A TOKEN FOR AN API DOES NOT CARRY OIDC SCOPES. rcbj
  //     chose it (2026-09-13) over refusing and over the arrangement it
  //     replaces: `scope=openid profile apigw1` is a token for `apigw1` alone,
  //     with `openid` and `profile` left off its scope claim — Microsoft
  //     Entra ID's behaviour. Those scopes are still GRANTED: the ID Token is
  //     minted, and the refresh token keeps the whole scope. What changes is
  //     that the access token no longer ALSO names this service's own
  //     resource server, which `oauth2.ts`'s `withOwnResource()` used to
  //     append so that the same token could call UserInfo. That made `apigw1`
  //     receive a token whose `openid profile` meant nothing to it, which is
  //     exactly the ambiguity above; a client that wants UserInfo asks for a
  //     token without the API in it. `stripped` names what came off, for the
  //     log.
  //
  // **A PERMISSION'S SCOPE IS ITS BARE NAME ON A TOKEN WITH ONE AUDIENCE AND
  // ITS WHOLE IDENTIFIER ON A TOKEN WITH SEVERAL.** `https://a.example/read`
  // becomes `read` for a token addressed to `https://a.example/` — Entra's
  // spelling, and unambiguous because there is only one API it could be read
  // at. On a token for two APIs `read` would be ambiguous and the identifier
  // is not, so the identifier is kept verbatim: it is the one spelling that
  // correlates itself.
  // -------------------------------------------------------------------------
  private planRefusal(error: string, code: string,
                      description: string): Refusal {
    const { log, errorCodes } = this.deps;
    log.debug("Entering JwtAccessTokens.planRefusal(). code=" + code);
    const out = { error: error, description: description };
    errorCodes.mark(out, code);
    log.debug("Leaving JwtAccessTokens.planRefusal().");
    return out;
  }

  private unique(list: unknown): string[] {
    const { log } = this.deps;
    log.debug("Entering JwtAccessTokens.unique().");
    const out: string[] = [];
    ((list as unknown[]) || []).forEach(function (one) {
      const text = String(one);
      if (text && out.indexOf(text) < 0) {
        out.push(text);
      }
    });
    log.debug("Leaving JwtAccessTokens.unique().");
    return out;
  }

  audiencePlan(input: Json): AudiencePlan {
    const { log } = this.deps;
    const self = this;
    const unique = function (list: unknown): string[] {
      return self.unique(list);
    };
    log.debug("Entering JwtAccessTokens.audiencePlan().");
    const ownResource = String(input.ownResource || '');
    const explicit = unique(input.explicit);
    const scopes: Json[] = input.scopes || [];
    const derived = unique(scopes.filter(function (one) {
      return one.kind === 'audience' || one.kind === 'permission';
    }).map(function (one) {
      return one.kind === 'audience' ? one.value : one.audience;
    }));

    if (derived.length > 1) {
      log.debug("Leaving JwtAccessTokens.audiencePlan(). The scopes name " +
                derived.length + " resources.");
      return { audiences: [], scope: '', stripped: [],
        refusal: self.planRefusal('invalid_scope', 'STS-OAUTH-0244',
          'RFC 9068 section 3: the scope parameter names more than one ' +
          'resource — ' + derived.map(function (one) {
            return '"' + one + '"';
          }).join(', ') + ' — and a JWT access token with scopes for ' +
          'several resources is one whose authorization is ambiguous to ' +
          'each of them. Ask for one token per resource.') };
    }
    // RFC 9396's authorization_details, as
    // `authorization_details.audienceFor()` resolved them: the resource
    // server each detail's TYPE belongs to, the audiences its details name,
    // and every identifier that resource answers to. One resource is one API
    // however many locations it has, so its audiences do not make a token
    // "for several resources" below; two resources are refused for the
    // reason two named APIs are, and a `resource` or a scope naming something
    // else beside them is naming a second API.
    const details = input.details || {};
    const detailResources: string[] = details.resources || [];
    const detailIdentifiers: string[] = details.identifiers || [];
    if (detailResources.length > 1) {
      log.debug("Leaving JwtAccessTokens.audiencePlan(). The details " +
                "address " + detailResources.length + " resources.");
      return { audiences: [], scope: '', stripped: [],
        refusal: self.planRefusal('invalid_authorization_details',
          'STS-OAUTH-0459',
          'RFC 9068 section 3: this request\'s authorization_details are of ' +
          'types declared by more than one resource server — ' +
          detailResources.map(function (one) {
            return '"' + one + '"';
          }).join(', ') + ' — and a JWT access token authorizing several ' +
          'of them is ambiguous to each. Ask for one token per resource ' +
          'server.') };
    }
    const fromDetails = detailResources.length === 1;
    if (fromDetails) {
      const foreignScope = derived.filter(function (one) {
        return detailIdentifiers.indexOf(one) < 0;
      });
      if (foreignScope.length) {
        log.debug("Leaving JwtAccessTokens.audiencePlan(). A scope names " +
                  "another resource than the details.");
        return { audiences: [], scope: '', stripped: [],
          refusal: self.planRefusal('invalid_scope', 'STS-OAUTH-0460',
            'RFC 9068 section 2.2.3: this request\'s authorization_details ' +
            'are for "' + detailResources[0] + '", and its scope names "' +
            foreignScope[0] + '", another resource server. One access ' +
            'token is for one API; ask for the other in a request of its ' +
            'own.') };
      }
      const foreignTarget = explicit.filter(function (one) {
        return detailIdentifiers.indexOf(one) < 0;
      });
      if (foreignTarget.length) {
        log.debug("Leaving JwtAccessTokens.audiencePlan(). A resource names " +
                  "another resource than the details.");
        return { audiences: [], scope: '', stripped: [],
          refusal: self.planRefusal('invalid_target', 'STS-OAUTH-0460',
            'RFC 9396 section 3.1: this request\'s authorization_details ' +
            'are for "' + detailResources[0] + '", which answers to ' +
            detailIdentifiers.map(function (one) {
              return '"' + one + '"';
            }).join(', ') + ', and its resource parameter names "' +
            foreignTarget[0] + '". Name one of those, or leave the ' +
            'resource parameter out and the details decide the ' +
            'audience.') };
      }
    }
    if (!fromDetails && explicit.length && derived.length === 1 &&
        explicit.indexOf(derived[0]) < 0) {
      log.debug("Leaving JwtAccessTokens.audiencePlan(). A scope names a " +
                "resource the request did not address.");
      return { audiences: [], scope: '', stripped: [],
        refusal: self.planRefusal('invalid_scope', 'STS-OAUTH-0245',
          'RFC 9068 section 2.2.3: every scope on a JWT access token MUST ' +
          'have meaning for the resources in its aud, and this request ' +
          'addresses ' +
          explicit.map(function (one) {
            return '"' + one + '"';
          }).join(', ') + ' while its scope names "' + derived[0] + '". ' +
          'Either name "' + derived[0] + '" as the resource, or leave the ' +
          'scope that belongs to it out of this request.') };
    }

    const audiences = explicit.length ? explicit :
                      (fromDetails ? unique((details.audiences || [])
                                            .concat(derived)) :
                       (derived.length ? derived : [ownResource]));
    const several = audiences.length > 1 && !fromDetails;
    const forOwn = audiences.indexOf(ownResource) >= 0;
    const kept: string[] = [];
    const stripped: string[] = [];
    const ambiguous: string[] = [];
    scopes.forEach(function (one) {
      if (one.kind === 'audience') {
        // It became the aud and is not a scope of the token.
        return;
      }
      if (one.kind === 'permission') {
        kept.push(several ? one.value : one.name);
        return;
      }
      if (one.kind === 'oidc') {
        if (forOwn) {
          kept.push(one.value);
        } else {
          stripped.push(one.value);
        }
        return;
      }
      if (several) {
        ambiguous.push(one.value);
        return;
      }
      kept.push(one.value);
    });
    if (ambiguous.length) {
      log.debug("Leaving JwtAccessTokens.audiencePlan(). " +
                ambiguous.length + " scope(s) cannot be tied to one of " +
                audiences.length + " audiences.");
      return { audiences: [], scope: '', stripped: [],
        refusal: self.planRefusal('invalid_target', 'STS-OAUTH-0246',
          'RFC 9068 section 3: a JWT access token MUST NOT be issued when ' +
          'the authorization it grants would be ambiguous, and this ' +
          'request addresses ' + audiences.length + ' resources — ' +
          audiences.map(function (one) {
            return '"' + one + '"';
          }).join(', ') + ' — with the scope' +
          (ambiguous.length === 1 ? ' ' : 's ') +
          ambiguous.map(function (one) {
            return '"' + one + '"';
          }).join(', ') + ', which could mean something at any of them. A ' +
          'token for several resources may carry only scopes that name ' +
          'one: a delegated permission by its whole identifier, or an ' +
          'OpenID Connect scope where this service\'s own resource server ' +
          'is one of them. Otherwise ask for one token per resource.') };
    }
    log.debug("Leaving JwtAccessTokens.audiencePlan(). " + audiences.length +
              " audience(s), " + kept.length + " scope(s), " +
              stripped.length + " stripped.");
    return { audiences: audiences, scope: unique(kept).join(' '),
             stripped: stripped, refusal: null };
  }
}

// ---------------------------------------------------------------------------
// THE INSTANCE, BUILT BY THE COMPOSITION ROOT (#50, R2). This module builds no
// instance of its own: `common/protocol_stack.ts` builds one and calls
// `installInstance()`. The exports below are FACADES that forward to that
// instance, for the JavaScript that still calls this module through
// `require()`; a process that never runs the root gets a default instance,
// built from `defaultDeps()` when this module loads (see
// `common/instance_slot.ts`).
// ---------------------------------------------------------------------------
const slot = new InstanceSlot<JwtAccessTokens>(
  'oauth-oidc/jwt_access_token',
  () => new JwtAccessTokens(JwtAccessTokens.defaultDeps()),
  null,
  helpers.log);

// Standalone, build the default now, as loading this module always did.
slot.buildNowUnlessDeferred();

export = {
  JwtAccessTokens: JwtAccessTokens,
  installInstance: (instance: JwtAccessTokens): void => slot.install(instance),
  instanceOrigin: (): string => slot.origin(),
  TYP: JwtAccessTokens.TYP,
  MEDIA_TYPE: JwtAccessTokens.MEDIA_TYPE,
  RESOURCE_PATH: JwtAccessTokens.RESOURCE_PATH,
  OIDC_SCOPES: JwtAccessTokens.OIDC_SCOPES,
  header: slot.forward('header'),
  isAccessTokenType: slot.forward('isAccessTokenType'),
  typOf: slot.forward('typOf'),
  issuerFor: slot.forward('issuerFor'),
  defaultAudienceFor: slot.forward('defaultAudienceFor'),
  isHostedIssuer: slot.forward('isHostedIssuer'),
  isOwnResourceAudience: slot.forward('isOwnResourceAudience'),
  resourceServerRefusal: slot.forward('resourceServerRefusal'),
  audiencePlan: slot.forward('audiencePlan')
};

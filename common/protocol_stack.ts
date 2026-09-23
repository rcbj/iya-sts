'use strict';
//
// File: protocol_stack.ts
//
// ---------------------------------------------------------------------------
// THE REQUIRE ORDER AND THE ROUTE ORDER, IN ONE PLACE — THE COMPOSITION ROOT.
//
// Rule 1 in the root CLAUDE.md used to say that requiring a module registers
// its endpoints, so the require order in this file WAS the route order.
// **Since #50's R1 (2026-09-16) a converted module registers NOTHING when it is
// required**: it exports `registerRoutes(app)`, and this file calls each one,
// at the point in the sequence where requiring that module used to register
// its routes. The route order is therefore the order of the `register()` calls
// below, and the modules still written in JavaScript (the parent project's
// Kerberos closure, `tls_server`, `ldap_server`) still register when they are
// required, at the require that loads them. The two sequences
// are interleaved exactly as they ran before, and the router's layer list was
// compared before and after the change and is identical.
//
// That sequence lived in `server.js` until 2026-09-07 and it moved here for one
// reason: it now has TWO readers.
//
// `server.js` is the front process — it loads this, then binds the sockets.
// `common/request_worker.ts` is a worker — it loads THIS SAME FILE and binds
// none of them. **A second copy of the order would be a second answer to
// "which handler wins",** and the two processes would disagree about it in
// exactly the cases that are hardest to see: a route registered before a
// middleware in one and after it in the other.
//
// So there is one copy, and it is this. Every constraint on the order is
// argued where the module lives; the table in the root CLAUDE.md is the index.
//
// ---------------------------------------------------------------------------
// WHAT THIS FILE DOES NOT DO IS BIND ANYTHING.
//
// Five of these modules own listeners — the two Kerberos ones, the LDAP
// directory, SPIFFE (its per-realm gRPC sockets) and the embedded debugger —
// and so does `pki/pki_service` (the plain-HTTP revocation listener), which
// `server.js` requires for itself. Loading them registers their HTTP views
// (at the require for the JavaScript ones, by `register()` below for the
// converted ones, on its own app for the debugger) and NOTHING ELSE;
// `listen()` is called by `server.js` and by nothing here. That separation
// already existed and is what makes a worker possible at all: a worker loads
// every route and owns no port, so N of them can run beside one front
// process without a single conflict.
//
// Those five are returned rather than merely required, because `server.js`
// needs the handles to start and to report them — and so is `tls/tls_server`,
// which owned the 8443/9443 listeners until they were deleted on 2026-09-16
// and binds nothing now: `server.js` still reads the certificate and the
// client truststore it presents on the main port, and still calls its no-op
// `listen()`.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A CLASS, AS THE TYPESCRIPT CONVERSION ASKS (#50): `ProtocolStack.load(app)`
// is the sequence. The one instance is built and loaded when this module is
// required, which is what `server.js`, `common/request_worker.ts` and the
// tests that load the whole stack rely on; that is TRANSITIONAL until the
// composition root also constructs the modules (#50's R2).
// ---------------------------------------------------------------------------

import appModule = require('./app');
import helpers = require('./helpers');
import InstanceSlot = require('./instance_slot');

// A module whose routes this root registers.
interface RouteModule {
  registerRoutes(app: any): void;
}

// A module whose instance this root builds (#50, R2): it takes the instance
// through `installInstance()` and answers where its instance came from.
// (Not `install`: three modules already export an `install` of their own.)
interface InstalledModule {
  installInstance(instance: object): void;
  instanceOrigin(): string;
}

// What `load()` hands back: the six modules `server.js` needs to start and
// report their listeners.
interface StackSockets {
  krb5: any;
  krb5Service: any;
  tlsServer: any;
  ldapServer: any;
  spiffeServer: any;
  debuggerServer: any;
}

class ProtocolStack {
  private registered: string[] = [];
  private installed: Array<{ what: string; mod: InstalledModule }> = [];

  // One module's routes, now, on `app`. `what` is its path, for the log and
  // for `registeredModules()`.
  private register(app: any, mod: RouteModule, what: string): void {
    helpers.log.debug("Entering ProtocolStack.register(). " + what);
    mod.registerRoutes(app);
    this.registered.push(what);
    helpers.log.debug("Leaving ProtocolStack.register().");
  }

  // One module's instance, built here and handed to it (#50, R2). The module
  // refuses if it already has one, which is what catches a module used before
  // the root reached it.
  private install(what: string, mod: InstalledModule,
                  instance: object): void {
    helpers.log.debug("Entering ProtocolStack.install(). " + what);
    mod.installInstance(instance);
    this.installed.push({ what: what, mod: mod });
    helpers.log.debug("Leaving ProtocolStack.install().");
  }

  // Every module this root builds, and where its instance came from now.
  // After `load()` each must say `root`: a `default` means something in the
  // service built its own, which R2 exists to rule out.
  instanceOrigins(): Array<{ what: string; origin: string }> {
    helpers.log.debug("Entering ProtocolStack.instanceOrigins().");
    const out = this.installed.map(function (row) {
      return { what: row.what, origin: row.mod.instanceOrigin() };
    });
    helpers.log.debug("Leaving ProtocolStack.instanceOrigins().");
    return out;
  }

  // ---------------------------------------------------------------------
  // BUILD ONE MODULE'S INSTANCE (#50, R2). Called right after the require
  // step that loaded the module, in the order the modules FINISHED loading,
  // so everything a module depends on is installed before it is — the order
  // was recorded from the running service (`build()` lines below) and the
  // `wire` step each module moved its load-time work into runs in that
  // order. A module that does not export `installInstance()` is not on R2's
  // pattern
  // yet and is skipped (TRANSITIONAL, for the rollout).
  // ---------------------------------------------------------------------
  private build(what: string, mod: any, className: string): void {
    helpers.log.debug("Entering ProtocolStack.build(). " + what);
    if (!mod || typeof mod.installInstance !== 'function' ||
        typeof mod.instanceOrigin !== 'function') {
      helpers.log.debug("Leaving ProtocolStack.build(). Not on R2's " +
                        "pattern yet.");
      return;
    }
    const Cls = mod[className];
    this.install(what, mod, new Cls(Cls.defaultDeps()));
    helpers.log.debug("Leaving ProtocolStack.build().");
  }

  // Refuses a stack in which any module this root builds holds an instance it
  // did not build.
  private checkOrigins(): void {
    helpers.log.debug("Entering ProtocolStack.checkOrigins().");
    const wrong = this.instanceOrigins().filter(function (row) {
      return row.origin !== 'root';
    });
    if (wrong.length) {
      helpers.log.debug("Leaving ProtocolStack.checkOrigins(). " +
                        wrong.length + " wrong.");
      throw new Error('the composition root did not build every instance: ' +
                      wrong.map(function (row) {
                        return row.what + ' (' + row.origin + ')';
                      }).join(', '));
    }
    helpers.log.debug("Leaving ProtocolStack.checkOrigins().");
  }

  // The modules whose routes this root registered, in order.
  registeredModules(): string[] {
    helpers.log.debug("Entering ProtocolStack.registeredModules().");
    helpers.log.debug("Leaving ProtocolStack.registeredModules().");
    return this.registered.slice();
  }

  load(app: any): StackSockets {
    helpers.log.debug("Entering ProtocolStack.load().");
    // Every module loaded from here on waits for `installInstance()` instead of
    // building its own instance at the end of its load (#50, R2).
    InstanceSlot.deferToRoot();
    // Which LDAP attributes the four claim sets carry. A LIBRARY — it registers
    // no route, so this line adds nothing to /admin/sts-metadata and its
    // position in the route order is not a position at all. It is required
    // HERE, ahead of the modules that issue, because requiring it is what fills
    // admin_stats.js's attribute-resolver slot, and an empty slot means tokens
    // issued without their configured attributes. admin.js requires it too,
    // which would be enough today by accident; this line is what makes it true
    // on purpose, and what keeps it true for a process that loads the protocol
    // modules without the console.
    require('./claim_attributes');
    this.build('oid4vc/vc_claims', require('../oid4vc/vc_claims'), 'VcClaims');
    this.build('common/claim_attributes', require('./claim_attributes'),
               'ClaimAttributes');

    // The groups claim: for anybody who is a member of a group in the embedded
    // directory, a claim naming those groups in every access token, ID Token
    // and both SAML assertions. A LIBRARY too, required HERE for exactly the
    // reason the line above is: requiring it is what fills admin_stats.js's
    // group-resolver slot, and an empty slot means tokens issued without the
    // claim with nothing looking wrong. It must come before the modules that
    // issue; the directory it reads arrives later, through its own slot, and
    // until then it simply reports that no directory is loaded.
    require('./group_claims');
    this.build('common/group_claims', require('./group_claims'), 'GroupClaims');

    // The front door: GET / and the one image on it. It is first among the
    // modules that register routes, and the position is a preference rather
    // than a dependency — it requires nothing but the app, registers two EXACT
    // paths that nothing else here could shadow, and being first is what puts
    // the page a person meets first at the top of the list on
    // /admin/sts-metadata. Before this module existed the root of this service
    // was an unrouted path, so the answer to the one URL somebody types first
    // was Express's `Cannot GET /`.
    require('../home/home');
    this.build('home/home', require('../home/home'), 'Home');
    this.register(app, require('../home/home'), 'home/home');

    // The authentication service: the sign-in screen every protocol here sends
    // a person to, and the session store it fills. FIRST of the modules that
    // use it, because this order is the route order on the /admin/sts-metadata
    // page and the thing that authenticates should be listed before the
    // protocols that lean on it.
    require('../authn/authn');
    this.build('common/totp', require('./totp'), 'Totp');
    this.build('common/backup_codes', require('./backup_codes'), 'BackupCodes');
    this.build('common/password_policy', require('./password_policy'),
               'PasswordPolicy');
    this.build('authn/webauthn_policy', require('../authn/webauthn_policy'),
               'WebauthnPolicy');
    this.build('common/credentials', require('./credentials'), 'Credentials');
    this.build('common/account_state', require('./account_state'),
               'AccountState');
    // #110: which scopes a client may be issued. A library, asked at request
    // time by the authorization server, GNAP and the three resource servers
    // behind this service's own protected scopes.
    this.build('common/scope_policy', require('./scope_policy'),
               'ScopePolicy');
    this.build('cluster/cluster_secrets', require('../cluster/cluster_secrets'),
               'ClusterSecrets');
    this.build('common/websecurity', require('./websecurity'), 'WebSecurity');
    this.build('authn/authn', require('../authn/authn'), 'Authn');
    this.register(app, require('../authn/authn'), 'authn/authn');
    // WS-Trust 1.0-1.4. **IT MOVED BELOW authn.js ON 2026-09-05 AND THE ORDER
    // IS NOW A DEPENDENCY** where it had been no constraint at all. Issuing a
    // token or an assertion here starts a tracked sign-on session — see
    // ws-trust/CLAUDE.md for why an issued credential implies one — and it does
    // that by calling `authn.startSession()` directly, without a screen,
    // exactly as federation/federation_sp.ts does and for the same reason: the
    // caller presented a credential of its own (a UsernameToken) rather than
    // being sent somewhere to type one. Requiring it from ABOVE authn.js would
    // have dragged every /authn route to the front of the router (rule 1, as
    // it was before #50's R1), which is why this line moved rather than a
    // require being added where it stood. Since R1 such a require would move
    // no route — the `register()` calls here place them — but it would still
    // run authn's load-time code (its stores and slots) out of order.
    require('../ws-trust/wstrust');
    this.build('saml/document_settings', require('../saml/document_settings'),
               'DocumentSettings');
    this.build('saml/saml2', require('../saml/saml2'), 'Saml2Assertions');
    this.build('ws-trust/wstrust', require('../ws-trust/wstrust'), 'WsTrust');
    this.register(app, require('../ws-trust/wstrust'), 'ws-trust/wstrust');
    // THE USER PORTAL. **After `authn`**, whose session store every
    // authenticated route on it reads — a dependency of the same kind
    // `saml2_sso.ts` and `consent_screen.js` have, and one-way in the same way:
    // `authn.js` knows nothing about the portal. It registers its own routes
    // under /portal, which nothing else here could shadow.
    //
    // **AND AFTER `oauth-oidc/oauth2.ts` IN EFFECT SINCE 2026-09-06**, though
    // not as an ordering constraint: this portal is an OpenID Connect RELYING
    // PARTY of this service's own authorization server (`common/oidc_rp.ts`),
    // so it needs `/oauth2/authorize` and `/oauth2/token` to be REGISTERED
    // rather than required — and they are, at 9, a few lines below, which is
    // before any request arrives. A process that loaded this module without
    // them would have a portal whose sign-in redirects to a 404.
    // `oidc_rp.js` itself is a LIBRARY (rule 3): it registers nothing, the two
    // callbacks are registered by the two surfaces, and it requires
    // `tls_server` LAZILY inside the one function that dials the back channel —
    // a require at its top would drag every /tls route here.
    require('../portal/portal');
    this.build('common/realm_chooser', require('./realm_chooser'),
               'RealmChooser');
    this.build('ssf/account_signals', require('../ssf/account_signals'),
               'AccountSignals');
    this.build('saml/authn_context', require('../saml/authn_context'),
               'AuthnContext');
    this.build('common/inetorgperson', require('./inetorgperson'),
               'InetOrgPerson');
    this.build('common/oidc_rp', require('./oidc_rp'), 'OidcRelyingParty');
    this.build('common/access_gate', require('./access_gate'), 'AccessGate');
    this.build('ssf/ssf_streams', require('../ssf/ssf_streams'), 'SsfStreams');
    this.build('ssf/ssf_http', require('../ssf/ssf_http'), 'SsfHttp');
    this.build('ssf/ssf_receivers', require('../ssf/ssf_receivers'),
               'SsfReceivers');
    this.build('admin-ui/admin_rbac', require('../admin-ui/admin_rbac'),
               'AdminRbac');
    this.build('common/cert_enrollment', require('./cert_enrollment'),
               'CertEnrollment');
    this.build('common/enrollment_monitor', require('./enrollment_monitor'),
               'EnrollmentMonitor');
    this.build('portal/portal_certificates',
               require('../portal/portal_certificates'),
               'PortalCertificates');
    this.build('portal/portal', require('../portal/portal'), 'Portal');
    this.register(app, require('../portal/portal'), 'portal/portal');
    // The consent screen. It must come AFTER authn.js and BEFORE oauth2.js, and
    // both halves are dependencies rather than preferences. AFTER, because it
    // reads that module's session to check that the person answering is the
    // person the question was asked of, and draws with that module's stylesheet
    // so the two screens a person meets seconds apart in one flow look like one
    // service. BEFORE, because the authorization endpoint calls beginConsent()
    // and takes the browser back afterwards — exactly the arrangement it
    // already has with beginAuthentication(), and the dependency is one-way in
    // the same way: this module knows nothing about OAuth beyond a `returnTo`
    // it is handed and a `consent_error` it hands back.
    require('../oauth-oidc/consent_screen');
    this.build('common/consent', require('./consent'), 'Consent');
    this.build('oauth-oidc/authorization_details',
               require('../oauth-oidc/authorization_details'),
               'AuthorizationDetails');
    this.build('oauth-oidc/consent_screen',
               require('../oauth-oidc/consent_screen'),
               'ConsentScreen');
    this.register(app, require('../oauth-oidc/consent_screen'),
                  'oauth-oidc/consent_screen');
    require('../oauth-oidc/oauth2');
    this.build('oauth-oidc/authorization_servers',
               require('../oauth-oidc/authorization_servers'),
               'AuthorizationServers');
    this.build('oauth-oidc/jwt_access_token',
               require('../oauth-oidc/jwt_access_token'),
               'JwtAccessTokens');
    this.build('oauth-oidc/oauth2_monitor',
               require('../oauth-oidc/oauth2_monitor'),
               'OAuth2Monitor');
    this.build('oauth-oidc/step_up', require('../oauth-oidc/step_up'),
               'StepUp');
    this.build('oauth-oidc/dpop', require('../oauth-oidc/dpop'), 'Dpop');
    this.build('oauth-oidc/software_statement',
               require('../oauth-oidc/software_statement'),
               'SoftwareStatement');
    this.build('oid4vc/vc_configs', require('../oid4vc/vc_configs'),
               'VcConfigs');
    this.build('oid4vc/vc_offers', require('../oid4vc/vc_offers'), 'VcOffers');
    this.build('oauth-oidc/frontchannel_logout',
               require('../oauth-oidc/frontchannel_logout'),
               'FrontchannelLogout');
    this.build('oauth-oidc/backchannel_logout',
               require('../oauth-oidc/backchannel_logout'),
               'BackchannelLogout');
    this.build('oauth-oidc/refresh_token_crypto',
               require('../oauth-oidc/refresh_token_crypto'),
               'RefreshTokenCrypto');
    this.build('oauth-oidc/introspection_jwt',
               require('../oauth-oidc/introspection_jwt'),
               'IntrospectionJwt');
    this.build('oauth-oidc/id_token_encryption',
               require('../oauth-oidc/id_token_encryption'),
               'IdTokenEncryption');
    this.build('oauth-oidc/jarm', require('../oauth-oidc/jarm'), 'Jarm');
    this.build('oauth-oidc/pairwise_subjects',
               require('../oauth-oidc/pairwise_subjects'),
               'PairwiseSubjects');
    this.build('oauth-oidc/request_object',
               require('../oauth-oidc/request_object'),
               'RequestObject');
    this.build('oauth-oidc/par', require('../oauth-oidc/par'),
               'PushedRequests');
    this.build('debugger/debugger_access',
               require('../debugger/debugger_access'),
               'DebuggerAccess');
    this.build('oauth-oidc/oauth2', require('../oauth-oidc/oauth2'),
               'OAuth2Server');
    // The Credential Offer pages BEFORE the authorization server's own routes,
    // and that is not a slip: `oauth2.ts` requires `oid4vc/vc_offers.ts` (rule
    // 2), and until #50's R1 that require was what registered the offer pages,
    // so this is where their routes always landed. Registering them at 11-14
    // below, where the module is nominally required, would move them.
    this.register(app, require('../oid4vc/vc_offers'), 'oid4vc/vc_offers');
    this.register(app, require('../oauth-oidc/oauth2'), 'oauth-oidc/oauth2');
    // WS-Federation's passive requestor profile. It must come AFTER authn.js
    // and the order is a dependency and not a preference: it signs users in to
    // the session that service owns (startSession/sessionOf), so that single
    // sign-on works across the two protocols. The dependency is one-way —
    // authn.js knows nothing about this module — which is what keeps it out of
    // the cycles the split exists to avoid.
    require('../ws-federation/wsfed');
    this.build('saml/saml11', require('../saml/saml11'), 'Saml11Assertions');
    this.build('saml/return_address', require('../saml/return_address'),
               'ReturnAddress');
    this.build('saml/person_attributes', require('../saml/person_attributes'),
               'PersonAttributes');
    this.build('ws-federation/wsfed', require('../ws-federation/wsfed'),
               'WsFederation');
    this.register(app, require('../ws-federation/wsfed'),
                  'ws-federation/wsfed');
    // SAML 2.0 Web Browser SSO — the profile this service spent years
    // documenting the absence of. It must come AFTER authn.js for the reason
    // wsfed.ts must, and it is a stronger dependency here rather than a weaker
    // one: this module has NO sign-in screen of its own at all and reaches that
    // service's through beginAuthentication(). It has no constraint against
    // wsfed.ts in either direction — the two share the session and know nothing
    // about each other — and it sits here so that the two browser SSO profiles
    // read together in the route order and on /admin/sts-metadata.
    require('../saml/saml2_sso');
    this.build('federation/federation_http',
               require('../federation/federation_http'),
               'FederationHttp');
    this.build('saml/sp_metadata', require('../saml/sp_metadata'),
               'SpMetadata');
    // Whether a service provider's request is signed by it (#37). A library
    // `saml2_sso.ts` requires, built before that module's instance.
    this.build('saml/request_signature', require('../saml/request_signature'),
               'RequestSignature');
    this.build('saml/saml2_sso', require('../saml/saml2_sso'), 'Saml2Sso');
    this.register(app, require('../saml/saml2_sso'), 'saml/saml2_sso');
    // SAML 1.1's two browser profiles, and the SAML responder behind one of
    // them. TWO constraints, and the second is the interesting one. It must
    // come AFTER authn.js for the same reason saml2_sso.ts must — no sign-in
    // screen of its own, and beginAuthentication() is how it reaches one. And
    // it must come AFTER saml/saml2_sso.ts, because it takes that module's
    // slugOf(): the slug is a HANDLE FOR AN APPLICATION shared by both profiles
    // and by the console, and two spellings of it would make
    // /saml2/metadata/app-1a2b3c and /saml11/metadata/app-9f8e7d name one entry
    // in one directory. That require is in the ordinary direction and closes no
    // cycle. Nothing else passes between them; the two profiles share a
    // registry and a session and know nothing else about each other.
    require('../saml/saml11_sso');
    this.build('saml/saml11_sso', require('../saml/saml11_sso'), 'Saml11Sso');
    this.register(app, require('../saml/saml11_sso'), 'saml/saml11_sso');
    // FEDERATION, and it is the one module here that consumes rather than
    // issues. ONE constraint, and it is the strongest of the three sign-in
    // dependencies: it must come AFTER authn/authn.ts, because it has no
    // sign-in screen of its own AND it does not go through
    // beginAuthentication() either — a federated sign-in ends by calling
    // startSession() directly, since the person has already authenticated
    // somewhere else and there is no screen to show them.
    //
    // No constraint against the four protocol modules above it in either
    // direction. They know nothing about federation and federation knows
    // nothing about them: what joins the two halves is the SESSION, which is
    // authn.js's, so a federated identity satisfies an OAuth 2.0 authorization
    // request, a WS-Federation sign-in or a SAML AuthnRequest without any of
    // those modules being told this one exists. That is the whole design and it
    // is why this require can sit anywhere below `authn/authn`.
    //
    // It is placed HERE, after the four browser SSO profiles, so that the route
    // order and /admin/sts-metadata read in the order somebody thinks about
    // them: what this service ISSUES, and then what it CONSUMES.
    //
    // Only federation_sp.ts is required. `federation.js`, `federation_map.ts`
    // and `federation_http.ts` are libraries (rule 3) — they register nothing,
    // so their position is not a position — and each is required by whoever
    // needs it: admin_stats.js and authn.js reach the register directly, and
    // ldap_server.js fills its directory slot at its own require time.
    require('../federation/federation_sp');
    this.build('federation/federation_map',
               require('../federation/federation_map'),
               'FederationMap');
    this.build('federation/federation_sp',
               require('../federation/federation_sp'),
               'FederationSp');
    this.register(app, require('../federation/federation_sp'),
                  'federation/federation_sp');
    // A cache hit since `oauth2` above; kept so that the require order still
    // reads 11-14 in one place. Its routes were registered above.
    require('../oid4vc/vc_offers');
    require('../oid4vc/vc_did');
    this.build('oid4vc/vc_did', require('../oid4vc/vc_did'), 'VcDid');
    this.register(app, require('../oid4vc/vc_did'), 'oid4vc/vc_did');
    // THE STATUS LISTS AND THEIR TWO LIBRARIES (#38's follow-ups): the codec
    // (Token Status List, CBOR/COSE, Bitstring Status List), the holder's
    // Data Integrity proof, and the lists themselves, whose routes —
    // /oid4vci/status-lists/* — register here, ahead of the issuer that
    // references them. None requires the issuer or the verifier.
    this.build('oid4vc/vc_status_codec', require('../oid4vc/vc_status_codec'),
               'VcStatusCodec');
    this.build('oid4vc/vc_data_integrity',
               require('../oid4vc/vc_data_integrity'), 'VcDataIntegrity');
    this.build('oid4vc/vc_status', require('../oid4vc/vc_status'), 'VcStatus');
    this.register(app, require('../oid4vc/vc_status'), 'oid4vc/vc_status');
    // The register of credentials issued for a directory entry (#38): a
    // library both the issuer and the verifier read, built before either.
    this.build('oid4vc/vc_issued', require('../oid4vc/vc_issued'), 'VcIssued');
    require('../oid4vc/vc_issuer');
    this.build('oid4vc/vc_issuer', require('../oid4vc/vc_issuer'), 'VcIssuer');
    this.register(app, require('../oid4vc/vc_issuer'), 'oid4vc/vc_issuer');
    require('../oid4vc/vc_verifier');
    this.build('oid4vc/vc_verifier_config',
               require('../oid4vc/vc_verifier_config'),
               'VcVerifierConfig');
    this.build('oid4vc/vc_verifier', require('../oid4vc/vc_verifier'),
               'VcVerifier');
    this.register(app, require('../oid4vc/vc_verifier'), 'oid4vc/vc_verifier');
    // -------------------------------------------------------------------------
    // 14a. AND A PRESENTATION AS A SIGN-IN (2026-09-17, #38): /authn/wallet,
    // which turns a verified presentation of a credential this realm issued
    // into the session every protocol family reads. After `vc_verifier`,
    // whose transactions it is, and after `authn/authn` (#8), whose
    // `startSession()` it calls — `kerberos/spnego_authn`'s arrangement, and
    // for its reason: `authn` declares the two paths and requires nothing
    // here, so no route moves and no cycle closes.
    // -------------------------------------------------------------------------
    require('../oid4vc/vc_signin');
    this.build('oid4vc/vc_signin', require('../oid4vc/vc_signin'), 'VcSignin');
    this.register(app, require('../oid4vc/vc_signin'), 'oid4vc/vc_signin');
    // The Kerberos KDC. Requiring it registers /KdcProxy and /krb5/principals
    // — it is one of the parent project's locked JavaScript files, which still
    // register at require (rule 1) — but NOT the raw TCP/UDP listeners on port
    // 88, which are started by krb5.listen() below. Binding a privileged port
    // can fail, and a require that throws takes the whole service down; a route
    // cannot.
    const krb5 = require('../kerberos/krb5_kdc');
    // The Kerberos-protected service. Like the KDC it registers its HTTP view
    // at require time and starts its socket from listen(), for the same reason.
    const krb5Service = require('../kerberos/krb5_service');
    // The same acceptor over HTTP: SPNEGO. It must come AFTER krb5_service.js
    // and the order is a dependency rather than a preference — it calls that
    // module's accept() for every Kerberos check and adds none of its own.
    // Unlike the two above it starts nothing: it is HTTP all the way down, so
    // requiring it is the whole of its installation.
    require('../kerberos/spnego');
    // -------------------------------------------------------------------------
    // AND THE SAME HANDSHAKE AS A SIGN-IN: /authn/spnego, which turns a
    // Kerberos ticket into the browser session every protocol family here
    // reads.
    //
    // TWO constraints, and both are dependencies rather than preferences. It
    // must come AFTER `spnego.js`, whose page shell and check table it draws
    // with and whose `spnego_exchange.js` performs the negotiation; and it must
    // come AFTER `authn/authn.ts`, which is at #8, because it calls that
    // module's `startSession()` and reads its pending records. The second is
    // why the endpoint is HERE and not over there: `authn.js` is required
    // before `oauth2.js`, which reads the session it owns, so a require in the
    // other direction would drag the KDC's routes to the front of the router
    // and close a cycle besides. What `authn.js` needs to know about this door
    // is a path it declares itself and one setting they both read — no inverted
    // hook, and its own header says why one would have been the wrong answer.
    //
    // It starts nothing, exactly as `spnego.js` starts nothing.
    // -------------------------------------------------------------------------
    require('../kerberos/spnego_authn');
    this.build('kerberos/spnego_authn', require('../kerberos/spnego_authn'),
               'SpnegoAuthn');
    this.register(app, require('../kerberos/spnego_authn'),
                  'kerberos/spnego_authn');
    // -------------------------------------------------------------------------
    // 17b. THE REVOCATION ENDPOINTS. `/pki/crl/{scope}/{ca}.crl`,
    // `/pki/ocsp/{scope}/{ca}`, `/pki/ca/{scope}/{ca}.cer` and the index at
    // `/pki/revocation` — the HTTP half of the two schemes every certificate
    // this service issues names in its CRL distribution points and its
    // Authority Information Access (served on the main port and on the
    // plain-HTTP listener `server.js` binds from `pki/pki_service.ts`). The
    // LDAP half is the directory's, published into `ou=crl` by
    // `ldap/ldap_server.js`.
    //
    // **A PROTOCOL SURFACE AND NOT A CONSOLE ONE**, which is why it is here
    // among the protocol families rather than beside `/admin/pki` below.
    // Nothing in it is behind a gate and nothing in it takes a credential: a
    // relying party fetches a CRL before it has decided to trust anything,
    // often before it has authenticated to anybody, and a revocation list
    // nobody can read is a revocation nobody acts on.
    //
    // NO CONSTRAINT IN EITHER DIRECTION. It requires `common/app`,
    // `common/helpers`, `common/config`, `common/pki` and
    // `common/pki_revocation` — every one of them a LIBRARY (rule 3) that
    // registers nothing — so its require moves no other module's route
    // wherever it is put, and its own routes land where the `register()` call
    // below is. It is HERE, ahead of the console, only so that the endpoint
    // list on `/admin/sts-metadata` groups it with the protocols it belongs to.
    // -------------------------------------------------------------------------
    require('../pki/pki_service');
    this.build('common/proxy_protocol', require('./proxy_protocol'),
               'ProxyProtocol');
    // The JA4 reader (#62 P0): a library like the PROXY protocol above it,
    // installed on the main port by `server.js` and read by `authn/`.
    this.build('tls/client_hello', require('../tls/client_hello'),
               'ClientHello');
    this.build('pki/pki_service', require('../pki/pki_service'), 'PkiService');
    this.register(app, require('../pki/pki_service'), 'pki/pki_service');
    // 17c. THE PUBLIC CRYPTO METADATA DOCUMENT (#42, 2026-09-22):
    // `/crypto/metadata{,.json,.xml,.jwt,.signed.xml,.xsd}`. Beside the
    // revocation endpoints and for their reason: it requires libraries only,
    // with `pki.js`, `oauth2.ts`'s signer and the revocation module each
    // LAZILY, so it is grouped with them on `/admin/sts-metadata`.
    this.build('pki/crypto_metadata_document',
               require('../pki/crypto_metadata_document'),
               'CryptoMetadataDocument');
    this.register(app, require('../pki/crypto_metadata_document'),
                  'pki/crypto_metadata_document');
    // The admin console. It must come AFTER oauth2.js and, like wsfed.ts, the
    // order is a dependency rather than a preference: its metrics page reports
    // the browser sign-on sessions oauth2.js owns, read through the `sessions`
    // map that module exports. The dependency is one way — oauth2.js knows
    // nothing about the console — so it is not a cycle. What holds the STATE it
    // renders is admin_stats.js, which registers no route and is required by
    // app.js, so the counting is already running by the time this line is
    // reached.
    require('../admin-ui/admin');
    this.build('oauth-oidc/protected_resource_metadata',
               require('../oauth-oidc/protected_resource_metadata'),
               'ProtectedResourceMetadata');
    this.build('spiffe/spiffe_id', require('../spiffe/spiffe_id'), 'SpiffeId');
    this.build('spiffe/spiffe_ca', require('../spiffe/spiffe_ca'), 'SpiffeCa');
    this.build('spiffe/spiffe_registry', require('../spiffe/spiffe_registry'),
               'SpiffeRegistry');
    this.build('common/app_permissions', require('./app_permissions'),
               'AppPermissions');
    this.build('kerberos/krb5_keytab', require('../kerberos/krb5_keytab'),
               'Krb5Keytab');
    this.build('kerberos/krb5_person_keys',
               require('../kerberos/krb5_person_keys'),
               'Krb5PersonKeys');
    this.build('admin-core/admin_actions',
               require('../admin-core/admin_actions'),
               'AdminActions');
    this.build('scim/scim_map', require('../scim/scim_map'), 'ScimMap');
    this.build('spiffe/spiffe_auth', require('../spiffe/spiffe_auth'),
               'SpiffeAuth');
    this.build('admin-core/admin_views', require('../admin-core/admin_views'),
               'AdminViews');
    this.build('admin-core/protocol_endpoints',
               require('../admin-core/protocol_endpoints'),
               'ProtocolEndpoints');
    this.build('ldap/directory_create_claims',
               require('../ldap/directory_create_claims'),
               'DirectoryCreateClaims');
    this.build('admin-ui/admin_scope', require('../admin-ui/admin_scope'),
               'AdminScope');
    this.build('federation/federation_graph',
               require('../federation/federation_graph'),
               'FederationGraph');
    this.build('admin-ui/delegation_map', require('../admin-ui/delegation_map'),
               'DelegationMap');
    this.build('admin-ui/federation_diagram',
               require('../admin-ui/federation_diagram'),
               'FederationDiagram');
    this.build('common/user_graph', require('./user_graph'), 'UserGraph');
    this.build('common/credential_graph', require('./credential_graph'),
               'CredentialGraph');
    this.build('admin-ui/admin', require('../admin-ui/admin'), 'AdminConsole');
    this.register(app, require('../admin-ui/admin'), 'admin-ui/admin');
    // -------------------------------------------------------------------------
    // 18a. THE PKI PAGE. `/admin/pki` — the certificate authority this service
    // maintains per trust realm, and the signing key pairs it issues to
    // applications from it (RFC 7521 / RFC 7523).
    //
    // **HERE RATHER THAN AT 20a WITH THE CRYPTO REPORT, AND THAT IS THE WHOLE
    // OF WHY IT NEEDS NO SLOT.** It requires `admin-ui/admin` for the shell —
    // so a require the other way would close a cycle — and `common/pki.js`,
    // which is a LIBRARY (rule 3) and registers nothing. That is the entire
    // list, so `mgmt-api/admin_api.ts` at 19 can require it in the ORDINARY
    // DIRECTION and move no route: by then these lines have loaded it and
    // registered `/admin/pki`, and that require is a cache hit (which, since
    // #50's R1, could register nothing even if it were not).
    // `crypto_metadata.ts` could not do this because it reads an algorithm
    // table out of
    // `tls/tls_server.js` at 20, and requiring that from here would drag every
    // `/tls*` route in front of the management API's own. Rule 3e says a slot
    // is what you pay for a require that would close a cycle or move a route,
    // and not to add one by analogy.
    // -------------------------------------------------------------------------
    require('../admin-ui/pki_admin');
    this.build('common/pki_authoring', require('./pki_authoring'),
               'PkiAuthoring');
    this.build('common/certificate_details', require('./certificate_details'),
               'CertificateDetails');
    this.build('admin-core/certificate_views',
               require('../admin-core/certificate_views'),
               'CertificateViews');
    this.build('common/pqc_support', require('./pqc_support'), 'PqcSupport');
    this.build('admin-ui/pqc_badge', require('../admin-ui/pqc_badge'),
               'PqcBadge');
    this.build('admin-ui/certificate_dialog',
               require('../admin-ui/certificate_dialog'),
               'CertificateDialog');
    this.build('admin-ui/pki_admin', require('../admin-ui/pki_admin'),
               'PkiAdmin');
    this.register(app, require('../admin-ui/pki_admin'), 'admin-ui/pki_admin');
    // -------------------------------------------------------------------------
    // 18b. THE ENCRYPTION REPORT. `/admin/encryption` — what this service seals
    // at rest, with which key, under which algorithm, and how many encryptions
    // and decryptions have happened in this process.
    //
    // **SAME PLACEMENT ARGUMENT AS 18a, AND IT NEEDS NO SLOT FOR THE SAME
    // REASON.** It requires `admin-ui/admin` for the shell — a require the
    // other way would close a cycle — and `common/crypto`, `common/keystore`,
    // `common/secrets`, `common/mode` and `persistence/persistence`, every one
    // of which is a LIBRARY (rule 3) that registers nothing and every one of
    // which is already loaded by this line. So `mgmt-api/admin_api.ts` at 19
    // requires it in the ORDINARY DIRECTION and moves no route.
    //
    // It is a MONITORING page rather than a protocol one, which is a statement
    // `admin-ui/admin.ts`'s `SECTIONS` makes and this line does not: where a
    // page is FILED is decided by the question it answers, and its position in
    // the require order is decided by what it requires.
    // -------------------------------------------------------------------------
    require('../admin-ui/encryption_admin');
    this.build('admin-ui/encryption_admin',
               require('../admin-ui/encryption_admin'),
               'EncryptionAdmin');
    this.register(app, require('../admin-ui/encryption_admin'),
                  'admin-ui/encryption_admin');
    // -------------------------------------------------------------------------
    // 18c. THE DATABASE REPORT. `/admin/database` — everything PostgreSQL will
    // tell this service about itself, and the state of the schema this service
    // owns in it.
    //
    // **SAME PLACEMENT ARGUMENT AS 18a AND 18b, AND IT NEEDS NO SLOT EITHER.**
    // It requires `admin-ui/admin` for the shell and `persistence/persistence`,
    // which is a LIBRARY (rule 3) required at 4a and therefore a cache hit by
    // this line. It does NOT require `pg` and never sees a connection string:
    // every statement behind the page is a literal in
    // `persistence/persistence_postgres.js`, which owns the pool, and the
    // console asks `persistence.databaseMetrics()` for the answer.
    //
    // A MONITORING page rather than a settings one — `/admin/persistence` is
    // what this service is CONFIGURED to write down, and this is what the
    // database has DONE. That placement is `admin-ui/admin.ts`'s `SECTIONS` to
    // state and not this line's.
    // -------------------------------------------------------------------------
    require('../admin-ui/database_admin');
    this.build('admin-ui/database_admin', require('../admin-ui/database_admin'),
               'DatabaseAdmin');
    this.register(app, require('../admin-ui/database_admin'),
                  'admin-ui/database_admin');
    // -------------------------------------------------------------------------
    // 18d. THE SECRET-STORE REPORT. `/admin/secrets` — where the key-encryption
    // key and the database password come from, whether this process actually
    // read them, and what the store at the other end is doing.
    //
    // **SAME PLACEMENT ARGUMENT AS 18a, 18b AND 18c, AND IT NEEDS NO SLOT FOR
    // THE SAME REASON.** It requires `admin-ui/admin` for the shell and
    // `common/secrets`, `common/keystore` and `common/mode`, every one of which
    // is a LIBRARY (rule 3) that registers nothing and every one of which is
    // already loaded by this line — `secrets.js` is pulled in by `helpers.js`
    // at 3. So `mgmt-api/admin_api.ts` at 19 requires it in the ORDINARY
    // DIRECTION and moves no route.
    //
    // It holds no SDK and makes no request itself: every probe behind the page
    // is in `common/secrets.js`, which owns the providers, the client and the
    // login — so the login a probe makes is the same login a startup read
    // makes, and the page cannot be right about a store nobody is talking to.
    //
    // A MONITORING page rather than a settings one, and rather than a second
    // `/admin/encryption`: that page says what is SEALED and with what, and
    // this says what is at the other end of the one paragraph in it about the
    // key. `admin-ui/admin.ts`'s `SECTIONS` states the placement and this line
    // does not.
    // -------------------------------------------------------------------------
    require('../admin-ui/secrets_admin');
    this.build('admin-ui/secrets_admin', require('../admin-ui/secrets_admin'),
               'SecretsAdmin');
    this.register(app, require('../admin-ui/secrets_admin'),
                  'admin-ui/secrets_admin');
    // -------------------------------------------------------------------------
    // 18e. THE EMBEDDED PROTOCOL DEBUGGER'S REPORT (2026-09-13).
    // `/admin/debugger` — the same placement as 18a to 18d, for their reason:
    // it requires `admin-ui/admin` for the shell and nothing that registers a
    // route, and `mgmt-api/admin_api.ts` at 19 requires it in the ordinary
    // direction. It reads the listener's status LAZILY, because
    // `debugger/debugger_server.ts` requires `tls/tls_server.js` at 20. See 23h
    // for the listener itself.
    // -------------------------------------------------------------------------
    require('../debugger/debugger_admin');
    this.build('debugger/debugger_admin', require('../debugger/debugger_admin'),
               'DebuggerAdmin');
    this.register(app, require('../debugger/debugger_admin'),
                  'debugger/debugger_admin');
    // -------------------------------------------------------------------------
    // 18f. THE OAUTH 2.0 / OIDC MONITORING PAGE (2026-09-13).
    // `/admin/oauth2/monitor` — what the authorization server has done, one
    // section per mechanism, RFC 9126's pushed authorization requests first.
    //
    // The same placement as 18a to 18e, for their reason: it requires
    // `admin-ui/admin` for the shell and, through `oauth2_monitor_console.js`,
    // `admin-core/admin_views.ts`, `oauth-oidc/par.ts` and
    // `oauth-oidc/oauth2_monitor.ts` — libraries every one of which is loaded
    // by this line — so it moves no route. It cannot be required from
    // `oauth2.js` at 9, which would drag the whole console in front of the
    // authorization server. `mgmt-api/admin_api.ts` at 19 reaches the model
    // lazily through `oauth-oidc/oauth2_monitor_api.ts`.
    // -------------------------------------------------------------------------
    require('../oauth-oidc/oauth2_monitor_admin');
    this.build('oauth-oidc/oauth2_monitor_console',
               require('../oauth-oidc/oauth2_monitor_console'),
               'OAuth2MonitorConsole');
    this.build('oauth-oidc/oauth2_monitor_admin',
               require('../oauth-oidc/oauth2_monitor_admin'),
               'OAuth2MonitorAdmin');
    this.register(app, require('../oauth-oidc/oauth2_monitor_admin'),
                  'oauth-oidc/oauth2_monitor_admin');
    // -------------------------------------------------------------------------
    // 18g. THE CACHES PAGE (#74, 2026-09-17). `/admin/caches` — every cache
    // `common/cache_registry.js` knows, and one cache's entries. 18a's
    // placement and 18a's reason: the console's shell and libraries already
    // loaded, and `mgmt-api/admin_api.ts` at 19 requires it in the ordinary
    // direction. Every cache owner above has registered by this line, and one
    // that registers later still appears, because the page asks the registry
    // when it is drawn.
    // -------------------------------------------------------------------------
    require('../admin-ui/caches_admin');
    this.build('admin-ui/caches_admin', require('../admin-ui/caches_admin'),
               'CachesAdmin');
    this.register(app, require('../admin-ui/caches_admin'),
                  'admin-ui/caches_admin');
    // 18h. THE STATUS LISTS' PAGE (#38's follow-ups), 18a's placement and
    // reason: the console's shell and `oid4vc/vc_status` already loaded, and
    // `mgmt-api/admin_api` requires it.
    require('../admin-ui/vc_status_admin');
    this.build('admin-ui/vc_status_admin',
               require('../admin-ui/vc_status_admin'), 'VcStatusAdmin');
    this.register(app, require('../admin-ui/vc_status_admin'),
                  'admin-ui/vc_status_admin');
    // 18i. THE SCHEDULER'S PAGE (#49, 2026-09-22). `/admin/scheduler` —
    // every job `cluster/scheduler.ts` knows, its last run and its next.
    // 18a's placement and 18a's reason: the console's shell and the
    // scheduler (a library, loaded by the job owners above) already here,
    // and `mgmt-api/admin_api` requires it in the ordinary direction. A job
    // registered later still appears: the page asks the scheduler when it
    // is drawn.
    require('../admin-ui/scheduler_admin');
    this.build('admin-ui/scheduler_admin',
               require('../admin-ui/scheduler_admin'), 'SchedulerAdmin');
    this.register(app, require('../admin-ui/scheduler_admin'),
                  'admin-ui/scheduler_admin');
    // 18j. RISK SCORING (#62 P1, 2026-09-22): the store, the datasets and
    // the failure history are LIBRARIES (rule 3) that register no route, and
    // then Monitoring → Risk, for 18a's reason — the console's shell and the
    // scheduler (whose two risk jobs the datasets module registers when it
    // is wired) are loaded, and `mgmt-api/admin_api` requires the page.
    // Nothing loads the three libraries before this line: `persistence.js`
    // and `credentials.ts` reach them lazily, at run time.
    this.build('risk/risk_store', require('../risk/risk_store'), 'RiskStore');
    this.build('risk/risk_terms', require('../risk/risk_terms'), 'RiskTerms');
    this.build('risk/risk_datasets', require('../risk/risk_datasets'),
               'RiskDatasets');
    this.build('risk/risk_failures', require('../risk/risk_failures'),
               'RiskFailures');
    this.build('risk/risk_engine', require('../risk/risk_engine'),
               'RiskEngine');
    require('../admin-ui/risk_admin');
    this.build('admin-ui/risk_admin', require('../admin-ui/risk_admin'),
               'RiskAdmin');
    this.register(app, require('../admin-ui/risk_admin'),
                  'admin-ui/risk_admin');
    // The management API: everything that console shows and everything it can
    // change, at /admin-api, over JSON. It must come AFTER admin.js and the
    // order is a dependency rather than a preference — it requires that module
    // for the four action functions and the per-page JSON views, and calls
    // nothing else, which is what makes it incapable of holding a second
    // opinion about what a revocation means. Its OpenAPI document is built from
    // its own route table (admin_api.js -> admin_api_spec.js), so an operation
    // cannot be undocumented.
    require('../mgmt-api/admin_api');
    this.build('mgmt-api/admin_api_spec', require('../mgmt-api/admin_api_spec'),
               'AdminApiSpec');
    this.build('mgmt-api/admin_api_docs', require('../mgmt-api/admin_api_docs'),
               'AdminApiDocs');
    this.build('acme/acme_api', require('../acme/acme_api'), 'AcmeApi');
    this.build('est/est_api', require('../est/est_api'), 'EstApi');
    this.build('scep/scep_api', require('../scep/scep_api'), 'ScepApi');
    this.build('oauth-oidc/oauth2_monitor_api',
               require('../oauth-oidc/oauth2_monitor_api'),
               'OAuth2MonitorApi');
    this.build('mgmt-api/admin_api', require('../mgmt-api/admin_api'),
               'AdminApi');
    this.register(app, require('../mgmt-api/admin_api'), 'mgmt-api/admin_api');
    // 19a. THE API EXPLORER, which is a page of the CONSOLE and not of that
    // API.
    //
    // It was `GET /admin-api/docs` until 2026-09-09, when that API began
    // requiring an access token — and a browser navigating to a URL carries
    // none, so the one page in this service written to be opened in a browser
    // had become the one page a browser could not open. It is
    // `/admin/api-explorer` now, behind the console's session and roles.
    //
    // AFTER BOTH of the modules above and for two different reasons: it
    // requires `admin.js` (18) for the shell and the gate, and `admin_api.js`
    // (19) for the route table its OpenAPI document is built from. Both are
    // plain requires in the ordinary direction — neither of those files knows
    // this one exists, so there is no cycle to close and no route to move. It
    // is a file of its own for `crypto_metadata.ts`'s reason: putting it in
    // `admin.ts` would mean that module requiring the management API, which
    // would have dragged every `/admin-api` route ahead of the console's own
    // before #50's R1 — and still closes a cycle, since the management API
    // requires the console.
    require('../admin-ui/api_explorer');
    this.build('admin-ui/api_explorer', require('../admin-ui/api_explorer'),
               'ApiExplorer');
    this.register(app, require('../admin-ui/api_explorer'),
                  'admin-ui/api_explorer');
    // TLS / mutual TLS. It registers its views (/tls, /tls/sign-in,
    // /tls/server-certificate, /tls/trust and the rest) at require time, and
    // holds the certificate the main port, LDAPS 636 and the debugger listener
    // present and the client truststore the main port asks with. **It owns no
    // socket since 2026-09-16**, when its 8443 and 9443 listeners were deleted
    // and a client certificate began arriving on the main port; its `listen()`
    // is a no-op kept so `server.js`'s call site did not change
    // (`tls/CLAUDE.md`).
    //
    // Its position used to be free. It is not any more: ldap_server.js below
    // serves this module's server certificate on 636, so it requires this file
    // — and node would load it here whatever this line said. Saying it
    // explicitly is what keeps "the order in this file is the route order"
    // true.
    const tlsServer = require('../tls/tls_server');
    // -------------------------------------------------------------------------
    // 20-slot. THE CLIENT-CERTIFICATE TRUSTSTORE, HANDED TO THE CONSOLE
    // (2026-09-12).
    //
    // `admin.setTruststore()` is an inverted hook (rule 3e) and this is the one
    // slot in the service filled HERE rather than by the module that owns what
    // it carries. The ordinary shape — `tls/tls_server.js` requiring
    // `admin-ui/admin` at its own top level and filling it — does not work, and
    // the reason is the real load order rather than the one written above: that
    // module is first loaded from INSIDE `admin.js`'s require, through
    // `admin-core/admin_views.ts` → `spiffe/spiffe_auth.ts`. A require of
    // `admin.js` from there is a cycle and hands back its half-built exports,
    // on which `setTruststore` is not yet defined. Here both modules are whole,
    // and so is every process that runs the stack — `server.js`'s and every
    // request worker's.
    //
    // A process that never loads this file (an in-process test) has an unfilled
    // slot, and `/admin/tls/trust` then says the truststore is not installed
    // rather than drawing an empty one.
    // -------------------------------------------------------------------------
    require('../admin-ui/admin').setTruststore(tlsServer.truststore);
    // -------------------------------------------------------------------------
    // GET /admin/crypto-metadata — the console's report on what this service
    // does with cryptography, for every identity service it advertises.
    //
    // ITS POSITION IS A DEPENDENCY AND NOT A PREFERENCE, and it is an unusual
    // one: this module reads an algorithm table out of eleven other modules,
    // and requiring one of them that this file has not yet loaded would have
    // REGISTERED ITS ROUTES HERE (rule 1). Since #50's R1 that is still true of
    // the JavaScript ones (`tls_server`, `krb5_kdc`), and a converted one would
    // run its load-time code here instead. Here, everything it reaches for is
    // already loaded, so every one of its requires is a cache hit that
    // registers nothing and moves nothing:
    //
    //   after ./admin-ui/admin     for the console SHELL and its gate — express
    //                              applies middleware only to routes added
    //                              after it, so this page is behind the
    //                              sign-on and the two roles by construction
    //   after ./oauth-oidc/oauth2  the ID Token and UserInfo signing lists, and
    //                              dpop.js's DPoP filter over the shared table
    //   after ./authn/authn        webauthn.js's COSE tables
    //   after ./kerberos/krb5_kdc  the encryption type codec
    //   after ./tls/tls_server     the server certificate — THE ONE THAT
    //                              DECIDES THIS LINE'S PLACE. Every other
    //                              dependency is satisfied several requires
    //                              earlier; this is the last of them, which is
    //                              why the module sits immediately below that
    //                              one.
    //
    // It fills admin.js's setCryptoReporter() so that GET /admin-api/crypto can
    // mirror the page without the management API requiring this file — a
    // require in that direction would drag every one of tls_server's routes
    // (and, before #50's R1, this page's) ahead of the management API's own.
    // And ./sts_metadata.ts, last in this file, hands it the protocol family
    // list so that the two pages' idea of what this service advertises is
    // checked rather than agreed by hand.
    // -------------------------------------------------------------------------
    require('../admin-ui/crypto_metadata');
    this.build('ldap/ldap_cluster_connections',
               require('../ldap/ldap_cluster_connections'),
               'LdapClusterConnections');
    this.build('xacml/xacml_store', require('../xacml/xacml_store'),
               'XacmlStore');
    this.build('xacml/xacml_pep_registry',
               require('../xacml/xacml_pep_registry'),
               'PepRegistry');
    this.build('xacml/xacml_pip', require('../xacml/xacml_pip'), 'XacmlPip');
    this.build('scim/scim_auth', require('../scim/scim_auth'), 'ScimAuth');
    this.build('ssf/ssf_auth', require('../ssf/ssf_auth'), 'SsfAuth');
    this.build('admin-ui/crypto_metadata',
               require('../admin-ui/crypto_metadata'),
               'CryptoMetadata');
    this.register(app, require('../admin-ui/crypto_metadata'),
                  'admin-ui/crypto_metadata');
    // The embedded LDAPv3 directory (RFC 4511), built on the node-ldapjs
    // submodule. Like the two Kerberos modules it registers its HTTP views at
    // require time (the `/admin/ldap/*` console pages) and starts its TCP
    // listeners from `server.js`'s listen(), for the same reason: binding port
    // 389 is privileged and can fail, and a require that throws takes the whole
    // service down where a route cannot.
    //
    // It must come AFTER admin.js, and that is a dependency rather than a
    // preference: it installs itself as admin_stats.js's user observer, which
    // is how an entry appears under ou=users for anybody who authenticates
    // through ANY protocol here. Requiring it earlier would work too — nothing
    // authenticates during require — but keeping it beside the console is what
    // makes the pairing visible to the next reader.
    //
    // It must also come after ./tls_server above, and THAT one is not optional:
    // its LDAPS listener on 636 serves the certificate and key that module
    // generates, so requiring it first is what makes the route order in this
    // file the real one rather than a fiction node quietly corrects.
    const ldapServer = require('../ldap/ldap_server');
    // SCIM 2.0 (RFC 7642, 7643, 7644) — the fifteenth family, and the one whose
    // whole purpose is to WRITE. It provisions into the directory above, entry
    // for entry, with no store of its own: a POST /scim/v2/Users and an ldapadd
    // write the same entry, so a person provisioned over SCIM appears on
    // /admin/users, carries the credential-claim attributes /admin/vc selects,
    // and lands in whatever group a client puts them in.
    //
    // It must come AFTER ./ldap_server, and that is a dependency rather than a
    // preference: it requires that module for the twelve functions that make
    // ou=users and ou=groups a store, and requiring it any earlier would pull
    // every /ldap route into the express router at that point. It is NOT one of
    // that file's five inverted hooks — there is no cycle and no route moves,
    // which is rule 3e's test, and this proposal fails it both ways round, so
    // it is a plain require.
    //
    // Unlike the three socket owners above it, it starts nothing: it is HTTP
    // all the way down, so requiring it is the whole of its installation.
    require('../scim/scim');
    this.build('scim/scim', require('../scim/scim'), 'Scim');
    this.register(app, require('../scim/scim'), 'scim/scim');
    // SPIFFE — the sixteenth family, and the third family here (after Kerberos
    // and the directory) whose own listeners are started from `server.js`'s
    // listen() rather than at require time.
    //
    // Three server-side surfaces: the BUNDLE ENDPOINT (plain HTTPS, registered
    // by the `register()` call below), the WORKLOAD API and the SPIRE SERVER
    // API (both gRPC, on a Unix socket and a TCP port each). The gRPC
    // listeners are invisible to /admin/sts-metadata for the same reason the
    // KDC's and the directory's sockets are, so they are described by hand
    // there.
    //
    // It must come AFTER ./ldap_server, and it is a dependency rather than a
    // preference: the SPIFFE registry's store is the directory under ou=spiffe,
    // and that module fills spiffe_registry.js's setDirectory() slot at ITS
    // require time. Requiring this any earlier would leave the registry with no
    // store at the moment the seed entries are written.
    //
    // The 636/8081 certificate is NOT shared with this. The SPIFFE authority
    // signs identities in a trust domain and the TLS certificate identifies a
    // host, so since 2026-09-11 each is its own Issuing CA — `spiffe` under the
    // realm's Intermediate, `tls` under the process's — and the only thing they
    // share is the service Root an operator installs. See spiffe_ca.js and
    // common/CLAUDE.md (3w).
    const spiffeServer = require('../spiffe/spiffe_server');
    this.build('spiffe/spiffe_grpc', require('../spiffe/spiffe_grpc'),
               'SpiffeGrpc');
    this.build('spiffe/spiffe_workload', require('../spiffe/spiffe_workload'),
               'SpiffeWorkload');
    this.build('spiffe/spiffe_api', require('../spiffe/spiffe_api'),
               'SpiffeApi');
    this.build('spiffe/spiffe_server', require('../spiffe/spiffe_server'),
               'SpiffeServer');
    this.register(app, require('../spiffe/spiffe_server'),
                  'spiffe/spiffe_server');
    // -------------------------------------------------------------------------
    // SHARED SIGNALS — THE SEVENTEENTH FAMILY, AND THE FIRST ONE THAT TALKS
    // BACK.
    //
    // Every other module above answers a request. This one AGREES A STREAM and
    // then delivers a Security Event Token to somebody who asked in advance to
    // be told — which is why it was the first protocol module here to make an
    // outbound request, and the second module in the repository to do so
    // (`federation/federation_http.ts` was the first; others have followed,
    // each argued in its own file, and `ssf/ssf_http.ts` argues its own case
    // rather than citing that one, because RFC 8935 push IS the receiver
    // telling the transmitter where to post).
    //
    // **AFTER `admin-ui/admin.ts`, and that is the constraint that decides the
    // line.** It fills that module's eighth slot — the reader and the four
    // actions behind `/admin/ssf` and `/admin-api/ssf` — and it requires it for
    // the page shell and the gate, exactly as `sts_metadata.ts` and
    // `crypto_metadata.js` do. Rule 3e's test was applied both ways round: a
    // require from `admin.js` to here CLOSES A CYCLE, and a require from
    // `mgmt-api/admin_api.ts` to here would MOVE ROUTES — every /ssf endpoint
    // and the well-known document ahead of the management API's own and of
    // ldap, scim and spiffe. So a slot, not an indirection added by analogy.
    // (That was the route half before #50's R1; since then the routes are
    // placed by the `register()` below, and such a require would instead run
    // this module's slot fills at 19 — and load the JavaScript
    // `ldap/ldap_server`, whose routes WOULD still move.)
    //
    // It starts nothing: it is HTTP all the way down, so requiring it and
    // registering it are the whole of its installation. It registers no
    // listener and holds no socket.
    // Its streams and queues are `realms.map({ persist })` stores, so they are
    // kept exactly where persistence/CLAUDE.md keeps minted state and nowhere
    // else.
    require('../ssf/ssf');
    this.build('ssf/caep', require('../ssf/caep'), 'CaepRegister');
    this.build('ssf/risc', require('../ssf/risc'), 'RiscRegister');
    this.build('ssf/ssf_dead_letter_report',
               require('../ssf/ssf_dead_letter_report'),
               'DeadLetterReport');
    this.build('ssf/ssf_cluster', require('../ssf/ssf_cluster'), 'SsfCluster');
    this.build('ssf/ssf', require('../ssf/ssf'), 'SharedSignals');
    this.register(app, require('../ssf/ssf'), 'ssf/ssf');
    // 23b-ii. SIGNING KEY ROTATION (#42, 2026-09-22): a library that registers
    // its two scheduler jobs when built and no route. After `ssf/ssf`, whose
    // signingKeyRotated() it calls (lazily, so the order is for a reader).
    this.build('common/signing_rotation', require('./signing_rotation'),
               'SigningRotation');
    // -------------------------------------------------------------------------
    // 23c. XACML 3.0 — the PDP, the policy repository, the PIP, the embedded
    // PEPs and the PAP console.
    //
    // AFTER `ldap/ldap_server` (21), which fills the directory slots this
    // family owns: the policy repository's (`xacml_store.js`), the remote PEP
    // register's (`xacml_pep_registry.js`) and the PIP's entry lookup
    // (`xacml_pip.js`). The store IS ou=policies, so this module has nothing to
    // load and nothing to hold.
    //
    // AND AFTER `admin-ui/admin` (18), whose `setXacmlPages()` slot
    // `xacml/xacml_admin.ts` fills — for the reason SSF's does at 23b: a
    // require from mgmt-api/admin_api.ts (19) to this module would have
    // dragged every /xacml route ahead of the management API's own (before
    // #50's R1), and would still arm the gate and fill the slots at 19.
    // `xacml.ts` requires `xacml_admin.ts`, `xacml_role_pep.ts` and
    // `xacml_access_pep.ts` itself, so the family is one REQUIRE here — and
    // **requiring `xacml_role_pep.ts` is what arms every issuance site**:
    // before this require `common/issuance_gate.js` answers "allowed". It is
    // two `register()` calls, `xacml_admin` FIRST: requiring `xacml.ts` used
    // to register the PAP's pages (its own require of `xacml_admin`) before
    // its own routes, and this keeps that order.
    //
    // It starts nothing and holds no socket.
    require('../xacml/xacml');
    this.build('xacml/xacml_pep_http', require('../xacml/xacml_pep_http'),
               'PepNotifier');
    this.build('xacml/xacml_monitor', require('../xacml/xacml_monitor'),
               'XacmlMonitor');
    this.build('xacml/xacml_editor', require('../xacml/xacml_editor'),
               'XacmlEditor');
    this.build('xacml/xacml_templates', require('../xacml/xacml_templates'),
               'XacmlTemplates');
    this.build('xacml/xacml_alfa', require('../xacml/xacml_alfa'),
               'AlfaLanguage');
    this.build('xacml/xacml_pep_tls', require('../xacml/xacml_pep_tls'),
               'PepTls');
    this.build('xacml/xacml_admin', require('../xacml/xacml_admin'),
               'XacmlAdmin');
    this.build('xacml/xacml_role_pep', require('../xacml/xacml_role_pep'),
               'XacmlRolePep');
    this.build('xacml/xacml_access_pep', require('../xacml/xacml_access_pep'),
               'XacmlAccessPep');
    this.build('xacml/xacml', require('../xacml/xacml'), 'XacmlSurface');
    this.register(app, require('../xacml/xacml_admin'), 'xacml/xacml_admin');
    this.register(app, require('../xacml/xacml'), 'xacml/xacml');

    // GNAP (RFC 9635 + RFC 9767), 2026-09-12 — 23d. After `authn` (the resource
    // owner signs in through `beginAuthentication()`), after `oauth2` (the ID
    // Token builder and the authorization server profiles), after `saml/saml2`,
    // after `ssf/ssf` at 23b (its streams take GNAP's subject scope and its
    // CAEP delivery is called at event time) and after the console at 18 (whose
    // shell `gnap_admin.js` draws its two pages with). Before `logout`, which
    // reads every store a sign-out ends, and before `sts_metadata`, which reads
    // the router. `gnap.ts` requires `gnap_interact.ts` and `gnap_admin.ts`
    // itself, so this family has one require here, and three `register()`
    // calls in the order the family's routes were registered before #50's R1:
    // `gnap`, then the resource-owner pages, then the two console pages.
    require('../gnap/gnap');
    this.build('gnap/gnap_store', require('../gnap/gnap_store'), 'GnapStore');
    this.build('gnap/gnap_keys', require('../gnap/gnap_keys'), 'GnapKeys');
    this.build('gnap/gnap_sf', require('../gnap/gnap_sf'), 'GnapSf');
    this.build('gnap/gnap_httpsig', require('../gnap/gnap_httpsig'),
               'GnapHttpsig');
    this.build('gnap/gnap_proof', require('../gnap/gnap_proof'), 'GnapProof');
    this.build('gnap/gnap_schemas', require('../gnap/gnap_schemas'),
               'GnapSchemas');
    this.build('gnap/gnap_request', require('../gnap/gnap_request'),
               'GnapRequest');
    this.build('gnap/gnap_access', require('../gnap/gnap_access'),
               'GnapAccess');
    this.build('gnap/token_macaroon', require('../gnap/token_macaroon'),
               'TokenMacaroon');
    this.build('gnap/token_biscuit', require('../gnap/token_biscuit'),
               'TokenBiscuit');
    this.build('gnap/token_zcap', require('../gnap/token_zcap'), 'TokenZcap');
    this.build('gnap/gnap_tokens', require('../gnap/gnap_tokens'),
               'GnapTokens');
    this.build('gnap/gnap_subject', require('../gnap/gnap_subject'),
               'GnapSubject');
    this.build('gnap/gnap_http', require('../gnap/gnap_http'), 'GnapHttp');
    this.build('gnap/gnap_monitor', require('../gnap/gnap_monitor'),
               'GnapMonitor');
    this.build('gnap/gnap_signals', require('../gnap/gnap_signals'),
               'GnapSignals');
    this.build('gnap/gnap_grants', require('../gnap/gnap_grants'),
               'GnapGrants');
    this.build('gnap/gnap_rs', require('../gnap/gnap_rs'), 'GnapRs');
    this.build('gnap/gnap_interact', require('../gnap/gnap_interact'),
               'GnapInteract');
    this.build('gnap/gnap_console', require('../gnap/gnap_console'),
               'GnapConsole');
    this.build('gnap/gnap_admin', require('../gnap/gnap_admin'), 'GnapAdmin');
    this.build('gnap/gnap', require('../gnap/gnap'), 'GnapRoutes');
    this.register(app, require('../gnap/gnap'), 'gnap/gnap');
    this.register(app, require('../gnap/gnap_interact'), 'gnap/gnap_interact');
    this.register(app, require('../gnap/gnap_admin'), 'gnap/gnap_admin');

    // CERTIFICATE ENROLLMENT (2026-09-13) — 23e, 23f, 23g. ACME (RFC 8555), EST
    // (RFC 7030) and SCEP (RFC 8894). After the console at 18, whose shell each
    // family's `<family>_admin.ts` draws its two pages with, and after `ldap`
    // at 21, whose slot `common/cert_enrollment.ts` reads the entries through.
    // Each module requires its own `_admin.ts`, so each family is one require
    // here, and two `register()` calls — the protocol's routes, then its
    // console pages, the order they had before #50's R1. No constraint
    // between the three.
    require('../acme/acme');
    this.build('acme/acme_jws', require('../acme/acme_jws'), 'AcmeJws');
    this.build('acme/acme_store', require('../acme/acme_store'), 'AcmeStore');
    this.build('acme/acme_console', require('../acme/acme_console'),
               'AcmeConsole');
    this.build('acme/acme_admin', require('../acme/acme_admin'), 'AcmeAdmin');
    this.build('acme/acme', require('../acme/acme'), 'Acme');
    this.register(app, require('../acme/acme'), 'acme/acme');
    this.register(app, require('../acme/acme_admin'), 'acme/acme_admin');
    require('../est/est');
    this.build('est/est_codec', require('../est/est_codec'), 'EstCodec');
    this.build('est/est_console', require('../est/est_console'), 'EstConsole');
    this.build('est/est_admin', require('../est/est_admin'), 'EstAdmin');
    this.build('est/est', require('../est/est'), 'Est');
    this.register(app, require('../est/est'), 'est/est');
    this.register(app, require('../est/est_admin'), 'est/est_admin');
    require('../scep/scep');
    this.build('scep/scep_cms', require('../scep/scep_cms'), 'ScepCms');
    this.build('scep/scep_ra', require('../scep/scep_ra'), 'ScepRa');
    this.build('scep/scep_console', require('../scep/scep_console'),
               'ScepConsole');
    this.build('scep/scep_admin', require('../scep/scep_admin'), 'ScepAdmin');
    this.build('scep/scep', require('../scep/scep'), 'Scep');
    this.register(app, require('../scep/scep'), 'scep/scep');
    this.register(app, require('../scep/scep_admin'), 'scep/scep_admin');

    // THE EMBEDDED PROTOCOL DEBUGGER (2026-09-13) — 23h. A socket owner:
    // requiring it builds the debugger listener's OWN express app and registers
    // nothing on this one, and `server.js`'s `listen()` binds it and forks the
    // api process. After `authn` (8, its sessions), `oauth2` (9, whose scope
    // rule it relies on), `tls/tls_server` (20, the certificate it presents)
    // and the console (18, whose roster decides who may use it). No route here
    // depends on its position.
    const debuggerServer = require('../debugger/debugger_server');
    this.build('debugger/debugger_api_process',
               require('../debugger/debugger_api_process'),
               'DebuggerApiProcess');
    this.build('debugger/debugger_server',
               require('../debugger/debugger_server'),
               'DebuggerServer');

    // -------------------------------------------------------------------------
    // THE PROTOCOL-INDEPENDENT LOGOUT — SECOND TO LAST, AND THE POSITION IS THE
    // WHOLE OF ITS ARGUMENT.
    //
    // `GET|POST /logout` lists everything this service is still holding for one
    // identity — across the session store, the token registry, the
    // authorization codes, the pre-authorized codes, the directory's bound
    // connections and the Kerberos principal database — and ends what is asked
    // for. So it READS NINE MODULES, and it must come after every one of them.
    //
    // It is a plain require of each rather than nine inverted hooks, and rule
    // 3e's test is why: a slot is what you reach for when a require would close
    // a cycle or move a route, and neither applies here. Every module it
    // requires has already been loaded by the lines above, so each require is a
    // cache hit that registers nothing and moves nothing; and nothing in this
    // service requires that module back, so there is no cycle to close.
    //
    // It is NOT last. `sts_metadata.ts` is, for everybody, because it reads the
    // router to list what everything else registered — and a logout endpoint
    // missing from that list would be the exact drift that page exists to
    // catch.
    // -------------------------------------------------------------------------
    require('../logout/logout');
    this.build('logout/logout', require('../logout/logout'), 'Logout');
    this.register(app, require('../logout/logout'), 'logout/logout');
    // -------------------------------------------------------------------------
    // 24. GET /admin/sts-metadata — LAST, FOR EVERYBODY. It reads the router to
    // list what everything else registered, so its `register()` is the last
    // one here; its `wire` step hands its protocol family list to the crypto
    // page (20a), which is installed long before this build.
    // -------------------------------------------------------------------------
    require('../sts_metadata');
    this.build('sts_metadata', require('../sts_metadata'), 'StsMetadata');
    this.register(app, require('../sts_metadata'), 'sts_metadata');
    // NO `build()` OF THIS FILE (2026-09-17, #36 follow-up). There was one
    // here — R2's build list was recorded from the order modules FINISHED
    // loading, and this file finishes last — and it was the one line in the
    // service that required a module from inside its own load: `load()` runs
    // at this file's require, so `require('./protocol_stack')` answered the
    // half-built `module.exports` and node printed "Accessing non-existent
    // property 'installInstance' of module exports inside circular
    // dependency" on every start, every worker and every whole-stack test.
    // It built nothing — `ProtocolStack` exports no `installInstance()` and
    // `build()` skipped it — so the line is removed rather than made lazy:
    // the root is not a module the root installs, and a lazy require of
    // itself would still be a cycle, only a quieter one.
    // `tests/composition_root.js` fails if any circular-dependency warning is
    // printed while the stack loads.
    this.checkOrigins();
    helpers.log.debug("Leaving ProtocolStack.load(). " +
                      this.registered.length + " route module(s), " +
                      this.installed.length + " instance(s) built here.");
    return {
      krb5: krb5,
      krb5Service: krb5Service,
      tlsServer: tlsServer,
      ldapServer: ldapServer,
      spiffeServer: spiffeServer,
      debuggerServer: debuggerServer
    };
  }
}

// THE ONE INSTANCE, loaded at require time — TRANSITIONAL, see the header.
// Requiring THIS file is therefore still what registers every route; a
// process that wants the routes and requires only one module has to call
// that module's `registerRoutes(app)` itself.
const stack = new ProtocolStack();
const sockets = stack.load(appModule);

export = {
  ProtocolStack: ProtocolStack,
  registeredModules: stack.registeredModules.bind(stack) as
    ProtocolStack['registeredModules'],
  instanceOrigins: stack.instanceOrigins.bind(stack) as
    ProtocolStack['instanceOrigins'],
  krb5: sockets.krb5,
  krb5Service: sockets.krb5Service,
  tlsServer: sockets.tlsServer,
  ldapServer: sockets.ldapServer,
  spiffeServer: sockets.spiffeServer,
  debuggerServer: sockets.debuggerServer
};

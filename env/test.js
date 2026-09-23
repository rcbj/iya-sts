// Configuration the test launchers select for a run below debug level
// (run-tests.sh's and run-coverage.sh's THE SERVICE'S LOG LEVEL
// blocks; local-run-tests.sh had one too until it was removed, 2026-09-16).
//
// Identical to env/local.js apart from this comment; the two differed in the
// log level until 2026-09-12, when every appconfig file here went to info. See
// that file's header and `config.js` for what each setting means.
var config = {
  // Bunyan log level (trace|debug|info|warn|error|fatal).
  logLevel: "info",

  // --- Global ------------------------------------------------------------
  global: {
    host: "0.0.0.0", // restart to apply
    port: 8081,      // restart to apply

    // TLS ON THE MAIN PORT, SET HERE RATHER THAN LEFT TO DERIVE (2026-08-30).
    // `global.https` is `derived: true` in common/config.js and its default is
    // whatever `oauth2.rfc9700` (or `oauth2.oauth21`) is — both `false` below —
    // so every service started with an appconfig file of this repository's own
    // served PLAIN HTTP on this port while 8443, 9443 and LDAPS 636 were all
    // TLS. That is one trust decision too many for a mock whose whole
    // certificate story is "one key pair per start, shared by every listener":
    // a caller that had already trusted the key for three sockets still met an
    // unencrypted fourth. (8443 and 9443 were deleted on 2026-09-16; the
    // argument stands for LDAPS 636 and the debugger's listener — see
    // env/CLAUDE.md.)
    //
    // WHAT IT COSTS is what config.js's own row says it costs: there is then NO
    // plain listener left in this process, and `GET /tls/server-certificate`
    // and `POST /tls/trust` are the two endpoints a caller reaches BEFORE it
    // trusts anything — so the first fetch of the certificate has to be made
    // with verification off (`curl -k`). That is the ordinary bootstrap for a
    // service that regenerates its key every start, and /tls says so.
    //
    // STS_HTTPS still wins over this file, so `STS_HTTPS=false` is the way back
    // to a plain port without editing anything.
    // The default realm's DNS domain: its directory is dc=example,dc=com.
    domain: "example.com", // restart to apply
    https: true,

    // Believe X-Forwarded-Proto and X-Forwarded-Host. OFF: with nothing in
    // front of this service they are headers any client can set, and believing
    // them lets a caller choose what this service thinks its own issuer,
    // endpoints and DPoP htu are. Turn it ON behind a reverse proxy — see
    // GET /tls/forwarded, which shows what arrived and what was believed.
    trustProxy: false
  },

  // --- OAuth 2.0 / OIDC --------------------------------------------------
  oauth2: {
    issuer: "",

    // RFC 9700 (OAuth 2.0 Security BCP) enforcement on the authorization flow.
    // OFF, which is what keeps every existing caller working: the debugger's
    // own panes use an unregistered redirect_uri, no PKCE and — in one of them
    // — the implicit grant, all of which this mode refuses. Turn it on to
    // exercise a client against a server that behaves like a real deployment.
    // GET /oauth2/rfc9700 lists what it does and does not enforce.
    rfc9700: false,

    // OAuth 2.1 (draft-ietf-oauth-v2-1-16). OFF, for the reason above; it
    // turns RFC 9700 mode on as well, and additionally refuses a client that
    // has not registered its own redirect URI. GET /oauth2/oauth21 lists it.
    oauth21: false,

    // OpenID Connect Front-Channel Logout 1.0: the two discovery members,
    // the `sid` claim on an ID Token issued on a browser session, and the
    // iframe fan-out every sign-out renders. ON. `sid` stays while either
    // this or the back-channel row below is on.
    frontchannelLogout: true,

    // OpenID Connect Back-Channel Logout 1.0 (#36): the two discovery
    // members, and a signed Logout Token POSTed to every relying party on an
    // ending session that registered a backchannel_logout_uri, after the
    // sign-out has answered and through the outbound policy. ON.
    backchannelLogout: true,

    // What the mode compares redirect_uri against, by exact string match, for
    // any client that did not register its own. Empty, so the mode refuses
    // every authorization request until this is filled in; the refusal says so.
    redirectUris: "",

    // RFC 8252 section 7.3's exception, which RFC 9700 says a server MUST
    // honour. Off makes this server non-compliant on purpose.
    loopbackPortWildcard: true,

    // Put a deliberately WRONG nonce in every ID Token, so that a client which
    // accepts one is shown not to be validating it — the one part of RFC 9700's
    // nonce requirement this server cannot enforce. Not part of RFC 9700 mode;
    // useful in either. Off, and loud when on.
    breakIdTokenNonce: false,

    // How far out a client assertion's exp/nbf/iat may be (private_key_jwt and
    // client_secret_jwt), and how long past expiry its jti is remembered.
    clientAssertionSkewS: 60,

    // RFC 9700 mode only. How long a refresh CHAIN may go unused before it
    // stops working (0 turns it off), and whether ending a sign-on session
    // revokes the refresh tokens issued on it.
    refreshIdleSeconds: 86400,
    revokeRefreshOnLogout: true,

    // HOW LONG WHAT THIS SERVICE ISSUES IS GOOD FOR. Three lifetimes and one
    // allowance, all in seconds, all read PER TOKEN — so changing one on
    // /admin/token-lifetimes or through POST /admin-api/token-lifetimes/set
    // applies to the next token issued and to nothing already in a client's
    // hands. Every lifetime must be a whole number of THIRTY-SECOND units
    // (these exist to be set short and watched, and below half a minute a
    // token expires between the response being written and the client reading
    // it); the skew is capped at 300, which is what krb5.clockSkew allows.
    //
    // refreshTokenTtlS IS A BEHAVIOUR CHANGE: it was thirty days as a constant
    // in oauth-oidc/oauth2.ts and is twenty-four hours here. Put 2592000 back
    // for exactly the old behaviour.
    //
    // clockSkewS is NOT clientAssertionSkewS above it: that one is how far out
    // a CLIENT'S assertion may be (RFC 7523), this is how far out this
    // service's own clock may be when it reads back a token it signed.
    accessTokenTtlS: 3600,
    idTokenTtlS: 3600,
    refreshTokenTtlS: 86400,
    clockSkewS: 30
  },

  // --- The admin console -------------------------------------------------
  // The console at /admin asks for a sign-on session and one of two roles,
  // and the roles are two ORDINARY GROUPS in the embedded directory — so an
  // ldapmodify, a SCIM PATCH, /admin/rbac and the management API are four doors
  // onto one membership. Write implies read. openWhenEmpty decides whether
  // every signed-in person may use the console until the bootstrap
  // administrator (admin.bootstrapUsername) first signs in (on), or only role
  // members may from the start (off) — in development mode only: product
  // never opens the console to whoever signs in (#103). config.js's row
  // carries the older rule for a process with no bootstrap administrator.
  // /admin-api takes an access token carrying admin:read / admin:write
  // (adminApi.authRequired), and it is the way back in if the console locks
  // everybody out.
  admin: {
    readGroup: "admin-read",
    writeGroup: "admin-write",
    openWhenEmpty: true
  },

  // --- Applications ------------------------------------------------------
  // The registry of every OAuth client, relying party, service provider and
  // Kerberos service this instance has been asked about. It IS the
  // ou=applications container in the embedded directory — see
  // /admin/ldap/applications — so this is a directory limit: past it a new
  // application is refused rather than an old one evicted.
  applications: {
    max: 500,

    // Create an application entry for the ADMIN CONSOLE at /admin and one for
    // the MANAGEMENT API at /admin-api when this service starts. Every other
    // entry in the registry arrives because a caller presented an identifier,
    // and these two surfaces are this process — so without this the registry
    // listed everything except the two things the reader was standing in. They
    // are seeded as FULL RFC 7591 registrations (the console a confidential
    // OIDC relying party on the code grant, this API a confidential client on
    // client_credentials, each with a secret minted at startup), so they are
    // clients that can be exercised rather than rows on a page — the console
    // signs in through its own code flow at /admin/callback, and /admin-api
    // takes an access token audienced to it (mgmt-api/CLAUDE.md). Restart to
    // apply; seeded only where the identifier is free, so a deleted one stays
    // deleted until the next start.
    seedInternal: true
  },

  // --- SAML --------------------------------------------------------------
  saml: {
    issuer: "urn:wstrust:mock:sts"
  },

  // --- WS-Trust ----------------------------------------------------------
  wstrust: {
    issuer: "urn:wstrust:mock:sts"
  },

  // --- WS-Federation -----------------------------------------------------
  wsfed: {
    entityId: "urn:wstrust:mock:sts"
  },

  // --- TLS ---------------------------------------------------------------
  tls: {
    hostnames: "localhost,sts,sts-mock,sts.example.com", // restart to apply
    ips: "127.0.0.1"                                     // restart to apply
  },

  // --- OID4VCI -----------------------------------------------------------
  oid4vci: {
    walletUrl: "http://localhost:3000",
    authorizationServer: "",
    batchSize: 4,
    deferredReadyMs: 4000,
    deferredIntervalS: 2,
    offerUsername: "diploma.student",
    requestEncryptionRequired: false,

    // Name the issuer of the PLAIN credential configurations by did:web
    // rather than by https URL — what a deployment that had gone to DIDs
    // throughout would look like. Both OFF, for two different reasons
    // config.js gives; the IdentityCredentialDid configurations always use
    // a DID whatever these are, so both routes are live in one issuer.
    // Restart to apply: vc_did.js reads them once, and the issuer metadata
    // is built from what it read.
    sdJwtIssuerDid: false,
    ldpVcIssuerDid: false
  },

  // --- OID4VP ------------------------------------------------------------
  oid4vp: {
    clientId: "sts-verifier",
    // walletUrl: falls back to oid4vci.walletUrl. Uncomment to point the mock
    //   Verifier at a different wallet from the issuer's.
    kbMaxAgeS: 600,
    claims: "given_name,family_name"
  },

  // --- Kerberos ----------------------------------------------------------
  krb5: {
    // restart to apply
    realm: "EXAMPLE.COM",
    kdcPort:
      88,                                                   // restart to apply
    servicePort:
      8888,                                             // restart to apply
    servicePrincipal:
      "HTTP/web.example.com",                      // restart to apply
    clockSkew: 300,
    clockOffset: 0,
    // restart to apply
    userPassword: "password!",
    unknownUsers: "nosuchuser,nobody",
    // serviceDomains: derived from krb5.realm. Uncomment to replace the whole
    // list;
    //   an empty string creates no service accounts at all.
    autoServicePassword:
      "auto-service-password",                  // restart to apply
    krbtgtPassword:
      "krbtgt-mock-password",                        // restart to apply
    domainSid:
      "S-1-5-21-1004336348-1177238915-682003330",         // restart to apply
    trustedRealm:
      "PARTNER.COM",                                   // restart to apply
    trustPassword:
      "inter-realm-trust-password",                   // restart to apply
    trustedDomainSid:
      "S-1-5-21-2035427030-2118130302-1178042555", // restart to apply
    trustedKrbtgtPassword:
      "partner-krbtgt-password",              // restart to apply
    s2kparams: "omit"
  },

  // --- LDAP --------------------------------------------------------------
  ldap: {
    port: 389,                   // restart to apply
    tlsPort: 636,                // restart to apply
    // ON. It was `false` in all three env files, which is what an
    // appconfig value does: it beats the default, and the default is
    // what every document here describes. So a person signed in through
    // any protocol and the directory stayed empty — which reads as a
    // broken hook and is a setting doing what it was told.
    autocreateUsers: true,
    maxEntries: 2000,
    sizeLimit: 500
  },

  // --- SCIM --------------------------------------------------------------
  //
  // SCIM 2.0 provisions into the directory above — the same entries, the same
  // cap — so `ldap.maxEntries` is what a POST /scim/v2/Users runs out of and
  // there is nothing here about storage. What IS here is authentication: see
  // the second half of the block, and GET /scim for what each scheme costs a
  // caller (which is very little — it is a turnstile, not a lock).
  scim: {
    enabled: true,
    maxResults: 200,
    bulkMaxOperations: 100,
    bulkMaxPayloadSize: 1048576,

    // The SCIM endpoints refuse a caller who presents nothing — they create
    // and delete accounts. All six schemes RFC 7644 section 2 names are
    // offered, and in development mode every one of them is permissive:
    // anybody can get a token with either scope, any password but "invalid"
    // works over Basic, any username works over Digest with the shared
    // password below, and anybody may register a HOBA key. There is no longer
    // a way to turn the requirement off (`scim.authRequired` was removed on
    // 2026-09-06); product mode CHECKS what is presented — scim/CLAUDE.md.
    authDiscovery: false,
    authRealm: "SCIM",
    scopeRead: "scim:read",
    scopeWrite: "scim:write",
    authBearer: true,
    authBasic: true,
    authDigest: true,
    digestPassword: "password!",
    digestNonceSeconds: 300,
    authHoba: true,
    hobaMaxAgeSeconds: 600,
    authCookie: true,
    authClientCert: true
  },

  // --- The group claim ---------------------------------------------------
  //
  // A groups claim in every access token, ID Token and SAML assertion, for
  // anybody who is a member of a group in the embedded directory. Omitted
  // entirely for somebody who is in none, which is why ON by default changes
  // nothing for a caller who never touched ou=groups. A group still GRANTS
  // nothing here — see /admin/groups — the token merely carries it.
  groups: {
    claim: true,
    claimName: "groups",
    claimValue: "cn",       // "cn" or "dn"
    claimFromMemberOf: true
  },

  // --- Audit log ---------------------------------------------------------
  audit: {
    maxEvents: 5000,
    protocolCalls: true
  },

  // --- Logout --------------------------------------------------------------
  //
  // `GET|POST /logout` — the protocol-independent sign-out. Three of these are
  // REFUSALS the feature introduced, and every refusal in this service is
  // switchable for the reason RFC 9700 mode's are: a client is exercised by
  // both answers.
  logout: {
    // Whether ?username= may name somebody other than the caller. It grants
    // nothing that was not already true in development mode — no password is
    // checked at any sign-in screen there — and what it buys is a headless
    // test.
    anyUser: true,
    // Whether a logout stamps a sign-out instant on the Kerberos principal,
    // after which a TGS-REQ carrying an older ticket is refused
    // KDC_ERR_TGT_REVOKED (20). It does NOT reach a service ticket already in
    // a cache: accepting one never contacts the KDC.
    kerberosSignOut: true,
    // Whether it closes directory connections bound as that person. RFC 4511
    // section 4.2 makes the bind the authorization state of a CONNECTION, so
    // closing it is the only sign-out LDAP has.
    ldapDisconnect: true,
    // How many live items one inventory draws. The cap is on what is LISTED,
    // never on what a termination reaches.
    maxRows: 500
  },

  // --- Web security --------------------------------------------------------
  //
  // THE RATE LIMITS ARE RAISED HERE AND NOWHERE ELSE (2026-09-06), AND THE
  // PLACEMENT IS THE WHOLE POINT.
  //
  // `env/defaults.js` ships 5 per identity and 20 per address per 60s, and
  // those are the right numbers for what the limiter was written for: a
  // SIGN-IN, where five attempts a minute is generous and a sixth is somebody
  // guessing. **They are wrong for a test suite**, because every job in it
  // comes from ONE ADDRESS — the runner — so the address bucket counts the
  // whole suite as one caller while the identity bucket, the one that is
  // actually about credential guessing, is nowhere near its limit.
  //
  // MEASURED, rather than guessed at (2026-09-06, the whole suite against one
  // instance with the limiter effectively off):
  //
  //   activation   per address   peak 25   — over the shipped limit of 20
  //   activation   per identity  peak  2   — nowhere near the limit of 5
  //   xacml-pip    per address   peak  7
  //   sign-in      per address   never accumulated, because a SUCCESSFUL
  //                              sign-in calls succeeded() and clears it
  //
  // So one door did it: `activation`. `sts_portal_sessions.js` and
  // `sts_admin_console.js` each issue and open several activation links, and
  // the address bucket is not cleared by an activation that WORKS the way a
  // sign-in's is. The symptom was a 429 on a link the console had just handed
  // over — which reads exactly like a broken handler and is not one.
  //
  // 500 and 100 are 20× and 50× the measured peaks, so the suite has room to
  // grow several times over before this needs looking at again, and both are
  // still a real control: 500 activation attempts a minute from one address is
  // abuse by any reading.
  //
  // **THIS IS A LAYER, NOT A CHANGE TO THE SETTING.** `env/defaults.js` is
  // GENERATED from `config.js` and still says 5 and 20, so a service handed
  // somebody else's appconfig file — or none — gets the shipped limits. It is
  // the same decision `global.https` records above: what OUR OWN STACKS do
  // belongs in the appconfig files, and what this service IS belongs in
  // config.js. Raising the default instead would have weakened a security
  // control for every deployment, including product mode, to fix a test run.
  //
  // The limiter itself is guarded by `tests/rate_limiter.js`, which drives
  // `websecurity.attempt()` in process with limits of its own — so turning
  // these up here does not leave the control untested. It was untested before
  // this change and the 429s were the only thing exercising it.
  security: {
    rateLimitWindowS: 60,
    rateLimitPerIdentity: 100,
    rateLimitPerAddress: 500,
    activationTtlMinutes: 1440
  },

  // --- ACME's refusal throttle ----------------------------------------------
  // THE SAME ONE-ADDRESS PROBLEM AS `security` ABOVE, ONE FAMILY ALONG
  // (2026-09-13). `acme.attemptsPerAddress` counts REFUSED ACME requests from
  // one address and ships at 120 a window. `tests/vendored/sts_route_inputs.js`
  // sends every route a malformed request on purpose, and measured against one
  // instance it leaves 132 refused ACME requests on the runner's address — so
  // the next job to read `/enroll/acme/directory`, `sts_metadata_anonymous.js`,
  // got 429 twelve seconds later about a document that was correct. EST and
  // SCEP were 10 each against 60 and are left alone.
  //
  // 5000 is ~40× that peak. It is a LAYER for our own stacks, not the setting:
  // `env/defaults.js` still ships 120, and the enrollment jobs that assert the
  // throttle set their own limits inside the realms they create.
  acme: {
    attemptsPerAddress: 5000
  },

  // --- SPIFFE / SPIRE ------------------------------------------------------
  //
  // The bundle endpoint, the Workload API and the SPIRE Server API. Four of
  // these are bound sockets and three are material derived at startup (the
  // trust domain and the two key types), which is why config.js marks them
  // restart-only.
  spiffe: {
    // Whether the three SPIFFE surfaces answer.
    enabled: true,
    // The trust domain this service issues for.
    trustDomain: 'example.org',
    // The X.509 authority's key. What SPIRE issues by default.
    x509KeyType: 'ec-p256',
    // The JWT authority's key, which decides the alg of every JWT-SVID.
    jwtKeyType: 'ec-p256',
    // How long the X.509 authority's own certificate is valid, in seconds.
    caTtl: 86400,
    // The default X509-SVID lifetime, in seconds.
    svidTtl: 3600,
    // The default JWT-SVID lifetime, in seconds. Shorter because it is a bearer
    // credential.
    jwtSvidTtl: 300,
    // spiffe_refresh_hint in the published bundle, in seconds.
    refreshHint: 300,
    // The X.501 subject on every SVID. SPIRE's own value; the identity is the
    // URI SAN.
    svidSubject: 'C=US,O=SPIRE',
    // Invent a registration entry for a workload that matches none. Off is how
    // a client's "I have no identity" path is exercised.
    autoCreateEntries: true,
    // Refuse a Workload API call with no workload.spiffe.io: true header, as
    // every conforming implementation does.
    requireSecurityHeader: true,
    // Trust a caller on the SPIRE Server API's Unix socket as the `local`
    // entity, the way a real spire-server trusts its private socket. (The TCP
    // port's mutual TLS and per-method authorization are no longer a setting:
    // `spiffe.authRequired` was removed on 2026-09-06.)
    trustLocalSocket: true,
    // SPIFFE IDs that are administrators of the SPIRE Server API,
    // comma-separated. SPIRE's admin_ids; no registration entry needed.
    adminIds: '',
    // How far out a caller's clock may be when its X509-SVID is checked, in
    // seconds.
    clockSkew: 60,
    // Answer a Workload API caller with the entries its observable selectors
    // match, rather than with every entry.
    attestWorkloads: true,
    // Believe selectors a workload sends in a metadata header. NOT attestation;
    // it exists so selector matching can be exercised at all.
    acceptAssertedSelectors: false,
    // How many registration entries may live under ou=spiffe.
    maxEntries: 500,
    // How many attested agents are held.
    maxAgents: 200,
    // How many foreign trust domains' bundles are held.
    maxFederatedBundles: 32,
    // Where the trust bundle is published.
    bundlePath: '/spiffe/bundle',
    // Serve the Workload API on a Unix socket. What SPIFFE_ENDPOINT_SOCKET
    // means to every real client.
    workloadSocketEnabled: true,
    // Where that socket lives. SPIRE's own default path.
    workloadSocket: '/tmp/spire-agent/public/api.sock',
    // The Workload API over TCP. 0 turns it off.
    workloadPort: 8092,
    // The SPIRE Server API over gRPC. SPIRE's own default is 8081, which this
    // service's HTTP port already has.
    serverPort: 8181,
    // Also serve the SPIRE Server API on a Unix socket.
    serverSocketEnabled: false,
    // Where that socket lives when it is on.
    serverSocket: '/tmp/spire-server/private/api.sock',
    // The address both TCP gRPC listeners bind.
    grpcHost: '0.0.0.0'
  },

  // -------------------------------------------------------------------------
  // PERSISTENCE, since 2026-08-27, and the one thing to know before changing
  // it: THREE THINGS CAN SURVIVE A RESTART in development mode, and nothing
  // this service MINTS does. The embedded LDAP directory (which is also the
  // applications registry, the federation register and the SPIFFE registry —
  // they are directory entries and nothing else), the trust realm registry,
  // and the runtime setting changes made in the console. Sessions, access
  // tokens, ID Tokens, refresh tokens, authorization codes, SAML artifacts,
  // Kerberos tickets, the statistics and the audit log go with the process,
  // because the signing key is regenerated on every start and a token that
  // outlived it would verify against nothing. PRODUCT MODE ON A POSTGRES STORE
  // keeps its signing keys and therefore persists those too (2026-09-06) —
  // persistence/CLAUDE.md.
  //
  // OFF HERE, which is the default and is what this service did for its whole
  // life until that date. docker-compose.yml turns it on with environment
  // variables; a host run that wants it needs only `mode: 'ldif'`, which
  // writes RFC 2849 files into `dataDir` and needs no database.
  //
  // ALL BUT writeDelay ARE RESTART-ONLY: the store is opened and READ before
  // the HTTP listener binds, so a mode changed at runtime would leave a
  // service whose directory came from one place and whose writes went to
  // another.
  // -------------------------------------------------------------------------
  persistence: {
    // ---------------------------------------------------------------------
    // memory | ldif | postgres.
    //
    // memory writes NOTHING and is what this service did for its whole life
    // until 2026-08-27. It is the value here so that a run with this file
    // behaves exactly as one with the file that predated persistence — the
    // rule this whole file follows.
    //
    // Change this ONE WORD to turn the base PostgreSQL configuration below
    // on; `databaseUrl` is already filled in for a local database. Or set it
    // to 'ldif', which needs no database at all and writes an RFC 2849 file
    // per trust realm into `dataDir`.
    // ---------------------------------------------------------------------
    mode: 'memory',

    // Where ldif mode writes. Relative paths resolve against the PACKAGE ROOT
    // rather than the working directory, for the reason CONFIG_FILE does (see
    // common/config_file.js): the modules that read it sit in different
    // directories. In a container this is what a volume mounts over.
    dataDir: './data',

    // ---------------------------------------------------------------------
    // THE BASE POSTGRESQL CONFIGURATION. Ready to use, and INERT until `mode`
    // above is 'postgres' — nothing dials this on an ordinary run.
    //
    // It matches the owner of the Postgres service in this repository's
    // docker-compose.yml — user `sts`, password `sts`, database `sts`. That
    // stack itself dials as the least-privilege `sts_app` role over TLS
    // (postgres/CLAUDE.md); this host-run value uses the owner, which may
    // create the tables. Bring one up to match:
    //
    //   docker run -d --name sts-db -p 5432:5432 \
    //     -e POSTGRES_USER=sts -e POSTGRES_PASSWORD=sts -e POSTGRES_DB=sts \
    //     postgres:18
    //
    // THE HOST IS `localhost` BECAUSE THIS IS THE HOST-RUN VALUE. Inside the
    // compose stack the database is reached as `postgres`, the service name on
    // that network, and that stack sets STS_DATABASE_URL itself — an
    // environment variable beats this file, so both work without either being
    // wrong.
    //
    // The tables are created on first connection by a role allowed to create
    // them. Nothing is migrated: if the schema ever changes, drop them.
    //
    // The password is here in plain text on purpose. It guards a throwaway
    // database of MOCK identities, and nothing in this repository is a real
    // credential; an operator with a real one sets STS_DATABASE_URL. This
    // service never echoes the string back either — /admin/persistence and
    // GET /admin-api/persistence report the host, port, database and user
    // parsed out of it.
    // ---------------------------------------------------------------------
    databaseUrl: 'postgres://sts:sts@localhost:5432/sts',

    // How long a change waits before the ldif store is rewritten, so a burst —
    // a realm build writes thirteen entries — costs one file write. POSTGRES
    // IGNORES IT and commits per request: the unit of writing there is a
    // transaction rather than a file.
    writeDelay: 1500,

    // Write the trust realm registry down too. Off is a half-persisted service
    // rather than a smaller one: a realm holds its own directory, so its
    // entries would be stored with no realm to restore them into.
    realms: true,

    // Make a setting changed in the console or through the management API
    // survive a restart. It adds NO LAYER — the saved values are re-applied at
    // startup through the same setOverride() a caller uses, so the five layers
    // are unchanged and a runtime override is simply durable.
    appconfig: true
  }
};

module.exports = config;

# CLAUDE.md — `env/`

## What is in here

| File | What it is |
|---|---|
| `defaults.js` | **GENERATED, and never hand-edited.** One row per setting in `common/config.js`'s `SETTINGS`, written from its `dflt` column by `generate_defaults.js`. It is not selected by anything — it is the layer UNDER whichever file is. |
| `generate_defaults.js` | `node env/generate_defaults.js` writes the above. Adding a setting is one edit: add the row to `SETTINGS`, regenerate. |
| `local.js` | the appconfig for a host run — `CONFIG_FILE=./env/local.js node server.js` |
| `test.js` | the appconfig the throwaway service in `tests/tools/service.js` runs under |
| `docker-tests.js` | the appconfig the container in `docker-compose.yml` runs under |

**`CONFIG_FILE` selects one of the last three and it is a LAYER, not the whole
configuration.** The selected file is unioned on top of `defaults.js`, key by
key, with the selected file winning; above both sit the environment variables,
and above those the runtime overrides the console and `/admin-api` set in
memory. **A setting with a row in `SETTINGS` and no row in `defaults.js` stops
the service from starting and names itself** — there is no sixth level, no
constant in a module underneath the table. `common/CLAUDE.md` argues the whole
layering and is the one place it is written down; this file lists the files.
README.md's *Configuration* lists every setting, its environment variable and
its default.

**`common/config_file.js` makes `CONFIG_FILE` absolute before anything reads
it**, because a relative path resolves against the directory of the module doing
the requiring and thirteen modules read it directly. It is the first require in
`server.js` for that reason.

## THESE FILES ARE WHAT MADE THE MAIN PORT HTTPS (2026-08-30)

**All three appconfig files here carry `global.https: true`, and both compose
files set `STS_HTTPS` to the same answer** so a container's healthcheck probes
the scheme its service is bound in. That is where the switch lives — **the
SETTING was not touched.** `global.https` is still `derived: true` with
`oauth2.rfc9700` as its default, so a service handed somebody else's appconfig
file (the parent project's in-process Kerberos jobs) still gets plain HTTP, and
`tests/config_realm_layer.js` still asserts what it always did. What changed is
what these files SAY.

The argument was one sentence: 8443, 9443 and LDAPS 636 were TLS on a certificate
the main port did not use, so a caller who had trusted this service's key for
three sockets still met an unencrypted fourth on the port every protocol family
actually answers on. **Two of those sockets were deleted on 2026-09-16 and the
sentence is stronger for it**: LDAPS 636 and the debugger's listener are TLS on
that certificate, and the port every protocol family answers on — which is now
also the port a client certificate is presented to — has no business being the
one in the clear. **`STS_HTTPS=false` is the way back and is a supported
configuration, not an escape hatch.**

**And these files no longer carry a `tls.port` or a `tls.mutualPort`**, which
went with the listeners: a deployment that sets either gets the "unknown
setting" warning at startup rather than a silent no-op.

What it costs is that the FIRST fetch of the certificate cannot be verified —
there is no plain listener left and the key does not exist until the process
starts. `docs/configuration.md`'s `global.https` section is the user-facing half;
`tls/CLAUDE.md` says what it takes away from `/tls/trust`, and
`tests/tools/trust.js` is what pays for it in a test run.

## AND THEY ARE WHAT RAISED THE RATE LIMITS (2026-09-06)

**The second use of the same placement, and it is worth having as a pair with
the one above.** All three files now carry a `security` block raising
`rateLimitPerAddress` to 500 and `rateLimitPerIdentity` to 100.
**`env/defaults.js` still says 20 and 5** — it is GENERATED from `config.js`,
and `config.js` describes what this service IS.

The problem was structural rather than a wrong number. The limiter's shipped
values are right for what it was written for: a SIGN-IN, where five attempts a
minute is generous and a sixth is somebody guessing. **A test suite is the
wrong shape for them**, because every job in it comes from ONE ADDRESS — the
runner — so the address bucket counts the whole suite as one caller while the
identity bucket, the one that is actually about credential guessing, stays
nearly empty.

MEASURED before it was changed, with the limiter effectively off and the whole
suite driven against one instance:

| action | bucket | peak | shipped limit |
|---|---|---|---|
| `activation` | address | **25** | 20 |
| `activation` | identity | 2 | 5 |
| `xacml-pip` | address | 7 | 20 |
| `sign-in` | address | never accumulated | 20 |

**One door did it.** `sts_portal_sessions.js` and `sts_admin_console.js` each
issue and open several activation links, and the address bucket is not cleared
by an activation that WORKS the way a sign-in's is — `succeeded()` is called on
the sign-in path and not there. The symptom was a 429 on a link the console had
just handed over, which reads exactly like a broken handler.

500 and 100 are 20× and 50× the measured peaks, so the suite can grow several
times over before this needs looking at again, and both remain a real control.

**Two things keep this honest, and neither existed before the change.**
`tests/rate_limiter.js` drives `websecurity.attempt()` in process with limits
passed as arguments, so the control is TESTED rather than merely exercised by
accident — before this, the suite's own 429s were the only thing touching it,
and raising the limit would have made it invisible. And the numbers above are
reproducible: put a peak counter in `attempt()`, run the suite with
`STS_SECURITY_RATE_PER_ADDRESS` very high, and read it back.

**THE THIRD USE, 2026-09-13: `acme.attemptsPerAddress` at 5000.** ACME counts
REFUSED requests per address (shipped 120), and `sts_route_inputs.js` — which
sends every route a malformed request on purpose — leaves 132 of them on the
runner's one address, so `sts_metadata_anonymous.js` met a 429 on
`/enroll/acme/directory` twelve seconds later. Measured off
`GET /admin-api/acme/monitor` after that job alone; EST and SCEP were 10 each
against 60 and have no block. The enrollment jobs that assert the throttle set
their own limits inside their realms, so the layer hides none of them.

## The union is also what keeps a file that is NOT this service's loadable

The parent project's in-process Kerberos jobs point `CONFIG_FILE` at that test
suite's own config, which carries exactly one of our keys — `logLevel`, the one
key every appconfig file in this ecosystem has. Because the selected file is a
layer rather than the configuration, every other setting comes from
`defaults.js` and the service starts. Do not add a check that refuses a file it
does not recognise.

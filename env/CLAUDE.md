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

The argument is one sentence: 8443, 9443 and LDAPS 636 were TLS on a certificate
the main port did not use, so a caller who had trusted this service's key for
three sockets still met an unencrypted fourth on the port every protocol family
actually answers on. **`STS_HTTPS=false` is the way back and is a supported
configuration, not an escape hatch.**

What it costs is that the FIRST fetch of the certificate cannot be verified —
there is no plain listener left and the key does not exist until the process
starts. `docs/configuration.md`'s `global.https` section is the user-facing half;
`tls/CLAUDE.md` says what it takes away from `/tls/trust`, and
`tests/tools/trust.js` is what pays for it in a test run.

## The union is also what keeps a file that is NOT this service's loadable

The parent project's in-process Kerberos jobs point `CONFIG_FILE` at that test
suite's own config, which carries exactly one of our keys — `logLevel`, the one
key every appconfig file in this ecosystem has. Because the selected file is a
layer rather than the configuration, every other setting comes from
`defaults.js` and the service starts. Do not add a check that refuses a file it
does not recognise.

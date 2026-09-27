Copyright (c) 2026 Iya CyberSecurity Solutions, LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## What is not MIT

Four things in this repository were written by somebody else and keep their
own licences. `REUSE.toml` declares each of them in machine-readable form and
`LICENSES/` holds the texts:

| Path | From | Licence |
|---|---|---|
| `xacml/conformance/` | The OASIS XACML 3.0 conformance test suite, taken from [`authzforce/core`](https://github.com/authzforce/core). `xacml/conformance/PROVENANCE.md` records the full chain — OASIS XACML TC, then AT&T (April 2014, MIT), then AuthzForce — together with the one link in that chain that public sources do not establish. Its own `LICENSE` file sits beside it. | Apache-2.0 |
| `spiffe/protos/` | The SPIRE API SDK's protobuf definitions, the SPIFFE Workload API and the SPIFFE Broker API, copied verbatim. | Apache-2.0 |
| `common/vendored/contexts/credentials_v1.json`, `credentials_v2.json` | The W3C Verifiable Credentials JSON-LD contexts. | W3C Software and Document License |
| `admin-ui/natural_earth/` | Country outlines derived from Natural Earth's 1:50m Admin 0 – Countries by `tests/tools/natural-earth.js`. | Public domain |

The MIT licence above covers every other file. The rest of `common/vendored/`,
the eight Kerberos codec files in `kerberos/` and the non-`local` jobs in
`tests/vendored/` are byte-identical copies of the parent project's files. They
have the same owner and the same licence, and carry no header because they may
not be edited here.

## How each file says so

Every source file this repository owns starts with two
[SPDX](https://spdx.dev/) lines. They come after a `#!` line or
`// @ts-check` where the file has one:

```
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
```

Files that cannot carry a comment (JSON, Markdown, data), the copies above,
and the third-party trees are covered by `REUSE.toml`. Together they meet the
[REUSE specification](https://reuse.software/), and `reuse lint` passes.
`tests/copyright_notices.js` fails when a source file this repository owns
lacks the two lines, when a file that may not be edited here was given them,
or when `REUSE.toml` names a licence with no text in `LICENSES/` or a
third-party path that no longer exists. `env/generate_defaults.js` writes the
lines into `env/defaults.js`.

## Runtime dependencies in the service image

The service image installs the npm packages in `package.json`'s
`dependencies`. Each carries its own licence in its `node_modules/`
directory:

| Licence | Packages |
|---|---|
| MIT | @dagrejs/dagre, @fingerprintjs/fingerprintjs, @noble/curves, @noble/hashes, @noble/post-quantum, @xmldom/xmldom, ajv, ajv-formats, body-parser, bowser, bunyan, busboy, cors, croner, express, jsonwebtoken, ldapjs (the `node-ldapjs` submodule, fork `rcbj/node-ldapjs`), pg, qrcode, scimmy, xml-crypto, yauzl, zod |
| MIT-0 | nodemailer |
| BSD-3-Clause | @digitalbazaar/bbs-signatures, @digitalbazaar/ed25519-signature-2020, @digitalbazaar/ed25519-verification-key-2020, @digitalbazaar/security-context, @digitalbazaar/zcap, asn1js, jsonld, jsonld-signatures, macaroon, pkijs |
| Apache-2.0 | @biscuit-auth/biscuit-wasm, @grpc/grpc-js, @grpc/proto-loader |
| BSD-3-Clause OR GPL-2.0 | node-forge, used under BSD-3-Clause |
| Unlicense | isbot |

Their transitive dependencies, and the optional cloud SDKs under
`peerDependencies`, carry their licences the same way. The test suite's
tools, corpora and conformance suites are fetched or built into the TESTS
image only. None of them is in the service image or committed here, and
`tests/CLAUDE.md` names each one's pin and licence.

---

## Third-party notices

### JA4 (TLS client fingerprinting)

`tls/client_hello.ts` computes the JA4 TLS client fingerprint, written here
from FoxIO's published specification. JA4 — and only JA4 — is licensed by
FoxIO under the BSD 3-Clause licence below. **The rest of JA4+ (JA4S, JA4H,
JA4L, JA4X, JA4SSH, JA4T and the others) is under the FoxIO License 1.1, which
restricts commercial use; none of it is implemented in this repository, and
none may be added under this notice.**

```
Copyright (c) 2026 FoxIO
All rights reserved.
Software: JA4 (TLS client fingerprinting)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of FoxIO nor the names of its contributors may be used to
  endorse or promote products derived from this software without specific
  prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### The Freeman et al. risk model (das-group/rba-algorithm)

`risk/risk_model.ts` is a port of `freeman_rba_score()` and the functions it
calls in [`das-group/rba-algorithm`](https://github.com/das-group/rba-algorithm)'s
notebook, an implementation of Freeman et al., "Who Are You? A Statistical
Approach to Measuring User Authenticity" (NDSS 2016). The notebook is under the
MIT licence below, and the same notice is at the head of the ported file,
where it travels into every image that carries the compiled code.

```
MIT License

Copyright (c) 2022 Stephan Wiefling / Data and Application Security Group

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The notebook's own test compares against das-group's RBA dataset, which this
repository does not carry; `tests/risk_model.js` instead holds the port to the
notebook's functions run on a synthetic history.

### FingerprintJS (optional browser fingerprinting)

When `risk.fingerprinting` is on, the sign-in screen serves
[FingerprintJS](https://github.com/fingerprintjs/fingerprintjs) v5
(`@fingerprintjs/fingerprintjs`, a dependency) to the browser, as
`/authn/fingerprint.js`. It is served as published, with its licence header
intact. Its licence:

```
MIT License

Copyright (c) 2025 FingerprintJS, Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Risk-scoring datasets are not distributed

Risk scoring (issue #62) reads geolocation, ASN, Tor exit, IP reputation, FIDO
metadata and breached-password data. **None of it is part of this repository,
its container images or its tests.** Each is an administrator-supplied input:
the deployment obtains it under its provider's terms — DB-IP Lite (CC BY 4.0,
with a link back that the Risk console page draws), IPinfo Lite (CC BY-SA
4.0), the Tor Project's exit list, FireHOL's lists (each constituent list
under its own terms), the FIDO Metadata Service (FIDO Alliance terms), Pwned
Passwords (HIBP's terms), MaxMind GeoLite2 (the GeoLite EULA, not yet
supported) — and pulls it into its own database at install time with
`risk/risk_install.ts`. **No provider's data is imported until somebody has
accepted that provider's current terms, and each acceptance is recorded** —
who, when, through which door, from which deployment, and the terms text —
in the deployment's database and audit log (`risk/risk_terms.ts`). IPinfo
data in particular must remain isolated in that database and must not be
bundled with a software distribution. The fixtures in `tests/` are synthetic:
documentation address ranges and invented names in each provider's format.
`tests/no_third_party_datasets.js` fails if a provider's file is ever added.

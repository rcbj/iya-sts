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

## One subtree is not MIT

`xacml/conformance/` holds the OASIS XACML 3.0 conformance test suite, taken
from [`authzforce/core`](https://github.com/authzforce/core) and **licensed
under Apache-2.0**, not under the MIT licence above. Its own `LICENSE` file
sits beside it and `xacml/conformance/PROVENANCE.md` records the full chain —
OASIS XACML TC, then AT&T (April 2014, MIT), then AuthzForce — together with
the one link in that chain that public sources do not establish.

Nothing else in this repository is affected. The MIT licence above covers every
other file.

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

### Third-party datasets are not distributed

Risk scoring (issue #62) reads geolocation, ASN, Tor exit, IP reputation, FIDO
metadata and breached-password data. **None of it is part of this repository,
its container images or its tests.** Each is an administrator-supplied input:
the deployment obtains it under its provider's terms — DB-IP Lite (CC BY 4.0,
with a link back that the Risk console page draws), IPinfo Lite (CC BY-SA
4.0), the Tor Project's exit list, FireHOL's lists (each constituent list
under its own terms), the FIDO Metadata Service (FIDO Alliance terms), Pwned
Passwords (HIBP's terms), MaxMind GeoLite2 (the GeoLite EULA, not yet
supported) — and pulls it into its own database at install time with
`risk/risk_install.ts`. The fixtures in `tests/` are synthetic: documentation
address ranges and invented names in each provider's format.
`tests/no_third_party_datasets.js` fails if a provider's file is ever added.

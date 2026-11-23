# The embedded PEP corpus

These are the cases every embedded PEP package's XACML engine is held to (#1206, #2024). There is one `iya-pep-<lang>` package per language, shared by that language's authentication libraries. Each package carries a lightweight engine of its own. **`rust/crates/sts-xacml` is the reference**, and a package passes only when it gives that engine's answer on every case here.

**Never edit these files by hand.** `rust/crates/sts-xacml/tests/pep_corpus.rs` writes them from the reference engine, and the same test fails when a committed file differs from what the engine answers:

```bash
# in rust/, in the Rust image CI uses (no Cargo on the host)
STS_PEP_CORPUS_WRITE=1 cargo test -p sts-xacml --test pep_corpus   # regenerate
cargo test -p sts-xacml --test pep_corpus                          # check (CI's `rust` job)
```

## What is here

| File | What it holds |
|---|---|
| `MANIFEST.json` | `format`, `version`, `sha256` and `now`, the case counts, the sources, and every case left out with the reason |
| `oasis/<case>.json` | One case per file, from the OASIS XACML 3.0 conformance suite's mandatory cases (`xacml/conformance/mandatory`) |
| `enforcement.json` | A byte-for-byte copy of `xacml-pep/enforcement_cases.json`: section 7.2's bias and obligation rule, as a table |

**A case is in the corpus only if the reference engine agrees with the suite.** At the corpus's fixed instant (`now`), its decision and obligation identifiers must match the suite's own `Response.xml`, so the corpus can't encode an answer the standard disagrees with. These cases are left out:
- an invalid policy the PDP must refuse. Static validation is the service's job at deploy, and a PEP is only ever sent policies that passed it.
- an invalid request XML. A PEP builds its request in code and reads no request XML.
- the reference engine's one recorded failure, `IIE003`. The reason is in `xacml/conformance/MANIFEST.js`.

## A case

```json
{
  "name": "IIA001",
  "source": "oasis-mandatory",
  "policies": [
    { "policyId": "…", "kind": "Policy", "version": "1.0", "isRoot": true, "document": "<Policy …>" }
  ],
  "request": {
    "returnPolicyIdList": false,
    "combinedDecision": false,
    "categories": [
      { "category": "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject",
        "hasContent": false,
        "attributes": [
          { "attributeId": "…", "issuer": "…", "includeInResult": false,
            "values": [ { "dataType": "http://www.w3.org/2001/XMLSchema#string", "value": "Julius Hibbert" } ] } ] }
    ]
  },
  "expected": {
    "decision": "Permit",
    "obligations": [ { "id": "…", "assignments": [ { "attributeId": "…", "category": "…", "issuer": "…", "dataType": "…", "value": "…" } ] } ],
    "advice": []
  }
}
```

- **`policies`** has the same shape as the policy pull's `PolicyRow` (`GET /xacml/pep/policies`), minus the members only the console reads. Exactly one row has `isRoot: true`, and it is the one evaluated. Every `PolicyIdReference` and `PolicySetIdReference` resolves to another row of the same case, by `policyId`. Nothing outside the case is referenced.
- **`request`** is a request as a package builds it in code. A category may appear more than once. `issuer` and `id` appear only when the request carried them. `hasContent` says that the category carried a `<Content>` element. The reference engine evaluates no XPath over it, and a package doesn't either.
- **`now`**, in `MANIFEST.json`, is the instant `current-time`, `current-date` and `current-dateTime` come from. Inject it. A package's own clock gives different answers on the cases that read it.
- **`expected.decision`** is one of `Permit`, `Deny`, `NotApplicable` or `Indeterminate`. The extended Indeterminates are folded, as in a response.

## How a package compares its answer

1. **The decision must be equal.**
2. **Obligations, and advice separately, are compared as multisets.** Two obligations are equal when their `id` is equal and their assignments are equal as multisets. Two assignments are equal when `attributeId`, `category`, `issuer` and `dataType` are equal (an absent member equals only an absent member), and the two values are equal under the datatype's own equality function.
3. **`value` is the reference engine's canonical lexical form for `dataType`.** A package either parses it and compares typed values, or writes its own value in the same canonical form.
4. **Not compared:** the status code and message, which the specification lets a PDP choose between, the policy identifier list, and any XML.

## Versions

`version` in `MANIFEST.json` moves by one whenever `sha256`, the digest of every case file and `enforcement.json`, changes. A regeneration that changes nothing keeps the version. `format` moves only when the shape of a case file changes.

A package vendors the files and records the `version` and `sha256` it took. Its test fails on any case it does not pass. A newer corpus is taken deliberately, never automatically.

## Licence

- **`oasis/`** is derived from the OASIS XACML 3.0 conformance suite as adapted by AT&T and then AuthzForce (OW2), and is **Apache-2.0** like its source (`xacml/conformance/PROVENANCE.md`, `LICENSES/Apache-2.0.txt`). Per Apache-2.0 section 4(b): each case is a modified form of its source. The policies are carried verbatim. The request is converted from `Request.xml` into the attribute form above, and the expected answer is the reference engine's, checked against `Response.xml`.
- **`MANIFEST.json`, `enforcement.json` and this file** are **MIT** (`LICENSES/MIT.txt`), so the MIT packages can vendor all of it.

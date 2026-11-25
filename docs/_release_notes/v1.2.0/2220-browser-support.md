---
title: "Every page says what this browser lacks, in the reader's language"
kind: fixed
issue: 2220
---
A browser that cannot run this service's pages is now told so instead of
showing a blank page. Every page's document runs a small check written in
ECMAScript 5, `/web/browser-check.js`, before its main script. Where `fetch`,
`TextEncoder`, `URL` or ECMAScript 2022 is missing, the check shows a notice
that the server drew in the reader's language, and the page's script does not
start. The console, the portal and the reports application also check
`sessionStorage` before they sign in ("This browser cannot sign you in
here"). The portal and the console's passkey upgrade check for WebAuthn
before a ceremony ("This browser cannot use passkeys"). The `<noscript>`
notices are drawn in the request's language. The console's "sign-in window
was blocked" message is translated. The portal and the reports application
now keep the page's choices when a browser without `window.open` or
`BroadcastChannel` has to leave the page for permission. The portal's
**Copy** falls back to `execCommand('copy')` and says when it fails. Each
notice links to a new section for people,
[For people using this service](browser-requirements.md#for-people-using-this-service).
No setting and no endpoint behaviour changes; the one new route is the check
script. ASVS 5.0.0 3.1.1.

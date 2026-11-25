---
title: "the console, portal and reports say why they cannot open without WebCrypto"
kind: fixed
issue: 2143
---

The admin console, the user portal and the reports application sign in with
the browser's WebCrypto, which a browser offers only to a page opened over
HTTPS (or `localhost`). Opened over plain HTTP, or in a browser too old to have
WebCrypto, each one used to stop with a blank page. Each now checks before it
signs in and, where WebCrypto is missing, shows one sentence in the page's
language saying that this browser cannot run the page securely, usually
because the page was not opened over HTTPS or the browser is too old.

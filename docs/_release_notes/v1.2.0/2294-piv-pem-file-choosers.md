---
title: "Choose the PIV enrolment files from disk on the portal"
kind: added
issue: 2294
---
The portal's **Tokens and keys → PIV** form has a file chooser beside each
of its three boxes: the certificate request, the slot attestation and the f9
attestation certificate. The browser reads the chosen file and checks it
before using it. The file must hold exactly one PEM block of the right kind,
with valid base64, and the block must have the structure of an X.509
certificate or a PKCS #10 certificate request. Only that block is put in the
box. Any other file is refused with a message saying why, and the box is left
as it was. The file itself is never sent.

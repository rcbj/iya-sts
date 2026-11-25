---
title: "A file an administrator names is checked on the descriptor it is read through"
kind: security
issue: 2247
---

In product mode a file a setting or an administrator names (a CA file, a
truststore's setting file, the DKIM key, a SPIFFE attestor's token or
credentials file, AuthZEN's external PDP keys) must be inside a directory
`security.fileRoots` lists. Until 1.2.0 the path was checked and then opened
again, so a symbolic link swapped in between could be followed out of those
directories. The file is now opened once, and the open file itself is
checked (a regular file, its real path inside a listed directory) before it
is read through that same descriptor (ASVS 5.0.0 15.4.2). A link inside the
directories to a file inside them, such as `/etc/ssl/certs` or a Kubernetes
secret volume, still reads as before, and the refusal sentences and error
codes are unchanged. The GCP instance-identity attestor's service account
key file is now read by the service and handed to the Google client as its
contents when it is JSON. Development mode confines nothing, as before.

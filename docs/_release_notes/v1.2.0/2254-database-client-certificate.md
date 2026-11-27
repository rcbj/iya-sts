---
title: "The database connection can authenticate with a client certificate"
kind: added
issue: 2254
---
`persistence.databaseTlsClientCertFile` and `persistence.databaseTlsClientKeyFile` name a PEM client certificate and its key, and the service presents them on every connection it makes to PostgreSQL or MariaDB: the pools, the LISTEN and liveness connections, the read replica, a cell's global tier and the command-line tools. The database may authenticate the service by the certificate alone (PostgreSQL's `cert` method, MariaDB's `REQUIRE X509`), with no password, or by the certificate and the password together (`clientcert=verify-full`). The files are read again every `persistence.databasePasswordRefreshS`, so a renewed certificate is used for new connections without a restart. A pair that cannot be read, or whose key is not the certificate's, stops the service at start (`STS-STORE-0180`). Both settings are empty by default, which keeps the password-only connection. The compose postgres container can require one with `POSTGRES_CLIENT_CERT`. See [Persistence](persistence.md#a-client-certificate-for-the-database).

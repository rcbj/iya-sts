---
title: "Limits and timeouts on everything the service connects to"
kind: security
issue: 2220
---
Every outbound HTTP call now shares one keep-alive connection pool per
process, capped per destination (`federation.outboundMaxSockets`, 64) and in
all (`federation.outboundMaxTotalSockets`, 1024), and has an overall deadline
(`federation.outboundDeadlineMs`, 2 minutes) and a connect timeout
(`federation.outboundConnectTimeoutMs`, 10 s) beside its inactivity timeout.
Ordinary database statements run under `persistence.statementTimeoutMs`
(5 minutes); the start's migrations and restore are not under it. The pool's
size and waits are settings (`persistence.poolSize`, `persistence.poolWaitMs`,
`persistence.connectTimeoutMs`, `persistence.idleTimeoutMs`), as is an
attribute source's pool (`attributeSources.poolSize`). The secret store and
the cloud key services get each SDK's own timeout and retry bound
(`keys.storeTimeoutMs`, `keys.storeAttempts`); HSM operations a timeout and a
queue limit (`keys.pkcs11TimeoutMs`, `keys.pkcs11QueueLimit`); malware scans a
concurrency limit and queue (`malwareScan.concurrency`,
`malwareScan.queueLimit`, refused 503 past it); and an inter-cell answer a
size cap (`cells.maxAnswerBytes`). The mail outbox's first attempt is held to
`mail.concurrency`, and a message that would take the pending rows past
`mail.maxRows` is refused (`STS-MAIL-0244`) instead of growing the outbox
without bound. Every default is above what normal traffic uses. See
[Dependencies, limits and timeouts](dependencies.md).

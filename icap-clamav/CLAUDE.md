# CLAUDE.md

**Not part of the service.** A c-icap adapter that puts ClamAV behind ICAP, for
`common/malware_scan.ts`. Off by default (`STS_ICAP_SCALE=0`); users with another
antivirus product point `malwareScan.url` at its ICAP service and never run this.

**c-icap must not start before clamd answers.** At load `clamd_mod` asks clamd for
its version. If that fails it logs *Registry 'virus_scan::engines' does not
exist!* and c-icap then answers **204 to every file** for as long as it runs, so
everything looks clean. `start.sh` waits for a PONG.

**It talks to clamd over the Unix socket, on the `clamd-socket` volume.** Over TCP
`clamd_mod` sends clamd a file PATH, which does not exist in the other container
(*File path check failure*, ICAP 500). Over the socket it passes the open file
descriptor. The volume is mounted over `/tmp` in `clamav` because that image's
own start script waits for `/tmp/clamd.sock`.

All of this was found only by sending EICAR through a real stack. A stand-in ICAP
service in `tests/malware_scan.js` cannot show it, which is why
`MalwareScan.test()` requires EICAR to be flagged.

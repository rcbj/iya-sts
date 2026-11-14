# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# An ICAP service in front of the `clamav` container, for a stack that wants
# malware scanning with ClamAV. See docs/malware-scanning.md.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends c-icap libc-icap-mod-virus-scan socat openssl \
 && rm -rf /var/lib/apt/lists/*
COPY c-icap.conf /etc/c-icap/c-icap.conf
COPY start.sh /usr/local/bin/start-c-icap
RUN chmod 755 /usr/local/bin/start-c-icap \
 && mkdir -p /run/c-icap /icap-tls \
 && chown c-icap:c-icap /run/c-icap /icap-tls
USER c-icap
EXPOSE 11344 1344
CMD ["/usr/local/bin/start-c-icap"]

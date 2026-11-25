# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# An ICAP service in front of the `clamav` container, for a stack that wants
# malware scanning with ClamAV. See docs/v1.2.0/malware-scanning.md.
#
# C-ICAP IS PINNED (#2220, ASVS 5.0.0 15.2.4): the server, its library and its
# virus-scan module at the versions Debian bookworm carried on 2026-11-25, so
# the adapter is the same build until somebody moves the pins. A security
# update in bookworm REPLACES the version in the archive, and then this build
# fails at `apt-get install` naming the package — which is the signal to
# move the pin, not a fault: read `apt-cache policy` in a bookworm-slim
# container and write the new versions here. What the module pulls in
# (libclamav, socat, openssl) follows Debian's security updates unpinned; the
# daily image scan (.github/workflows/dependency-windows.yml) scans this image
# and holds its findings to SECURITY.md's windows.
FROM debian:bookworm-slim
ARG C_ICAP_VERSION=1:0.5.10-4
ARG C_ICAP_VIRUS_SCAN_VERSION=1:0.5.5-2+deb12u1
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      "c-icap=${C_ICAP_VERSION}" "libicapapi5=${C_ICAP_VERSION}" \
      "libc-icap-mod-virus-scan=${C_ICAP_VIRUS_SCAN_VERSION}" \
      socat openssl \
 && rm -rf /var/lib/apt/lists/*
COPY c-icap.conf /etc/c-icap/c-icap.conf
COPY start.sh /usr/local/bin/start-c-icap
RUN chmod 755 /usr/local/bin/start-c-icap \
 && mkdir -p /run/c-icap /icap-tls \
 && chown c-icap:c-icap /run/c-icap /icap-tls
USER c-icap
EXPOSE 11344 1344
CMD ["/usr/local/bin/start-c-icap"]

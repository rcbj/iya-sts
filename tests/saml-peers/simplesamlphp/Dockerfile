# ===========================================================================
# SIMPLESAMLPHP AS AN INTEROPERABILITY PEER (#191).
#
# The official release tarball, pinned by version AND by its sha256 (the
# build fails on one differing byte), under the PHP project's official
# Apache image. A different implementation lineage from Shibboleth, Keycloak
# and pysaml2. One `saml:SP` auth source (config/authsources.php, which says
# why there is no artifact one).
#
# Nothing here is a key: the SP's key pair and SimpleSAMLphp's secret salt
# are made when the container STARTS (entrypoint.sh). The job hands the
# identity provider's metadata to /peer/configure.php, which the
# release's own SAMLParser reads, and SimpleSAMLphp's schema validation of
# every message it receives is on (`debug.validatexml`), so its log — the
# harness's error-and-warning source — names a document that does not
# validate. tests/CLAUDE.md, *THE SAML PEERS*, argues the rest.
#
# SimpleSAMLphp is LGPL-2.1; nothing of it is vendored into this repository.
# ===========================================================================
FROM php:8.3-apache

ARG SSP_VERSION=2.5.3.1
ARG SSP_SHA256=38d81fc60f358b46a58df38617b02f97f57793dcbf8e491c1abcedb6706ffe3c

RUN curl -fsSL -o /tmp/ssp.tgz \
      "https://github.com/simplesamlphp/simplesamlphp/releases/download/v${SSP_VERSION}/simplesamlphp-${SSP_VERSION}-slim.tar.gz" && \
    echo "${SSP_SHA256}  /tmp/ssp.tgz" | sha256sum -c - && \
    mkdir -p /var/simplesamlphp && \
    tar xzf /tmp/ssp.tgz -C /var/simplesamlphp --strip-components=1 && \
    rm /tmp/ssp.tgz && \
    apt-get update && apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

COPY config.php authsources.php /var/simplesamlphp/config/
COPY saml20-idp-remote.php /var/simplesamlphp/metadata/
COPY peer/ /var/www/peer/
COPY peer.conf /etc/apache2/sites-available/000-default.conf
COPY entrypoint.sh /usr/local/sbin/entrypoint.sh
RUN chmod 0755 /usr/local/sbin/entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]

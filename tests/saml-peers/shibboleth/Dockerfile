# ===========================================================================
# THE SHIBBOLETH SERVICE PROVIDER 3 AS AN INTEROPERABILITY PEER (#189).
#
# shibd and Apache httpd with mod_shib, from the Shibboleth Consortium's OWN
# package repository for Rocky Linux 9 — the packages the project publishes,
# at a pinned release — with a small control server beside them that the job
# hands the identity provider's metadata and the service's TLS anchor to.
# Nothing in this image is a key: the SP's signing and encryption pairs are
# made by keygen.sh when the container STARTS (entrypoint.sh), so every run
# has its own and none is ever in git.
#
# The Consortium publishes no container image for the SP, so this one is the
# vendor's packages on the vendor's supported platform, which is as close to
# "official" as the SP comes. tests/CLAUDE.md, *THE SAML PEERS*, argues the
# rest.
# ===========================================================================
FROM rockylinux/rockylinux:9

# THE RELEASE UNDER TEST. The repository file is the Consortium's generator's
# output for this platform; its packages are signed with the key it names and
# dnf checks them (gpgcheck=1 in that file).
ARG SHIBBOLETH_SP_VERSION=3.6.0-1.el9

RUN curl -fsS -o /etc/yum.repos.d/shibboleth.repo \
      "https://shibboleth.net/cgi-bin/sp_repo.cgi?platform=rockylinux9" && \
    dnf -y install "shibboleth-${SHIBBOLETH_SP_VERSION}" httpd python3 \
      procps-ng && \
    dnf clean all && \
    rm -f /etc/shibboleth/sp-*.pem /etc/httpd/conf.d/welcome.conf \
      /etc/httpd/conf.d/ssl.conf

COPY shibboleth2.xml attribute-map.xml /etc/shibboleth/
COPY peer.conf /etc/httpd/conf.d/peer.conf
COPY peer-env.py /var/www/cgi-bin/peer-env.py
COPY control.py entrypoint.sh /usr/local/sbin/
RUN chmod 0755 /var/www/cgi-bin/peer-env.py /usr/local/sbin/control.py \
      /usr/local/sbin/entrypoint.sh

EXPOSE 80 9090
ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]

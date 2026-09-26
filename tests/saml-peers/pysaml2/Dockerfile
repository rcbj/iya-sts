# ===========================================================================
# PYSAML2 AS A SCRIPTED SAML 2.0 SERVICE PROVIDER (#190).
#
# pysaml2 from PyPI at a pinned release (IdentityPython, Apache-2.0), with
# the xmlsec1 it signs and encrypts through, under the Python project's
# official slim image. peer.py is the SP — a small server over pysaml2's
# Saml2Client that the job drives, including the negative cases. The SP's
# key pair is made when the container STARTS (entrypoint.sh); nothing here is
# a key. tests/CLAUDE.md, *THE SAML PEERS*, argues the rest.
# ===========================================================================
FROM python:3.12-slim-bookworm

ARG PYSAML2_VERSION=7.5.5

RUN apt-get update && \
    apt-get install -y --no-install-recommends xmlsec1 openssl && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir "pysaml2==${PYSAML2_VERSION}"

COPY peer.py entrypoint.sh /usr/local/sbin/
RUN chmod 0755 /usr/local/sbin/peer.py /usr/local/sbin/entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]

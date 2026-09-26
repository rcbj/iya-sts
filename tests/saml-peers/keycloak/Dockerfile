# ===========================================================================
# KEYCLOAK AS A SAML 2.0 BROKERING SERVICE PROVIDER (#192).
#
# Keycloak's official image at a pinned tag — the one the parent project's
# stack runs — with a start script in front of it. Keycloak is configured
# ENTIRELY through its admin REST API by the job at run time (a realm, a SAML
# identity provider pointed at this service, a client to sign in through);
# there is no exported realm file, and so no key in git. Its SP signing and
# encryption keys are the realm's own, generated when the job creates it.
#
# ROOT, where the image runs as uid 1000: the start script makes its log
# directory on the volume the suite shares with its runner, which is root's.
# tests/CLAUDE.md, *THE SAML PEERS*, argues the rest.
# ===========================================================================
FROM quay.io/keycloak/keycloak:26.6.4

USER root
COPY entrypoint.sh /opt/keycloak/bin/peer-entrypoint.sh
RUN chmod 0755 /opt/keycloak/bin/peer-entrypoint.sh
ENTRYPOINT ["/opt/keycloak/bin/peer-entrypoint.sh"]

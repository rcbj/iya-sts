---
title: "dynamic selectable roles"
kind: added
issue: 1072
---

A role can be **dynamic selectable**: nobody is a member of it, and a person
chooses it at sign-in for the application they are signing in to, from the
roles that role's own XACML policy permits them. A role marked `required`
must be chosen. The choice is kept on the sign-on session, is asked of each
role's policy again at every issuance, and appears in the roles claim and
the SAML 2.0, SAML 1.1 and WS-Federation roles attribute for that
application only. Single sign-on into another application carries no
choice: the portal's **Sign in again** asks for a fresh sign-in, and an
application that requires a role the session did not choose for it sends
the person to sign in again. Flows with no sign-in screen (the password
grant, token exchange, the assertion grants, the device grant, CIBA,
WS-Trust, Kerberos and LDAP) never carry a chosen role, and are refused
where a role is required (`STS-XACML-0332`). See
[Dynamic selectable roles](dynamic-roles.md).

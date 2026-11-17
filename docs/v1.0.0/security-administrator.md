---
title: Security Administrator
---

# The Security Administrator

The **Security Administrator** is a built-in console role. It is the only
role that may change the security policies of a realm. **Admin Write**
cannot, so managing security can be one person's job while administering
the service is another's.

## What only a Security Administrator may do

* **Save, reset or act on a policy** on **Directory → Policies**: the
  password, authentication, service-account, passkey, locale, attribute and
  post-login activity policies, and any policy kind added later.
* **Name a policy** on an application, a group or a person (an application's
  `appPasswordPolicy`, a group's `stsPasswordPolicy`, a service account's
  `stsServiceAccountPolicy` and the rest). A form that posts the reference
  unchanged is not a change, so Admin Write can still save an application's
  or a person's other fields.
* **Grant or revoke the Security Administrator role**, by any door: the
  **Admin roles** page, `POST /admin-api/rbac/grant`, the `SECURITY_ADMIN`
  role on **Directory → Roles**, the `cn=security-admin` group, and the
  `admin.securityGroup` setting that names that group.
* **Act on the account of a person who holds the role**: reset or set their
  password, disable or delete them, clear a second factor, or issue a
  certificate in their name. Without this, somebody with Admin Write could
  reset a Security Administrator's password and sign in as them.

XACML policies, fine-grained authorization, AuthZEN and delegation policy are
not on this list. They stay with Admin Write.

The role **implies Admin Read and not Admin Write**: a Security Administrator
can see every console page and change only the things above.

## Who holds it

* **The default realm's bootstrap administrator** (`admin`) holds it. That
  account is the global administrator, so it is the global Security
  Administrator, over every realm.
* **A trust realm's own bootstrap administrator does not.** A realm's
  Security Administrator is granted explicitly, by a global Security
  Administrator or by one already in that realm, and is confined to that
  realm, as every realm administrator is.
* **On an existing deployment**, the first start with this version creates
  `cn=security-admin` with the bootstrap administrator in it, and nobody
  else. Members of Admin Write are not copied. If the group already exists,
  it is left alone, even when it is empty.
* **`sts-api-client`**, the management API's machine client, is a member of
  `SECURITY_ADMIN`, so a script that saves policies keeps working. Take it out
  on **Directory → Roles** if no machine should.

## Giving the role to somebody who is not an administrator

1. Sign in to the console as a Security Administrator (on a new service,
   the bootstrap administrator).
2. On **Admin roles** (`/admin/rbac`), grant **Security Administrator** to
   the person. Do not grant them Admin Write.
3. They sign in to the console and see every page. They can save policies
   and nothing else.
4. If you want the bootstrap administrator out of the role, revoke it there
   too, once somebody else holds it.

The same with the management API:

```bash
curl -X POST "$BASE/admin-api/rbac/grant" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"username": "sec-officer", "role": "security"}'
```

`$TOKEN` must carry `admin:security`.

## The management API

A security change takes the scope **`admin:security`** instead of
`admin:write`, and its subject must hold `SECURITY_ADMIN`:

* a person is issued `admin:security` only while they hold the role on the
  realm's roster;
* an application is issued it only while it is a member of `SECURITY_ADMIN`.

A request without it is refused **403** and recorded as `STS-API-0138`. This
is checked by the API itself, not only by the access-control policy, so
turning `xacml.enforceAccess` off does not open it. Ask for the scope as
well as the others:

```bash
curl -u "sts-api-client:$SECRET" "$BASE/oauth2/token" \
  -d grant_type=client_credentials \
  -d 'scope=admin:read admin:write admin:security' \
  -d "resource=$BASE/admin-api"
```

**A deployment whose clients were seeded before this version** has
`sts-api-client` and `sts-admin-console` entries without a delegated
permission grant of `admin:security`: give each one
`urn:sts:admin-api:admin:security` (**Applications →** the client **→
Permissions**, or `POST /admin-api/permissions/grant-permission`), or the
console cannot save a policy even for a Security Administrator.

## The directory and SCIM

In product mode an LDAP write needs the role when it is under a
Directory → Policies container, is the `cn=security-admin` group, writes a
policy reference attribute, writes a `memberOf` naming that group, or is the
entry of a person who holds the role (`STS-LDAP-0203`). A SCIM write of the
group, or of the User of a person who holds the role, needs it too
(`STS-SCIM-0086`).

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `admin.securityGroup` | `security-admin` | The cn of the role's group. Changing it is itself a Security Administrator's change. |

// ---------------------------------------------------------------------------
// MODULES THIS SERVICE LOADS ONLY WHEN A DEPLOYMENT ASKS FOR THEM (#50).
//
// `common/secrets.js` requires a cloud secret store's SDK lazily, inside the
// provider that uses it, and none of them is a dependency of this package: a
// deployment that names the provider installs it. Declared here as `any` so the
// checker does not fail on a module that is absent by design.
// ---------------------------------------------------------------------------
declare module '@aws-sdk/client-secrets-manager';
declare module '@google-cloud/secret-manager';
declare module '@azure/keyvault-secrets';
declare module '@azure/identity';
declare module 'node-vault';

// `admin-core/admin_views.ts` reads the password generator's version out of its
// package.json, which the package's own declarations do not cover.
declare module 'generate-password/package.json';

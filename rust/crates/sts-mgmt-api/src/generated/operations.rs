// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// GENERATED from models/api/ (#1390, #444). Do not edit: change the
// model and run tests/tools/regenerate-model-docs.sh.
// tests/model_domain.js fails when this differs.

// Every operation of the two documents /admin-api serves, in each
// document's path order. Included by sts-mgmt-api's operations.rs.

/// One operation of the Management API or Admin Console API OpenAPI
/// document, by its operationId.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Operation {
    /// `GET /admin-api`
    GetIndex,
    /// `GET /admin-api/sts-metadata`
    GetStsMetadata,
    /// `GET /admin-api/openapi.json`
    GetOpenApi,
    /// `GET /admin-api/crypto`
    GetCryptoMetadata,
    /// `GET /admin-api/encryption`
    GetEncryption,
    /// `POST /admin-api/encryption/rotate-data-keys`
    RotateDataKeys,
    /// `POST /admin-api/encryption/reencrypt-data-keys`
    ReencryptDataKeys,
    /// `POST /admin-api/encryption/count-data-keys`
    CountDataKeys,
    /// `POST /admin-api/encryption/rotate-kek`
    RotateKek,
    /// `GET /admin-api/cells`
    GetCells,
    /// `GET /admin-api/cells/people`
    GetCellPeople,
    /// `POST /admin-api/cells/rehome`
    RehomePerson,
    /// `GET /admin-api/broadcast`
    GetBroadcast,
    /// `POST /admin-api/broadcast/send`
    SendBroadcast,
    /// `GET /admin-api/announcements`
    GetConsoleAnnouncements,
    /// `GET /admin-api/mode`
    GetMode,
    /// `GET /admin-api/account-api`
    GetAccountApi,
    /// `GET /admin-api/listeners`
    GetListeners,
    /// `POST /admin-api/listeners/set-listeners`
    SetListeners,
    /// `POST /admin-api/listeners/set-applications`
    SetListenerApplications,
    /// `GET /admin-api/vc-status`
    GetCredentialStatus,
    /// `POST /admin-api/vc-status/suspend`
    SuspendCredential,
    /// `POST /admin-api/vc-status/reinstate`
    ReinstateCredential,
    /// `POST /admin-api/vc-status/revoke`
    RevokeCredential,
    /// `POST /admin-api/vc-status/publish`
    PublishStatusList,
    /// `GET /admin-api/risk`
    GetRisk,
    /// `GET /admin-api/risk/metrics`
    GetRiskMetrics,
    /// `GET /admin-api/geolocation`
    GetGeolocation,
    /// `POST /admin-api/risk/upload`
    UploadRiskDataset,
    /// `POST /admin-api/risk/import`
    ImportRiskDataset,
    /// `POST /admin-api/risk/activate`
    ActivateRiskDataset,
    /// `POST /admin-api/risk/reload`
    ReloadRiskDatasetVersion,
    /// `POST /admin-api/risk/rollback`
    RollbackRiskDataset,
    /// `POST /admin-api/risk/accept-terms`
    AcceptRiskProviderTerms,
    /// `POST /admin-api/risk/delete`
    DeleteRiskDatasetVersion,
    /// `GET /admin-api/mail`
    GetMail,
    /// `POST /admin-api/mail/test`
    SendMailTestMessage,
    /// `POST /admin-api/mail/verify`
    SendMailVerificationLink,
    /// `POST /admin-api/mail/save-template`
    SaveMailTemplate,
    /// `POST /admin-api/mail/reset-template`
    ResetMailTemplate,
    /// `GET /admin-api/mail/outbox`
    GetMailOutbox,
    /// `POST /admin-api/mail/outbox/retry`
    RetryMailDeadLetter,
    /// `GET /admin-api/devices`
    GetDevices,
    /// `POST /admin-api/devices/create`
    CreateDevice,
    /// `POST /admin-api/devices/update`
    UpdateDevice,
    /// `POST /admin-api/devices/remove`
    RemoveDevice,
    /// `POST /admin-api/devices/add-key`
    AddDeviceKey,
    /// `POST /admin-api/devices/remove-key`
    RemoveDeviceKey,
    /// `POST /admin-api/devices/set-compliance`
    SetDeviceCompliance,
    /// `POST /admin-api/devices/set-status`
    SetDeviceStatus,
    /// `POST /admin-api/device-compliance`
    ReportDeviceCompliance,
    /// `GET /admin-api/devices/monitor`
    GetDevicesMonitor,
    /// `GET /admin-api/service-accounts`
    GetServiceAccounts,
    /// `GET /admin-api/device-registration`
    GetDeviceRegistration,
    /// `GET /admin-api/scheduler`
    GetScheduler,
    /// `POST /admin-api/scheduler/run`
    RunSchedulerJob,
    /// `POST /admin-api/scheduler/step-down`
    StepDownScheduler,
    /// `GET /admin-api/caches`
    GetCaches,
    /// `GET /admin-api/worker-pools`
    GetWorkerPools,
    /// `GET /admin-api/node-health`
    GetNodeHealth,
    /// `POST /admin-api/node-health/collect-garbage`
    CollectGarbage,
    /// `GET /admin-api/database`
    GetDatabase,
    /// `GET /admin-api/secrets`
    GetSecrets,
    /// `GET /admin-api/debugger`
    GetDebugger,
    /// `GET /admin-api/keys`
    GetKeys,
    /// `GET /admin-api/keys/history/certificate`
    GetKeyHistoryCertificate,
    /// `GET /admin-api/keys/history`
    GetKeyHistory,
    /// `POST /admin-api/keys/export`
    ExportKey,
    /// `POST /admin-api/keys/rotate`
    RotateSigningKeys,
    /// `POST /admin-api/keys/emergency`
    RotateSigningKeysEmergency,
    /// `GET /admin-api/status`
    GetStatus,
    /// `GET /admin-api/me`
    GetMe,
    /// `GET /admin-api/metrics`
    GetMetrics,
    /// `GET /admin-api/users`
    GetUsers,
    /// `GET /admin-api/users/app-passwords`
    GetUserAppPasswords,
    /// `GET /admin-api/users/certificates`
    GetUserCertificates,
    /// `GET /admin-api/users/devices`
    GetUserDevices,
    /// `GET /admin-api/users/self-issued-subjects`
    GetUserSelfIssuedSubjects,
    /// `GET /admin-api/users/published-dids`
    GetUserPublishedDids,
    /// `GET /admin-api/users/verifications`
    GetUserVerifications,
    /// `GET /admin-api/users/new`
    GetNewUserForm,
    /// `POST /admin-api/users/issue-activation`
    IssueActivationLink,
    /// `POST /admin-api/users/create`
    CreateUser,
    /// `POST /admin-api/users/set-password`
    SetUserPassword,
    /// `POST /admin-api/users/clear-totp`
    ClearUserAuthenticatorApp,
    /// `POST /admin-api/users/clear-backup-codes`
    ClearUserBackupCodes,
    /// `POST /admin-api/users/clear-email-factor`
    ClearUserEmailFactor,
    /// `POST /admin-api/users/set-aud-sub`
    SetUserAudSub,
    /// `POST /admin-api/users/set-mail`
    SetUserMail,
    /// `POST /admin-api/users/set-pseudonyms`
    SetUserPseudonyms,
    /// `POST /admin-api/users/set-attribute`
    SetUserAttribute,
    /// `POST /admin-api/users/add-attribute`
    AddUserAttributeValue,
    /// `POST /admin-api/users/remove-attribute`
    RemoveUserAttributeValue,
    /// `POST /admin-api/users/update-fields`
    UpdateUserFields,
    /// `POST /admin-api/users/reset-password`
    ResetUserPassword,
    /// `POST /admin-api/users/issue-password-reset`
    IssuePasswordResetLink,
    /// `POST /admin-api/users/disable-primary-keys`
    DisableUserPasskeys,
    /// `POST /admin-api/users/disable-mfa`
    DisableUserSecondFactors,
    /// `POST /admin-api/users/require-mfa`
    RequireUserSecondFactor,
    /// `POST /admin-api/users/stop-requiring-mfa`
    StopRequiringUserSecondFactor,
    /// `POST /admin-api/users/set-service-account`
    SetUserServiceAccount,
    /// `POST /admin-api/users/add-service-account-owner`
    AddServiceAccountOwner,
    /// `POST /admin-api/users/remove-service-account-owner`
    RemoveServiceAccountOwner,
    /// `POST /admin-api/users/set-service-account-destination`
    SetServiceAccountDestination,
    /// `POST /admin-api/users/rotate-password`
    RotateServiceAccountPassword,
    /// `POST /admin-api/users/set-not-delegated`
    SetUserNotDelegated,
    /// `POST /admin-api/users/set-may-act`
    SetUserMayAct,
    /// `POST /admin-api/users/set-delegation-semantics`
    SetUserDelegationSemantics,
    /// `POST /admin-api/users/answer-ciba-request`
    AnswerUserCibaRequest,
    /// `POST /admin-api/users/remove-device`
    RemoveUserDevice,
    /// `POST /admin-api/users/add-certificate`
    AddUserCertificate,
    /// `POST /admin-api/users/remove-certificate`
    RemoveUserCertificate,
    /// `POST /admin-api/users/export-ldif`
    ExportUserLdif,
    /// `POST /admin-api/users/import-ldif`
    ImportUserLdif,
    /// `POST /admin-api/users/issue-signing-certificate`
    IssueUserSigningCertificate,
    /// `POST /admin-api/users/revoke-signing-certificate`
    RevokeUserSigningCertificate,
    /// `POST /admin-api/users/enrol-self-issued-subject`
    EnrolUserSelfIssuedSubject,
    /// `POST /admin-api/users/remove-self-issued-subject`
    RemoveUserSelfIssuedSubject,
    /// `POST /admin-api/users/set-preferred-self-issued-subject`
    SetUserPreferredSelfIssuedSubject,
    /// `POST /admin-api/users/deactivate-published-did`
    DeactivateUserPublishedDid,
    /// `POST /admin-api/users/record-verification`
    RecordUserVerification,
    /// `POST /admin-api/users/remove-verification`
    RemoveUserVerification,
    /// `POST /admin-api/users/disable`
    DisableUserAccount,
    /// `POST /admin-api/users/enable`
    EnableUserAccount,
    /// `POST /admin-api/users/federation-link`
    LinkUserFederation,
    /// `POST /admin-api/users/federation-unlink`
    UnlinkUserFederation,
    /// `POST /admin-api/users/create-app-password`
    CreateUserAppPassword,
    /// `POST /admin-api/users/revoke-app-password`
    RevokeUserAppPassword,
    /// `POST /admin-api/users/begin-passkey-upgrade`
    BeginUserPasskeyUpgrade,
    /// `POST /admin-api/users/prove-passkey-upgrade`
    ProveUserPasskeyUpgrade,
    /// `POST /admin-api/users/finish-passkey-upgrade`
    FinishUserPasskeyUpgrade,
    /// `POST /admin-api/users/cancel-passkey-upgrade`
    CancelUserPasskeyUpgrade,
    /// `POST /admin-api/users/clear-key`
    ClearUserSecurityKey,
    /// `POST /admin-api/users/rename-key`
    RenameUserPasskey,
    /// `POST /admin-api/users/begin-passkey-enrolment`
    BeginUserPasskeyEnrolment,
    /// `POST /admin-api/users/finish-passkey-enrolment`
    FinishUserPasskeyEnrolment,
    /// `GET /admin-api/sessions`
    GetSessions,
    /// `POST /admin-api/sessions/revoke`
    RevokeSession,
    /// `GET /admin-api/logout`
    GetLiveSessions,
    /// `POST /admin-api/logout/global`
    GlobalLogout,
    /// `POST /admin-api/logout/end`
    EndLiveSessions,
    /// `POST /admin-api/logout/retry-backchannel`
    RetryBackchannelDelivery,
    /// `POST /admin-api/logout/restore-token`
    RestoreLoggedOutToken,
    /// `POST /admin-api/logout/restore-kerberos`
    ClearKerberosSignOut,
    /// `GET /admin-api/groups`
    GetGroups,
    /// `POST /admin-api/groups/create`
    CreateGroup,
    /// `POST /admin-api/groups/add-member`
    AddGroupMember,
    /// `POST /admin-api/groups/set-mail`
    SetGroupMail,
    /// `POST /admin-api/groups/set-policy`
    SetGroupPolicy,
    /// `POST /admin-api/groups/add-owner`
    AddGroupOwner,
    /// `POST /admin-api/groups/remove-owner`
    RemoveGroupOwner,
    /// `GET /admin-api/ldap/directory`
    GetDirectoryEntries,
    /// `GET /admin-api/ldap/applications`
    GetDirectoryApplications,
    /// `GET /admin-api/ldap/federations`
    GetDirectoryFederations,
    /// `GET /admin-api/ldap/spiffe`
    GetDirectorySpiffe,
    /// `GET /admin-api/ldap/roles`
    GetDirectoryRoles,
    /// `GET /admin-api/ldap/policies`
    GetDirectoryPolicies,
    /// `GET /admin-api/ldap/peps`
    GetDirectoryPeps,
    /// `GET /admin-api/ldap/devices`
    GetDirectoryDevices,
    /// `GET /admin-api/ldap/service`
    GetDirectoryService,
    /// `GET /admin-api/rbac`
    GetAdminRoles,
    /// `POST /admin-api/rbac/grant`
    GrantAdminRole,
    /// `POST /admin-api/rbac/revoke`
    RevokeAdminRole,
    /// `GET /admin-api/mfa`
    GetMultiFactor,
    /// `POST /admin-api/mfa/clear-totp`
    ClearAuthenticatorApp,
    /// `POST /admin-api/mfa/clear-key`
    ClearSecurityKey,
    /// `POST /admin-api/mfa/clear-email-factor`
    ClearEmailFactor,
    /// `GET /admin-api/tokens/credential`
    GetCredentialLineage,
    /// `GET /admin-api/tokens`
    GetIssued,
    /// `GET /admin-api/tokens/set`
    GetIssuedSet,
    /// `POST /admin-api/tokens/revoke`
    RevokeToken,
    /// `POST /admin-api/tokens/restore`
    RestoreToken,
    /// `POST /admin-api/tokens/revoke-artifact`
    RevokeIssuedArtifact,
    /// `POST /admin-api/tokens/restore-artifact`
    RestoreIssuedArtifact,
    /// `POST /admin-api/tokens/revoke-set`
    RevokeIssuedSet,
    /// `POST /admin-api/tokens/restore-set`
    RestoreIssuedSet,
    /// `POST /admin-api/tokens/revoke-kind`
    RevokeTokensByKind,
    /// `POST /admin-api/tokens/revoke-subject`
    RevokeTokensBySubject,
    /// `POST /admin-api/tokens/revoke-user`
    RevokeTokensByUser,
    /// `POST /admin-api/tokens/revoke-all`
    RevokeAllTokens,
    /// `GET /admin-api/realms`
    GetRealms,
    /// `POST /admin-api/realms/create`
    CreateRealm,
    /// `POST /admin-api/realms/update`
    UpdateRealm,
    /// `POST /admin-api/realms/set`
    SetRealmSetting,
    /// `POST /admin-api/realms/unset`
    UnsetRealmSetting,
    /// `POST /admin-api/realms/remove`
    RemoveRealm,
    /// `GET /admin-api/config`
    GetConfig,
    /// `GET /admin-api/config-dump`
    GetConfigDump,
    /// `POST /admin-api/config/set`
    SetSetting,
    /// `POST /admin-api/config/set-many`
    SetSettings,
    /// `POST /admin-api/config/reset`
    ResetSetting,
    /// `POST /admin-api/config/reset-all`
    ResetAllSettings,
    /// `GET /admin-api/oauth2`
    GetOauth2Settings,
    /// `GET /admin-api/oid4vci-settings`
    GetOid4vciSettings,
    /// `GET /admin-api/oid4vp-settings`
    GetOid4vpSettings,
    /// `GET /admin-api/totp`
    GetTotpSettings,
    /// `GET /admin-api/backup-codes`
    GetBackupCodesSettings,
    /// `GET /admin-api/webauthn`
    GetWebauthnSettings,
    /// `GET /admin-api/kerberos`
    GetKerberosSettings,
    /// `GET /admin-api/ldap`
    GetLdapSettings,
    /// `GET /admin-api/persistence`
    GetPersistenceSettings,
    /// `GET /admin-api/cluster`
    GetClusterSettings,
    /// `GET /admin-api/wstrust`
    GetWsTrustSettings,
    /// `GET /admin-api/wsfed`
    GetWsFedSettings,
    /// `GET /admin-api/tls`
    GetTlsSettings,
    /// `GET /admin-api/token-lifetimes`
    GetTokenLifetimes,
    /// `POST /admin-api/token-lifetimes/set`
    SetTokenLifetimes,
    /// `POST /admin-api/token-lifetimes/defaults`
    ResetTokenLifetimes,
    /// `GET /admin-api/saml-assertions`
    GetSamlAssertions,
    /// `POST /admin-api/saml-assertions/set`
    SetSamlAssertions,
    /// `POST /admin-api/saml-assertions/defaults`
    ResetSamlAssertions,
    /// `GET /admin-api/claims`
    GetClaims,
    /// `POST /admin-api/claims/add`
    AddClaim,
    /// `POST /admin-api/claims/add-attribute-claim`
    AddAttributeClaim,
    /// `POST /admin-api/claims/remove`
    RemoveClaim,
    /// `POST /admin-api/claims/clear`
    ClearClaims,
    /// `POST /admin-api/claims/replace`
    ReplaceClaims,
    /// `POST /admin-api/claims/attributes`
    SetClaimAttributes,
    /// `POST /admin-api/claims/attributes-all`
    SelectAllClaimAttributes,
    /// `POST /admin-api/claims/attributes-clear`
    ClearClaimAttributes,
    /// `GET /admin-api/userinfo-claims`
    GetUserInfoClaims,
    /// `POST /admin-api/userinfo-claims/add`
    AddUserInfoClaim,
    /// `POST /admin-api/userinfo-claims/add-attribute-claim`
    AddUserInfoAttributeClaim,
    /// `POST /admin-api/userinfo-claims/remove`
    RemoveUserInfoClaim,
    /// `POST /admin-api/userinfo-claims/clear`
    ClearUserInfoClaims,
    /// `POST /admin-api/userinfo-claims/replace`
    ReplaceUserInfoClaims,
    /// `POST /admin-api/userinfo-claims/attributes`
    SetUserInfoClaimAttributes,
    /// `POST /admin-api/userinfo-claims/attributes-all`
    SelectAllUserInfoClaimAttributes,
    /// `POST /admin-api/userinfo-claims/attributes-clear`
    ClearUserInfoClaimAttributes,
    /// `GET /admin-api/saml-attributes`
    GetSamlAttributes,
    /// `POST /admin-api/saml-attributes/add`
    AddSamlAttribute,
    /// `POST /admin-api/saml-attributes/add-attribute-claim`
    AddSamlDirectoryAttributeClaim,
    /// `POST /admin-api/saml-attributes/remove`
    RemoveSamlAttribute,
    /// `POST /admin-api/saml-attributes/clear`
    ClearSamlAttributes,
    /// `POST /admin-api/saml-attributes/replace`
    ReplaceSamlAttributes,
    /// `POST /admin-api/saml-attributes/attributes`
    SetSamlDirectoryAttributes,
    /// `POST /admin-api/saml-attributes/attributes-all`
    SelectAllSamlDirectoryAttributes,
    /// `POST /admin-api/saml-attributes/attributes-clear`
    ClearSamlDirectoryAttributes,
    /// `GET /admin-api/kerberos/claims`
    GetKerberosPacClaims,
    /// `POST /admin-api/kerberos/claims/add`
    AddKerberosPacClaim,
    /// `POST /admin-api/kerberos/claims/add-attribute-claim`
    AddKerberosPacAttributeClaim,
    /// `POST /admin-api/kerberos/claims/remove`
    RemoveKerberosPacClaim,
    /// `POST /admin-api/kerberos/claims/clear`
    ClearKerberosPacClaims,
    /// `POST /admin-api/kerberos/claims/replace`
    ReplaceKerberosPacClaims,
    /// `POST /admin-api/kerberos/claims/attributes`
    SetKerberosPacClaimAttributes,
    /// `POST /admin-api/kerberos/claims/attributes-all`
    SelectAllKerberosPacClaimAttributes,
    /// `POST /admin-api/kerberos/claims/attributes-clear`
    ClearKerberosPacClaimAttributes,
    /// `GET /admin-api/credential-claims`
    GetCredentialClaims,
    /// `POST /admin-api/credential-claims/select`
    SelectCredentialClaims,
    /// `POST /admin-api/credential-claims/add`
    AddCredentialClaim,
    /// `POST /admin-api/credential-claims/remove`
    RemoveCredentialClaim,
    /// `POST /admin-api/credential-claims/defaults`
    ResetCredentialClaims,
    /// `POST /admin-api/credential-claims/populate`
    PopulateDirectory,
    /// `GET /admin-api/verifier-request`
    GetVerifierRequest,
    /// `POST /admin-api/verifier-request/select`
    SelectRequestedClaims,
    /// `POST /admin-api/verifier-request/add`
    AddRequestedClaim,
    /// `POST /admin-api/verifier-request/remove`
    RemoveRequestedClaim,
    /// `POST /admin-api/verifier-request/defaults`
    ResetRequestedClaims,
    /// `POST /admin-api/verifier-request/format`
    SetRequestFormat,
    /// `POST /admin-api/verifications/start`
    StartVerification,
    /// `GET /admin-api/verifications`
    GetVerifications,
    /// `GET /admin-api/oid4vci/last-request`
    GetLastCredentialRequest,
    /// `GET /admin-api/oid4vci/notifications`
    GetCredentialNotification,
    /// `GET /admin-api/federation`
    GetFederationRelationships,
    /// `POST /admin-api/federation/create`
    CreateFederationRelationship,
    /// `POST /admin-api/federation/set`
    SetFederationField,
    /// `POST /admin-api/federation/add-value`
    AddFederationValue,
    /// `POST /admin-api/federation/remove-value`
    RemoveFederationValue,
    /// `POST /admin-api/federation/enable`
    EnableFederationRelationship,
    /// `POST /admin-api/federation/disable`
    DisableFederationRelationship,
    /// `POST /admin-api/federation/check-partner`
    CheckFederationPartner,
    /// `POST /admin-api/federation/register-partner`
    RegisterAtFederationPartner,
    /// `POST /admin-api/federation/rotate-key`
    RotateFederationKey,
    /// `POST /admin-api/federation/signals-discover`
    DiscoverFederationSignals,
    /// `POST /admin-api/federation/signals-create-stream`
    CreateFederationSignalsStream,
    /// `POST /admin-api/federation/signals-read-stream`
    ReadFederationSignalsStream,
    /// `POST /admin-api/federation/signals-update-stream`
    UpdateFederationSignalsStream,
    /// `POST /admin-api/federation/signals-replace-stream`
    ReplaceFederationSignalsStream,
    /// `POST /admin-api/federation/signals-delete-stream`
    DeleteFederationSignalsStream,
    /// `POST /admin-api/federation/signals-read-status`
    ReadFederationSignalsStatus,
    /// `POST /admin-api/federation/signals-verify`
    VerifyFederationSignalsStream,
    /// `POST /admin-api/federation/signals-poll-now`
    PollFederationSignals,
    /// `POST /admin-api/federation/signals-set-status`
    SetFederationSignalsStatus,
    /// `POST /admin-api/federation/signals-add-subject`
    AddFederationSignalsSubject,
    /// `POST /admin-api/federation/signals-remove-subject`
    RemoveFederationSignalsSubject,
    /// `POST /admin-api/federation/signals-unblock`
    UnblockFederationSignals,
    /// `POST /admin-api/federation/delete`
    DeleteFederationRelationship,
    /// `GET /admin-api/saml2`
    GetSaml2ServiceProviders,
    /// `POST /admin-api/saml2/register`
    RegisterSaml2ServiceProvider,
    /// `POST /admin-api/saml2/set-logout-service`
    AddSaml2LogoutService,
    /// `POST /admin-api/saml2/remove-logout-service`
    RemoveSaml2LogoutService,
    /// `POST /admin-api/saml2/set-signing-certificate`
    SetSaml2SigningCertificate,
    /// `POST /admin-api/saml2/remove-signing-certificate`
    RemoveSaml2SigningCertificate,
    /// `POST /admin-api/saml2/confirm-signing-certificate`
    ConfirmSaml2SigningCertificate,
    /// `POST /admin-api/saml2/discard-signing-certificate`
    DiscardSaml2SigningCertificate,
    /// `POST /admin-api/saml2/set-metadata-signing-certificate`
    SetSaml2MetadataSigningCertificate,
    /// `POST /admin-api/saml2/refresh-metadata`
    RefreshSaml2Metadata,
    /// `POST /admin-api/saml2/mdq-import`
    ImportSaml2MetadataFromMdq,
    /// `POST /admin-api/saml2/upload-metadata`
    UploadSaml2Metadata,
    /// `GET /admin-api/saml11`
    GetSaml11RelyingParties,
    /// `GET /admin-api/saml-idp-initiated`
    GetSamlIdpInitiatedApplications,
    /// `POST /admin-api/saml11/register`
    RegisterSaml11RelyingParty,
    /// `GET /admin-api/authorization-servers`
    GetAuthorizationServers,
    /// `POST /admin-api/authorization-servers/create`
    CreateAuthorizationServer,
    /// `POST /admin-api/authorization-servers/set`
    SetAuthorizationServerMember,
    /// `POST /admin-api/authorization-servers/remove`
    RemoveAuthorizationServerMember,
    /// `POST /admin-api/authorization-servers/reset`
    ResetAuthorizationServerMember,
    /// `POST /admin-api/authorization-servers/delete`
    DeleteAuthorizationServer,
    /// `GET /admin-api/applications`
    GetApplications,
    /// `GET /admin-api/applications/new`
    GetNewApplicationForm,
    /// `POST /admin-api/applications/create`
    CreateApplication,
    /// `POST /admin-api/applications/set`
    SetApplicationAttribute,
    /// `POST /admin-api/applications/add`
    AddApplicationValue,
    /// `POST /admin-api/applications/remove`
    RemoveApplicationValue,
    /// `POST /admin-api/applications/update-fields`
    UpdateApplicationFields,
    /// `POST /admin-api/applications/confirm-address`
    ConfirmApplicationReturnAddress,
    /// `POST /admin-api/applications/discard-address`
    DiscardApplicationReturnAddress,
    /// `POST /admin-api/applications/add-owner`
    AddApplicationOwner,
    /// `POST /admin-api/applications/remove-owner`
    RemoveApplicationOwner,
    /// `POST /admin-api/applications/regenerate-secret`
    RegenerateApplicationClientSecret,
    /// `POST /admin-api/applications/rotate-secret`
    RotateApplicationClientSecret,
    /// `POST /admin-api/applications/add-secret`
    AddApplicationClientSecret,
    /// `POST /admin-api/applications/remove-secret`
    RemoveApplicationClientSecret,
    /// `POST /admin-api/applications/reveal-secret`
    RevealApplicationSecret,
    /// `POST /admin-api/applications/generate-did-key`
    GenerateApplicationDidKey,
    /// `POST /admin-api/applications/sign-domain-linkage`
    SignApplicationDomainLinkage,
    /// `POST /admin-api/applications/set-custom-claim`
    SetApplicationCustomClaim,
    /// `POST /admin-api/applications/remove-custom-claim`
    RemoveApplicationCustomClaim,
    /// `POST /admin-api/applications/set-claim-attributes`
    SetApplicationClaimAttributes,
    /// `POST /admin-api/applications/set-claim-selections`
    SetApplicationClaimSelections,
    /// `POST /admin-api/applications/inherit-claim-attributes`
    InheritApplicationClaimAttributes,
    /// `POST /admin-api/applications/set-permission-claims`
    SetApplicationPermissionClaims,
    /// `POST /admin-api/applications/clear-permission-claims`
    ClearApplicationPermissionClaims,
    /// `POST /admin-api/applications/set-access-type`
    SetApplicationAccessType,
    /// `POST /admin-api/applications/remove-access-type`
    RemoveApplicationAccessType,
    /// `POST /admin-api/applications/set-access-type-row`
    SetApplicationAccessTypeRow,
    /// `POST /admin-api/applications/remove-access-type-row`
    RemoveApplicationAccessTypeRow,
    /// `POST /admin-api/applications/set-not-for-policy`
    SetApplicationAccessTypeNotForPolicy,
    /// `POST /admin-api/applications/fga-enable`
    EnableApplicationFga,
    /// `POST /admin-api/applications/fga-disable`
    DisableApplicationFga,
    /// `POST /admin-api/applications/fga-create-policy`
    CreateApplicationFgaPolicy,
    /// `POST /admin-api/applications/fga-reset-policy`
    ResetApplicationFgaPolicy,
    /// `POST /admin-api/applications/issue-tls-client-certificate`
    IssueApplicationTlsClientCertificate,
    /// `POST /admin-api/applications/revoke-tls-client-certificate`
    RevokeApplicationTlsClientCertificate,
    /// `POST /admin-api/applications/issue-signing-certificate`
    IssueApplicationSigningCertificate,
    /// `POST /admin-api/applications/revoke-signing-certificate`
    RevokeApplicationSigningCertificate,
    /// `POST /admin-api/applications/add-certificate`
    AddApplicationCertificate,
    /// `POST /admin-api/applications/remove-certificate`
    RemoveApplicationCertificate,
    /// `POST /admin-api/applications/issue-software-statement`
    IssueApplicationSoftwareStatement,
    /// `POST /admin-api/applications/revoke-registration`
    RevokeApplicationRegistration,
    /// `POST /admin-api/applications/refresh-metadata`
    RefreshApplicationMetadata,
    /// `POST /admin-api/applications/load-resource-metadata`
    LoadProtectedResourceMetadata,
    /// `POST /admin-api/applications/export-ldif`
    ExportApplicationLdif,
    /// `POST /admin-api/applications/import-ldif`
    ImportApplicationLdif,
    /// `POST /admin-api/applications/forget`
    DeleteApplication,
    /// `GET /admin-api/xacml`
    GetXacml,
    /// `GET /admin-api/xacml/policies`
    GetXacmlPolicies,
    /// `GET /admin-api/xacml/editor`
    GetXacmlEditor,
    /// `GET /admin-api/xacml/decide`
    GetXacmlDecision,
    /// `GET /admin-api/gnap`
    GetGnap,
    /// `GET /admin-api/gnap/monitor`
    GetGnapMonitor,
    /// `POST /admin-api/gnap/revoke-grant`
    RevokeGnapGrant,
    /// `POST /admin-api/gnap/delete-resource-set`
    DeleteGnapResourceSet,
    /// `GET /admin-api/xacml/monitor`
    GetXacmlMonitor,
    /// `GET /admin-api/xacml/peps`
    GetXacmlPeps,
    /// `POST /admin-api/xacml/create-from-template`
    CreateXacmlPolicy,
    /// `POST /admin-api/xacml/import-alfa`
    ImportXacmlAlfa,
    /// `POST /admin-api/xacml/enable`
    EnableXacmlPolicy,
    /// `POST /admin-api/xacml/disable`
    DisableXacmlPolicy,
    /// `POST /admin-api/xacml/set-root`
    SetXacmlRootPolicy,
    /// `POST /admin-api/xacml/delete`
    DeleteXacmlPolicy,
    /// `POST /admin-api/xacml/edit-policy`
    EditXacmlPolicy,
    /// `POST /admin-api/xacml/add-rule`
    AddXacmlRule,
    /// `POST /admin-api/xacml/edit-match`
    EditXacmlMatch,
    /// `POST /admin-api/xacml/remove`
    RemoveXacmlNode,
    /// `POST /admin-api/xacml/add-target-anyof`
    AddXacmlTargetClause,
    /// `POST /admin-api/xacml/add-allof`
    AddXacmlAlternative,
    /// `POST /admin-api/xacml/add-match`
    AddXacmlMatch,
    /// `POST /admin-api/xacml/edit-rule`
    EditXacmlRule,
    /// `POST /admin-api/xacml/add-condition`
    AddXacmlCondition,
    /// `POST /admin-api/xacml/set-expression-apply`
    SetXacmlApply,
    /// `POST /admin-api/xacml/set-expression-value`
    SetXacmlValue,
    /// `POST /admin-api/xacml/set-expression-designator`
    SetXacmlDesignator,
    /// `POST /admin-api/xacml/set-expression-variable`
    SetXacmlVariable,
    /// `POST /admin-api/xacml/add-argument`
    AddXacmlArgument,
    /// `POST /admin-api/xacml/edit-apply`
    EditXacmlApply,
    /// `POST /admin-api/xacml/edit-value`
    EditXacmlValue,
    /// `POST /admin-api/xacml/edit-designator`
    EditXacmlDesignator,
    /// `POST /admin-api/xacml/add-rule-obligation`
    AddXacmlRuleObligation,
    /// `POST /admin-api/xacml/add-policy-obligation`
    AddXacmlPolicyObligation,
    /// `POST /admin-api/xacml/add-rule-advice`
    AddXacmlRuleAdvice,
    /// `POST /admin-api/xacml/add-policy-advice`
    AddXacmlPolicyAdvice,
    /// `POST /admin-api/xacml/edit-obligation`
    EditXacmlObligation,
    /// `POST /admin-api/xacml/add-assignment`
    AddXacmlAssignment,
    /// `POST /admin-api/xacml/add-policy`
    AddXacmlPolicyToSet,
    /// `POST /admin-api/xacml/add-policyset`
    AddXacmlPolicySetToSet,
    /// `POST /admin-api/xacml/add-policy-reference`
    AddXacmlPolicyReference,
    /// `POST /admin-api/xacml/add-policyset-reference`
    AddXacmlPolicySetReference,
    /// `POST /admin-api/xacml/edit-reference`
    EditXacmlReference,
    /// `POST /admin-api/xacml/add-variable`
    AddXacmlVariable,
    /// `POST /admin-api/xacml/edit-variable`
    RenameXacmlVariable,
    /// `POST /admin-api/xacml/set-expression-selector`
    SetXacmlExpressionSelector,
    /// `POST /admin-api/xacml/edit-selector`
    EditXacmlSelector,
    /// `POST /admin-api/xacml/set-expression-function`
    SetXacmlExpressionFunction,
    /// `POST /admin-api/xacml/edit-function`
    EditXacmlFunctionReference,
    /// `POST /admin-api/xacml/edit-assignment`
    EditXacmlAssignment,
    /// `POST /admin-api/xacml/disable-pep`
    DisableXacmlPep,
    /// `POST /admin-api/xacml/enable-pep`
    EnableXacmlPep,
    /// `POST /admin-api/xacml/forget-pep`
    ForgetXacmlPep,
    /// `POST /admin-api/xacml/issue-pep-certificate`
    IssueXacmlPepCertificate,
    /// `GET /admin-api/ssf`
    GetSsf,
    /// `GET /admin-api/ssf/dead-letters`
    GetSsfDeadLetters,
    /// `POST /admin-api/ssf/status`
    SetSsfStreamStatus,
    /// `POST /admin-api/ssf/transmit`
    TransmitSsfEvent,
    /// `POST /admin-api/ssf/delete`
    DeleteSsfStream,
    /// `POST /admin-api/ssf/revive`
    ReviveSsfStream,
    /// `POST /admin-api/ssf/verify`
    VerifySsfStream,
    /// `POST /admin-api/ssf/clear-dead-letters`
    ClearSsfDeadLetters,
    /// `GET /admin-api/caep`
    GetCaep,
    /// `GET /admin-api/caep/sessions`
    GetCaepSessions,
    /// `POST /admin-api/caep/emit`
    EmitCaepEvent,
    /// `POST /admin-api/caep/reset-session`
    ResetCaepSession,
    /// `POST /admin-api/caep/clear`
    ClearCaepSessions,
    /// `GET /admin-api/risc`
    GetRisc,
    /// `GET /admin-api/risc/accounts`
    GetRiscAccounts,
    /// `POST /admin-api/risc/emit`
    EmitRiscEvent,
    /// `POST /admin-api/risc/reset-account`
    ResetRiscAccount,
    /// `POST /admin-api/risc/clear`
    ClearRiscAccounts,
    /// `GET /admin-api/scim`
    GetScim,
    /// `GET /admin-api/pki`
    GetPki,
    /// `GET /admin-api/certificates`
    GetCertificates,
    /// `GET /admin-api/pki/trust`
    GetPkiTrust,
    /// `POST /admin-api/pki/trust/add`
    AddSignerTrustAnchors,
    /// `POST /admin-api/pki/trust/remove`
    RemoveSignerTrustAnchor,
    /// `POST /admin-api/pki/trust/recheck`
    RecheckPinnedCertificates,
    /// `POST /admin-api/pki/trust/set-row`
    SetParanoidPkiRow,
    /// `POST /admin-api/pki/build`
    BuildPkiChain,
    /// `POST /admin-api/pki/issue`
    IssuePkiKeyPair,
    /// `POST /admin-api/pki/revoke`
    RevokePkiKeyPair,
    /// `POST /admin-api/pki/upload-certificate`
    UploadPkiCertificate,
    /// `POST /admin-api/pki/clear`
    ClearPkiChain,
    /// `POST /admin-api/pki/issue-certificate`
    IssuePkiCertificate,
    /// `POST /admin-api/pki/remove-object`
    RemovePkiObject,
    /// `POST /admin-api/pki/clear-store`
    ClearPkiObjects,
    /// `POST /admin-api/pki/export`
    ExportPkiKeyPair,
    /// `POST /admin-api/pki/build-root`
    BuildPkiRoot,
    /// `POST /admin-api/pki/build-scope`
    BuildPkiScope,
    /// `POST /admin-api/pki/reissue-use-case`
    ReissuePkiUseCase,
    /// `POST /admin-api/pki/recertify`
    RecertifyPkiUseCase,
    /// `POST /admin-api/pki/import-ca`
    ImportPkiCa,
    /// `POST /admin-api/pki/pin-key`
    PinPkiKeyPair,
    /// `POST /admin-api/pki/unpin-key`
    UnpinPkiKeyPair,
    /// `POST /admin-api/pki/revoke-certificate`
    RevokePkiCertificate,
    /// `POST /admin-api/pki/release-hold`
    ReleasePkiCertificateHold,
    /// `GET /admin-api/scim/monitor`
    GetScimMonitor,
    /// `GET /admin-api/signals`
    GetSignals,
    /// `POST /admin-api/signals/clear`
    ClearSignalsInbox,
    /// `GET /admin-api/tls/trust`
    GetTruststore,
    /// `POST /admin-api/tls/trust/add`
    AddTrustAnchors,
    /// `POST /admin-api/tls/trust/remove`
    RemoveTrustAnchor,
    /// `GET /admin-api/tls-connection`
    GetTlsConnection,
    /// `GET /admin-api/kerberos/principals`
    GetKerberosPrincipals,
    /// `POST /admin-api/kerberos/principals/create-service`
    CreateKerberosServicePrincipal,
    /// `POST /admin-api/kerberos/principals/rotate-service`
    RotateKerberosServicePrincipal,
    /// `POST /admin-api/kerberos/principals/delete-service`
    DeleteKerberosServicePrincipal,
    /// `POST /admin-api/kerberos/principals/clear-person-keys`
    ClearKerberosPersonKeys,
    /// `POST /admin-api/kerberos/principals/drop-previous-service-keys`
    DropKerberosServicePreviousKeys,
    /// `POST /admin-api/kerberos/principals/drop-previous-person-keys`
    DropKerberosPersonPreviousKeys,
    /// `POST /admin-api/kerberos/principals/reset-person-keytab`
    ResetKerberosPersonKeytab,
    /// `POST /admin-api/kerberos/principals/rotate-krbtgt`
    RotateKerberosKrbtgt,
    /// `POST /admin-api/kerberos/principals/rotate-krbtgt-invalidate`
    RotateKerberosKrbtgtInvalidate,
    /// `GET /admin-api/kerberos/trusts`
    GetKerberosTrusts,
    /// `POST /admin-api/kerberos/trusts/add`
    AddKerberosTrust,
    /// `POST /admin-api/kerberos/trusts/update`
    UpdateKerberosTrust,
    /// `POST /admin-api/kerberos/trusts/enable`
    EnableKerberosTrust,
    /// `POST /admin-api/kerberos/trusts/disable`
    DisableKerberosTrust,
    /// `POST /admin-api/kerberos/trusts/rotate-key`
    RotateKerberosTrustKey,
    /// `POST /admin-api/kerberos/trusts/remove`
    RemoveKerberosTrust,
    /// `POST /admin-api/kerberos/trusts/pair`
    PairKerberosTrust,
    /// `GET /admin-api/audit`
    GetAudit,
    /// `GET /admin-api/error-codes`
    GetErrorCodes,
    /// `GET /admin-api/used-assertions`
    GetUsedAssertions,
    /// `GET /admin-api/delegation`
    GetDelegation,
    /// `GET /admin-api/delegation/user`
    GetDelegationUser,
    /// `GET /admin-api/delegation/application`
    GetDelegationApplication,
    /// `GET /admin-api/delegation/policy`
    GetDelegationPolicy,
    /// `GET /admin-api/permissions`
    GetPermissions,
    /// `GET /admin-api/permissions/groups`
    GetPermissionGroups,
    /// `POST /admin-api/permissions/set-permission-base`
    SetPermissionBase,
    /// `POST /admin-api/permissions/define-permission`
    DefinePermission,
    /// `POST /admin-api/permissions/remove-permission`
    RemovePermission,
    /// `POST /admin-api/permissions/grant-permission`
    GrantPermission,
    /// `POST /admin-api/permissions/revoke-permission`
    RevokePermission,
    /// `GET /admin-api/roles`
    GetRoles,
    /// `GET /admin-api/roles/preview`
    PreviewRoleIssuance,
    /// `POST /admin-api/roles/create-role`
    CreateRole,
    /// `POST /admin-api/roles/delete-role`
    DeleteRole,
    /// `POST /admin-api/roles/describe-role`
    DescribeRole,
    /// `POST /admin-api/roles/add-member`
    AddRoleMember,
    /// `POST /admin-api/roles/remove-member`
    RemoveRoleMember,
    /// `POST /admin-api/roles/add-permission`
    AddRolePermission,
    /// `POST /admin-api/roles/remove-permission`
    RemoveRolePermission,
    /// `POST /admin-api/roles/add-conferring-client`
    AddRoleConferringClient,
    /// `POST /admin-api/roles/remove-conferring-client`
    RemoveRoleConferringClient,
    /// `POST /admin-api/roles/add-owner`
    AddRoleOwner,
    /// `POST /admin-api/roles/remove-owner`
    RemoveRoleOwner,
    /// `GET /admin-api/ownership`
    GetOwnership,
    /// `POST /admin-api/ownership/set-protected`
    SetOwnerProtected,
    /// `GET /admin-api/policies`
    GetPolicies,
    /// `POST /admin-api/policies/save-password-policy`
    SavePasswordPolicy,
    /// `POST /admin-api/policies/reset-password-policy`
    ResetPasswordPolicy,
    /// `POST /admin-api/policies/save-authn-policy`
    SaveAuthnPolicy,
    /// `POST /admin-api/policies/reset-authn-policy`
    ResetAuthnPolicy,
    /// `POST /admin-api/policies/save-named-authn-policy`
    SaveNamedAuthnPolicy,
    /// `POST /admin-api/policies/delete-named-authn-policy`
    DeleteNamedAuthnPolicy,
    /// `GET /admin-api/policies/transfer`
    GetPolicyTransfer,
    /// `POST /admin-api/policies/transfer/export`
    ExportPolicies,
    /// `POST /admin-api/policies/transfer/inspect`
    InspectPolicyExport,
    /// `POST /admin-api/policies/transfer/import`
    ImportPolicies,
    /// `POST /admin-api/policies/save-serviceAccount-policy`
    SaveServiceAccountPolicy,
    /// `POST /admin-api/policies/reset-serviceAccount-policy`
    ResetServiceAccountPolicy,
    /// `POST /admin-api/policies/save-passkey-policy`
    SavePasskeyPolicy,
    /// `POST /admin-api/policies/reset-passkey-policy`
    ResetPasskeyPolicy,
    /// `POST /admin-api/policies/clear-passkey-client`
    ClearPasskeyClient,
    /// `POST /admin-api/policies/clear-passkey-clients`
    ClearPasskeyClients,
    /// `POST /admin-api/policies/save-locale-policy`
    SaveLocalePolicy,
    /// `POST /admin-api/policies/reset-locale-policy`
    ResetLocalePolicy,
    /// `POST /admin-api/policies/save-attributes-policy`
    SaveAttributesPolicy,
    /// `POST /admin-api/policies/reset-attributes-policy`
    ResetAttributesPolicy,
    /// `POST /admin-api/policies/define-person-attribute`
    DefinePersonAttribute,
    /// `POST /admin-api/policies/update-person-attribute`
    UpdatePersonAttribute,
    /// `POST /admin-api/policies/remove-person-attribute`
    RemovePersonAttribute,
    /// `POST /admin-api/policies/save-postLogin-policy`
    SavePostLoginPolicy,
    /// `POST /admin-api/policies/reset-postLogin-policy`
    ResetPostLoginPolicy,
    /// `GET /admin-api/consent`
    GetConsent,
    /// `POST /admin-api/consent/grant-global-consent`
    GrantGlobalConsent,
    /// `POST /admin-api/consent/revoke-global-consent`
    RevokeGlobalConsent,
    /// `POST /admin-api/consent/revoke-consent`
    RevokeConsent,
    /// `POST /admin-api/consent/revoke-application-consent`
    RevokeApplicationConsent,
    /// `POST /admin-api/consent/forget-user-consent`
    ForgetUserConsent,
    /// `GET /admin-api/spiffe`
    GetSpiffe,
    /// `POST /admin-api/spiffe/rotate`
    RotateSpiffeAuthority,
    /// `POST /admin-api/spiffe/federation-set`
    SetSpiffeFederatedBundle,
    /// `POST /admin-api/spiffe/federation-remove`
    RemoveSpiffeFederatedBundle,
    /// `GET /admin-api/spiffe/entries`
    GetSpiffeEntries,
    /// `POST /admin-api/spiffe/entries/create`
    CreateSpiffeEntry,
    /// `POST /admin-api/spiffe/entries/update`
    UpdateSpiffeEntry,
    /// `POST /admin-api/spiffe/entries/delete`
    DeleteSpiffeEntry,
    /// `GET /admin-api/spiffe/brokers`
    GetSpiffeBrokers,
    /// `POST /admin-api/spiffe/brokers/set`
    SetSpiffeBroker,
    /// `POST /admin-api/spiffe/brokers/remove`
    RemoveSpiffeBroker,
    /// `GET /admin-api/spiffe/agents`
    GetSpiffeAgents,
    /// `POST /admin-api/spiffe/agents/ban`
    BanSpiffeAgent,
    /// `POST /admin-api/spiffe/agents/unban`
    UnbanSpiffeAgent,
    /// `POST /admin-api/spiffe/agents/delete`
    DeleteSpiffeAgent,
    /// `POST /admin-api/spiffe/agents/join-token`
    CreateSpiffeJoinToken,
    /// `GET /admin-api/acme`
    GetAcme,
    /// `GET /admin-api/acme/monitor`
    GetAcmeMonitor,
    /// `POST /admin-api/acme/create-eab`
    CreateAcmeEab,
    /// `POST /admin-api/acme/delete-eab`
    DeleteAcmeEab,
    /// `POST /admin-api/acme/deactivate-account`
    DeactivateAcmeAccount,
    /// `POST /admin-api/acme/revoke-certificate`
    RevokeAcmeCertificate,
    /// `POST /admin-api/acme/add-host-name`
    AddAcmeHostName,
    /// `POST /admin-api/acme/remove-host-name`
    RemoveAcmeHostName,
    /// `GET /admin-api/est`
    GetEst,
    /// `GET /admin-api/est/monitor`
    GetEstMonitor,
    /// `POST /admin-api/est/issue-server-key`
    IssueEstServerKey,
    /// `POST /admin-api/est/revoke-certificate`
    RevokeEstCertificate,
    /// `POST /admin-api/est/add-host-name`
    AddEstHostName,
    /// `POST /admin-api/est/remove-host-name`
    RemoveEstHostName,
    /// `GET /admin-api/scep`
    GetScep,
    /// `GET /admin-api/scep/monitor`
    GetScepMonitor,
    /// `POST /admin-api/scep/create-challenge`
    CreateScepChallenge,
    /// `POST /admin-api/scep/delete-challenge`
    DeleteScepChallenge,
    /// `POST /admin-api/scep/reissue-ra`
    ReissueScepRa,
    /// `POST /admin-api/scep/revoke-certificate`
    RevokeScepCertificate,
    /// `POST /admin-api/scep/add-host-name`
    AddScepHostName,
    /// `POST /admin-api/scep/remove-host-name`
    RemoveScepHostName,
    /// `GET /admin-api/oidfed`
    GetOidfed,
    /// `POST /admin-api/oidfed/add-subordinate`
    AddOidfedSubordinate,
    /// `POST /admin-api/oidfed/remove-subordinate`
    RemoveOidfedSubordinate,
    /// `POST /admin-api/oidfed/suspend-subordinate`
    SuspendOidfedSubordinate,
    /// `POST /admin-api/oidfed/reinstate-subordinate`
    ReinstateOidfedSubordinate,
    /// `POST /admin-api/oidfed/crawl-collection`
    CrawlOidfedCollection,
    /// `POST /admin-api/oidfed/add-trust-anchor`
    AddOidfedTrustAnchor,
    /// `POST /admin-api/oidfed/remove-trust-anchor`
    RemoveOidfedTrustAnchor,
    /// `POST /admin-api/oidfed/add-mark-type`
    AddOidfedMarkType,
    /// `POST /admin-api/oidfed/remove-mark-type`
    RemoveOidfedMarkType,
    /// `POST /admin-api/oidfed/set-mark-policy`
    SetOidfedMarkPolicy,
    /// `POST /admin-api/oidfed/remove-mark-policy`
    RemoveOidfedMarkPolicy,
    /// `POST /admin-api/oidfed/issue-trust-mark`
    IssueOidfedTrustMark,
    /// `POST /admin-api/oidfed/revoke-trust-mark`
    RevokeOidfedTrustMark,
    /// `POST /admin-api/oidfed/add-held-mark`
    AddOidfedHeldMark,
    /// `POST /admin-api/oidfed/remove-held-mark`
    RemoveOidfedHeldMark,
    /// `POST /admin-api/oidfed/resolve`
    ResolveOidfedEntity,
    /// `POST /admin-api/oidfed/rotate-key`
    RotateOidfedKey,
    /// `POST /admin-api/oidfed/revoke-key`
    RevokeOidfedKey,
    /// `GET /admin-api/oauth2/monitor`
    GetOauth2Monitor,
    /// `POST /admin-api/oauth2/monitor/delete-pushed-request`
    DeletePushedRequest,
    /// `GET /admin-api/grants`
    GetGrants,
    /// `POST /admin-api/grants/revoke-grant`
    RevokeGrant,
    /// `GET /admin-api/claim-providers`
    GetClaimProviders,
    /// `POST /admin-api/claim-providers/add-provider`
    AddClaimProvider,
    /// `POST /admin-api/claim-providers/update-provider`
    UpdateClaimProvider,
    /// `POST /admin-api/claim-providers/remove-provider`
    RemoveClaimProvider,
    /// `POST /admin-api/claim-providers/revoke-link`
    RevokeClaimSourceLink,
    /// `GET /admin-api/attribute-sources`
    GetAttributeSources,
    /// `POST /admin-api/attribute-sources/add-source`
    AddAttributeSource,
    /// `POST /admin-api/attribute-sources/update-source`
    UpdateAttributeSource,
    /// `POST /admin-api/attribute-sources/remove-source`
    RemoveAttributeSource,
    /// `POST /admin-api/attribute-sources/test-source`
    TestAttributeSource,
    /// `POST /admin-api/attribute-sources/refresh-source`
    RefreshAttributeSource,
    /// `POST /admin-api/attribute-sources/refresh-person`
    RefreshAttributeSourcePerson,
    /// `GET /admin-api/secret-destinations`
    GetSecretDestinations,
    /// `POST /admin-api/secret-destinations/add-destination`
    AddSecretDestination,
    /// `POST /admin-api/secret-destinations/update-destination`
    UpdateSecretDestination,
    /// `POST /admin-api/secret-destinations/remove-destination`
    RemoveSecretDestination,
    /// `POST /admin-api/secret-destinations/test-push`
    TestSecretDestination,
    /// `GET /admin-api/xacml/authzen`
    GetXacmlAuthzen,
    /// `POST /admin-api/xacml/authzen/set-attribute`
    SetAuthzenAttribute,
    /// `POST /admin-api/xacml/authzen/remove-attribute`
    RemoveAuthzenAttribute,
    /// `POST /admin-api/xacml/authzen/set-scope`
    SetAuthzenScope,
    /// `POST /admin-api/xacml/authzen/set-callbacks`
    SetAuthzenCallbacks,
    /// `POST /admin-api/xacml/authzen/approve-access-request`
    ApproveAuthzenAccessRequest,
    /// `POST /admin-api/xacml/authzen/deny-access-request`
    DenyAuthzenAccessRequest,
    /// `POST /admin-api/xacml/authzen/revoke-access-request`
    RevokeAuthzenAccessRequest,
    /// `POST /admin-api/xacml/authzen/cancel-access-request`
    CancelAuthzenAccessRequest,
    /// `GET /admin-api/uma`
    GetUma,
    /// `GET /admin-api/uma/monitor`
    GetUmaMonitor,
    /// `POST /admin-api/uma/enable-resource-server`
    EnableUmaResourceServer,
    /// `POST /admin-api/uma/disable-resource-server`
    DisableUmaResourceServer,
    /// `POST /admin-api/uma/set-owns-resources`
    SetUmaOwnsResources,
    /// `POST /admin-api/uma/delete-resource`
    DeleteUmaResource,
    /// `POST /admin-api/uma/revoke-rpt`
    RevokeUmaRpt,
    /// `POST /admin-api/uma/owner-share`
    ShareUmaResource,
    /// `POST /admin-api/uma/owner-unshare`
    UnshareUmaResource,
    /// `POST /admin-api/uma/owner-approve`
    ApproveUmaRequest,
    /// `POST /admin-api/uma/owner-refuse`
    RefuseUmaRequest,
    /// `GET /admin-api/passkey-report`
    GetPasskeyReport,
    /// `GET /admin-api/passkey-report/export`
    ExportPasskeyReport,
    /// `GET /admin-api/passkey-report/evidence`
    ExportPasskeyAttestationEvidence,
    /// `POST /admin-api/passkey-report/recount`
    RecountPasskeyReport,
    /// `GET /admin-api/post-login-activities`
    GetPostLoginActivities,
    /// `POST /admin-api/post-login-activities/start`
    StartPostLoginActivity,
    /// `POST /admin-api/post-login-activities/pause`
    PausePostLoginActivity,
    /// `POST /admin-api/post-login-activities/resume`
    ResumePostLoginActivity,
    /// `POST /admin-api/post-login-activities/end`
    EndPostLoginActivity,
    /// `GET /admin-api/audit-export`
    GetAuditExport,
    /// `POST /admin-api/audit-export/add`
    AddAuditExportDestination,
    /// `POST /admin-api/audit-export/update`
    UpdateAuditExportDestination,
    /// `POST /admin-api/audit-export/remove`
    RemoveAuditExportDestination,
    /// `POST /admin-api/audit-export/enable`
    EnableAuditExportDestination,
    /// `POST /admin-api/audit-export/disable`
    DisableAuditExportDestination,
    /// `POST /admin-api/audit-export/test`
    TestAuditExportDestination,
    /// `GET /admin-api/branding`
    GetBranding,
    /// `POST /admin-api/branding/logo`
    UploadBrandingLogo,
    /// `POST /admin-api/branding/save`
    SaveBranding,
    /// `POST /admin-api/branding/remove-logo`
    RemoveBrandingLogo,
    /// `GET /admin-api/scim/clients`
    GetScimClients,
    /// `POST /admin-api/scim/clients/add-client`
    AddScimClient,
    /// `POST /admin-api/scim/clients/update-client`
    UpdateScimClient,
    /// `POST /admin-api/scim/clients/remove-client`
    RemoveScimClient,
    /// `POST /admin-api/scim/clients/issue-certificate`
    IssueScimClientCertificate,
    /// `POST /admin-api/scim/clients/test-connection`
    TestScimClient,
    /// `POST /admin-api/scim/clients/reconcile`
    ReconcileScimClient,
    /// `POST /admin-api/scim/clients/deliver-now`
    DeliverScimClientNow,
    /// `POST /admin-api/scim/clients/retry-delivery`
    RetryScimDelivery,
    /// `POST /admin-api/scim/clients/retry-dead`
    RetryScimDeadLetters,
    /// `POST /admin-api/scim/clients/purge-dead`
    PurgeScimDeadLetters,
    /// `GET /admin-api/commands`
    GetProviderCommands,
    /// `POST /admin-api/commands/send-account`
    SendAccountCommand,
    /// `POST /admin-api/commands/send-tenant`
    SendTenantCommand,
    /// `POST /admin-api/commands/retry-delivery`
    RetryCommandDelivery,
    /// `GET /admin-api/deliveries`
    GetOutboundDeliveries,
    /// `POST /admin-api/deliveries/retry`
    RetryOutboundDelivery,
    /// `GET /admin-api/ssf/transmitters`
    GetPartnerSignals,
    /// `GET /admin-api/malware-scanning`
    GetMalwareScanning,
    /// `POST /admin-api/malware-scanning/test`
    TestMalwareScanning,
    /// `POST /admin-api/sessions/end-all`
    EndAllSessions,
    /// `GET /admin-api/audit/integrity`
    GetAuditIntegrity,
    /// `GET /admin-api/console/api-explorer`
    GetApiExplorer,
    /// `GET /admin-api/console`
    GetConsoleShell,
    /// `POST /admin-api/console/language`
    SetConsoleLanguage,
    /// `GET /admin-api/console/delegation/map`
    GetDelegationMap,
    /// `GET /admin-api/console/federation/map`
    GetFederationMap,
    /// `GET /admin-api/console/delegation/cluster`
    GetDelegationCluster,
    /// `GET /admin-api/console/delegation/allowed`
    GetDelegationAllowed,
    /// `GET /admin-api/console/delegation-settings`
    GetDelegationSettings,
    /// `GET /admin-api/console/delegation/chain`
    GetDelegationChain,
    /// `GET /admin-api/console/dashboard`
    GetConsoleDashboard,
    /// `GET /admin-api/console/applications/new`
    GetConsoleNewApplicationForm,
    /// `GET /admin-api/console/delegation/user`
    GetConsoleDelegationUser,
    /// `GET /admin-api/console/delegation/application`
    GetConsoleDelegationApplication,
    /// `POST /admin-api/console/pki/apply-profile`
    ApplyPkiProfile,
    /// `POST /admin-api/console/pki/generate-keys`
    GeneratePkiKeyPair,
    /// `POST /admin-api/console/pki/generate-alt-keys`
    GeneratePkiAltKeyPair,
    /// `POST /admin-api/console/pki/use-key`
    UsePkiStoredKey,
    /// `POST /admin-api/console/applications/generate-secret`
    GenerateClientSecret,
    /// `GET /admin-api/console/operations`
    GetConsoleOperations,
    /// `GET /admin-api/console/openapi.json`
    GetConsoleOpenApi,
}

/// The table: one row per operation.
pub const OPERATIONS: &[OperationRow] = &[
    OperationRow { operation: Operation::GetIndex, id: "getIndex", method: "GET", path: "/admin-api", kind: Kind::Management },
    OperationRow { operation: Operation::GetStsMetadata, id: "getStsMetadata", method: "GET", path: "/admin-api/sts-metadata", kind: Kind::Management },
    OperationRow { operation: Operation::GetOpenApi, id: "getOpenApi", method: "GET", path: "/admin-api/openapi.json", kind: Kind::Management },
    OperationRow { operation: Operation::GetCryptoMetadata, id: "getCryptoMetadata", method: "GET", path: "/admin-api/crypto", kind: Kind::Management },
    OperationRow { operation: Operation::GetEncryption, id: "getEncryption", method: "GET", path: "/admin-api/encryption", kind: Kind::Management },
    OperationRow { operation: Operation::RotateDataKeys, id: "rotateDataKeys", method: "POST", path: "/admin-api/encryption/rotate-data-keys", kind: Kind::Management },
    OperationRow { operation: Operation::ReencryptDataKeys, id: "reencryptDataKeys", method: "POST", path: "/admin-api/encryption/reencrypt-data-keys", kind: Kind::Management },
    OperationRow { operation: Operation::CountDataKeys, id: "countDataKeys", method: "POST", path: "/admin-api/encryption/count-data-keys", kind: Kind::Management },
    OperationRow { operation: Operation::RotateKek, id: "rotateKek", method: "POST", path: "/admin-api/encryption/rotate-kek", kind: Kind::Management },
    OperationRow { operation: Operation::GetCells, id: "getCells", method: "GET", path: "/admin-api/cells", kind: Kind::Management },
    OperationRow { operation: Operation::GetCellPeople, id: "getCellPeople", method: "GET", path: "/admin-api/cells/people", kind: Kind::Management },
    OperationRow { operation: Operation::RehomePerson, id: "rehomePerson", method: "POST", path: "/admin-api/cells/rehome", kind: Kind::Management },
    OperationRow { operation: Operation::GetBroadcast, id: "getBroadcast", method: "GET", path: "/admin-api/broadcast", kind: Kind::Management },
    OperationRow { operation: Operation::SendBroadcast, id: "sendBroadcast", method: "POST", path: "/admin-api/broadcast/send", kind: Kind::Management },
    OperationRow { operation: Operation::GetConsoleAnnouncements, id: "getConsoleAnnouncements", method: "GET", path: "/admin-api/announcements", kind: Kind::Management },
    OperationRow { operation: Operation::GetMode, id: "getMode", method: "GET", path: "/admin-api/mode", kind: Kind::Management },
    OperationRow { operation: Operation::GetAccountApi, id: "getAccountApi", method: "GET", path: "/admin-api/account-api", kind: Kind::Management },
    OperationRow { operation: Operation::GetListeners, id: "getListeners", method: "GET", path: "/admin-api/listeners", kind: Kind::Management },
    OperationRow { operation: Operation::SetListeners, id: "setListeners", method: "POST", path: "/admin-api/listeners/set-listeners", kind: Kind::Management },
    OperationRow { operation: Operation::SetListenerApplications, id: "setListenerApplications", method: "POST", path: "/admin-api/listeners/set-applications", kind: Kind::Management },
    OperationRow { operation: Operation::GetCredentialStatus, id: "getCredentialStatus", method: "GET", path: "/admin-api/vc-status", kind: Kind::Management },
    OperationRow { operation: Operation::SuspendCredential, id: "suspendCredential", method: "POST", path: "/admin-api/vc-status/suspend", kind: Kind::Management },
    OperationRow { operation: Operation::ReinstateCredential, id: "reinstateCredential", method: "POST", path: "/admin-api/vc-status/reinstate", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeCredential, id: "revokeCredential", method: "POST", path: "/admin-api/vc-status/revoke", kind: Kind::Management },
    OperationRow { operation: Operation::PublishStatusList, id: "publishStatusList", method: "POST", path: "/admin-api/vc-status/publish", kind: Kind::Management },
    OperationRow { operation: Operation::GetRisk, id: "getRisk", method: "GET", path: "/admin-api/risk", kind: Kind::Management },
    OperationRow { operation: Operation::GetRiskMetrics, id: "getRiskMetrics", method: "GET", path: "/admin-api/risk/metrics", kind: Kind::Management },
    OperationRow { operation: Operation::GetGeolocation, id: "getGeolocation", method: "GET", path: "/admin-api/geolocation", kind: Kind::Management },
    OperationRow { operation: Operation::UploadRiskDataset, id: "uploadRiskDataset", method: "POST", path: "/admin-api/risk/upload", kind: Kind::Management },
    OperationRow { operation: Operation::ImportRiskDataset, id: "importRiskDataset", method: "POST", path: "/admin-api/risk/import", kind: Kind::Management },
    OperationRow { operation: Operation::ActivateRiskDataset, id: "activateRiskDataset", method: "POST", path: "/admin-api/risk/activate", kind: Kind::Management },
    OperationRow { operation: Operation::ReloadRiskDatasetVersion, id: "reloadRiskDatasetVersion", method: "POST", path: "/admin-api/risk/reload", kind: Kind::Management },
    OperationRow { operation: Operation::RollbackRiskDataset, id: "rollbackRiskDataset", method: "POST", path: "/admin-api/risk/rollback", kind: Kind::Management },
    OperationRow { operation: Operation::AcceptRiskProviderTerms, id: "acceptRiskProviderTerms", method: "POST", path: "/admin-api/risk/accept-terms", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteRiskDatasetVersion, id: "deleteRiskDatasetVersion", method: "POST", path: "/admin-api/risk/delete", kind: Kind::Management },
    OperationRow { operation: Operation::GetMail, id: "getMail", method: "GET", path: "/admin-api/mail", kind: Kind::Management },
    OperationRow { operation: Operation::SendMailTestMessage, id: "sendMailTestMessage", method: "POST", path: "/admin-api/mail/test", kind: Kind::Management },
    OperationRow { operation: Operation::SendMailVerificationLink, id: "sendMailVerificationLink", method: "POST", path: "/admin-api/mail/verify", kind: Kind::Management },
    OperationRow { operation: Operation::SaveMailTemplate, id: "saveMailTemplate", method: "POST", path: "/admin-api/mail/save-template", kind: Kind::Management },
    OperationRow { operation: Operation::ResetMailTemplate, id: "resetMailTemplate", method: "POST", path: "/admin-api/mail/reset-template", kind: Kind::Management },
    OperationRow { operation: Operation::GetMailOutbox, id: "getMailOutbox", method: "GET", path: "/admin-api/mail/outbox", kind: Kind::Management },
    OperationRow { operation: Operation::RetryMailDeadLetter, id: "retryMailDeadLetter", method: "POST", path: "/admin-api/mail/outbox/retry", kind: Kind::Management },
    OperationRow { operation: Operation::GetDevices, id: "getDevices", method: "GET", path: "/admin-api/devices", kind: Kind::Management },
    OperationRow { operation: Operation::CreateDevice, id: "createDevice", method: "POST", path: "/admin-api/devices/create", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateDevice, id: "updateDevice", method: "POST", path: "/admin-api/devices/update", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveDevice, id: "removeDevice", method: "POST", path: "/admin-api/devices/remove", kind: Kind::Management },
    OperationRow { operation: Operation::AddDeviceKey, id: "addDeviceKey", method: "POST", path: "/admin-api/devices/add-key", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveDeviceKey, id: "removeDeviceKey", method: "POST", path: "/admin-api/devices/remove-key", kind: Kind::Management },
    OperationRow { operation: Operation::SetDeviceCompliance, id: "setDeviceCompliance", method: "POST", path: "/admin-api/devices/set-compliance", kind: Kind::Management },
    OperationRow { operation: Operation::SetDeviceStatus, id: "setDeviceStatus", method: "POST", path: "/admin-api/devices/set-status", kind: Kind::Management },
    OperationRow { operation: Operation::ReportDeviceCompliance, id: "reportDeviceCompliance", method: "POST", path: "/admin-api/device-compliance", kind: Kind::Management },
    OperationRow { operation: Operation::GetDevicesMonitor, id: "getDevicesMonitor", method: "GET", path: "/admin-api/devices/monitor", kind: Kind::Management },
    OperationRow { operation: Operation::GetServiceAccounts, id: "getServiceAccounts", method: "GET", path: "/admin-api/service-accounts", kind: Kind::Management },
    OperationRow { operation: Operation::GetDeviceRegistration, id: "getDeviceRegistration", method: "GET", path: "/admin-api/device-registration", kind: Kind::Management },
    OperationRow { operation: Operation::GetScheduler, id: "getScheduler", method: "GET", path: "/admin-api/scheduler", kind: Kind::Management },
    OperationRow { operation: Operation::RunSchedulerJob, id: "runSchedulerJob", method: "POST", path: "/admin-api/scheduler/run", kind: Kind::Management },
    OperationRow { operation: Operation::StepDownScheduler, id: "stepDownScheduler", method: "POST", path: "/admin-api/scheduler/step-down", kind: Kind::Management },
    OperationRow { operation: Operation::GetCaches, id: "getCaches", method: "GET", path: "/admin-api/caches", kind: Kind::Management },
    OperationRow { operation: Operation::GetWorkerPools, id: "getWorkerPools", method: "GET", path: "/admin-api/worker-pools", kind: Kind::Management },
    OperationRow { operation: Operation::GetNodeHealth, id: "getNodeHealth", method: "GET", path: "/admin-api/node-health", kind: Kind::Management },
    OperationRow { operation: Operation::CollectGarbage, id: "collectGarbage", method: "POST", path: "/admin-api/node-health/collect-garbage", kind: Kind::Management },
    OperationRow { operation: Operation::GetDatabase, id: "getDatabase", method: "GET", path: "/admin-api/database", kind: Kind::Management },
    OperationRow { operation: Operation::GetSecrets, id: "getSecrets", method: "GET", path: "/admin-api/secrets", kind: Kind::Management },
    OperationRow { operation: Operation::GetDebugger, id: "getDebugger", method: "GET", path: "/admin-api/debugger", kind: Kind::Management },
    OperationRow { operation: Operation::GetKeys, id: "getKeys", method: "GET", path: "/admin-api/keys", kind: Kind::Management },
    OperationRow { operation: Operation::GetKeyHistoryCertificate, id: "getKeyHistoryCertificate", method: "GET", path: "/admin-api/keys/history/certificate", kind: Kind::Management },
    OperationRow { operation: Operation::GetKeyHistory, id: "getKeyHistory", method: "GET", path: "/admin-api/keys/history", kind: Kind::Management },
    OperationRow { operation: Operation::ExportKey, id: "exportKey", method: "POST", path: "/admin-api/keys/export", kind: Kind::Management },
    OperationRow { operation: Operation::RotateSigningKeys, id: "rotateSigningKeys", method: "POST", path: "/admin-api/keys/rotate", kind: Kind::Management },
    OperationRow { operation: Operation::RotateSigningKeysEmergency, id: "rotateSigningKeysEmergency", method: "POST", path: "/admin-api/keys/emergency", kind: Kind::Management },
    OperationRow { operation: Operation::GetStatus, id: "getStatus", method: "GET", path: "/admin-api/status", kind: Kind::Management },
    OperationRow { operation: Operation::GetMe, id: "getMe", method: "GET", path: "/admin-api/me", kind: Kind::Management },
    OperationRow { operation: Operation::GetMetrics, id: "getMetrics", method: "GET", path: "/admin-api/metrics", kind: Kind::Management },
    OperationRow { operation: Operation::GetUsers, id: "getUsers", method: "GET", path: "/admin-api/users", kind: Kind::Management },
    OperationRow { operation: Operation::GetUserAppPasswords, id: "getUserAppPasswords", method: "GET", path: "/admin-api/users/app-passwords", kind: Kind::Management },
    OperationRow { operation: Operation::GetUserCertificates, id: "getUserCertificates", method: "GET", path: "/admin-api/users/certificates", kind: Kind::Management },
    OperationRow { operation: Operation::GetUserDevices, id: "getUserDevices", method: "GET", path: "/admin-api/users/devices", kind: Kind::Management },
    OperationRow { operation: Operation::GetUserSelfIssuedSubjects, id: "getUserSelfIssuedSubjects", method: "GET", path: "/admin-api/users/self-issued-subjects", kind: Kind::Management },
    OperationRow { operation: Operation::GetUserPublishedDids, id: "getUserPublishedDids", method: "GET", path: "/admin-api/users/published-dids", kind: Kind::Management },
    OperationRow { operation: Operation::GetUserVerifications, id: "getUserVerifications", method: "GET", path: "/admin-api/users/verifications", kind: Kind::Management },
    OperationRow { operation: Operation::GetNewUserForm, id: "getNewUserForm", method: "GET", path: "/admin-api/users/new", kind: Kind::Management },
    OperationRow { operation: Operation::IssueActivationLink, id: "issueActivationLink", method: "POST", path: "/admin-api/users/issue-activation", kind: Kind::Management },
    OperationRow { operation: Operation::CreateUser, id: "createUser", method: "POST", path: "/admin-api/users/create", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserPassword, id: "setUserPassword", method: "POST", path: "/admin-api/users/set-password", kind: Kind::Management },
    OperationRow { operation: Operation::ClearUserAuthenticatorApp, id: "clearUserAuthenticatorApp", method: "POST", path: "/admin-api/users/clear-totp", kind: Kind::Management },
    OperationRow { operation: Operation::ClearUserBackupCodes, id: "clearUserBackupCodes", method: "POST", path: "/admin-api/users/clear-backup-codes", kind: Kind::Management },
    OperationRow { operation: Operation::ClearUserEmailFactor, id: "clearUserEmailFactor", method: "POST", path: "/admin-api/users/clear-email-factor", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserAudSub, id: "setUserAudSub", method: "POST", path: "/admin-api/users/set-aud-sub", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserMail, id: "setUserMail", method: "POST", path: "/admin-api/users/set-mail", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserPseudonyms, id: "setUserPseudonyms", method: "POST", path: "/admin-api/users/set-pseudonyms", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserAttribute, id: "setUserAttribute", method: "POST", path: "/admin-api/users/set-attribute", kind: Kind::Management },
    OperationRow { operation: Operation::AddUserAttributeValue, id: "addUserAttributeValue", method: "POST", path: "/admin-api/users/add-attribute", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveUserAttributeValue, id: "removeUserAttributeValue", method: "POST", path: "/admin-api/users/remove-attribute", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateUserFields, id: "updateUserFields", method: "POST", path: "/admin-api/users/update-fields", kind: Kind::Management },
    OperationRow { operation: Operation::ResetUserPassword, id: "resetUserPassword", method: "POST", path: "/admin-api/users/reset-password", kind: Kind::Management },
    OperationRow { operation: Operation::IssuePasswordResetLink, id: "issuePasswordResetLink", method: "POST", path: "/admin-api/users/issue-password-reset", kind: Kind::Management },
    OperationRow { operation: Operation::DisableUserPasskeys, id: "disableUserPasskeys", method: "POST", path: "/admin-api/users/disable-primary-keys", kind: Kind::Management },
    OperationRow { operation: Operation::DisableUserSecondFactors, id: "disableUserSecondFactors", method: "POST", path: "/admin-api/users/disable-mfa", kind: Kind::Management },
    OperationRow { operation: Operation::RequireUserSecondFactor, id: "requireUserSecondFactor", method: "POST", path: "/admin-api/users/require-mfa", kind: Kind::Management },
    OperationRow { operation: Operation::StopRequiringUserSecondFactor, id: "stopRequiringUserSecondFactor", method: "POST", path: "/admin-api/users/stop-requiring-mfa", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserServiceAccount, id: "setUserServiceAccount", method: "POST", path: "/admin-api/users/set-service-account", kind: Kind::Management },
    OperationRow { operation: Operation::AddServiceAccountOwner, id: "addServiceAccountOwner", method: "POST", path: "/admin-api/users/add-service-account-owner", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveServiceAccountOwner, id: "removeServiceAccountOwner", method: "POST", path: "/admin-api/users/remove-service-account-owner", kind: Kind::Management },
    OperationRow { operation: Operation::SetServiceAccountDestination, id: "setServiceAccountDestination", method: "POST", path: "/admin-api/users/set-service-account-destination", kind: Kind::Management },
    OperationRow { operation: Operation::RotateServiceAccountPassword, id: "rotateServiceAccountPassword", method: "POST", path: "/admin-api/users/rotate-password", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserNotDelegated, id: "setUserNotDelegated", method: "POST", path: "/admin-api/users/set-not-delegated", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserMayAct, id: "setUserMayAct", method: "POST", path: "/admin-api/users/set-may-act", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserDelegationSemantics, id: "setUserDelegationSemantics", method: "POST", path: "/admin-api/users/set-delegation-semantics", kind: Kind::Management },
    OperationRow { operation: Operation::AnswerUserCibaRequest, id: "answerUserCibaRequest", method: "POST", path: "/admin-api/users/answer-ciba-request", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveUserDevice, id: "removeUserDevice", method: "POST", path: "/admin-api/users/remove-device", kind: Kind::Management },
    OperationRow { operation: Operation::AddUserCertificate, id: "addUserCertificate", method: "POST", path: "/admin-api/users/add-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveUserCertificate, id: "removeUserCertificate", method: "POST", path: "/admin-api/users/remove-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::ExportUserLdif, id: "exportUserLdif", method: "POST", path: "/admin-api/users/export-ldif", kind: Kind::Management },
    OperationRow { operation: Operation::ImportUserLdif, id: "importUserLdif", method: "POST", path: "/admin-api/users/import-ldif", kind: Kind::Management },
    OperationRow { operation: Operation::IssueUserSigningCertificate, id: "issueUserSigningCertificate", method: "POST", path: "/admin-api/users/issue-signing-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeUserSigningCertificate, id: "revokeUserSigningCertificate", method: "POST", path: "/admin-api/users/revoke-signing-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::EnrolUserSelfIssuedSubject, id: "enrolUserSelfIssuedSubject", method: "POST", path: "/admin-api/users/enrol-self-issued-subject", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveUserSelfIssuedSubject, id: "removeUserSelfIssuedSubject", method: "POST", path: "/admin-api/users/remove-self-issued-subject", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserPreferredSelfIssuedSubject, id: "setUserPreferredSelfIssuedSubject", method: "POST", path: "/admin-api/users/set-preferred-self-issued-subject", kind: Kind::Management },
    OperationRow { operation: Operation::DeactivateUserPublishedDid, id: "deactivateUserPublishedDid", method: "POST", path: "/admin-api/users/deactivate-published-did", kind: Kind::Management },
    OperationRow { operation: Operation::RecordUserVerification, id: "recordUserVerification", method: "POST", path: "/admin-api/users/record-verification", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveUserVerification, id: "removeUserVerification", method: "POST", path: "/admin-api/users/remove-verification", kind: Kind::Management },
    OperationRow { operation: Operation::DisableUserAccount, id: "disableUserAccount", method: "POST", path: "/admin-api/users/disable", kind: Kind::Management },
    OperationRow { operation: Operation::EnableUserAccount, id: "enableUserAccount", method: "POST", path: "/admin-api/users/enable", kind: Kind::Management },
    OperationRow { operation: Operation::LinkUserFederation, id: "linkUserFederation", method: "POST", path: "/admin-api/users/federation-link", kind: Kind::Management },
    OperationRow { operation: Operation::UnlinkUserFederation, id: "unlinkUserFederation", method: "POST", path: "/admin-api/users/federation-unlink", kind: Kind::Management },
    OperationRow { operation: Operation::CreateUserAppPassword, id: "createUserAppPassword", method: "POST", path: "/admin-api/users/create-app-password", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeUserAppPassword, id: "revokeUserAppPassword", method: "POST", path: "/admin-api/users/revoke-app-password", kind: Kind::Management },
    OperationRow { operation: Operation::BeginUserPasskeyUpgrade, id: "beginUserPasskeyUpgrade", method: "POST", path: "/admin-api/users/begin-passkey-upgrade", kind: Kind::Management },
    OperationRow { operation: Operation::ProveUserPasskeyUpgrade, id: "proveUserPasskeyUpgrade", method: "POST", path: "/admin-api/users/prove-passkey-upgrade", kind: Kind::Management },
    OperationRow { operation: Operation::FinishUserPasskeyUpgrade, id: "finishUserPasskeyUpgrade", method: "POST", path: "/admin-api/users/finish-passkey-upgrade", kind: Kind::Management },
    OperationRow { operation: Operation::CancelUserPasskeyUpgrade, id: "cancelUserPasskeyUpgrade", method: "POST", path: "/admin-api/users/cancel-passkey-upgrade", kind: Kind::Management },
    OperationRow { operation: Operation::ClearUserSecurityKey, id: "clearUserSecurityKey", method: "POST", path: "/admin-api/users/clear-key", kind: Kind::Management },
    OperationRow { operation: Operation::RenameUserPasskey, id: "renameUserPasskey", method: "POST", path: "/admin-api/users/rename-key", kind: Kind::Management },
    OperationRow { operation: Operation::BeginUserPasskeyEnrolment, id: "beginUserPasskeyEnrolment", method: "POST", path: "/admin-api/users/begin-passkey-enrolment", kind: Kind::Management },
    OperationRow { operation: Operation::FinishUserPasskeyEnrolment, id: "finishUserPasskeyEnrolment", method: "POST", path: "/admin-api/users/finish-passkey-enrolment", kind: Kind::Management },
    OperationRow { operation: Operation::GetSessions, id: "getSessions", method: "GET", path: "/admin-api/sessions", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeSession, id: "revokeSession", method: "POST", path: "/admin-api/sessions/revoke", kind: Kind::Management },
    OperationRow { operation: Operation::GetLiveSessions, id: "getLiveSessions", method: "GET", path: "/admin-api/logout", kind: Kind::Management },
    OperationRow { operation: Operation::GlobalLogout, id: "globalLogout", method: "POST", path: "/admin-api/logout/global", kind: Kind::Management },
    OperationRow { operation: Operation::EndLiveSessions, id: "endLiveSessions", method: "POST", path: "/admin-api/logout/end", kind: Kind::Management },
    OperationRow { operation: Operation::RetryBackchannelDelivery, id: "retryBackchannelDelivery", method: "POST", path: "/admin-api/logout/retry-backchannel", kind: Kind::Management },
    OperationRow { operation: Operation::RestoreLoggedOutToken, id: "restoreLoggedOutToken", method: "POST", path: "/admin-api/logout/restore-token", kind: Kind::Management },
    OperationRow { operation: Operation::ClearKerberosSignOut, id: "clearKerberosSignOut", method: "POST", path: "/admin-api/logout/restore-kerberos", kind: Kind::Management },
    OperationRow { operation: Operation::GetGroups, id: "getGroups", method: "GET", path: "/admin-api/groups", kind: Kind::Management },
    OperationRow { operation: Operation::CreateGroup, id: "createGroup", method: "POST", path: "/admin-api/groups/create", kind: Kind::Management },
    OperationRow { operation: Operation::AddGroupMember, id: "addGroupMember", method: "POST", path: "/admin-api/groups/add-member", kind: Kind::Management },
    OperationRow { operation: Operation::SetGroupMail, id: "setGroupMail", method: "POST", path: "/admin-api/groups/set-mail", kind: Kind::Management },
    OperationRow { operation: Operation::SetGroupPolicy, id: "setGroupPolicy", method: "POST", path: "/admin-api/groups/set-policy", kind: Kind::Management },
    OperationRow { operation: Operation::AddGroupOwner, id: "addGroupOwner", method: "POST", path: "/admin-api/groups/add-owner", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveGroupOwner, id: "removeGroupOwner", method: "POST", path: "/admin-api/groups/remove-owner", kind: Kind::Management },
    OperationRow { operation: Operation::GetDirectoryEntries, id: "getDirectoryEntries", method: "GET", path: "/admin-api/ldap/directory", kind: Kind::Management },
    OperationRow { operation: Operation::GetDirectoryApplications, id: "getDirectoryApplications", method: "GET", path: "/admin-api/ldap/applications", kind: Kind::Management },
    OperationRow { operation: Operation::GetDirectoryFederations, id: "getDirectoryFederations", method: "GET", path: "/admin-api/ldap/federations", kind: Kind::Management },
    OperationRow { operation: Operation::GetDirectorySpiffe, id: "getDirectorySpiffe", method: "GET", path: "/admin-api/ldap/spiffe", kind: Kind::Management },
    OperationRow { operation: Operation::GetDirectoryRoles, id: "getDirectoryRoles", method: "GET", path: "/admin-api/ldap/roles", kind: Kind::Management },
    OperationRow { operation: Operation::GetDirectoryPolicies, id: "getDirectoryPolicies", method: "GET", path: "/admin-api/ldap/policies", kind: Kind::Management },
    OperationRow { operation: Operation::GetDirectoryPeps, id: "getDirectoryPeps", method: "GET", path: "/admin-api/ldap/peps", kind: Kind::Management },
    OperationRow { operation: Operation::GetDirectoryDevices, id: "getDirectoryDevices", method: "GET", path: "/admin-api/ldap/devices", kind: Kind::Management },
    OperationRow { operation: Operation::GetDirectoryService, id: "getDirectoryService", method: "GET", path: "/admin-api/ldap/service", kind: Kind::Management },
    OperationRow { operation: Operation::GetAdminRoles, id: "getAdminRoles", method: "GET", path: "/admin-api/rbac", kind: Kind::Management },
    OperationRow { operation: Operation::GrantAdminRole, id: "grantAdminRole", method: "POST", path: "/admin-api/rbac/grant", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeAdminRole, id: "revokeAdminRole", method: "POST", path: "/admin-api/rbac/revoke", kind: Kind::Management },
    OperationRow { operation: Operation::GetMultiFactor, id: "getMultiFactor", method: "GET", path: "/admin-api/mfa", kind: Kind::Management },
    OperationRow { operation: Operation::ClearAuthenticatorApp, id: "clearAuthenticatorApp", method: "POST", path: "/admin-api/mfa/clear-totp", kind: Kind::Management },
    OperationRow { operation: Operation::ClearSecurityKey, id: "clearSecurityKey", method: "POST", path: "/admin-api/mfa/clear-key", kind: Kind::Management },
    OperationRow { operation: Operation::ClearEmailFactor, id: "clearEmailFactor", method: "POST", path: "/admin-api/mfa/clear-email-factor", kind: Kind::Management },
    OperationRow { operation: Operation::GetCredentialLineage, id: "getCredentialLineage", method: "GET", path: "/admin-api/tokens/credential", kind: Kind::Management },
    OperationRow { operation: Operation::GetIssued, id: "getIssued", method: "GET", path: "/admin-api/tokens", kind: Kind::Management },
    OperationRow { operation: Operation::GetIssuedSet, id: "getIssuedSet", method: "GET", path: "/admin-api/tokens/set", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeToken, id: "revokeToken", method: "POST", path: "/admin-api/tokens/revoke", kind: Kind::Management },
    OperationRow { operation: Operation::RestoreToken, id: "restoreToken", method: "POST", path: "/admin-api/tokens/restore", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeIssuedArtifact, id: "revokeIssuedArtifact", method: "POST", path: "/admin-api/tokens/revoke-artifact", kind: Kind::Management },
    OperationRow { operation: Operation::RestoreIssuedArtifact, id: "restoreIssuedArtifact", method: "POST", path: "/admin-api/tokens/restore-artifact", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeIssuedSet, id: "revokeIssuedSet", method: "POST", path: "/admin-api/tokens/revoke-set", kind: Kind::Management },
    OperationRow { operation: Operation::RestoreIssuedSet, id: "restoreIssuedSet", method: "POST", path: "/admin-api/tokens/restore-set", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeTokensByKind, id: "revokeTokensByKind", method: "POST", path: "/admin-api/tokens/revoke-kind", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeTokensBySubject, id: "revokeTokensBySubject", method: "POST", path: "/admin-api/tokens/revoke-subject", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeTokensByUser, id: "revokeTokensByUser", method: "POST", path: "/admin-api/tokens/revoke-user", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeAllTokens, id: "revokeAllTokens", method: "POST", path: "/admin-api/tokens/revoke-all", kind: Kind::Management },
    OperationRow { operation: Operation::GetRealms, id: "getRealms", method: "GET", path: "/admin-api/realms", kind: Kind::Management },
    OperationRow { operation: Operation::CreateRealm, id: "createRealm", method: "POST", path: "/admin-api/realms/create", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateRealm, id: "updateRealm", method: "POST", path: "/admin-api/realms/update", kind: Kind::Management },
    OperationRow { operation: Operation::SetRealmSetting, id: "setRealmSetting", method: "POST", path: "/admin-api/realms/set", kind: Kind::Management },
    OperationRow { operation: Operation::UnsetRealmSetting, id: "unsetRealmSetting", method: "POST", path: "/admin-api/realms/unset", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveRealm, id: "removeRealm", method: "POST", path: "/admin-api/realms/remove", kind: Kind::Management },
    OperationRow { operation: Operation::GetConfig, id: "getConfig", method: "GET", path: "/admin-api/config", kind: Kind::Management },
    OperationRow { operation: Operation::GetConfigDump, id: "getConfigDump", method: "GET", path: "/admin-api/config-dump", kind: Kind::Management },
    OperationRow { operation: Operation::SetSetting, id: "setSetting", method: "POST", path: "/admin-api/config/set", kind: Kind::Management },
    OperationRow { operation: Operation::SetSettings, id: "setSettings", method: "POST", path: "/admin-api/config/set-many", kind: Kind::Management },
    OperationRow { operation: Operation::ResetSetting, id: "resetSetting", method: "POST", path: "/admin-api/config/reset", kind: Kind::Management },
    OperationRow { operation: Operation::ResetAllSettings, id: "resetAllSettings", method: "POST", path: "/admin-api/config/reset-all", kind: Kind::Management },
    OperationRow { operation: Operation::GetOauth2Settings, id: "getOauth2Settings", method: "GET", path: "/admin-api/oauth2", kind: Kind::Management },
    OperationRow { operation: Operation::GetOid4vciSettings, id: "getOid4vciSettings", method: "GET", path: "/admin-api/oid4vci-settings", kind: Kind::Management },
    OperationRow { operation: Operation::GetOid4vpSettings, id: "getOid4vpSettings", method: "GET", path: "/admin-api/oid4vp-settings", kind: Kind::Management },
    OperationRow { operation: Operation::GetTotpSettings, id: "getTotpSettings", method: "GET", path: "/admin-api/totp", kind: Kind::Management },
    OperationRow { operation: Operation::GetBackupCodesSettings, id: "getBackupCodesSettings", method: "GET", path: "/admin-api/backup-codes", kind: Kind::Management },
    OperationRow { operation: Operation::GetWebauthnSettings, id: "getWebauthnSettings", method: "GET", path: "/admin-api/webauthn", kind: Kind::Management },
    OperationRow { operation: Operation::GetKerberosSettings, id: "getKerberosSettings", method: "GET", path: "/admin-api/kerberos", kind: Kind::Management },
    OperationRow { operation: Operation::GetLdapSettings, id: "getLdapSettings", method: "GET", path: "/admin-api/ldap", kind: Kind::Management },
    OperationRow { operation: Operation::GetPersistenceSettings, id: "getPersistenceSettings", method: "GET", path: "/admin-api/persistence", kind: Kind::Management },
    OperationRow { operation: Operation::GetClusterSettings, id: "getClusterSettings", method: "GET", path: "/admin-api/cluster", kind: Kind::Management },
    OperationRow { operation: Operation::GetWsTrustSettings, id: "getWsTrustSettings", method: "GET", path: "/admin-api/wstrust", kind: Kind::Management },
    OperationRow { operation: Operation::GetWsFedSettings, id: "getWsFedSettings", method: "GET", path: "/admin-api/wsfed", kind: Kind::Management },
    OperationRow { operation: Operation::GetTlsSettings, id: "getTlsSettings", method: "GET", path: "/admin-api/tls", kind: Kind::Management },
    OperationRow { operation: Operation::GetTokenLifetimes, id: "getTokenLifetimes", method: "GET", path: "/admin-api/token-lifetimes", kind: Kind::Management },
    OperationRow { operation: Operation::SetTokenLifetimes, id: "setTokenLifetimes", method: "POST", path: "/admin-api/token-lifetimes/set", kind: Kind::Management },
    OperationRow { operation: Operation::ResetTokenLifetimes, id: "resetTokenLifetimes", method: "POST", path: "/admin-api/token-lifetimes/defaults", kind: Kind::Management },
    OperationRow { operation: Operation::GetSamlAssertions, id: "getSamlAssertions", method: "GET", path: "/admin-api/saml-assertions", kind: Kind::Management },
    OperationRow { operation: Operation::SetSamlAssertions, id: "setSamlAssertions", method: "POST", path: "/admin-api/saml-assertions/set", kind: Kind::Management },
    OperationRow { operation: Operation::ResetSamlAssertions, id: "resetSamlAssertions", method: "POST", path: "/admin-api/saml-assertions/defaults", kind: Kind::Management },
    OperationRow { operation: Operation::GetClaims, id: "getClaims", method: "GET", path: "/admin-api/claims", kind: Kind::Management },
    OperationRow { operation: Operation::AddClaim, id: "addClaim", method: "POST", path: "/admin-api/claims/add", kind: Kind::Management },
    OperationRow { operation: Operation::AddAttributeClaim, id: "addAttributeClaim", method: "POST", path: "/admin-api/claims/add-attribute-claim", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveClaim, id: "removeClaim", method: "POST", path: "/admin-api/claims/remove", kind: Kind::Management },
    OperationRow { operation: Operation::ClearClaims, id: "clearClaims", method: "POST", path: "/admin-api/claims/clear", kind: Kind::Management },
    OperationRow { operation: Operation::ReplaceClaims, id: "replaceClaims", method: "POST", path: "/admin-api/claims/replace", kind: Kind::Management },
    OperationRow { operation: Operation::SetClaimAttributes, id: "setClaimAttributes", method: "POST", path: "/admin-api/claims/attributes", kind: Kind::Management },
    OperationRow { operation: Operation::SelectAllClaimAttributes, id: "selectAllClaimAttributes", method: "POST", path: "/admin-api/claims/attributes-all", kind: Kind::Management },
    OperationRow { operation: Operation::ClearClaimAttributes, id: "clearClaimAttributes", method: "POST", path: "/admin-api/claims/attributes-clear", kind: Kind::Management },
    OperationRow { operation: Operation::GetUserInfoClaims, id: "getUserInfoClaims", method: "GET", path: "/admin-api/userinfo-claims", kind: Kind::Management },
    OperationRow { operation: Operation::AddUserInfoClaim, id: "addUserInfoClaim", method: "POST", path: "/admin-api/userinfo-claims/add", kind: Kind::Management },
    OperationRow { operation: Operation::AddUserInfoAttributeClaim, id: "addUserInfoAttributeClaim", method: "POST", path: "/admin-api/userinfo-claims/add-attribute-claim", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveUserInfoClaim, id: "removeUserInfoClaim", method: "POST", path: "/admin-api/userinfo-claims/remove", kind: Kind::Management },
    OperationRow { operation: Operation::ClearUserInfoClaims, id: "clearUserInfoClaims", method: "POST", path: "/admin-api/userinfo-claims/clear", kind: Kind::Management },
    OperationRow { operation: Operation::ReplaceUserInfoClaims, id: "replaceUserInfoClaims", method: "POST", path: "/admin-api/userinfo-claims/replace", kind: Kind::Management },
    OperationRow { operation: Operation::SetUserInfoClaimAttributes, id: "setUserInfoClaimAttributes", method: "POST", path: "/admin-api/userinfo-claims/attributes", kind: Kind::Management },
    OperationRow { operation: Operation::SelectAllUserInfoClaimAttributes, id: "selectAllUserInfoClaimAttributes", method: "POST", path: "/admin-api/userinfo-claims/attributes-all", kind: Kind::Management },
    OperationRow { operation: Operation::ClearUserInfoClaimAttributes, id: "clearUserInfoClaimAttributes", method: "POST", path: "/admin-api/userinfo-claims/attributes-clear", kind: Kind::Management },
    OperationRow { operation: Operation::GetSamlAttributes, id: "getSamlAttributes", method: "GET", path: "/admin-api/saml-attributes", kind: Kind::Management },
    OperationRow { operation: Operation::AddSamlAttribute, id: "addSamlAttribute", method: "POST", path: "/admin-api/saml-attributes/add", kind: Kind::Management },
    OperationRow { operation: Operation::AddSamlDirectoryAttributeClaim, id: "addSamlDirectoryAttributeClaim", method: "POST", path: "/admin-api/saml-attributes/add-attribute-claim", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveSamlAttribute, id: "removeSamlAttribute", method: "POST", path: "/admin-api/saml-attributes/remove", kind: Kind::Management },
    OperationRow { operation: Operation::ClearSamlAttributes, id: "clearSamlAttributes", method: "POST", path: "/admin-api/saml-attributes/clear", kind: Kind::Management },
    OperationRow { operation: Operation::ReplaceSamlAttributes, id: "replaceSamlAttributes", method: "POST", path: "/admin-api/saml-attributes/replace", kind: Kind::Management },
    OperationRow { operation: Operation::SetSamlDirectoryAttributes, id: "setSamlDirectoryAttributes", method: "POST", path: "/admin-api/saml-attributes/attributes", kind: Kind::Management },
    OperationRow { operation: Operation::SelectAllSamlDirectoryAttributes, id: "selectAllSamlDirectoryAttributes", method: "POST", path: "/admin-api/saml-attributes/attributes-all", kind: Kind::Management },
    OperationRow { operation: Operation::ClearSamlDirectoryAttributes, id: "clearSamlDirectoryAttributes", method: "POST", path: "/admin-api/saml-attributes/attributes-clear", kind: Kind::Management },
    OperationRow { operation: Operation::GetKerberosPacClaims, id: "getKerberosPacClaims", method: "GET", path: "/admin-api/kerberos/claims", kind: Kind::Management },
    OperationRow { operation: Operation::AddKerberosPacClaim, id: "addKerberosPacClaim", method: "POST", path: "/admin-api/kerberos/claims/add", kind: Kind::Management },
    OperationRow { operation: Operation::AddKerberosPacAttributeClaim, id: "addKerberosPacAttributeClaim", method: "POST", path: "/admin-api/kerberos/claims/add-attribute-claim", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveKerberosPacClaim, id: "removeKerberosPacClaim", method: "POST", path: "/admin-api/kerberos/claims/remove", kind: Kind::Management },
    OperationRow { operation: Operation::ClearKerberosPacClaims, id: "clearKerberosPacClaims", method: "POST", path: "/admin-api/kerberos/claims/clear", kind: Kind::Management },
    OperationRow { operation: Operation::ReplaceKerberosPacClaims, id: "replaceKerberosPacClaims", method: "POST", path: "/admin-api/kerberos/claims/replace", kind: Kind::Management },
    OperationRow { operation: Operation::SetKerberosPacClaimAttributes, id: "setKerberosPacClaimAttributes", method: "POST", path: "/admin-api/kerberos/claims/attributes", kind: Kind::Management },
    OperationRow { operation: Operation::SelectAllKerberosPacClaimAttributes, id: "selectAllKerberosPacClaimAttributes", method: "POST", path: "/admin-api/kerberos/claims/attributes-all", kind: Kind::Management },
    OperationRow { operation: Operation::ClearKerberosPacClaimAttributes, id: "clearKerberosPacClaimAttributes", method: "POST", path: "/admin-api/kerberos/claims/attributes-clear", kind: Kind::Management },
    OperationRow { operation: Operation::GetCredentialClaims, id: "getCredentialClaims", method: "GET", path: "/admin-api/credential-claims", kind: Kind::Management },
    OperationRow { operation: Operation::SelectCredentialClaims, id: "selectCredentialClaims", method: "POST", path: "/admin-api/credential-claims/select", kind: Kind::Management },
    OperationRow { operation: Operation::AddCredentialClaim, id: "addCredentialClaim", method: "POST", path: "/admin-api/credential-claims/add", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveCredentialClaim, id: "removeCredentialClaim", method: "POST", path: "/admin-api/credential-claims/remove", kind: Kind::Management },
    OperationRow { operation: Operation::ResetCredentialClaims, id: "resetCredentialClaims", method: "POST", path: "/admin-api/credential-claims/defaults", kind: Kind::Management },
    OperationRow { operation: Operation::PopulateDirectory, id: "populateDirectory", method: "POST", path: "/admin-api/credential-claims/populate", kind: Kind::Management },
    OperationRow { operation: Operation::GetVerifierRequest, id: "getVerifierRequest", method: "GET", path: "/admin-api/verifier-request", kind: Kind::Management },
    OperationRow { operation: Operation::SelectRequestedClaims, id: "selectRequestedClaims", method: "POST", path: "/admin-api/verifier-request/select", kind: Kind::Management },
    OperationRow { operation: Operation::AddRequestedClaim, id: "addRequestedClaim", method: "POST", path: "/admin-api/verifier-request/add", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveRequestedClaim, id: "removeRequestedClaim", method: "POST", path: "/admin-api/verifier-request/remove", kind: Kind::Management },
    OperationRow { operation: Operation::ResetRequestedClaims, id: "resetRequestedClaims", method: "POST", path: "/admin-api/verifier-request/defaults", kind: Kind::Management },
    OperationRow { operation: Operation::SetRequestFormat, id: "setRequestFormat", method: "POST", path: "/admin-api/verifier-request/format", kind: Kind::Management },
    OperationRow { operation: Operation::StartVerification, id: "startVerification", method: "POST", path: "/admin-api/verifications/start", kind: Kind::Management },
    OperationRow { operation: Operation::GetVerifications, id: "getVerifications", method: "GET", path: "/admin-api/verifications", kind: Kind::Management },
    OperationRow { operation: Operation::GetLastCredentialRequest, id: "getLastCredentialRequest", method: "GET", path: "/admin-api/oid4vci/last-request", kind: Kind::Management },
    OperationRow { operation: Operation::GetCredentialNotification, id: "getCredentialNotification", method: "GET", path: "/admin-api/oid4vci/notifications", kind: Kind::Management },
    OperationRow { operation: Operation::GetFederationRelationships, id: "getFederationRelationships", method: "GET", path: "/admin-api/federation", kind: Kind::Management },
    OperationRow { operation: Operation::CreateFederationRelationship, id: "createFederationRelationship", method: "POST", path: "/admin-api/federation/create", kind: Kind::Management },
    OperationRow { operation: Operation::SetFederationField, id: "setFederationField", method: "POST", path: "/admin-api/federation/set", kind: Kind::Management },
    OperationRow { operation: Operation::AddFederationValue, id: "addFederationValue", method: "POST", path: "/admin-api/federation/add-value", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveFederationValue, id: "removeFederationValue", method: "POST", path: "/admin-api/federation/remove-value", kind: Kind::Management },
    OperationRow { operation: Operation::EnableFederationRelationship, id: "enableFederationRelationship", method: "POST", path: "/admin-api/federation/enable", kind: Kind::Management },
    OperationRow { operation: Operation::DisableFederationRelationship, id: "disableFederationRelationship", method: "POST", path: "/admin-api/federation/disable", kind: Kind::Management },
    OperationRow { operation: Operation::CheckFederationPartner, id: "checkFederationPartner", method: "POST", path: "/admin-api/federation/check-partner", kind: Kind::Management },
    OperationRow { operation: Operation::RegisterAtFederationPartner, id: "registerAtFederationPartner", method: "POST", path: "/admin-api/federation/register-partner", kind: Kind::Management },
    OperationRow { operation: Operation::RotateFederationKey, id: "rotateFederationKey", method: "POST", path: "/admin-api/federation/rotate-key", kind: Kind::Management },
    OperationRow { operation: Operation::DiscoverFederationSignals, id: "discoverFederationSignals", method: "POST", path: "/admin-api/federation/signals-discover", kind: Kind::Management },
    OperationRow { operation: Operation::CreateFederationSignalsStream, id: "createFederationSignalsStream", method: "POST", path: "/admin-api/federation/signals-create-stream", kind: Kind::Management },
    OperationRow { operation: Operation::ReadFederationSignalsStream, id: "readFederationSignalsStream", method: "POST", path: "/admin-api/federation/signals-read-stream", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateFederationSignalsStream, id: "updateFederationSignalsStream", method: "POST", path: "/admin-api/federation/signals-update-stream", kind: Kind::Management },
    OperationRow { operation: Operation::ReplaceFederationSignalsStream, id: "replaceFederationSignalsStream", method: "POST", path: "/admin-api/federation/signals-replace-stream", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteFederationSignalsStream, id: "deleteFederationSignalsStream", method: "POST", path: "/admin-api/federation/signals-delete-stream", kind: Kind::Management },
    OperationRow { operation: Operation::ReadFederationSignalsStatus, id: "readFederationSignalsStatus", method: "POST", path: "/admin-api/federation/signals-read-status", kind: Kind::Management },
    OperationRow { operation: Operation::VerifyFederationSignalsStream, id: "verifyFederationSignalsStream", method: "POST", path: "/admin-api/federation/signals-verify", kind: Kind::Management },
    OperationRow { operation: Operation::PollFederationSignals, id: "pollFederationSignals", method: "POST", path: "/admin-api/federation/signals-poll-now", kind: Kind::Management },
    OperationRow { operation: Operation::SetFederationSignalsStatus, id: "setFederationSignalsStatus", method: "POST", path: "/admin-api/federation/signals-set-status", kind: Kind::Management },
    OperationRow { operation: Operation::AddFederationSignalsSubject, id: "addFederationSignalsSubject", method: "POST", path: "/admin-api/federation/signals-add-subject", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveFederationSignalsSubject, id: "removeFederationSignalsSubject", method: "POST", path: "/admin-api/federation/signals-remove-subject", kind: Kind::Management },
    OperationRow { operation: Operation::UnblockFederationSignals, id: "unblockFederationSignals", method: "POST", path: "/admin-api/federation/signals-unblock", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteFederationRelationship, id: "deleteFederationRelationship", method: "POST", path: "/admin-api/federation/delete", kind: Kind::Management },
    OperationRow { operation: Operation::GetSaml2ServiceProviders, id: "getSaml2ServiceProviders", method: "GET", path: "/admin-api/saml2", kind: Kind::Management },
    OperationRow { operation: Operation::RegisterSaml2ServiceProvider, id: "registerSaml2ServiceProvider", method: "POST", path: "/admin-api/saml2/register", kind: Kind::Management },
    OperationRow { operation: Operation::AddSaml2LogoutService, id: "addSaml2LogoutService", method: "POST", path: "/admin-api/saml2/set-logout-service", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveSaml2LogoutService, id: "removeSaml2LogoutService", method: "POST", path: "/admin-api/saml2/remove-logout-service", kind: Kind::Management },
    OperationRow { operation: Operation::SetSaml2SigningCertificate, id: "setSaml2SigningCertificate", method: "POST", path: "/admin-api/saml2/set-signing-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveSaml2SigningCertificate, id: "removeSaml2SigningCertificate", method: "POST", path: "/admin-api/saml2/remove-signing-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::ConfirmSaml2SigningCertificate, id: "confirmSaml2SigningCertificate", method: "POST", path: "/admin-api/saml2/confirm-signing-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::DiscardSaml2SigningCertificate, id: "discardSaml2SigningCertificate", method: "POST", path: "/admin-api/saml2/discard-signing-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::SetSaml2MetadataSigningCertificate, id: "setSaml2MetadataSigningCertificate", method: "POST", path: "/admin-api/saml2/set-metadata-signing-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::RefreshSaml2Metadata, id: "refreshSaml2Metadata", method: "POST", path: "/admin-api/saml2/refresh-metadata", kind: Kind::Management },
    OperationRow { operation: Operation::ImportSaml2MetadataFromMdq, id: "importSaml2MetadataFromMdq", method: "POST", path: "/admin-api/saml2/mdq-import", kind: Kind::Management },
    OperationRow { operation: Operation::UploadSaml2Metadata, id: "uploadSaml2Metadata", method: "POST", path: "/admin-api/saml2/upload-metadata", kind: Kind::Management },
    OperationRow { operation: Operation::GetSaml11RelyingParties, id: "getSaml11RelyingParties", method: "GET", path: "/admin-api/saml11", kind: Kind::Management },
    OperationRow { operation: Operation::GetSamlIdpInitiatedApplications, id: "getSamlIdpInitiatedApplications", method: "GET", path: "/admin-api/saml-idp-initiated", kind: Kind::Management },
    OperationRow { operation: Operation::RegisterSaml11RelyingParty, id: "registerSaml11RelyingParty", method: "POST", path: "/admin-api/saml11/register", kind: Kind::Management },
    OperationRow { operation: Operation::GetAuthorizationServers, id: "getAuthorizationServers", method: "GET", path: "/admin-api/authorization-servers", kind: Kind::Management },
    OperationRow { operation: Operation::CreateAuthorizationServer, id: "createAuthorizationServer", method: "POST", path: "/admin-api/authorization-servers/create", kind: Kind::Management },
    OperationRow { operation: Operation::SetAuthorizationServerMember, id: "setAuthorizationServerMember", method: "POST", path: "/admin-api/authorization-servers/set", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveAuthorizationServerMember, id: "removeAuthorizationServerMember", method: "POST", path: "/admin-api/authorization-servers/remove", kind: Kind::Management },
    OperationRow { operation: Operation::ResetAuthorizationServerMember, id: "resetAuthorizationServerMember", method: "POST", path: "/admin-api/authorization-servers/reset", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteAuthorizationServer, id: "deleteAuthorizationServer", method: "POST", path: "/admin-api/authorization-servers/delete", kind: Kind::Management },
    OperationRow { operation: Operation::GetApplications, id: "getApplications", method: "GET", path: "/admin-api/applications", kind: Kind::Management },
    OperationRow { operation: Operation::GetNewApplicationForm, id: "getNewApplicationForm", method: "GET", path: "/admin-api/applications/new", kind: Kind::Management },
    OperationRow { operation: Operation::CreateApplication, id: "createApplication", method: "POST", path: "/admin-api/applications/create", kind: Kind::Management },
    OperationRow { operation: Operation::SetApplicationAttribute, id: "setApplicationAttribute", method: "POST", path: "/admin-api/applications/set", kind: Kind::Management },
    OperationRow { operation: Operation::AddApplicationValue, id: "addApplicationValue", method: "POST", path: "/admin-api/applications/add", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveApplicationValue, id: "removeApplicationValue", method: "POST", path: "/admin-api/applications/remove", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateApplicationFields, id: "updateApplicationFields", method: "POST", path: "/admin-api/applications/update-fields", kind: Kind::Management },
    OperationRow { operation: Operation::ConfirmApplicationReturnAddress, id: "confirmApplicationReturnAddress", method: "POST", path: "/admin-api/applications/confirm-address", kind: Kind::Management },
    OperationRow { operation: Operation::DiscardApplicationReturnAddress, id: "discardApplicationReturnAddress", method: "POST", path: "/admin-api/applications/discard-address", kind: Kind::Management },
    OperationRow { operation: Operation::AddApplicationOwner, id: "addApplicationOwner", method: "POST", path: "/admin-api/applications/add-owner", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveApplicationOwner, id: "removeApplicationOwner", method: "POST", path: "/admin-api/applications/remove-owner", kind: Kind::Management },
    OperationRow { operation: Operation::RegenerateApplicationClientSecret, id: "regenerateApplicationClientSecret", method: "POST", path: "/admin-api/applications/regenerate-secret", kind: Kind::Management },
    OperationRow { operation: Operation::RotateApplicationClientSecret, id: "rotateApplicationClientSecret", method: "POST", path: "/admin-api/applications/rotate-secret", kind: Kind::Management },
    OperationRow { operation: Operation::AddApplicationClientSecret, id: "addApplicationClientSecret", method: "POST", path: "/admin-api/applications/add-secret", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveApplicationClientSecret, id: "removeApplicationClientSecret", method: "POST", path: "/admin-api/applications/remove-secret", kind: Kind::Management },
    OperationRow { operation: Operation::RevealApplicationSecret, id: "revealApplicationSecret", method: "POST", path: "/admin-api/applications/reveal-secret", kind: Kind::Management },
    OperationRow { operation: Operation::GenerateApplicationDidKey, id: "generateApplicationDidKey", method: "POST", path: "/admin-api/applications/generate-did-key", kind: Kind::Management },
    OperationRow { operation: Operation::SignApplicationDomainLinkage, id: "signApplicationDomainLinkage", method: "POST", path: "/admin-api/applications/sign-domain-linkage", kind: Kind::Management },
    OperationRow { operation: Operation::SetApplicationCustomClaim, id: "setApplicationCustomClaim", method: "POST", path: "/admin-api/applications/set-custom-claim", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveApplicationCustomClaim, id: "removeApplicationCustomClaim", method: "POST", path: "/admin-api/applications/remove-custom-claim", kind: Kind::Management },
    OperationRow { operation: Operation::SetApplicationClaimAttributes, id: "setApplicationClaimAttributes", method: "POST", path: "/admin-api/applications/set-claim-attributes", kind: Kind::Management },
    OperationRow { operation: Operation::SetApplicationClaimSelections, id: "setApplicationClaimSelections", method: "POST", path: "/admin-api/applications/set-claim-selections", kind: Kind::Management },
    OperationRow { operation: Operation::InheritApplicationClaimAttributes, id: "inheritApplicationClaimAttributes", method: "POST", path: "/admin-api/applications/inherit-claim-attributes", kind: Kind::Management },
    OperationRow { operation: Operation::SetApplicationPermissionClaims, id: "setApplicationPermissionClaims", method: "POST", path: "/admin-api/applications/set-permission-claims", kind: Kind::Management },
    OperationRow { operation: Operation::ClearApplicationPermissionClaims, id: "clearApplicationPermissionClaims", method: "POST", path: "/admin-api/applications/clear-permission-claims", kind: Kind::Management },
    OperationRow { operation: Operation::SetApplicationAccessType, id: "setApplicationAccessType", method: "POST", path: "/admin-api/applications/set-access-type", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveApplicationAccessType, id: "removeApplicationAccessType", method: "POST", path: "/admin-api/applications/remove-access-type", kind: Kind::Management },
    OperationRow { operation: Operation::SetApplicationAccessTypeRow, id: "setApplicationAccessTypeRow", method: "POST", path: "/admin-api/applications/set-access-type-row", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveApplicationAccessTypeRow, id: "removeApplicationAccessTypeRow", method: "POST", path: "/admin-api/applications/remove-access-type-row", kind: Kind::Management },
    OperationRow { operation: Operation::SetApplicationAccessTypeNotForPolicy, id: "setApplicationAccessTypeNotForPolicy", method: "POST", path: "/admin-api/applications/set-not-for-policy", kind: Kind::Management },
    OperationRow { operation: Operation::EnableApplicationFga, id: "enableApplicationFga", method: "POST", path: "/admin-api/applications/fga-enable", kind: Kind::Management },
    OperationRow { operation: Operation::DisableApplicationFga, id: "disableApplicationFga", method: "POST", path: "/admin-api/applications/fga-disable", kind: Kind::Management },
    OperationRow { operation: Operation::CreateApplicationFgaPolicy, id: "createApplicationFgaPolicy", method: "POST", path: "/admin-api/applications/fga-create-policy", kind: Kind::Management },
    OperationRow { operation: Operation::ResetApplicationFgaPolicy, id: "resetApplicationFgaPolicy", method: "POST", path: "/admin-api/applications/fga-reset-policy", kind: Kind::Management },
    OperationRow { operation: Operation::IssueApplicationTlsClientCertificate, id: "issueApplicationTlsClientCertificate", method: "POST", path: "/admin-api/applications/issue-tls-client-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeApplicationTlsClientCertificate, id: "revokeApplicationTlsClientCertificate", method: "POST", path: "/admin-api/applications/revoke-tls-client-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::IssueApplicationSigningCertificate, id: "issueApplicationSigningCertificate", method: "POST", path: "/admin-api/applications/issue-signing-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeApplicationSigningCertificate, id: "revokeApplicationSigningCertificate", method: "POST", path: "/admin-api/applications/revoke-signing-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::AddApplicationCertificate, id: "addApplicationCertificate", method: "POST", path: "/admin-api/applications/add-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveApplicationCertificate, id: "removeApplicationCertificate", method: "POST", path: "/admin-api/applications/remove-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::IssueApplicationSoftwareStatement, id: "issueApplicationSoftwareStatement", method: "POST", path: "/admin-api/applications/issue-software-statement", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeApplicationRegistration, id: "revokeApplicationRegistration", method: "POST", path: "/admin-api/applications/revoke-registration", kind: Kind::Management },
    OperationRow { operation: Operation::RefreshApplicationMetadata, id: "refreshApplicationMetadata", method: "POST", path: "/admin-api/applications/refresh-metadata", kind: Kind::Management },
    OperationRow { operation: Operation::LoadProtectedResourceMetadata, id: "loadProtectedResourceMetadata", method: "POST", path: "/admin-api/applications/load-resource-metadata", kind: Kind::Management },
    OperationRow { operation: Operation::ExportApplicationLdif, id: "exportApplicationLdif", method: "POST", path: "/admin-api/applications/export-ldif", kind: Kind::Management },
    OperationRow { operation: Operation::ImportApplicationLdif, id: "importApplicationLdif", method: "POST", path: "/admin-api/applications/import-ldif", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteApplication, id: "deleteApplication", method: "POST", path: "/admin-api/applications/forget", kind: Kind::Management },
    OperationRow { operation: Operation::GetXacml, id: "getXacml", method: "GET", path: "/admin-api/xacml", kind: Kind::Management },
    OperationRow { operation: Operation::GetXacmlPolicies, id: "getXacmlPolicies", method: "GET", path: "/admin-api/xacml/policies", kind: Kind::Management },
    OperationRow { operation: Operation::GetXacmlEditor, id: "getXacmlEditor", method: "GET", path: "/admin-api/xacml/editor", kind: Kind::Management },
    OperationRow { operation: Operation::GetXacmlDecision, id: "getXacmlDecision", method: "GET", path: "/admin-api/xacml/decide", kind: Kind::Management },
    OperationRow { operation: Operation::GetGnap, id: "getGnap", method: "GET", path: "/admin-api/gnap", kind: Kind::Management },
    OperationRow { operation: Operation::GetGnapMonitor, id: "getGnapMonitor", method: "GET", path: "/admin-api/gnap/monitor", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeGnapGrant, id: "revokeGnapGrant", method: "POST", path: "/admin-api/gnap/revoke-grant", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteGnapResourceSet, id: "deleteGnapResourceSet", method: "POST", path: "/admin-api/gnap/delete-resource-set", kind: Kind::Management },
    OperationRow { operation: Operation::GetXacmlMonitor, id: "getXacmlMonitor", method: "GET", path: "/admin-api/xacml/monitor", kind: Kind::Management },
    OperationRow { operation: Operation::GetXacmlPeps, id: "getXacmlPeps", method: "GET", path: "/admin-api/xacml/peps", kind: Kind::Management },
    OperationRow { operation: Operation::CreateXacmlPolicy, id: "createXacmlPolicy", method: "POST", path: "/admin-api/xacml/create-from-template", kind: Kind::Management },
    OperationRow { operation: Operation::ImportXacmlAlfa, id: "importXacmlAlfa", method: "POST", path: "/admin-api/xacml/import-alfa", kind: Kind::Management },
    OperationRow { operation: Operation::EnableXacmlPolicy, id: "enableXacmlPolicy", method: "POST", path: "/admin-api/xacml/enable", kind: Kind::Management },
    OperationRow { operation: Operation::DisableXacmlPolicy, id: "disableXacmlPolicy", method: "POST", path: "/admin-api/xacml/disable", kind: Kind::Management },
    OperationRow { operation: Operation::SetXacmlRootPolicy, id: "setXacmlRootPolicy", method: "POST", path: "/admin-api/xacml/set-root", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteXacmlPolicy, id: "deleteXacmlPolicy", method: "POST", path: "/admin-api/xacml/delete", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlPolicy, id: "editXacmlPolicy", method: "POST", path: "/admin-api/xacml/edit-policy", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlRule, id: "addXacmlRule", method: "POST", path: "/admin-api/xacml/add-rule", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlMatch, id: "editXacmlMatch", method: "POST", path: "/admin-api/xacml/edit-match", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveXacmlNode, id: "removeXacmlNode", method: "POST", path: "/admin-api/xacml/remove", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlTargetClause, id: "addXacmlTargetClause", method: "POST", path: "/admin-api/xacml/add-target-anyof", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlAlternative, id: "addXacmlAlternative", method: "POST", path: "/admin-api/xacml/add-allof", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlMatch, id: "addXacmlMatch", method: "POST", path: "/admin-api/xacml/add-match", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlRule, id: "editXacmlRule", method: "POST", path: "/admin-api/xacml/edit-rule", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlCondition, id: "addXacmlCondition", method: "POST", path: "/admin-api/xacml/add-condition", kind: Kind::Management },
    OperationRow { operation: Operation::SetXacmlApply, id: "setXacmlApply", method: "POST", path: "/admin-api/xacml/set-expression-apply", kind: Kind::Management },
    OperationRow { operation: Operation::SetXacmlValue, id: "setXacmlValue", method: "POST", path: "/admin-api/xacml/set-expression-value", kind: Kind::Management },
    OperationRow { operation: Operation::SetXacmlDesignator, id: "setXacmlDesignator", method: "POST", path: "/admin-api/xacml/set-expression-designator", kind: Kind::Management },
    OperationRow { operation: Operation::SetXacmlVariable, id: "setXacmlVariable", method: "POST", path: "/admin-api/xacml/set-expression-variable", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlArgument, id: "addXacmlArgument", method: "POST", path: "/admin-api/xacml/add-argument", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlApply, id: "editXacmlApply", method: "POST", path: "/admin-api/xacml/edit-apply", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlValue, id: "editXacmlValue", method: "POST", path: "/admin-api/xacml/edit-value", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlDesignator, id: "editXacmlDesignator", method: "POST", path: "/admin-api/xacml/edit-designator", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlRuleObligation, id: "addXacmlRuleObligation", method: "POST", path: "/admin-api/xacml/add-rule-obligation", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlPolicyObligation, id: "addXacmlPolicyObligation", method: "POST", path: "/admin-api/xacml/add-policy-obligation", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlRuleAdvice, id: "addXacmlRuleAdvice", method: "POST", path: "/admin-api/xacml/add-rule-advice", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlPolicyAdvice, id: "addXacmlPolicyAdvice", method: "POST", path: "/admin-api/xacml/add-policy-advice", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlObligation, id: "editXacmlObligation", method: "POST", path: "/admin-api/xacml/edit-obligation", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlAssignment, id: "addXacmlAssignment", method: "POST", path: "/admin-api/xacml/add-assignment", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlPolicyToSet, id: "addXacmlPolicyToSet", method: "POST", path: "/admin-api/xacml/add-policy", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlPolicySetToSet, id: "addXacmlPolicySetToSet", method: "POST", path: "/admin-api/xacml/add-policyset", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlPolicyReference, id: "addXacmlPolicyReference", method: "POST", path: "/admin-api/xacml/add-policy-reference", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlPolicySetReference, id: "addXacmlPolicySetReference", method: "POST", path: "/admin-api/xacml/add-policyset-reference", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlReference, id: "editXacmlReference", method: "POST", path: "/admin-api/xacml/edit-reference", kind: Kind::Management },
    OperationRow { operation: Operation::AddXacmlVariable, id: "addXacmlVariable", method: "POST", path: "/admin-api/xacml/add-variable", kind: Kind::Management },
    OperationRow { operation: Operation::RenameXacmlVariable, id: "renameXacmlVariable", method: "POST", path: "/admin-api/xacml/edit-variable", kind: Kind::Management },
    OperationRow { operation: Operation::SetXacmlExpressionSelector, id: "setXacmlExpressionSelector", method: "POST", path: "/admin-api/xacml/set-expression-selector", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlSelector, id: "editXacmlSelector", method: "POST", path: "/admin-api/xacml/edit-selector", kind: Kind::Management },
    OperationRow { operation: Operation::SetXacmlExpressionFunction, id: "setXacmlExpressionFunction", method: "POST", path: "/admin-api/xacml/set-expression-function", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlFunctionReference, id: "editXacmlFunctionReference", method: "POST", path: "/admin-api/xacml/edit-function", kind: Kind::Management },
    OperationRow { operation: Operation::EditXacmlAssignment, id: "editXacmlAssignment", method: "POST", path: "/admin-api/xacml/edit-assignment", kind: Kind::Management },
    OperationRow { operation: Operation::DisableXacmlPep, id: "disableXacmlPep", method: "POST", path: "/admin-api/xacml/disable-pep", kind: Kind::Management },
    OperationRow { operation: Operation::EnableXacmlPep, id: "enableXacmlPep", method: "POST", path: "/admin-api/xacml/enable-pep", kind: Kind::Management },
    OperationRow { operation: Operation::ForgetXacmlPep, id: "forgetXacmlPep", method: "POST", path: "/admin-api/xacml/forget-pep", kind: Kind::Management },
    OperationRow { operation: Operation::IssueXacmlPepCertificate, id: "issueXacmlPepCertificate", method: "POST", path: "/admin-api/xacml/issue-pep-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::GetSsf, id: "getSsf", method: "GET", path: "/admin-api/ssf", kind: Kind::Management },
    OperationRow { operation: Operation::GetSsfDeadLetters, id: "getSsfDeadLetters", method: "GET", path: "/admin-api/ssf/dead-letters", kind: Kind::Management },
    OperationRow { operation: Operation::SetSsfStreamStatus, id: "setSsfStreamStatus", method: "POST", path: "/admin-api/ssf/status", kind: Kind::Management },
    OperationRow { operation: Operation::TransmitSsfEvent, id: "transmitSsfEvent", method: "POST", path: "/admin-api/ssf/transmit", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteSsfStream, id: "deleteSsfStream", method: "POST", path: "/admin-api/ssf/delete", kind: Kind::Management },
    OperationRow { operation: Operation::ReviveSsfStream, id: "reviveSsfStream", method: "POST", path: "/admin-api/ssf/revive", kind: Kind::Management },
    OperationRow { operation: Operation::VerifySsfStream, id: "verifySsfStream", method: "POST", path: "/admin-api/ssf/verify", kind: Kind::Management },
    OperationRow { operation: Operation::ClearSsfDeadLetters, id: "clearSsfDeadLetters", method: "POST", path: "/admin-api/ssf/clear-dead-letters", kind: Kind::Management },
    OperationRow { operation: Operation::GetCaep, id: "getCaep", method: "GET", path: "/admin-api/caep", kind: Kind::Management },
    OperationRow { operation: Operation::GetCaepSessions, id: "getCaepSessions", method: "GET", path: "/admin-api/caep/sessions", kind: Kind::Management },
    OperationRow { operation: Operation::EmitCaepEvent, id: "emitCaepEvent", method: "POST", path: "/admin-api/caep/emit", kind: Kind::Management },
    OperationRow { operation: Operation::ResetCaepSession, id: "resetCaepSession", method: "POST", path: "/admin-api/caep/reset-session", kind: Kind::Management },
    OperationRow { operation: Operation::ClearCaepSessions, id: "clearCaepSessions", method: "POST", path: "/admin-api/caep/clear", kind: Kind::Management },
    OperationRow { operation: Operation::GetRisc, id: "getRisc", method: "GET", path: "/admin-api/risc", kind: Kind::Management },
    OperationRow { operation: Operation::GetRiscAccounts, id: "getRiscAccounts", method: "GET", path: "/admin-api/risc/accounts", kind: Kind::Management },
    OperationRow { operation: Operation::EmitRiscEvent, id: "emitRiscEvent", method: "POST", path: "/admin-api/risc/emit", kind: Kind::Management },
    OperationRow { operation: Operation::ResetRiscAccount, id: "resetRiscAccount", method: "POST", path: "/admin-api/risc/reset-account", kind: Kind::Management },
    OperationRow { operation: Operation::ClearRiscAccounts, id: "clearRiscAccounts", method: "POST", path: "/admin-api/risc/clear", kind: Kind::Management },
    OperationRow { operation: Operation::GetScim, id: "getScim", method: "GET", path: "/admin-api/scim", kind: Kind::Management },
    OperationRow { operation: Operation::GetPki, id: "getPki", method: "GET", path: "/admin-api/pki", kind: Kind::Management },
    OperationRow { operation: Operation::GetCertificates, id: "getCertificates", method: "GET", path: "/admin-api/certificates", kind: Kind::Management },
    OperationRow { operation: Operation::GetPkiTrust, id: "getPkiTrust", method: "GET", path: "/admin-api/pki/trust", kind: Kind::Management },
    OperationRow { operation: Operation::AddSignerTrustAnchors, id: "addSignerTrustAnchors", method: "POST", path: "/admin-api/pki/trust/add", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveSignerTrustAnchor, id: "removeSignerTrustAnchor", method: "POST", path: "/admin-api/pki/trust/remove", kind: Kind::Management },
    OperationRow { operation: Operation::RecheckPinnedCertificates, id: "recheckPinnedCertificates", method: "POST", path: "/admin-api/pki/trust/recheck", kind: Kind::Management },
    OperationRow { operation: Operation::SetParanoidPkiRow, id: "setParanoidPkiRow", method: "POST", path: "/admin-api/pki/trust/set-row", kind: Kind::Management },
    OperationRow { operation: Operation::BuildPkiChain, id: "buildPkiChain", method: "POST", path: "/admin-api/pki/build", kind: Kind::Management },
    OperationRow { operation: Operation::IssuePkiKeyPair, id: "issuePkiKeyPair", method: "POST", path: "/admin-api/pki/issue", kind: Kind::Management },
    OperationRow { operation: Operation::RevokePkiKeyPair, id: "revokePkiKeyPair", method: "POST", path: "/admin-api/pki/revoke", kind: Kind::Management },
    OperationRow { operation: Operation::UploadPkiCertificate, id: "uploadPkiCertificate", method: "POST", path: "/admin-api/pki/upload-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::ClearPkiChain, id: "clearPkiChain", method: "POST", path: "/admin-api/pki/clear", kind: Kind::Management },
    OperationRow { operation: Operation::IssuePkiCertificate, id: "issuePkiCertificate", method: "POST", path: "/admin-api/pki/issue-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::RemovePkiObject, id: "removePkiObject", method: "POST", path: "/admin-api/pki/remove-object", kind: Kind::Management },
    OperationRow { operation: Operation::ClearPkiObjects, id: "clearPkiObjects", method: "POST", path: "/admin-api/pki/clear-store", kind: Kind::Management },
    OperationRow { operation: Operation::ExportPkiKeyPair, id: "exportPkiKeyPair", method: "POST", path: "/admin-api/pki/export", kind: Kind::Management },
    OperationRow { operation: Operation::BuildPkiRoot, id: "buildPkiRoot", method: "POST", path: "/admin-api/pki/build-root", kind: Kind::Management },
    OperationRow { operation: Operation::BuildPkiScope, id: "buildPkiScope", method: "POST", path: "/admin-api/pki/build-scope", kind: Kind::Management },
    OperationRow { operation: Operation::ReissuePkiUseCase, id: "reissuePkiUseCase", method: "POST", path: "/admin-api/pki/reissue-use-case", kind: Kind::Management },
    OperationRow { operation: Operation::RecertifyPkiUseCase, id: "recertifyPkiUseCase", method: "POST", path: "/admin-api/pki/recertify", kind: Kind::Management },
    OperationRow { operation: Operation::ImportPkiCa, id: "importPkiCa", method: "POST", path: "/admin-api/pki/import-ca", kind: Kind::Management },
    OperationRow { operation: Operation::PinPkiKeyPair, id: "pinPkiKeyPair", method: "POST", path: "/admin-api/pki/pin-key", kind: Kind::Management },
    OperationRow { operation: Operation::UnpinPkiKeyPair, id: "unpinPkiKeyPair", method: "POST", path: "/admin-api/pki/unpin-key", kind: Kind::Management },
    OperationRow { operation: Operation::RevokePkiCertificate, id: "revokePkiCertificate", method: "POST", path: "/admin-api/pki/revoke-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::ReleasePkiCertificateHold, id: "releasePkiCertificateHold", method: "POST", path: "/admin-api/pki/release-hold", kind: Kind::Management },
    OperationRow { operation: Operation::GetScimMonitor, id: "getScimMonitor", method: "GET", path: "/admin-api/scim/monitor", kind: Kind::Management },
    OperationRow { operation: Operation::GetSignals, id: "getSignals", method: "GET", path: "/admin-api/signals", kind: Kind::Management },
    OperationRow { operation: Operation::ClearSignalsInbox, id: "clearSignalsInbox", method: "POST", path: "/admin-api/signals/clear", kind: Kind::Management },
    OperationRow { operation: Operation::GetTruststore, id: "getTruststore", method: "GET", path: "/admin-api/tls/trust", kind: Kind::Management },
    OperationRow { operation: Operation::AddTrustAnchors, id: "addTrustAnchors", method: "POST", path: "/admin-api/tls/trust/add", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveTrustAnchor, id: "removeTrustAnchor", method: "POST", path: "/admin-api/tls/trust/remove", kind: Kind::Management },
    OperationRow { operation: Operation::GetTlsConnection, id: "getTlsConnection", method: "GET", path: "/admin-api/tls-connection", kind: Kind::Management },
    OperationRow { operation: Operation::GetKerberosPrincipals, id: "getKerberosPrincipals", method: "GET", path: "/admin-api/kerberos/principals", kind: Kind::Management },
    OperationRow { operation: Operation::CreateKerberosServicePrincipal, id: "createKerberosServicePrincipal", method: "POST", path: "/admin-api/kerberos/principals/create-service", kind: Kind::Management },
    OperationRow { operation: Operation::RotateKerberosServicePrincipal, id: "rotateKerberosServicePrincipal", method: "POST", path: "/admin-api/kerberos/principals/rotate-service", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteKerberosServicePrincipal, id: "deleteKerberosServicePrincipal", method: "POST", path: "/admin-api/kerberos/principals/delete-service", kind: Kind::Management },
    OperationRow { operation: Operation::ClearKerberosPersonKeys, id: "clearKerberosPersonKeys", method: "POST", path: "/admin-api/kerberos/principals/clear-person-keys", kind: Kind::Management },
    OperationRow { operation: Operation::DropKerberosServicePreviousKeys, id: "dropKerberosServicePreviousKeys", method: "POST", path: "/admin-api/kerberos/principals/drop-previous-service-keys", kind: Kind::Management },
    OperationRow { operation: Operation::DropKerberosPersonPreviousKeys, id: "dropKerberosPersonPreviousKeys", method: "POST", path: "/admin-api/kerberos/principals/drop-previous-person-keys", kind: Kind::Management },
    OperationRow { operation: Operation::ResetKerberosPersonKeytab, id: "resetKerberosPersonKeytab", method: "POST", path: "/admin-api/kerberos/principals/reset-person-keytab", kind: Kind::Management },
    OperationRow { operation: Operation::RotateKerberosKrbtgt, id: "rotateKerberosKrbtgt", method: "POST", path: "/admin-api/kerberos/principals/rotate-krbtgt", kind: Kind::Management },
    OperationRow { operation: Operation::RotateKerberosKrbtgtInvalidate, id: "rotateKerberosKrbtgtInvalidate", method: "POST", path: "/admin-api/kerberos/principals/rotate-krbtgt-invalidate", kind: Kind::Management },
    OperationRow { operation: Operation::GetKerberosTrusts, id: "getKerberosTrusts", method: "GET", path: "/admin-api/kerberos/trusts", kind: Kind::Management },
    OperationRow { operation: Operation::AddKerberosTrust, id: "addKerberosTrust", method: "POST", path: "/admin-api/kerberos/trusts/add", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateKerberosTrust, id: "updateKerberosTrust", method: "POST", path: "/admin-api/kerberos/trusts/update", kind: Kind::Management },
    OperationRow { operation: Operation::EnableKerberosTrust, id: "enableKerberosTrust", method: "POST", path: "/admin-api/kerberos/trusts/enable", kind: Kind::Management },
    OperationRow { operation: Operation::DisableKerberosTrust, id: "disableKerberosTrust", method: "POST", path: "/admin-api/kerberos/trusts/disable", kind: Kind::Management },
    OperationRow { operation: Operation::RotateKerberosTrustKey, id: "rotateKerberosTrustKey", method: "POST", path: "/admin-api/kerberos/trusts/rotate-key", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveKerberosTrust, id: "removeKerberosTrust", method: "POST", path: "/admin-api/kerberos/trusts/remove", kind: Kind::Management },
    OperationRow { operation: Operation::PairKerberosTrust, id: "pairKerberosTrust", method: "POST", path: "/admin-api/kerberos/trusts/pair", kind: Kind::Management },
    OperationRow { operation: Operation::GetAudit, id: "getAudit", method: "GET", path: "/admin-api/audit", kind: Kind::Management },
    OperationRow { operation: Operation::GetErrorCodes, id: "getErrorCodes", method: "GET", path: "/admin-api/error-codes", kind: Kind::Management },
    OperationRow { operation: Operation::GetUsedAssertions, id: "getUsedAssertions", method: "GET", path: "/admin-api/used-assertions", kind: Kind::Management },
    OperationRow { operation: Operation::GetDelegation, id: "getDelegation", method: "GET", path: "/admin-api/delegation", kind: Kind::Management },
    OperationRow { operation: Operation::GetDelegationUser, id: "getDelegationUser", method: "GET", path: "/admin-api/delegation/user", kind: Kind::Management },
    OperationRow { operation: Operation::GetDelegationApplication, id: "getDelegationApplication", method: "GET", path: "/admin-api/delegation/application", kind: Kind::Management },
    OperationRow { operation: Operation::GetDelegationPolicy, id: "getDelegationPolicy", method: "GET", path: "/admin-api/delegation/policy", kind: Kind::Management },
    OperationRow { operation: Operation::GetPermissions, id: "getPermissions", method: "GET", path: "/admin-api/permissions", kind: Kind::Management },
    OperationRow { operation: Operation::GetPermissionGroups, id: "getPermissionGroups", method: "GET", path: "/admin-api/permissions/groups", kind: Kind::Management },
    OperationRow { operation: Operation::SetPermissionBase, id: "setPermissionBase", method: "POST", path: "/admin-api/permissions/set-permission-base", kind: Kind::Management },
    OperationRow { operation: Operation::DefinePermission, id: "definePermission", method: "POST", path: "/admin-api/permissions/define-permission", kind: Kind::Management },
    OperationRow { operation: Operation::RemovePermission, id: "removePermission", method: "POST", path: "/admin-api/permissions/remove-permission", kind: Kind::Management },
    OperationRow { operation: Operation::GrantPermission, id: "grantPermission", method: "POST", path: "/admin-api/permissions/grant-permission", kind: Kind::Management },
    OperationRow { operation: Operation::RevokePermission, id: "revokePermission", method: "POST", path: "/admin-api/permissions/revoke-permission", kind: Kind::Management },
    OperationRow { operation: Operation::GetRoles, id: "getRoles", method: "GET", path: "/admin-api/roles", kind: Kind::Management },
    OperationRow { operation: Operation::PreviewRoleIssuance, id: "previewRoleIssuance", method: "GET", path: "/admin-api/roles/preview", kind: Kind::Management },
    OperationRow { operation: Operation::CreateRole, id: "createRole", method: "POST", path: "/admin-api/roles/create-role", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteRole, id: "deleteRole", method: "POST", path: "/admin-api/roles/delete-role", kind: Kind::Management },
    OperationRow { operation: Operation::DescribeRole, id: "describeRole", method: "POST", path: "/admin-api/roles/describe-role", kind: Kind::Management },
    OperationRow { operation: Operation::AddRoleMember, id: "addRoleMember", method: "POST", path: "/admin-api/roles/add-member", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveRoleMember, id: "removeRoleMember", method: "POST", path: "/admin-api/roles/remove-member", kind: Kind::Management },
    OperationRow { operation: Operation::AddRolePermission, id: "addRolePermission", method: "POST", path: "/admin-api/roles/add-permission", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveRolePermission, id: "removeRolePermission", method: "POST", path: "/admin-api/roles/remove-permission", kind: Kind::Management },
    OperationRow { operation: Operation::AddRoleConferringClient, id: "addRoleConferringClient", method: "POST", path: "/admin-api/roles/add-conferring-client", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveRoleConferringClient, id: "removeRoleConferringClient", method: "POST", path: "/admin-api/roles/remove-conferring-client", kind: Kind::Management },
    OperationRow { operation: Operation::AddRoleOwner, id: "addRoleOwner", method: "POST", path: "/admin-api/roles/add-owner", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveRoleOwner, id: "removeRoleOwner", method: "POST", path: "/admin-api/roles/remove-owner", kind: Kind::Management },
    OperationRow { operation: Operation::GetOwnership, id: "getOwnership", method: "GET", path: "/admin-api/ownership", kind: Kind::Management },
    OperationRow { operation: Operation::SetOwnerProtected, id: "setOwnerProtected", method: "POST", path: "/admin-api/ownership/set-protected", kind: Kind::Management },
    OperationRow { operation: Operation::GetPolicies, id: "getPolicies", method: "GET", path: "/admin-api/policies", kind: Kind::Management },
    OperationRow { operation: Operation::SavePasswordPolicy, id: "savePasswordPolicy", method: "POST", path: "/admin-api/policies/save-password-policy", kind: Kind::Management },
    OperationRow { operation: Operation::ResetPasswordPolicy, id: "resetPasswordPolicy", method: "POST", path: "/admin-api/policies/reset-password-policy", kind: Kind::Management },
    OperationRow { operation: Operation::SaveAuthnPolicy, id: "saveAuthnPolicy", method: "POST", path: "/admin-api/policies/save-authn-policy", kind: Kind::Management },
    OperationRow { operation: Operation::ResetAuthnPolicy, id: "resetAuthnPolicy", method: "POST", path: "/admin-api/policies/reset-authn-policy", kind: Kind::Management },
    OperationRow { operation: Operation::SaveNamedAuthnPolicy, id: "saveNamedAuthnPolicy", method: "POST", path: "/admin-api/policies/save-named-authn-policy", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteNamedAuthnPolicy, id: "deleteNamedAuthnPolicy", method: "POST", path: "/admin-api/policies/delete-named-authn-policy", kind: Kind::Management },
    OperationRow { operation: Operation::GetPolicyTransfer, id: "getPolicyTransfer", method: "GET", path: "/admin-api/policies/transfer", kind: Kind::Management },
    OperationRow { operation: Operation::ExportPolicies, id: "exportPolicies", method: "POST", path: "/admin-api/policies/transfer/export", kind: Kind::Management },
    OperationRow { operation: Operation::InspectPolicyExport, id: "inspectPolicyExport", method: "POST", path: "/admin-api/policies/transfer/inspect", kind: Kind::Management },
    OperationRow { operation: Operation::ImportPolicies, id: "importPolicies", method: "POST", path: "/admin-api/policies/transfer/import", kind: Kind::Management },
    OperationRow { operation: Operation::SaveServiceAccountPolicy, id: "saveServiceAccountPolicy", method: "POST", path: "/admin-api/policies/save-serviceAccount-policy", kind: Kind::Management },
    OperationRow { operation: Operation::ResetServiceAccountPolicy, id: "resetServiceAccountPolicy", method: "POST", path: "/admin-api/policies/reset-serviceAccount-policy", kind: Kind::Management },
    OperationRow { operation: Operation::SavePasskeyPolicy, id: "savePasskeyPolicy", method: "POST", path: "/admin-api/policies/save-passkey-policy", kind: Kind::Management },
    OperationRow { operation: Operation::ResetPasskeyPolicy, id: "resetPasskeyPolicy", method: "POST", path: "/admin-api/policies/reset-passkey-policy", kind: Kind::Management },
    OperationRow { operation: Operation::ClearPasskeyClient, id: "clearPasskeyClient", method: "POST", path: "/admin-api/policies/clear-passkey-client", kind: Kind::Management },
    OperationRow { operation: Operation::ClearPasskeyClients, id: "clearPasskeyClients", method: "POST", path: "/admin-api/policies/clear-passkey-clients", kind: Kind::Management },
    OperationRow { operation: Operation::SaveLocalePolicy, id: "saveLocalePolicy", method: "POST", path: "/admin-api/policies/save-locale-policy", kind: Kind::Management },
    OperationRow { operation: Operation::ResetLocalePolicy, id: "resetLocalePolicy", method: "POST", path: "/admin-api/policies/reset-locale-policy", kind: Kind::Management },
    OperationRow { operation: Operation::SaveAttributesPolicy, id: "saveAttributesPolicy", method: "POST", path: "/admin-api/policies/save-attributes-policy", kind: Kind::Management },
    OperationRow { operation: Operation::ResetAttributesPolicy, id: "resetAttributesPolicy", method: "POST", path: "/admin-api/policies/reset-attributes-policy", kind: Kind::Management },
    OperationRow { operation: Operation::DefinePersonAttribute, id: "definePersonAttribute", method: "POST", path: "/admin-api/policies/define-person-attribute", kind: Kind::Management },
    OperationRow { operation: Operation::UpdatePersonAttribute, id: "updatePersonAttribute", method: "POST", path: "/admin-api/policies/update-person-attribute", kind: Kind::Management },
    OperationRow { operation: Operation::RemovePersonAttribute, id: "removePersonAttribute", method: "POST", path: "/admin-api/policies/remove-person-attribute", kind: Kind::Management },
    OperationRow { operation: Operation::SavePostLoginPolicy, id: "savePostLoginPolicy", method: "POST", path: "/admin-api/policies/save-postLogin-policy", kind: Kind::Management },
    OperationRow { operation: Operation::ResetPostLoginPolicy, id: "resetPostLoginPolicy", method: "POST", path: "/admin-api/policies/reset-postLogin-policy", kind: Kind::Management },
    OperationRow { operation: Operation::GetConsent, id: "getConsent", method: "GET", path: "/admin-api/consent", kind: Kind::Management },
    OperationRow { operation: Operation::GrantGlobalConsent, id: "grantGlobalConsent", method: "POST", path: "/admin-api/consent/grant-global-consent", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeGlobalConsent, id: "revokeGlobalConsent", method: "POST", path: "/admin-api/consent/revoke-global-consent", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeConsent, id: "revokeConsent", method: "POST", path: "/admin-api/consent/revoke-consent", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeApplicationConsent, id: "revokeApplicationConsent", method: "POST", path: "/admin-api/consent/revoke-application-consent", kind: Kind::Management },
    OperationRow { operation: Operation::ForgetUserConsent, id: "forgetUserConsent", method: "POST", path: "/admin-api/consent/forget-user-consent", kind: Kind::Management },
    OperationRow { operation: Operation::GetSpiffe, id: "getSpiffe", method: "GET", path: "/admin-api/spiffe", kind: Kind::Management },
    OperationRow { operation: Operation::RotateSpiffeAuthority, id: "rotateSpiffeAuthority", method: "POST", path: "/admin-api/spiffe/rotate", kind: Kind::Management },
    OperationRow { operation: Operation::SetSpiffeFederatedBundle, id: "setSpiffeFederatedBundle", method: "POST", path: "/admin-api/spiffe/federation-set", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveSpiffeFederatedBundle, id: "removeSpiffeFederatedBundle", method: "POST", path: "/admin-api/spiffe/federation-remove", kind: Kind::Management },
    OperationRow { operation: Operation::GetSpiffeEntries, id: "getSpiffeEntries", method: "GET", path: "/admin-api/spiffe/entries", kind: Kind::Management },
    OperationRow { operation: Operation::CreateSpiffeEntry, id: "createSpiffeEntry", method: "POST", path: "/admin-api/spiffe/entries/create", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateSpiffeEntry, id: "updateSpiffeEntry", method: "POST", path: "/admin-api/spiffe/entries/update", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteSpiffeEntry, id: "deleteSpiffeEntry", method: "POST", path: "/admin-api/spiffe/entries/delete", kind: Kind::Management },
    OperationRow { operation: Operation::GetSpiffeBrokers, id: "getSpiffeBrokers", method: "GET", path: "/admin-api/spiffe/brokers", kind: Kind::Management },
    OperationRow { operation: Operation::SetSpiffeBroker, id: "setSpiffeBroker", method: "POST", path: "/admin-api/spiffe/brokers/set", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveSpiffeBroker, id: "removeSpiffeBroker", method: "POST", path: "/admin-api/spiffe/brokers/remove", kind: Kind::Management },
    OperationRow { operation: Operation::GetSpiffeAgents, id: "getSpiffeAgents", method: "GET", path: "/admin-api/spiffe/agents", kind: Kind::Management },
    OperationRow { operation: Operation::BanSpiffeAgent, id: "banSpiffeAgent", method: "POST", path: "/admin-api/spiffe/agents/ban", kind: Kind::Management },
    OperationRow { operation: Operation::UnbanSpiffeAgent, id: "unbanSpiffeAgent", method: "POST", path: "/admin-api/spiffe/agents/unban", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteSpiffeAgent, id: "deleteSpiffeAgent", method: "POST", path: "/admin-api/spiffe/agents/delete", kind: Kind::Management },
    OperationRow { operation: Operation::CreateSpiffeJoinToken, id: "createSpiffeJoinToken", method: "POST", path: "/admin-api/spiffe/agents/join-token", kind: Kind::Management },
    OperationRow { operation: Operation::GetAcme, id: "getAcme", method: "GET", path: "/admin-api/acme", kind: Kind::Management },
    OperationRow { operation: Operation::GetAcmeMonitor, id: "getAcmeMonitor", method: "GET", path: "/admin-api/acme/monitor", kind: Kind::Management },
    OperationRow { operation: Operation::CreateAcmeEab, id: "createAcmeEab", method: "POST", path: "/admin-api/acme/create-eab", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteAcmeEab, id: "deleteAcmeEab", method: "POST", path: "/admin-api/acme/delete-eab", kind: Kind::Management },
    OperationRow { operation: Operation::DeactivateAcmeAccount, id: "deactivateAcmeAccount", method: "POST", path: "/admin-api/acme/deactivate-account", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeAcmeCertificate, id: "revokeAcmeCertificate", method: "POST", path: "/admin-api/acme/revoke-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::AddAcmeHostName, id: "addAcmeHostName", method: "POST", path: "/admin-api/acme/add-host-name", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveAcmeHostName, id: "removeAcmeHostName", method: "POST", path: "/admin-api/acme/remove-host-name", kind: Kind::Management },
    OperationRow { operation: Operation::GetEst, id: "getEst", method: "GET", path: "/admin-api/est", kind: Kind::Management },
    OperationRow { operation: Operation::GetEstMonitor, id: "getEstMonitor", method: "GET", path: "/admin-api/est/monitor", kind: Kind::Management },
    OperationRow { operation: Operation::IssueEstServerKey, id: "issueEstServerKey", method: "POST", path: "/admin-api/est/issue-server-key", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeEstCertificate, id: "revokeEstCertificate", method: "POST", path: "/admin-api/est/revoke-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::AddEstHostName, id: "addEstHostName", method: "POST", path: "/admin-api/est/add-host-name", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveEstHostName, id: "removeEstHostName", method: "POST", path: "/admin-api/est/remove-host-name", kind: Kind::Management },
    OperationRow { operation: Operation::GetScep, id: "getScep", method: "GET", path: "/admin-api/scep", kind: Kind::Management },
    OperationRow { operation: Operation::GetScepMonitor, id: "getScepMonitor", method: "GET", path: "/admin-api/scep/monitor", kind: Kind::Management },
    OperationRow { operation: Operation::CreateScepChallenge, id: "createScepChallenge", method: "POST", path: "/admin-api/scep/create-challenge", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteScepChallenge, id: "deleteScepChallenge", method: "POST", path: "/admin-api/scep/delete-challenge", kind: Kind::Management },
    OperationRow { operation: Operation::ReissueScepRa, id: "reissueScepRa", method: "POST", path: "/admin-api/scep/reissue-ra", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeScepCertificate, id: "revokeScepCertificate", method: "POST", path: "/admin-api/scep/revoke-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::AddScepHostName, id: "addScepHostName", method: "POST", path: "/admin-api/scep/add-host-name", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveScepHostName, id: "removeScepHostName", method: "POST", path: "/admin-api/scep/remove-host-name", kind: Kind::Management },
    OperationRow { operation: Operation::GetOidfed, id: "getOidfed", method: "GET", path: "/admin-api/oidfed", kind: Kind::Management },
    OperationRow { operation: Operation::AddOidfedSubordinate, id: "addOidfedSubordinate", method: "POST", path: "/admin-api/oidfed/add-subordinate", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveOidfedSubordinate, id: "removeOidfedSubordinate", method: "POST", path: "/admin-api/oidfed/remove-subordinate", kind: Kind::Management },
    OperationRow { operation: Operation::SuspendOidfedSubordinate, id: "suspendOidfedSubordinate", method: "POST", path: "/admin-api/oidfed/suspend-subordinate", kind: Kind::Management },
    OperationRow { operation: Operation::ReinstateOidfedSubordinate, id: "reinstateOidfedSubordinate", method: "POST", path: "/admin-api/oidfed/reinstate-subordinate", kind: Kind::Management },
    OperationRow { operation: Operation::CrawlOidfedCollection, id: "crawlOidfedCollection", method: "POST", path: "/admin-api/oidfed/crawl-collection", kind: Kind::Management },
    OperationRow { operation: Operation::AddOidfedTrustAnchor, id: "addOidfedTrustAnchor", method: "POST", path: "/admin-api/oidfed/add-trust-anchor", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveOidfedTrustAnchor, id: "removeOidfedTrustAnchor", method: "POST", path: "/admin-api/oidfed/remove-trust-anchor", kind: Kind::Management },
    OperationRow { operation: Operation::AddOidfedMarkType, id: "addOidfedMarkType", method: "POST", path: "/admin-api/oidfed/add-mark-type", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveOidfedMarkType, id: "removeOidfedMarkType", method: "POST", path: "/admin-api/oidfed/remove-mark-type", kind: Kind::Management },
    OperationRow { operation: Operation::SetOidfedMarkPolicy, id: "setOidfedMarkPolicy", method: "POST", path: "/admin-api/oidfed/set-mark-policy", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveOidfedMarkPolicy, id: "removeOidfedMarkPolicy", method: "POST", path: "/admin-api/oidfed/remove-mark-policy", kind: Kind::Management },
    OperationRow { operation: Operation::IssueOidfedTrustMark, id: "issueOidfedTrustMark", method: "POST", path: "/admin-api/oidfed/issue-trust-mark", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeOidfedTrustMark, id: "revokeOidfedTrustMark", method: "POST", path: "/admin-api/oidfed/revoke-trust-mark", kind: Kind::Management },
    OperationRow { operation: Operation::AddOidfedHeldMark, id: "addOidfedHeldMark", method: "POST", path: "/admin-api/oidfed/add-held-mark", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveOidfedHeldMark, id: "removeOidfedHeldMark", method: "POST", path: "/admin-api/oidfed/remove-held-mark", kind: Kind::Management },
    OperationRow { operation: Operation::ResolveOidfedEntity, id: "resolveOidfedEntity", method: "POST", path: "/admin-api/oidfed/resolve", kind: Kind::Management },
    OperationRow { operation: Operation::RotateOidfedKey, id: "rotateOidfedKey", method: "POST", path: "/admin-api/oidfed/rotate-key", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeOidfedKey, id: "revokeOidfedKey", method: "POST", path: "/admin-api/oidfed/revoke-key", kind: Kind::Management },
    OperationRow { operation: Operation::GetOauth2Monitor, id: "getOauth2Monitor", method: "GET", path: "/admin-api/oauth2/monitor", kind: Kind::Management },
    OperationRow { operation: Operation::DeletePushedRequest, id: "deletePushedRequest", method: "POST", path: "/admin-api/oauth2/monitor/delete-pushed-request", kind: Kind::Management },
    OperationRow { operation: Operation::GetGrants, id: "getGrants", method: "GET", path: "/admin-api/grants", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeGrant, id: "revokeGrant", method: "POST", path: "/admin-api/grants/revoke-grant", kind: Kind::Management },
    OperationRow { operation: Operation::GetClaimProviders, id: "getClaimProviders", method: "GET", path: "/admin-api/claim-providers", kind: Kind::Management },
    OperationRow { operation: Operation::AddClaimProvider, id: "addClaimProvider", method: "POST", path: "/admin-api/claim-providers/add-provider", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateClaimProvider, id: "updateClaimProvider", method: "POST", path: "/admin-api/claim-providers/update-provider", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveClaimProvider, id: "removeClaimProvider", method: "POST", path: "/admin-api/claim-providers/remove-provider", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeClaimSourceLink, id: "revokeClaimSourceLink", method: "POST", path: "/admin-api/claim-providers/revoke-link", kind: Kind::Management },
    OperationRow { operation: Operation::GetAttributeSources, id: "getAttributeSources", method: "GET", path: "/admin-api/attribute-sources", kind: Kind::Management },
    OperationRow { operation: Operation::AddAttributeSource, id: "addAttributeSource", method: "POST", path: "/admin-api/attribute-sources/add-source", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateAttributeSource, id: "updateAttributeSource", method: "POST", path: "/admin-api/attribute-sources/update-source", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveAttributeSource, id: "removeAttributeSource", method: "POST", path: "/admin-api/attribute-sources/remove-source", kind: Kind::Management },
    OperationRow { operation: Operation::TestAttributeSource, id: "testAttributeSource", method: "POST", path: "/admin-api/attribute-sources/test-source", kind: Kind::Management },
    OperationRow { operation: Operation::RefreshAttributeSource, id: "refreshAttributeSource", method: "POST", path: "/admin-api/attribute-sources/refresh-source", kind: Kind::Management },
    OperationRow { operation: Operation::RefreshAttributeSourcePerson, id: "refreshAttributeSourcePerson", method: "POST", path: "/admin-api/attribute-sources/refresh-person", kind: Kind::Management },
    OperationRow { operation: Operation::GetSecretDestinations, id: "getSecretDestinations", method: "GET", path: "/admin-api/secret-destinations", kind: Kind::Management },
    OperationRow { operation: Operation::AddSecretDestination, id: "addSecretDestination", method: "POST", path: "/admin-api/secret-destinations/add-destination", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateSecretDestination, id: "updateSecretDestination", method: "POST", path: "/admin-api/secret-destinations/update-destination", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveSecretDestination, id: "removeSecretDestination", method: "POST", path: "/admin-api/secret-destinations/remove-destination", kind: Kind::Management },
    OperationRow { operation: Operation::TestSecretDestination, id: "testSecretDestination", method: "POST", path: "/admin-api/secret-destinations/test-push", kind: Kind::Management },
    OperationRow { operation: Operation::GetXacmlAuthzen, id: "getXacmlAuthzen", method: "GET", path: "/admin-api/xacml/authzen", kind: Kind::Management },
    OperationRow { operation: Operation::SetAuthzenAttribute, id: "setAuthzenAttribute", method: "POST", path: "/admin-api/xacml/authzen/set-attribute", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveAuthzenAttribute, id: "removeAuthzenAttribute", method: "POST", path: "/admin-api/xacml/authzen/remove-attribute", kind: Kind::Management },
    OperationRow { operation: Operation::SetAuthzenScope, id: "setAuthzenScope", method: "POST", path: "/admin-api/xacml/authzen/set-scope", kind: Kind::Management },
    OperationRow { operation: Operation::SetAuthzenCallbacks, id: "setAuthzenCallbacks", method: "POST", path: "/admin-api/xacml/authzen/set-callbacks", kind: Kind::Management },
    OperationRow { operation: Operation::ApproveAuthzenAccessRequest, id: "approveAuthzenAccessRequest", method: "POST", path: "/admin-api/xacml/authzen/approve-access-request", kind: Kind::Management },
    OperationRow { operation: Operation::DenyAuthzenAccessRequest, id: "denyAuthzenAccessRequest", method: "POST", path: "/admin-api/xacml/authzen/deny-access-request", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeAuthzenAccessRequest, id: "revokeAuthzenAccessRequest", method: "POST", path: "/admin-api/xacml/authzen/revoke-access-request", kind: Kind::Management },
    OperationRow { operation: Operation::CancelAuthzenAccessRequest, id: "cancelAuthzenAccessRequest", method: "POST", path: "/admin-api/xacml/authzen/cancel-access-request", kind: Kind::Management },
    OperationRow { operation: Operation::GetUma, id: "getUma", method: "GET", path: "/admin-api/uma", kind: Kind::Management },
    OperationRow { operation: Operation::GetUmaMonitor, id: "getUmaMonitor", method: "GET", path: "/admin-api/uma/monitor", kind: Kind::Management },
    OperationRow { operation: Operation::EnableUmaResourceServer, id: "enableUmaResourceServer", method: "POST", path: "/admin-api/uma/enable-resource-server", kind: Kind::Management },
    OperationRow { operation: Operation::DisableUmaResourceServer, id: "disableUmaResourceServer", method: "POST", path: "/admin-api/uma/disable-resource-server", kind: Kind::Management },
    OperationRow { operation: Operation::SetUmaOwnsResources, id: "setUmaOwnsResources", method: "POST", path: "/admin-api/uma/set-owns-resources", kind: Kind::Management },
    OperationRow { operation: Operation::DeleteUmaResource, id: "deleteUmaResource", method: "POST", path: "/admin-api/uma/delete-resource", kind: Kind::Management },
    OperationRow { operation: Operation::RevokeUmaRpt, id: "revokeUmaRpt", method: "POST", path: "/admin-api/uma/revoke-rpt", kind: Kind::Management },
    OperationRow { operation: Operation::ShareUmaResource, id: "shareUmaResource", method: "POST", path: "/admin-api/uma/owner-share", kind: Kind::Management },
    OperationRow { operation: Operation::UnshareUmaResource, id: "unshareUmaResource", method: "POST", path: "/admin-api/uma/owner-unshare", kind: Kind::Management },
    OperationRow { operation: Operation::ApproveUmaRequest, id: "approveUmaRequest", method: "POST", path: "/admin-api/uma/owner-approve", kind: Kind::Management },
    OperationRow { operation: Operation::RefuseUmaRequest, id: "refuseUmaRequest", method: "POST", path: "/admin-api/uma/owner-refuse", kind: Kind::Management },
    OperationRow { operation: Operation::GetPasskeyReport, id: "getPasskeyReport", method: "GET", path: "/admin-api/passkey-report", kind: Kind::Management },
    OperationRow { operation: Operation::ExportPasskeyReport, id: "exportPasskeyReport", method: "GET", path: "/admin-api/passkey-report/export", kind: Kind::Management },
    OperationRow { operation: Operation::ExportPasskeyAttestationEvidence, id: "exportPasskeyAttestationEvidence", method: "GET", path: "/admin-api/passkey-report/evidence", kind: Kind::Management },
    OperationRow { operation: Operation::RecountPasskeyReport, id: "recountPasskeyReport", method: "POST", path: "/admin-api/passkey-report/recount", kind: Kind::Management },
    OperationRow { operation: Operation::GetPostLoginActivities, id: "getPostLoginActivities", method: "GET", path: "/admin-api/post-login-activities", kind: Kind::Management },
    OperationRow { operation: Operation::StartPostLoginActivity, id: "startPostLoginActivity", method: "POST", path: "/admin-api/post-login-activities/start", kind: Kind::Management },
    OperationRow { operation: Operation::PausePostLoginActivity, id: "pausePostLoginActivity", method: "POST", path: "/admin-api/post-login-activities/pause", kind: Kind::Management },
    OperationRow { operation: Operation::ResumePostLoginActivity, id: "resumePostLoginActivity", method: "POST", path: "/admin-api/post-login-activities/resume", kind: Kind::Management },
    OperationRow { operation: Operation::EndPostLoginActivity, id: "endPostLoginActivity", method: "POST", path: "/admin-api/post-login-activities/end", kind: Kind::Management },
    OperationRow { operation: Operation::GetAuditExport, id: "getAuditExport", method: "GET", path: "/admin-api/audit-export", kind: Kind::Management },
    OperationRow { operation: Operation::AddAuditExportDestination, id: "addAuditExportDestination", method: "POST", path: "/admin-api/audit-export/add", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateAuditExportDestination, id: "updateAuditExportDestination", method: "POST", path: "/admin-api/audit-export/update", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveAuditExportDestination, id: "removeAuditExportDestination", method: "POST", path: "/admin-api/audit-export/remove", kind: Kind::Management },
    OperationRow { operation: Operation::EnableAuditExportDestination, id: "enableAuditExportDestination", method: "POST", path: "/admin-api/audit-export/enable", kind: Kind::Management },
    OperationRow { operation: Operation::DisableAuditExportDestination, id: "disableAuditExportDestination", method: "POST", path: "/admin-api/audit-export/disable", kind: Kind::Management },
    OperationRow { operation: Operation::TestAuditExportDestination, id: "testAuditExportDestination", method: "POST", path: "/admin-api/audit-export/test", kind: Kind::Management },
    OperationRow { operation: Operation::GetBranding, id: "getBranding", method: "GET", path: "/admin-api/branding", kind: Kind::Management },
    OperationRow { operation: Operation::UploadBrandingLogo, id: "uploadBrandingLogo", method: "POST", path: "/admin-api/branding/logo", kind: Kind::Management },
    OperationRow { operation: Operation::SaveBranding, id: "saveBranding", method: "POST", path: "/admin-api/branding/save", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveBrandingLogo, id: "removeBrandingLogo", method: "POST", path: "/admin-api/branding/remove-logo", kind: Kind::Management },
    OperationRow { operation: Operation::GetScimClients, id: "getScimClients", method: "GET", path: "/admin-api/scim/clients", kind: Kind::Management },
    OperationRow { operation: Operation::AddScimClient, id: "addScimClient", method: "POST", path: "/admin-api/scim/clients/add-client", kind: Kind::Management },
    OperationRow { operation: Operation::UpdateScimClient, id: "updateScimClient", method: "POST", path: "/admin-api/scim/clients/update-client", kind: Kind::Management },
    OperationRow { operation: Operation::RemoveScimClient, id: "removeScimClient", method: "POST", path: "/admin-api/scim/clients/remove-client", kind: Kind::Management },
    OperationRow { operation: Operation::IssueScimClientCertificate, id: "issueScimClientCertificate", method: "POST", path: "/admin-api/scim/clients/issue-certificate", kind: Kind::Management },
    OperationRow { operation: Operation::TestScimClient, id: "testScimClient", method: "POST", path: "/admin-api/scim/clients/test-connection", kind: Kind::Management },
    OperationRow { operation: Operation::ReconcileScimClient, id: "reconcileScimClient", method: "POST", path: "/admin-api/scim/clients/reconcile", kind: Kind::Management },
    OperationRow { operation: Operation::DeliverScimClientNow, id: "deliverScimClientNow", method: "POST", path: "/admin-api/scim/clients/deliver-now", kind: Kind::Management },
    OperationRow { operation: Operation::RetryScimDelivery, id: "retryScimDelivery", method: "POST", path: "/admin-api/scim/clients/retry-delivery", kind: Kind::Management },
    OperationRow { operation: Operation::RetryScimDeadLetters, id: "retryScimDeadLetters", method: "POST", path: "/admin-api/scim/clients/retry-dead", kind: Kind::Management },
    OperationRow { operation: Operation::PurgeScimDeadLetters, id: "purgeScimDeadLetters", method: "POST", path: "/admin-api/scim/clients/purge-dead", kind: Kind::Management },
    OperationRow { operation: Operation::GetProviderCommands, id: "getProviderCommands", method: "GET", path: "/admin-api/commands", kind: Kind::Management },
    OperationRow { operation: Operation::SendAccountCommand, id: "sendAccountCommand", method: "POST", path: "/admin-api/commands/send-account", kind: Kind::Management },
    OperationRow { operation: Operation::SendTenantCommand, id: "sendTenantCommand", method: "POST", path: "/admin-api/commands/send-tenant", kind: Kind::Management },
    OperationRow { operation: Operation::RetryCommandDelivery, id: "retryCommandDelivery", method: "POST", path: "/admin-api/commands/retry-delivery", kind: Kind::Management },
    OperationRow { operation: Operation::GetOutboundDeliveries, id: "getOutboundDeliveries", method: "GET", path: "/admin-api/deliveries", kind: Kind::Management },
    OperationRow { operation: Operation::RetryOutboundDelivery, id: "retryOutboundDelivery", method: "POST", path: "/admin-api/deliveries/retry", kind: Kind::Management },
    OperationRow { operation: Operation::GetPartnerSignals, id: "getPartnerSignals", method: "GET", path: "/admin-api/ssf/transmitters", kind: Kind::Management },
    OperationRow { operation: Operation::GetMalwareScanning, id: "getMalwareScanning", method: "GET", path: "/admin-api/malware-scanning", kind: Kind::Management },
    OperationRow { operation: Operation::TestMalwareScanning, id: "testMalwareScanning", method: "POST", path: "/admin-api/malware-scanning/test", kind: Kind::Management },
    OperationRow { operation: Operation::EndAllSessions, id: "endAllSessions", method: "POST", path: "/admin-api/sessions/end-all", kind: Kind::Management },
    OperationRow { operation: Operation::GetAuditIntegrity, id: "getAuditIntegrity", method: "GET", path: "/admin-api/audit/integrity", kind: Kind::Management },
    OperationRow { operation: Operation::GetApiExplorer, id: "getApiExplorer", method: "GET", path: "/admin-api/console/api-explorer", kind: Kind::Console },
    OperationRow { operation: Operation::GetConsoleShell, id: "getConsoleShell", method: "GET", path: "/admin-api/console", kind: Kind::Console },
    OperationRow { operation: Operation::SetConsoleLanguage, id: "setConsoleLanguage", method: "POST", path: "/admin-api/console/language", kind: Kind::Console },
    OperationRow { operation: Operation::GetDelegationMap, id: "getDelegationMap", method: "GET", path: "/admin-api/console/delegation/map", kind: Kind::Console },
    OperationRow { operation: Operation::GetFederationMap, id: "getFederationMap", method: "GET", path: "/admin-api/console/federation/map", kind: Kind::Console },
    OperationRow { operation: Operation::GetDelegationCluster, id: "getDelegationCluster", method: "GET", path: "/admin-api/console/delegation/cluster", kind: Kind::Console },
    OperationRow { operation: Operation::GetDelegationAllowed, id: "getDelegationAllowed", method: "GET", path: "/admin-api/console/delegation/allowed", kind: Kind::Console },
    OperationRow { operation: Operation::GetDelegationSettings, id: "getDelegationSettings", method: "GET", path: "/admin-api/console/delegation-settings", kind: Kind::Console },
    OperationRow { operation: Operation::GetDelegationChain, id: "getDelegationChain", method: "GET", path: "/admin-api/console/delegation/chain", kind: Kind::Console },
    OperationRow { operation: Operation::GetConsoleDashboard, id: "getConsoleDashboard", method: "GET", path: "/admin-api/console/dashboard", kind: Kind::Console },
    OperationRow { operation: Operation::GetConsoleNewApplicationForm, id: "getConsoleNewApplicationForm", method: "GET", path: "/admin-api/console/applications/new", kind: Kind::Console },
    OperationRow { operation: Operation::GetConsoleDelegationUser, id: "getConsoleDelegationUser", method: "GET", path: "/admin-api/console/delegation/user", kind: Kind::Console },
    OperationRow { operation: Operation::GetConsoleDelegationApplication, id: "getConsoleDelegationApplication", method: "GET", path: "/admin-api/console/delegation/application", kind: Kind::Console },
    OperationRow { operation: Operation::ApplyPkiProfile, id: "applyPkiProfile", method: "POST", path: "/admin-api/console/pki/apply-profile", kind: Kind::Console },
    OperationRow { operation: Operation::GeneratePkiKeyPair, id: "generatePkiKeyPair", method: "POST", path: "/admin-api/console/pki/generate-keys", kind: Kind::Console },
    OperationRow { operation: Operation::GeneratePkiAltKeyPair, id: "generatePkiAltKeyPair", method: "POST", path: "/admin-api/console/pki/generate-alt-keys", kind: Kind::Console },
    OperationRow { operation: Operation::UsePkiStoredKey, id: "usePkiStoredKey", method: "POST", path: "/admin-api/console/pki/use-key", kind: Kind::Console },
    OperationRow { operation: Operation::GenerateClientSecret, id: "generateClientSecret", method: "POST", path: "/admin-api/console/applications/generate-secret", kind: Kind::Console },
    OperationRow { operation: Operation::GetConsoleOperations, id: "getConsoleOperations", method: "GET", path: "/admin-api/console/operations", kind: Kind::Console },
    OperationRow { operation: Operation::GetConsoleOpenApi, id: "getConsoleOpenApi", method: "GET", path: "/admin-api/console/openapi.json", kind: Kind::Console },
];

// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
//
// The shapes more than one operation of the published APIs shares (#1390),
// each written once. A shape is here because at least two operations hold it.

import "../lib/api_lib.tsp";

using IyaSts.ApiLib;

namespace IyaSts.Api.Common;

@js(#{`$types`:#["string","null"]}) @hoisted model NullableString {}

@js(#{`$types`:#["number","null"]}) @hoisted model NullableNumber {}

@js(#{`description`:"A translated message by its key."}) @hoisted model ListOfRecordString is Record<string>;

@js(#{`const`:""}) @hoisted scalar EmptyText extends string;

@js(#{`maxLength`:1024}) @hoisted scalar StringMax1024 extends string;

@js(#{`minimum`:1,`maximum`:100000}) @hoisted scalar IntegerFrom1To100000 extends integer;

@js(#{`$types`:#["string","number","null"]}) @hoisted model Shape {}

@js(#{`$types`:#["string","number"]}) @hoisted model Shape2 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `reason`:#{`type`:"string"}, `at`:#{`type`:"number"}, `note`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject {}

@js(#{ `x-free-form`:"An RFC 9635 section 8 access right as the client asked for it: a reference string, or an object whose members the client and the resource server define.", `description`:"An RFC 9635 section 8 access right as the client asked for it: a reference string, or an object whose members the client and the resource server define." }) @hoisted model Shape3 {}

@hoisted union StringOrString {string, (string)[]}

@js(#{`minLength`:1,`maxLength`:256}) @hoisted scalar StringMin1Max256 extends string;

@js(#{`minLength`:1,`maxLength`:4096,`pattern`:"^[A-Za-z0-9._~+/=-]+$"}) @hoisted scalar StringMin1Max4096Matchingfb79a8 extends string;

@js(#{ `additionalProperties`:false, `properties`:#{ `you`:#{`type`:"boolean"}, `groups`:#{`type`:"array",`items`:#{`type`:"string"}} }, `$types`:#["object","null"] }) @hoisted model NullableObject2 {}

@js(#{`minLength`:1,`maxLength`:256,`pattern`:"^[\\x21-\\x7E]+$"}) @hoisted scalar StringMin1Max256Matching8fe5b0 extends string;

@js(#{`$types`:#["boolean","null"]}) @hoisted model NullableBoolean {}

@js(#{ `additionalProperties`:false, `properties`:#{ `upgradedAt`:#{`type`:"number"}, `mode`:#{`type`:"string"}, `previousAlgorithm`:#{`type`:"string"}, `previousCredentialId`:#{`type`:"string"}, `upgradedTo`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject3 {}

@js(#{ `additionalProperties`:false, `properties`:#{`at`:#{`type`:"number"}}, `$types`:#["object","null"] }) @hoisted model NullableObject4 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `verified`:#{`type`:"boolean"}, `trusted`:#{`type`:"boolean"}, `model`:#{`type`:"string"}, `type`:#{`type`:"string"}, `androidStatus`:#{`type`:"string"}, `deviceSerial`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject5 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `kind`:#{`type`:"string"}, `lane`:#{`type`:"string"}, `challenge`:#{`type`:"string"}, `rpId`:#{`type`:"string"}, `user`:#{`type`:"string"}, `userHandle`:#{`type`:"string"}, `display`:#{`type`:"string"}, `exclude`:#{`type`:"array",`items`:#{`type`:"string"}}, `options`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `rp`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`name`:#{`type`:"string"},`id`:#{`type`:"string"}} }, `algorithms`:#{`type`:"array",`items`:#{`type`:"integer"}}, `attestation`:#{`type`:"string"}, `timeout`:#{`type`:"number"}, `authenticatorSelection`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `userVerification`:#{`type`:"string"}, `residentKey`:#{`type`:"string"}, `requireResidentKey`:#{`type`:"boolean"}, `authenticatorAttachment`:#{`type`:"string"} } }, `credProps`:#{`type`:"boolean"}, `minPinLength`:#{`type`:"boolean"}, `hints`:#{`type`:"array",`items`:#{`type`:"string"}} } }, `fallback`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `asksPostQuantum`:#{`type`:"boolean"}, `classical`:#{`type`:"boolean"}, `retrying`:#{`type`:"boolean"} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject6 {}

@js(#{`minLength`:1,`maxLength`:4096,`pattern`:"^[A-Za-z0-9_-]+$"}) @hoisted scalar StringMin1Max4096Matchinga5aa8a extends string;

@js(#{ `additionalProperties`:false, `properties`:#{ `enrolledAt`:#{`type`:#["string","number","null"]}, `lastUsedAt`:#{`type`:#["string","number","null"]}, `algorithm`:#{`type`:"string"}, `digits`:#{`type`:"number"}, `period`:#{`type`:"number"} }, `$types`:#["object","null"] }) @hoisted model NullableObject7 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `grouped`:#{`type`:"string"}, `issuer`:#{`type`:"string"}, `qr`:#{`type`:"string"}, `algorithm`:#{`type`:"string"}, `digits`:#{`type`:"number"}, `period`:#{`type`:"number"} }, `$types`:#["object","null"] }) @hoisted model NullableObject8 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `allowed`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`code`:#{`type`:"boolean"},`link`:#{`type`:"boolean"}} }, `optedIn`:#{`type`:"string"}, `usable`:#{`type`:"boolean"}, `kind`:#{`type`:"string"}, `why`:#{`type`:"string"}, `offered`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`code`:#{`type`:"boolean"},`link`:#{`type`:"boolean"}} }, `verified`:#{`type`:"boolean"}, `masked`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject9 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `handle`:#{`type`:"string"}, `replacing`:#{`type`:"boolean"}, `codes`:#{`type`:"array",`items`:#{`type`:"string"}} }, `$types`:#["object","null"] }) @hoisted model NullableObject10 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `issued`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `subject`:#{`type`:"string"}, `serialHex`:#{`type`:"string"}, `keyAlg`:#{`type`:"string"}, `notAfter`:#{`type`:"string"} } }, `purpose`:#{`type`:"string"}, `handle`:#{`type`:"string"}, `label`:#{`type`:"string"}, `files`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `key`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `name`:#{`type`:"string"}, `mime`:#{`type`:"string"}, `base64`:#{`type`:"string"} } }, `chain`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `name`:#{`type`:"string"}, `mime`:#{`type`:"string"}, `base64`:#{`type`:"string"} } } } }, `kid`:#{`type`:"string"}, `thumbprint`:#{`type`:"string"}, `jwsAlg`:#{`type`:"string"}, `issuer`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject11 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `id`:#{`type`:"string"}, `admin`:#{`type`:"boolean"} }, `$types`:#["object","null"] }) @hoisted model NullableObject12 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `keys`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kid`:#{`type`:"string"}, `createdAt`:#{`type`:#["string","number","null"]}, `expiresAt`:#{`type`:#["string","number","null"]}, `createdBy`:#{`type`:#["string","null"]}, `boundAccount`:#{`type`:#["string","null"]}, `boundAt`:#{`type`:#["string","number","null"]}, `status`:#{`type`:"string"} } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject13 {}

@js(#{ `additionalProperties`:false, `properties`:#{`profiles`:#{`type`:"array",`items`:#{`type`:"string"}}}, `$types`:#["object","null"] }) @hoisted model NullableObject14 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `challenges`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `profile`:#{`type`:#["string","null"]}, `createdAt`:#{`type`:#["string","number","null"]}, `expiresAt`:#{`type`:#["string","number","null"]}, `createdBy`:#{`type`:#["string","null"]}, `usedAt`:#{`type`:#["string","number","null"]}, `status`:#{`type`:"string"} } } }, `profiles`:#{`type`:"array",`items`:#{`type`:"string"}}, `defaultProfile`:#{`type`:#["string","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject15 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `kvno`:#{`type`:#["number","null"]}, `current`:#{`type`:"boolean"}, `etypes`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`name`:#{`type`:"string"}} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject16 {}

@js(#{ `additionalProperties`:false, `properties`:#{`kind`:#{`type`:"string"}}, `$types`:#["object","null"] }) @hoisted model NullableObject17 {}

@js(#{`pattern`:"^[A-Za-z0-9_-]{22}(?:[A-Za-z0-9_-]{12})?$"}) @hoisted scalar StringMatchinga3848a extends string;

@js(#{ `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `env`:#{`type`:"string"}, `administrator`:#{`type`:"boolean"}, `page`:#{`type`:#["string","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject18 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `enabled`:#{`type`:"boolean"}, `custody`:#{`type`:"string"}, `maxPerPerson`:#{`type`:"number"}, `keyAlgorithm`:#{`type`:"string"}, `active`:#{`type`:"integer"}, `canPublish`:#{`type`:"boolean"}, `dids`:#{ `type`:#["array","null"], `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `rid`:#{`type`:"string"}, `did`:#{`type`:"string"}, `custody`:#{`type`:"string"}, `documentUrl`:#{`type`:"string"}, `createdAt`:#{`type`:#["string","number","null"]}, `by`:#{`type`:#["string","null"]}, `state`:#{`type`:"string"}, `deactivated`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `at`:#{`type`:"string"}, `by`:#{`type`:#["string","null"]}, `reason`:#{`type`:#["string","null"]} } }, `proof`:#{`type`:"string"}, `preferred`:#{`type`:"boolean"}, `currentVersion`:#{`type`:"number"}, `pending`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{`change`:#{`type`:"string"},`expiresAt`:#{`type`:"string"}} }, `versions`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `versionId`:#{`type`:"number"}, `created`:#{`type`:#["string","number","null"]}, `change`:#{`type`:"string"}, `keys`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `kty`:#{`type`:"string"}, `crv`:#{`type`:"string"}, `alg`:#{`type`:"string"} } } }, `authorizedBy`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `subject`:#{`type`:"string"}, `keyThumbprint`:#{`type`:"string"}, `versionId`:#{`type`:"number"}, `transaction`:#{`type`:"string"}, `at`:#{`type`:"string"}, `actor`:#{`type`:"string"} } } } } } } } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject19 {}

@js(#{ `additionalProperties`:false, `properties`:#{`kind`:#{`type`:"string"},`value`:#{`type`:"string"}}, `$types`:#["object","null"] }) @hoisted model NullableObject20 {}

@js(#{`maxLength`:2048}) @hoisted scalar StringMax2048 extends string;

@js(#{ `additionalProperties`:false, `properties`:#{ `credentialOfferUri`:#{`type`:"string"}, `offerUri`:#{`type`:"string"}, `walletUrl`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject21 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `challenge`:#{`type`:"string"}, `expiresAt`:#{`type`:#["string","number","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject22 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `challenge`:#{`type`:"string"}, `rpId`:#{`type`:"string"}, `user`:#{`type`:"string"}, `allow`:#{`type`:"string"}, `options`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `rpId`:#{`type`:"string"}, `userVerification`:#{`type`:"string"}, `timeout`:#{`type`:"number"}, `hints`:#{`type`:"array",`items`:#{`type`:"string"}} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject23 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `dn`:#{`type`:"string"}, `owner`:#{`type`:"string"}, `ownerKind`:#{`type`:"string"}, `label`:#{`type`:"string"}, `applications`:#{`type`:"array",`items`:#{`type`:"string"}}, `keys`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `kind`:#{`type`:"string"}, `thumbprint`:#{`type`:"string"}, `label`:#{`type`:"string"}, `added`:#{`type`:"string"}, `addedBy`:#{`type`:"string"}, `proof`:#{`type`:"string"}, `attestation`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `level`:#{`type`:"string"}, `format`:#{`type`:"string"}, `summary`:#{`type`:"string"}, `verifiedAt`:#{`type`:"string"}, `chainSerials`:#{`type`:"array",`items`:#{`type`:"string"}}, `revocation`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `status`:#{`type`:"string"}, `reason`:#{`type`:"string"}, `serial`:#{`type`:"string"}, `listVersion`:#{`type`:"string"}, `checkedAt`:#{`type`:"string"}, `chainSerials`:#{`type`:"array",`items`:#{`type`:"string"}}, `why`:#{`type`:"string"} } }, `freshness`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`status`:#{`type`:"string"},`detail`:#{`type`:"string"}} } } }, `material`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `certificate`:#{`type`:"string"}, `subject`:#{`type`:"string"}, `issuer`:#{`type`:"string"}, `serial`:#{`type`:"string"}, `notAfter`:#{`type`:"string"}, `jwk`:#{ `x-free-form`:"A public JWK as the device presented it (RFC 7517): its members depend on its key type.", `description`:"A public JWK as the device presented it (RFC 7517): its members depend on its key type." }, `credentialId`:#{`type`:"string"}, `aaguid`:#{`type`:"string"}, `attachment`:#{`type`:"string"} } } } } }, `keyKinds`:#{`type`:"array",`items`:#{`type`:"string"}}, `attestation`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `level`:#{`type`:"string"}, `format`:#{`type`:"string"}, `summary`:#{`type`:"string"}, `keyId`:#{`type`:"string"} } }, `compliance`:#{`type`:"string"}, `complianceChange`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `status`:#{`type`:"string"}, `previous`:#{`type`:"string"}, `at`:#{`type`:"string"}, `source`:#{`type`:"string"}, `actor`:#{`type`:"string"}, `reason`:#{`type`:"string"} } }, `status`:#{`type`:"string"}, `statusChange`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `status`:#{`type`:"string"}, `previous`:#{`type`:"string"}, `at`:#{`type`:"string"}, `source`:#{`type`:"string"}, `actor`:#{`type`:"string"}, `reason`:#{`type`:"string"} } }, `riskLevel`:#{`type`:"string"}, `riskChange`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `level`:#{`type`:"string"}, `previous`:#{`type`:"string"}, `at`:#{`type`:"string"}, `source`:#{`type`:"string"}, `actor`:#{`type`:"string"}, `reason`:#{`type`:"string"}, `beforeCompromise`:#{`type`:"string"} } }, `platform`:#{`type`:"string"}, `model`:#{`type`:"string"}, `os`:#{`type`:"string"}, `enrolment`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `method`:#{`type`:"string"}, `at`:#{`type`:"string"}, `actor`:#{`type`:"string"} } }, `nativeSso`:#{`type`:"boolean"}, `rememberedBrowser`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `generation`:#{`type`:"number"}, `issuedAt`:#{`type`:"string"}, `browser`:#{`type`:"string"}, `secondFactorAt`:#{`type`:"string"} } }, `sessionLive`:#{`type`:"boolean"}, `lastUsed`:#{`type`:"string"}, `created`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject24 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `kind`:#{`type`:"string"}, `thumbprint`:#{`type`:"string"}, `label`:#{`type`:"string"}, `added`:#{`type`:"string"}, `addedBy`:#{`type`:"string"}, `proof`:#{`type`:"string"}, `attestation`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `level`:#{`type`:"string"}, `format`:#{`type`:"string"}, `summary`:#{`type`:"string"}, `verifiedAt`:#{`type`:"string"}, `chainSerials`:#{`type`:"array",`items`:#{`type`:"string"}}, `revocation`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `status`:#{`type`:"string"}, `reason`:#{`type`:"string"}, `serial`:#{`type`:"string"}, `listVersion`:#{`type`:"string"}, `checkedAt`:#{`type`:"string"}, `chainSerials`:#{`type`:"array",`items`:#{`type`:"string"}}, `why`:#{`type`:"string"} } }, `freshness`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`status`:#{`type`:"string"},`detail`:#{`type`:"string"}} } } }, `material`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `certificate`:#{`type`:"string"}, `subject`:#{`type`:"string"}, `issuer`:#{`type`:"string"}, `serial`:#{`type`:"string"}, `notAfter`:#{`type`:"string"}, `jwk`:#{ `x-free-form`:"A public JWK as the device presented it (RFC 7517): its members depend on its key type.", `description`:"A public JWK as the device presented it (RFC 7517): its members depend on its key type." }, `credentialId`:#{`type`:"string"}, `aaguid`:#{`type`:"string"}, `attachment`:#{`type`:"string"} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject25 {}

@js(#{ `additionalProperties`:false, `properties`:#{`id`:#{`type`:"string"},`name`:#{`type`:"string"}}, `$types`:#["object","null"] }) @hoisted model NullableObject26 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `approvedAt`:#{`type`:#["string","number","null"]}, `approvedUntil`:#{`type`:#["string","number","null"]}, `approver`:#{`type`:#["string","null"]}, `revoked`:#{`type`:"boolean"} }, `$types`:#["object","null"] }) @hoisted model NullableObject27 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `userCode`:#{`type`:"string"}, `clientId`:#{`type`:"string"}, `clientName`:#{`type`:"string"}, `scope`:#{`type`:"string"}, `expiresAt`:#{`type`:#["string","number","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject28 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `linkedAt`:#{`type`:#["string","number","null"]}, `stale`:#{`type`:"boolean"} }, `$types`:#["object","null"] }) @hoisted model NullableObject29 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `name`:#{`type`:"string"}, `logo`:#{`type`:"string"}, `logoOrigin`:#{`type`:"string"}, `policy`:#{`type`:"string"}, `tos`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject30 {}

@js(#{ `additionalProperties`:false, `properties`:#{`register`:#{`type`:"string"}}, `$types`:#["object","null"] }) @hoisted model NullableObject31 {}

@js(#{ `additionalProperties`:false, `properties`:#{`why`:#{`type`:"string"}}, `$types`:#["object","null"] }) @hoisted model NullableObject32 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `asksPostQuantum`:#{`type`:"boolean"}, `classical`:#{`type`:"boolean"}, `retrying`:#{`type`:"boolean"}, `upgrade`:#{`type`:"boolean"} }, `$types`:#["object","null"] }) @hoisted model NullableObject33 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `required`:#{`type`:"boolean"}, `upgrade`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `phase`:#{`type`:"string",`enum`:#["proof","registration"]}, `name`:#{`type`:"string"}, `previousAlgorithm`:#{`type`:"string"} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject34 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `uri`:#{`type`:"string"}, `secret`:#{`type`:"string"}, `algorithm`:#{`type`:"string"}, `digits`:#{`type`:"number"}, `period`:#{`type`:"number"} }, `$types`:#["object","null"] }) @hoisted model NullableObject35 {}

@js(#{`minLength`:1,`maxLength`:4096}) @hoisted scalar StringMin1Max4096 extends string;

@js(#{ `additionalProperties`:false, `properties`:#{ `protocol`:#{`type`:"string"}, `data`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`request`:#{`type`:"string"}} } }, `$types`:#["object","null"] }) @hoisted model NullableObject36 {}

@hoisted union StringOrNumeric {string, numeric}

@js(#{`maxLength`:4096}) @hoisted scalar StringMax4096 extends string;

@hoisted union StringOrNumericOrBoolean {string, numeric, boolean}

@js(#{`description`:"One operation."}) @hoisted model WithMethodPathOperationIdEtc { `method`?: string; `path`?: string; `operationId`?: string; `summary`?: string; @js(#{`description`:"The /admin control this operation is the API form of."}) `mirrors`?: string; @js(#{`description`:"Which of the two kinds the operation is (#454)."}) `kind`?: "management" | "console"; @js(#{ `description`:"The console pages drawn from this operation's data by one of the console's own operations (#454); present only where there are any." }) `drawnOn`?: (string)[] }

@js(#{`$types`:#["integer","null"]}) @hoisted model NullableInteger {}

@js(#{ `additionalProperties`:false, `properties`:#{ `subject`:#{`type`:#["string","null"]}, `issuedBy`:#{`type`:#["string","null"]}, `notAfter`:#{`type`:#["string","null"]}, `pinned`:#{`type`:"boolean"} }, `$types`:#["object","null"] }) @hoisted model NullableObject37 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `algorithm`:#{`type`:"string"}, `label`:#{`type`:"string"}, `family`:#{`type`:"string"}, `standard`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject38 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `scheduled`:#{`type`:"boolean"}, `offReason`:#{`type`:"string"}, `units`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `unit`:#{`type`:"string"}, `current`:#{`type`:#["string","null"]}, `next`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{`kid`:#{`type`:"string"},`since`:#{`type`:#["string","null"]}} }, `retired`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kid`:#{`type`:"string"}, `retiredAt`:#{`type`:#["string","null"]}, `verifiesUntil`:#{`type`:#["string","null"]} } } }, `lastRotated`:#{`type`:#["string","null"]}, `intervalDays`:#{`type`:"number"}, `graceDays`:#{`type`:"number"}, `credentialSigner`:#{`type`:"boolean"} } } }, `refresh`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `lastRotated`:#{`type`:#["string","null"]}, `retired`:#{`type`:"integer"}, `graceDays`:#{`type`:"number"} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject39 {}

@js(#{`description`:"One file."}) @hoisted model WithNameMimeBytesEtc {`name`?: string; `mime`?: string; `bytes`?: integer; `base64`?: string}

@js(#{ `additionalProperties`:false, `properties`:#{ `bound`:#{`type`:"boolean"}, `fact`:#{`type`:"string"}, `alg`:#{`type`:"string"}, `boundAt`:#{`type`:"number"}, `refreshedAt`:#{`type`:"number"}, `refreshes`:#{`type`:"number"}, `reasons`:#{`type`:"array",`items`:#{`type`:"string"}} }, `$types`:#["object","null"] }) @hoisted model NullableObject40 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `people`:#{`type`:"number"}, `withSecond`:#{`type`:"number"}, `withTotp`:#{`type`:"number"}, `withKeys`:#{`type`:"number"}, `primaryKeys`:#{`type`:"number"}, `unreadable`:#{`type`:"number"}, `withPassword`:#{`type`:"number"}, `passwordOnly`:#{`type`:"number"}, `noWayIn`:#{`type`:"number"}, `signedInHere`:#{`type`:#["number","null"]}, `neverSignedInHere`:#{`type`:#["number","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject41 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `username`:#{`type`:"string"}, `inDirectory`:#{`type`:"boolean"}, `known`:#{`type`:"boolean"}, `password`:#{`type`:"boolean"}, `primaryKeys`:#{`type`:"number"}, `mfaKeys`:#{`type`:"number"}, `totp`:#{`type`:"boolean"}, `totpUsable`:#{`type`:"boolean"}, `totpDetail`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `enrolledAt`:#{`type`:"number"}, `lastUsedAt`:#{`type`:"number"}, `algorithm`:#{`type`:"string"}, `digits`:#{`type`:"number"}, `period`:#{`type`:"number"}, `sealed`:#{`type`:"boolean"}, `unusable`:#{`type`:"boolean"}, `why`:#{`type`:"string"} } }, `backupCodes`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `present`:#{`type`:"boolean"}, `usable`:#{`type`:"boolean"}, `total`:#{`type`:"number"}, `remaining`:#{`type`:"number"}, `used`:#{`type`:"number"}, `generatedAt`:#{`type`:"number"}, `lastUsedAt`:#{`type`:"number"}, `sealed`:#{`type`:"boolean"}, `hashed`:#{`type`:"boolean"}, `legacy`:#{`type`:"boolean"}, `why`:#{`type`:"string"} } }, `recoveryAdvised`:#{`type`:"boolean"}, `mfaRequired`:#{`type`:"boolean"}, `secondFactor`:#{`type`:#["string","null"]}, `usable`:#{`type`:"boolean"} }, `$types`:#["object","null"] }) @hoisted model NullableObject42 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `username`:#{`type`:"string"}, `owners`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `dn`:#{`type`:"string"}, `kind`:#{`type`:"string"}, `name`:#{`type`:"string"}, `present`:#{`type`:"boolean"} } } }, `ownership`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `name`:#{`type`:"string"}, `marked`:#{`type`:"boolean"}, `protected`:#{`type`:"boolean"}, `reasons`:#{`type`:"array",`items`:#{`type`:"string"}} } }, `destination`:#{`type`:#["string","null"]}, `secretName`:#{`type`:#["string","null"]}, `rotatedAt`:#{`type`:#["string","null"]}, `previousPasswordUntil`:#{`type`:#["string","null"]}, `rotation`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `enabled`:#{`type`:"boolean"}, `rotates`:#{`type`:"boolean"}, `nextDueAt`:#{`type`:#["string","null"]}, `failures`:#{`type`:"number"}, `lastError`:#{`type`:#["string","null"]}, `lastAttemptAt`:#{`type`:#["string","null"]}, `alarm`:#{`type`:"boolean"} } }, `policy`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `exemptFromSecondFactor`:#{`type`:"boolean"}, `allowBrowserSignIn`:#{`type`:"boolean"}, `doors`:#{`type`:"array",`items`:#{`type`:"string"}}, `requiresOwner`:#{`type`:"boolean"}, `from`:#{`type`:"string"}, `name`:#{`type`:#["string","null"]} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject43 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `subject`:#{`type`:"string"}, `level`:#{`type`:"string"}, `score`:#{`type`:"number"}, `previousLevel`:#{`type`:"string"}, `reason`:#{`type`:"string"}, `lastAssessment`:#{`type`:"string"}, `crossedAt`:#{`type`:"number"}, `updatedAt`:#{`type`:"number"} }, `$types`:#["object","null"] }) @hoisted model NullableObject44 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `password`:#{`type`:"boolean"}, `passwordChangeRequired`:#{`type`:"boolean"}, `passwordResetLink`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{`expires`:#{`type`:"number"},`expired`:#{`type`:"boolean"}} }, `disabled`:#{`type`:"boolean"}, `mfaRequirement`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `required`:#{`type`:"boolean"}, `byUser`:#{`type`:"boolean"}, `byRealm`:#{`type`:"boolean"}, `byAdministrator`:#{`type`:"boolean"}, `offered`:#{`type`:"boolean"}, `exemptServiceAccount`:#{`type`:"boolean"} } }, `usable`:#{`type`:"boolean"}, `activated`:#{`type`:"boolean"}, `mfaRequired`:#{`type`:"boolean"}, `secondFactor`:#{`type`:#["string","null"]}, `totp`:#{`type`:"boolean"}, `totpUsable`:#{`type`:"boolean"}, `totpDetail`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `enrolledAt`:#{`type`:"number"}, `lastUsedAt`:#{`type`:"number"}, `algorithm`:#{`type`:"string"}, `digits`:#{`type`:"number"}, `period`:#{`type`:"number"}, `sealed`:#{`type`:"boolean"}, `unusable`:#{`type`:"boolean"}, `why`:#{`type`:"string"} } }, `backupCodes`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `present`:#{`type`:"boolean"}, `usable`:#{`type`:"boolean"}, `total`:#{`type`:"number"}, `remaining`:#{`type`:"number"}, `used`:#{`type`:"number"}, `generatedAt`:#{`type`:"number"}, `lastUsedAt`:#{`type`:"number"}, `sealed`:#{`type`:"boolean"}, `hashed`:#{`type`:"boolean"}, `legacy`:#{`type`:"boolean"}, `why`:#{`type`:"string"} } }, `keys`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `credentialId`:#{`type`:"string"}, `label`:#{`type`:#["string","null"]}, `signCount`:#{`type`:"number"}, `enrolledAt`:#{`type`:"number"}, `aaguid`:#{`type`:#["string","null"]}, `algorithm`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `name`:#{`type`:"string"}, `coseAlg`:#{`type`:#["number","null"]}, `text`:#{`type`:"string"}, `postQuantum`:#{`type`:"boolean"}, `insecure`:#{`type`:"boolean"}, `lane`:#{`type`:"string"} } }, `lane`:#{`type`:"string"}, `attestation`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `policy`:#{`type`:"string"}, `format`:#{`type`:"string"}, `type`:#{`type`:"string"}, `verified`:#{`type`:"boolean"}, `trusted`:#{`type`:"boolean"}, `anchor`:#{`type`:"string"}, `aaguid`:#{`type`:#["string","null"]}, `model`:#{`type`:"string"}, `certificationLevel`:#{`type`:"string"}, `mdsStatus`:#{`type`:"string"}, `mdsVersion`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `checkedAt`:#{`type`:"number"}, `algorithms`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `statement`:#{`type`:"string"}, `statementCoseAlg`:#{`type`:#["integer","null"]}, `certificates`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `algorithm`:#{`type`:"string"}, `oid`:#{`type`:"string"}, `family`:#{`type`:"string"}, `postQuantum`:#{`type`:"boolean"}, `composite`:#{`type`:"boolean"} } } }, `anchor`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `algorithm`:#{`type`:"string"}, `oid`:#{`type`:"string"}, `family`:#{`type`:"string"}, `postQuantum`:#{`type`:"boolean"}, `composite`:#{`type`:"boolean"} } }, `postQuantum`:#{`type`:"boolean"}, `members`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `format`:#{`type`:"string"}, `statement`:#{`type`:"string"}, `statementCoseAlg`:#{`type`:#["integer","null"]}, `certificates`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `algorithm`:#{`type`:"string"}, `oid`:#{`type`:"string"}, `family`:#{`type`:"string"}, `postQuantum`:#{`type`:"boolean"}, `composite`:#{`type`:"boolean"} } } }, `anchor`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `algorithm`:#{`type`:"string"}, `oid`:#{`type`:"string"}, `family`:#{`type`:"string"}, `postQuantum`:#{`type`:"boolean"}, `composite`:#{`type`:"boolean"} } } } } } } }, `conveyance`:#{`type`:"string"}, `enterpriseDowngraded`:#{`type`:"boolean"}, `attestationKeyId`:#{`type`:"string"}, `deviceSerial`:#{`type`:"string"}, `deviceSerialSource`:#{`type`:"string"}, `evidence`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `syntax`:#{`type`:"string"}, `version`:#{`type`:"number"}, `object`:#{`type`:"string"}, `objectDigest`:#{`type`:"string"}, `evidenceRecord`:#{`type`:"string"}, `timestamps`:#{`type`:"array",`items`:#{`type`:"string"}}, `createdAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `renewedAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `renewAfter`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `hashAlgorithm`:#{`type`:"string"}, `tsa`:#{`type`:#["string","null"]} } }, `androidRevocation`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `status`:#{`type`:"string"}, `reason`:#{`type`:"string"}, `serial`:#{`type`:"string"}, `listVersion`:#{`type`:"string"}, `checkedAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `chainSerials`:#{`type`:"array",`items`:#{`type`:"string"}}, `why`:#{`type`:"string"} } } } }, `attestationAlgorithms`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `verified`:#{`type`:"boolean"}, `trusted`:#{`type`:"boolean"}, `recorded`:#{`type`:"boolean"}, `statement`:#{`type`:"string"}, `statements`:#{`type`:"array",`items`:#{`type`:"string"}}, `certificates`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `algorithm`:#{`type`:"string"}, `family`:#{`type`:"string"}, `postQuantum`:#{`type`:"boolean"} } } }, `postQuantum`:#{`type`:"boolean"} } }, `name`:#{`type`:"string"}, `group`:#{`type`:"string"}, `provider`:#{`type`:#["string","null"]}, `lastUsedAt`:#{`type`:"number"}, `backupEligible`:#{`type`:#["boolean","null"]}, `backupState`:#{`type`:#["boolean","null"]}, `transports`:#{`type`:"array",`items`:#{`type`:"string"}}, `discoverable`:#{`type`:#["boolean","null"]}, `deviceSerial`:#{`type`:#["string","null"]}, `possiblyReplaced`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{`by`:#{`type`:"string"},`at`:#{`type`:"number"}} }, `withoutUsername`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`ready`:#{`type`:"boolean"},`text`:#{`type`:"string"}} }, `postQuantumRefused`:#{`type`:"string"} } } }, `primaryKeys`:#{`type`:"number"}, `mfaKeys`:#{`type`:"number"}, `appPasswords`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `name`:#{`type`:"string"}, `doors`:#{`type`:"array",`items`:#{`type`:"string"}}, `doorLabels`:#{`type`:"array",`items`:#{`type`:"string"}}, `createdAt`:#{`type`:"number"}, `createdBy`:#{`type`:"string"}, `lastUsedAt`:#{`type`:"number"}, `lastUsedDoor`:#{`type`:"string"} } } }, `passwordOnlyDoors`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `secondFactor`:#{`type`:"boolean"}, `refused`:#{`type`:"array",`items`:#{`type`:"string"}}, `accepted`:#{`type`:"array",`items`:#{`type`:"string"}}, `passwordAloneDoors`:#{`type`:"array",`items`:#{`type`:"string"}}, `sentence`:#{`type`:"string"} } }, `policy`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `totpEnabled`:#{`type`:"boolean"}, `backupCodesEnabled`:#{`type`:"boolean"}, `backupCodesCount`:#{`type`:"number"}, `webauthnEnabled`:#{`type`:"boolean"}, `primaryAllowed`:#{`type`:"boolean"}, `mfaAllowed`:#{`type`:"boolean"}, `maxKeysPerPerson`:#{`type`:"number"} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject45 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `dn`:#{`type`:"string"}, `found`:#{`type`:"boolean"}, `entry`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `dn`:#{`type`:"string"}, `origin`:#{`type`:"string"}, `createdAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `modifiedAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `operational`:#{`type`:"array",`items`:#{`type`:"string"}}, `attributes`:#{ `type`:"object", `additionalProperties`:#{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] } }, `rule`:#{`type`:"string"}, `members`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `value`:#{`type`:"string"}, `attribute`:#{`type`:"string"}, `holds`:#{`type`:"string"}, `dn`:#{`type`:"string"}, `present`:#{`type`:"boolean"}, `kind`:#{`type`:"string"}, `userKey`:#{`type`:"string"}, `cn`:#{`type`:"string"}, `mail`:#{`type`:"string"}, `displayName`:#{`type`:"string"} } } } } }, `alsoNamed`:#{`type`:"array",`items`:#{`type`:"string"}}, `baseDn`:#{`type`:"string"}, `usersDn`:#{`type`:"string"}, `port`:#{`type`:#["number","null"]}, `listening`:#{`type`:"boolean"}, `listenError`:#{`type`:#["string","null"]}, `ldapsPort`:#{`type`:#["number","null"]}, `ldapsListening`:#{`type`:"boolean"}, `autoCreateUsers`:#{`type`:"boolean"}, `entryCount`:#{`type`:"number"}, `maxEntries`:#{`type`:"number"}, `full`:#{`type`:"boolean"} }, `$types`:#["object","null"] }) @hoisted model NullableObject46 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `subject`:#{`type`:"string"}, `issuer`:#{`type`:"string"}, `serialHex`:#{`type`:"string"}, `notBefore`:#{`type`:"string"}, `notAfter`:#{`type`:"string"}, `expired`:#{`type`:"boolean"}, `selfSigned`:#{`type`:"boolean"}, `keyType`:#{`type`:"string"}, `thumbprint`:#{`type`:"string"}, `unreadable`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject47 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `kvno`:#{`type`:#["number","null"]}, `etypes`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`etype`:#{`type`:"number"},`name`:#{`type`:"string"}} } }, `derivedAt`:#{`type`:"string"}, `derivedOn`:#{`type`:"string"}, `sealed`:#{`type`:"boolean"}, `current`:#{`type`:"boolean"}, `retained`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kvno`:#{`type`:#["number","null"]}, `etypes`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`etype`:#{`type`:"number"},`name`:#{`type`:"string"}} } }, `retiredAt`:#{`type`:"string"}, `expiresAt`:#{`type`:"string"} } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject48 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `dn`:#{`type`:"string"}, `attributes`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `name`:#{`type`:"string"}, `label`:#{`type`:"string"}, `schema`:#{`type`:"string"}, `note`:#{`type`:"string"}, `simple`:#{`type`:"boolean"}, `must`:#{`type`:"boolean"}, `format`:#{`type`:"string"}, `custom`:#{`type`:"boolean"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `required`:#{`type`:"boolean"}, `why`:#{`type`:"string"}, `example`:#{`type`:"string"}, `editable`:#{`type`:"boolean"}, `group`:#{`type`:"string"}, `multi`:#{`type`:"boolean"}, `choices`:#{`type`:"array",`items`:#{`type`:"string"}} } } }, `withheld`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `name`:#{`type`:"string"}, `label`:#{`type`:"string"}, `kind`:#{`type`:"string"}, `why`:#{`type`:"string"} } } }, `mail`:#{`type`:"string"}, `pseudonyms`:#{`type`:"array",`items`:#{`type`:"string"}}, `pseudonymPending`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject49 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `page`:#{`type`:"integer"}, `pages`:#{`type`:"integer"}, `perPage`:#{`type`:"integer"}, `firstRow`:#{`type`:"integer"}, `lastRow`:#{`type`:"integer"}, `total`:#{`type`:"integer"}, `param`:#{`type`:"string"}, `noun`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject50 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `multiCell`:#{`type`:"boolean"}, `cell`:#{`type`:"string"}, `complete`:#{`type`:"boolean"}, `note`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject51 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `user`:#{`type`:"string"}, `resources`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `name`:#{`type`:"string"}, `type`:#{`type`:"string"}, `scopes`:#{`type`:"array",`items`:#{`type`:"string"}}, `resourceServer`:#{`type`:"string"}, `owner`:#{`type`:"string"}, `ownerKind`:#{`type`:"string"}, `createdAt`:#{`type`:"number"} } } }, `shares`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `resourceId`:#{`type`:"string"}, `scopes`:#{`type`:"array",`items`:#{`type`:"string"}}, `recipient`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `value`:#{`type`:"string"}, `label`:#{`type`:"string"} } }, `expires`:#{`type`:"string"}, `acr`:#{`type`:"string"}, `askMe`:#{`type`:"boolean"} } } }, `held`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `jti`:#{`type`:"string"}, `requestingParty`:#{`type`:"string"}, `client`:#{`type`:"string"}, `resourceServer`:#{`type`:"string"}, `permissions`:#{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] }, `upgradedFrom`:#{`type`:"string"}, `createdAt`:#{`type`:"number"}, `exp`:#{`type`:"number"} } } }, `pending`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `state`:#{`type`:"string"}, `owner`:#{`type`:"string"}, `ownerKind`:#{`type`:"string"}, `requester`:#{`type`:"string"}, `client`:#{`type`:"string"}, `resourceServer`:#{`type`:"string"}, `permissions`:#{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] }, `createdAt`:#{`type`:"number"}, `expiresAt`:#{`type`:"number"} } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject52 {}

@hoisted union StringOrNumericOrBooleanEtc {string, numeric, boolean, null}

@js(#{ `additionalProperties`:false, `properties`:#{ `policy`:#{`type`:"string"}, `format`:#{`type`:"string"}, `type`:#{`type`:"string"}, `verified`:#{`type`:"boolean"}, `trusted`:#{`type`:"boolean"}, `anchor`:#{`type`:"string"}, `aaguid`:#{`type`:#["string","null"]}, `model`:#{`type`:"string"}, `certificationLevel`:#{`type`:"string"}, `mdsStatus`:#{`type`:"string"}, `mdsVersion`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `checkedAt`:#{`type`:"number"}, `algorithms`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `statement`:#{`type`:"string"}, `statementCoseAlg`:#{`type`:#["integer","null"]}, `certificates`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `algorithm`:#{`type`:"string"}, `oid`:#{`type`:"string"}, `family`:#{`type`:"string"}, `postQuantum`:#{`type`:"boolean"}, `composite`:#{`type`:"boolean"} } } }, `anchor`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `algorithm`:#{`type`:"string"}, `oid`:#{`type`:"string"}, `family`:#{`type`:"string"}, `postQuantum`:#{`type`:"boolean"}, `composite`:#{`type`:"boolean"} } }, `postQuantum`:#{`type`:"boolean"}, `members`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `format`:#{`type`:"string"}, `statement`:#{`type`:"string"}, `statementCoseAlg`:#{`type`:#["integer","null"]}, `certificates`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `algorithm`:#{`type`:"string"}, `oid`:#{`type`:"string"}, `family`:#{`type`:"string"}, `postQuantum`:#{`type`:"boolean"}, `composite`:#{`type`:"boolean"} } } }, `anchor`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `algorithm`:#{`type`:"string"}, `oid`:#{`type`:"string"}, `family`:#{`type`:"string"}, `postQuantum`:#{`type`:"boolean"}, `composite`:#{`type`:"boolean"} } } } } } } }, `conveyance`:#{`type`:"string"}, `enterpriseDowngraded`:#{`type`:"boolean"}, `attestationKeyId`:#{`type`:"string"}, `deviceSerial`:#{`type`:"string"}, `deviceSerialSource`:#{`type`:"string"}, `evidence`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `syntax`:#{`type`:"string"}, `version`:#{`type`:"number"}, `object`:#{`type`:"string"}, `objectDigest`:#{`type`:"string"}, `evidenceRecord`:#{`type`:"string"}, `timestamps`:#{`type`:"array",`items`:#{`type`:"string"}}, `createdAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `renewedAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `renewAfter`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `hashAlgorithm`:#{`type`:"string"}, `tsa`:#{`type`:#["string","null"]} } }, `androidRevocation`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `status`:#{`type`:"string"}, `reason`:#{`type`:"string"}, `serial`:#{`type`:"string"}, `listVersion`:#{`type`:"string"}, `checkedAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `chainSerials`:#{`type`:"array",`items`:#{`type`:"string"}}, `why`:#{`type`:"string"} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject53 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `enrolledAt`:#{`type`:"number"}, `lastUsedAt`:#{`type`:"number"}, `algorithm`:#{`type`:"string"}, `digits`:#{`type`:"number"}, `period`:#{`type`:"number"}, `sealed`:#{`type`:"boolean"}, `unusable`:#{`type`:"boolean"}, `why`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject54 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `present`:#{`type`:"boolean"}, `usable`:#{`type`:"boolean"}, `total`:#{`type`:"number"}, `remaining`:#{`type`:"number"}, `used`:#{`type`:"number"}, `generatedAt`:#{`type`:"number"}, `lastUsedAt`:#{`type`:"number"}, `sealed`:#{`type`:"boolean"}, `hashed`:#{`type`:"boolean"}, `legacy`:#{`type`:"boolean"}, `why`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject55 {}

@js(#{ `additionalProperties`:false, `properties`:#{`expires`:#{`type`:"number"},`expired`:#{`type`:"boolean"}}, `$types`:#["object","null"] }) @hoisted model NullableObject56 {}

@hoisted union BooleanOrNumeric {boolean, numeric}

@js(#{ `additionalProperties`:false, `properties`:#{ `status`:#{`type`:"string"}, `compliance`:#{`type`:"string"}, `level`:#{`type`:"string"}, `previous`:#{`type`:#["string","null"]}, `at`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `source`:#{`type`:"string"}, `actor`:#{`type`:"string"}, `reason`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject57 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `generation`:#{`type`:"number"}, `issuedAt`:#{`type`:"string"}, `browser`:#{`type`:"string"}, `secondFactorAt`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject58 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `change`:#{`type`:"string"}, `expiresAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] } }, `$types`:#["object","null"] }) @hoisted model NullableObject59 {}

@hoisted union StringOrDnStringNameStringKindStringPresentBooleanSubString { string, { `dn`?: string; `name`?: string; `kind`?: string; `present`?: boolean; `sub`?: string } }

@hoisted union BooleanOrNumericOrStringEtc {boolean, numeric, string, (string)[], null}

@js(#{ `additionalProperties`:false, `properties`:#{ `ok`:#{`type`:"boolean"}, `lastAttemptAt`:#{`type`:"string"}, `lastSuccessAt`:#{`type`:"string"}, `failingSince`:#{`type`:"string"}, `failures`:#{`type`:"number"}, `why`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject60 {}

@hoisted union IntegerOrBoolean {integer, boolean}

@js(#{ `additionalProperties`:false, `properties`:#{ `page`:#{`type`:"string"}, `groups`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `group`:#{`type`:"string"}, `settings`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `key`:#{`type`:"string"}, `group`:#{`type`:"string"}, `label`:#{`type`:"string"}, `description`:#{`type`:"string"}, `type`:#{`type`:"string"}, `enumValues`:#{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] } }, `csvValues`:#{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] } }, `ordered`:#{`type`:"boolean"}, `csvValueNotes`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}}, `selectAll`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `onlyWhileOn`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } }, `aloneWhileOn`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } } } }, `min`:#{`type`:"number"}, `max`:#{`type`:"number"}, `step`:#{`type`:"number"}, `value`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] } } ] }, `text`:#{`type`:#["string","null"]}, `source`:#{`type`:"string"}, `editable`:#{`type`:"boolean"}, `restartReason`:#{`type`:"string"}, `editRefusal`:#{`type`:"string"}, `env`:#{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] }, `legacyEnv`:#{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] }, `appconfigPath`:#{`type`:"string"}, `default`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] } } ] }, `masked`:#{`type`:"boolean"}, `realmSettable`:#{`type`:"boolean"}, `overridden`:#{`type`:"boolean"} } } } } } }, `settingCount`:#{`type`:"integer"}, `editableCount`:#{`type`:"integer"}, `overridden`:#{`type`:"array",`items`:#{`type`:"string"}}, `setWith`:#{`type`:"string"}, `context`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `configFile`:#{`type`:#["string","null"]}, `defaultsFile`:#{`type`:#["string","null"]}, `persistsAppconfig`:#{`type`:"boolean"}, `persistsRealms`:#{`type`:"boolean"}, `persistenceMode`:#{`type`:"string"}, `inRealm`:#{`type`:"boolean"}, `realmId`:#{`type`:"string"} } }, `sharedWith`:#{ `type`:"object", `additionalProperties`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`path`:#{`type`:"string"},`label`:#{`type`:"string"}} } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject61 {}

@hoisted union StringOrNullOrIdStringLabelStringNoteStringDocsStringRealmOnBoolean { string, null, { `id`?: string; `label`?: string; `note`?: string; `docs`?: string; `realmOn`?: boolean } }

@hoisted union BooleanOrString {boolean, string}

@js(#{ `additionalProperties`:false, `properties`:#{ `relationship`:#{`type`:"string"}, `name`:#{`type`:"string"}, `kind`:#{`type`:"string"}, `enabled`:#{`type`:"boolean"}, `signalsEnabled`:#{`type`:"boolean"}, `receiving`:#{`type`:"boolean"}, `issuer`:#{`type`:"string"}, `delivery`:#{`type`:"string"}, `eventsRequested`:#{`type`:"array",`items`:#{`type`:"string"}}, `credential`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `method`:#{`type`:"string"}, `tokenEndpoint`:#{`type`:"string"}, `clientId`:#{`type`:"string"}, `scope`:#{`type`:"string"}, `secretHeld`:#{`type`:"boolean"} } }, `ready`:#{`type`:"boolean"}, `missing`:#{`type`:"array",`items`:#{`type`:"string"}}, `config`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `issuer`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `jwks_uri`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `configuration_endpoint`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `status_endpoint`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `add_subject_endpoint`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `remove_subject_endpoint`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `verification_endpoint`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `delivery_methods_supported`:#{ `type`:"array", `items`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." } } } }, `discoveryUrl`:#{`type`:"string"}, `discoveredAt`:#{`type`:"string"}, `streamId`:#{`type`:"string"}, `stream`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `stream_id`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `aud`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `events_supported`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `events_requested`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `events_delivered`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `delivery`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `method`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." }, `endpoint_url`:#{ `x-free-form`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure.", `description`:"A value of a document a partner published or answered, kept and relayed as it arrived: nothing here narrows it, and a partner's odd value must not turn an operator's own page into a failure." } } } } }, `streamDelivery`:#{`type`:"string"}, `streamAud`:#{`type`:"array",`items`:#{`type`:"string"}}, `pollEndpoint`:#{`type`:"string"}, `pushEndpoint`:#{`type`:"string"}, `pushEndpointSet`:#{`type`:"boolean"}, `state`:#{`type`:"string"}, `streamStatus`:#{`type`:"string"}, `verifiedAt`:#{`type`:"string"}, `lastPollAt`:#{`type`:"string"}, `lastPollResult`:#{`type`:"string"}, `lastError`:#{`type`:"string"}, `counts`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `received`:#{`type`:"integer"}, `verified`:#{`type`:"integer"}, `refused`:#{`type`:"integer"}, `acted`:#{`type`:"integer"} } }, `blocks`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `relationship`:#{`type`:"string"}, `username`:#{`type`:"string"}, `at`:#{`type`:"string"}, `event`:#{`type`:"string"}, `jti`:#{`type`:"string"}, `by`:#{`type`:"string"} } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject62 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `application`:#{`type`:"string"}, `streams`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `streamId`:#{`type`:"string"}, `delivery`:#{`type`:"string"}, `status`:#{`type`:"string"}, `eventsDelivered`:#{`type`:"array",`items`:#{`type`:"string"}}, `createdBy`:#{`type`:"string"}, `lastActivityAt`:#{`type`:"string"}, `dead`:#{`type`:"boolean"}, `deadLetters`:#{`type`:"integer"} } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject63 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `policy`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `family`:#{`type`:"string"}, `keyType`:#{`type`:"string"}, `management`:#{`type`:"string"}, `content`:#{`type`:"string"} } }, `required`:#{`type`:"boolean"}, `allowUnencrypted`:#{`type`:"boolean"}, `graceS`:#{`type`:"number"}, `current`:#{`type`:"string"}, `certificatePem`:#{`type`:"string"}, `jwk`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `kty`:#{`type`:"string"}, `use`:#{`type`:"string"}, `alg`:#{`type`:"string"}, `kid`:#{`type`:"string"}, `key_ops`:#{`type`:"array",`items`:#{`type`:"string"}}, `ext`:#{`type`:"boolean"}, `crv`:#{`type`:"string"}, `x`:#{`type`:"string"}, `y`:#{`type`:"string"}, `n`:#{`type`:"string"}, `e`:#{`type`:"string"}, `pub`:#{`type`:"string"}, `ek`:#{`type`:"string"}, `x5c`:#{`type`:"array",`items`:#{`type`:"string"}}, `x5t`:#{`type`:"string"}, `x5t#S256`:#{`type`:"string"}, `x5u`:#{`type`:"string"} } }, `keys`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kid`:#{`type`:"string"}, `keyType`:#{`type`:"string"}, `state`:#{`type`:"string"}, `notAfter`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `createdAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `retiresAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `decrypts`:#{`type`:"boolean"}, `sealed`:#{`type`:"boolean"} } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject64 {}

@js(#{ `x-free-form`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines.", `description`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines." }) @hoisted model Shape4 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","null"]}) @hoisted model NullableArray {}

@hoisted union StringOrKindStringLabelStringWhatString {string, {`kind`?: string; `label`?: string; `what`?: string}}

@js(#{ `additionalProperties`:false, `properties`:#{ `page`:#{`type`:"string"}, `groups`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `group`:#{`type`:"string"}, `settings`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `key`:#{`type`:"string"}, `group`:#{`type`:"string"}, `label`:#{`type`:"string"}, `description`:#{`type`:"string"}, `type`:#{`type`:"string"}, `enumValues`:#{`type`:"array",`items`:#{`type`:"string"}}, `csvValues`:#{`type`:"array",`items`:#{`type`:"string"}}, `ordered`:#{`type`:"boolean"}, `csvValueNotes`:#{ `type`:"object", `additionalProperties`:#{`type`:"string"}, `description`:"The sentence beside each of a list's values." }, `selectAll`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `onlyWhileOn`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } }, `aloneWhileOn`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } } } }, `min`:#{`type`:"number"}, `max`:#{`type`:"number"}, `step`:#{`type`:"number"}, `value`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{`type`:"array",`items`:#{`type`:"string"}} ] }, `text`:#{`type`:"string"}, `source`:#{`type`:"string"}, `editable`:#{`type`:"boolean"}, `restartReason`:#{`type`:"string"}, `editRefusal`:#{`type`:"string"}, `env`:#{`type`:#["string","null"]}, `legacyEnv`:#{`type`:#["string","null"]}, `appconfigPath`:#{`type`:"string"}, `default`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{`type`:"array",`items`:#{`type`:"string"}} ] }, `masked`:#{`type`:"boolean"}, `realmSettable`:#{`type`:"boolean"}, `overridden`:#{`type`:"boolean"} } } } } } }, `settingCount`:#{`type`:"integer"}, `editableCount`:#{`type`:"integer"}, `overridden`:#{`type`:"array",`items`:#{`type`:"string"}}, `setWith`:#{`type`:"string"}, `context`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `configFile`:#{`type`:#["string","null"]}, `defaultsFile`:#{`type`:#["string","null"]}, `persistsAppconfig`:#{`type`:"boolean"}, `persistsRealms`:#{`type`:"boolean"}, `persistenceMode`:#{`type`:"string"}, `inRealm`:#{`type`:"boolean"}, `realmId`:#{`type`:"string"} } }, `sharedWith`:#{ `type`:"object", `additionalProperties`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`path`:#{`type`:"string"},`label`:#{`type`:"string"}} } }, `description`:"The other pages each settings group is drawn on." } }, `$types`:#["object","null"] }) @hoisted model NullableObject65 {}

@hoisted union StringOrIdStringLabelStringKindStringKindsStringIdentifierAttributeStringRedirectAttributeStringLogoutAttributeStringDeliveryAttributeStringEventsAttributeStringSecretAttributeStringWhatString { string, { `id`?: string; `label`?: string; `kind`?: string; `kinds`?: (string)[]; `identifierAttribute`?: string; `redirectAttribute`?: string; `logoutAttribute`?: string; `deliveryAttribute`?: string; `eventsAttribute`?: string; `secretAttribute`?: string; `what`?: string } }

@hoisted union StringOrBoolean {string, boolean}

@hoisted union StringOrNumericOrBooleanEtc2 {string, numeric, boolean, null, (string)[]}

@js(#{ `additionalProperties`:false, `properties`:#{ `signed`:#{`type`:"boolean"}, `outcome`:#{`type`:"string"}, `binding`:#{`type`:"string"}, `signatureMethod`:#{`type`:"string"}, `weak`:#{`type`:"boolean"} }, `$types`:#["object","null"] }) @hoisted model NullableObject66 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `subject`:#{`type`:"string"}, `sha256`:#{`type`:"string"}, `unreadable`:#{`type`:"boolean"} }, `$types`:#["object","null"] }) @hoisted model NullableObject67 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `known`:#{`type`:"boolean"}, `enforced`:#{`type`:"boolean"}, `reference`:#{`type`:#["string","null"]}, `policy`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `name`:#{`type`:"string"}, `policyId`:#{`type`:#["string","null"]}, `version`:#{`type`:#["string","null"]}, `enabled`:#{`type`:"boolean"}, `application`:#{`type`:#["string","null"]}, `orphanedAt`:#{`type`:#["string","null"]}, `own`:#{`type`:"boolean"}, `editor`:#{`type`:"string"} } }, `usable`:#{`type`:"boolean"}, `failure`:#{`type`:"string"}, `why`:#{`type`:"string"}, `types`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `type`:#{`type`:"string"}, `covered`:#{`type`:"boolean"}, `uncovered`:#{`type`:"array",`items`:#{`type`:"string"}}, `rows`:#{`type`:"integer"}, `notForPolicy`:#{`type`:"array",`items`:#{`type`:"string"}} } } }, `unreadable`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`stored`:#{`type`:"string"},`problem`:#{`type`:"string"}} } }, `template`:#{`type`:"string"}, `peps`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `group`:#{`type`:"string"}, `authzenGroup`:#{`type`:"string"}, `total`:#{`type`:"integer"}, `truncated`:#{`type`:"boolean"}, `unlocated`:#{`type`:"integer"}, `holders`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `name`:#{`type`:"string"}, `kind`:#{`type`:"string"}, `dn`:#{`type`:"string"}, `member`:#{`type`:"boolean"}, `scoped`:#{`type`:"boolean"}, `scope`:#{`type`:"boolean"}, `why`:#{`type`:"string"} } } } } }, `applicationPolicies`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`count`:#{`type`:"integer"},`max`:#{`type`:"number"}} }, `choices`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `categories`:#{`type`:"array",`items`:#{`type`:"string"}}, `dataTypes`:#{`type`:"array",`items`:#{`type`:"string"}}, `multiplicities`:#{`type`:"array",`items`:#{`type`:"string"}} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject68 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `subject`:#{`type`:"string"}, `issuer`:#{`type`:"string"}, `serialHex`:#{`type`:"string"}, `notBefore`:#{`type`:"string"}, `notAfter`:#{`type`:"string"}, `expired`:#{`type`:"boolean"}, `selfSigned`:#{`type`:"boolean"}, `keyType`:#{`type`:#["string","null"]}, `thumbprint`:#{`type`:"string"}, `unreadable`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject69 {}

@hoisted union StringOrNumericOrNull {string, numeric, null}

@js(#{ `additionalProperties`:false, `properties`:#{ `readable`:#{`type`:"boolean"}, `why`:#{`type`:"string"}, `verifies`:#{`type`:"boolean"}, `typed`:#{`type`:"boolean"}, `issuer`:#{`type`:"string"}, `issuedAt`:#{`type`:"number"}, `expiresAt`:#{`type`:"number"}, `metadata`:#{ `x-free-form`:"RFC 7591 client metadata fixed by a software statement: any member a publisher chose, including extensions no specification defines.", `description`:"RFC 7591 client metadata fixed by a software statement: any member a publisher chose, including extensions no specification defines." }, `thumbprint`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject70 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `issuer`:#{`type`:"string"}, `trusted`:#{`type`:"boolean"}, `publisher`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject71 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `readable`:#{`type`:"boolean"}, `why`:#{`type`:"string"}, `verifies`:#{`type`:"boolean"}, `typed`:#{`type`:"boolean"}, `issuer`:#{`type`:"string"}, `issuedAt`:#{`type`:"number"}, `expiresAt`:#{`type`:"number"}, `metadata`:#{ `x-free-form`:"RFC 7591 client metadata fixed by a software statement: any member a publisher chose, including extensions no specification defines.", `description`:"RFC 7591 client metadata fixed by a software statement: any member a publisher chose, including extensions no specification defines." }, `thumbprint`:#{`type`:"string"}, `statement`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject72 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `attribute`:#{`type`:"string"}, `realm`:#{`type`:"array",`items`:#{`type`:"string"}}, `own`:#{`type`:#["array","null"],`items`:#{`type`:"string"}}, `inherited`:#{`type`:"boolean"}, `effective`:#{`type`:"array",`items`:#{`type`:"string"}}, `claims`:#{ `type`:"object", `additionalProperties`:#{ `anyOf`:#[ #{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"boolean"}]} } ] }, #{ `type`:"object", `additionalProperties`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"boolean"}]} } ] }, `description`:"A claim's members, as `address` has." } ] }, `description`:"The claims, by name." }, `report`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `ldap`:#{`type`:"string"}, `claim`:#{`type`:"string"}, `value`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"boolean"}]} } ] }, `source`:#{`type`:"string"}, `ldpTerm`:#{`type`:#["string","null"]} } } }, `ldpOmitted`:#{`type`:"array",`items`:#{`type`:"string"}} }, `$types`:#["object","null"] }) @hoisted model NullableObject73 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `basicAuthentication`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}} }, `certificateAuthentication`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}} }, `serverKeyGeneration`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`on`:#{`type`:"boolean"},`source`:#{`type`:"string"}} } }, `$types`:#["object","null"] }) @hoisted model NullableObject74 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `realm`:#{`type`:"string"}, `frontEnds`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `realm`:#{`type`:"string"}, `via`:#{`type`:"string"}, `path`:#{`type`:"array",`items`:#{`type`:"string"}}, `ok`:#{`type`:"boolean"}, `problems`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `params`:#{ `type`:"object", `additionalProperties`:#{`type`:"string"}, `description`:"What the sentence names." }, `text`:#{`type`:"string"} } } }, `actor`:#{`type`:"string"} } } }, `targets`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `realm`:#{`type`:"string"}, `via`:#{`type`:"string"}, `path`:#{`type`:"array",`items`:#{`type`:"string"}}, `ok`:#{`type`:"boolean"}, `problems`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `params`:#{ `type`:"object", `additionalProperties`:#{`type`:"string"}, `description`:"What the sentence names." }, `text`:#{`type`:"string"} } } }, `target`:#{`type`:"string"}, `classicRefused`:#{`type`:"boolean"}, `classicProblems`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `params`:#{ `type`:"object", `additionalProperties`:#{`type`:"string"}, `description`:"What the sentence names." }, `text`:#{`type`:"string"} } } } } } }, `selfRealms`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `realm`:#{`type`:"string"}, `via`:#{`type`:"string"}, `path`:#{`type`:"array",`items`:#{`type`:"string"}}, `ok`:#{`type`:"boolean"}, `problems`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `params`:#{ `type`:"object", `additionalProperties`:#{`type`:"string"}, `description`:"What the sentence names." }, `text`:#{`type`:"string"} } } }, `accepted`:#{`type`:"boolean"} } } }, `tgtDelegation`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `unconstrained`:#{`type`:"boolean"}, `foreignTgtDelegation`:#{`type`:"string"}, `trusts`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `partner`:#{`type`:"string"}, `allowed`:#{`type`:"boolean"}, `attributes`:#{`type`:"array",`items`:#{`type`:"string"}}, `delivered`:#{`type`:"boolean"} } } } } }, `choices`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `krb5S4uSelfRealm`:#{`type`:"array",`items`:#{`type`:"string"}}, `krb5ForeignTgtDelegation`:#{`type`:"array",`items`:#{`type`:"string"}} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject75 {}

@js(#{ `additionalProperties`:#{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] }, `$types`:#["object","null"] }) @hoisted model NullableObject76 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `page`:#{`type`:"string"}, `groups`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `group`:#{`type`:"string"}, `settings`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `key`:#{`type`:"string"}, `group`:#{`type`:"string"}, `label`:#{`type`:"string"}, `description`:#{`type`:"string"}, `type`:#{`type`:"string"}, `enumValues`:#{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] } }, `csvValues`:#{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] } }, `ordered`:#{`type`:"boolean"}, `csvValueNotes`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}}, `selectAll`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `onlyWhileOn`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } }, `aloneWhileOn`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } } } }, `min`:#{`type`:"number"}, `max`:#{`type`:"number"}, `step`:#{`type`:"number"}, `value`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] } } ] }, `text`:#{`type`:#["string","null"]}, `source`:#{`type`:"string"}, `editable`:#{`type`:"boolean"}, `restartReason`:#{`type`:"string"}, `editRefusal`:#{`type`:"string"}, `env`:#{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] }, `legacyEnv`:#{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] }, `appconfigPath`:#{`type`:"string"}, `default`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] } } ] }, `masked`:#{`type`:"boolean"}, `realmSettable`:#{`type`:"boolean"}, `overridden`:#{`type`:"boolean"} } } } } } }, `settingCount`:#{`type`:"integer"}, `editableCount`:#{`type`:"integer"}, `overridden`:#{`type`:"array",`items`:#{`type`:"string"}}, `setWith`:#{`type`:"string"}, `context`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `configFile`:#{`type`:#["string","null"]}, `defaultsFile`:#{`type`:#["string","null"]}, `persistsAppconfig`:#{`type`:"boolean"}, `persistsRealms`:#{`type`:"boolean"}, `persistenceMode`:#{`type`:"string"}, `inRealm`:#{`type`:"boolean"}, `realmId`:#{`type`:"string"} } }, `sharedWith`:#{ `type`:"object", `additionalProperties`:#{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{ `type`:"object", `additionalProperties`:false, `properties`:#{`path`:#{`type`:"string"},`label`:#{`type`:"string"}} } ] } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject77 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `complete`:#{`type`:"boolean"}, `scanned`:#{`type`:"integer"}, `scanLimit`:#{`type`:"integer"} }, `$types`:#["object","null"] }) @hoisted model NullableObject78 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `host`:#{`type`:#["string","null"]}, `port`:#{`type`:#["string","null"]}, `database`:#{`type`:#["string","null"]}, `user`:#{`type`:#["string","null"]}, `passwordFrom`:#{`type`:"string"}, `passwordProvider`:#{`type`:"string"}, `passwordSecret`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `secret`:#{`type`:"string"}, `configured`:#{`type`:"boolean"}, `provider`:#{`type`:"string"}, `label`:#{`type`:"string"}, `known`:#{`type`:"boolean"}, `where`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `from`:#{`type`:"string"}, `shared`:#{`type`:"boolean"}, `region`:#{`type`:"string"}, `vault`:#{`type`:"string"}, `endpoint`:#{`type`:"string"}, `field`:#{`type`:"string"}, `wraps`:#{`type`:"string"}, `authenticates`:#{`type`:"string"} } }, `shared`:#{`type`:"boolean"}, `field`:#{`type`:"string"}, `providers`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`id`:#{`type`:"string"},`label`:#{`type`:"string"}} } } } }, `sslmode`:#{`type`:"string"}, `encrypted`:#{`type`:"boolean"}, `verifyCertificate`:#{`type`:"boolean"}, `caFile`:#{`type`:#["string","null"]}, `tls`:#{`type`:"string"}, `note`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject79 {}

@hoisted union NumericOrStringOrNull {numeric, string, null}

@js(#{ `additionalProperties`:false, `properties`:#{ `at`:#{`type`:"string"}, `error`:#{`type`:#["string","null"]}, `trimmed`:#{`type`:"number"}, `bound`:#{`type`:#["number","null"]}, `readers`:#{`type`:"number"}, `readersGone`:#{`type`:"number"} }, `$types`:#["object","null"] }) @hoisted model NullableObject80 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `cell`:#{`type`:#["string","null"]}, `jurisdiction`:#{`type`:#["string","null"]}, `globalReplication`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `coordinating`:#{`type`:"boolean"}, `supported`:#{`type`:"boolean"}, `startedAt`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `appliedSeq`:#{`type`:"number"}, `highestSeq`:#{`type`:"number"}, `holes`:#{`type`:"number"}, `holeRanges`:#{`type`:"number"}, `holesAbandoned`:#{`type`:"number"}, `pollIntervalMs`:#{`type`:"number"}, `pulls`:#{`type`:"number"}, `nudges`:#{`type`:"number"}, `failures`:#{`type`:"number"}, `rowsApplied`:#{`type`:"number"}, `byKind`:#{ `type`:"object", `additionalProperties`:#{`type`:"number"}, `description`:"A count per name." }, `lastPullAt`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `lastError`:#{`type`:#["string","null"]}, `otherProcesses`:#{`type`:"number"}, `originsDropped`:#{`type`:"number"}, `retention`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `retentionS`:#{`type`:"number"}, `readerTtlS`:#{`type`:"number"}, `reportedAt`:#{`type`:#["string","null"]}, `reportError`:#{`type`:#["string","null"]}, `declaredGoneAt`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `fanInGraceS`:#{`type`:"number"}, `trimming`:#{`type`:"boolean"}, `lastTrim`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `at`:#{`type`:"string"}, `error`:#{`type`:#["string","null"]}, `trimmed`:#{`type`:"number"}, `bound`:#{`type`:#["number","null"]}, `readers`:#{`type`:"number"}, `readersGone`:#{`type`:"number"} } } } }, `note`:#{`type`:"string"} } }, `routing`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `indexed`:#{`type`:"number"}, `conflicts`:#{`type`:"number"}, `lastConflict`:#{`type`:#["string","null"]}, `projectionWrites`:#{`type`:"number"} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject81 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `origin`:#{`type`:#["string","null"]}, `adopted`:#{`type`:"boolean"}, `why`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject82 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `open`:#{`type`:"boolean"}, `queries`:#{`type`:"number"}, `connects`:#{`type`:"number"}, `drops`:#{`type`:"number"}, `viaPool`:#{`type`:"number"} }, `$types`:#["object","null"] }) @hoisted model NullableObject83 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `lastReport`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `maxMs`:#{`type`:"number"}, `p99Ms`:#{`type`:"number"}, `meanMs`:#{`type`:"number"}, `at`:#{`type`:"string"} } }, `sinceReport`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `maxMs`:#{`type`:"number"}, `p99Ms`:#{`type`:"number"}, `meanMs`:#{`type`:"number"}, `at`:#{`type`:"string"} } }, `warnAboveMs`:#{`type`:"number"} }, `$types`:#["object","null"] }) @hoisted model NullableObject84 {}

@js(#{ `description`:"The CONFIG_FILE this process was started with, which is the file to edit to make a change survive a restart. Nothing here ever writes to it.", `$types`:#["string","null"] }) @hoisted model NullableString2 {}

@js(#{`description`:"One group, and the page or pages that draw it."}) @hoisted model WithGroupPagesDescriptionEtc { `group`?: string; `pages`?: (string)[]; @js(#{`description`:"The pages' console labels, in the same order."}) `labels`?: (string)[] }

@js(#{`description`:"One link the page offers."}) @hoisted model WithHrefWhat {`href`?: string; `what`?: string}

@js(#{ `additionalProperties`:false, `properties`:#{ `host`:#{`type`:#["string","null"]}, `port`:#{`type`:#["string","null"]}, `database`:#{`type`:#["string","null"]}, `user`:#{`type`:#["string","null"]}, `passwordFrom`:#{`type`:"string"}, `passwordProvider`:#{`type`:"string"}, `passwordSecret`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `secret`:#{`type`:"string"}, `configured`:#{`type`:"boolean"}, `provider`:#{`type`:"string"}, `label`:#{`type`:"string"}, `known`:#{`type`:"boolean"}, `where`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `from`:#{`type`:"string"}, `shared`:#{`type`:"boolean"}, `region`:#{`type`:"string"}, `vault`:#{`type`:"string"}, `endpoint`:#{`type`:"string"}, `field`:#{`type`:"string"}, `authenticates`:#{`type`:"string"}, `wraps`:#{`type`:"string"} } }, `shared`:#{`type`:"boolean"}, `field`:#{`type`:"string"}, `providers`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`id`:#{`type`:"string"},`label`:#{`type`:"string"}} } } } }, `sslmode`:#{`type`:"string"}, `encrypted`:#{`type`:"boolean"}, `verifyCertificate`:#{`type`:"boolean"}, `caFile`:#{`type`:#["string","null"]}, `tls`:#{`type`:"string"}, `note`:#{`type`:"string"} }, `description`:"Parsed out of the connection string, which is never returned.", `$types`:#["object","null"] }) @hoisted model NullableObject85 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `at`:#{`type`:"string"}, `error`:#{`type`:#["string","null"]}, `readersGone`:#{`type`:"integer"}, `readers`:#{`type`:"integer"}, `bound`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"}]}] }, `trimmed`:#{`type`:"integer"} }, `$types`:#["object","null"] }) @hoisted model NullableObject86 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `cell`:#{`type`:"string"}, `jurisdiction`:#{`type`:#["string","null"]}, `globalReplication`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `coordinating`:#{`type`:"boolean"}, `supported`:#{`type`:"boolean"}, `startedAt`:#{`type`:#["string","null"]}, `appliedSeq`:#{`type`:"number"}, `highestSeq`:#{`type`:"number"}, `holes`:#{`type`:"integer"}, `holeRanges`:#{`type`:"integer"}, `holesAbandoned`:#{`type`:"integer"}, `pollIntervalMs`:#{`type`:"number"}, `pulls`:#{`type`:"integer"}, `nudges`:#{`type`:"integer"}, `failures`:#{`type`:"integer"}, `rowsApplied`:#{`type`:"integer"}, `byKind`:#{ `type`:"object", `additionalProperties`:#{`type`:"integer"}, `description`:"Rows applied, per kind of change." }, `lastPullAt`:#{`type`:#["string","null"]}, `lastError`:#{`type`:#["string","null"]}, `otherProcesses`:#{`type`:"integer"}, `originsDropped`:#{`type`:"integer"}, `retention`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `retentionS`:#{`type`:"integer"}, `readerTtlS`:#{`type`:"integer"}, `reportedAt`:#{`type`:#["string","null"]}, `reportError`:#{`type`:#["string","null"]}, `declaredGoneAt`:#{`type`:#["string","null"]}, `fanInGraceS`:#{`type`:"integer"}, `trimming`:#{`type`:"boolean"}, `lastTrim`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `at`:#{`type`:"string"}, `error`:#{`type`:#["string","null"]}, `readersGone`:#{`type`:"integer"}, `readers`:#{`type`:"integer"}, `bound`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"}]}] }, `trimmed`:#{`type`:"integer"} } } } }, `note`:#{`type`:"string"} } }, `routing`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `indexed`:#{`type`:"integer"}, `conflicts`:#{`type`:"integer"}, `lastConflict`:#{`type`:#["string","null"]}, `projectionWrites`:#{`type`:"integer"} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject87 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `origin`:#{`type`:"string"}, `adopted`:#{`type`:"boolean"}, `why`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject88 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `open`:#{`type`:"boolean"}, `queries`:#{`type`:"integer"}, `connects`:#{`type`:"integer"}, `drops`:#{`type`:"integer"}, `viaPool`:#{`type`:"integer"} }, `$types`:#["object","null"] }) @hoisted model NullableObject89 {}

@hoisted union NumericOrString {numeric, string}

@js(#{ `additionalProperties`:false, `properties`:#{ `at`:#{`type`:"number"}, `pid`:#{`type`:"string"}, `caches`:#{ `type`:"array", `items`:#{ `type`:"array", `items`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"null"}]} }, `description`:"name, size, largest realm, valid, bound, hits, misses, evictions, refusals." } }, `$types`:#["object","null"] }) @hoisted model NullableObject90 {}

@js(#{ `description`:"Whether its settings fingerprint agrees with the node answering; the fingerprint is never returned.", `$types`:#["boolean","null"] }) @hoisted model NullableBoolean2 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `running`:#{`type`:"array",`items`:#{`type`:"string"}}, `restarts`:#{ `type`:"object", `additionalProperties`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`count`:#{`type`:"integer"},`lastEndedAt`:#{`type`:"number"}} }, `description`:"Per running name." }, `leftOrExpired`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `nodeId`:#{`type`:"string"}, `name`:#{`type`:#["string","null"]}, `earlierLives`:#{`type`:"integer"} } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject91 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `askedAt`:#{`type`:"number"}, `cells`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `cell`:#{`type`:"string"}, `jurisdiction`:#{`type`:#["string","null"]}, `reachable`:#{`type`:"boolean"}, `answeredMs`:#{`type`:"number"}, `summary`:#{ `x-free-form`:"Another cell's own cluster summary, relayed: that cell may run another build, so this one does not narrow it.", `description`:"Another cell's own cluster summary, relayed: that cell may run another build, so this one does not narrow it." }, `error`:#{`type`:"string"} } } }, `error`:#{`type`:#["string","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject92 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `configFile`:#{`type`:#["string","null"]}, `defaultsFile`:#{`type`:#["string","null"]}, `persistsAppconfig`:#{`type`:"boolean"}, `persistsRealms`:#{`type`:"boolean"}, `persistenceMode`:#{`type`:"string"}, `inRealm`:#{`type`:"boolean"}, `realmId`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject93 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `configFile`:#{`type`:#["string","null"]}, `defaultsFile`:#{`type`:#["string","null"]}, `persistsAppconfig`:#{`type`:"boolean"}, `persistsRealms`:#{`type`:"boolean"}, `persistenceMode`:#{`type`:"string"}, `inRealm`:#{`type`:"boolean"}, `realmId`:#{`type`:#["string","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject94 {}

@js(#{ `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.", `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path." }) @hoisted model Shape5 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `page`:#{`type`:"string"}, `groups`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `group`:#{`type`:"string"}, `settings`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `key`:#{`type`:"string"}, `group`:#{`type`:"string"}, `label`:#{`type`:"string"}, `description`:#{`type`:"string"}, `type`:#{`type`:"string"}, `enumValues`:#{`type`:"array",`items`:#{`type`:"string"}}, `csvValues`:#{`type`:"array",`items`:#{`type`:"string"}}, `ordered`:#{`type`:"boolean"}, `csvValueNotes`:#{`type`:"object",`additionalProperties`:#{`type`:"string"}}, `selectAll`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `onlyWhileOn`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } }, `aloneWhileOn`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } } } }, `min`:#{`type`:"number"}, `max`:#{`type`:"number"}, `step`:#{`type`:"number"}, `value`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] } } ] }, `text`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] }, `source`:#{`type`:"string"}, `editable`:#{`type`:"boolean"}, `restartReason`:#{`type`:#["string","null"]}, `editRefusal`:#{`type`:#["string","null"]}, `env`:#{ `oneOf`:#[ #{`type`:"null"}, #{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] } ] }, `legacyEnv`:#{ `oneOf`:#[ #{`type`:"null"}, #{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] } ] }, `appconfigPath`:#{`type`:"string"}, `default`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"} ] } } ] }, `masked`:#{`type`:"boolean"}, `realmSettable`:#{`type`:"boolean"}, `overridden`:#{`type`:"boolean"} } } } } } }, `settingCount`:#{`type`:"integer"}, `editableCount`:#{`type`:"integer"}, `overridden`:#{`type`:"array",`items`:#{`type`:"string"}}, `setWith`:#{`type`:"string"}, `context`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `configFile`:#{`type`:#["string","null"]}, `defaultsFile`:#{`type`:#["string","null"]}, `persistsAppconfig`:#{`type`:"boolean"}, `persistsRealms`:#{`type`:"boolean"}, `persistenceMode`:#{`type`:"string"}, `inRealm`:#{`type`:"boolean"}, `realmId`:#{`type`:"string"} } }, `sharedWith`:#{ `type`:"object", `additionalProperties`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`path`:#{`type`:"string"},`label`:#{`type`:#["string","null"]}} } } } }, `$types`:#["object","null"] }) @hoisted model NullableObject95 {}

@js(#{ `description`:"The entry's flag, or null when there is no entry.", `$types`:#["boolean","null"] }) @hoisted model NullableBoolean3 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `name`:#{`type`:"string"}, `enabled`:#{`type`:"boolean"}, `isRoot`:#{`type`:"boolean"}, `policyId`:#{`type`:#["string","null"]}, `kind`:#{`type`:#["string","null"]}, `version`:#{`type`:#["string","null"]}, `combiningAlgId`:#{`type`:#["string","null"]}, `description`:#{`type`:#["string","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject96 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `node`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `id`:#{`type`:"string"}, `description`:#{`type`:#["string","null"]}, `version`:#{`type`:#["string","null"]}, `combiningAlgId`:#{`type`:"string"}, `xpathVersion`:#{`type`:#["string","null"]}, `target`:#{`type`:"null"}, `condition`:#{`type`:"null"}, `maxDelegationDepth`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"null"}]}, `effect`:#{`type`:"string"}, `ref`:#{`type`:"string"}, `matchId`:#{`type`:"string"}, `value`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `type`:#{`type`:"string"}, `lexical`:#{`type`:"string"}, `namespaces`:#{`type`:"object",`additionalProperties`:#{`type`:#["string","null"]}}, `xpathCategory`:#{`type`:#["string","null"]}, `category`:#{`type`:#["string","null"]}, `attributeId`:#{`type`:"string"}, `dataType`:#{`type`:"string"}, `issuer`:#{`type`:#["string","null"]}, `mustBePresent`:#{`type`:"boolean"}, `path`:#{`type`:"string"}, `contextSelectorId`:#{`type`:#["string","null"]}, `functionId`:#{`type`:"string"}, `description`:#{`type`:#["string","null"]}, `variableId`:#{`type`:"string"} } }, `reference`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `kind`:#{`type`:"string"}, `type`:#{`type`:"string"}, `lexical`:#{`type`:"string"}, `namespaces`:#{`type`:"object",`additionalProperties`:#{`type`:#["string","null"]}}, `xpathCategory`:#{`type`:#["string","null"]}, `category`:#{`type`:#["string","null"]}, `attributeId`:#{`type`:"string"}, `dataType`:#{`type`:"string"}, `issuer`:#{`type`:#["string","null"]}, `mustBePresent`:#{`type`:"boolean"}, `path`:#{`type`:"string"}, `contextSelectorId`:#{`type`:#["string","null"]}, `functionId`:#{`type`:"string"}, `description`:#{`type`:#["string","null"]}, `variableId`:#{`type`:"string"} } }, `namespaces`:#{`type`:"object",`additionalProperties`:#{`type`:#["string","null"]}}, `type`:#{`type`:"string"}, `lexical`:#{`type`:"string"}, `xpathCategory`:#{`type`:#["string","null"]}, `category`:#{`type`:#["string","null"]}, `attributeId`:#{`type`:"string"}, `dataType`:#{`type`:"string"}, `issuer`:#{`type`:#["string","null"]}, `mustBePresent`:#{`type`:"boolean"}, `path`:#{`type`:"string"}, `contextSelectorId`:#{`type`:#["string","null"]}, `functionId`:#{`type`:"string"}, `variableId`:#{`type`:"string"}, `on`:#{`type`:"string"}, `name`:#{`type`:"string"} } }, `algorithms`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `uri`:#{`type`:"string"}, `label`:#{`type`:"string"}, `what`:#{`type`:"string"} } } }, `scope`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`id`:#{`type`:"string"},`detail`:#{`type`:"string"}} } }, `valueShortType`:#{`type`:#["string","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject97 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `types`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`value`:#{`type`:"string"},`label`:#{`type`:"string"}} } }, `categories`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`value`:#{`type`:"string"},`label`:#{`type`:"string"}} } }, `functions`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`value`:#{`type`:"string"},`label`:#{`type`:"string"}} } }, `matchFunctions`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`value`:#{`type`:"string"},`label`:#{`type`:"string"}} } }, `xpathType`:#{`type`:"string"}, `resourceCategory`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject98 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `code`:#{`type`:"string"}, `message`:#{`type`:#["string","null"]}, `detail`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `attributeId`:#{`type`:"string"}, `category`:#{`type`:"string"}, `dataType`:#{`type`:"string"}, `problems`:#{`type`:"array",`items`:#{`type`:"string"}}, `errors`:#{`type`:"array",`items`:#{`type`:"string"}}, `type`:#{`type`:"string"}, `lexical`:#{`type`:"string"} } } }, `$types`:#["object","null"] }) @hoisted model NullableObject99 {}

@hoisted union StringOrKindStringIdStringVersionString {string, {`kind`?: string; `id`?: string; `version`?: string}}

@hoisted union StringOrStringOrBooleanEtc {(string)[], string, boolean, null}

@js(#{ `additionalProperties`:false, `properties`:#{ `modes`:#{`type`:"array",`items`:#{`type`:"string"}}, `finish`:#{`type`:#["string","null"]}, `started`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `expiresAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] } }, `$types`:#["object","null"] }) @hoisted model NullableObject100 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `reason`:#{`type`:"string"}, `at`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `note`:#{`type`:#["string","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject101 {}

@js(#{ `x-free-form`:"An RFC 9635 section 8 access right as a resource server registered it: a string reference, or an object whose members are that API's own.", `description`:"An RFC 9635 section 8 access right as a resource server registered it: a string reference, or an object whose members are that API's own." }) @hoisted model Shape6 {}

@hoisted union NumericOrStringOrNullEtc {numeric, string, null, Record<numeric>}

@js(#{ `additionalProperties`:false, `properties`:#{ `subject`:#{`type`:"string"}, `serialHex`:#{`type`:"string"}, `notBefore`:#{`type`:"string"}, `notAfter`:#{`type`:"string"}, `expired`:#{`type`:"boolean"}, `thumbprint`:#{`type`:"string"}, `keyAlg`:#{`type`:"string"}, `signatureAlg`:#{`type`:"string"}, `dnsNames`:#{`type`:"array",`items`:#{`type`:"string"}}, `ipAddresses`:#{`type`:"array",`items`:#{`type`:"string"}}, `issuedAt`:#{`type`:"string"}, `certificatePem`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject102 {}

@hoisted union BooleanOrStringOrNull {boolean, string, null}

@js(#{ `additionalProperties`:false, `properties`:#{ `jti`:#{`type`:"string"}, `iat`:#{`type`:"number"}, `issuer`:#{`type`:"string"}, `audience`:#{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] }, `types`:#{`type`:"array",`items`:#{`type`:"string"}}, `name`:#{`type`:"string"}, `subject`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject103 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `sessionId`:#{`type`:"string"}, `sub`:#{`type`:#["string","null"]}, `username`:#{`type`:#["string","null"]}, `iss`:#{`type`:#["string","null"]}, `protocol`:#{`type`:#["string","null"]}, `establishedAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `updatedAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `state`:#{`type`:#["string","null"]}, `acr`:#{`type`:#["string","null"]}, `amr`:#{`type`:"array",`items`:#{`type`:"string"}}, `assurance`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `namespace`:#{`type`:"string"}, `level`:#{`type`:"string"}, `previousLevel`:#{`type`:"string"} } }, `compliance`:#{`type`:#["string","null"]}, `risk`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `level`:#{`type`:"string"}, `previousLevel`:#{`type`:"string"}, `reason`:#{`type`:"string"} } }, `claims`:#{ `x-free-form`:"The claims a `token-claims-change` event said changed: whichever a person configured or an emitter named.", `description`:"The claims a `token-claims-change` event said changed: whichever a person configured or an emitter named." }, `credentials`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `at`:#{`type`:"string"}, `credentialType`:#{`type`:"string"}, `changeType`:#{`type`:"string"}, `friendlyName`:#{`type`:"string"} } } }, `counts`:#{`type`:"object",`additionalProperties`:#{`type`:"number"}}, `total`:#{`type`:"integer"}, `events`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `jti`:#{`type`:"string"}, `uri`:#{`type`:"string"}, `name`:#{`type`:"string"}, `at`:#{`type`:"string"}, `streamId`:#{`type`:"string"}, `warnings`:#{`type`:"array",`items`:#{`type`:"string"}} } } }, `streams`:#{`type`:"array",`items`:#{`type`:"string"}}, `notes`:#{`type`:"array",`items`:#{`type`:"string"}}, `subject`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject104 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `accountId`:#{`type`:"string"}, `sub`:#{`type`:#["string","null"]}, `username`:#{`type`:#["string","null"]}, `iss`:#{`type`:#["string","null"]}, `dn`:#{`type`:#["string","null"]}, `realm`:#{`type`:#["string","null"]}, `email`:#{`type`:#["string","null"]}, `phone`:#{`type`:#["string","null"]}, `formerIdentifiers`:#{`type`:"array",`items`:#{`type`:"string"}}, `createdAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `updatedAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `lifecycle`:#{`type`:#["string","null"]}, `kind`:#{`type`:"string"}, `application`:#{`type`:"string"}, `serviceAccount`:#{`type`:"boolean"}, `optOut`:#{`type`:#["string","null"]}, `optOutApplies`:#{`type`:"boolean"}, `credentialStanding`:#{`type`:#["string","null"]}, `credentialChangeRequired`:#{`type`:"boolean"}, `recoveryActivated`:#{`type`:"boolean"}, `identifierChanges`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `at`:#{`type`:"string"}, `from`:#{`type`:"string"}, `to`:#{`type`:"string"} } } }, `credentials`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `at`:#{`type`:"string"}, `credentialType`:#{`type`:"string"}, `discoveredAt`:#{`type`:"number"} } } }, `counts`:#{`type`:"object",`additionalProperties`:#{`type`:"number"}}, `total`:#{`type`:"integer"}, `suppressed`:#{`type`:"integer"}, `events`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `jti`:#{`type`:"string"}, `uri`:#{`type`:"string"}, `name`:#{`type`:"string"}, `at`:#{`type`:"string"}, `streamId`:#{`type`:"string"}, `warnings`:#{`type`:"array",`items`:#{`type`:"string"}} } } }, `streams`:#{`type`:"array",`items`:#{`type`:"string"}}, `notes`:#{`type`:"array",`items`:#{`type`:"string"}}, `subject`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject105 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `what`:#{`type`:"string"}, `users`:#{`type`:"string"}, `groups`:#{`type`:"string"}, `baseDn`:#{`type`:"string"}, `userCount`:#{`type`:"number"}, `groupCount`:#{`type`:"number"}, `entryCount`:#{`type`:"number"}, `maxEntries`:#{`type`:"number"} }, `$types`:#["object","null"] }) @hoisted model NullableObject106 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `why`:#{`type`:"string"}, `example`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject107 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `required`:#{`type`:"boolean"}, `discoveryOpen`:#{`type`:"boolean"}, `realm`:#{`type`:"string"}, `scopes`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`read`:#{`type`:"string"},`write`:#{`type`:"string"}} }, `hobaRegistration`:#{`type`:"string"}, `digestAlgorithms`:#{`type`:"array",`items`:#{`type`:"string"}}, `schemes`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `type`:#{`type`:"string"}, `canonical`:#{`type`:"boolean"}, `name`:#{`type`:"string"}, `enabled`:#{`type`:"boolean"}, `refusedByMode`:#{`type`:"string"}, `setting`:#{`type`:"string"}, `primary`:#{`type`:"boolean"}, `scoped`:#{`type`:"boolean"}, `applicationScoped`:#{`type`:"boolean"}, `recorded`:#{`type`:"boolean"}, `challenged`:#{`type`:"boolean"}, `spec`:#{`type`:"string"}, `specUri`:#{`type`:"string"}, `description`:#{`type`:"string"} } } }, `policy`:#{`type`:"array",`items`:#{`type`:"string"}} }, `$types`:#["object","null"] }) @hoisted model NullableObject108 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `page`:#{`type`:"string"}, `groups`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `group`:#{`type`:"string"}, `settings`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `key`:#{`type`:"string"}, `group`:#{`type`:"string"}, `label`:#{`type`:"string"}, `description`:#{`type`:"string"}, `type`:#{`type`:"string"}, `enumValues`:#{`type`:"array",`items`:#{`type`:"string"}}, `csvValues`:#{`type`:"array",`items`:#{`type`:"string"}}, `ordered`:#{`type`:"boolean"}, `csvValueNotes`:#{ `type`:"object", `additionalProperties`:#{`type`:"string"}, `description`:"The sentence beside each value." }, `selectAll`:#{ `type`:"object", `additionalProperties`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } }, `description`:"The rules by kind: onlyWhileOn and aloneWhileOn." }, `min`:#{`type`:"number"}, `max`:#{`type`:"number"}, `step`:#{`type`:"number"}, `value`:#{ `anyOf`:#[ #{`type`:"boolean"}, #{`type`:"number"}, #{`type`:"string"}, #{`type`:"array",`items`:#{`type`:"string"}}, #{`type`:"null"} ] }, `text`:#{`type`:#["string","null"]}, `source`:#{`type`:"string"}, `editable`:#{`type`:"boolean"}, `restartReason`:#{`type`:"string"}, `editRefusal`:#{`type`:"string"}, `env`:#{`type`:#["string","null"]}, `legacyEnv`:#{`type`:#["string","null"]}, `appconfigPath`:#{`type`:"string"}, `default`:#{ `anyOf`:#[ #{`type`:"boolean"}, #{`type`:"number"}, #{`type`:"string"}, #{`type`:"array",`items`:#{`type`:"string"}}, #{`type`:"null"} ] }, `masked`:#{`type`:"boolean"}, `realmSettable`:#{`type`:"boolean"}, `overridden`:#{`type`:"boolean"} } } } } } }, `settingCount`:#{`type`:"integer"}, `editableCount`:#{`type`:"integer"}, `overridden`:#{`type`:"array",`items`:#{`type`:"string"}}, `setWith`:#{`type`:"string"}, `context`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `configFile`:#{`type`:#["string","null"]}, `defaultsFile`:#{`type`:#["string","null"]}, `persistsAppconfig`:#{`type`:"boolean"}, `persistsRealms`:#{`type`:"boolean"}, `persistenceMode`:#{`type`:"string"}, `inRealm`:#{`type`:"boolean"}, `realmId`:#{`type`:#["string","null"]} } }, `sharedWith`:#{ `type`:"object", `additionalProperties`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`path`:#{`type`:"string"},`label`:#{`type`:"string"}} } }, `description`:"The other pages, by settings group." } }, `$types`:#["object","null"] }) @hoisted model NullableObject109 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `family`:#{`type`:"string"}, `clients`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `identifier`:#{`type`:"string"}, `dn`:#{`type`:"string"}, `name`:#{`type`:"string"}, `baseUrl`:#{`type`:"string"}, `authMethod`:#{`type`:"string"}, `username`:#{`type`:"string"}, `tokenEndpoint`:#{`type`:"string"}, `oauthClientId`:#{`type`:"string"}, `oauthClientAuth`:#{`type`:"string"}, `oauthScope`:#{`type`:"string"}, `oauthResource`:#{`type`:"string"}, `tlsSource`:#{`type`:"string"}, `tlsCertificate`:#{`type`:"string"}, `caCertificates`:#{`type`:"string"}, `scopeMode`:#{`type`:"string"}, `scopeFilter`:#{`type`:"string"}, `groupMode`:#{`type`:"string"}, `deprovision`:#{`type`:"string"}, `reconcileMinutes`:#{`type`:"string"}, `jurisdiction`:#{`type`:"string"}, `maxRequestsPerSecond`:#{`type`:"string"}, `scopeGroups`:#{`type`:"array",`items`:#{`type`:"string"}}, `groups`:#{`type`:"array",`items`:#{`type`:"string"}}, `cells`:#{`type`:"array",`items`:#{`type`:"string"}}, `enabled`:#{`type`:"boolean"}, `passwordSet`:#{`type`:"boolean"}, `oauthClientSecretSet`:#{`type`:"boolean"}, `tlsPrivateKeySet`:#{`type`:"boolean"}, `certificate`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `subject`:#{`type`:"string"}, `issuer`:#{`type`:"string"}, `notAfter`:#{`type`:#["string","null"]}, `serial`:#{`type`:#["string","null"]}, `error`:#{`type`:"string"} } }, `problems`:#{`type`:"array",`items`:#{`type`:"string"}}, `usable`:#{`type`:"boolean"}, `counts`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `queued`:#{`type`:"number"}, `retrying`:#{`type`:"number"}, `dead`:#{`type`:"number"}, `sent`:#{`type`:"number"} } }, `pausedUntil`:#{`type`:"string"}, `failures`:#{`type`:"number"}, `lastReconcileAt`:#{`type`:"string"}, `lastReconcile`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `ok`:#{`type`:"boolean"}, `users`:#{`type`:"number"}, `groups`:#{`type`:"number"}, `deprovisioned`:#{`type`:"number"}, `why`:#{`type`:"string"}, `notPushedHere`:#{`type`:"boolean"} } }, `byCell`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `cell`:#{`type`:"string"}, `here`:#{`type`:"boolean"}, `reachable`:#{`type`:"boolean"}, `error`:#{`type`:"string"}, `withheld`:#{`type`:"string"}, `identifier`:#{`type`:"string"}, `pushes`:#{`type`:"boolean"}, `counts`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `queued`:#{`type`:"number"}, `retrying`:#{`type`:"number"}, `dead`:#{`type`:"number"}, `sent`:#{`type`:"number"} } }, `pausedUntil`:#{`type`:"string"}, `failures`:#{`type`:"number"}, `lastReconcileAt`:#{`type`:"string"}, `queued`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `realm`:#{`type`:#["string","null"]}, `clientId`:#{`type`:"string"}, `uri`:#{`type`:#["string","null"]}, `state`:#{`type`:"string"}, `generation`:#{`type`:#["number","null"]}, `attempts`:#{`type`:#["number","null"]}, `inFlight`:#{`type`:"boolean"}, `holder`:#{`type`:"string"}, `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `errorCode`:#{`type`:#["string","null"]}, `why`:#{`type`:#["string","null"]}, `queuedAt`:#{`type`:"string"}, `nextAttemptAt`:#{`type`:"string"}, `lastAttemptAt`:#{`type`:"string"}, `finishedAt`:#{`type`:"string"}, `client`:#{`type`:"string"}, `type`:#{`type`:"string"}, `uuid`:#{`type`:"string"}, `name`:#{`type`:"string"}, `pendingChange`:#{`type`:"boolean"} } } }, `retrying`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `realm`:#{`type`:#["string","null"]}, `clientId`:#{`type`:"string"}, `uri`:#{`type`:#["string","null"]}, `state`:#{`type`:"string"}, `generation`:#{`type`:#["number","null"]}, `attempts`:#{`type`:#["number","null"]}, `inFlight`:#{`type`:"boolean"}, `holder`:#{`type`:"string"}, `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `errorCode`:#{`type`:#["string","null"]}, `why`:#{`type`:#["string","null"]}, `queuedAt`:#{`type`:"string"}, `nextAttemptAt`:#{`type`:"string"}, `lastAttemptAt`:#{`type`:"string"}, `finishedAt`:#{`type`:"string"}, `client`:#{`type`:"string"}, `type`:#{`type`:"string"}, `uuid`:#{`type`:"string"}, `name`:#{`type`:"string"}, `pendingChange`:#{`type`:"boolean"} } } }, `dead`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `realm`:#{`type`:#["string","null"]}, `clientId`:#{`type`:"string"}, `uri`:#{`type`:#["string","null"]}, `state`:#{`type`:"string"}, `generation`:#{`type`:#["number","null"]}, `attempts`:#{`type`:#["number","null"]}, `inFlight`:#{`type`:"boolean"}, `holder`:#{`type`:"string"}, `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `errorCode`:#{`type`:#["string","null"]}, `why`:#{`type`:#["string","null"]}, `queuedAt`:#{`type`:"string"}, `nextAttemptAt`:#{`type`:"string"}, `lastAttemptAt`:#{`type`:"string"}, `finishedAt`:#{`type`:"string"}, `client`:#{`type`:"string"}, `type`:#{`type`:"string"}, `uuid`:#{`type`:"string"}, `name`:#{`type`:"string"}, `pendingChange`:#{`type`:"boolean"} } } } } } } } } }, `choices`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `authMethods`:#{`type`:"array",`items`:#{`type`:"string"}}, `oauthClientAuth`:#{`type`:"array",`items`:#{`type`:"string"}}, `tlsSources`:#{`type`:"array",`items`:#{`type`:"string"}}, `scopeModes`:#{`type`:"array",`items`:#{`type`:"string"}}, `groupModes`:#{`type`:"array",`items`:#{`type`:"string"}}, `deprovision`:#{`type`:"array",`items`:#{`type`:"string"}} } }, `httpAllowed`:#{`type`:"boolean"}, `client`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `identifier`:#{`type`:"string"}, `dn`:#{`type`:"string"}, `name`:#{`type`:"string"}, `baseUrl`:#{`type`:"string"}, `authMethod`:#{`type`:"string"}, `username`:#{`type`:"string"}, `tokenEndpoint`:#{`type`:"string"}, `oauthClientId`:#{`type`:"string"}, `oauthClientAuth`:#{`type`:"string"}, `oauthScope`:#{`type`:"string"}, `oauthResource`:#{`type`:"string"}, `tlsSource`:#{`type`:"string"}, `tlsCertificate`:#{`type`:"string"}, `caCertificates`:#{`type`:"string"}, `scopeMode`:#{`type`:"string"}, `scopeFilter`:#{`type`:"string"}, `groupMode`:#{`type`:"string"}, `deprovision`:#{`type`:"string"}, `reconcileMinutes`:#{`type`:"string"}, `jurisdiction`:#{`type`:"string"}, `maxRequestsPerSecond`:#{`type`:"string"}, `scopeGroups`:#{`type`:"array",`items`:#{`type`:"string"}}, `groups`:#{`type`:"array",`items`:#{`type`:"string"}}, `cells`:#{`type`:"array",`items`:#{`type`:"string"}}, `enabled`:#{`type`:"boolean"}, `passwordSet`:#{`type`:"boolean"}, `oauthClientSecretSet`:#{`type`:"boolean"}, `tlsPrivateKeySet`:#{`type`:"boolean"}, `certificate`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `subject`:#{`type`:"string"}, `issuer`:#{`type`:"string"}, `notAfter`:#{`type`:#["string","null"]}, `serial`:#{`type`:#["string","null"]}, `error`:#{`type`:"string"} } }, `problems`:#{`type`:"array",`items`:#{`type`:"string"}}, `usable`:#{`type`:"boolean"}, `counts`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `queued`:#{`type`:"number"}, `retrying`:#{`type`:"number"}, `dead`:#{`type`:"number"}, `sent`:#{`type`:"number"} } }, `pausedUntil`:#{`type`:"string"}, `failures`:#{`type`:"number"}, `lastReconcileAt`:#{`type`:"string"}, `lastReconcile`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `ok`:#{`type`:"boolean"}, `users`:#{`type`:"number"}, `groups`:#{`type`:"number"}, `deprovisioned`:#{`type`:"number"}, `why`:#{`type`:"string"}, `notPushedHere`:#{`type`:"boolean"} } }, `byCell`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `cell`:#{`type`:"string"}, `here`:#{`type`:"boolean"}, `reachable`:#{`type`:"boolean"}, `error`:#{`type`:"string"}, `withheld`:#{`type`:"string"}, `identifier`:#{`type`:"string"}, `pushes`:#{`type`:"boolean"}, `counts`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `queued`:#{`type`:"number"}, `retrying`:#{`type`:"number"}, `dead`:#{`type`:"number"}, `sent`:#{`type`:"number"} } }, `pausedUntil`:#{`type`:"string"}, `failures`:#{`type`:"number"}, `lastReconcileAt`:#{`type`:"string"}, `queued`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `realm`:#{`type`:#["string","null"]}, `clientId`:#{`type`:"string"}, `uri`:#{`type`:#["string","null"]}, `state`:#{`type`:"string"}, `generation`:#{`type`:#["number","null"]}, `attempts`:#{`type`:#["number","null"]}, `inFlight`:#{`type`:"boolean"}, `holder`:#{`type`:"string"}, `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `errorCode`:#{`type`:#["string","null"]}, `why`:#{`type`:#["string","null"]}, `queuedAt`:#{`type`:"string"}, `nextAttemptAt`:#{`type`:"string"}, `lastAttemptAt`:#{`type`:"string"}, `finishedAt`:#{`type`:"string"}, `client`:#{`type`:"string"}, `type`:#{`type`:"string"}, `uuid`:#{`type`:"string"}, `name`:#{`type`:"string"}, `pendingChange`:#{`type`:"boolean"} } } }, `retrying`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `realm`:#{`type`:#["string","null"]}, `clientId`:#{`type`:"string"}, `uri`:#{`type`:#["string","null"]}, `state`:#{`type`:"string"}, `generation`:#{`type`:#["number","null"]}, `attempts`:#{`type`:#["number","null"]}, `inFlight`:#{`type`:"boolean"}, `holder`:#{`type`:"string"}, `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `errorCode`:#{`type`:#["string","null"]}, `why`:#{`type`:#["string","null"]}, `queuedAt`:#{`type`:"string"}, `nextAttemptAt`:#{`type`:"string"}, `lastAttemptAt`:#{`type`:"string"}, `finishedAt`:#{`type`:"string"}, `client`:#{`type`:"string"}, `type`:#{`type`:"string"}, `uuid`:#{`type`:"string"}, `name`:#{`type`:"string"}, `pendingChange`:#{`type`:"boolean"} } } }, `dead`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `realm`:#{`type`:#["string","null"]}, `clientId`:#{`type`:"string"}, `uri`:#{`type`:#["string","null"]}, `state`:#{`type`:"string"}, `generation`:#{`type`:#["number","null"]}, `attempts`:#{`type`:#["number","null"]}, `inFlight`:#{`type`:"boolean"}, `holder`:#{`type`:"string"}, `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `errorCode`:#{`type`:#["string","null"]}, `why`:#{`type`:#["string","null"]}, `queuedAt`:#{`type`:"string"}, `nextAttemptAt`:#{`type`:"string"}, `lastAttemptAt`:#{`type`:"string"}, `finishedAt`:#{`type`:"string"}, `client`:#{`type`:"string"}, `type`:#{`type`:"string"}, `uuid`:#{`type`:"string"}, `name`:#{`type`:"string"}, `pendingChange`:#{`type`:"boolean"} } } } } } }, `queues`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `queued`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `realm`:#{`type`:#["string","null"]}, `clientId`:#{`type`:"string"}, `uri`:#{`type`:#["string","null"]}, `state`:#{`type`:"string"}, `generation`:#{`type`:#["number","null"]}, `attempts`:#{`type`:#["number","null"]}, `inFlight`:#{`type`:"boolean"}, `holder`:#{`type`:"string"}, `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `errorCode`:#{`type`:#["string","null"]}, `why`:#{`type`:#["string","null"]}, `queuedAt`:#{`type`:"string"}, `nextAttemptAt`:#{`type`:"string"}, `lastAttemptAt`:#{`type`:"string"}, `finishedAt`:#{`type`:"string"}, `client`:#{`type`:"string"}, `type`:#{`type`:"string"}, `uuid`:#{`type`:"string"}, `name`:#{`type`:"string"}, `pendingChange`:#{`type`:"boolean"} } } }, `retrying`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `realm`:#{`type`:#["string","null"]}, `clientId`:#{`type`:"string"}, `uri`:#{`type`:#["string","null"]}, `state`:#{`type`:"string"}, `generation`:#{`type`:#["number","null"]}, `attempts`:#{`type`:#["number","null"]}, `inFlight`:#{`type`:"boolean"}, `holder`:#{`type`:"string"}, `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `errorCode`:#{`type`:#["string","null"]}, `why`:#{`type`:#["string","null"]}, `queuedAt`:#{`type`:"string"}, `nextAttemptAt`:#{`type`:"string"}, `lastAttemptAt`:#{`type`:"string"}, `finishedAt`:#{`type`:"string"}, `client`:#{`type`:"string"}, `type`:#{`type`:"string"}, `uuid`:#{`type`:"string"}, `name`:#{`type`:"string"}, `pendingChange`:#{`type`:"boolean"} } } }, `dead`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `realm`:#{`type`:#["string","null"]}, `clientId`:#{`type`:"string"}, `uri`:#{`type`:#["string","null"]}, `state`:#{`type`:"string"}, `generation`:#{`type`:#["number","null"]}, `attempts`:#{`type`:#["number","null"]}, `inFlight`:#{`type`:"boolean"}, `holder`:#{`type`:"string"}, `status`:#{`anyOf`:#[#{`type`:"number"},#{`type`:"string"},#{`type`:"null"}]}, `errorCode`:#{`type`:#["string","null"]}, `why`:#{`type`:#["string","null"]}, `queuedAt`:#{`type`:"string"}, `nextAttemptAt`:#{`type`:"string"}, `lastAttemptAt`:#{`type`:"string"}, `finishedAt`:#{`type`:"string"}, `client`:#{`type`:"string"}, `type`:#{`type`:"string"}, `uuid`:#{`type`:"string"}, `name`:#{`type`:"string"}, `pendingChange`:#{`type`:"boolean"} } } }, `counts`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `queued`:#{`type`:"number"}, `retrying`:#{`type`:"number"}, `dead`:#{`type`:"number"}, `sent`:#{`type`:"number"} } } } }, `linked`:#{`type`:"number"}, `discovery`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `ok`:#{`type`:"boolean"}, `patch`:#{`type`:"boolean"}, `filter`:#{`type`:"boolean"}, `etag`:#{`type`:"boolean"}, `endpoints`:#{ `type`:"object", `additionalProperties`:#{`type`:"string"}, `description`:"The path of each resource type, by its name." }, `why`:#{`type`:"string"}, `maxResults`:#{`type`:"number"}, `bulk`:#{`type`:"boolean"}, `authenticationSchemes`:#{`type`:"array",`items`:#{`type`:"string"}}, `at`:#{`type`:"string"} } } } }, `missing`:#{`type`:"string"}, `cellId`:#{`type`:#["string","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject110 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `id`:#{`type`:"string"}, `label`:#{`type`:"string"}, `audience`:#{`type`:"string"}, `receivePath`:#{`type`:"string"}, `inboxPath`:#{`type`:"string"}, `sees`:#{`type`:"string"}, `realm`:#{`type`:"string"}, `enabled`:#{`type`:"boolean"}, `ssfEnabled`:#{`type`:"boolean"}, `internalReceivers`:#{`type`:"boolean"}, `pushDelivery`:#{`type`:"boolean"}, `caepEnabled`:#{`type`:"boolean"}, `riscEnabled`:#{`type`:"boolean"}, `held`:#{`type`:"integer"}, `max`:#{`type`:"number"}, `stream`:#{ `type`:#["object","null"], `additionalProperties`:false, `properties`:#{ `stream_id`:#{`type`:"string"}, `iss`:#{`type`:#["string","null"]}, `aud`:#{ `oneOf`:#[ #{`type`:"null"}, #{ `anyOf`:#[#{`type`:"string"},#{`type`:"array",`items`:#{`type`:"string"}}] } ] }, `status`:#{`type`:"string"}, `statusReason`:#{`type`:#["string","null"]}, `delivery`:#{`type`:"string"}, `endpoint_url`:#{`type`:"string"}, `pollEveryMs`:#{`type`:"number"}, `delivers`:#{`type`:"integer"}, `requested`:#{`type`:"integer"}, `caepDelivered`:#{`type`:"integer"}, `riscDelivered`:#{`type`:"integer"}, `queued`:#{`type`:"integer"}, `counters`:#{`type`:"object",`additionalProperties`:#{`type`:"number"}}, `lastPushAt`:#{ `oneOf`:#[#{`type`:"null"},#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"}]}] }, `lastPushError`:#{`type`:#["string","null"]} } }, `why`:#{`type`:"array",`items`:#{`type`:"string"}} }, `$types`:#["object","null"] }) @hoisted model NullableObject111 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `name`:#{`type`:"string"}, `types`:#{`type`:"array",`items`:#{`type`:"string"}}, `subject`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject112 {}

@hoisted union IntegerOrString {integer, string}

@js(#{`description`:"One configured pair.",`additionalProperties`:true}) @hoisted model WithMechanismDescriptionTypeEtc { `mechanism`?: "classic" | "rbcd"; @js(#{ `description`:"The same mechanism id an ACT carries, so the two halves of this resource can be read against each other without a second lookup table." }) `type`?: string; @js(#{`description`:"Who may act."}) `frontEnd`?: string; @js(#{`description`:"What may be reached."}) `target`?: string; `realm`?: string; @js(#{ `description`:"`msDS-AllowedToDelegateTo` or `msDS-AllowedToActOnBehalfOfOtherIdentity`." }) `attribute`?: string; @js(#{ `description`:"THE ACCOUNT THE PERMISSION LIVES ON, and the field to read first. Classic puts it on the front end, where only a domain admin can set it; resource-based puts it on the back end, where whoever controls that object can set it themselves. That is the entire security story of RBCD." }) `setOn`?: string; `setOnRole`?: "front end" | "back end"; @js(#{`description`:"What ELSE the mechanism needs beyond the attribute."}) `requires`?: string; @js(#{ `description`:"Whether this KDC has a principal by that name. A misspelt SPN fails at TGS time with an error about authorization rather than spelling." }) `targetKnown`?: boolean; @js(#{ `description`:"Why this pair may still fail although the attribute names it. The expensive one: a front end with no TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION gets a non-forwardable ticket out of S4U2Self, so classic S4U2Proxy then fails complaining about the evidence — two steps from the attribute that caused it." }) `warning`?: string; `note`?: string }

@js(#{`description`:"One account.",`additionalProperties`:true}) @hoisted model WithPrincipalRealmNotDelegatedEtc { `principal`?: string; `realm`?: string; `notDelegated`?: boolean; `trustedToAuthenticateForDelegation`?: boolean; @js(#{ `description`:"ADVICE TO THE CLIENT and not a control: it tells a client this service may be trusted with forwarded credentials, a client is free to ignore it, and this KDC enforces nothing by it." }) `okAsDelegate`?: boolean; `autoCreated`?: boolean; `description`?: string; @js(#{`description`:"What each flag actually does."}) `effects`?: (string)[] }

@js(#{ `additionalProperties`:false, `properties`:#{ `page`:#{`type`:"string"}, `groups`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `group`:#{`type`:"string"}, `settings`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `key`:#{ `type`:"string", `description`:"The dot path, which is BOTH the name every operation here takes and the path in the appconfig file. `oid4vci.batchSize` is `appconfig.oid4vci.batchSize`." }, `group`:#{ `type`:"string", `description`:"The protocol it belongs to, and the console's section heading." }, `label`:#{`type`:"string"}, `description`:#{ `type`:"string", `description`:"What it does and why the default is the default." }, `type`:#{ `type`:"string", `description`:"How a value posted for it is coerced and checked: one of `config.js`'s types (string, int, port, bool, csv, enum, color)." }, `enumValues`:#{ `type`:"array", `items`:#{`type`:"string"}, `description`:"Present on `enum` settings only." }, `csvValues`:#{ `type`:"array", `items`:#{`type`:"string"}, `description`:"Present on a `csv` setting whose entries must each be one of these; absent on an open list." }, `masked`:#{ `type`:"boolean", `description`:"Present, true, when a sensitive value here was replaced." }, `ordered`:#{ `type`:"boolean", `description`:"Present, true, on a `csv` setting whose order is a preference: the first value is the most preferred." }, `csvValueNotes`:#{ `type`:"object", `additionalProperties`:#{`type`:"string"}, `description`:"Present beside `csvValues` where the setting describes each value: the value mapped to one sentence." }, `selectAll`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `onlyWhileOn`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } }, `aloneWhileOn`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `setting`:#{`type`:"string"}, `values`:#{`type`:"array",`items`:#{`type`:"string"}}, `on`:#{`type`:"boolean"}, `canBeOn`:#{`type`:"boolean"} } } } }, `description`:"Present on an `ordered` setting whose select-all is narrowed by other settings. `onlyWhileOn`: the values are selected only while that setting is on. `aloneWhileOn`: while that setting is on, only the values are selected. `canBeOn` is false where this mode never lets that setting be on." }, `min`:#{ `type`:"number", `description`:"The lowest value POST /config/set will take, on an int setting that declares one." }, `max`:#{`type`:"number",`description`:"The highest value it will take."}, `step`:#{ `type`:"number", `description`:"The value must be a MULTIPLE of this, counted from `min`. The four token lifetimes use 30." }, `value`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"boolean"}]} } ], `description`:"The effective value, coerced to its type: a number for int/port, a boolean for bool, an array of strings for csv." }, `text`:#{ `type`:"string", `description`:"The same value on one line: what the console shows in its input and what the environment variable would carry." }, `source`:#{ `type`:"string", `enum`:#["realm","override","env","env-legacy","appconfig","defaults","default"], `description`:"Where the effective value came from, highest first: this trust realm's own value; a runtime override set through this API or the console; the setting's own environment variable; a legacy variable (no row has one since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig file that one is unioned on top of. `default` is reachable only for the DERIVED settings, whose value is a function of a neighbouring setting: for every other setting, no value anywhere stops this service from STARTING." }, `editable`:#{ `type`:"boolean", `description`:"Whether POST /config/set will take it from the realm this answer was read in. False means either the value was consumed at startup or `editRefusal` is set. It is refused rather than accepted, because an accepted change that does nothing reads as having worked." }, `restartReason`:#{ `type`:"string", `description`:"Why it is not editable, when the value was consumed at startup." }, `editRefusal`:#{ `type`:"string", `description`:"Why this row cannot be edited from the realm the reader is in: `realms.maxCount` while a realm other than the default is ambient. Absent on every row of the default realm's answer." }, `env`:#{`type`:"string",`description`:"Its environment variable."}, `appconfigPath`:#{`type`:"string"}, `default`:#{ `anyOf`:#[ #{`type`:"string"}, #{`type`:"number"}, #{`type`:"boolean"}, #{`type`:"null"}, #{ `type`:"array", `items`:#{`anyOf`:#[#{`type`:"string"},#{`type`:"number"},#{`type`:"boolean"}]} } ], `description`:"The built-in default: the `dflt` column of `config.js`'s table, which `env/defaults.js` is GENERATED from. It is what the value WOULD be with nothing set anywhere." }, `realmSettable`:#{ `type`:"boolean", `description`:"Whether a trust realm may hold its own value for it." }, `overridden`:#{ `type`:"boolean", `description`:"Whether a runtime override is in force. Equal to `source === \"override\"`, and reported separately so a caller can filter without matching a string." } }, `description`:"One setting: what it is, what it is set to, and where that came from." } } }, `description`:"One group's settings." }, `description`:"In the order `config.js` declares them." }, `settingCount`:#{`type`:"integer"}, `editableCount`:#{ `type`:"integer", `description`:"How many of them can be changed while the service runs." }, `overridden`:#{ `type`:"array", `items`:#{`type`:"string"}, `description`:"The keys on this page with a runtime override in force." }, `setWith`:#{`type`:"string",`description`:"The operation that writes them."}, `context`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{ `configFile`:#{`type`:#["string","null"]}, `defaultsFile`:#{`type`:"string"}, `persistsAppconfig`:#{`type`:"boolean"}, `persistsRealms`:#{`type`:"boolean"}, `persistenceMode`:#{`type`:"string"}, `inRealm`:#{`type`:"boolean"}, `realmId`:#{`type`:"string"} } }, `sharedWith`:#{ `type`:"object", `additionalProperties`:#{ `type`:"array", `items`:#{ `type`:"object", `additionalProperties`:false, `properties`:#{`path`:#{`type`:"string"},`label`:#{`type`:#["string","null"]}} } }, `description`:"A group drawn on another page as well, and those pages." } }, `description`:"The settings this page draws, described: the same rows GET /config returns, filtered to the ones this page owns.", `$types`:#["object","null"] }) @hoisted model NullableObject113 {}

@js(#{ `items`:#{`type`:#["string","number","boolean"]}, `$types`:#["string","number","boolean","array","null"] }) @hoisted model Shape7 {}

@js(#{`$types`:#["string","boolean","number","null"]}) @hoisted model Shape8 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `since`:#{`type`:"number"}, `sinceIso`:#{`type`:"string"}, `inProgress`:#{`type`:"boolean"}, `interrupted`:#{`type`:"boolean"}, `finishesBy`:#{`type`:"number"}, `refusing`:#{`type`:"string"}, `why`:#{`type`:"string"}, `finish`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject114 {}

@js(#{`$types`:#["string","boolean","null"]}) @hoisted model Shape9 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `credentials`:#{`type`:"integer"}, `acts`:#{`type`:"integer"}, `chains`:#{`type`:"integer"}, `authentications`:#{`type`:"integer"}, `applications`:#{`type`:"integer"} }, `$types`:#["object","null"] }) @hoisted model NullableObject115 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `status`:#{`type`:"string"}, `previous`:#{`type`:#["string","null"]}, `at`:#{`type`:"string"}, `source`:#{`type`:"string"}, `actor`:#{`type`:"string"}, `reason`:#{`type`:"string"} }, `$types`:#["object","null"] }) @hoisted model NullableObject116 {}

@js(#{ `description`:"`summaryOf()`: the job's answer as text, 500 characters at most.", `$types`:#["string","null"] }) @hoisted model NullableString3 {}

@js(#{ `additionalProperties`:false, `properties`:#{ `node`:#{`type`:#["string","null"]}, `pid`:#{`type`:#["integer","null"]}, `token`:#{`type`:#["number","null"]} }, `$types`:#["object","null"] }) @hoisted model NullableObject117 {}

@hoisted union BooleanOrString2 {boolean, (string)[]}

@hoisted union StringOrNumericOrString {string, numeric, (string)[]}

@js(#{`$noProps`:true,`$open`:true}) @hoisted model Shape10 {}

@js(#{ `items`:#{`type`:"string"}, `description`:"The fields the console's form drew, by attribute name, space or comma separated or as a list: each one is cleared when the form carries no value for it.", `$types`:#["string","array"] }) @hoisted model Shape11 {}

@js(#{`required`:#["attribute"]}) @hoisted model Shape12 {}

@js(#{`required`:#["name"]}) @hoisted model Shape13 {}

@js(#{`required`:#["claim"]}) @hoisted model Shape14 {}

@js(#{`required`:#["profile"]}) @hoisted model Shape15 {}

@js(#{`required`:#["id"]}) @hoisted model Shape16 {}

@js(#{`$types`:#["integer","string"]}) @hoisted model Shape17 {}

@js(#{`items`:#{`type`:"string"},`$types`:#["array","string"]}) @hoisted model Shape18 {}

@js(#{`$types`:#["object","string"]}) @hoisted model Shape19 {}

@js(#{ `items`:#{`type`:"string"}, `description`:"The DNS suffixes routed to the partner.", `$types`:#["array","string"] }) @hoisted model Shape20 {}

@js(#{ `items`:#{`type`:#["integer","string"]}, `description`:"The enctypes its keys are made for, by number; AES by default.", `$types`:#["array","string"] }) @hoisted model Shape21 {}

@js(#{ `description`:"A cross-forest trust's { domains: [{ sid, dnsName, netbiosName, sidEnabled }], topLevelNames: [{ name, enabled }] }.", `$types`:#["object","string","null"] }) @hoisted model Shape22 {}

@js(#{`minimum`:1,`maximum`:1000}) @hoisted scalar IntegerFrom1To1000 extends integer;

@js(#{`minimum`:1,`maximum`:16}) @hoisted scalar IntegerFrom1To16 extends integer;

@js(#{ `description`:"A password on the sign-in screen. As a SECOND factor it is the password asked for after a wallet or other passwordless first factor. (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default true.", `$comb`:"oneOf" }) @hoisted union BooleanOrString3 {boolean, string}

@js(#{ `description`:"A six-digit code mailed to the person's VERIFIED address. NIST SP 800-63B-4 section 3.1.3.1: \"Email SHALL NOT be used for out-of-band authentication\", because a mailbox may be reached with a password alone, and mail may be read in transit or rerouted. Off by default for that reason; turn it on only where that is an accepted risk. (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default false.", `$comb`:"oneOf" }) @hoisted union BooleanOrString4 {boolean, string}

@js(#{ `description`:"A single-use link mailed to the person's VERIFIED address, which completes the sign-in only in the browser that started it. NIST SP 800-63B-4 section 3.1.3.1: \"Email SHALL NOT be used for out-of-band authentication\", because a mailbox may be reached with a password alone, and mail may be read in transit or rerouted. Off by default for that reason; turn it on only where that is an accepted risk. (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default false.", `$comb`:"oneOf" }) @hoisted union BooleanOrString5 {boolean, string}

@js(#{ `description`:"/authn/wallet with a credential this realm issued, or a SIOPv2 self-issued ID Token from an enrolled key. As a SECOND factor, the wallet presented after a password. (`true`/`false`, or `TRUE`/`FALSE` from a form.) Default true.", `$comb`:"oneOf" }) @hoisted union BooleanOrString6 {boolean, string}

@js(#{`maxLength`:128}) @hoisted scalar StringMax128 extends string;

@js(#{`maxLength`:16384}) @hoisted scalar StringMax16384 extends string;

@js(#{`maxLength`:256}) @hoisted scalar StringMax256 extends string;

@js(#{`maxLength`:8192}) @hoisted scalar StringMax8192 extends string;

@js(#{`$types`:#["string","null"]}) @hoisted scalar String extends string;

@hoisted union EmptyTextOrIntegerFrom1To100000 { EmptyText, IntegerFrom1To100000 }

@hoisted union EmptyTextOrIntegerFrom1To1000002 {EmptyText, IntegerFrom1To100000}

@js(#{`description`:"The page of the list the form was on."}) @hoisted union EmptyTextOrIntegerFrom1To1000003 { EmptyText, IntegerFrom1To100000 }

@js(#{`$comb`:"oneOf"}) @hoisted union NullOrStringOrString {null, StringOrString}

@js(#{`$comb`:"oneOf"}) @hoisted union NullOrStringOrString2 { null, StringOrString }

@hoisted union EmptyTextOrStringMin1Max256 { EmptyText, StringMin1Max256 }

@js(#{`description`:"The username the link names."}) @hoisted union EmptyTextOrStringMin1Max2562 { EmptyText, StringMin1Max256 }

@js(#{`description`:"The link's single-use secret."}) @hoisted union EmptyTextOrStringMin1Max4096Matchingfb79a8 { EmptyText, StringMin1Max4096Matchingfb79a8 }

@js(#{`description`:"One of your own passkeys."}) @hoisted union EmptyTextOrStringMin1Max4096Matchinga5aa8a { EmptyText, StringMin1Max4096Matchinga5aa8a }

@hoisted union EmptyTextOr1 {EmptyText, "1"}

@js(#{ `description`:"Which page of `issued`, newest first. Clamped to the last." }) @hoisted union EmptyTextOrIntegerFrom1To1000004 { EmptyText, IntegerFrom1To100000 }

@hoisted union EmptyTextOr01TrueFalseOnOffYesNo { EmptyText, "0" | "1" | "true" | "false" | "on" | "off" | "yes" | "no" }

@hoisted union EmptyTextOrStringMin1Max4096Matchinga5aa8a2 { EmptyText, StringMin1Max4096Matchinga5aa8a }

@hoisted union EmptyTextOrStringMin1Max4096 { EmptyText, StringMin1Max4096 }

@hoisted union EmptyTextOr12 { EmptyText, "1" }

@hoisted union StringOrNumericOrBooleanEtc3 {string, numeric, boolean, null, (StringOrNumericOrBoolean)[]}

@hoisted union StringOrNumericOrBooleanEtc4 { string, numeric, boolean, null, (StringOrNumericOrBoolean)[] }

@js(#{ `description`:"The effective value, coerced to its type: a number for int/port, a boolean for bool, an array of strings for csv." }) @hoisted union StringOrNumericOrBooleanEtc5 { string, numeric, boolean, null, (StringOrNumericOrBoolean)[] }

@js(#{ `description`:"The built-in default: the `dflt` column of `config.js`'s table, which `env/defaults.js` is GENERATED from. It is what the value WOULD be with nothing set anywhere." }) @hoisted union StringOrNumericOrBooleanEtc6 { string, numeric, boolean, null, (StringOrNumericOrBoolean)[] }

@js(#{`description`:"One key pair."}) @hoisted model WithDescriptionIdLabelEtc { @js(#{`description`:"What POST /admin-api/keys/export takes as `key`."}) `id`?: string; `label`?: string; `alg`?: string; `kty`?: NullableString; `crv`?: string; `bits`?: numeric; @js(#{`description`:"Empty for the TLS key, which has a fingerprint instead."}) `kid`?: string; @js(#{`description`:"`realm` or `process`."}) `scope`?: string; `realm`?: string; @js(#{`description`:"Whether a PKCS#12 is possible."}) `hasCertificate`?: boolean; `generated`?: boolean; `certifiedBy`?: NullableObject37; @js(#{`description`:"Empty means not exportable."}) `formats`?: (string)[]; `usedFor`?: (string)[]; `fingerprint`?: NullableString; `subject`?: NullableString; `names`?: (string)[]; `notAfter`?: NullableString; `pqc`?: NullableObject38 }

@js(#{`$comb`:"oneOf"}) @hoisted union NullOrStringOrNumeric {null, StringOrNumeric}

@hoisted union StringOrNumericOrBooleanEtcOrStringOrNumericOrBooleanEtc { StringOrNumericOrBooleanEtc, (StringOrNumericOrBooleanEtc)[] }

@hoisted union NameStringCoseAlgNullableNumberTextStringPostQuantumBooleanInsecureBooleanLaneStringOrNullOrString { { `name`?: string; `coseAlg`?: NullableNumber; `text`?: string; `postQuantum`?: boolean; `insecure`?: boolean; `lane`?: string }, null, string }

@js(#{`$comb`:"oneOf"}) @hoisted union NullOrBooleanOrNumeric {null, BooleanOrNumeric}

@js(#{`$comb`:"oneOf"}) @hoisted union NullOrStringOrNumeric2 { null, StringOrNumeric }

@js(#{`$comb`:"oneOf"}) @hoisted union NullOrStringOrDnStringNameStringKindStringPresentBooleanSubString {null, StringOrDnStringNameStringKindStringPresentBooleanSubString}

@js(#{ `description`:"What the store is actually doing, which is a different fact from what `persistence.*` says it should." }) @hoisted model WithModeConfiguredModeEnabledEtc { `mode`?: string; `configuredMode`?: string; `enabled`?: boolean; `healthy`?: NullableBoolean; `dataDir`?: NullableString; `database`?: NullableObject85; `engine`?: NullableString; `writeDelayMs`?: integer; `persistsDirectory`?: boolean; `persistsRealms`?: boolean; `persistsAppconfig`?: boolean; `pending`?: boolean; `writes`?: integer; `failures`?: integer; `lastWriteAt`?: NullableString; `lastError`?: NullableString; `restoredAt`?: NullableString; `restored`?: {`realms`?: integer; `entries`?: integer; `overrides`?: integer}; `entriesTracked`?: integer; `realmsTracked`?: integer; `coordinates`?: boolean; `minted`?: { `persisting`?: boolean; `supported`?: boolean; `unsupportedReason`?: string; `sealed`?: boolean; `mode`?: string; `setting`?: boolean; `retentionMs`?: numeric; `stores`?: integer; `shared`?: integer; `handles`?: ({`handle`?: string; `shape`?: string; `scope`?: string})[]; `pending`?: integer; `writes`?: integer; `failures`?: integer; `rowsWritten`?: integer; `rowsDeleted`?: integer; `lastWriteAt`?: NullableString; `lastError`?: string; `restoredAt`?: NullableString; `restored`?: integer; `droppedUnreadable`?: integer; `droppedUnknown`?: integer; `droppedPoison`?: integer; `poisonDrops`?: ({ `at`?: string; `code`?: string; `message`?: string; `rows`?: integer; `handles`?: (string)[]; `realms`?: (string)[] })[] }; `usedAssertions`?: { `store`?: string; `kind`?: string; `persistent`?: boolean; `atomicAcrossProcesses`?: boolean; `why`?: string; `cap`?: numeric; `live`?: NullableInteger; `liveIsCurrent`?: boolean }; `replication`?: { `coordinating`?: boolean; `supported`?: boolean; `startedAt`?: NullableString; `appliedSeq`?: numeric; `highestSeq`?: numeric; `holes`?: integer; `holeRanges`?: integer; `holesAbandoned`?: integer; `pollIntervalMs`?: numeric; `pulls`?: integer; `nudges`?: integer; `failures`?: integer; `rowsApplied`?: integer; @js(#{`description`:"Rows applied, per kind of change."}) `byKind`?: Record<integer>; `lastPullAt`?: NullableString; `lastError`?: NullableString; `otherProcesses`?: integer; `originsDropped`?: integer; `retention`?: { `retentionS`?: integer; `readerTtlS`?: integer; `reportedAt`?: NullableString; `reportError`?: NullableString; `declaredGoneAt`?: NullableString; `fanInGraceS`?: integer; `trimming`?: boolean; `lastTrim`?: NullableObject86 }; `note`?: string }; `cells`?: NullableObject87; `origin`?: NullableObject88; `answersAfterCommit`?: boolean; `commitBacklog`?: boolean; `retryArmed`?: boolean; `liveness`?: NullableObject89; `eventLoop`?: NullableObject84; `note`?: string }

@js(#{ `description`:"Whether a cluster is WORKING, which `cluster.mode` being set does not say." }) @hoisted model WithSelfModeWhyEtc { `self`?: { `mode`?: string; `why`?: string; `refused`?: NullableString; `configured`?: string; `nodeId`?: NullableString; `name`?: NullableString; `role`?: NullableString; `joinedAt`?: NullableString; `heartbeatMs`?: numeric; `ttlMs`?: numeric; `lastStallMs`?: numeric; `msSinceRenewal`?: NullableNumber; `heartbeatFailures`?: integer; `lastHeartbeatError`?: NullableString; `leases`?: ({ `name`?: string; `token`?: NumericOrString })[]; `fingerprintSet`?: boolean; `agreementSettings`?: (string)[]; `capabilities`?: { `rows`?: ({ `id`?: string; `section`?: string; `by`?: string; `what`?: string; `provided`?: boolean; `note`?: string; `accepted`?: boolean })[]; `missing`?: (string)[]; `acceptedMissing`?: (string)[]; `unknownAccepted`?: (string)[]; `ready`?: boolean } }; `snapshotAgeMs`?: NullableNumber; `nodes`?: ({ `nodeId`?: string; `name`?: NullableString; `mode`?: NullableString; `version`?: NullableString; `startedAt`?: numeric; `heartbeatAt`?: numeric; `expiresAt`?: numeric; `leftAt`?: numeric; @js(#{`description`:"What only that node can say about itself."}) `info`?: { `pid`?: integer; `host`?: string; `port`?: StringOrNumericOrBooleanEtc; `uptimeMs`?: numeric; `workers`?: integer; `lastStallMs`?: numeric; `caches`?: NullableObject90; @js(#{`description`:"Base64, the PEM's body."}) `listenerCertificates`?: (string)[] }; `agrees`?: NullableBoolean2 })[]; `members`?: NullableObject91; `leases`?: ({ `name`?: string; `holder`?: string; `token`?: numeric; `acquiredAt`?: numeric; `expiresAt`?: numeric })[]; `databaseNow`?: NullableNumber; `otherCells`?: NullableObject92; @js(#{ `description`:"Where each shared secret's value came from, never the value." }) `secrets`?: { `started`?: boolean; `secrets`?: ({`name`?: string; `what`?: string; `source`?: string})[] }; `barrier`?: { `active`?: boolean; `holds`?: boolean; `requests`?: integer; `caughtUp`?: integer; `gaveUp`?: integer; `heldForCommit`?: integer; `answeredUnheld`?: integer; `commitFailures`?: integer; `totalWaitMs`?: numeric; `totalHoldMs`?: numeric; `refusedForCommit`?: integer; `heldForBacklog`?: integer; `ldapHeldForCommit`?: integer; `ldapRefusedForCommit`?: integer; @js(#{ `description`:"Responses whose commit succeeded and whose deferred check (an access token's status index, #884) then refused them; each answered 503." }) `checkRefusals`?: integer; `meanWaitMs`?: numeric; `meanHoldMs`?: numeric } }

@js(#{`$comb`:"oneOf"}) @hoisted union NullOrIntegerOrString {null, IntegerOrString}

@hoisted union StringOrRecordStringOrNumericOrBooleanEtc {string, Record<StringOrNumericOrBooleanEtc>}

@hoisted union StringOrNumericOrBooleanEtc7 {string, numeric, boolean, null, (StringOrNumericOrBooleanEtc)[]}

@js(#{`$comb`:"oneOf"}) @hoisted union NullOrStringOrBoolean {null, StringOrBoolean}

@hoisted union StringOrNumericOrBooleanEtc8 { string, numeric, boolean, null, (StringOrNumericOrBooleanEtc)[] }

@js(#{ `type`:"object", `properties`:#{ `attribute`:#{`type`:"string"}, `name`:#{ `type`:"string", `description`:"An alias for `attribute`; `vcAction()` reads `body.attribute || body.name`, so both spellings have always worked and only one was published." } }, `examples`:#[#{`attribute`:"title"}], `additionalProperties`:false }) @hoisted union Shape12OrShape13 { Shape12, Shape13 }

@js(#{ `type`:"object", `properties`:#{ `claim`:#{`type`:"string"}, `name`:#{ `type`:"string", `description`:"An alias for `claim`; `vpConfigAction()` reads `body.claim || body.name`, so both spellings have always worked and only one was published." } }, `examples`:#[#{`claim`:"birthdate"}], `additionalProperties`:false }) @hoisted union Shape14OrShape13 { Shape14, Shape13 }

@js(#{ `description`:"A named profile only: the lowest matching precedence wins. Default 100.", `$comb`:"oneOf" }) @hoisted union IntegerFrom1To1000OrString { IntegerFrom1To1000, string }

@js(#{`maxItems`:64}) @hoisted model ListOfStringMax256 is (StringMax256)[];

@js(#{`maxItems`:256}) @hoisted model ListOfStringMax2048 is (StringMax2048)[];

@hoisted union StringOrNumericOrBoolean2 {String, numeric, boolean}

@js(#{ `description`:"One setting: what it is, what it is set to, and where that came from." }) @hoisted model WithDescriptionKeyDescriptionEtc { @js(#{ `description`:"The dot path, which is BOTH the name every operation here takes and the path in the appconfig file. `oid4vci.batchSize` is `appconfig.oid4vci.batchSize`." }) `key`?: string; @js(#{ `description`:"The protocol it belongs to, and the console's section heading." }) `group`?: string; `label`?: string; @js(#{`description`:"What it does and why the default is the default."}) `description`?: string; @js(#{ `description`:"How a value posted for it is coerced and checked: one of `config.js`'s types (string, int, port, bool, csv, enum, color)." }) `type`?: string; @js(#{`description`:"Present on `enum` settings only."}) `enumValues`?: (string)[]; @js(#{ `description`:"Present on a `csv` setting whose entries must each be one of these; absent on an open list." }) `csvValues`?: (string)[]; @js(#{ `description`:"Present, true, when a sensitive value here was replaced." }) `masked`?: boolean; @js(#{ `description`:"Present, true, on a `csv` setting whose order is a preference: the first value is the most preferred." }) `ordered`?: boolean; @js(#{ `description`:"Present beside `csvValues` where the setting describes each value: the value mapped to one sentence." }) `csvValueNotes`?: Record<string>; @js(#{ `description`:"Present on an `ordered` setting whose select-all is narrowed by other settings. `onlyWhileOn`: the values are selected only while that setting is on. `aloneWhileOn`: while that setting is on, only the values are selected. `canBeOn` is false where this mode never lets that setting be on." }) `selectAll`?: { `onlyWhileOn`?: ({ `setting`?: string; `values`?: (string)[]; `on`?: boolean; `canBeOn`?: boolean })[]; `aloneWhileOn`?: ({ `setting`?: string; `values`?: (string)[]; `on`?: boolean; `canBeOn`?: boolean })[] }; @js(#{ `description`:"The lowest value POST /config/set will take, on an int setting that declares one." }) `min`?: numeric; @js(#{`description`:"The highest value it will take."}) `max`?: numeric; @js(#{ `description`:"The value must be a MULTIPLE of this, counted from `min`. The four token lifetimes use 30." }) `step`?: numeric; `value`?: StringOrNumericOrBooleanEtc5; @js(#{ `description`:"The same value on one line: what the console shows in its input and what the environment variable would carry." }) `text`?: string; @js(#{ `description`:"Where the effective value came from, highest first: this trust realm's own value; a runtime override set through this API or the console; the setting's own environment variable; a legacy variable (no row has one since #523); the appconfig file CONFIG_FILE names; `env/defaults.js`, the DEFAULT appconfig file that one is unioned on top of. `default` is reachable only for the DERIVED settings, whose value is a function of a neighbouring setting: for every other setting, no value anywhere stops this service from STARTING." }) `source`?: "realm" | "override" | "env" | "env-legacy" | "appconfig" | "defaults" | "default"; @js(#{ `description`:"Whether POST /config/set will take it from the realm this answer was read in. False means either the value was consumed at startup or `editRefusal` is set. It is refused rather than accepted, because an accepted change that does nothing reads as having worked." }) `editable`?: boolean; @js(#{ `description`:"Why it is not editable, when the value was consumed at startup." }) `restartReason`?: string; @js(#{ `description`:"Why this row cannot be edited from the realm the reader is in: `realms.maxCount` while a realm other than the default is ambient. Absent on every row of the default realm's answer." }) `editRefusal`?: string; @js(#{`description`:"Its environment variable."}) `env`?: string; `appconfigPath`?: string; `default`?: StringOrNumericOrBooleanEtc6; @js(#{`description`:"Whether a trust realm may hold its own value for it."}) `realmSettable`?: boolean; @js(#{ `description`:"Whether a runtime override is in force. Equal to `source === \"override\"`, and reported separately so a caller can filter without matching a string." }) `overridden`?: boolean }

@hoisted union BooleanOrStringOrAtNullOrStringOrNumeric2ByStringReasonStringViaString { boolean, string, { `at`?: NullOrStringOrNumeric2; `by`?: string; `reason`?: string; `via`?: string } }

@js(#{`description`:"A claim's members, as `address` has."}) @hoisted model ListOfRecordStringOrNumericOrBooleanEtc4 is Record<StringOrNumericOrBooleanEtc4>;

@hoisted union WithModeConfiguredModeEnabledEtcOrWithSelfModeWhyEtc {WithModeConfiguredModeEnabledEtc, WithSelfModeWhyEtc}

@js(#{ `description`:"groups: the groups whose members are pushed, by cn or DN.", `$comb`:"oneOf" }) @hoisted union StringMax8192OrListOfStringMax2048 { StringMax8192, ListOfStringMax2048 }

@js(#{ `description`:"selected: the groups pushed, by cn or DN.", `$comb`:"oneOf" }) @hoisted union StringMax8192OrListOfStringMax20482 { StringMax8192, ListOfStringMax2048 }

@js(#{ `description`:"A service deployed as cells (#553): the cells that push to the service provider, by id; empty is every cell. Ignored in a service that is one cell.", `$comb`:"oneOf" }) @hoisted union StringMax8192OrListOfStringMax20483 { StringMax8192, ListOfStringMax2048 }


@js(#{`description`:"One group's settings."}) @hoisted model WithGroupSettings { `group`?: string; `settings`?: (WithDescriptionKeyDescriptionEtc)[] }

@js(#{`$comb`:"oneOf"}) @hoisted union NullOrBooleanOrStringOrAtNullOrStringOrNumeric2ByStringReasonStringViaString {null, BooleanOrStringOrAtNullOrStringOrNumeric2ByStringReasonStringViaString}

@hoisted union StringOrNumericOrBooleanEtc4OrListOfRecordStringOrNumericOrBooleanEtc4 { StringOrNumericOrBooleanEtc4, ListOfRecordStringOrNumericOrBooleanEtc4 }

@js(#{`description`:"One group's settings."}) @hoisted model WithGroupSettings2 {`group`?: string; `settings`?: (WithDescriptionKeyDescriptionEtc)[]}

@hoisted model WithIssuerState {`issuer_state`?: string}

@hoisted model WithSet {`set`: "saml2" | "saml11"}

@hoisted model WithReceived {`received`?: NullableString}

@hoisted model WithDnCn {`dn`?: string; `cn`?: string}

@hoisted model WithIdWhy {`id`?: string; `why`?: string}

@hoisted model WithNameId {`name`?: string; `id`?: string}

@hoisted model WithIdName {`id`?: string; `name`?: string}

@hoisted model WithWhyAt {`why`?: string; `at`?: numeric}

@hoisted model WithKindId {`kind`?: string; `id`?: string}

@hoisted model WithIdWhat {`id`?: string; `what`?: string}

@hoisted model WithTagName {`tag`?: string; `name`?: string}

@hoisted model WithScopeAt {`scope`?: string; `at`?: string}

@hoisted model WithIdName2 {`id`?: integer; `name`?: string}

@hoisted model WithStateAt {`state`?: string; `at`?: string}

@hoisted model WithIdLabel {`id`?: string; `label`?: string}

@hoisted model WithNameOid {`name`?: string; `oid`?: string}

@hoisted model WithIsoType {`iso`?: string; `type`?: string}

@hoisted model WithNameText {`name`?: string; `text`: string}

@hoisted model WithUriLabel {`uri`?: string; `label`?: string}

@hoisted model WithNameWhat {`name`?: string; `what`?: string}

// A policy's attribute as its SCHEMA row draws it: with how many values it
// holds, `single` or `multi`, where the model states it (#1579).
@hoisted model WithNameWhatKind {`name`?: string; `what`?: string; `kind`?: "single" | "multi"}

@hoisted model WithDnOrigin {`dn`?: string; `origin`?: string}

@hoisted model WithHrefWhat2 {`href`?: string; `what`?: string}

@hoisted model WithKindLevel {`kind`?: string; `level`?: string}

@hoisted model WithTokenHash {`token`?: string; `hash`?: string}

@hoisted model WithKindValue {`kind`?: string; `value`?: string}

@hoisted model WithTypeValue {`type`?: string; `value`?: string}

@hoisted model WithAttrField {`attr`?: string; `field`?: string}

@hoisted model WithCodeLink {`code`?: boolean; `link`?: boolean}

@hoisted model WithFormCount {`form`?: string; `count`?: numeric}

@hoisted model WithKindCount {`kind`?: string; `count`?: numeric}

@hoisted model WithLdapSchema {`ldap`?: string; `schema`?: string}

@hoisted model WithWhatAnswer {`what`?: string; `answer`?: string}

@hoisted model WithSet2 {`set`: "access_token" | "id_token"}

@hoisted model WithLabelWhere {`label`?: string; `where`?: string}

@hoisted model WithConsoleApi {`console`?: string; `api`?: string}

@hoisted model WithNameCount {`name`?: string; `count`?: numeric}

@hoisted model WithNameCount2 {`name`?: string; `count`?: integer}

@hoisted model WithOkMessage { `ok`: boolean; `message`: string }

@hoisted model WithRealmCount {`realm`?: string; `count`?: numeric}

@hoisted model WithIdNames {`id`?: string; `names`?: (string)[]}

@hoisted model WithCoseAlgJose {`coseAlg`?: integer; `jose`?: string}

@hoisted model WithMethodCount {`method`?: string; `count`?: numeric}

@hoisted model WithStatusDetail {`status`?: string; `detail`?: string}

@hoisted model WithFedIdFedPeer {`fedId`?: string; `fedPeer`?: string}

@hoisted model WithRequiredWhy {`required`?: boolean; `why`?: string}

@hoisted model WithValueSource {`value`?: numeric; `source`?: string}

@hoisted model WithEnabledMode {`enabled`?: boolean; `mode`?: string}

@hoisted model WithTotalTaking {`total`?: integer; `taking`?: integer}

@hoisted model WithStatusCount {`status`?: numeric; `count`?: integer}

@hoisted model WithMatchedFrom {`matched`?: integer; `from`?: integer}

@hoisted model WithDigitsPeriod {`digits`?: numeric; `period`?: numeric}

@hoisted model WithTotpWebauthn {`totp`?: boolean; `webauthn`?: boolean}

@hoisted model WithMaxLengthCode {@js(#{`maxLength`:32}) `code`?: string}

@hoisted model WithValueDeclared {`value`?: string; `declared`?: boolean}

@hoisted model WithNameSensitive {`name`?: string; `sensitive`?: boolean}

@hoisted model WithIdentifierName {`identifier`?: string; `name`?: string}

@hoisted model WithIdName3 {`id`?: string; `name`?: NullableString}

@hoisted model WithValuePopulated {`value`?: string; `populated`?: boolean}

@hoisted model WithWhatSockets {`what`?: string; `sockets`?: (string)[]}

@hoisted model WithStoredCanonical {`stored`?: string; `canonical`?: string}

@hoisted model WithApplicationSecret {`application`: string; `secret`: string}

@hoisted model WithMaxLengthType {@js(#{`maxLength`:2048}) `type`: string}

@hoisted model WithVersionBuildInfo {`version`?: string; `buildInfo`?: string}

@hoisted model WithSettingAttribute {`setting`?: string; `attribute`?: string}

@hoisted model WithOfferUriWalletUrl {`offerUri`?: string; `walletUrl`?: string}

@hoisted model WithAttributeFrom {`attribute`?: string; `from`?: (string)[]}

@hoisted model WithIdName4 { `id`?: integer; `name`?: NullableString }

@hoisted model WithEnforcedRules {`enforced`?: boolean; `rules`?: (string)[]}

@hoisted model WithClaimPaths {`claim`?: string; `paths`?: ((string)[])[]}

@hoisted model WithNodePid { `node`?: NullableString; `pid`?: integer }

@hoisted model WithAppliesRefused {`applies`?: boolean; `refused`?: (string)[]}

@hoisted model WithEtypeName { `etype`?: integer; `name`?: NullableString }

@hoisted model WithControllerCryptosuite {`controller`?: string; `cryptosuite`?: string}

@hoisted model WithAtFromTo {`at`?: string; `from`?: string; `to`?: string}

@hoisted model WithPersistsDirectoryMode {`persistsDirectory`?: boolean; `mode`?: string}

@hoisted model WithAtReasonBy {`at`?: string; `reason`?: string; `by`?: string}

@hoisted model WithEnabledCounts {`enabled`?: boolean; `counts`?: Record<numeric>}

@hoisted model WithAtKindText {`at`?: string; `kind`?: string; `text`?: string}

@hoisted model WithIdAtMessage {`id`?: string; `at`?: string; `message`?: string}

@hoisted model WithIdLabelWhat {`id`?: string; `label`?: string; `what`?: string}

@hoisted model WithAlgWhatSpec {`alg`?: string; `what`?: string; `spec`?: string}

@hoisted model WithIdLabelKind {`id`?: string; `label`?: string; `kind`?: string; `tlsUsable`?: boolean}

@hoisted model WithOptionsRequired {`options`?: ((string)[])[]; `required`?: boolean}

@hoisted model WithIdName5 { `id`?: NullableString; `name`?: NullableString }

@hoisted model WithOkMessageGo {`ok`?: boolean; `message`?: string; `go`?: string}

@hoisted model WithHashWhereWhy {`hash`?: string; `where`?: string; `why`?: string}

@hoisted model WithQExclude { `q`?: NullableString; `exclude`?: NullableArray }

@hoisted model WithQOrigin { `q`?: NullableString; `origin`?: NullableString }

@hoisted model WithUnknownCredentialAutofill {`unknownCredential`?: string; `autofill`?: boolean}

@hoisted model WithOkNameDetail {`ok`?: boolean; `name`?: string; `detail`?: string}

@hoisted model WithWhereHashWhat {`where`?: string; `hash`?: string; `what`?: string}

@hoisted model WithKindLabelWhat {`kind`?: string; `label`?: string; `what`?: string}

@hoisted model WithModeLabelWhat {`mode`?: string; `label`?: string; `what`?: string}

@hoisted model WithRoleLabelWhat {`role`?: string; `label`?: string; `what`?: string}

@hoisted model WithMinMaxDflt {`min`?: numeric; `max`?: numeric; `dflt`?: numeric}

@hoisted model WithNameMimeBase64 {`name`?: string; `mime`?: string; `base64`?: string}

@hoisted model WithLabelValueNote {`label`?: string; `value`?: string; `note`?: string}

@hoisted model WithIdLabelMessage {`id`?: string; `label`?: string; `message`?: string}

@hoisted model WithQProtocol { `q`?: NullableString; `protocol`?: NullableString }

@hoisted model WithUsernameSubAt {`username`?: string; `sub`?: string; `at`?: numeric}

@hoisted model WithLdapClaimLabel {`ldap`?: string; `claim`?: string; `label`?: string}

@hoisted model WithReadWrite { `read`?: NullableString; `write`?: NullableString }

@hoisted model WithMethodPathWhat {`method`?: string; `path`?: string; `what`?: string}

@hoisted model WithTypeNameCount {`type`?: string; `name`?: string; `count`?: integer}

@hoisted model WithSurfaceStateHow {`surface`?: string; `state`?: string; `how`?: string}

@hoisted model WithMlKemHpkeHybrid {`mlKem`?: string; `hpke`?: string; `hybrid`?: string}

@hoisted model WithMethodEndpointUrl { `method`?: string; `endpoint_url`?: NullableString }

@hoisted model WithActionLabelHelp {`action`?: string; `label`?: string; `help`?: string}

@hoisted model WithResourceTypeCount { `resourceType`?: NullableString; `count`?: numeric }

@hoisted model WithHandleShapeScope {`handle`?: string; `shape`?: string; `scope`?: string}

@hoisted model WithIdNameIsDefault {`id`?: string; `name`?: string; `isDefault`?: boolean}

@hoisted model WithPagePagesTotal {`page`?: integer; `pages`?: integer; `total`?: integer}

@hoisted model WithIdDescriptionAlfa {`id`?: string; `description`?: string; `alfa`?: string}

@hoisted model WithResourceIdResourceScopes {`resource_id`?: string; `resource_scopes`?: (string)[]}

@hoisted model WithNameDisplayNameId {`name`?: string; `displayName`?: string; `id`?: string}

@hoisted model WithEntryqAgentq { `entryq`?: NullableString; `agentq`?: NullableString }

@hoisted model WithEventCounterLabel {`event`?: string; `counter`?: string; `label`?: string}

@hoisted model WithCategoryLabelWhat {`category`?: string; `label`?: string; `what`?: string}

@hoisted model WithDescriptionId {@js(#{`description`:"The relationship."}) `id`: string}

@hoisted model WithMinLengthMaxLengthAccount {@js(#{`minLength`:1,`maxLength`:600}) `account`: string}

@hoisted model WithStateStrongestWhat {`state`?: string; `strongest`?: string; `what`?: string}

@hoisted model WithKindIdentifierNote {`kind`?: string; `identifier`?: string; `note`?: string}

@hoisted model WithDescriptionStreamId {@js(#{`description`:"The stream."}) `stream_id`: string}

@hoisted model WithPendingSentDead {`pending`?: integer; `sent`?: integer; `dead`?: integer}

@hoisted model WithIdLabelFamilies {`id`?: string; `label`?: string; `families`?: (string)[]}

@hoisted model WithNodesEdgesGrants {`nodes`?: integer; `edges`?: integer; `grants`?: integer}

@hoisted model WithActionCategoryLabel {`action`?: string; `category`?: string; `label`?: string}

@hoisted model WithOkMessageErrors {`ok`: boolean; `message`?: string; `errors`?: (string)[]}

@hoisted model WithAddressUsernameToken {`address`?: string; `username`?: string; `token`?: string}

@hoisted model WithAcmeDirectoryScepEst {`acmeDirectory`?: string; `scep`?: string; `est`?: string}

@hoisted model WithCryptosuiteCurveWhat {`cryptosuite`?: string; `curve`?: string; `what`?: string}

@hoisted model WithIssuerKeysPrivateKey {`issuer`?: string; `keys`?: string; `privateKey`?: string}

@hoisted model WithIdentifierNameAsked {`identifier`?: string; `name`?: string; `asked`?: boolean}

@hoisted model WithAtReasonBy2 { `at`?: StringOrNumeric; `reason`?: string; `by`?: string }

@hoisted model WithAcrValuesPromptMaxAge {`acrValues`?: string; `prompt`?: string; `maxAge`?: numeric}

@hoisted model WithFamilySubjectsWho {`family`?: string; `subjects`?: integer; `who`?: (string)[]}

@hoisted model WithValueSource2 { `value`?: StringOrNumericOrBooleanEtc4; `source`?: string }

@hoisted model WithAuthorizationServerResourceServer {`authorization_server`?: string; `resource_server`?: string}

@hoisted model WithEmbeddedRemoteTotal {`embedded`?: integer; `remote`?: integer; `total`?: integer}

@hoisted model WithIdNameCount { `id`?: string; `name`?: NullableString; `count`?: integer }

@hoisted model WithPermissionsGrants { `permissions`?: NullableString; `grants`?: NullableString }

@hoisted model WithResourceNameScopes {`resource`?: string; `name`?: string; `scopes`?: (string)[]}

@hoisted model WithTitleVersionDescription {`title`?: string; `version`?: string; `description`?: string}

@hoisted model WithSettingAttributeProfile {`setting`?: string; `attribute`?: string; `profile`?: string}

@hoisted model WithFormatEmailPhoneNumber {`format`?: string; `email`?: string; `phone_number`?: string}

@hoisted model WithVerifiedAddressUsername {`verified`?: boolean; `address`?: string; `username`?: string}

@hoisted model WithCredentialIdNameTrusted {`credentialId`?: string; `name`?: string; `trusted`?: boolean}

@hoisted model WithIdKtyCrvEtc4 {`id`?: string; `kty`?: string; `crv`?: string; `alg`?: string}

@hoisted model WithLevelPreviousLevelReason {`level`?: string; `previousLevel`?: string; `reason`?: string}

@hoisted model WithVersionStampedBuildInfo {`version`?: string; `stamped`?: boolean; `buildInfo`?: string}

@hoisted model WithEndedTerminatedMessage {`ended`?: boolean; `terminated`?: numeric; `message`?: string}

@hoisted model WithTextPostQuantumInsecure {`text`?: string; `postQuantum`?: boolean; `insecure`?: boolean}

@hoisted model WithProfileEnforcedRules {`profile`?: string; `enforced`?: boolean; `rules`?: (string)[]}

@hoisted model WithRealmsEntriesOverrides {`realms`?: numeric; `entries`?: numeric; `overrides`?: numeric}

@hoisted model WithAllowedBiasWhy { `allowed`?: boolean; `bias`?: string; `why`?: NullableString }

@hoisted model WithSessionsApplications { `sessions`?: NullableString; `applications`?: NullableString }

@hoisted model WithAccountsApplications { `accounts`?: NullableString; `applications`?: NullableString }

@hoisted model WithUsernameInDirectorySeen {`username`?: string; `inDirectory`?: boolean; `seen`?: boolean}

@hoisted model WithDescriptionAgent {@js(#{`description`:"The agent's SPIFFE ID."}) `agent`: string}

@hoisted model WithRolesGroupsOwners {`roles`?: (string)[]; `groups`?: (string)[]; `owners`?: boolean}

@hoisted model WithRequiresOwnerMaxOwnersDn {`requiresOwner`?: boolean; `maxOwners`?: numeric; `dn`?: string}

@hoisted model WithIdNameIsDefault2 { `id`?: string; `name`?: NullableString; `isDefault`?: boolean }

@hoisted model WithDescriptionUser {@js(#{`description`:"The person, by username."}) `user`: string}

@hoisted model WithEnabledEnforcedWaived {`enabled`?: (string)[]; `enforced`?: boolean; `waived`?: boolean}

@hoisted model WithNamespaceLevelPreviousLevel {`namespace`?: string; `level`?: string; `previousLevel`?: string}

@hoisted model WithInputModeLengthDescription {`input_mode`?: string; `length`?: integer; `description`?: string}

@hoisted model WithWhatValuesHow { `what`?: string; `values`?: (StringOrNumeric)[]; `how`?: string }

@hoisted model WithKnownCarriedMissing {`known`?: boolean; `carried`?: (string)[]; `missing`?: (string)[]}

@hoisted model WithTotalEnabledRoot { `total`?: integer; `enabled`?: integer; `root`?: NullableString }

@hoisted model WithInitialIntermediaryTarget {`initial`?: numeric; `intermediary`?: numeric; `target`?: numeric}

@hoisted model WithInitialIntermediaryTarget2 {`initial`?: integer; `intermediary`?: integer; `target`?: integer}

@hoisted model WithCredentialIdLabelEnrolledAt {`credentialId`?: string; `label`?: string; `enrolledAt`?: numeric}

@hoisted model WithDescriptionName {@js(#{`description`:"The registered PEP's name."}) `name`: string}

@hoisted model WithDescriptionSpn {@js(#{`description`:"The service principal name."}) `spn`: string}

@hoisted model WithAtCredentialTypeDiscoveredAt {`at`?: string; `credentialType`?: string; `discoveredAt`?: numeric}

@hoisted model WithWidthHeightFailed { `width`?: numeric; `height`?: numeric; `failed`?: NullableString }

@hoisted model WithIdentifierAudienceRegistered {`identifier`?: string; `audience`?: string; `registered`?: boolean}

@hoisted model WithOkMessageGoEtc4 {`ok`?: boolean; `message`?: string; `go`?: string; `photo`?: string}

@hoisted model WithMethodAtActor { `method`?: string; `at`?: NullOrStringOrNumeric; `actor`?: string }

@hoisted model WithSessionsApplicationsStreams {`sessions`?: integer; `applications`?: integer; `streams`?: integer}

@hoisted model WithAccountsApplicationsStreams {`accounts`?: integer; `applications`?: integer; `streams`?: integer}

@hoisted model WithEnabledTypedRecord { `enabled`?: boolean; `typed`?: string; `record`?: NullableObject28 }

@hoisted model WithMethodActionFieldsEtc4 {`method`?: "POST"; `action`?: string; `fields`?: {`result`?: string}}

@hoisted model WithNameUriSchemeEtc4 {`name`?: string; `uri`?: string; `scheme`?: string; `safe`?: boolean}

@hoisted model WithBindingLocationResponseLocation {`binding`?: string; `location`?: string; `responseLocation`?: string}

@hoisted model WithRoleLabelShortEtc4 {`role`?: string; `label`?: string; `short`?: string; `what`?: string}

@hoisted model WithDnKindNameEtc4 {`dn`?: string; `kind`?: string; `name`?: string; `present`?: boolean}

@hoisted model WithNameMimeTextEtc4 {`name`?: string; `mime`?: string; `text`?: string; `base64`?: string}

@hoisted model WithKindValueClaimEtc4 {`kind`?: string; `value`?: string; `claim`?: string; `label`?: string}

@hoisted model WithRefusedSecondFactorApplies {`refused`?: (string)[]; `secondFactor`?: boolean; `applies`?: boolean}

@hoisted model WithNameRefusedFirstEtc4 {`name`?: string; `refused`?: string; `first`?: string; `last`?: string}

@hoisted model WithIdLabelKindsEtc4 {`id`?: string; `label`?: string; `kinds`?: (string)[]; `kind`?: string}

@hoisted model WithTotalMsAverageMsMaxMs { `totalMs`?: numeric; `averageMs`?: NullableNumber; `maxMs`?: numeric }

@hoisted model WithOkDeviceKey { `ok`?: boolean; `device`?: NullableObject24; `key`?: NullableObject25 }

@hoisted model WithOkMessageErrorsEtc4 {`ok`: boolean; `message`?: string; `errors`?: (string)[]; `id`?: string}

@hoisted model WithOidNameParameters { `oid`?: string; `name`?: NullableString; `parameters`?: NullableString }

@hoisted model WithPagePagesPerEtc4 { `page`?: integer; `pages`?: integer; `per`?: integer; `total`?: integer }

@hoisted model WithAlgorithmCertificateFingerprint { `algorithm`?: NullableString; `certificateFingerprint`?: NullableString }

@hoisted model WithAtStateNote { `at`?: NullOrStringOrNumeric; `state`?: string; `note`?: NullableString }

@hoisted model WithAsksPostQuantumClassicalRetrying { `asksPostQuantum`?: boolean; `classical`?: boolean; `retrying`?: boolean }

@hoisted model WithQKindExclude { `q`?: NullableString; `kind`?: NullableString; `exclude`?: NullableArray }

@hoisted model WithNameWhatWhereEtc4 { `name`?: string; `what`?: string; `where`?: string; `standard`?: boolean }

@hoisted model WithNoteSpellingsMalformedIsRefused { `note`?: string; `spellings`?: (string)[]; `malformedIsRefused`?: string }

@hoisted model WithMethodNameWhatEtc4 { `method`?: string; `name`?: string; `what`?: string; `offered`?: boolean }

@hoisted model WithOkMessageErrorsEtc42 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `jti`?: string }

@hoisted model WithOkMessageErrorsEtc43 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `kid`?: string }

@hoisted model WithIdNameDoorsEtc4 { `id`?: string; `name`?: string; `doors`?: (string)[]; `password`?: string }

@hoisted model WithHeldOptedInWhyEtc4 { `held`?: string; `optedIn`?: string; `why`?: string; `verified`?: boolean }

@hoisted model WithLevelFormatSummaryEtc4 { `level`?: string; `format`?: string; `summary`?: string; `keyId`?: string }

@hoisted model WithOauthOidcAuthorizeEtc4 { `oauth`?: string; `oidc`?: string; `authorize`?: string; `token`?: string }

@hoisted model WithQStreamCause { `q`?: NullableString; `stream`?: NullableString; `cause`?: NullableString }

@hoisted model WithDescriptionName2 { @js(#{`description`:"The policy's directory entry name."}) `name`: string }

@hoisted model WithOkMessageErrorsEtc44 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `name`?: string }

@hoisted model WithMaxLengthDescriptionId { @js(#{`maxLength`:64,`description`:"The started activity."}) `id`: string }

@hoisted model WithMayActDelegateNotDelegated { `mayAct`?: string; `delegate`?: NullableObject17; `notDelegated`?: boolean }

@hoisted model WithQRoleCategory { `q`?: NullableString; `role`?: NullableString; `category`?: NullableString }

@hoisted model WithFamilyLabelKindsEtc4 { `family`?: string; `label`?: string; `kinds`?: (string)[]; `what`?: string }

@hoisted model WithUseCaseKeyAlgorithmsDefaultKeyAlg { `useCase`?: string; `keyAlgorithms`?: (string)[]; `defaultKeyAlg`?: string }

@hoisted model WithIdLabelWeakEtc4 { `id`?: string; `label`?: string; `weak`?: boolean; `kind`?: NullableString }

@hoisted model WithOkMessageErrorsEtc45 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `label`?: string }

@hoisted model WithDescriptionPartnerRealm { @js(#{`description`:"The partner Kerberos realm."}) `partnerRealm`: string }

@hoisted model WithIdLabelWhatEtc4 { `id`?: string; `label`?: string; `what`?: string; `attributes`?: (string)[] }

@hoisted model WithValuePermissionApiEtc4 { `value`?: string; `permission`?: string; `api`?: string; `apiName`?: string }

@hoisted model WithMemberAttributeLabelEtc4 { `member`?: string; `attribute`?: string; `label`?: string; `value`?: string }

@hoisted model WithQueuedRetryingDeadEtc4 { `queued`?: numeric; `retrying`?: numeric; `dead`?: numeric; `sent`?: numeric }

@hoisted model WithOkMessageErrorsEtc46 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `setting`?: string }

@hoisted model WithMultiCellCellCompleteEtc4 { `multiCell`?: boolean; `cell`?: string; `complete`?: boolean; `note`?: string }

@hoisted model WithNameResolvesDisplayNameEtc4 { `name`?: string; `resolves`?: string; `displayName`?: string; `role`?: string }

@hoisted model WithAttributeValueHeldEtc4 { `attribute`?: string; `value`?: string; `held`?: boolean; `trusted`?: boolean }

@hoisted model WithErrorCodeCountCauseEtc4 { `errorCode`?: string; `count`?: integer; `cause`?: string; `summary`?: string }

@hoisted model WithKeyPresentedApplicationEtc4 { `key`?: string; `presented`?: string; `application`?: string; `what`?: string }

@hoisted model WithPendingSentCapturedEtc4 { `pending`?: integer; `sent`?: integer; `captured`?: integer; `dead`?: integer }

@hoisted model WithOkMessageErrorsEtc47 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `dropped`?: integer }

@hoisted model WithOkMessageErrorsEtc48 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `revoked`?: integer }

@hoisted model WithSettingValuesOnEtc4 { `setting`?: string; `values`?: (string)[]; `on`?: boolean; `canBeOn`?: boolean }

@hoisted model WithOkMessageErrorsEtc49 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `reference`?: string }

@hoisted model WithScopeGroupProfileEtc4 { `scope`?: string; `group`?: string; `profile`?: string; `application`?: string }

@hoisted model WithAttributeNounChoicesEtc4 { `attribute`?: string; `noun`?: string; `choices`?: (string)[]; `value`?: string }

@hoisted model WithTotpWebauthnPasswordEtc4 { `totp`?: boolean; `webauthn`?: boolean; `password`?: boolean; `backup`?: boolean }

@hoisted model WithKeyUsernameDisplayNameEtc4 { `key`?: string; `username`?: string; `displayName`?: string; `current`?: boolean }

@hoisted model WithKidKtyCrvEtc5 { `kid`?: string; `kty`?: string; `crv`?: string; `alg`?: string; `kept`?: boolean }

@hoisted model WithClaimLdapLabelEtc4 { `claim`?: string; `ldap`?: string; `label`?: NullableString; `grouped`?: boolean }

@hoisted model WithPersistedScopeEffectEtc4 { `persisted`?: string; `scope`?: string; `effect`?: string; `revocation`?: string }

@hoisted model WithEnabledCountLengthEtc4 { `enabled`?: boolean; `count`?: numeric; `length`?: numeric; `groupSize`?: numeric }

@hoisted model WithUsersAppsNameEtc4 { `users`?: Record<boolean>; `apps`?: Record<{`name`?: string; `dnLabel`?: string}> }

@hoisted model WithHeaderPresentValueEtc4 { `header`?: string; `present`?: boolean; `value`?: NullableString; `what`?: string }

@hoisted model WithHeldRecordedDroppedEtc4 { `held`?: numeric; `recorded`?: numeric; `dropped`?: numeric; `maxEvents`?: numeric }

@hoisted model WithThreeFieldsNoteTooManyEtc4 { `threeFields`?: boolean; `note`?: string; `tooMany`?: string; `notOffered`?: string }

@hoisted model WithTotalPendingApprovedEtc4 { `total`?: integer; `pending`?: integer; `approved`?: integer; `finalized`?: integer }

@hoisted model WithUserUpgradeIdMaxLengthEtc4 { `user`: string; `upgradeId`: string; @js(#{`maxLength`:65536}) `credential`: string }

@hoisted model WithOkMessageErrorsEtc410 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `runId`?: StringOrNumeric }

@hoisted model WithOkErrorsErrorEtc5 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: {`refused`?: string} }

@hoisted model WithOutcomeBindingSignatureMethodEtc4 { `outcome`?: string; `binding`?: string; `signatureMethod`?: string; `weak`?: boolean }

@hoisted model WithIdLabelCodeEtc5 { `id`?: string; `label`?: string; `code`?: string; `what`?: string; `count`?: integer }

@hoisted model WithStartStartMsTotalEtc4 { `start`?: string; `startMs`?: numeric; `total`?: integer; `counts`?: Record<numeric> }

@hoisted model WithDescriptionObjectId { @js(#{`description`:"The `id` of a row in `workbench.objects`."}) `objectId`: string }

@hoisted model WithOkErrorsErrorEtc4 { `ok`?: boolean; `errors`?: (string)[]; `error`?: string; `error_description`?: string }

@hoisted model WithActiveWaitingConcurrencyEtc4 { `active`?: integer; `waiting`?: integer; `concurrency`?: numeric; `backlog`?: numeric }

@hoisted model WithRpIdUserVerificationTimeoutEtc4 { `rpId`?: string; `userVerification`?: string; `timeout`?: numeric; `hints`?: (string)[] }

@hoisted model WithVctValuesDoctypeValueTypeValues { `vct_values`?: (string)[]; `doctype_value`?: string; `type_values`?: (StringOrString)[] }

@hoisted model WithIdLabelWhatEtc5 { `id`?: string; `label`?: string; `what`?: string; `optional`?: boolean; `sent`?: boolean }

@hoisted model WithIndexIsDefaultBindingEtc4 { `index`?: string; `isDefault`?: NullableBoolean; `binding`?: string; `location`?: string }

@hoisted model WithAtCredentialTypeChangeTypeEtc4 { `at`?: string; `credentialType`?: string; `changeType`?: string; `friendlyName`?: string }

@hoisted model WithSubjectFingerprint256Source { `subject`?: NullableString; `fingerprint256`?: NullableString; `source`?: NullableString }

@hoisted model WithCurrentShareTargetEtc4 { `current`?: numeric; `share`?: numeric; `target`?: numeric; `suggested`?: NullableNumber }

@hoisted model WithNameModeSensitiveEtc4 { `name`?: string; `mode`?: StringOrBoolean; `sensitive`?: boolean; `families`?: (string)[] }

@hoisted model WithIdNameSpecUrnEtc5 { `id`?: string; `name`?: string; `spec_urn`?: string; `what`?: string; `offered`?: boolean }

@hoisted model WithUsernameDnLinkEtc5 { `username`?: string; `dn`?: string; `link`?: string; `issuer`?: string; `subject`?: string }

@hoisted model WithIdLabelFamiliesEtc5 { `id`?: string; `label`?: string; `families`?: (string)[]; `kind`?: string; `what`?: string }

@hoisted model WithWellKnownAcceptsNonconformingDialsInternalAddresses { `wellKnown`?: string; `acceptsNonconforming`?: boolean; `dialsInternalAddresses`?: boolean }

@hoisted model WithUserToken { `user`?: EmptyTextOrStringMin1Max2562; `token`?: EmptyTextOrStringMin1Max4096Matchingfb79a8 }

@hoisted model WithKeyNameSpecsEtc5 { `key`?: string; `name`?: string; `specs`?: (string)[]; `coverage`?: string; `what`?: string }

@hoisted model WithIatEventEventDescriptionEtc4 { `iat`?: numeric; `event`?: string; `event_description`?: string; `information_uri`?: string }

@hoisted model WithOkMessageErrorsEtc5 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `idx`?: integer; `status`?: string }

@hoisted model WithOkMessageErrorsEtc52 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `role`?: string; `client`?: string }

@hoisted model WithOkMessageErrorsEtc53 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `id`?: string; `entryUri`?: string }

@hoisted model WithOperationLabelMethodEtc5 { `operation`?: string; `label`?: string; `method`?: string; `what`?: string; `count`?: numeric }

@hoisted model WithOkMessageErrorsEtc54 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `trustMark`?: string; `id`?: string }

@hoisted model WithOkMessageErrorsEtc55 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `rpt`?: string; `revoked`?: integer }

@hoisted model WithKeyUnitKindEtc5 { `key`?: string; `unit`?: string; `kind`?: NullableString; `profile`?: string; `field`?: string }

@hoisted model WithOkMessageErrorsEtc56 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `revoked`?: integer; `user`?: string }

@hoisted model WithCheckedUndescribedStaleEtc4 { `checked`?: boolean; `undescribed`?: (string)[]; `stale`?: (string)[]; `envelopes`?: (string)[] }

@hoisted model WithAttributeValueReasonEtc5 { `attribute`?: string; `value`?: string; `reason`?: string; `dropped`?: boolean; `text`?: string }

@hoisted model WithOkMessageErrorsEtc57 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `mail`?: string; `verified`?: boolean }

@hoisted model WithApplicationSerialHexReason { `application`: string; `serialHex`: string; `reason`?: "cessationOfOperation" | "keyCompromise" }

@hoisted model WithKidKtyAlgEtc5 { `kid`?: string; `kty`?: string; `alg`?: string; `use`?: string; `certificate`?: NullableObject69 }

@hoisted model WithOkMessageErrorsEtc58 { `ok`: boolean; `message`?: string; `errors`?: (string)[]; `clientId`?: string; `issuer`?: string }

@hoisted model WithKindIssuedValidEtc5 { `kind`?: string; `issued`?: integer; `valid`?: integer; `expired`?: integer; `noExpiry`?: integer }

@hoisted model WithAlgKtyKidEtc4 { `alg`?: string; `kty`?: string; `kid`?: NullableString; `certificateFingerprint`?: NullableString }

@hoisted model WithPendingSentDescriptionEtc4 { `pending`?: integer; `sent`?: integer; @js(#{`description`:"The dead letters."}) `dead`?: integer }

@hoisted model WithNameDescriptionIdEtc4 { `name`?: string; `description`?: NullableString; `id`?: NullableString; `attributes`?: (string)[] }

@hoisted model WithKindIssuedValidEtc52 { `kind`?: string; `issued`?: numeric; `valid`?: numeric; `expired`?: numeric; `noExpiry`?: numeric }

@hoisted model WithTypeLifetimeSLogoUriEtc5 { `type`?: string; `lifetimeS`?: numeric; `logoUri`?: string; `ref`?: string; `delegation`?: string }

@hoisted model WithPeopleSignInsSuppressedEtc4 { `people`?: NullableNumber; `signIns`?: NullableNumber; `suppressed`?: boolean; `lastAt`?: numeric }

@hoisted model WithIssuedValidExpiredEtc5 { `issued`?: numeric; `valid`?: numeric; `expired`?: numeric; `revoked`?: numeric; `other`?: numeric }

@hoisted model WithKeyNamesLabelEtc5 { `key`?: string; `names`?: (NullableString)[]; `label`?: string; `detail`?: string; `href`?: string }

@hoisted model WithIssuedValidExpiredEtc52 { `issued`?: integer; `valid`?: integer; `expired`?: integer; `revoked`?: integer; `other`?: integer }

@hoisted model WithSettingAttributeValueEtc4 { `setting`?: string; `attribute`?: string; `value`?: StringOrNumericOrBooleanEtc2; `source`?: string }

@hoisted model WithKindNameMarkedEtc5 { `kind`?: string; `name`?: string; `marked`?: boolean; `protected`?: boolean; `reasons`?: (string)[] }

@hoisted model WithProtocolLabelSettingEtc5 { `protocol`?: string; `label`?: string; `setting`?: string; `attribute`?: string; `enabled`?: boolean }

@hoisted model WithQProtocolFactorEtc4 { `q`?: NullableString; `protocol`?: NullableString; `factor`?: NullableString; `kind`?: NullableString }

@hoisted model WithAttributeLabelSchemaEtc5 { `attribute`?: string; `label`?: string; `schema`?: string; `claim`?: (string)[]; `invented`?: boolean }

@hoisted model WithQueuedAtSubjectToEtc4 { `queuedAt`?: Shape; `subject`?: NullableString; `to`?: NullOrStringOrString2; `state`?: NullableString }

@hoisted model WithMinimumDescriptionIdx { @js(#{ `minimum`:0, `description`:"The index, as GET /admin-api/vc-status lists it." }) `idx`: integer }

@hoisted model WithMaxLengthDescriptionId2 { @js(#{ `maxLength`:2048, `description`:"The client: its identifier or its entry's DN." }) `id`: string }

@hoisted model WithFamilyKindStateEtc4 { `family`?: NullableString; `kind`?: NullableString; `state`?: NullableString; `session`?: NullableString }

@hoisted model WithOkErrorsDescriptionEtc4 { `ok`?: boolean; `errors`?: (string)[]; @js(#{`description`:"The nodes there are."}) `nodes`?: (string)[] }

@hoisted model WithOkNextErrorsEtc5 { `ok`?: boolean; `next`?: "refused"; `errors`?: (string)[]; `error`?: string; `error_description`?: string }

@hoisted model WithOkErrorsErrorEtc52 { `ok`?: boolean; `errors`?: (string)[]; `error`?: string; `error_description`?: string; `message`?: string }

@hoisted model WithDescriptionIdApTrueEtc4 { @js(#{`description`:"The relationship."}) `id`: string; @js(#{`$apTrue`:true}) `subject`: Record<unknown> }

@hoisted model WithAccessTokenTtlSIdTokenTtlSRefreshTokenTtlSEtc4 { `accessTokenTtlS`?: numeric; `idTokenTtlS`?: numeric; `refreshTokenTtlS`?: numeric; `clockSkewS`?: numeric }

@hoisted model WithCnDnRuleEtc5 { `cn`?: NullableString; `dn`?: string; `rule`?: NullableString; `via`?: (string)[]; `viaMemberOf`?: boolean }

@hoisted model WithClustersApplicationsLargestEtc5 { `clusters`?: integer; `applications`?: integer; `largest`?: integer; `alone`?: integer; `joined`?: integer }

@hoisted model WithProtocolMethodCountEtc5 { `protocol`?: string; `method`?: string; `count`?: integer; `at`?: NullableNumber; `lastAt`?: NullableNumber }

@hoisted model WithAvailableMechanismsOutsideCertificateAuthoritiesEtc4 { `available`?: boolean; `mechanisms`?: (string)[]; `outsideCertificateAuthorities`?: boolean; `rule`?: string }

@hoisted model WithNameIdTypeEtc6 { `name`?: string; `id`?: string; `type`?: string; `values`?: (Shape5)[]; `from`?: string; `dropped`?: boolean }

@hoisted model WithJtiUriNameEtc6 { `jti`?: string; `uri`?: string; `name`?: string; `at`?: string; `streamId`?: string; `warnings`?: (string)[] }

@hoisted model WithPatternDescriptionId { @js(#{ `pattern`:"^[a-z0-9][a-z0-9-]{0,62}$", `description`:"The source's id in this realm." }) `id`: string }

@hoisted model WithLocaleChainCatalogEtc5 { `locale`?: string; `chain`?: (string)[]; `catalog`?: string; `direction`?: "ltr" | "rtl"; `matched`?: boolean }

@hoisted model WithEntityIdWhyFirstAtEtc5 { `entityId`?: string; `why`?: string; `firstAt`?: NullableString; `lastAt`?: NullableString; `count`?: numeric }

@hoisted model WithNameGroupKindEtc6 { `name`?: string; `group`?: string; `kind`?: string; `what`?: string; `enforces`?: string; `document`?: string }

@hoisted model WithAllowHttpSkipTlsVerificationSetSkipTlsVerificationEtc4 { `allowHttp`?: boolean; `skipTlsVerificationSet`?: boolean; `skipTlsVerification`?: boolean; `caFile`?: string }

@hoisted model WithMinLengthMaxLengthDescriptionEtc4 { @js(#{ `minLength`:1, `maxLength`:256, `description`:"The application's identifier." }) `application`: string }

@hoisted model WithBlockCipherKeyTransportEncryptAssertionEtc4 { `blockCipher`?: string; `keyTransport`?: string; `encryptAssertion`?: boolean; `encryptLogoutNameId`?: boolean }

@hoisted model WithMinLengthMaxLengthDescriptionEtc42 { @js(#{ `minLength`:1, `maxLength`:128, `description`:"The access request's id (arq_...)." }) `request`: string }

@hoisted model WithAlgorithmCoseAlgLaneEtc5 { `algorithm`?: string; `coseAlg`?: NullableInteger; `lane`?: string; `postQuantum`?: boolean; `count`?: numeric }

@hoisted model WithLinkRelationshipIssuerEtc5 { `link`?: string; `relationship`?: string; `issuer`?: string; `subject`?: string; `relationshipExists`?: boolean }

@hoisted model WithNameValuesSealedAtRestEtc4 { `name`?: string; `values`?: (StringOrNumericOrBooleanEtc4)[]; `sealedAtRest`?: boolean; `operational`?: boolean }

@hoisted model WithJwksUriAlgKidEtc5 { `jwks_uri`?: string; `alg`?: string; `kid`?: string; `typ`?: string; `status_list_aggregation_endpoint`?: string }

@hoisted model WithPseudonymsPendingCapEtc5 { `pseudonyms`?: (string)[]; `pending`?: NullableString; `cap`?: numeric; `available`?: boolean; `refused`?: string }

@hoisted model WithLaneRpIdUserIdEtc6 { `lane`?: string; `rpId`?: string; `userId`?: string; `accepted`?: (string)[]; `name`?: string; `display`?: string }

@hoisted model WithAlgKtyCrvEtc5 { `alg`?: string; `kty`?: string; `crv`?: string; `kid`?: NullableString; `certificateFingerprint`?: NullableString }

@hoisted model WithLdapClaimLabelEtc6 { `ldap`?: string; `claim`?: string; `label`?: string; `schema`?: string; `ldpTerm`?: string; `generated`?: boolean }

@hoisted model WithNameLabelHelpEtc5 { `name`?: string; `label`?: string; `help`?: NullableString; `type`?: string; `dflt`?: StringOrNumericOrBooleanEtc }

@hoisted model WithKindCountIdentifiersEtc5 { `kind`?: string; `count`?: integer; `identifiers`?: (string)[]; `moreIdentifiers`?: integer; `notes`?: (string)[] }

@hoisted model WithGroupedIssuerQrEtc6 { `grouped`?: string; `issuer`?: string; `qr`?: string; `algorithm`?: string; `digits`?: numeric; `period`?: numeric }

@hoisted model WithRequireTrustedIssuerOpensRegistrationRequiredEtc4 { `requireTrustedIssuer`?: boolean; `opensRegistration`?: boolean; `required`?: boolean; `lifetimeSeconds`?: numeric }

@hoisted model WithDescriptionUsername { @js(#{ `description`:"The person, as they sign in — in the default trust realm's directory." }) `username`: string }

@hoisted model WithAtCodeMessageEtc6 { `at`?: string; `code`?: string; `message`?: string; `rows`?: numeric; `handles`?: (string)[]; `realms`?: (string)[] }

@hoisted model WithReadWriteReadAlsoEtc5 { `read`?: string; `write`?: string; `readAlso`?: (string)[]; `writeAlso`?: (string)[]; `writeIncludesRead`?: boolean }

@hoisted model WithDecisionsAllowedRefusedEtc5 { `decisions`?: integer; `allowed`?: integer; `refused`?: integer; `unenforced`?: integer; `undischargeable`?: integer }

@hoisted model WithNameRequiredWhatEtc5 { `name`?: string; `required`?: BooleanOrStringOrNull; `what`?: string; `type`?: NullableString; `values`?: (string)[] }

@hoisted model WithNameIdDnEtc6 { `name`?: string; `id`?: string; `dn`?: string; `detail`?: NullableString; `via`?: NullableObject2; `closed`?: boolean }

@hoisted model WithNameUriKeyBitsEtc6 { `name`?: string; `uri`?: string; `keyBits`?: numeric; `mode`?: string; `ivBytes`?: numeric; `authenticated`?: boolean }

@hoisted model WithTotpWebauthnWalletEtc6 { `totp`?: boolean; `webauthn`?: boolean; `wallet`?: boolean; `password`?: boolean; `email`?: string; `backup`?: boolean }

@hoisted model WithMaxEntriesMaxSearchResultsCurrentEntriesEtc4 { `maxEntries`?: numeric; `maxSearchResults`?: numeric; `currentEntries`?: numeric; `currentEntriesEverywhere`?: numeric }

@hoisted model WithUserVerificationResidentKeyRequireResidentKeyEtc4 { `userVerification`?: string; `residentKey`?: string; `requireResidentKey`?: boolean; `authenticatorAttachment`?: string }

@hoisted model WithIdNameDoorsEtc6 { `id`?: string; `name`?: string; `doors`?: (string)[]; `createdAt`?: Shape; `lastUsedAt`?: Shape; `lastUsedDoor`?: string }

@hoisted model WithSettingAttributeLabelEtc6 { `setting`?: string; `attribute`?: string; `label`?: string; `value`?: numeric; `realmValue`?: numeric; `source`?: string }

@hoisted model WithLdapClaimValueEtc5 { `ldap`?: string; `claim`?: string; `value`?: StringOrNumericOrBooleanEtc4; `source`?: string; `ldpTerm`?: NullableString }

@hoisted model WithJtiQueuedAtDeliveredAtEtc4 { `jti`?: string; `queuedAt`?: NullOrStringOrNumeric; `deliveredAt`?: NullOrStringOrNumeric; `summary`?: NullableObject103 }

@hoisted model WithFactorBackRemainingEtc5 { `factor`?: "passkey" | "code" | "link" | "app"; `back`?: string; `remaining`?: numeric; `total`?: numeric; `low`?: boolean }

@hoisted model WithUriLabelExclusiveEtc5 { `uri`?: string; `label`?: string; `exclusive`?: NullableBoolean; `comments`?: NullableBoolean; `usedHere`?: NullableBoolean }

@hoisted model WithEncBitsModeEtc6 { `enc`?: string; `bits`?: numeric; `mode`?: string; `cekBytes`?: numeric; `authenticated`?: boolean; `note`?: NullableString }

@hoisted model WithNameMethodsUrlEtc6 { `name`?: string; `methods`?: StringOrString; `url`?: string; `route`?: string; `transport`?: string; `registered`?: boolean }

@hoisted model WithIdNameProviderEtc5 { `id`?: string; `name`?: NullableString; `provider`?: NullableString; `providerLabel`?: NullableString; `connected`?: boolean }

@hoisted model WithRememberBrowserMaxLengthPatternEtc4 { `remember_browser`?: EmptyTextOr01TrueFalseOnOffYesNo; @js(#{`maxLength`:64,`pattern`:"^[A-Za-z0-9]*$"}) `device_fp`?: string }

@hoisted model WithNamedMissingAppliesEtc6 { `named`?: string; `missing`?: boolean; `applies`?: string; `precedence`?: numeric; `groupPolicies`?: integer; `link`?: string }

@hoisted model WithTypeProtocolModeEtc7 { `type`?: string; `protocol`?: string; `mode`?: string; `label`?: string; `spec`?: string; `policed`?: boolean; `what`?: string }

@hoisted model WithTypeModeOutcomeEtc5 { `type`?: NullableString; `mode`?: NullableString; `outcome`?: NullableString; `protocol`?: NullableString; `q`?: NullableString }

@hoisted model WithNameIdDisplayNameEtc6 { `name`?: string; `id`?: string; `displayName`?: string; `application`?: string; `carriedAs`?: string; `permissions`?: (string)[] }

@hoisted model WithSecondFactorRefusedAcceptedEtc5 { `secondFactor`?: boolean; `refused`?: (string)[]; `accepted`?: (string)[]; `passwordAloneDoors`?: (string)[]; `sentence`?: string }

@hoisted model WithPathAttributeIdCategoryEtc6 { `path`?: string; `attributeId`?: string; `category`?: string; `dataType`?: string; `multiplicity`?: string; `description`?: string }

@hoisted model WithMethodActionDescriptionEtc4 { `method`?: "GET" | "POST"; `action`?: string; @js(#{`description`:"A request's own parameters, by name."}) `fields`?: Record<string> }

@hoisted model WithPrincipalKvnoEtypesEtc6 { `principal`?: string; `kvno`?: NullableNumber; `etypes`?: (string)[]; `source`?: string; `keytab`?: string; `keytabFilename`?: string }

@hoisted model WithIdCreatedAtExpiresAtEtc6 { `id`?: string; `createdAt`?: numeric; `expiresAt`?: numeric; `description`?: NullableString; `expired`?: boolean; `primary`?: boolean }

@hoisted model WithSubjectNamesFingerprint256Etc5 { `subject`?: NullableString; `names`?: NullableArray; `fingerprint256`?: NullableString; `notAfter`?: NullableString; `source`?: string }

@hoisted model WithStreamIdAudStatusEtc6 { `stream_id`?: string; `aud`?: NullOrStringOrString; `status`?: string; `delivery`?: string; `subjects`?: integer; `takes`?: (string)[] }

@hoisted model WithUsernameDnNotDelegatedEtc6 { `username`?: string; `dn`?: string; `notDelegated`?: boolean; `mayAct`?: string; `semantics`?: (string)[]; `defaultSemantics`?: string }

@hoisted model WithAlgMlDsaTraditionalEtc5 { `alg`?: string; `mlDsa`?: NullableString; `traditional`?: NullableString; `prehash`?: NullableString; `domainSeparator`?: NullableString }

@hoisted model WithSaml2LifetimeMinSaml11LifetimeMinClockSkewSEtc5 { `saml2LifetimeMin`?: numeric; `saml11LifetimeMin`?: numeric; `clockSkewS`?: numeric; `saml2WindowS`?: numeric; `saml11WindowS`?: numeric }

@hoisted model WithLabelSerialHexKeyAlgEtc7 { `label`?: string; `serialHex`?: string; `keyAlg`?: string; `notAfter`?: string; `state`?: string; `reason`?: string; `revokedAt`?: string }

@hoisted model WithProtocolLabelFamilyEtc7 { `protocol`?: string; `label`?: string; `family`?: string; `what`?: string; `needs`?: (string)[]; `spec`?: string; `signalsOnly`?: boolean }

@hoisted model WithEventReactionSkippedEtc7 { `event`?: string; `reaction`?: string; `skipped`?: string; `observed`?: boolean; `ended`?: integer; `revoked`?: integer; `failed`?: boolean }

@hoisted model WithNamePolicyIdVersionEtc6 { `name`?: string; `policyId`?: NullableString; `version`?: string; `enabled`?: boolean; `orphanedAt`?: NullableString; `referenced`?: boolean }

@hoisted model WithSingleLogoutSignOutCleanupBackchannelLogoutEtc5 { `singleLogout`?: string; `signOutCleanup`?: string; `backchannelLogout`?: string; `frontchannelLogout`?: string; `postLogoutRedirect`?: string }

@hoisted model WithSourceCompleteNewestEtc6 { `source`?: string; `complete`?: boolean; `newest`?: NullableNumber; `session`?: NullableString; `unread`?: boolean; `countEstimated`?: boolean }

@hoisted model WithNameMethodsUrlEtc7 { `name`?: string; `methods`?: (string)[]; `url`?: string; `route`?: string; `transport`?: string; `registered`?: boolean; `listening`?: boolean }

@hoisted model WithEnrolledUsableDetailEtc6 { `enrolled`?: boolean; `usable`?: boolean; `detail`?: NullableObject7; `offered`?: boolean; `digits`?: NullableNumber; `period`?: NullableNumber }

@hoisted model WithBoundAlgBoundAtEtc7 { `bound`?: boolean; `alg`?: string; `boundAt`?: numeric; `refreshes`?: numeric; `refreshedAt`?: numeric; `fact`?: string; `reasons`?: (string)[] }

@hoisted model WithLiveTokensValidEtc7 { `live`?: numeric; `tokens`?: numeric; `valid`?: numeric; `expired`?: numeric; `artifacts`?: numeric; `ended`?: numeric; `sessionless`?: numeric }

@hoisted model WithIdNameIssuerEtc6 { `id`?: string; `name`?: NullableString; `issuer`?: NullableString; `claims`?: (string)[]; `delivery`?: NullableString; `link`?: NullableObject29 }

@hoisted model WithPersistingRetentionPlaintextTtlSEtc6 { `persisting`?: boolean; `retention`?: string; `plaintextTtlS`?: numeric; `note`?: string; `realmsHeld`?: (string)[]; `plaintextHeld`?: (string)[] }

@hoisted model WithRequiredByUserByRealmEtc6 { `required`?: boolean; `byUser`?: boolean; `byRealm`?: boolean; `byAdministrator`?: boolean; `offered`?: boolean; `exemptServiceAccount`?: boolean }

@hoisted model WithNameMethodsUrlEtc72 { `name`?: string; `methods`?: StringOrString; `url`?: string; `route`?: string; `transport`?: string; `registered`?: boolean; `listening`?: boolean }

@hoisted model WithStreamsEnabledDeliveredEtc7 { `streams`?: integer; `enabled`?: integer; `delivered`?: numeric; `failed`?: numeric; `waiting`?: integer; `dead`?: integer; `deadLetters`?: integer }

@hoisted model WithKtyBitsAlgEtc7 { `kty`?: string; `bits`?: integer; `alg`?: string; `kid`?: string; `certificate`?: string; `certificateFingerprint`?: NullableString; `what`?: string }

@hoisted model WithFirstSweepAtSweepsLettersEtc7 { `firstSweepAt`?: string; `sweeps`?: numeric; `letters`?: numeric; `expired`?: numeric; `orphaned`?: numeric; `trimmed`?: numeric; `probes`?: numeric }

@hoisted model WithDescriptionUserDescriptionEtc4 { @js(#{`description`:"The person, as /admin-api/users names them."}) `user`: string; @js(#{`description`:"Accepted for `user`."}) `username`?: string }

@hoisted model WithDescriptionSetDescriptionEtc4 { @js(#{`description`:"The `setKey` off a row of GET /admin-api/tokens."}) `set`: string; @js(#{`description`:"Accepted for `set`."}) `setKey`?: string }

@hoisted model WithEnabledCountAtCapEtc7 { `enabled`?: boolean; `count`?: integer; `atCap`?: boolean; `allowed`?: boolean; `kinds`?: (string)[]; `pending`?: NullableObject6; `lanes`?: (string)[] }

@hoisted model WithPagePagesPerPageEtc8 { `page`?: integer; `pages`?: integer; `perPage`?: integer; `firstRow`?: integer; `lastRow`?: integer; `total`?: integer; `param`?: string; `noun`?: string }

@hoisted model WithAttributeLabelGroupEtc8 { `attribute`?: string; `label`?: string; `group`?: string; `multi`?: boolean; `example`?: string; `simple`?: boolean; `takes`?: string; `custom`?: boolean }

@hoisted model WithFormatByModeEtc6 { `format`?: (string)[]; `by`?: (string)[]; `mode`?: (string)[]; `response_type`?: (string)[]; `response_mode`?: (string)[]; `client_id_prefix`?: (string)[] }

@hoisted model WithNameValueAttributeEtc8 { `name`?: string; `value`?: string; `attribute`?: string; `multi`?: boolean; `type`?: string; `nameFormat`?: string; `namespace`?: string; `claimId`?: string }

@hoisted model WithNameValueNameFormatEtc7 { `name`?: string; `value`?: StringOrNumericOrBooleanEtc4; `nameFormat`?: string; `namespace`?: string; `attribute`?: string; `multi`?: boolean; `type`?: string }

@hoisted model WithKindKidHmacKeyEtc8 { `kind`?: string; `kid`?: string; `hmacKey`?: string; `challenge`?: string; `profile`?: string; `expiresAt`?: Shape; `scepUrl`?: string; `plainScepUrl`?: string }

@hoisted model WithApplicationImpersonatesSemanticsEtc6 { `application`?: string; `impersonates`?: boolean; `semantics`?: (string)[]; `defaultSemantics`?: string; `notDelegated`?: boolean; `subjectGroups`?: (string)[] }

@hoisted model WithKnownCapHeldOnlyEtc7 { `known`?: integer; `cap`?: integer; `heldOnly`?: boolean; `forgotten`?: integer; `authenticatedHere`?: integer; `clients`?: integer; `authentications`?: integer }

@hoisted model WithUriLabelFamilyEtc7 { `uri`?: string; `label`?: string; `family`?: NullableString; `hash`?: NullableString; `keyKind`?: NullableString; `verifiedHere`?: boolean; `signsWith`?: boolean }

@hoisted model WithAtHeldLettersEtc8 { `at`?: string; `held`?: integer; `letters`?: integer; `expired`?: integer; `orphaned`?: integer; `trimmed`?: integer; `deadStreams`?: integer; `probes`?: integer }

@hoisted model WithKindIssuedValidEtc8 { `kind`?: string; `issued`?: integer; `valid`?: integer; `expired`?: integer; `revoked`?: integer; `notYetValid`?: integer; `noExpiry`?: integer; `bound`?: integer }

@hoisted model WithStatusReasonSerialEtc7 { `status`?: string; `reason`?: string; `serial`?: string; `listVersion`?: string; `checkedAt`?: NullOrStringOrNumeric2; `chainSerials`?: (string)[]; `why`?: string }

@hoisted model WithKindSubjectActorEtc7 { `kind`?: string; `subject`?: string; `actor`?: string; `at`?: NullOrStringOrNumeric2; `keyThumbprint`?: string; `versionId`?: StringOrNumeric; `transaction`?: string }

@hoisted model WithWithSecondWithTotpWithKeysEtc7 { `withSecond`?: numeric; `withTotp`?: numeric; `withKeys`?: numeric; `primaryKeys`?: numeric; `passwordOnly`?: numeric; `unreadable`?: numeric; `noCredential`?: numeric }

@hoisted model WithSha256SubjectIssuerEtc8 { `sha256`?: string; `subject`?: string; `issuer`?: string; `serialNumber`?: string; `notBefore`?: string; `notAfter`?: string; `expired`?: boolean; `readable`?: boolean }

@hoisted model WithPatternDescriptionProfile { @js(#{ `pattern`:"^(default|[a-z0-9][a-z0-9-]{0,63})$", `description`:"Which profile: `default` goes back to inheriting; a named one is removed." }) `profile`?: string }

@hoisted model WithPagePagesPerPageEtc82 { `page`?: integer; `pages`?: integer; `perPage`?: integer; `firstRow`?: integer; `lastRow`?: integer; `total`?: integer; `param`?: NullableString; `noun`?: NullableString }

@hoisted model WithGroupSlotAlgEtc7 { `group`?: string; `slot`?: string; `alg`?: string; `kind`?: NullableString; `kid`?: NullableString; `pairedSlot`?: NullableString; `certificateFingerprint`?: NullableString }

@hoisted model WithEnabledIssuerDigitsEtc8 { `enabled`?: boolean; `issuer`?: string; `digits`?: numeric; `period`?: numeric; `algorithm`?: string; `window`?: numeric; `secretBytes`?: numeric; `enrolmentTtlMs`?: numeric }

@hoisted model WithIdNameDoorsEtc8 { `id`?: string; `name`?: string; `doors`?: (string)[]; `doorLabels`?: (string)[]; `createdAt`?: numeric; `createdBy`?: string; `lastUsedAt`?: numeric; `lastUsedDoor`?: string }

@hoisted model WithPagePerPagePagesEtc9 { `page`?: integer; `perPage`?: integer; `pages`?: integer; `offset`?: integer; `total`?: integer; `firstRow`?: integer; `lastRow`?: integer; `param`?: string; `noun`?: string }

@hoisted model WithDnOriginDescriptionEtc4 { `dn`?: string; `origin`?: string; @js(#{ `description`:"Attribute names, which are data in a schemaless directory, and values." }) `attributes`?: Record<NullOrStringOrString> }

@hoisted model WithReferenceResourceServerAccessEtc6 { `reference`?: string; `resourceServer`?: string; `access`?: (Shape6)[]; `tokenFormats`?: NullableArray; `introspectionRequired`?: boolean; `createdAt`?: NullOrStringOrNumeric }

@hoisted model WithResourcesPermissionsUnidentifiedEtc8 { `resources`?: integer; `permissions`?: integer; `unidentified`?: integer; `grants`?: integer; `dangling`?: integer; `unused`?: integer; `ungranted`?: integer; `clients`?: integer }

@hoisted model WithNameKindRoleEtc9 { `name`?: string; `kind`?: string; `role`?: string; `from`?: string; `what`?: string; `standard`?: boolean; `sensitive`?: boolean; `enum`?: (string)[]; `editable`?: BooleanOrString }

@hoisted model WithRetentionSMaxPerStreamDeadStreamTimeoutSEtc7 { `retentionS`?: numeric; `maxPerStream`?: numeric; `deadStreamTimeoutS`?: numeric; `sweepS`?: numeric; `pushConcurrency`?: numeric; `pushBacklog`?: numeric; `pushRetries`?: numeric }

@hoisted model WithAlgFamilyKtyEtc9 { `alg`?: string; `family`?: NullableString; `kty`?: string; `crv`?: string; `hash`?: string; `asymmetric`?: boolean; `postQuantum`?: boolean; `composite`?: boolean; `dpop`?: boolean }

@hoisted model WithConfigFileDefaultsFilePersistsAppconfigEtc7 { `configFile`?: NullableString; `defaultsFile`?: string; `persistsAppconfig`?: boolean; `persistsRealms`?: boolean; `persistenceMode`?: string; `inRealm`?: boolean; `realmId`?: string }

@hoisted model WithCategoryActionOutcomeEtc7 { `category`?: NullableString; `action`?: NullableString; `outcome`?: NullableString; `actor`?: NullableString; `q`?: NullableString; `code`?: NullableString; `address`?: NullableString }

@hoisted model WithValueAttributeHoldsEtc10 { `value`?: string; `attribute`?: string; `holds`?: string; `dn`?: string; `present`?: boolean; `kind`?: string; `userKey`?: string; `cn`?: string; `mail`?: string; `displayName`?: string }

@hoisted model WithDnKindUserKeyEtc10 { `dn`?: string; `kind`?: string; `userKey`?: string; `cn`?: string; `mail`?: string; `displayName`?: string; `value`?: string; `attribute`?: string; `holds`?: string; `present`?: boolean }

@hoisted model WithActivityReasonRequiredEtc9 { `activity`?: string; `reason`?: string; `required`?: boolean; `canSkip`?: boolean; `method`?: string; `failed`?: string; `separate`?: boolean; `snoozeDays`?: numeric; `deadline`?: string }

@hoisted model WithIdProfileCreatedAtEtc7 { `id`?: string; `profile`?: NullableString; `createdAt`?: StringOrNumeric; `expiresAt`?: StringOrNumeric; `createdBy`?: NullableString; `usedAt`?: StringOrNumericOrNull; `status`?: string }

@hoisted model WithPagePagesPerPageEtc9 { `page`?: integer; `pages`?: integer; `perPage`?: integer; `offset`?: integer; `total`?: integer; `firstRow`?: integer; `lastRow`?: integer; `param`?: NullableString; `noun`?: NullableString }

@hoisted model WithKtyCrvAlgEtc12 { `kty`?: string; `crv`?: string; `alg`?: string; `use`?: string; `kid`?: string; `x`?: string; `y`?: string; `n`?: string; `e`?: string; `pub`?: string; `ext`?: boolean; `key_ops`?: (string)[] }

@hoisted model WithDescriptionTargetDescriptionEtc6 { @js(#{`description`:"A jti, or a whole JWT."}) `target`?: string; @js(#{`description`:"Accepted for `target`."}) `jti`?: string; @js(#{`description`:"Accepted for `target`."}) `token`?: string }

@hoisted model WithKidCreatedAtExpiresAtEtc7 { `kid`?: string; `createdAt`?: StringOrNumeric; `expiresAt`?: StringOrNumeric; `createdBy`?: NullableString; `boundAccount`?: NullableString; `boundAt`?: StringOrNumericOrNull; `status`?: string }

@hoisted model WithIdentifierNameEntityIdEtc9 { `identifier`?: string; `name`?: string; `entityId`?: string; `protocol`?: string; `label`?: string; `attribute`?: string; `launchUrl`?: string; `endpoint`?: NullableString; `missing`?: (string)[] }

@hoisted model WithMethodPathMatchedEtc9 { `method`?: string; `path`?: string; `matched`?: boolean; `count`?: numeric; `totalMs`?: numeric; `maxMs`?: numeric; `lastAt`?: numeric; `lastStatus`?: NullableInteger; `statuses`?: Record<numeric> }

@hoisted model WithSubjectLabelEnrolledAtEtc9 { `subject`?: string; `label`?: string; `enrolledAt`?: Shape; `by`?: string; `proof`?: string; `preferred`?: boolean; `location`?: NullableObject20; `didDocumentUrl`?: string; `didResolved`?: boolean }

@hoisted model WithConfigFileDefaultsFilePersistsAppconfigEtc72 { `configFile`?: NullableString; `defaultsFile`?: NullableString; `persistsAppconfig`?: boolean; `persistsRealms`?: boolean; `persistenceMode`?: string; `inRealm`?: boolean; `realmId`?: NullableString }

@hoisted model WithJtiLabelFormatEtc9 { `jti`?: string; `label`?: NullableString; `format`?: NullableString; `issuedAt`?: Shape; `expiresAt`?: Shape; `state`?: string; `bearer`?: boolean; `access`?: (Shape3)[]; `revokedWhy`?: NullableString }

@hoisted model WithStoreKindPersistentEtc8 { `store`?: NullableString; `kind`?: NullableString; `persistent`?: boolean; `atomicAcrossProcesses`?: boolean; `why`?: NullableString; `cap`?: numeric; `live`?: NullableNumber; `liveIsCurrent`?: boolean }

@hoisted model WithIssuerCertificateChainEtc10 { `issuer`?: string; `certificate`?: string; `chain`?: string; `privateKey`?: string; `handle`?: string; `handleLabel`?: string; `expires`?: string; `source`?: string; `jwks`?: string; `registered`?: string }

@hoisted model WithNameValueNameFormatEtc9 { `name`?: string; `value`?: StringOrNumericOrBooleanEtc4; `nameFormat`?: string; `namespace`?: string; `attribute`?: string; `multi`?: boolean; `type`?: string; `source`?: string; `replacesRealm`?: boolean }

@hoisted model WithOperationLabelMethodEtc10 { `operation`?: string; `label`?: string; `method`?: string; `what`?: string; `count`?: numeric; `ok`?: numeric; `failed`?: numeric; `averageMs`?: NullableNumber; `maxMs`?: NullableNumber; `bytes`?: numeric }

@hoisted model WithKeySubUsernameEtc9 { `key`?: string; `sub`?: string; `username`?: string; `displayName`?: string; `state`?: "signed-in" | "signed-out"; `signedInAt`?: numeric; `authTime`?: numeric; `signedOutAt`?: numeric; `current`?: boolean }

@hoisted model WithPrincipalRealmNotDelegatedEtc8 { `principal`?: string; `realm`?: string; `notDelegated`?: boolean; `trustedToAuthenticateForDelegation`?: boolean; `okAsDelegate`?: boolean; `autoCreated`?: boolean; `description`?: string; `effects`?: (string)[] }

@hoisted model WithSubjectIssuerSerialHexEtc10 { `subject`?: string; `issuer`?: string; `serialHex`?: string; `notBefore`?: string; `notAfter`?: string; `expired`?: boolean; `selfSigned`?: boolean; `keyType`?: string; `thumbprint`?: string; `unreadable`?: string }

@hoisted model WithMinLengthMaxLengthPatternEtc5 { @js(#{ `minLength`:1, `maxLength`:63, `pattern`:"^[a-z0-9][a-z0-9-]{0,62}$", `description`:"The destination id. A letter or a digit, then lower-case letters, digits and hyphens. It does not change." }) `id`: string }

@hoisted model WithIdLabelIdentifiedByEtc9 { `id`?: string; `label`?: string; `identifiedBy`?: string; `identifier`?: StringOrString; `selectiveDisclosure`?: string; `holderBinding`?: string; `configurations`?: (string)[]; `identifierText`?: string; `what`?: string }

@hoisted model WithJtiQueuedAtDeadAtEtc8 { `jti`?: string; `queuedAt`?: NullOrStringOrNumeric; `deadAt`?: NullOrStringOrNumeric; `reason`?: NullableString; `errorCode`?: NullableString; `status`?: NullableInteger; `signed`?: boolean; `summary`?: NullableObject103 }

@hoisted model WithScimLdapKindEtc10 { `scim`?: string; `ldap`?: NullableString; `kind`?: NullableString; `type`?: NullableString; `parent`?: NullableString; `extension`?: boolean; `readOnly`?: boolean; `required`?: boolean; `schema`?: string; `note`?: string }

@hoisted model WithDatasetVersionRealm { `dataset`: "geo.city" | "geo.country" | "asn" | "iplist.tor-exit" | "iplist.reputation" | "iplist.operator-deny" | "iplist.operator-allow" | "fido.mds3" | "android.attestation-status"; `version`: string; `realm`?: string }

@hoisted model WithHandleLabelSourceEtc11 { `handle`?: string; `label`?: string; `source`?: string; `serialHex`?: string; `keyAlg`?: string; `notAfter`?: string; `expiresAt`?: string; `state`?: string; `reason`?: string; `revokedAt`?: string; `certificate`?: string }

@hoisted model WithSubjectIssuerSerialHexEtc102 { `subject`?: string; `issuer`?: string; `serialHex`?: string; `notBefore`?: string; `notAfter`?: string; `expired`?: boolean; `selfSigned`?: boolean; `keyType`?: NullableString; `thumbprint`?: string; `unreadable`?: string }

@hoisted model WithDistinctApplicationsIdentitiesEtc9 { `distinct`?: numeric; `applications`?: numeric; `identities`?: numeric; `anonymous`?: numeric; `refused`?: numeric; `capped`?: boolean; `cap`?: numeric; @js(#{`description`:"A count per name."}) `byScheme`?: Record<numeric> }

@hoisted model WithIdAtCityEtc12 { `id`?: Shape2; `at`?: Shape; `city`?: string; `country`?: string; `asOrg`?: string; `addressPrefix`?: string; `uaFamily`?: string; `uaOs`?: string; `door`?: string; `application`?: string; `level`?: string; `feedback`?: string }

@hoisted model WithRetentionSReaderTtlSReportedAtEtc8 { `retentionS`?: numeric; `readerTtlS`?: numeric; `reportedAt`?: NullableString; `reportError`?: NullableString; `declaredGoneAt`?: NumericOrStringOrNull; `fanInGraceS`?: numeric; `trimming`?: boolean; `lastTrim`?: NullableObject80 }

@hoisted model WithAtProtocolMethodEtc12 { `at`?: numeric; `protocol`?: string; `method`?: string; `presented`?: string; `realm`?: string; `sub`?: string; `address`?: string; `client_id`?: string; `amr`?: StringOrString; `acr`?: string; `sessionId`?: string; `note`?: string }

@hoisted model WithStreamIdStatusDeliveryEtc9 { `stream_id`?: string; `status`?: string; `delivery`?: string; `events_delivered`?: (string)[]; `subjects`?: integer; `queued`?: integer; `counters`?: Record<numeric>; `createdAt`?: NullOrStringOrNumeric; `lastPushError`?: NullableString }

@hoisted model WithEnabledCountLengthEtc11 { `enabled`?: boolean; `count`?: NullableNumber; `length`?: NullableNumber; `advised`?: boolean; `present`?: boolean; `usable`?: boolean; `why`?: string; `remaining`?: numeric; `total`?: numeric; `generatedAt`?: Shape; `lastUsedAt`?: Shape }

@hoisted model WithApplicationMinLengthMaxLengthEtc10 { `application`: string; @js(#{`minLength`:8,`maxLength`:256}) `password`: string; `confirm`?: string; `keyAlg`?: "rsa-2048" | "rsa-3072" | "ec-p256" | "ec-p384"; @js(#{`maxLength`:40}) `label`?: string; @js(#{`minimum`:1}) `days`?: integer }

@hoisted model WithClientClientNamePermissionIdEtc10 { `client`?: string; `clientName`?: string; `permissionId`?: string; `resource`?: string; `resourceName`?: string; `baseUri`?: NullableString; `permissionName`?: string; `description`?: NullableString; `dangling`?: boolean; `asked`?: boolean }

@hoisted model WithUserDescriptionByLdapEtc9 { `user`?: string; @js(#{`description`:"By lower-cased attribute name."}) `byLdap`?: Record<{ `ldap`?: string; `claim`?: string; `value`?: StringOrNumericOrBooleanEtc4; `source`?: string; `ldpTerm`?: NullableString }>; `entryFound`?: boolean }

@hoisted model WithMechanismTypeFrontEndEtc12 { `mechanism`?: string; `type`?: string; `frontEnd`?: string; `target`?: string; `realm`?: string; `attribute`?: string; `setOn`?: string; `setOnRole`?: string; `requires`?: string; `targetKnown`?: boolean; `warning`?: string; `note`?: string }

@hoisted model WithFamilyLabelAllowedProfilesEtc8 { `family`?: string; `label`?: string; `allowedProfiles`?: (string)[]; `allowedProfilesSource`?: string; `defaultProfile`?: NullableString; `defaultProfileSource`?: string; `certificateLifetimeDays`?: numeric; `certificateLifetimeSource`?: string }

@hoisted model WithKdcRealmTrustRealmEtc11 { `kdc`?: boolean; `realm`?: string; `trustRealm`?: string; `reason`?: string; `productKdc`?: NullableBoolean; `personKeys`?: boolean; `principal`?: string; `nameUsable`?: boolean; `person`?: boolean; `disabled`?: boolean; `keys`?: NullableObject48 }

@hoisted model WithClientClientNamePermissionIdEtc102 { `client`?: string; `clientName`?: string; `permissionId`?: string; `resource`?: string; `resourceName`?: string; `baseUri`?: NullableString; `permissionName`?: NullableString; `description`?: NullableString; `dangling`?: boolean; `asked`?: boolean }

@hoisted model WithMinLengthMaxLengthDescriptionEtc8 { @js(#{ `minLength`:1, `maxLength`:256, `description`:"The application whose document it is; it must carry umaOwnsResources TRUE." }) `owner`: string; @js(#{`minLength`:1,`maxLength`:128,`description`:"The waiting request's id."}) `pending`: string }

@hoisted model WithIdLabelProtocolEtc12 { `id`?: string; `label`?: string; `protocol`?: string; `generic`?: boolean; `docs`?: string; `note`?: string; `defaults`?: Record<string>; `needs`?: (string)[]; `adapters`?: (string)[]; `subject`?: string; `emailVerified`?: string; `claims`?: (string)[] }

@hoisted model WithEventReactionDoneEtc13 { `event`?: string; `reaction`?: string; `done`?: boolean; `skipped`?: string; `observed`?: boolean; `why`?: string; `ended`?: integer; `revoked`?: integer; `gnapGrants`?: integer; `oauthGrants`?: integer; `tokens`?: integer; `codes`?: integer; `status`?: string }

@hoisted model WithNamePolicyIdKindEtc11 { `name`?: string; `policyId`?: NullableString; `kind`?: string; `version`?: string; `enabled`?: boolean; `isRoot`?: boolean; `combiningAlgId`?: string; `description`?: string; `application`?: NullableString; `orphanedAt`?: NullableString; `problems`?: (string)[] }

@hoisted model WithIdLabelKindEtc11 { `id`?: string; `label`?: string; `kind`?: string; `kinds`?: (string)[]; `identifierAttribute`?: string; `redirectAttribute`?: string; `logoutAttribute`?: string; `deliveryAttribute`?: string; `eventsAttribute`?: string; `secretAttribute`?: string; `what`?: string }

@hoisted model WithLdapClaimLabelEtc10 { `ldap`?: string; `claim`?: string; `label`?: NullableString; `schema`?: NullableString; @js(#{`description`:"Whether it is ticked, by claim set."}) `sets`?: Record<boolean>; `generated`?: boolean; `custom`?: boolean; `syntax`?: NullableString; `pacClaimId`?: string }

@hoisted model WithMechanismIntermediaryTargetEtc11 { `mechanism`?: string; `intermediary`?: string; `target`?: string; `targetApplication`?: NullableString; `attribute`?: string; `setOn`?: string; `setOnRole`?: string; `impersonates`?: boolean; `subjectGroups`?: (string)[]; `targetKnown`?: boolean; `warning`?: string }

@hoisted model WithIdFamilyKindEtc11 { `id`?: string; `family`?: string; `kind`?: string; `handle`?: StringOrNumeric; `label`?: NullableString; `detail`?: NullableString; `startedAt`?: NullableNumber; `expiresAt`?: NullableNumber; `terminable`?: boolean; `why`?: NullableString; `sessionId`?: NullableString }

@hoisted model WithSeqAtKindEtc13 { `seq`?: numeric; `at`?: NullableNumber; `kind`?: string; `identifier`?: string; `note`?: string; `protocol`?: string; `type`?: string; `typeLabel`?: string; `mode`?: string; `chainKey`?: string; `subject`?: NullableString; `actor`?: NullableString; `target`?: NullableString }

@hoisted model WithAuthenticatedCertificateSubjectCurrentEtc11 { `authenticated`?: boolean; `certificateSubject`?: string; `current`?: boolean; `stale`?: boolean; `enabled`?: boolean; `registeredAt`?: NullableString; `lastSeen`?: NullableString; `syncToken`?: string; `policyCount`?: NullableInteger; `version`?: string; `lastNotify`?: string }

@hoisted model WithKtyUseAlgEtc17 { `kty`?: string; `use`?: string; `alg`?: string; `kid`?: string; `key_ops`?: (string)[]; `ext`?: boolean; `crv`?: string; `x`?: string; `y`?: string; `n`?: string; `e`?: string; `pub`?: string; `ek`?: string; `x5c`?: (string)[]; `x5t`?: string; `x5t#S256`?: string; `x5u`?: string }

@hoisted model WithSerialHexLabelSubjectEtc11 { `serialHex`?: string; `label`?: string; `subject`?: string; `keyAlg`?: string; `notBefore`?: NullOrStringOrNumeric; `notAfter`?: NullOrStringOrNumeric; `thumbprint`?: string; `state`?: string; `reason`?: NullableString; `revokedAt`?: NullOrStringOrNumeric; `certificatePem`?: string }

@hoisted model WithStreamIdJtiQueuedAtEtc12 { `stream_id`?: string; `jti`?: string; `queuedAt`?: NullOrStringOrNumeric; `deadAt`?: NullOrStringOrNumeric; `ageS`?: NullableNumber; `cause`?: string; `reason`?: string; `errorCode`?: string; `status`?: numeric; `signed`?: boolean; `streamKnown`?: boolean; `event`?: NullableObject112 }

@hoisted model WithAssertionConsumerServiceLoginMetadataEtc10 { `assertionConsumerService`?: string; `login`?: string; `metadata`?: NullableString; `jwks`?: NullableString; `initiateLogin`?: NullableString; `singleLogout`?: string; `signOutCleanup`?: string; `backchannelLogout`?: string; `frontchannelLogout`?: string; `postLogoutRedirect`?: string }

@hoisted model WithNameDnOriginEtc8 { `name`?: string; `dn`?: string; `origin`?: NullableString; `createdAt`?: NullableString; `modifiedAt`?: NullableString; `operational`?: (string)[]; @js(#{ `description`:"Attribute names, which are data in a schemaless directory, and values." }) `attributes`?: Record<NullOrStringOrString> }

@hoisted model WithKeyLabelDecidesEtc15 { `key`?: string; `label`?: string; `decides`?: string; `asked`?: string; `remote`?: boolean; `name`?: string; `ok`?: boolean; `builtIn`?: boolean; `why`?: string; `setting`?: string; `template`?: string; `entry`?: boolean; `enabled`?: NullableBoolean; `effect`?: string; `readsRisk`?: boolean }

@hoisted model WithIdPositionOfEtc13 { `id`?: string; `position`?: integer; `of`?: integer; `issuedAt`?: string; `expiresAt`?: string; `status`?: string; `removable`?: boolean; `removedAt`?: string; `walletEvent`?: NullableString; `walletEventAt`?: string; `keyThumbprint`?: NullableString; `holderDid`?: NullableString; `statusIndex`?: Shape }

@hoisted model WithPrincipalKindCallsEtc11 { `principal`?: NullableString; `kind`?: NullableString; `calls`?: numeric; `ok`?: numeric; `failed`?: numeric; `schemes`?: (string)[]; `resourceTypes`?: (string)[]; `firstAt`?: NumericOrStringOrNull; `lastAt`?: NumericOrStringOrNull; `lastOperation`?: NullableString; `lastStatus`?: NumericOrStringOrNull }

@hoisted model WithGrantDiscoveryRsDiscoveryEtc12 { `grant`?: string; `discovery`?: string; `rsDiscovery`?: string; `continuation`?: string; `tokenManagement`?: string; `introspection`?: string; `resourceRegistration`?: string; `userCode`?: string; `keys`?: string; `zcapController`?: string; `accessTokenStatusList`?: string; `biscuitRevocations`?: string }

@hoisted model WithDescriptionEvidenceDescriptionEtc6 { @js(#{`description`:"How the person's identity was verified, in at least 8 characters. Product mode requires it, and it is recorded in the audit log."}) `evidence`?: string; @js(#{`description`:"The name they sign in as."}) `username`: string; @js(#{`description`:"Accepted for `username`."}) `user`?: string }

@hoisted model WithIdTypeCanonicalEtc15 { `id`?: string; `type`?: string; `canonical`?: boolean; `name`?: string; `enabled`?: boolean; `refusedByMode`?: string; `setting`?: string; `primary`?: boolean; `scoped`?: boolean; `applicationScoped`?: boolean; `recorded`?: boolean; `challenged`?: boolean; `spec`?: string; `specUri`?: string; `description`?: string }

@hoisted model WithDescriptionKindMaxLengthEtc8 { @js(#{`description`:"Whether the entry is a person or an application."}) `kind`: "person" | "application"; @js(#{ `minLength`:1, `maxLength`:256, `description`:"The username or the application identifier, in this realm." }) `identifier`: string; @js(#{`minLength`:1,`maxLength`:253,`description`:"A DNS name or an IP address."}) `hostName`: string }

@hoisted model WithAttributeTypeWhatEtc16 { `attribute`?: string; `type`?: string; `what`?: string; `example`?: string; `forText`?: string; `families`?: (string)[]; `everyFamily`?: boolean; `group`?: string; `simple`?: boolean; `required`?: boolean; `label`?: string; `schema`?: string; `claim`?: (string)[]; `multi`?: boolean; `custom`?: boolean; `takes`?: string }

@hoisted model WithSerialHexLabelSubjectEtc112 { `serialHex`?: string; `label`?: NullableString; `subject`?: NullableString; `keyAlg`?: NullableString; `notBefore`?: StringOrNumericOrNull; `notAfter`?: StringOrNumericOrNull; `thumbprint`?: NullableString; `state`?: string; `reason`?: NullableString; `revokedAt`?: StringOrNumericOrNull; `certificatePem`?: NullableString }

@hoisted model WithDescriptionEvidenceDescriptionEtc62 { @js(#{`description`:"How the person's identity was verified, in at least 8 characters. Product mode requires it, and it is recorded in the audit log."}) `evidence`?: string; @js(#{`description`:"The person, as /admin-api/users names them."}) `user`: string; @js(#{`description`:"Accepted for `user`."}) `username`?: string }

@hoisted model WithStateFormatResponseTypeEtc14 { `state`?: string; `format`?: string; `responseType`?: string; `responseMode`?: string; `byReference`?: boolean; `clientId`?: string; `requested`?: (string)[]; `expiresAt`?: string; `received`?: boolean; `ok`?: NullableBoolean; `decidedAt`?: NullableString; `claims`?: (string)[]; `failedChecks`?: (string)[]; `error`?: string }

@hoisted model WithHeldStreamsHoldingSignedEtc13 { `held`?: integer; `streamsHolding`?: integer; `signed`?: integer; `unsigned`?: integer; `deadStreams`?: integer; `halfOpenStreams`?: integer; `failingStreams`?: integer; `pushStreams`?: integer; `oldestAt`?: string; `newestAt`?: string; `oldestAgeS`?: NullableNumber; `newestAgeS`?: NullableNumber; `deadLetteredEver`?: numeric }

@hoisted model WithAtOperationResourceTypeEtc12 { `at`?: NumericOrStringOrNull; `operation`?: NullableString; `resourceType`?: NullableString; `status`?: NumericOrStringOrNull; `ok`?: boolean; `scimType`?: NullableString; `scheme`?: NullableString; `principal`?: NullableString; `ms`?: NullableNumber; `bytes`?: NullableNumber; `method`?: NullableString; `path`?: NullableString }

@hoisted model WithEnabledReadyPerRealmEtc13 { `enabled`?: boolean; `ready`?: boolean; `perRealm`?: boolean; `trustDomain`?: NullableString; `authoritySource`?: string; `svidKeyType`?: string; `authorityKeyType`?: string; `x509KeyType`?: string; `jwtKeyType`?: string; `x509Authorities`?: integer; `authorityFingerprint`?: NullableString; `trustAnchors`?: integer; `jwtAuthorities`?: integer }

@hoisted model WithDnCnRuleEtc14 { `dn`?: string; `cn`?: string; `rule`?: string; `description`?: string; `objectClass`?: (string)[]; `origin`?: string; `createdAt`?: NullOrStringOrNumeric; `modifiedAt`?: NullOrStringOrNumeric; `memberCount`?: numeric; `presentCount`?: numeric; `danglingCount`?: numeric; `claimedCount`?: numeric; `ownerCount`?: numeric; `attributeCount`?: numeric }

@hoisted model WithNameWhatKindEtc16 { `name`?: string; `what`?: string; `kind`?: string; `from`?: string; `role`?: string; `standard`?: boolean; `sensitive`?: boolean; `secret`?: boolean; `identifier`?: boolean; `identifierName`?: string; `editable`?: BooleanOrString; `enum`?: (string)[]; `families`?: (string)[]; `familyWhy`?: string; `overrides`?: string; `strictOverride`?: boolean }

@hoisted model WithDescriptionPolicyDescriptionEtc4 { @js(#{ `description`:"The directory entry name of the policy to edit — the `cn` under ou=policies, not the PolicyId inside the document." }) `policy`: string; @js(#{ `description`:"The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule 1 now means rule 0." }) `path`: string }

@hoisted model WithMaxLengthDescriptionIdEtc6 { @js(#{ `maxLength`:2048, `description`:"The client: its identifier or its entry's DN." }) `id`: string; @js(#{ `maxLength`:64, `description`:"A service deployed as cells (#553): the cell the act is sent to. Without it the act goes to every cell that pushes to the client, and the answer lists each cell's result. Refused in a service that is one cell." }) `cell`?: string }

@hoisted model WithSeqOriginAtEtc16 { `seq`?: numeric; `origin`?: StringOrNumericOrNull; `at`?: numeric; `category`?: string; `action`?: string; `outcome`?: string; `errorCode`?: string; `actor`?: string; `actorForm`?: string; `mac`?: string; `prev`?: string; `target`?: string; `protocol`?: string; `channel`?: string; `address`?: string; `summary`?: string; @js(#{`description`:"What the event recorded."}) `detail`?: Record<StringOrNumericOrBoolean> }

@hoisted model WithNameAuthenticationsSessionsEtc15 { `name`?: NullableString; `authentications`?: numeric; `sessions`?: numeric; `users`?: numeric; `firstSeen`?: string; `lastSeen`?: string; `assertionConsumerServices`?: (string)[]; `nameIdFormats`?: (string)[]; `profiles`?: (string)[]; `identifier`?: string; `slug`?: NullableString; `idpProviderId`?: NullableString; `metadataUrl`?: string; `ssoUrl`?: string; `responderUrl`?: string }

@hoisted model WithStreamIdAudEndpointUrlEtc16 { `stream_id`?: string; `aud`?: NullOrStringOrString; `endpoint_url`?: string; `status`?: string; `state`?: string; `held`?: integer; `causes`?: Record<numeric>; `oldestAt`?: string; `newestAt`?: string; `deadLetteredEver`?: numeric; `deadSince`?: string; `failingSince`?: string; `nextProbeAt`?: string; `deadReason`?: string; `lastPushError`?: string; `lastPushAt`?: NullOrStringOrNumeric }

@hoisted model WithBaseLoginAcsEtc18 { `base`?: string; `login`?: string; `acs`?: string; `metadata`?: string; `link`?: string; `notifications`?: string; `stepup`?: string; `profile`?: string; `slo`?: string; `backchannelLogout`?: string; `frontchannelLogout`?: string; `jwks`?: string; `atprotoClient`?: string; `initiateLogin`?: string; `fragmentScript`?: string; `requestObject`?: string; `webfinger`?: string; `signals`?: string }

@hoisted model WithSpecVersionIssuerJwksUriEtc13 { `spec_version`?: string; `issuer`?: string; `jwks_uri`?: string; `delivery_methods_supported`?: (string)[]; `configuration_endpoint`?: string; `status_endpoint`?: string; `add_subject_endpoint`?: string; `remove_subject_endpoint`?: string; `verification_endpoint`?: string; `default_subjects`?: string; `authorization_schemes`?: ({`spec_urn`?: string})[]; `critical_subject_members`?: (string)[] }

@hoisted model WithNameAttributeCarriedEtc6 { `name`?: string; `attribute`?: string; `carried`?: boolean; @js(#{ `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.", `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path." }) `value`?: unknown }

@hoisted model WithRequestedClaimLdapEtc7 { `requested`?: string; `claim`?: string; `ldap`?: string; @js(#{ `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.", `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path." }) `value`?: unknown; `source`?: string }

@hoisted model WithMaxLengthDescriptionEntityIdEtc9 { @js(#{ `maxLength`:2048, `description`:"An Entity Identifier: an https URL with no query or fragment." }) `entityId`: string; @js(#{ `maxLength`:1000, `description`:"Recorded as the event_description of the event this act adds to the subordinate's history." }) `reason`?: string; @js(#{ `maxLength`:2048, `description`:"An http or https URL of a page about the event, recorded as its information_uri." }) `informationUri`?: string }

@hoisted model WithGrantRequestEndpointInteractionStartModesSupportedInteractionFinishMethodsSupportedEtc8 { `grant_request_endpoint`?: string; `interaction_start_modes_supported`?: StringOrStringOrBooleanEtc; `interaction_finish_methods_supported`?: StringOrStringOrBooleanEtc; `key_proofs_supported`?: StringOrStringOrBooleanEtc; `sub_id_formats_supported`?: StringOrStringOrBooleanEtc; `assertion_formats_supported`?: StringOrStringOrBooleanEtc; `key_rotation_supported`?: StringOrStringOrBooleanEtc; `token_formats_supported`?: StringOrStringOrBooleanEtc }

@hoisted model WithDescriptionPolicyDescriptionEtc6 { @js(#{ `description`:"The directory entry name of the policy to edit — the `cn` under ou=policies, not the PolicyId inside the document." }) `policy`: string; @js(#{ `description`:"The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule 1 now means rule 0." }) `path`?: string; @js(#{`description`:"Permit or Deny. Defaults to Permit."}) `on`?: "Permit" | "Deny" }

@hoisted model WithAtFamilyKindEtc20 { `at`?: NullableNumber; `family`?: string; `kind`?: string; `identifier`?: string; `flow`?: string; `flowLabel`?: NullableString; `flowProtocol`?: NullableString; `flowSpec`?: NullableString; `flowOidc`?: NullableString; `flowStated`?: boolean; `holder`?: string; `audience`?: string; `scope`?: string; `issuer`?: string; `state`?: NullableString; `sessionId`?: string; `revocable`?: boolean; `revoked`?: boolean; `detail`?: string; `expiresAtMs`?: NullableNumber }

@hoisted model WithLdapClaimXFreeFormEtc9 { `ldap`?: string; `claim`?: string; @js(#{ `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.", `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path." }) `value`?: unknown; `source`?: string; `ldpTerm`?: NullableString; `claimId`?: string; `values`?: (Shape5)[] }

@hoisted model WithStateKindIssuedAtEtc23 { `state`?: string; `kind`?: string; `issuedAt`?: numeric; `expiresAt`?: NullOrStringOrNumeric; `subject`?: string; `key`?: string; `id`?: string; `audience`?: string; `signed`?: boolean; `revoked`?: boolean; `revokedAt`?: numeric; `revokedVia`?: string; `realm`?: string; `service`?: string; `etype`?: StringOrNumeric; `claimSet`?: string; `username`?: string; `pacClaims`?: numeric; `entryId`?: string; `serial`?: string; `hint`?: string; `person`?: string; `configId`?: string }

@hoisted model WithEnabledRpNameRpIdEtc19 { `enabled`?: boolean; `rpName`?: string; `rpId`?: string; `algorithms`?: (string)[]; `attestation`?: string; `userVerification`?: string; `residentKey`?: string; `authenticatorAttachment`?: string; `timeoutMs`?: numeric; `credProps`?: boolean; `minPinLength`?: NullOrBooleanOrNumeric; `hints`?: (string)[]; `maxKeysPerPerson`?: numeric; `primaryAllowed`?: boolean; `mfaAllowed`?: boolean; `usernameless`?: boolean; `insecureAlgorithms`?: boolean; `pqcOnly`?: boolean; `pqcAlongsideClassical`?: boolean }

@hoisted model WithNameAuthenticationsSessionsEtc19 { `name`?: NullableString; `authentications`?: numeric; `sessions`?: numeric; `users`?: numeric; `firstSeen`?: string; `lastSeen`?: string; `assertionConsumerServices`?: (string)[]; `singleLogoutServices`?: (string)[]; `nameIdFormats`?: (string)[]; `responseBindings`?: (string)[]; `lastRequestSigned`?: boolean; `lastRequestVerification`?: string; `identifier`?: string; `slug`?: NullableString; `idpEntityId`?: NullableString; `metadataUrl`?: string; `ssoUrl`?: string; `sloUrl`?: string; `arsUrl`?: string }

@hoisted model WithTextVerifiedAddedAtEtc6 { `text`?: string; `verified`?: NullableBoolean; `addedAt`?: NullOrStringOrNumeric; @js(#{ `x-free-form`:"An RFC 9493 subject identifier, as a stream was given it or a person named it: the format decides the members, an `aliases` nests, and SSF 1.0 section 3.3 lets a receiver add its own.", `description`:"An RFC 9493 subject identifier, as a stream was given it or a person named it: the format decides the members, an `aliases` nests, and SSF 1.0 section 3.3 lets a receiver add its own." }) `subject`?: unknown }

@hoisted model WithJtiLabelFormatEtc11 { `jti`?: string; `label`?: NullableString; `format`?: string; `issuedAt`?: NullableNumber; `expiresAt`?: NullableNumber; `state`?: string; `bearer`?: boolean; @js(#{ `x-free-form`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines.", `description`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines." }) `access`?: unknown; `revokedWhy`?: NullableString }

@hoisted model WithDescriptionIdDescriptionEtc15 { @js(#{`description`:"The algorithm."}) `id`?: string; @js(#{`description`:"Its name on this surface."}) `spelling`?: string; @js(#{`description`:"pq or composite, or empty for a classical algorithm."}) `pqc`?: string; `weak`?: boolean; @js(#{`description`:"Whether this realm signs with it now."}) `signs`?: boolean; @js(#{`description`:"Why not, or empty."}) `signRefusal`?: string; @js(#{`description`:"Whether this realm accepts it now."}) `accepts`?: boolean; @js(#{`description`:"Why not, or empty."}) `acceptRefusal`?: string }

@hoisted model WithIdentifierNameRegisteredEtc23 { `identifier`?: string; `name`?: NullableString; `registered`?: boolean; `declared`?: boolean; `dn`?: string; `endpoints`?: (string)[]; `streams`?: (string)[]; `streamCount`?: integer; `enabled`?: integer; `deliveries`?: (string)[]; `audiences`?: (string)[]; `takes`?: (string)[]; `counts`?: Record<numeric>; `total`?: integer; `sessions`?: integer; `accounts`?: integer; `queued`?: integer; `delivered`?: integer; `failed`?: integer; `acknowledged`?: integer; `receiverErrors`?: integer; `lastPushAt`?: NullOrStringOrNumeric; `lastPushError`?: NullableString }

@hoisted model WithIdNameRoleEtc26 { `id`?: string; `name`?: string; `role`?: string; `roleLabel`?: string; `protocol`?: string; `protocolLabel`?: string; `peer`?: string; `application`?: string; `category`?: string; `provider`?: string; `providerLabel`?: string; `enabled`?: boolean; `ready`?: boolean; `missing`?: (string)[]; `usable`?: boolean; `signsIn`?: boolean; `signalsEnabled`?: boolean; `releases`?: (string)[]; `mappings`?: (string)[]; `authentications`?: integer; `users`?: integer; `lastUser`?: string; `lastSeen`?: string; `lastError`?: string; `lastErrorAt`?: string; `dn`?: string }

@hoisted model WithUserDescriptionByLdapEtc13 { `user`?: string; @js(#{`description`:"By directory attribute."}) `byLdap`?: Record<{ `ldap`?: string; `claim`?: string; @js(#{ `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.", `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path." }) `value`?: unknown; `source`?: string; `ldpTerm`?: NullableString; `claimId`?: string; `values`?: (Shape5)[] }>; `entryFound`?: boolean }

@hoisted model WithStateKeyJtiEtc29 { `state`?: string; `key`?: string; `jti`?: string; `kind`?: string; `typ`?: string; `revocable`?: boolean; `sub`?: string; `iss`?: string; `username`?: string; `client_id`?: StringOrString; `audience`?: string; `scope`?: StringOrString; `jkt`?: string; `x5t`?: string; `x5tSpki`?: string; `iat`?: numeric; `nbf`?: numeric; `exp`?: numeric; `sessionId`?: string; `sessionAuthenticated`?: boolean; `setId`?: string; `grant`?: string; `grantId`?: string; `grantRefresh`?: boolean; `issuedAt`?: numeric; `revoked`?: boolean; `revokedAt`?: numeric; `revokedVia`?: string; `length`?: numeric }

@hoisted model WithDescriptionTotalDescriptionEtc12 { @js(#{ `description`:"How many there are in all, which is what to page through rather than the length of this array." }) `total`?: integer; @js(#{ `description`:"The page these rows are from, CLAMPED — `?page=999` on a two-page list reports 2, which is the page in the reply." }) `page`?: integer; @js(#{`description`:"How many pages the match has."}) `pages`?: integer; @js(#{`description`:"Rows per page, clamped to the cap."}) `perPage`?: integer; @js(#{`description`:"1-based and inclusive; 0 when nothing matched."}) `firstRow`?: integer; @js(#{`description`:"1-based and inclusive."}) `lastRow`?: integer }

@hoisted model WithSeqOriginAtEtc17 { `seq`?: numeric; `origin`?: string; `at`?: numeric; `category`?: string; `action`?: string; `outcome`?: string; `errorCode`?: string; `actor`?: string; `actorForm`?: string; `mac`?: string; `prev`?: string; `target`?: string; `protocol`?: string; `channel`?: string; `address`?: string; `summary`?: string; @js(#{ `x-free-form`:"What the call site that wrote the audit row chose to record, which differs at each of hundreds of them; the keys and the values are data.", `description`:"What the call site that wrote the audit row chose to record, which differs at each of hundreds of them; the keys and the values are data." }) `detail`?: unknown }

@hoisted model WithNameDnIdentityEtc25 { `name`?: string; `dn`?: string; `identity`?: string; `certificateSubject`?: string; `thumbprint`?: string; `authenticated`?: boolean; `notifyUrl`?: string; `bias`?: string; `resource`?: string; `description`?: string; `version`?: string; `enabled`?: boolean; `registeredAt`?: string; `lastSeen`?: string; `syncToken`?: string; `policyCount`?: NullableNumber; `decisions`?: NullableNumber; `allowed`?: NullableNumber; `refused`?: NullableNumber; `undischargeable`?: NullableNumber; `lastNotify`?: string; `current`?: boolean; `stale`?: boolean; `notifyProblem`?: NullableString; `listenerCertificate`?: NullableObject102 }

@hoisted model WithSeqOriginAtEtc172 { `seq`?: numeric; `origin`?: NullableString; `at`?: numeric; `category`?: string; `action`?: string; `outcome`?: string; `errorCode`?: NullableString; `actor`?: string; `actorForm`?: string; `mac`?: string; `prev`?: string; `target`?: string; `protocol`?: string; `channel`?: string; `address`?: string; `summary`?: string; @js(#{ `x-free-form`:"What this one kind of event recorded about its own act: several hundred call sites each name their members, and values are trimmed by `detailOf()`.", `description`:"What this one kind of event recorded about its own act: several hundred call sites each name their members, and values are trimmed by `detailOf()`." }) `detail`?: unknown }

@hoisted model WithMemberXFreeFormDescriptionEtc9 { `member`?: string; @js(#{ `x-free-form`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines.", `description`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines." }) `published`?: unknown; @js(#{ `x-free-form`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines.", `description`:"An RFC 8414 metadata member's value as the operator chose to publish it: any JSON, deliberately, including what no specification defines." }) `actual`?: unknown; `kind`?: string; `what`?: string }

@hoisted model WithKeyGroupLabelEtc32 { `key`?: string; `group`?: string; `label`?: string; `description`?: string; `type`?: string; `enumValues`?: (string)[]; `csvValues`?: (string)[]; `ordered`?: boolean; @js(#{`description`:"The sentence beside each value."}) `csvValueNotes`?: Record<string>; @js(#{`description`:"The rules by kind: onlyWhileOn and aloneWhileOn."}) `selectAll`?: Record<({ `setting`?: string; `values`?: (string)[]; `on`?: boolean; `canBeOn`?: boolean })[]>; `min`?: numeric; `max`?: numeric; `step`?: numeric; `value`?: BooleanOrNumericOrStringEtc; `text`?: NullableString; `source`?: string; `editable`?: boolean; `restartReason`?: string; `editRefusal`?: string; `env`?: NullableString; `legacyEnv`?: NullableString; `appconfigPath`?: string; `default`?: BooleanOrNumericOrStringEtc; `masked`?: boolean; `realmSettable`?: boolean; `overridden`?: boolean }

@hoisted model WithIdRecordedSourceEtc10 { `id`?: string; `recorded`?: NullOrStringOrNumeric2; `source`?: string; `by`?: string; @js(#{ `x-free-form`:"The OpenID Connect for Identity Assurance `verification` element: a caller may post it whole as JSON, and a wallet or a certificate may supply it, so its evidence is that specification's to shape.", `description`:"The OpenID Connect for Identity Assurance `verification` element: a caller may post it whole as JSON, and a wallet or a certificate may supply it, so its evidence is that specification's to shape." }) `verification`?: unknown; @js(#{ `x-free-form`:"The verified claims and their values, as the OpenID Connect claim each is: a string for most, an object for `address`, a list for `nationalities`.", `description`:"The verified claims and their values, as the OpenID Connect claim each is: a string for most, an object for `address`, a list for `nationalities`." }) `claims`?: unknown }

@hoisted model WithDescriptionPolicyDescriptionEtc12 { @js(#{ `description`:"The directory entry name of the policy to edit — the `cn` under ou=policies, not the PolicyId inside the document." }) `policy`: string; @js(#{ `description`:"The node's address, from GET /admin-api/xacml/editor. ONLY VALID AGAINST THE DOCUMENT IT WAS READ FROM: remove rule 0 and every path naming rule 1 now means rule 0." }) `path`: string; @js(#{ `description`:"The match function. Defaults to string-equal. THE DATATYPE FOLLOWS IT on both sides, so choosing the function settles the literal's type and the designator's together." }) `matchId`?: string; @js(#{`description`:"The literal to test against."}) `value`?: string; @js(#{`description`:"The attribute category. Defaults to access-subject."}) `category`?: string; @js(#{ `description`:"The attribute to read. A bare name or the `urn:sts:xacml:attribute:` prefix reaches the directory through the PIP; anything else must be in the request." }) `attributeId`?: string }

@hoisted model WithApplicationAttributeValue { `application`: string; `attribute`: "appCorsOrigin" | "appAllowedProtocol" | "oauthClientId" | "oauthAudience" | "oauthRedirectUri" | "oauthClaimsRedirectUri" | "oauthPostLogoutRedirectUri" | "oauthGrantType" | "oauthResponseType" | "oauthAllowedTokenResponseTypes" | "oauthScope" | "oauthAllowedScope" | "oauthPermission" | "oauthRoleGatedPermission" | "oauthDelegatedPermission" | "oauthGlobalConsent" | "oauthTokenEndpointAuthMethod" | "oauthRequestUri" | "oauthAuthorizationDetailsType" | "oauthAuthorizationDetailsTypes" | "authzenAttribute" | "appAuthzenApplication" | "appAuthzenCallbackUri" | "oauthAssertionIssuer" | "oauthSamlAssertionIssuer" | "oauthSoftwareStatementIssuer" | "samlEntityId" | "samlAssertionConsumerService" | "samlSingleLogoutService" | "samlSigningCertificate" | "oauthAccessTokenClaim" | "appRequiredRole" | "appAllowedToDelegateTo" | "appAllowedToActOnBehalfOf" | "appDelegationSubjectGroup" | "appDelegationSemantics" | "wsfedRealm" | "wsfedReplyUrl" | "wsfedSignOutUri" | "wstrustAppliesTo" | "wstrustJwtScope" | "krb5ServicePrincipalName" | "krb5S4uSelfRealm" | "oid4vpClientId" | "federationPartnerId" | "ldapBindDn" | "scimClientId" | "acmeAllowedProfiles" | "estAllowedProfiles" | "scepAllowedProfiles" | "didPublicKeyJwk" | "didService" | "didAlsoKnownAs" | "scimClientScopeGroups" | "scimClientGroups" | "scimClientCells" | "ssfReceiverId" | "ssfDeliveryEndpoint" | "ssfAllowedEvents" | "gnapFinishUri" | "gnapInteractionStartModes" | "gnapAllowedAccess" | "gnapResourceServerUri" | "spiffeWorkloadId" | "appFederationRelationship"; `value`: string }

@hoisted model WithFedIdCnFedNameEtc89 { `fedId`?: string; `cn`?: string; `fedName`?: string; `fedRole`?: string; `fedProtocol`?: string; `fedProvider`?: string; `fedPeer`?: string; `fedLocalEntityId`?: string; `fedEnabled`?: string; `fedSsoUrl`?: string; `fedTokenUrl`?: string; `fedUserinfoUrl`?: string; `fedJwksUri`?: string; `fedEmailsUrl`?: string; `fedJwks`?: string; `fedTrustAnchor`?: string; `fedSigningCertificate`?: string; `fedClientId`?: string; `fedClientSecret`?: string; `fedResponseMode`?: string; `fedTeamId`?: string; `fedKeyId`?: string; `fedClientSigningKey`?: string; `fedTokenAuth`?: string; `fedScope`?: string; `fedResponseType`?: string; `fedIdTokenSignedResponseAlg`?: string; `fedUserinfoSignedResponseAlg`?: string; `fedRefreshTokens`?: string; `fedRefreshEverySeconds`?: string; `fedRegister`?: string; `fedRegisteredIssuer`?: string; `fedRequestObject`?: string; `fedRequestObjectSigningAlg`?: string; `fedWebFinger`?: string; `fedDiscovery`?: string; `fedFapi`?: string; `fedInitiateLogin`?: string; `fedBinding`?: string; `fedSignRequest`?: string; `fedUsernameSource`?: string; `fedSubjectClaim`?: string; `fedAutocreateUsers`?: string; `fedUpdateUserAttributes`?: string; `fedProvisionGroups`?: string; `fedProvisionCap`?: string; `fedProvisionIdleMinutes`?: string; `fedSubjectPolicy`?: string; `fedSubjectPattern`?: string; `fedMayAssertAdministrators`?: string; `fedSignalEmailMatch`?: string; `fedSignalsEnabled`?: string; `fedSignalsIssuer`?: string; `fedSignalsDelivery`?: string; `fedSignalsTokenUrl`?: string; `fedSignalsClientId`?: string; `fedSignalsClientSecret`?: string; `fedSignalsScope`?: string; `fedSignalsBearer`?: string; `fedSloUrl`?: string; `fedSloBinding`?: string; `fedEndSessionUrl`?: string; `fedAcceptSignout`?: string; `fedRequireSignedLogout`?: string; `fedEncryptionKeyType`?: string; `fedKeyManagementAlgorithm`?: string; `fedContentEncryptionAlgorithm`?: string; `fedAllowUnencrypted`?: string; `fedAllowUnsolicited`?: string; `fedApplication`?: string; `fedAuthnMechanism`?: string; `fedAuthnRelationship`?: string; `fedFirstSeen`?: string; `fedLastSeen`?: string; `fedAuthentications`?: string; `fedUsers`?: string; `fedLastUser`?: string; `fedLastError`?: string; `fedLastErrorAt`?: string; `description`?: (string)[]; `fedAllowedTenants`?: (string)[]; `fedAuthorizeParams`?: (string)[]; `fedAttributeMap`?: (string)[]; `fedSubjectGroup`?: (string)[]; `fedSubjectDomain`?: (string)[]; `fedHomeRealmDomain`?: (string)[]; `fedSignalsEvents`?: (string)[]; `fedEncryptionKey`?: string; `fedRelease`?: (string)[]; `fedApplicationUse`?: (string)[] }

@hoisted model WithDnCreatedAtModifiedAtEtc99 { `dn`?: string; `createdAt`?: string; `modifiedAt`?: string; `ready`?: boolean; `missing`?: (string)[]; @js(#{ `description`:"Attribute names, which are data in a schemaless directory, and values." }) `entryAttributes`?: Record<NullOrStringOrString2>; `roleShort`?: string; `protocolLabel`?: string; `enabled`?: boolean; `fedId`?: string; `cn`?: string; `fedName`?: string; `fedRole`?: string; `fedProtocol`?: string; `fedProvider`?: string; `fedPeer`?: string; `fedLocalEntityId`?: string; `fedEnabled`?: string; `fedSsoUrl`?: string; `fedTokenUrl`?: string; `fedUserinfoUrl`?: string; `fedJwksUri`?: string; `fedEmailsUrl`?: string; `fedJwks`?: string; `fedTrustAnchor`?: string; `fedSigningCertificate`?: string; `fedClientId`?: string; `fedClientSecret`?: string; `fedResponseMode`?: string; `fedTeamId`?: string; `fedKeyId`?: string; `fedClientSigningKey`?: string; `fedTokenAuth`?: string; `fedScope`?: string; `fedResponseType`?: string; `fedIdTokenSignedResponseAlg`?: string; `fedUserinfoSignedResponseAlg`?: string; `fedRefreshTokens`?: string; `fedRefreshEverySeconds`?: string; `fedRegister`?: string; `fedRegisteredIssuer`?: string; `fedRequestObject`?: string; `fedRequestObjectSigningAlg`?: string; `fedWebFinger`?: string; `fedDiscovery`?: string; `fedFapi`?: string; `fedInitiateLogin`?: string; `fedBinding`?: string; `fedSignRequest`?: string; `fedUsernameSource`?: string; `fedSubjectClaim`?: string; `fedAutocreateUsers`?: string; `fedUpdateUserAttributes`?: string; `fedProvisionGroups`?: string; `fedProvisionCap`?: string; `fedProvisionIdleMinutes`?: string; `fedSubjectPolicy`?: string; `fedSubjectPattern`?: string; `fedMayAssertAdministrators`?: string; `fedSignalEmailMatch`?: string; `fedSignalsEnabled`?: string; `fedSignalsIssuer`?: string; `fedSignalsDelivery`?: string; `fedSignalsTokenUrl`?: string; `fedSignalsClientId`?: string; `fedSignalsClientSecret`?: string; `fedSignalsScope`?: string; `fedSignalsBearer`?: string; `fedSloUrl`?: string; `fedSloBinding`?: string; `fedEndSessionUrl`?: string; `fedAcceptSignout`?: string; `fedRequireSignedLogout`?: string; `fedEncryptionKeyType`?: string; `fedKeyManagementAlgorithm`?: string; `fedContentEncryptionAlgorithm`?: string; `fedAllowUnencrypted`?: string; `fedAllowUnsolicited`?: string; `fedApplication`?: string; `fedAuthnMechanism`?: string; `fedAuthnRelationship`?: string; `fedFirstSeen`?: string; `fedLastSeen`?: string; `fedAuthentications`?: string; `fedUsers`?: string; `fedLastUser`?: string; `fedLastError`?: string; `fedLastErrorAt`?: string; `description`?: (string)[]; `fedAllowedTenants`?: (string)[]; `fedAuthorizeParams`?: (string)[]; `fedAttributeMap`?: (string)[]; `fedSubjectGroup`?: (string)[]; `fedSubjectDomain`?: (string)[]; `fedHomeRealmDomain`?: (string)[]; `fedSignalsEvents`?: (string)[]; `fedEncryptionKey`?: (string)[]; `fedRelease`?: (string)[]; `fedApplicationUse`?: (string)[] }

@hoisted model WithStreams { `streams`?: WithPagePagesPerPageEtc8 }

@hoisted model WithReceived2 { `received`?: WithPagePagesPerPageEtc8 }

@hoisted model WithModelKeys { `model`?: string; `keys`?: (WithGroupSlotAlgEtc7)[] }

@hoisted model WithHasPasswordRules { `hasPassword`?: boolean; `rules`?: WithEnforcedRules }

@hoisted model WithOauthAllowedScope { `oauthAllowedScope`?: (WithValuePermissionApiEtc4)[] }

@hoisted model WithGroupSettings3 { `group`?: string; `settings`?: (WithKeyGroupLabelEtc32)[] }

@hoisted model WithOnCatalogue { `on`?: boolean; `catalogue`?: (WithIdLabelProtocolEtc12)[] }

@hoisted model WithClientNameRows { `client`?: string; `name`?: string; `rows`?: (WithScopeAt)[] }

@hoisted model WithRowsSkew { `rows`?: (WithSettingAttributeLabelEtc6)[]; `skew`?: numeric }

@hoisted model WithFamiliesDistinctSubjects { `families`?: (WithFamilySubjectsWho)[]; `distinctSubjects`?: integer }

@hoisted model WithLifetimesClockSkewS { `lifetimes`?: (WithSettingAttributeLabelEtc6)[]; `clockSkewS`?: numeric }

@hoisted model WithUserGroup { `user`?: (WithScimLdapKindEtc10)[]; `group`?: (WithScimLdapKindEtc10)[] }

@hoisted model WithPreAuthorizedCodeTxCode { `pre-authorized_code`?: string; `tx_code`?: WithInputModeLengthDescription }

@hoisted model WithLettersStreams { `letters`?: WithPagePagesPerPageEtc8; `streams`?: WithPagePagesPerPageEtc8 }

@hoisted model WithNowEveryMsAnnouncements { `now`?: numeric; `everyMs`?: numeric; `announcements`?: (WithIdAtMessage)[] }

@hoisted model WithKindRidDidEtc4 { `kind`?: string; `rid`?: string; `did`?: string; `file`?: WithNameMimeBase64 }

@hoisted model WithShownPaging { `shown`?: (WithTypeProtocolModeEtc7)[]; `paging`?: WithPagePagesPerPageEtc82 }

@hoisted model WithPagingShown { `paging`?: WithPagePerPagePagesEtc9; `shown`?: (WithAttributeValueHeldEtc4)[] }

@hoisted model WithKindRemovableAdditions { `kind`?: string; `removable`?: boolean; `additions`?: (WithActionLabelHelp)[] }

@hoisted model WithKindPagingRows { `kind`?: string; `paging`?: WithPagePagesPerEtc4; `rows`?: (WithNameIdDnEtc6)[] }

@hoisted model WithPermissionsGrants2 { `permissions`?: WithPagePagesPerPageEtc82; `grants`?: WithPagePagesPerPageEtc82 }

@hoisted model WithKeysValidIssuers { `keys`?: (WithHandleLabelSourceEtc11)[]; `valid`?: integer; `issuers`?: (string)[] }

@hoisted model WithShownPaging2 { `shown`?: (WithMechanismTypeFrontEndEtc12)[]; `paging`?: WithPagePagesPerPageEtc82 }

@hoisted model WithShownPaging3 { `shown`?: (WithUsernameDnNotDelegatedEtc6)[]; `paging`?: WithPagePagesPerPageEtc82 }

@hoisted model WithStepUpOkMessageEtc4 {`stepUp`?: WithAcrValuesPromptMaxAge; `ok`?: boolean; `message`?: string; `go`?: string}

@hoisted model WithObjectClassesAttributes { `objectClasses`?: (WithNameWhatWhereEtc4)[]; `attributes`?: (WithNameWhatKindEtc16)[] }

@hoisted model WithEnrolledKeysRoaming { `enrolled`?: integer; `keys`?: (WithCredentialIdNameTrusted)[]; `roaming`?: (string)[] }

@hoisted model WithOkErrorsErrorEtc42 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithEnabledTypedRecord }

@hoisted model WithShownPaging4 { `shown`?: (WithPrincipalRealmNotDelegatedEtc8)[]; `paging`?: WithPagePagesPerPageEtc82 }

@hoisted model WithOkMessageGoEtc42 { `ok`?: boolean; `message`?: string; `go`?: string; `view`?: WithVerifiedAddressUsername }

@hoisted model WithPagingRows { `paging`?: WithPagePagesPerPageEtc8; `rows`?: (WithReferenceResourceServerAccessEtc6)[] }

@hoisted model WithPagingShown2 { `paging`?: WithPagePerPagePagesEtc9; `shown`?: (WithClientClientNamePermissionIdEtc10)[] }

@hoisted model WithShownPaging5 { `shown`?: (WithMechanismIntermediaryTargetEtc11)[]; `paging`?: WithPagePagesPerPageEtc82 }

@hoisted model WithPerformedDecodeOnlyPreference { `performed`?: (WithIdName2)[]; `decodeOnly`?: (WithIdName2)[]; `preference`?: (integer)[] }

@hoisted model WithOnlyWhileOnAloneWhileOn { `onlyWhileOn`?: (WithSettingValuesOnEtc4)[]; `aloneWhileOn`?: (WithSettingValuesOnEtc4)[] }

@hoisted model WithShownPaging6 { `shown`?: (WithClientClientNamePermissionIdEtc102)[]; `paging`?: WithPagePagesPerPageEtc82 }

@hoisted model WithOkErrorsErrorEtc43 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithPseudonymsPendingCapEtc5 }

@hoisted model WithVerificationsTotalLimit { `verifications`?: (WithStateFormatResponseTypeEtc14)[]; `total`?: integer; `limit`?: integer }

@hoisted model WithShownPaging7 { `shown`?: (WithApplicationImpersonatesSemanticsEtc6)[]; `paging`?: WithPagePagesPerPageEtc82 }

@hoisted model WithOkErrorsErrorEtc44 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithThreeFieldsNoteTooManyEtc4 }

@hoisted model WithIdLabelCountEtc4 { `id`?: string; `label`?: string; `count`?: integer; `claims`?: (WithNameValueNameFormatEtc7)[] }

@hoisted model WithAlgorithmsGeneratedKeysEtc4 { `algorithms`?: (string)[]; `generated`?: boolean; `keys`?: (WithAlgKtyKidEtc4)[]; `what`?: string }

@hoisted model WithHeldForgottenCapEtc4 { `held`?: numeric; `forgotten`?: numeric; `cap`?: numeric; `byKind`?: (WithKindIssuedValidEtc52)[] }

@hoisted model WithPairsAccounts { `pairs`?: (WithMechanismTypeFrontEndEtc12)[]; `accounts`?: (WithPrincipalRealmNotDelegatedEtc8)[] }

@hoisted model WithSetMultiMultiAll { `set`?: (WithNameSensitive)[]; `multi`?: (WithNameSensitive)[]; `multiAll`?: (WithNameSensitive)[] }

@hoisted model WithOkUnreadablePasswordsEtc4 { `ok`?: boolean; `unreadable`?: boolean; `passwords`?: (WithIdNameDoorsEtc8)[]; `errors`?: (string)[] }

@hoisted model WithIdLabelClaimsEtc4 { `id`?: string; `label`?: string; `claims`?: (WithNameValueAttributeEtc8)[]; `attributes`?: (string)[] }

@hoisted model WithProvidersConnectedNoticeEtc4 { `providers`?: (WithIdNameProviderEtc5)[]; `connected`?: integer; `notice`?: string; `problem`?: string }

@hoisted model WithDaysThisSessionPagingEtc4 { `days`?: numeric; `thisSession`?: string; `paging`?: WithPagePagesPerEtc4; `rows`?: (WithIdAtCityEtc12)[] }

@hoisted model WithPermissionsStaleCatalogue { `permissions`?: (WithNameDescriptionIdEtc4)[]; `stale`?: (string)[]; `catalogue`?: (WithLdapClaimLabel)[] }

@hoisted model WithIdLabelBlurbEtc5 { `id`?: string; `label`?: string; `blurb`?: string; `what`?: string; `parameters`?: (WithNameLabelHelpEtc5)[] }

@hoisted model WithAvailableKeyAlgLeafLifetimeDaysEtc4 { `available`?: boolean; `keyAlg`?: string; `leafLifetimeDays`?: numeric; `keyAlgorithms`?: (WithIdLabelKind)[] }

@hoisted model WithAvailableKeyAlgKeyAlgorithmsEtc4 { `available`?: boolean; `keyAlg`?: string; `keyAlgorithms`?: (WithIdLabelKind)[]; `leafLifetimeDays`?: numeric }

@hoisted model WithApplicationKnownEnforcedEtc4 { `application`?: string; `known`?: boolean; `enforced`?: boolean; `policies`?: (WithNamePolicyIdVersionEtc6)[] }

@hoisted model WithKeyManagementOutKeyManagementInContentEncryption { `keyManagementOut`?: (string)[]; `keyManagementIn`?: (string)[]; `contentEncryption`?: (WithEncBitsModeEtc6)[] }

@hoisted model WithProtocolCountFirstAtEtc5 { `protocol`?: string; `count`?: numeric; `firstAt`?: numeric; `lastAt`?: numeric; `methods`?: (WithMethodCount)[] }

@hoisted model WithHeldExposesGrantedOut { `held`?: WithPagePagesPerPageEtc8; `exposes`?: WithPagePagesPerPageEtc8; `grantedOut`?: WithPagePagesPerPageEtc8 }

@hoisted model WithHeldForgottenCapEtc5 { `held`?: integer; `forgotten`?: integer; `cap`?: numeric; `revoked`?: integer; `byKind`?: (WithKindIssuedValidEtc8)[] }

@hoisted model WithHeldHeldHereForgottenEtc5 { `held`?: integer; `heldHere`?: integer; `forgotten`?: integer; `cap`?: integer; `byKind`?: (WithKindIssuedValidEtc5)[] }

@hoisted model WithTotalEntriesSliceEtc5 { `total`?: integer; `entries`?: (WithKeyNamesLabelEtc5)[]; `slice`?: WithMatchedFrom; `search`?: string; `complete`?: boolean }

@hoisted model WithRetentionSMaxPerStreamDeadStreamTimeoutSEtc4 { `retentionS`?: numeric; `maxPerStream`?: numeric; `deadStreamTimeoutS`?: numeric; `pushes`?: WithActiveWaitingConcurrencyEtc4 }

@hoisted model WithAttributeProblemKeysEtc4 { `attribute`?: string; `problem`?: string; `keys`?: (WithKidKtyAlgEtc5)[]; `certificates`?: (WithSubjectIssuerSerialHexEtc102)[] }

@hoisted model WithDidUrlOkEtc6 { `did`?: NullableString; `url`?: string; `ok`?: boolean; `why`?: string; `methods`?: (WithKidKtyCrvEtc5)[]; `origins`?: (string)[] }

@hoisted model WithProvidersPagingLinkedEtc5 { `providers`?: (WithIdNameIssuerEtc6)[]; `paging`?: WithPagePagesPerEtc4; `linked`?: integer; `notice`?: string; `problem`?: string }

@hoisted model WithHereRemoteCombined { `here`?: WithDecisionsAllowedRefusedEtc5; `remote`?: WithDecisionsAllowedRefusedEtc5; `combined`?: WithDecisionsAllowedRefusedEtc5 }

@hoisted model WithStateAccountsPreselectedEtc4 { `state`?: "accounts"; `accounts`?: (WithKeyUsernameDisplayNameEtc4)[]; `preselected`?: string; `naming`?: "open" | "off" | "product" }

@hoisted model WithIdClientRequestingPartyEtc5 { `id`?: string; `client`?: string; `requestingParty`?: string; `permissions`?: (WithResourceIdResourceScopes)[]; `expiresAt`?: numeric }

@hoisted model WithOkErrorsUserEtc6 { `ok`?: boolean; `errors`?: (string)[]; `user`?: string; `dn`?: string; `certificates`?: (WithSha256SubjectIssuerEtc8)[]; `rule`?: string }

@hoisted model WithIdFormatNameEtc6 { `id`?: string; `format`?: string; `name`?: string; `issuerDid`?: boolean; `signingAlgs`?: (WithAlgWhatSpec)[]; `defaultSigningAlg`?: string }

@hoisted model WithHeldHeldOnlyForgottenEtc6 { `held`?: integer; `heldOnly`?: boolean; `forgotten`?: integer; `cap`?: integer; `revoked`?: integer; `byKind`?: (WithKindIssuedValidEtc8)[] }

@hoisted model WithOnAllowedHostsTimeoutMsEtc4 { `on`?: boolean; `allowedHosts`?: (string)[]; `timeoutMs`?: numeric; `transport`?: WithAllowHttpSkipTlsVerificationSetSkipTlsVerificationEtc4 }

@hoisted model WithHeldOfferableRequiredEtc4 { `held`?: (WithNameIdDisplayNameEtc6)[]; `offerable`?: (string)[]; `required`?: (WithNameResolvesDisplayNameEtc4)[]; `requirable`?: (string)[] }

@hoisted model WithIdLabelCapabilities { `id`?: string; `label`?: string; `capabilities`?: WithGrantRequestEndpointInteractionStartModesSupportedInteractionFinishMethodsSupportedEtc8 }

@hoisted model WithAlgorithmRootPublicKeyRevocationEndpointEtc5 { `algorithm`?: string; `root_public_key`?: string; `revocation_endpoint`?: string; `jwk`?: WithKtyUseAlgEtc17; `root_public_keys`?: (string)[] }

@hoisted model WithLdapClaimLabelEtc7 { `ldap`?: string; `claim`?: string; `label`?: string; `schema`?: string; `ldpTerm`?: string; `selected`?: boolean; `example`?: WithValueSource2 }

@hoisted model WithNameDescriptionIdEtc5 { `name`?: NullableString; `description`?: NullableString; `id`?: NullableString; `raw`?: NullableString; `grantedTo`?: (WithIdentifierNameAsked)[] }

@hoisted model WithStateOfferedOptionalEtc6 { `state`?: "choose" | "totp"; `offered`?: WithTotpWebauthn; `optional`?: boolean; `proved`?: boolean; `recovery`?: boolean; `totp`?: NullableObject35 }

@hoisted model WithOkErrorsApplicationEtc6 { `ok`?: boolean; `errors`?: (string)[]; `application`?: string; `dn`?: NullableString; `certificates`?: (WithSha256SubjectIssuerEtc8)[]; `rule`?: string }

@hoisted model WithIdResourceIdScopesEtc7 { `id`?: string; `resourceId`?: string; `scopes`?: (string)[]; `recipient`?: WithKindValueClaimEtc4; `expires`?: string; `acr`?: string; `askMe`?: boolean }

@hoisted model WithBlockCiphersKeyTransportsConfigured { `blockCiphers`?: (WithNameUriKeyBitsEtc6)[]; `keyTransports`?: (WithNameUriSchemeEtc4)[]; `configured`?: WithBlockCipherKeyTransportEncryptAssertionEtc4 }

@hoisted model WithMlDsaSlhDsaCompositeEtc6 { `mlDsa`?: (string)[]; `slhDsa`?: (string)[]; `composite`?: (WithAlgMlDsaTraditionalEtc5)[]; `keyType`?: string; `what`?: string; `independence`?: string }

@hoisted model WithJwsXmlDigestMethodsScimDigestEtc5 { `jws`?: (string)[]; `xmlDigestMethods`?: (WithUriLabel)[]; `scimDigest`?: (WithTokenHash)[]; `fixed`?: (WithWhereHashWhat)[]; `weak`?: (WithHashWhereWhy)[] }

@hoisted model WithSessionsApplicationsStreamsEtc4 { `sessions`?: WithPagePagesPerPageEtc8; `applications`?: WithPagePagesPerPageEtc8; `streams`?: WithPagePagesPerPageEtc8; `events`?: WithPagePagesPerPageEtc8 }

@hoisted model WithAccountsApplicationsStreamsEtc4 { `accounts`?: WithPagePagesPerPageEtc8; `applications`?: WithPagePagesPerPageEtc8; `streams`?: WithPagePagesPerPageEtc8; `events`?: WithPagePagesPerPageEtc8 }

@hoisted model WithUsernameTokenBaseEtc8 { `username`?: string; `token`?: string; `base`?: string; `rules`?: WithEnforcedRules; `refused`?: string; `tooMany`?: boolean; `done`?: boolean; `signIn`?: string }

@hoisted model WithOptedInKindUsableEtc8 { `optedIn`?: string; `kind`?: string; `usable`?: boolean; `why`?: string; `verified`?: boolean; `address`?: string; `offered`?: WithCodeLink; `failures`?: numeric }

@hoisted model WithVersionIdCreatedChangeEtc5 { `versionId`?: StringOrNumeric; `created`?: NullOrStringOrNumeric2; `change`?: string; `keys`?: (WithIdKtyCrvEtc4)[]; `authorizedBy`?: (WithKindSubjectActorEtc7)[] }

@hoisted model WithBucketSWindowSFromEtc7 { `bucketS`?: numeric; `windowS`?: numeric; `from`?: string; `to`?: string; `buckets`?: (WithStartStartMsTotalEtc4)[]; `peak`?: integer; `olderThanWindow`?: integer }

@hoisted model WithIdFormatMetaEtc6 { `id`?: string; `format`?: string; `meta`?: WithVctValuesDoctypeValueTypeValues; `require_cryptographic_holder_binding`?: boolean; `claims`?: ({`path`?: (string)[]})[] }

@hoisted model WithKdcPersonPrincipalEtc7 { `kdc`?: boolean; `person`?: boolean; `principal`?: string; `productKdc`?: boolean; `disabled`?: boolean; `keys`?: NullableObject16; `made`?: WithPrincipalKvnoEtypesEtc6 }

@hoisted model WithJwsXmlCanonicalizationEtc5 { `jws`?: (WithAlgFamilyKtyEtc9)[]; `xml`?: (WithUriLabelFamilyEtc7)[]; `canonicalization`?: (WithUriLabelExclusiveEtc5)[]; `cose`?: (WithCoseAlgJose)[]; `other`?: (WithNameWhat)[] }

@hoisted model WithAttributeRoleKindEtc8 { `attribute`?: string; `role`?: string; `kind`?: string; `editable`?: StringOrBoolean; `sensitive`?: boolean; `what`?: string; `families`?: (WithIdLabel)[]; `everyFamily`?: boolean }

@hoisted model WithNegotiatedDescriptionCatalogsEtc4 { `negotiated`?: WithLocaleChainCatalogEtc5; @js(#{`description`:"Each catalog along the chain, by language tag."}) `catalogs`?: Record<ListOfRecordString>; `offered`?: (WithTagName)[] }

@hoisted model WithSignInTrustedNoteEtc7 { `signIn`?: string; `trusted`?: boolean; `note`?: string; `maxPerPerson`?: numeric; `keyAlgs`?: (string)[]; `defaultKeyAlg`?: NullableString; `held`?: (WithLabelSerialHexKeyAlgEtc7)[] }

@hoisted model WithIdLabelAttributeEtc6 { `id`?: string; `label`?: string; `attribute`?: string; `realm`?: (WithNameValueNameFormatEtc7)[]; `own`?: (WithNameValueNameFormatEtc7)[]; `effective`?: (WithNameValueNameFormatEtc9)[] }

@hoisted model WithDeclaredIssuersUsableKeysIssuedEtc5 { `declaredIssuers`?: (string)[]; `usableKeys`?: integer; `issued`?: NullableObject72; `registeredWith`?: NullableObject71; `settings`?: WithRequireTrustedIssuerOpensRegistrationRequiredEtc4 }

@hoisted model WithHeldAuthMethodRegisteredEtc7 { `held`?: boolean; `authMethod`?: string; `registered`?: boolean; `registrationAccessTokenHeld`?: boolean; `expiresAt`?: numeric; `secrets`?: (WithIdCreatedAtExpiresAtEtc6)[]; `max`?: numeric }

@hoisted model WithAllowedTransportAllowedHostsEtc6 { `allowed`?: boolean; `transport`?: WithAllowHttpSkipTlsVerificationSetSkipTlsVerificationEtc4; `allowedHosts`?: (string)[]; `retries`?: numeric; `maxResponseBytes`?: numeric; `note`?: string }

@hoisted model WithWalletHeadingRetryEtc8 { `wallet`?: "refused"; `heading`?: string; `retry`?: string; `checks`?: (WithOkNameDetail)[]; `verdict`?: string; `back`?: string; `backKind`?: "portal" | "screen" | "none"; `reissue`?: string }

@hoisted model WithOkErrorsErrorEtc8 { `ok`?: boolean; `errors`?: (string)[]; `error`?: string; `error_description`?: string; `next`?: "refused"; `challenge`?: string; `rpId`?: string; `options`?: WithRpIdUserVerificationTimeoutEtc4 }

@hoisted model WithLevelFormatSummaryEtc7 { `level`?: string; `format`?: string; `summary`?: string; `verifiedAt`?: NullOrStringOrNumeric2; `chainSerials`?: (string)[]; `revocation`?: WithStatusReasonSerialEtc7; `freshness`?: WithStatusDetail }

@hoisted model WithClaimLabelNestedEtc8 { `claim`?: string; `label`?: string; `nested`?: boolean; `attributes`?: (WithLdapSchema)[]; `ldpTerms`?: (string)[]; `paths`?: ((string)[])[]; `requested`?: boolean; `issued`?: WithKnownCarriedMissing }

@hoisted model WithPidThreadRoleEtc6 { `pid`?: integer; `thread`?: NullOrIntegerOrString; `role`?: string; `pushes`?: WithActiveWaitingConcurrencyEtc4; `sweeps`?: (WithAtHeldLettersEtc8)[]; `sinceStart`?: WithFirstSweepAtSweepsLettersEtc7 }

@hoisted model WithAddressVerifiedChangingEtc7 { `address`?: string; `verified`?: boolean; `changing`?: string; `available`?: boolean; `categories`?: (WithIdLabelWhatEtc5)[]; `sent`?: (WithQueuedAtSubjectToEtc4)[]; `sentPaging`?: WithPagePagesPerEtc4 }

@hoisted model WithIdLabelApplicationsEtc9 { `id`?: string; `label`?: string; `applications`?: (string)[]; `nativeSso`?: boolean; `sessionLive`?: boolean; `keys`?: (WithKindLevel)[]; `attestation`?: string; `enrolment`?: string; `lastUsed`?: Shape }

@hoisted model WithIdLabelProtocolEtc10 { `id`?: string; `label`?: string; `protocol`?: string; `spec`?: string; `what`?: string; `terminable`?: boolean; `rows`?: (WithIdFamilyKindEtc11)[]; `held`?: numeric; `notListed`?: numeric; `failure`?: string }

@hoisted model WithStateSurfacesMechanismsEtc8 { `state`?: string; `surfaces`?: (WithSurfaceStateHow)[]; `mechanisms`?: (string)[]; `postQuantum`?: (string)[]; `hybrid`?: (string)[]; `drafts`?: WithMlKemHpkeHybrid; `what`?: string; `whatWouldClose`?: string }

@hoisted model WithSubjectNamesFingerprint256Etc7 { `subject`?: NullableString; `names`?: (string)[]; `fingerprint256`?: NullableString; `certificates`?: (WithAlgorithmCertificateFingerprint)[]; `notAfter`?: NullableString; `perRealm`?: boolean; `what`?: string }

@hoisted model WithDescriptionClaimsReportEtc4 { @js(#{`description`:"The credential subject's claims."}) `claims`?: Record<StringOrNumericOrBooleanEtc4OrListOfRecordStringOrNumericOrBooleanEtc4>; `report`?: (WithLdapClaimValueEtc5)[]; `entryFound`?: boolean }

@hoisted model WithResourceResourceNameBaseUriEtc8 { `resource`?: string; `resourceName`?: string; `baseUri`?: NullableString; `name`?: string; `description`?: NullableString; `id`?: NullableString; `raw`?: NullableString; `grantedTo`?: (WithIdentifierNameAsked)[] }

@hoisted model WithTotalPathsPathsHereEtc8 { `total`?: integer; `paths`?: integer; `pathsHere`?: integer; `pathsElsewhere`?: integer; `byStatusClass`?: Record<numeric>; `pathsCollapsed`?: integer; `healthProbes`?: integer; `rows`?: (WithMethodPathMatchedEtc9)[] }

@hoisted model WithRequiredRealmScopesEtc8 { `required`?: boolean; `realm`?: string; `scopes`?: WithReadWriteReadAlsoEtc5; `refusedPassword`?: string; `metadataIsOpen`?: boolean; `passwordVerified`?: boolean; `schemes`?: (WithIdNameSpecUrnEtc5)[]; `note`?: string }

@hoisted model WithResourceResourceNameBaseUriEtc82 { `resource`?: string; `resourceName`?: string; `baseUri`?: NullableString; `name`?: NullableString; `description`?: NullableString; `id`?: NullableString; `raw`?: NullableString; `grantedTo`?: (WithIdentifierNameAsked)[] }

@hoisted model WithNameSignsVerifiesEtc10 { `name`?: string; `signs`?: string; `verifies`?: string; `encrypts`?: string; `decrypts`?: string; `hashes`?: string; `keys`?: string; `whatItDoesNot`?: string; `envelopes`?: (string)[]; `algorithms`?: (WithWhatValuesHow)[] }

@hoisted model WithSubjectLabelEnrolledAtEtc10 { `subject`?: string; `label`?: string; `enrolledAt`?: NullOrStringOrNumeric; `by`?: string; `proof`?: string; `provedAt`?: NullOrStringOrNumeric; `keyAlg`?: string; `location`?: WithKindValue; `preferred`?: boolean; `pinnedKeys`?: (string)[] }

@hoisted model WithDescriptionSignSettingDescriptionEtc5 { @js(#{`description`:"The setting holding what this surface signs with."}) `signSetting`?: string; @js(#{`description`:"The setting holding what this surface accepts."}) `acceptSetting`?: string; `rows`?: (WithDescriptionIdDescriptionEtc15)[] }

@hoisted model WithRpAlgorithmsAttestationEtc8 { `rp`?: WithNameId; `algorithms`?: (integer)[]; `attestation`?: string; `timeout`?: numeric; `authenticatorSelection`?: WithUserVerificationResidentKeyRequireResidentKeyEtc4; `credProps`?: boolean; `minPinLength`?: boolean; `hints`?: (string)[] }

@hoisted model WithWalletKindSecondFactorEtc10 { `wallet`?: "start" | "refused"; `kind`?: string; `secondFactor`?: boolean; `heading`?: string; `retry`?: string; `checks`?: (WithOkNameDetail)[]; `verdict`?: string; `back`?: string; `backKind`?: "portal" | "screen" | "none"; `reissue`?: string }

@hoisted model WithHeldAuthMethodRegisteredEtc9 { `held`?: boolean; `authMethod`?: string; `registered`?: boolean; `registrationAccessTokenHeld`?: boolean; `expiresAt`?: numeric; `secrets`?: (WithIdCreatedAtExpiresAtEtc6)[]; `max`?: numeric; `defaultLifetimeDays`?: numeric; `overlapS`?: numeric }

@hoisted model WithPairsIntermediariesPeopleEtc6 { `pairs`?: (WithMechanismIntermediaryTargetEtc11)[]; `intermediaries`?: (WithApplicationImpersonatesSemanticsEtc6)[]; `people`?: (WithUsernameDnNotDelegatedEtc6)[]; `protectedGroups`?: (string)[]; `enforced`?: boolean; `attributes`?: Record<string> }

@hoisted model WithUsernameVerifiesCredentialsTotpEtc8 { `username`?: string; `verifiesCredentials`?: boolean; `totp`?: WithEnrolledUsableDetailEtc6; `doors`?: WithAppliesRefused; `setup`?: NullableObject8; `emailFactor`?: NullableObject9; `codes`?: WithEnabledCountLengthEtc11; `fresh`?: NullableObject10 }

@hoisted model WithUriNameShortEtc11 { `uri`?: string; `name`?: string; `short`?: string; `family`?: string; `subject`?: BooleanOrStringOrNull; `what`?: string; `offered`?: boolean; `members`?: (WithNameRequiredWhatEtc5)[]; `required`?: (string)[]; `subjectFormats`?: (string)[]; `deprecated`?: string }

@hoisted model WithFormatUriEmailEtc13 { `format`?: string; `uri`?: string; `email`?: string; `iss`?: string; `sub`?: string; `id`?: string; `phone_number`?: string; `url`?: string; `jti`?: string; `issuer`?: string; `assertion_id`?: string; `ip-addresses`?: (string)[]; `identifiers`?: (WithFormatEmailPhoneNumber)[] }

@hoisted model WithHandleLabelSourceEtc12 { `handle`?: string; `label`?: string; `source`?: string; `state`?: string; `reason`?: string; `revokedAt`?: string; `serialHex`?: string; `expiresAt`?: string; `notAfter`?: string; `privateKeyHeld`?: boolean; `certificate`?: NullableObject47; `chain`?: (WithSubjectIssuerSerialHexEtc10)[] }

@hoisted model WithIdUsernameSubEtc13 { `id`?: string; `username`?: string; `sub`?: string; `amr`?: string; `acr`?: string; `startedAt`?: numeric; `authTime`?: numeric; `authentications`?: integer; `expires`?: numeric; `expired`?: boolean; `wsfedRealms`?: (string)[]; `deviceBound`?: WithBoundAlgBoundAtEtc7; `accountSet`?: string }

@hoisted model WithFoundPersonUsernameEtc11 { `found`?: boolean; `person`?: boolean; `username`?: string; `dn`?: string; `sub`?: string; `notDelegated`?: boolean; `mayAct`?: string; `delegate`?: NullOrStringOrDnStringNameStringKindStringPresentBooleanSubString; `semantics`?: (string)[]; `defaultSemantics`?: string; `groups`?: (WithDnCn)[] }

@hoisted model WithRpAlgorithmsAttestationEtc10 { `rp`?: WithNameId; `algorithms`?: (NullableNumber)[]; `attestation`?: string; `timeout`?: numeric; `authenticatorSelection`?: WithUserVerificationResidentKeyRequireResidentKeyEtc4; `credProps`?: boolean; `minPinLength`?: boolean; `hints`?: (string)[]; `rpId`?: string; `userVerification`?: string }

@hoisted model WithOkKindHolderEtc12 { `ok`?: boolean; `kind`?: string; `holder`?: string; `implicitName`?: string; `certificates`?: (WithSerialHexLabelSubjectEtc11)[]; `active`?: numeric; `max`?: numeric; `keyAlgorithms`?: (string)[]; `defaultKeyAlg`?: string; `revocationReasons`?: (string)[]; `passwordMin`?: numeric; `caAvailable`?: boolean }

@hoisted model WithUserKeyApplicationEtc13 { `user`?: string; `key`?: NullableString; `application`?: string; `enabled`?: boolean; `loaded`?: boolean; `claim`?: NullableString; `valueForm`?: NullableString; `memberOfCounts`?: boolean; `reason`?: string; `dn`?: NullableString; `entryFound`?: boolean; `groups`?: (WithCnDnRuleEtc5)[]; `values`?: (string)[] }

@hoisted model WithKeyIdentifierSpellingsEtc13 { `key`?: string; `identifier`?: string; `spellings`?: (string)[]; `roles`?: WithInitialIntermediaryTarget; `protocols`?: (string)[]; `acts`?: integer; `issued`?: integer; `refused`?: integer; `credentials`?: integer; `firstAt`?: NullableNumber; `lastAt`?: NullableNumber; `identityKey`?: string; `chains`?: integer }

@hoisted model WithUsernameDoorsDoorTableEtc10 { `username`?: string; `doors`?: WithRefusedSecondFactorApplies; `doorTable`?: (WithIdLabelWhat)[]; @js(#{`description`:"Each door's label, by its id."}) `doorLabels`?: Record<string>; `unreadable`?: boolean; `passwords`?: (WithIdNameDoorsEtc6)[]; `enabled`?: boolean; `maxName`?: numeric; `fresh`?: WithIdNameDoorsEtc4 }

@hoisted model WithIdLabelAttributeEtc10 { `id`?: string; `label`?: string; `attribute`?: string; `realm`?: (string)[]; `own`?: NullableArray; `inherited`?: boolean; `effective`?: (string)[]; @js(#{`description`:"The claims, by name."}) `claims`?: Record<StringOrNumericOrBooleanEtc4OrListOfRecordStringOrNumericOrBooleanEtc4>; `report`?: (WithLdapClaimValueEtc5)[] }

@hoisted model WithLdapsPortUrlEtc10 { `ldaps`?: boolean; `port`?: NullableInteger; `url`?: string; `listening`?: boolean; `error`?: NullableString; `startTls`?: boolean; `clientCertificateMode`?: string; `saslExternal`?: WithAvailableMechanismsOutsideCertificateAuthoritiesEtc4; `clientCertificates`?: string; `certificate`?: WithSubjectNamesFingerprint256Etc5 }

@hoisted model WithCertificatesActiveMaxEtc13 { `certificates`?: (WithSerialHexLabelSubjectEtc112)[]; `active`?: integer; `max`?: numeric; `keyAlgorithms`?: (string)[]; `defaultKeyAlg`?: string; `revocationReasons`?: (string)[]; `passwordMin`?: numeric; `implicitName`?: string; `caAvailable`?: boolean; `ok`?: boolean; `kind`?: string; `holder`?: string; `wstrustDeclared`?: boolean }

@hoisted model WithIdentifierNameKindsEtc12 { `identifier`?: string; `name`?: NullableString; `kinds`?: (string)[]; `role`?: string; `registered`?: boolean; `finishUris`?: (string)[]; `webApplication`?: boolean; `grantsHeld`?: WithTotalPendingApprovedEtc4; `activeTokens`?: integer; `counters`?: Record<NumericOrStringOrNullEtc>; `lastAt`?: NullOrStringOrNumeric; `lastEvent`?: NullableString }

@hoisted model WithOkErrorsErrorEtc13 { `ok`?: boolean; `errors`?: (string)[]; `error`?: string; `error_description`?: string; `next`?: "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused"; `location`?: string; `step`?: string; `id`?: string; `form`?: WithMethodActionDescriptionEtc4; `notice`?: string; `end`?: {`title`?: string}; `passkey`?: WithUnknownCredentialAutofill }

@hoisted model WithIdUsernameSubEtc15 { `id`?: string; `username`?: string; `sub`?: string; `amr`?: string; `acr`?: string; `startedAt`?: numeric; `authTime`?: numeric; `authentications`?: numeric; `expires`?: numeric; `expired`?: boolean; `wsfedRealms`?: (string)[]; `deviceBound`?: NullableObject40; `accountSet`?: string; `tokens`?: (WithStateKeyJtiEtc29)[]; `tokensPaging`?: WithPagePagesPerPageEtc8 }

@hoisted model WithStateScopeKeyEtc11 { `state`?: "result" | "refused" | "nobody" | "accounts" | "reauthenticate"; @js(#{`description`:"With `state` reauthenticate: where to sign in again before ending another session, a path on this service that comes back to the sign-out page."}) `signIn`?: string; `scope`?: "global" | "selected"; `key`?: string; `message`?: string; `terminated`?: (WithIdLabelMessage)[]; `skipped`?: (WithIdLabelMessage)[]; `remaining`?: numeric; `verifiesCredentials`?: boolean; `accounts`?: (WithKeyUsernameDisplayNameEtc4)[]; `preselected`?: string; `naming`?: "open" | "off" | "product" }

@hoisted model WithIdConfigurationIdNameEtc14 { `id`?: string; `configurationId`?: NullableString; `name`?: string; `format`?: NullableString; `issuedAt`?: string; `expiresAt`?: string; `status`?: string; @js(#{`description`:"How many copies are in each status."}) `counts`?: Record<integer>; `removable`?: boolean; `removedAt`?: string; `walletEvent`?: NullableString; `walletEventAt`?: string; `copies`?: (WithIdPositionOfEtc13)[] }

@hoisted model WithIdLabelDescriptionEtc14 { `id`?: string; `label`?: string; `description`?: string; @js(#{`description`:"The members this server overrides."}) `overrides`?: Record<Shape4>; `removed`?: (string)[]; `changedAt`?: string; `memberCount`?: integer; `autoCreated`?: boolean; `seen`?: numeric; `seenAt`?: string; `createdAt`?: string; `urls`?: WithOauthOidcAuthorizeEtc4; `drift`?: (WithMemberXFreeFormDescriptionEtc9)[] }

@hoisted model WithEnforcedAttributesProtectedGroupsEtc9 { `enforced`?: boolean; `attributes`?: Record<string>; `protectedGroups`?: (string)[]; `pairs`?: (WithMechanismIntermediaryTargetEtc11)[]; `pairsPaging`?: WithPagePagesPerPageEtc82; `intermediaries`?: (WithApplicationImpersonatesSemanticsEtc6)[]; `intermediariesPaging`?: WithPagePagesPerPageEtc82; `people`?: (WithUsernameDnNotDelegatedEtc6)[]; `peoplePaging`?: WithPagePagesPerPageEtc82 }

@hoisted model WithIdDnAttestationTypeEtc13 { `id`?: string; `dn`?: string; `attestationType`?: string; `selectors`?: (WithTypeValue)[]; `banned`?: boolean; `canReattest`?: boolean; `svidHash`?: string; `expiresAt`?: numeric; `firstSeen`?: string; `lastSeen`?: string; `attestations`?: numeric; @js(#{ `description`:"Attribute names, which are data in a schemaless directory, and values." }) `attributes`?: Record<NullOrStringOrString> }

@hoisted model WithChainKeyProtocolTypeEtc15 { `chainKey`?: string; `protocol`?: string; `type`?: string; `typeLabel`?: string; `mode`?: string; `initial`?: WithKeyPresentedApplicationEtc4; `intermediary`?: WithKeyPresentedApplicationEtc4; `target`?: WithKeyPresentedApplicationEtc4; `acts`?: integer; `issued`?: integer; `refused`?: integer; `firstAt`?: NullableNumber; `lastAt`?: NullableNumber; `authorizedBy`?: string; `reason`?: string }

@hoisted model WithStreamIdStatusStatusReasonEtc14 { `stream_id`?: string; `status`?: string; `statusReason`?: NullableString; `aud`?: StringOrNumericOrBooleanEtc4; `delivery`?: WithMethodEndpointUrl; `events_requested`?: (string)[]; `events_delivered`?: (string)[]; `format`?: string; `description`?: string; `createdBy`?: string; `createdAt`?: StringOrNumeric; `updatedAt`?: StringOrNumeric; `lastPushAt`?: StringOrNumeric; `lastPushError`?: string }

@hoisted model WithUserTrustFrameworksEvidenceTypesEtc14 { `user`?: string; `trustFrameworks`?: (string)[]; `evidenceTypes`?: (string)[]; `documentTypes`?: (string)[]; `checkMethods`?: (string)[]; `electronicRecordTypes`?: (string)[]; `attestationTypes`?: (string)[]; `verifiableClaims`?: (string)[]; `verifications`?: (WithIdRecordedSourceEtc10)[]; `page`?: integer; `pages`?: integer; `perPage`?: integer; `total`?: integer; `paging`?: WithPagePagesPerPageEtc8 }

@hoisted model WithIdStateFinalizationEtc16 { `id`?: string; `state`?: string; `finalization`?: NullableObject; `client`?: NullableString; `clientName`?: NullableString; `authorizationServer`?: NullableString; `createdAt`?: Shape; `updatedAt`?: Shape; `grantExpiresAt`?: Shape; `approvedBy`?: string; `rights`?: (Shape3)[]; `rightsAre`?: string; `subjectReleasedAt`?: Shape; `derivedFrom`?: NullableString; `tokens`?: (WithJtiLabelFormatEtc9)[]; `revocable`?: boolean }

@hoisted model WithSerialHexFamilyProfileEtc19 { `serialHex`?: string; `family`?: string; `profile`?: string; `subject`?: string; `names`?: (string)[]; `thumbprint`?: string; `keyAlg`?: string; `notBefore`?: string; `notAfter`?: string; `issuedAt`?: string; `requestedBy`?: NullableObject12; `via`?: string; `keySource`?: string; `replaces`?: NullableString; `certificatePem`?: string; `chainPem`?: (string)[]; `revoked`?: WithAtReasonBy; `expired`?: boolean; `status`?: string }

@hoisted model WithTotalOkFailedEtc13 { `total`?: numeric; `ok`?: numeric; `failed`?: numeric; `firstAt`?: NumericOrStringOrNull; `lastAt`?: NumericOrStringOrNull; `operations`?: (WithOperationLabelMethodEtc5)[]; `resourceTypes`?: (WithResourceTypeCount)[]; @js(#{`description`:"A count per name."}) `byStatus`?: Record<numeric>; @js(#{`description`:"A count per name."}) `byScimType`?: Record<numeric>; @js(#{`description`:"A count per name."}) `byAuthScheme`?: Record<numeric> }

@hoisted model WithDnCnRuleEtc16 { `dn`?: string; `cn`?: string; `rule`?: string; `origin`?: string; `createdAt`?: NullOrStringOrNumeric; `modifiedAt`?: NullOrStringOrNumeric; `operational`?: (string)[]; `memberAttributes`?: (string)[]; `attributes`?: Record<StringOrString>; `members`?: (WithValueAttributeHoldsEtc10)[]; `memberCount`?: numeric; `presentCount`?: numeric; `danglingCount`?: numeric; `claimed`?: (WithDnKindUserKeyEtc10)[]; `owners`?: (WithDnKindNameEtc4)[]; `maxOwners`?: numeric }

@hoisted model WithOauthGrantTypeObservedOauthResponseTypeObservedAppRedirectUriObservedEtc10 { `oauthGrantTypeObserved`?: (WithValueDeclared)[]; `oauthResponseTypeObserved`?: (WithValueDeclared)[]; `appRedirectUriObserved`?: (WithValueDeclared)[]; `oauthScope`?: (WithValueDeclared)[]; `appAuthorizationServer`?: (WithValueDeclared)[]; `samlNameIdFormat`?: (WithValueDeclared)[]; `samlResponseBinding`?: (WithValueDeclared)[]; `samlLastRequest`?: NullableObject66; `samlObservedSigningCertificate`?: NullableObject67; `oauthAllowedTokenResponseTypes`?: WithEnabledEnforcedWaived }

@hoisted model WithIdStateAuthorizationServerEtc16 { `id`?: string; `state`?: string; `authorizationServer`?: NullableString; `grantEndpoint`?: NullableString; `client`?: NullableString; `proof`?: NullableString; `resourceOwner`?: NullableString; `decision`?: NullableString; `interaction`?: NullableObject100; `tokens`?: integer; `derivedFrom`?: NullableString; `createdAt`?: NullOrStringOrNumeric; `updatedAt`?: NullOrStringOrNumeric; `finalization`?: NullableObject101; `grantExpiresAt`?: NullOrStringOrNumeric; `history`?: (WithAtStateNote)[] }

@hoisted model WithWalletStateKindEtc22 { `wallet`?: "wait" | "refused"; `state`?: string; `kind`?: string; `secondFactor`?: boolean; `authn`?: string; `mfa`?: string; `enrol`?: boolean; `dcRequest`?: NullableObject36; `sameDevice`?: string; `webWallet`?: string; `qr`?: string; `expiresIn`?: numeric; `pollSeconds`?: numeric; `protocol`?: string; `verifier`?: string; `back`?: string; `backKind`?: "portal" | "screen" | "none"; `heading`?: string; `retry`?: string; `checks`?: (WithOkNameDetail)[]; `verdict`?: string; `reissue`?: string }

@hoisted model WithSerialHexFamilyProfileEtc21 { `serialHex`?: string; `family`?: string; `profile`?: string; `subject`?: string; `names`?: (string)[]; `thumbprint`?: string; `keyAlg`?: string; `notBefore`?: StringOrNumeric; `notAfter`?: StringOrNumeric; `issuedAt`?: string; `requestedBy`?: NullableObject12; `via`?: string; `keySource`?: string; `replaces`?: NullableString; `certificatePem`?: string; `chainPem`?: (string)[]; `device`?: string; `attestation`?: StringOrNumericOrBooleanEtc4; `revoked`?: WithAtReasonBy2; `expired`?: boolean; `status`?: string }

@hoisted model WithSeqOriginAtEtc20 { `seq`?: numeric; `origin`?: string; `at`?: NullableNumber; `protocol`?: string; `type`?: string; `typeLabel`?: string; `mode`?: string; `spec`?: string; `policed`?: boolean; `outcome`?: string; `initial`?: WithKeyPresentedApplicationEtc4; `intermediary`?: WithKeyPresentedApplicationEtc4; `target`?: WithKeyPresentedApplicationEtc4; `authorizedBy`?: string; `reason`?: string; `consumed`?: (WithKindIdentifierNote)[]; `produced`?: (WithKindIdentifierNote)[]; `sessionId`?: string; `note`?: string; `chainKey`?: string }

@hoisted model WithRelationshipJtiViaEtc15 { `relationship`?: string; `jti`?: string; `via`?: string; `receivedAt`?: string; `verified`?: boolean; `refusal`?: string; `why`?: string; `events`?: (string)[]; @js(#{ `x-free-form`:"An RFC 9493 subject identifier as a partner's SET carried it, in whatever format that partner chose.", `description`:"An RFC 9493 subject identifier as a partner's SET carried it, in whatever format that partner chose." }) `subject`?: unknown; `person`?: string; `mapping`?: string; `reactions`?: (WithEventReactionDoneEtc13)[]; `iat`?: numeric }

@hoisted model WithCertificatesActiveMaxEtc18 { `certificates`?: (WithSerialHexLabelSubjectEtc112)[]; `active`?: integer; `max`?: numeric; `keyAlgorithms`?: (string)[]; `defaultKeyAlg`?: string; `revocationReasons`?: (string)[]; `passwordMin`?: numeric; `implicitName`?: string; `caAvailable`?: boolean; `authMethod`?: string; `certificateMethod`?: boolean; `subjects`?: (WithMemberAttributeLabelEtc4)[]; `registeredSubject`?: (string)[]; `boundTokensAttribute`?: string; `boundTokens`?: boolean; `adminApiBound`?: boolean; `selfSignedThumbprint`?: string; `bindingAvailable`?: boolean }

@hoisted model WithCredentialIdGroupNameEtc21 { `credentialId`?: string; `group`?: string; `name`?: string; `provider`?: string; `enrolledAt`?: Shape; `lastUsedAt`?: Shape; `syncedRefused`?: boolean; `attestationRefused`?: string; `pinRefused`?: string; `postQuantumRefused`?: boolean; `backupEligible`?: NullableBoolean; `backupState`?: boolean; `transports`?: (string)[]; `kind`?: string; `withoutUsername`?: string; `algorithm`?: WithTextPostQuantumInsecure; `lane`?: string; `upgrade`?: NullableObject3; `possiblyReplaced`?: NullableObject4; `attestation`?: NullableObject5; `aaguid`?: string }

@hoisted model WithModePasswordlessChoicesEtc21 { `mode`?: "create" | "get"; `passwordless`?: boolean; `choices`?: (WithIdName)[]; `chosen`?: NullableObject26; `problem`?: string; `postQuantumRefused`?: NullableObject32; `hardwareRefused`?: NullableObject32; `postQuantumHelp`?: NullableObject31; `postQuantumAllowCredentials`?: string; `fallback`?: NullableObject33; `rpId`?: string; `widened`?: boolean; `challenge`?: string; `attestation`?: string; `algorithms`?: (string)[]; `postLogin`?: NullableObject34; `lanes`?: (string)[]; `lane`?: string; `userVerification`?: string; `residentKey`?: string; `attachment`?: string }

@hoisted model WithCoordinatingSupportedStartedAtEtc21 { `coordinating`?: boolean; `supported`?: boolean; `startedAt`?: NumericOrStringOrNull; `appliedSeq`?: numeric; `highestSeq`?: numeric; `holes`?: numeric; `holeRanges`?: numeric; `holesAbandoned`?: numeric; `pollIntervalMs`?: numeric; `pulls`?: numeric; `nudges`?: numeric; `failures`?: numeric; `rowsApplied`?: numeric; @js(#{`description`:"A count per name."}) `byKind`?: Record<numeric>; `lastPullAt`?: NumericOrStringOrNull; `lastError`?: NullableString; `otherProcesses`?: numeric; `originsDropped`?: numeric; `retention`?: WithRetentionSReaderTtlSReportedAtEtc8; `note`?: string }

@hoisted model WithPersistingSupportedUnsupportedReasonEtc23 { `persisting`?: boolean; `supported`?: boolean; `unsupportedReason`?: string; `sealed`?: boolean; `mode`?: string; `setting`?: boolean; `retentionMs`?: numeric; `stores`?: numeric; `shared`?: numeric; `handles`?: (WithHandleShapeScope)[]; `pending`?: numeric; `writes`?: numeric; `failures`?: numeric; `rowsWritten`?: numeric; `rowsDeleted`?: numeric; `lastWriteAt`?: NumericOrStringOrNull; `lastError`?: NullableString; `restoredAt`?: NumericOrStringOrNull; `restored`?: numeric; `droppedUnreadable`?: numeric; `droppedUnknown`?: numeric; `droppedPoison`?: numeric; `poisonDrops`?: (WithAtCodeMessageEtc6)[] }

@hoisted model WithIdLabelKindEtc22 { `id`?: string; `label`?: string; `kind`?: string; `where`?: string; `module`?: string; `guards`?: string; `enforces`?: boolean; `bias`?: NullableString; `dischargesObligations`?: boolean; `decisions`?: integer; `allowed`?: NullableInteger; `refused`?: NullableInteger; `permit`?: NullableInteger; `deny`?: NullableInteger; `notApplicable`?: NullableInteger; `indeterminate`?: NullableInteger; `other`?: NullableInteger; `undischargeable`?: integer; `lastAt`?: StringOrNumericOrNull; `lastDecision`?: NullableString; `lastAllowed`?: NullableBoolean; `remote`?: WithAuthenticatedCertificateSubjectCurrentEtc11 }

@hoisted model WithUserEntryFoundDescriptionEtc14 { `user`?: string; `entryFound`?: boolean; @js(#{`description`:"By directory attribute."}) `byLdap`?: Record<{ `ldap`?: string; `claim`?: string; @js(#{ `x-free-form`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path.", `description`:"A claim value as it would be issued. Its JSON type is the catalogue row's and the person's own data, and a row may nest under a dotted path." }) `value`?: unknown; `source`?: string; `ldpTerm`?: NullableString; `claimId`?: string; `values`?: (Shape5)[] }>; `claims`?: (WithNameIdTypeEtc6)[] }

@hoisted model WithIdLabelClaimsEtc11 { `id`?: string; `label`?: string; `claims`?: (WithNameValueAttributeEtc8)[]; `attributes`?: (string)[]; @js(#{ `x-free-form`:"The claims one person would be issued, keyed and nested by the claim names the catalogue and an administrator chose.", `description`:"The claims one person would be issued, keyed and nested by the claim names the catalogue and an administrator chose." }) `attributeClaims`?: unknown; `attributeReport`?: (WithLdapClaimXFreeFormEtc9)[]; `attributeClaimPreview`?: (WithNameAttributeCarriedEtc6)[]; @js(#{`description`:"Partners withholding it, by claim."}) `withheldFrom`?: Record<(string)[]> }

@hoisted model WithIdKindKeyEtc27 { `id`?: string; `kind`?: string; `key`?: string; `presented`?: string; `application`?: string; `aliases`?: (string)[]; `what`?: string; `roles`?: WithInitialIntermediaryTarget; `protocols`?: (string)[]; `acts`?: integer; `issued`?: integer; `refused`?: integer; `firstAt`?: NullableNumber; `lastAt`?: NullableNumber; `selfTarget`?: boolean; `chiefRole`?: string; `realm`?: WithIdNameIsDefault2; `issuer`?: string; `credentials`?: integer; `flows`?: (string)[]; `authentications`?: integer; `isSubject`?: boolean; `isClient`?: boolean; `kinds`?: (string)[]; `grants`?: integer; `exposes`?: integer; `dangling`?: integer }

@hoisted model WithPageDescriptionGroupsEtc15 { `page`?: string; @js(#{`description`:"In the order `config.js` declares them."}) `groups`?: (WithGroupSettings)[]; `settingCount`?: integer; @js(#{`description`:"How many of them can be changed while the service runs."}) `editableCount`?: integer; @js(#{`description`:"The keys on this page with a runtime override in force."}) `overridden`?: (string)[]; @js(#{`description`:"The operation that writes them."}) `setWith`?: string; `context`?: WithConfigFileDefaultsFilePersistsAppconfigEtc7; @js(#{`description`:"A group drawn on another page as well, and those pages."}) `sharedWith`?: Record<({`path`?: string; `label`?: NullableString})[]> }

@hoisted model WithPageDescriptionGroupsEtc152 { `page`?: string; @js(#{`description`:"In the order `config.js` declares them."}) `groups`?: (WithGroupSettings)[]; `settingCount`?: integer; @js(#{`description`:"How many of them can be changed while the service runs."}) `editableCount`?: integer; @js(#{`description`:"The keys on this page with a runtime override in force."}) `overridden`?: (string)[]; @js(#{`description`:"The operation that writes them."}) `setWith`?: string; `context`?: WithConfigFileDefaultsFilePersistsAppconfigEtc7; @js(#{`description`:"A group drawn on another page as well, and those pages."}) `sharedWith`?: Record<({ `path`?: string; `label`?: NullableString })[]> }

@hoisted model WithIdDnSpiffeIdEtc24 { `id`?: string; `dn`?: string; `spiffeId`?: string; `parentId`?: string; `selectors`?: (WithTypeValue)[]; `selectorTexts`?: (string)[]; `x509SvidTtl`?: numeric; `jwtSvidTtl`?: numeric; `dnsNames`?: (string)[]; `federatesWith`?: (string)[]; `hint`?: string; `admin`?: boolean; `downstream`?: boolean; `storeSvid`?: boolean; `expiresAt`?: numeric; `expired`?: boolean; `revisionNumber`?: numeric; `origin`?: string; `svidsIssued`?: numeric; `lastSvidAt`?: string; `createdAt`?: string; `modifiedAt`?: string; @js(#{ `description`:"Attribute names, which are data in a schemaless directory, and values." }) `attributes`?: Record<NullOrStringOrString> }

@hoisted model WithIdStateFinalizationEtc18 { `id`?: string; `state`?: string; `finalization`?: NullableObject; `client`?: NullableString; `clientName`?: NullableString; `authorizationServer`?: NullableString; `createdAt`?: NullableNumber; `updatedAt`?: NullableNumber; `grantExpiresAt`?: NullableNumber; `approvedBy`?: string; @js(#{ `x-free-form`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines.", `description`:"An RFC 9635 access right as the client asked for it: a reference string or an object in the access type the resource server defines." }) `rights`?: unknown; `rightsAre`?: string; `subjectReleasedAt`?: NullableNumber; `derivedFrom`?: NullableString; `tokens`?: (WithJtiLabelFormatEtc11)[]; `revocable`?: boolean }

@hoisted model WithCallsOkFailedEtc22 { `calls`?: numeric; `ok`?: numeric; `failed`?: numeric; `successRate`?: NullableNumber; `firstAt`?: NumericOrStringOrNull; `lastAt`?: NumericOrStringOrNull; `since`?: NumericOrStringOrNull; `latency`?: WithTotalMsAverageMsMaxMs; `bytesOut`?: numeric; `authentication`?: WithDistinctApplicationsIdentitiesEtc9; `operations`?: (WithOperationLabelMethodEtc10)[]; `resourceTypes`?: (WithResourceTypeCount)[]; @js(#{`description`:"A count per name."}) `byStatus`?: Record<numeric>; @js(#{`description`:"A count per name."}) `byStatusClass`?: Record<numeric>; @js(#{`description`:"A count per name."}) `byScimType`?: Record<numeric>; `clients`?: (WithPrincipalKindCallsEtc11)[]; `recent`?: (WithAtOperationResourceTypeEtc12)[]; `recentCap`?: numeric; `realm`?: WithIdName5 }

@hoisted model WithJtiAtTokenDigestEtc21 { `jti`?: string; `at`?: NullOrStringOrNumeric; `tokenDigest`?: string; `surface`?: NullableString; `stream`?: NullableString; `name`?: string; `types`?: (string)[]; `vocabulary`?: string; `issuer`?: string; `audience`?: string; `audienceOk`?: boolean; `subject`?: string; @js(#{ `x-free-form`:"An event's body as this receiver took it in: each event type has its own members, and a refused delivery is held here too.", `description`:"An event's body as this receiver took it in: each event type has its own members, and a refused delivery is held here too." }) `payload`?: unknown; `verified`?: boolean; `verificationNote`?: NullableString; `reactions`?: (WithEventReactionSkippedEtc7)[]; `contentType`?: NullableString; `correctMediaType`?: boolean; `problem`?: string }

@hoisted model WithStateStateWhyExpiresAtEtc27 { `state`?: string; `stateWhy`?: string; `expiresAt`?: string; `staleAt`?: string; `refreshable`?: boolean; `refresh`?: NullableObject60; `refresherEnabled`?: boolean; `refresherRunning`?: boolean; `trustAnchors`?: numeric; `trustAnchorProblems`?: (string)[]; `mdqUrl`?: string; `consumed`?: boolean; `consumedAt`?: string; `how`?: string; `url`?: string; `signature`?: string; `signingCertificateConfigured`?: boolean; `validUntil`?: string; `expired`?: boolean; `cacheDuration`?: string; `authnRequestsSigned`?: boolean; `wantAssertionsSigned`?: boolean; `wantAssertionsEncrypted`?: boolean; `nameIdFormats`?: (string)[]; `assertionConsumerServices`?: (WithIndexIsDefaultBindingEtc4)[]; `singleLogoutServices`?: (WithBindingLocationResponseLocation)[]; `encryptionCertificate`?: boolean }

@hoisted model WithStreamIdIssAudEtc26 { `stream_id`?: string; `iss`?: NullableString; `aud`?: NullOrStringOrString; `status`?: string; `statusReason`?: NullableString; `delivery`?: WithMethodEndpointUrl; `events_delivered`?: (string)[]; `events_requested`?: (string)[]; `format`?: NullableString; `description`?: NullableString; `createdAt`?: NullOrStringOrNumeric; `updatedAt`?: NullOrStringOrNumeric; `createdBy`?: NullableString; `internal`?: boolean; `counters`?: Record<numeric>; `lastPushError`?: NullableString; `lastPushAt`?: NullOrStringOrNumeric; `subjects`?: (WithTextVerifiedAddedAtEtc6)[]; `queue`?: (WithJtiQueuedAtDeliveredAtEtc4)[]; `dead`?: boolean; `deadSince`?: string; `deadReason`?: string; `failingSince`?: string; `nextProbeAt`?: string; `deadLetters`?: (WithJtiQueuedAtDeadAtEtc8)[]; `log`?: (WithAtKindText)[] }

@hoisted model WithAskedOkErrorEtc17 { `asked`?: boolean; `ok`?: boolean; `error`?: string; `request`?: string; @js(#{ `x-free-form`:"The claims request as a caller typed it, parsed: OIDC Core 5.5 keys it by the claims they ask for.", `description`:"The claims request as a caller typed it, parsed: OIDC Core 5.5 keys it by the claims they ask for." }) `parsed`?: unknown; `ignoredMembers`?: (string)[]; `idTokenNames`?: (string)[]; @js(#{ `x-free-form`:"The claims one person would be issued for that request, keyed by the names it asked for.", `description`:"The claims one person would be issued for that request, keyed by the names it asked for." }) `claims`?: unknown; `report`?: (WithRequestedClaimLdapEtc7)[]; `unresolvable`?: (string)[]; `essentialAndAbsent`?: (string)[]; `valueMismatches`?: (string)[]; `entryFound`?: boolean }

@hoisted model WithIdentifierDnLabelDnEtc27 { `identifier`?: string; `dnLabel`?: NullableString; `dn`?: NullableString; `name`?: NullableString; `kinds`?: (string)[]; `protocols`?: (string)[]; `allowedProtocols`?: (string)[]; `recordedProtocols`?: (string)[]; `declaredKinds`?: (string)[]; `registeredBy`?: string; `returnAddressesObserved`?: (WithAttributeValueHeldEtc4)[]; `registered`?: boolean; `firstSeen`?: string; `lastSeen`?: string; `authentications`?: numeric; `sessions`?: numeric; `users`?: numeric; `description`?: NullableString; `origin`?: NullableString; `createdAt`?: NullableString; `modifiedAt`?: NullableString; `operational`?: (string)[]; @js(#{`description`:"By attribute name."}) `attributes`?: Record<StringOrNumericOrBooleanEtc4>; @js(#{`description`:"By attribute name."}) `fields`?: Record<StringOrNumericOrBooleanEtc4>; `secretExpiry`?: WithStateAt }

@hoisted model WithAccountIdSubUsernameEtc29 { `accountId`?: string; `sub`?: NullableString; `username`?: NullableString; `iss`?: NullableString; `dn`?: NullableString; `realm`?: NullableString; `email`?: NullableString; `phone`?: NullableString; `formerIdentifiers`?: (string)[]; `createdAt`?: NullOrStringOrNumeric; `updatedAt`?: NullOrStringOrNumeric; `lifecycle`?: NullableString; `kind`?: string; `application`?: string; `serviceAccount`?: boolean; `optOut`?: NullableString; `optOutApplies`?: boolean; `credentialStanding`?: NullableString; `credentialChangeRequired`?: boolean; `recoveryActivated`?: boolean; `identifierChanges`?: (WithAtFromTo)[]; `credentials`?: (WithAtCredentialTypeDiscoveredAt)[]; `counts`?: Record<numeric>; `total`?: integer; `suppressed`?: integer; `events`?: (WithJtiUriNameEtc6)[]; `streams`?: (string)[]; `notes`?: (string)[]; `subject`?: string }

@hoisted model WithSessionIdSubUsernameEtc23 { `sessionId`?: string; `sub`?: NullableString; `username`?: NullableString; `iss`?: NullableString; `protocol`?: NullableString; `establishedAt`?: NullOrStringOrNumeric; `updatedAt`?: NullOrStringOrNumeric; `state`?: NullableString; `acr`?: NullableString; `amr`?: (string)[]; `assurance`?: WithNamespaceLevelPreviousLevel; `compliance`?: NullableString; `risk`?: WithLevelPreviousLevelReason; @js(#{ `x-free-form`:"The claims a `token-claims-change` event said changed: whichever a person configured or an emitter named.", `description`:"The claims a `token-claims-change` event said changed: whichever a person configured or an emitter named." }) `claims`?: unknown; `credentials`?: (WithAtCredentialTypeChangeTypeEtc4)[]; `counts`?: Record<numeric>; `total`?: integer; `events`?: (WithJtiUriNameEtc6)[]; `streams`?: (string)[]; `notes`?: (string)[]; `subject`?: string }

@hoisted model WithIdentifierDnLabelDnEtc26 { `identifier`?: string; `dnLabel`?: NullableString; `dn`?: NullableString; `name`?: NullableString; `kinds`?: (string)[]; `protocols`?: (string)[]; `allowedProtocols`?: (string)[]; `recordedProtocols`?: (string)[]; `declaredKinds`?: (string)[]; `registeredBy`?: string; `returnAddressesObserved`?: (WithAttributeValueHeldEtc4)[]; `registered`?: boolean; `firstSeen`?: string; `lastSeen`?: string; `authentications`?: numeric; `sessions`?: numeric; `users`?: numeric; `description`?: NullableString; `origin`?: NullableString; `createdAt`?: NullableString; `modifiedAt`?: NullableString; `operational`?: (string)[]; @js(#{ `description`:"Attribute names, which are data in a schemaless directory, and values." }) `attributes`?: Record<NullOrStringOrString>; @js(#{ `description`:"Attribute names, which are data in a schemaless directory, and values." }) `fields`?: Record<NullOrStringOrString> }

@hoisted model WithCredentialIdPublicKeyJwkSignCountEtc36 { `credentialId`?: string; `publicKeyJwk`?: WithKtyCrvAlgEtc12; `signCount`?: numeric; `enrolledAt`?: numeric; `lastUsedAt`?: numeric; `label`?: string; `attachment`?: NullableString; `userVerified`?: NullableBoolean; `aaguid`?: NullableString; `algorithm`?: NameStringCoseAlgNullableNumberTextStringPostQuantumBooleanInsecureBooleanLaneStringOrNullOrString; `coseAlg`?: NullableNumber; `attestation`?: NullableObject53; `backupEligible`?: NullableBoolean; `backupState`?: NullableBoolean; `transports`?: (string)[]; `discoverable`?: NullableBoolean; `minPinLength`?: NullableNumber; `userHandle`?: string; `lane`?: string; `enrolledBy`?: WithUsernameSubAt; `provider`?: NullableString; `providerSource`?: string; `name`?: string; `group`?: string; `upgradedAt`?: numeric; `upgradedTo`?: string; `previousAlgorithm`?: string; `previousCoseAlg`?: NullableNumber; `previousCredentialId`?: string; `upgradeMode`?: string; `possiblyReplacedBy`?: string; `possiblyReplacedAt`?: numeric; `policyRefused`?: Record<{`why`?: string; `at`?: numeric}>; `attestationRefused`?: WithWhyAt }

@hoisted model WithIdFromToEtc53 { `id`?: string; `from`?: string; `to`?: string; `fromRole`?: string; `toRole`?: string; `relation`?: string; `skipped`?: (string)[]; `chainKey`?: string; `protocol`?: NullableString; `protocols`?: (string)[]; `type`?: NullableString; `typeLabel`?: NullableString; `mode`?: string; `spec`?: NullableString; `policed`?: boolean; `subject`?: NullableString; `actor`?: NullableString; `acts`?: integer; `issued`?: integer; `refused`?: integer; `credentials`?: integer; `firstAt`?: NullableNumber; `lastAt`?: NullableNumber; `authorizedBy`?: string; `reason`?: string; `consumed`?: (WithKindCountIdentifiersEtc5)[]; `produced`?: (WithKindCountIdentifiersEtc5)[]; `consumedFold`?: Record<{ `kind`?: string; `count`?: integer; `identifiers`?: (string)[]; `moreIdentifiers`?: integer; `notes`?: (string)[] }>; `producedFold`?: Record<{ `kind`?: string; `count`?: integer; `identifiers`?: (string)[]; `moreIdentifiers`?: integer; `notes`?: (string)[] }>; `attribute`?: string; `mechanism`?: string; `setOn`?: string; `used`?: boolean; `authentications`?: (WithProtocolMethodCountEtc5)[]; `audience`?: string; `audienceRegistered`?: boolean; `permissions`?: (string)[]; `scopes`?: (string)[]; `permissionId`?: string; `permissionName`?: string; `baseUri`?: NullableString; `description`?: NullableString; `asked`?: boolean }

@hoisted model WithIdStatusRequesterEtc25 { `id`?: string; `status`?: string; `requester`?: NullableString; `client`?: NullableObject26; `application`?: NullableString; @js(#{ `x-free-form`:"An AuthZEN Authorization API 1.0 member as the PEP sent it: its `properties` and its context are the caller's to define.", `description`:"An AuthZEN Authorization API 1.0 member as the PEP sent it: its `properties` and its context are the caller's to define." }) `subject`?: unknown; @js(#{ `x-free-form`:"An AuthZEN Authorization API 1.0 member as the PEP sent it: its `properties` and its context are the caller's to define.", `description`:"An AuthZEN Authorization API 1.0 member as the PEP sent it: its `properties` and its context are the caller's to define." }) `action`?: unknown; @js(#{ `x-free-form`:"An AuthZEN Authorization API 1.0 member as the PEP sent it: its `properties` and its context are the caller's to define.", `description`:"An AuthZEN Authorization API 1.0 member as the PEP sent it: its `properties` and its context are the caller's to define." }) `resource`?: unknown; @js(#{ `x-free-form`:"An AuthZEN Authorization API 1.0 member as the PEP sent it: its `properties` and its context are the caller's to define.", `description`:"An AuthZEN Authorization API 1.0 member as the PEP sent it: its `properties` and its context are the caller's to define." }) `context`?: unknown; `emergency`?: boolean; `justification`?: string; `createdAt`?: Shape; `expiresAt`?: Shape; `finishedAt`?: Shape; `decidedBy`?: string; `approval`?: NullableObject27; `approvers`?: WithRolesGroupsOwners }

@hoisted model WithStoredTypeDescriptionEtc29 { `stored`?: string; `type`?: string; `description`?: string; `locations`?: (string)[]; @js(#{ `x-free-form`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition.", `description`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition." }) `schema`?: unknown; `validate`?: null; `problem`?: string; `actions`?: NullableArray; `datatypes`?: NullableArray; `privileges`?: NullableArray; `required`?: (string)[]; `interaction`?: string; `consentActions`?: (string)[]; `bearer`?: StringOrNumericOrBooleanEtc4; `maxLifetimeS`?: NullableNumber; `acr`?: string; `derivableFrom`?: (string)[]; `introspectionClaims`?: (string)[]; @js(#{ `x-free-form`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition.", `description`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition." }) `limits`?: unknown; `validateLimits`?: null; `xacml`?: (WithPathAttributeIdCategoryEtc6)[]; `notForPolicy`?: (string)[]; @js(#{ `x-free-form`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition.", `description`:"The JSON an operator wrote into an access type's definition: a JSON Schema (RFC 9396 leaves a type's fields to its definition), or the definition." }) `source`?: unknown }

@hoisted model WithUserClaims { `user`?: string; `claims`?: WithDescriptionClaimsReportEtc4 }

@hoisted model WithEnabledRows { `enabled`?: boolean; `rows`?: (WithIdStatusRequesterEtc25)[] }

@hoisted model WithStatusUsableAudSubs { `status`?: WithOptedInKindUsableEtc8; `usable`?: boolean; `audSubs`?: (string)[] }

@hoisted model WithShownPaging8 { `shown`?: (WithChainKeyProtocolTypeEtc15)[]; `paging`?: WithPagePagesPerPageEtc82 }

@hoisted model WithPagingShown3 { `paging`?: WithPagePerPagePagesEtc9; `shown`?: (WithSerialHexFamilyProfileEtc21)[] }

@hoisted model WithOkErrorsErrorEtc45 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithHasPasswordRules }

@hoisted model WithCredentialsCredentialSets { `credentials`?: (WithIdFormatMetaEtc6)[]; `credential_sets`?: (WithOptionsRequired)[] }

@hoisted model WithPagingShown4 { `paging`?: WithPagePerPagePagesEtc9; `shown`?: (WithResourceResourceNameBaseUriEtc8)[] }

@hoisted model WithShownPaging9 { `shown`?: (WithResourceResourceNameBaseUriEtc82)[]; `paging`?: WithPagePagesPerPageEtc82 }

@hoisted model WithOkErrorsErrorEtc46 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithUsernameTokenBaseEtc8 }

@hoisted model WithOkErrorsErrorEtc47 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithKdcPersonPrincipalEtc7 }

@hoisted model WithOkErrorsErrorEtc48 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithAddressVerifiedChangingEtc7 }

@hoisted model WithOkErrorsErrorEtc49 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithUsernameDoorsDoorTableEtc10 }

@hoisted model WithFormatMembersWhatEtc4 { `format`?: string; `members`?: (string)[]; `what`?: string; `example`?: WithFormatUriEmailEtc13 }

@hoisted model WithOkErrorsErrorEtc410 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithProvidersConnectedNoticeEtc4 }

@hoisted model WithIdRfcGrantTypeEtc5 { `id`?: string; `rfc`?: string; `grantType`?: string; `atCap`?: boolean; `held`?: WithKeysValidIssuers }

@hoisted model WithOkErrorsErrorEtc411 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithUsernameVerifiesCredentialsTotpEtc8 }

@hoisted model WithPagingGroupsAdministrative { `paging`?: WithPagePagesPerEtc4; `groups`?: (WithClientNameRows)[]; `administrative`?: (WithClientNameRows)[] }

@hoisted model WithInstalledStreamsSettings { `installed`?: boolean; `streams`?: (WithStreamIdStatusStatusReasonEtc14)[]; `settings`?: (WithSettingAttributeValueEtc4)[] }

@hoisted model WithHeldActiveWindowedEtc5 { `held`?: NullableInteger; `active`?: NullableInteger; `windowed`?: boolean; `unread`?: boolean; `rows`?: (WithIdUsernameSubEtc13)[] }

@hoisted model WithStateStatesPagingEtc4 { `state`?: NullableString; `states`?: (string)[]; `paging`?: WithPagePagesPerPageEtc8; `rows`?: (WithIdStateAuthorizationServerEtc16)[] }

@hoisted model WithIdNameTypeEtc6 { `id`?: string; `name`?: string; `type`?: string; `resourceServer`?: string; `scopes`?: (string)[]; `shares`?: (WithIdResourceIdScopesEtc7)[] }

@hoisted model WithRegisterPairsIntermediariesEtc4 { `register`?: WithPairsIntermediariesPeopleEtc6; `pairs`?: WithShownPaging5; `intermediaries`?: WithShownPaging7; `people`?: WithShownPaging3 }

@hoisted model WithSessionsApplicationsStreams2 { `sessions`?: (WithSessionIdSubUsernameEtc23)[]; `applications`?: (WithIdentifierNameRegisteredEtc23)[]; `streams`?: (WithStreamIdAudStatusEtc6)[] }

@hoisted model WithAccountsApplicationsStreams2 { `accounts`?: (WithAccountIdSubUsernameEtc29)[]; `applications`?: (WithIdentifierNameRegisteredEtc23)[]; `streams`?: (WithStreamIdAudStatusEtc6)[] }

@hoisted model WithPathDepthKindEtc7 { `path`?: string; `depth`?: integer; `kind`?: string; `label`?: string; `detail`?: string; `options`?: WithKindRemovableAdditions; `edit`?: NullableObject97 }

@hoisted model WithUserTotalRowsEtc5 { `user`?: string; `total`?: integer; `rows`?: (WithIdStateFinalizationEtc16)[]; `paging`?: WithPagePagesPerPageEtc82; `cells`?: WithMultiCellCellCompleteEtc4 }

@hoisted model WithCataloguePreviewSetsEtc4 { `catalogue`?: (WithLdapClaimLabelEtc6)[]; `preview`?: WithUserDescriptionByLdapEtc9; `sets`?: (WithIdLabelAttributeEtc10)[]; `credential`?: NullableObject73 }

@hoisted model WithIdentifierNameBaseUriEtc6 { `identifier`?: string; `name`?: string; `baseUri`?: NullableString; `rawBaseUri`?: string; `permissions`?: (WithNameDescriptionIdEtc5)[]; `grantsHeld`?: integer }

@hoisted model WithPasswordMfaRequiredKeysEtc5 { `password`?: boolean; `mfaRequired`?: boolean; `keys`?: (WithCredentialIdGroupNameEtc21)[]; `enrol`?: WithEnabledCountAtCapEtc7; `signals`?: (WithLaneRpIdUserIdEtc6)[] }

@hoisted model WithAlgorithmsSignaturesKeyEstablishmentEtc4 { `algorithms`?: WithMlDsaSlhDsaCompositeEtc6; `signatures`?: (WithSurfaceStateHow)[]; `keyEstablishment`?: WithStateSurfacesMechanismsEtc8; `symmetric`?: WithStateStrongestWhat }

@hoisted model WithUserEntryFoundSignInEnabledEtc6 { `user`?: string; `entryFound`?: boolean; `signInEnabled`?: boolean; `maxPerPerson`?: numeric; `subjectSyntaxTypes`?: (string)[]; `subjects`?: (WithSubjectLabelEnrolledAtEtc10)[] }

@hoisted model WithJweXmlKerberosEtc4 { `jwe`?: WithKeyManagementOutKeyManagementInContentEncryption; `xml`?: WithBlockCiphersKeyTransportsConfigured; `kerberos`?: WithPerformedDecodeOnlyPreference; `tls`?: WithWhatSockets }

@hoisted model WithOkCsrfUiLocalesEtc8 { `ok`?: boolean; `csrf`?: string; `uiLocales`?: string; `preferredLanguage`?: WithValuePopulated; `view`?: WithStateAccountsPreselectedEtc4; `errors`?: (string)[]; `error`?: string; `error_description`?: string }

@hoisted model WithJwtBiscuitZcapEtc6 { `jwt`?: WithJwksUriAlgKidEtc5; `biscuit`?: WithAlgorithmRootPublicKeyRevocationEndpointEtc5; `zcap`?: WithControllerCryptosuite; `macaroon`?: {`root_key`?: string}; `jwt-encrypted`?: WithAuthorizationServerResourceServer }

@hoisted model WithOkCsrfUiLocalesEtc9 { `ok`?: boolean; `csrf`?: string; `uiLocales`?: string; `preferredLanguage`?: WithValuePopulated; `view`?: WithWalletStateKindEtc22; `next`?: "refused"; `errors`?: (string)[]; `error`?: string; `error_description`?: string }

@hoisted model WithEnabledTurnOnLoginHintEtc8 { `enabled`?: boolean; `turnOn`?: NullableObject18; `loginHint`?: string; `didClaim`?: boolean; `published`?: NullableObject19; `subjects`?: (WithSubjectLabelEnrolledAtEtc9)[]; `notice`?: string; `fresh`?: WithKindRidDidEtc4 }

@hoisted model WithDevicesPlatformsProofEtc8 { `devices`?: (WithIdLabelApplicationsEtc9)[]; `platforms`?: (string)[]; `proof`?: NullableObject22; `audience`?: string; `proofTyp`?: string; `linking`?: NullableObject23; `link`?: WithEnrolledKeysRoaming; `remember`?: boolean }

@hoisted model WithOkCsrfUiLocalesEtc92 { `ok`?: boolean; `csrf`?: string; `uiLocales`?: string; `preferredLanguage`?: WithValuePopulated; `view`?: WithWalletKindSecondFactorEtc10; `next`?: "refused"; `errors`?: (string)[]; `error`?: string; `error_description`?: string }

@hoisted model WithHeldExposesOfferableEtc5 { `held`?: (WithClientClientNamePermissionIdEtc10)[]; `exposes`?: (WithResourceResourceNameBaseUriEtc8)[]; `offerable`?: (NullableString)[]; `grantedOut`?: (WithClientClientNamePermissionIdEtc10)[]; `paging`?: WithHeldExposesGrantedOut }

@hoisted model WithIdLabelHeldEtc10 { `id`?: string; `label`?: string; `held`?: boolean; `keys`?: (WithHandleLabelSourceEtc12)[]; `valid`?: numeric; `atCap`?: boolean; `handleLabel`?: string; `issuers`?: (string)[]; `effectiveIssuers`?: (string)[]; `attributes`?: WithIssuerKeysPrivateKey }

@hoisted model WithPurposeLabelHeldEtc10 { `purpose`?: string; `label`?: string; `held`?: boolean; `keys`?: (WithHandleLabelSourceEtc12)[]; `valid`?: numeric; `atCap`?: boolean; `handleLabel`?: string; `issuers`?: (string)[]; `effectiveIssuers`?: (string)[]; `attributes`?: WithIssuerKeysPrivateKey }

@hoisted model WithIdKindLaneEtc11 { `id`?: string; `kind`?: string; `lane`?: string; `challenge`?: string; `rpId`?: string; `user`?: string; `userHandle`?: string; `display`?: string; `exclude`?: (string)[]; `options`?: WithRpAlgorithmsAttestationEtc8; `fallback`?: WithAsksPostQuantumClassicalRetrying }

@hoisted model WithEnabledLoadedClaimEtc11 { `enabled`?: boolean; `loaded`?: boolean; `claim`?: NullableString; `valueForm`?: NullableString; `memberOfCounts`?: boolean; `sets`?: (string)[]; `problem`?: string; `grants`?: string; `precedence`?: string; `settings`?: (string)[]; `preview`?: WithUserKeyApplicationEtc13 }

@hoisted model WithSupportedMembersMaxClaimsEtc9 { `supported`?: boolean; `members`?: (string)[]; `maxClaims`?: numeric; `requestable`?: (WithClaimLdapLabelEtc4)[]; `fromTheSignIn`?: (string)[]; `precedence`?: (string)[]; `notEnforced`?: (string)[]; `directParameter`?: WithNoteSpellingsMalformedIsRefused; `preview`?: WithAskedOkErrorEtc17 }

@hoisted model WithIssuersUsableKeysKeyProblemsEtc8 { `issuers`?: (string)[]; `usableKeys`?: integer; `keyProblems`?: (StringOrNumericOrBooleanEtc4)[]; `issuedToken`?: string; `issued`?: NullableObject70; `registeredWith`?: NullableObject71; `settings`?: WithRequireTrustedIssuerOpensRegistrationRequiredEtc4; `json`?: WithDeclaredIssuersUsableKeysIssuedEtc5 }

@hoisted model WithJoseHttpsigCoseEtc6 { `jose`?: WithDescriptionSignSettingDescriptionEtc5; `httpsig`?: WithDescriptionSignSettingDescriptionEtc5; `cose`?: WithDescriptionSignSettingDescriptionEtc5; `xml`?: WithDescriptionSignSettingDescriptionEtc5; `di`?: WithDescriptionSignSettingDescriptionEtc5; `x509`?: WithDescriptionSignSettingDescriptionEtc5 }

@hoisted model WithRealmRegeneratedEveryStartSigningEtc9 { `realm`?: string; `regeneratedEveryStart`?: boolean; `signing`?: WithKtyBitsAlgEtc7; `curveKeys`?: (WithAlgKtyCrvEtc5)[]; `postQuantum`?: WithAlgorithmsGeneratedKeysEtc4; `signerGroups`?: WithModelKeys; `bbs`?: WithCryptosuiteCurveWhat; `tls`?: WithSubjectNamesFingerprint256Etc7; `spiffe`?: WithEnabledReadyPerRealmEtc13 }

@hoisted model WithOkErrorsErrorEtc132 { `ok`?: boolean; `errors`?: (string)[]; `error`?: string; `error_description`?: string; `mode`?: "create" | "get"; `challenge`?: string; `rpId`?: string; `user`?: WithNameDisplayNameId; `allow`?: (string)[]; `exclude`?: (string)[]; `options`?: WithRpAlgorithmsAttestationEtc10; `fallback`?: NullableObject33; `next`?: "refused" }

@hoisted model WithOkErrorsErrorEtc12 { `ok`?: boolean; `errors`?: (string)[]; `error`?: string; `error_description`?: string; `next`?: "signed-out" | "inventory" | "refused"; `username`?: string; `account`?: string; `location`?: string; `ownSessionEnded`?: boolean; `scope`?: "global" | "selected"; `form`?: WithMethodActionFieldsEtc4; `view`?: WithStateScopeKeyEtc11 }

@hoisted model WithPageGroupsSettingCountEtc11 { `page`?: string; `groups`?: (WithGroupSettings3)[]; `settingCount`?: integer; `editableCount`?: integer; `overridden`?: (string)[]; `setWith`?: string; `context`?: WithConfigFileDefaultsFilePersistsAppconfigEtc72; @js(#{`description`:"The other pages, by settings group."}) `sharedWith`?: Record<({`path`?: string; `label`?: string})[]> }

@hoisted model WithLabelHeldSourceEtc12 { `label`?: string; `held`?: boolean; `source`?: string; `privateKeyHeld`?: boolean; `certificate`?: NullableObject69; `chain`?: (WithSubjectIssuerSerialHexEtc102)[]; `handle`?: string; `handleLabel`?: string; `issuers`?: (string)[]; `attributes`?: WithIssuerCertificateChainEtc10; `registered`?: WithAttributeProblemKeysEtc4; `purpose`?: string }

@hoisted model WithRealmIssuerNodesEtc13 { `realm`?: WithIdNameIsDefault2; `issuer`?: string; `nodes`?: (WithIdKindKeyEtc27)[]; `edges`?: (WithIdFromToEtc53)[]; `tokens`?: (WithSeqAtKindEtc13)[]; `tokensLeftOff`?: integer; `maxTokenRows`?: integer; `acts`?: integer; `chains`?: integer; `credentials`?: (WithAtFamilyKindEtc20)[]; `credentialsOnDelegationLines`?: integer; `subject`?: string; `counts`?: WithNodesEdgesGrants }

@hoisted model WithNameResolvedReasonsEtc12 { `name`?: string; `resolved`?: boolean; `reasons`?: (string)[]; @js(#{`description`:"Each enrollment family's label, by its id."}) `familyLabels`?: Record<string>; `urls`?: WithAcmeDirectoryScepEst; `fresh`?: WithKindKidHmacKeyEtc8; `enrolled`?: (WithSerialHexFamilyProfileEtc19)[]; `hostNames`?: (string)[]; `acme`?: NullableObject13; `est`?: NullableObject14; `scep`?: NullableObject15 }

@hoisted model WithLabelHeldSourceEtc14 { `label`?: string; `held`?: boolean; `source`?: string; `privateKeyHeld`?: boolean; `certificate`?: NullableObject69; `chain`?: (WithSubjectIssuerSerialHexEtc102)[]; `handle`?: string; `handleLabel`?: string; `issuers`?: (string)[]; `attributes`?: WithIssuerCertificateChainEtc10; `registered`?: WithAttributeProblemKeysEtc4; `id`?: string; `sealedAtRest`?: boolean; `certificatePem`?: string }

@hoisted model WithFamiliesRulesCertificateCapEtc10 { `families`?: (string)[]; `rules`?: (WithFamilyLabelAllowedProfilesEtc8)[]; `certificateCap`?: WithValueSource; `est`?: NullableObject74; `certificates`?: (WithSerialHexFamilyProfileEtc21)[]; `certificatesPaging`?: WithPagePagesPerPageEtc8; `certificatesTotal`?: integer; `eabKeys`?: (WithKidCreatedAtExpiresAtEtc7)[]; `scepChallenges`?: (WithIdProfileCreatedAtEtc7)[]; `hostNames`?: (string)[] }

@hoisted model WithRidDidCustodyEtc13 { `rid`?: string; `did`?: string; `custody`?: string; `documentUrl`?: string; `createdAt`?: NullOrStringOrNumeric; `by`?: string; `state`?: string; `deactivated`?: NullOrBooleanOrStringOrAtNullOrStringOrNumeric2ByStringReasonStringViaString; `proof`?: string; `preferred`?: boolean; `currentVersion`?: StringOrNumeric; `pending`?: NullableObject59; `versions`?: (WithVersionIdCreatedChangeEtc5)[] }

@hoisted model WithStateUsernameNamedEtc16 { `state`?: "inventory" | "accounts" | "refused" | "nobody"; `username`?: string; `named`?: boolean; `naming`?: "open" | "off" | "product"; `account`?: string; `key`?: string; `sessions`?: numeric; `families`?: (WithIdLabelProtocolEtc10)[]; `total`?: numeric; `listed`?: numeric; `notListed`?: numeric; `maxRows`?: numeric; `at`?: numeric; `accounts`?: (WithKeyUsernameDisplayNameEtc4)[]; `preselected`?: string; `verifiesCredentials`?: boolean }

@hoisted model WithOkErrorsErrorEtc17 { `ok`?: boolean; `errors`?: (string)[]; `error`?: string; `error_description`?: string; `next`?: "wait" | "redirect" | "mfa" | "password-change" | "home-cell" | "stay" | "refused"; `location`?: string; `step`?: string; `id`?: string; `form`?: WithMethodActionDescriptionEtc4; `notice`?: string; `end`?: {`title`?: string}; `passkey`?: WithUnknownCredentialAutofill; `go`?: string; `state`?: string; `expiresIn`?: numeric; `view`?: WithWalletHeadingRetryEtc8 }

@hoisted model WithIdKindThumbprintEtc11 { `id`?: string; `kind`?: string; `thumbprint`?: string; `label`?: string; `added`?: NullOrStringOrNumeric; `addedBy`?: string; `proof`?: string; `attestation`?: WithLevelFormatSummaryEtc7; @js(#{ `x-free-form`:"A device key's public material as its kind carries it: a client's JWK, a certificate, or a WebAuthn credential.", `description`:"A device key's public material as its kind carries it: a client's JWK, a certificate, or a WebAuthn credential." }) `material`?: unknown }

@hoisted model WithKeyNameFormsEtc17 { `key`?: string; `name`?: string; `forms`?: (WithFormCount)[]; `realms`?: (WithRealmCount)[]; `protocols`?: (WithProtocolCountFirstAtEtc5)[]; `authentications`?: numeric; `firstAt`?: numeric; `lastAt`?: numeric; `isClient`?: boolean; `authenticated`?: boolean; `knownBy`?: string; `events`?: (WithAtProtocolMethodEtc12)[]; `eventsForgotten`?: numeric; `tokens`?: WithIssuedValidExpiredEtc5; `artifactKinds`?: (WithKindCount)[]; `artifacts`?: numeric; `lastActivityAt`?: numeric }

@hoisted model WithUsernamePasswordPrimaryKeysEtc18 { `username`?: string; `password`?: boolean; `primaryKeys`?: numeric; `mfaKeys`?: numeric; `keys`?: (WithCredentialIdPublicKeyJwkSignCountEtc36)[]; `totp`?: boolean; `totpUsable`?: boolean; `totpDetail`?: NullableObject54; `usable`?: boolean; `backupCodes`?: NullableObject55; `mfaRequired`?: boolean; `mailFactor`?: WithHeldOptedInWhyEtc4; `secondFactor`?: NullableString; `activated`?: boolean; `recoveryAdvised`?: boolean; `mfaRequirement`?: WithRequiredByUserByRealmEtc6; `passwordResetLink`?: NullableObject56; `disabled`?: boolean }

@hoisted model WithKeyNameFormsEtc22 { `key`?: string; `name`?: string; `forms`?: (WithFormCount)[]; `realms`?: (WithRealmCount)[]; `protocols`?: (WithProtocolCountFirstAtEtc5)[]; `authentications`?: numeric; `firstAt`?: numeric; `lastAt`?: numeric; `isClient`?: boolean; `authenticated`?: boolean; `knownBy`?: string; `events`?: (WithAtProtocolMethodEtc12)[]; `eventsForgotten`?: numeric; `tokens`?: WithIssuedValidExpiredEtc5; `artifactKinds`?: (WithKindCount)[]; `artifacts`?: numeric; `lastActivityAt`?: numeric; `factors`?: NullableObject42; `inDirectory`?: boolean; `serviceAccount`?: boolean; `liveSessions`?: NullableNumber; `dn`?: string }

@hoisted model WithPageIdUsernameEtc22 { `page`?: string; `id`?: string; `username`?: string; `passwordless`?: boolean; `links`?: WithTotpWebauthnWalletEtc6; `clientDisplay`?: NullableObject30; `totp`?: WithDigitsPeriod; `amr`?: (string)[]; `backup`?: WithFactorBackRemainingEtc5; `webauthn`?: WithModePasswordlessChoicesEtc21; `setup`?: WithStateOfferedOptionalEtc6; `postLogin`?: WithActivityReasonRequiredEtc9; `state`?: "ask" | "code" | "wait" | "open" | "elsewhere" | "end"; `kind`?: "code" | "link"; `primary`?: boolean; `address`?: string; `minutes`?: numeric; `seconds`?: numeric; `notice`?: string; `others`?: WithTotpWebauthnPasswordEtc4; `title`?: string; `sentence`?: string }

@hoisted model WithKeyGroupLabelEtc27 { `key`?: string; `group`?: string; `label`?: string; `description`?: string; `type`?: string; `enumValues`?: (string)[]; `csvValues`?: (string)[]; `ordered`?: boolean; @js(#{`description`:"The sentence beside each of a list's values."}) `csvValueNotes`?: Record<string>; `selectAll`?: WithOnlyWhileOnAloneWhileOn; `min`?: numeric; `max`?: numeric; `step`?: numeric; `value`?: StringOrNumericOrBooleanEtc2; `text`?: string; `source`?: string; `editable`?: boolean; `restartReason`?: string; `editRefusal`?: string; `env`?: NullableString; `legacyEnv`?: NullableString; `appconfigPath`?: string; `default`?: StringOrNumericOrBooleanEtc2; `masked`?: boolean; `realmSettable`?: boolean; `overridden`?: boolean }

@hoisted model WithModeConfiguredModeEnabledEtc32 { `mode`?: string; `configuredMode`?: string; `enabled`?: boolean; `healthy`?: NullableBoolean; `dataDir`?: NullableString; `database`?: NullableObject79; `engine`?: NullableString; `writeDelayMs`?: numeric; `persistsDirectory`?: boolean; `persistsRealms`?: boolean; `persistsAppconfig`?: boolean; `pending`?: boolean; `writes`?: numeric; `failures`?: numeric; `lastWriteAt`?: NumericOrStringOrNull; `lastError`?: NullableString; `restoredAt`?: NumericOrStringOrNull; `restored`?: WithRealmsEntriesOverrides; `entriesTracked`?: numeric; `realmsTracked`?: numeric; `coordinates`?: boolean; `minted`?: WithPersistingSupportedUnsupportedReasonEtc23; `usedAssertions`?: WithStoreKindPersistentEtc8; `replication`?: WithCoordinatingSupportedStartedAtEtc21; `cells`?: NullableObject81; `origin`?: NullableObject82; `answersAfterCommit`?: boolean; `commitBacklog`?: boolean; `retryArmed`?: boolean; `liveness`?: NullableObject83; `eventLoop`?: NullableObject84; `note`?: string }

@hoisted model WithPqcOnlySurfaces { `pqcOnly`?: boolean; `surfaces`?: WithJoseHttpsigCoseEtc6 }

@hoisted model WithOkErrorsErrorEtc412 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithNameResolvedReasonsEtc12 }

@hoisted model WithOkErrorsErrorEtc413 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithEnabledTurnOnLoginHintEtc8 }

@hoisted model WithOkErrorsErrorEtc414 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithPasswordMfaRequiredKeysEtc5 }

@hoisted model WithPermWantedGrantWantedPermPageEtc4 { `permWanted`?: string; `grantWanted`?: string; `permPage`?: WithShownPaging9; `grantPage`?: WithShownPaging6 }

@hoisted model WithStepUpOkMessageEtc5 {`stepUp`?: WithAcrValuesPromptMaxAge; `ok`?: boolean; `message`?: string; `go`?: string; `view`?: WithEnabledTurnOnLoginHintEtc8 }

@hoisted model WithUserEntryFoundPublishingEtc6 { `user`?: string; `entryFound`?: boolean; `publishing`?: boolean; `custody`?: string; `maxPerPerson`?: numeric; `dids`?: (WithRidDidCustodyEtc13)[] }

@hoisted model WithCredentialIssuerCredentialConfigurationIdsGrants { `credential_issuer`?: string; `credential_configuration_ids`?: (string)[]; `grants`?: WithUrnIetfParamsOauthGrantTypePreAuthorizedCodeAuthorizationCode }

@hoisted model WithInstalledStreamsSettingsEtc4 { `installed`?: boolean; `streams`?: (WithStreamIdStatusStatusReasonEtc14)[]; `settings`?: (WithSettingAttributeValueEtc4)[]; `json`?: WithInstalledStreamsSettings }

@hoisted model WithOkCsrfUiLocalesEtc82 { `ok`?: boolean; `csrf`?: string; `uiLocales`?: string; `preferredLanguage`?: WithValuePopulated; `view`?: WithPageIdUsernameEtc22; `errors`?: (string)[]; `error`?: string; `error_description`?: string }

@hoisted model WithOkCsrfUiLocalesEtc83 { `ok`?: boolean; `csrf`?: string; `uiLocales`?: string; `preferredLanguage`?: WithValuePopulated; `view`?: WithStateUsernameNamedEtc16; `errors`?: (string)[]; `error`?: string; `error_description`?: string }

@hoisted model WithResourcesPermissionsGrantsEtc4 { `resources`?: (WithIdentifierNameBaseUriEtc6)[]; `permissions`?: (WithResourceResourceNameBaseUriEtc82)[]; `grants`?: (WithClientClientNamePermissionIdEtc102)[]; `counts`?: WithResourcesPermissionsUnidentifiedEtc8 }

@hoisted model WithStorableFoundKeyPairsEtc9 { `storable`?: boolean; `found`?: boolean; `keyPairs`?: (WithPurposeLabelHeldEtc10)[]; `maxPerPerson`?: numeric; `revocationReasons`?: (string)[]; `caAvailable`?: boolean; `sealsAtRest`?: boolean; `selfService`?: boolean; `sources`?: (string)[] }

@hoisted model WithOkEnabledResourcesEtc10 { `ok`?: boolean; `enabled`?: boolean; `resources`?: (WithIdNameTypeEtc6)[]; `paging`?: WithPagePagesTotal; `custom`?: (WithIdDescriptionAlfa)[]; `pending`?: (WithIdClientRequestingPartyEtc5)[]; `alfaEditing`?: boolean; `alfa`?: string; `version`?: Shape; `recipients`?: (string)[] }

@hoisted model WithStorableFoundUsernameEtc10 { `storable`?: boolean; `found`?: boolean; `username`?: string; `purposes`?: (WithIdLabelHeldEtc10)[]; `ca`?: WithAvailableKeyAlgLeafLifetimeDaysEtc4; `sealsAtRest`?: boolean; `selfService`?: boolean; `sources`?: (string)[]; `maxPerPerson`?: numeric; `revocationReasons`?: (string)[] }

@hoisted model WithUsernameEntryHoldsAnyEtc11 { `username`?: string; `entry`?: boolean; `holdsAny`?: boolean; `offered`?: boolean; `issuable`?: boolean; `tokenEndpoint`?: string; `maxPerPerson`?: numeric; `reasons`?: (string)[]; `profiles`?: (WithIdRfcGrantTypeEtc5)[]; `tls`?: WithSignInTrustedNoteEtc7; `fresh`?: NullableObject11 }

@hoisted model WithClientSecretKeyPairsCaAvailableEtc8 { `clientSecret`?: WithHeldAuthMethodRegisteredEtc7; `keyPairs`?: (WithLabelHeldSourceEtc12)[]; `caAvailable`?: boolean; `oauthDeclared`?: boolean; `sources`?: (string)[]; `mtls`?: WithCertificatesActiveMaxEtc18; `signing`?: WithCertificatesActiveMaxEtc13; `stored`?: WithOkErrorsApplicationEtc6 }

@hoisted model WithOauthDeclaredClientSecretPurposesEtc8 { `oauthDeclared`?: boolean; `clientSecret`?: WithHeldAuthMethodRegisteredEtc9; `purposes`?: (WithLabelHeldSourceEtc14)[]; `ca`?: WithAvailableKeyAlgKeyAlgorithmsEtc4; `sources`?: (string)[]; `mtls`?: WithCertificatesActiveMaxEtc18; `signing`?: WithCertificatesActiveMaxEtc13; `stored`?: WithOkErrorsApplicationEtc6 }

@hoisted model WithResourcesPermissionsGrantsEtc7 { `resources`?: (WithIdentifierNameBaseUriEtc6)[]; `permissions`?: (WithResourceResourceNameBaseUriEtc82)[]; `grants`?: (WithClientClientNamePermissionIdEtc102)[]; `counts`?: WithResourcesPermissionsUnidentifiedEtc8; `graph`?: WithRealmIssuerNodesEtc13; `filter`?: WithPermissionsGrants; `paging`?: WithPermissionsGrants2 }

@hoisted model WithHeldExposesOfferableEtc8 { `held`?: (WithClientClientNamePermissionIdEtc10)[]; `exposes`?: (WithResourceResourceNameBaseUriEtc8)[]; `offerable`?: (WithResourceResourceNameBaseUriEtc8)[]; `clients`?: (WithIdentifierName)[]; `heldPage`?: WithPagingShown2; `exposedPage`?: WithPagingShown4; `grantedOutPage`?: WithPagingShown2; `registerPermissions`?: integer }

@hoisted model WithFamiliesRulesCapEtc11 { `families`?: (string)[]; `rules`?: (WithFamilyLabelAllowedProfilesEtc8)[]; `cap`?: WithValueSource; `est`?: NullableObject74; `certificates`?: (WithSerialHexFamilyProfileEtc21)[]; `paged`?: WithPagingShown3; `eabKeys`?: (WithKidCreatedAtExpiresAtEtc7)[]; `challenges`?: (WithIdProfileCreatedAtEtc7)[]; `hostNames`?: (string)[]; `keyAlgorithms`?: (string)[]; `json`?: WithFamiliesRulesCertificateCapEtc10 }

@hoisted model WithAttributeTypeLongEtc19 { `attribute`?: string; `type`?: string; `long`?: boolean; `editable`?: StringOrBoolean; `sensitive`?: boolean; `overrides`?: string; `choices`?: NullableArray; `example`?: NullableString; `what`?: string; `families`?: (string)[]; `everyFamily`?: boolean; `declaration`?: boolean; `primaryName`?: boolean; `simple`?: boolean; `group`?: string; `section`?: string; `sectionLabel`?: string; `described`?: WithKeyGroupLabelEtc27; `inSimple`?: boolean }

@hoisted model WithStepUserTokenEtc22 { `step`?: string; `user`?: string; `token`?: string; `base`?: string; `rules`?: WithEnforcedRules; `webauthnEnabled`?: boolean; `passkeyOffered`?: boolean; `passkeyAlone`?: boolean; `kinds`?: (string)[]; `lanes`?: (string)[]; `totpOffered`?: boolean; `title`?: string; `refused`?: string; `passkey`?: boolean; `secondStep`?: boolean; `wantsTotp`?: boolean; `pending`?: WithIdKindLaneEtc11; `enrolment`?: WithGroupedIssuerQrEtc6; `warning`?: string; `password`?: boolean; `withTotp`?: boolean; `signIn`?: string }

@hoisted model WithIdDnOwnerEtc24 { `id`?: string; `dn`?: string; `owner`?: string; `ownerKind`?: string; `label`?: string; `applications`?: (string)[]; `keys`?: (WithIdKindThumbprintEtc11)[]; `keyKinds`?: (string)[]; `attestation`?: WithLevelFormatSummaryEtc4; `compliance`?: string; `complianceChange`?: NullableObject57; `status`?: string; `statusChange`?: NullableObject57; `riskLevel`?: string; `riskChange`?: NullableObject57; `platform`?: string; `model`?: string; `os`?: string; `enrolment`?: WithMethodAtActor; `nativeSso`?: boolean; `rememberedBrowser`?: NullableObject58; `sessionLive`?: boolean; `lastUsed`?: NullOrStringOrNumeric; `created`?: NullOrStringOrNumeric }

@hoisted model WithUserMaxPerPersonDevices { `user`?: string; `maxPerPerson`?: numeric; `devices`?: (WithIdDnOwnerEtc24)[] }

@hoisted model WithCredentialsConfig { `credentials`?: WithFamiliesRulesCapEtc11; `config`?: WithFamiliesRulesCapEtc11 }

@hoisted model WithOkErrorsErrorEtc415 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithStepUserTokenEtc22 }

@hoisted model WithOkErrorsErrorEtc416 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithOkEnabledResourcesEtc10 }

@hoisted model WithOkErrorsErrorEtc417 { `ok`: boolean; `errors`: (string)[]; `error`?: string; `view`?: WithUsernameEntryHoldsAnyEtc11 }

@hoisted model WithRegisterListStateAllApplications { `register`?: WithResourcesPermissionsGrantsEtc4; `listState`?: WithPermWantedGrantWantedPermPageEtc4; `allApplications`?: (WithIdentifierName)[] }

@hoisted model WithConfigurationIdSigningAlgModeEtc8 { `configurationId`?: string; `signingAlg`?: string; `mode`?: string; `credentialOffer`?: WithCredentialIssuerCredentialConfigurationIdsGrants; `txCode`?: NullableString; `expiresAt`?: string; `byValue`?: WithOfferUriWalletUrl; `byReference`?: NullableObject21 }

@hoisted model WithFieldsDescriptionValuesEtc18 { `fields`?: (WithAttributeTypeLongEtc19)[]; @js(#{`description`:"Each field's values, by attribute."}) `values`?: Record<(string)[]>; `groups`?: (WithIdLabelFamilies)[]; `familyChoices`?: (WithIdLabelFamiliesEtc5)[]; `protocols`?: (WithIdLabelKindEtc11)[]; `longTextAttributes`?: (string)[]; @js(#{`description`:"What each attribute's search looks through."}) `fieldSearches`?: Record<string>; `observed`?: WithOauthGrantTypeObservedOauthResponseTypeObservedAppRedirectUriObservedEtc10; `derived`?: WithOauthAllowedScope; @js(#{`description`:"By attribute."}) `fieldWarnings`?: Record<({ `attribute`?: string; `value`?: string; `reason`?: string; `dropped`?: boolean; `text`?: string })[]> }

@hoisted model WithConfigurationsModesLifetimeSecondsEtc8 { `configurations`?: (WithIdFormatNameEtc6)[]; `modes`?: (string)[]; `lifetimeSeconds`?: numeric; `wallet`?: NullableString; `batchSize`?: numeric; `issued`?: (WithIdConfigurationIdNameEtc14)[]; `paging`?: WithPagePagesPerEtc4; `offer`?: WithConfigurationIdSigningAlgModeEtc8 }

@hoisted model WithStorableMechTotpEtc15 { `storable`?: boolean; `mech`?: WithUsernamePasswordPrimaryKeysEtc18; `totp`?: WithEnabledIssuerDigitsEtc8; `webauthn`?: WithEnabledRpNameRpIdEtc19; `recovery`?: WithEnabledCountLengthEtc4; `appPasswords`?: WithOkUnreadablePasswordsEtc4; `doors`?: WithSecondFactorRefusedAcceptedEtc5; `verifications`?: WithUserTrustFrameworksEvidenceTypesEtc14; `inventsClaimValues`?: boolean; `devices`?: WithUserMaxPerPersonDevices; `selfIssued`?: WithUserEntryFoundSignInEnabledEtc6; `publishedDids`?: WithUserEntryFoundPublishingEtc6; `certificates`?: WithOkErrorsUserEtc6; `signing`?: WithOkKindHolderEtc12; `mail`?: WithStatusUsableAudSubs }

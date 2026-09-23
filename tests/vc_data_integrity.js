'use strict';
//
// File: vc_data_integrity.js
//
// ===========================================================================
// A HOLDER'S DATA INTEGRITY PROOF ON A PRESENTATION (#38 follow-ups,
// 2026-09-17) — `oid4vc/vc_data_integrity.ts`, the library an `ldp_vc`
// sign-in's freshness rests on. Held:
//
//   A. JCS AND THE PUBLISHED VECTORS. The canonical forms and hashes the
//      three specifications print — eddsa-jcs-2022 (EdDSA Cryptosuites v1.0
//      B.3), ecdsa-jcs-2019 with P-256 and P-384 (ECDSA Cryptosuites v1.0
//      A.5, A.6) and mldsa44-jcs-2024 (Quantum-Resistant Cryptosuites v1.0
//      A.5.2) — come out byte for byte; each published signed credential
//      verifies against the key its did:key names; Ed25519 is deterministic,
//      so signing the published document with the published secret key
//      gives the published proofValue exactly; and each published secret key
//      derives the public key the did:key resolves to.
//   B. ROUND TRIPS for P-256, P-384, Ed25519 and ML-DSA-44: a presentation
//      signed here, with a did:jwk verification method and `holder` naming
//      it, verifies with its challenge and domain.
//   C. REFUSALS, each by the check named for it: a wrong challenge, a wrong
//      domain, a wrong purpose, no expected challenge at all, a tampered
//      document, a tampered proof configuration, a key that is not the
//      method's, an unsupported cryptosuite, one the caller did not allow, a
//      missing proofValue, a non-`z` multibase, a stale and a future
//      `created`, a passed `expires`, a holder the key does not belong to, a
//      proof chain, and a method that would have to be fetched. A domain set
//      containing the expected value, and a proof set, are accepted.
//   D. IDENTIFIERS: did:jwk both ways (and a private member refused),
//      did:key both ways for the three published keys, and the keys no
//      cryptosuite signs with named with a reason.
// ===========================================================================

const nodeCrypto = require('crypto');

const log = require('bunyan').createLogger({ name: 'vc_data_integrity_test',
  level: process.env.LOG_LEVEL || 'info' });

// --- eddsa-jcs-2022, EdDSA Cryptosuites v1.0 B.3 ---------------------------
const ED_PUBLIC = 'z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2';
const ED_SECRET = 'z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq';
const ALUMNI = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2'
  ],
  id: 'urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33',
  type: ['VerifiableCredential', 'AlumniCredential'],
  name: 'Alumni Credential',
  description: 'A minimum viable example of an Alumni Credential.',
  issuer: 'https://vc.example/issuers/5678',
  validFrom: '2023-01-01T00:00:00Z',
  credentialSubject: {
    id: 'did:example:abcdefgh',
    alumniOf: 'The School of Examples'
  }
};
const ALUMNI_CANONICAL = '{"@context":["https://www.w3.org/ns/credentials/' +
  'v2","https://www.w3.org/ns/credentials/examples/v2"],"credentialSubject"' +
  ':{"alumniOf":"The School of Examples","id":"did:example:abcdefgh"},' +
  '"description":"A minimum viable example of an Alumni Credential.","id":' +
  '"urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33","issuer":"https://vc.' +
  'example/issuers/5678","name":"Alumni Credential","type":["Verifiable' +
  'Credential","AlumniCredential"],"validFrom":"2023-01-01T00:00:00Z"}';
const ED_HASH = '66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe' +
  '539a1db59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19';
const ED_PROOF_VALUE = 'z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS' +
  '93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX';

// --- ecdsa-jcs-2019, ECDSA Cryptosuites v1.0 A.5 and A.6 -------------------
const P256_PUBLIC = 'zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP';
const P256_SECRET = 'z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN';
const P256_HASH = 'fe5799489119c7fe3c528715e72bd39d2ec6b4ab345978df32e9a93' +
  '12648ec2559b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19';
const P256_PROOF_VALUE = 'z5ptCet75SaEgzG4v4zJhbJtfNi74Wv7Fq15hhKouJQQjEPQv' +
  'PZKaYxcMXAMLPQS2FXrkCWokNJkFVkwxNzZfD5oT';
const P384_PUBLIC = 'z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4Luto' +
  'YWhvQCnGjdVn14kujQ';
const P384_SECRET = 'z2fanyY7zgwNpZGxX5fXXibvScNaUWNprHU9dKx7qpVj7mws9J8LL' +
  't4mDB5TyH2GLHWkUc';
const P384_HASH = '83e5057817abb0c6872eafeaba1a9e53893c58eeb7414fb6d8aa3fa8' +
  'c7917f7ad4792890b257c598baa17f4fbe6d183c3e0be671cc1881035d463158c8092197' +
  '3dab3534d4f8dfacf4ff2725a4115eb718e49d66de0e90e7365cd6062abf2259';
const P384_PROOF_VALUE = 'zq3EuTeLiGurmB2JR5oL8oWEsT7u2tba4HT1oZbiMYWc5qzso' +
  'W2kLYcBcF4HM5vCpJyTkceULKrVXuJQkXeN5seL4uXrFNFRMm53GWy1Yrto8rTWxZi9DkNe' +
  'WP7yUPs7ELAm';

// --- mldsa44-jcs-2024, Quantum-Resistant Cryptosuites v1.0 A.5.2 -----------
const MLDSA_HASH = '1f49de8352bfcdef9457b14be9f4375c7288fb914cf1c974eab20f3' +
  'd145b011a6ca388adaff807c71d063f666548493ba60c8c0fa109b3dd1e2564d61abe09cc';

const MLDSA_SIGNED = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://w3id.org/citizenship/v4rc1'
  ],
  type: [
    'VerifiableCredential',
    'EmploymentAuthorizationDocumentCredential'
  ],
  issuer: {
    id: 'did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76',
    image:
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAA' +
      'AfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg=='
  },
  credentialSubject: {
    type: [
      'Person',
      'EmployablePerson'
    ],
    givenName: 'JOHN',
    additionalName: 'JACOB',
    familyName: 'SMITH',
    image:
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAA' +
      'AfFcSJAAAADUlEQVQIW2Ng+M/wHwAEAQH/7yMK/gAAAABJRU5ErkJggg==',
    gender: 'Male',
    residentSince: '2015-01-01',
    birthCountry: 'Bahamas',
    birthDate: '1999-07-17',
    employmentAuthorizationDocument: {
      type: 'EmploymentAuthorizationDocument',
      identifier: '83627465',
      lprCategory: 'C09',
      lprNumber: '999-999-999'
    }
  },
  name: 'Employment Authorization Document',
  description: 'Example Employment Authorization Document.',
  validFrom: '2019-12-03T00:00:00Z',
  validUntil: '2029-12-03T00:00:00Z',
  proof: {
    type: 'DataIntegrityProof',
    cryptosuite: 'mldsa44-jcs-2024',
    created: '2023-02-24T23:36:38Z',
    verificationMethod:
      'did:key:ukCRKDtY8Do_dXzYGyuX7BY-1dDYM4FuSiw0gFdO-eJXFH0eqlt4' +
      '_CP4sEISGAzNlKDzLpUJWoInRywXOpd7FCp_QAJAlL7iRo4cepKhzhlq8xt6' +
      'qd5jkhYF9tNH8z3RGDl9aunNy_06fWLYNScWd5RmGg46Po8T-kIjMMkJftaq' +
      'qZcGDxktpu9Et2bnaZMx4K98YyG1urUpM9lgvldgg2qv-6XCrm2uXlJ9U-HN' +
      '4xtQKn4Ug-5xPwbhPGR2pbcBScTFotkhBqLc2eQLL6zPutWF83sSZbOhD_11' +
      'BjMkeiLyJbMeHCIhz5GDIbPksEFIaSho3MdFo5fpQ8QZoqCit3Jn4ddfuShf' +
      'IoLU1Hw5EZ0xBiqOU7e-TINd7-7HsgHLmYMGnpqljm1ot3c3cfalYsg87WQu' +
      'SscO7XNH3Ewa-cgU6Bnj1SGn0plTy6Yq-GxU8XUBPwsK_IoIJbXWC0UD97c9' +
      'UYpNiZi0-ECnbB-Y5_SM8auMfoIeap_buAOdXlJZmcp8xNCXI59AN9-96Sdh' +
      'ks5L-JmsELzyjAgjqNx8Zt3KPFc2jSwNjDVC1fEa8FdDdDT3WNkF6KTt65lb' +
      '5_aIkFh20nOvT7kIJcKTgmhRGNJZgGSPYVbMypaQoaac8dtEoQjvYgnO-rM_' +
      'RcsiWMHNc29br3o5wdiLXdr63MoX1lEWu_THBfeP1JuxrSbUmHOByepWbubb' +
      'SM4iVQITCxBHZT0Mj2bWwIxd3nZUajzebyEnsfitV01kpzlO7bzY2uxSzypl' +
      'TkRfppc_7YH0y0PHaggw0cIXNSh73wVqNZmzmJx5W0_akrvy5oSz9ZB1Io2p' +
      '_fTxzibefwO700bUqbElV_yuCjD7EJ_Hfqbog80y_g9TK6koX7wYwqFNQxBV' +
      'avKC-HbcT7yPdvzs9hlC2MNWCT3W7gVgeYr4AFgbV9EgMcH0GtJDKYw8vkpB' +
      '_vTsaSTGZAj3TNKalAwiGO50VAmF5tknF96kOrWmNL0MdkXhnm1vXgDpP68b' +
      'Mt4r2Qr-hNdJ4s3_nqmSDYTnZRA4qjXjrgKQfO19txt0tX7LifE1GZ1bQyS7' +
      'NqHWXyMEhw6_F8pc_tS16VhvJO_FM7CX51mLLkLCGl7DsmbnEIsVUW9qlCxb' +
      '6bj53UyijTYdu6uLZW9JISE2B4EevxzwDu9UGcJPHmJYi1rRQAP__jH97GiQ' +
      'C8FvkdAEfKqcwV9jAbBPQPG6lUkBLcoijgR3Bcwd-ta92oeZmcpoJ97PzzBb' +
      'CL-NrppJ2HHQ1SMsYWoPveZTmZc66YBA0P9YfT4hZ0RQiP2gxB4snTvMFI0O' +
      't6Q2nQ0p5DMxmWqIaCKW53rqn16AVXQeqC2TJjlbjA9sC6pr8GEGY2OQUgEm' +
      'Wu5GmnOSz1lNY7fNHJypChnieI_hyYiy06qouUpoHA5z_IUtfzZoMIG0yJiG' +
      'UUpF9BJvYChDECCqaUM1kWnO5tKcohSKq5Hqwu_EWDRYF2tj7igSimZkS4Pt' +
      's41tu8nIaVk5EkzAX9gCR2EX3Lk869mIxSyBS3MyG_NotPcbm6uXDn_YkV5Z' +
      '0HkxUxYRA9hIG-UhKhK3VOaHZP8GcQN8noOMa2CnPd208X6HOzlIlxs7SRbz' +
      'ppUs_fHN1eROglNy-2oJWGmo-xOy0Qd44TtY0S_bYhu6iH6inrx3-yncSrWF' +
      'xEiYosvYJD4ZBSyrV4d6UsfeNSHYS0ODTsdPqz4SYTeloZbIx8XWz7fxLXlN' +
      'yLr3s9tp-Q25f1vTIrmQL',
    proofPurpose: 'assertionMethod',
    proofValue:
      'uTSucVLvXmOpmjGGNB-B9rM-u4HzBxN8ZIuZbpTHrjOTNBnahoE4PSdkeD-I' +
      'zLLXykJn0aYq_APExy-Ka0BcJNMvKgkdjbbP33WmUwkzljno3szRUDrN9KX2' +
      'DMH7j0iOBakU4ByjD-hTSO1iR6rlxsZPHJM1H-WLMhzVSggBILAuglItzstl' +
      '663Gz5bFjEfbKAgfe50L4v4PjLFSDbJYcg65GtCKRXISkWrnJRuToWwvTVdc' +
      'nIBOQwPBFKsvApPJMKrUTkIuZf4-V1uJ81zzct4o20O-DqLQ5bHfOR2n5Y4D' +
      'Sy6e5zg0-S3ADKtMtuPaQ8cAPUTEKRXGRQnSndnrtgMh2dimvpSaaw0TDy7z' +
      'Y6vrDxJa1tkrS0ulKf3Xz8xsNrNIkx4SaKYWPTjhRvdKqjdrpbGRt3mRSFFc' +
      '0VE8vK44F_EVFIhwouL-4Rm4mXU2QkiO0YkwuAJM-QdWUACqzJ7TSf2QrrU8' +
      'zAwOLbrGS5uZ1qLGD1PcgWfg2d0zTAYmcWP4LP63fTnFxwr-L0N_3MLFXixH' +
      'NEp5osMlo2lhl5noDCmQpqCgluxkd5gXs1NSpOBbWVQyYWcj0WMBtMam8Aeq' +
      'XpA39L7oqvYxqbEpiwvKrmHsXIEZrnsHKCk2P0yc10AFCCtsIapvTHwIAjbD' +
      'hX11HFU5cci4X5vCdG2BUzRsgmGeiYiUClCHmqsBW4z2GA9r0d9jtHZ03nMi' +
      'e_qS95XPsXuAFqypsP1HOfcIUAHHS9Wn4XGFz3hXoqMsmoUGRg9vEpC2j_nk' +
      'cYZQphYLs54veWq5BBzoMqPuvYhhRdawdCnn-LTf7AxQgVGoRTpTy4IkXxr_' +
      'pC1LUJZJkdKeG-2TuQzyHSkbMPu3YbWsGy2KxdGeFN2yUI8TTQ-MFHl-_jDC' +
      'RBrAYyCVOgML4NAtbGqvs7h2tGZYI-m9MfjG0vjp7CUyIPD8BV-Yhku_bHd0' +
      'hcrseKtYYyUjxISf2wveo4dfQ2AnCVdDAbBmznjPIDlkqx0316sRc-vXJGRQ' +
      'mfXOW1dNk-7WNBrJVQbnT9m6cf0UEl3mEgagk1_lLOxTgjzZRpWcOB827VB3' +
      'hPi7RdI6U6knXuOflHPt9BZN7i6OAl76k69uMFH2KNH3Abm0GDhOv_nu1lEa' +
      'OH8aXdOqL3U8Yo0cp5roOoTw5fJP2gxwI3DY0TOWeNOCfLXmnodgoGaKG2Vn' +
      's4_-gN_Mg7g0ZinguwJMwKACx07H__ffh8jYQdc87EjCNyH4m8hJICvcC81J' +
      '7CKb89YTZm7IM0D1_qTR5t-DkuU4ypxNuFOCxWpN9y2QiLAAobDdc1Y_S3nX' +
      'FFkLmsn7hUNhcgXxPC3jLifiM0IV7DAqmQpk2ZGE59l0VTKb3F2Ualj9JcqK' +
      'tLg_b2KqprUol9WtjFlkbxqJPYyCKnSEitzDnDsfxTRFEIViTx5-1SFb0NjP' +
      'E_hv5MewCkizNpfo0b-m-FxvyWJnDYt4Igv8JtgF0K_xMRC9Tf3NaQgFHb1O' +
      'gkBz04C3wsxoPLqTgMWoxcZ2-2x7TRRvX2Nh1Ye-ZrpmF5hVeRMK0ECj_t5H' +
      'LPaq2md18rqnhwsZv84-V0eReDyXVIhkE2eAKedCM9t13UjTfF1qFoUQ3D8x' +
      'Q6MfR7zFwf6X78Tb0EFs0cBQ1TatzWysbE2b_0k-YbT78G4Ko8FlmTljBN1b' +
      '0StKxzOE1Kp1h4nDBY9jZYYPNnVrtAGn2AKN3HWr0bhhF8fW_G4SA_MGu2r6' +
      'LnobB3MLCSj1lbVZSk5YtCtMnkldAsDagoI8lRBlKW1R7PFvXatSHcwbe352' +
      'nVuvZYxs9QJVSylf2QS1xeUQUMS4AHd4h8Y9HqmnGPr5JX65uch8sr1bWcpG' +
      'iNlwnMlFy89pnEZU2v7IiC_foLi8JbxMud1k2XRDwThhepEf5bxqlBcgjF8v' +
      'AbGEKAJg5Oahl0GCBffuHhuUXmuF6XwOxLovlJUM8oFCTayQL42NGz_Z2cuF' +
      'ltmiy-cbI8NmEpvlOPnGZBj00ZIrp9tAgwepYvlt5ticFn9ufU-f8xZpBpZb' +
      '-rf5sVTNqYmoOYvhKVhE5cCPpCbzZ5GvW5ukB8yLLJC5sc6df9oSoujovfA_' +
      'VAXqsvmBuKU4cHcNTNEqzsGEg_l0ln5FIHKH3CRUTDemKN2vbtmTz1snn4Vf' +
      'dBFAlhJhBItpBmd3HibH-1q2WD313j-cE5nW_QgQeDn_JFJ7zwlORQVRUkeB' +
      '942HJjkHWXCJMXz9LKxdncKalaVNm-yVjDkQdgA1tKl9bc_QnAL7HWhtHFc_' +
      'XhzJvQxqLJ0aLUkkrnphrqscG6D_Kdh7aTTkDjDSA-dmgRQBh51YVBnfnp5V' +
      '28AwmGXXglBAWCWChGmAtac6xeLbxW143426J4HMAUIpLgNhjetQoQqKzVTI' +
      'pzcyo-GK8L3C0calt57orTswSRqDjxg_6zAQ6RPNoThToRqb2QgHr-gOop6N' +
      'EJkEy0K8GwPg3nYAFgVVjcCyDtMEbIrHXJ9WKg3oTd14eC7GNZgQ75aP3HpU' +
      'AqT5gqWdxer35Ohs3n1FylwreS1kOZ5Z4OVW5PVJkNHhKPfaNq4mQT5vBAWl' +
      'WphOotPHwTbN7oMiOGYu-AMTnsLPCn0A3VEXx16EROpu0zlVisEZo1sya8nQ' +
      'aJYiI_i3MEWqvV2ypvcMDYt_ArFjxMU3tjV5tNcJgIoE5E5UCGyo2HQMvN03' +
      'T0GdHZr7txswg9HpRJqntiJzm0iAr9BhRPfErg4HLQyc92gOH6UdczP4hvbw' +
      'eP3mcW67yUT3lH31vznZ5lIJ0pth3H_7khwUff5daIROar2usWxoMWTItY5H' +
      'C7v5HBjnfqj4EoVi1A4Uw7RvHhaCMkfDrqqntNM0TDDSfDP1uCB1RwZtcuWp' +
      'NfLWYyP1B9XqwKg3EworHhIq1vI74gZROvebyYqx8UCFeiLubTfXHJrC2evT' +
      '99ha6jf7vg8zKgew6Cj3Jz_RSRE5rF5uQQno6PsevbKKtZsQmn0PQphfNzWq' +
      'acMpred2yrmetGOEG_JvYxx5Scmu8w8Yg-3V7yhMeDsOh0DZ8sjTw5d-w3zK' +
      'UNeU2IZzz5wvaJ7-8RRxyJqxFsUFaBv7WxUZ0bmWg4pRXdBUKNW53mEUGDig' +
      'pRF6Fla-6wc4BCDhwfJWdpaixu8Lf4fkRKCs0Y4-lrsTH1-zwNkKBudbd6v4' +
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbKDA'
  }
};

const MLDSA_PUBLIC_HEX =
  '4a0ed63c0e8fdd5f3606cae5fb058fb574360ce05b928b0d2015d3be7895c51f' +
  '47aa96de3f08fe2c108486033365283ccba54256a089d1cb05cea5dec50a9fd0' +
  '0090252fb891a3871ea4a873865abcc6deaa7798e485817db4d1fccf74460e5f' +
  '5aba7372ff4e9f58b60d49c59de51986838e8fa3c4fe9088cc32425fb5aaaa65' +
  'c183c64b69bbd12dd9b9da64cc782bdf18c86d6ead4a4cf6582f95d820daabfe' +
  'e970ab9b6b97949f54f87378c6d40a9f8520fb9c4fc1b84f191da96dc0527131' +
  '68b64841a8b7367902cbeb33eeb5617cdec4996ce843ff5d418cc91e88bc896c' +
  'c787088873e460c86cf92c10521a4a1a3731d168e5fa50f10668a828addc99f8' +
  '75d7ee4a17c8a0b5351f0e44674c418aa394edef9320d77bfbb1ec8072e660c1' +
  'a7a6a9639b5a2dddcddc7da958b20f3b590b92b1c3bb5cd1f71306be72053a06' +
  '78f54869f4a654f2e98abe1b153c5d404fc2c2bf2282096d7582d140fdedcf54' +
  '629362662d3e1029db07e639fd233c6ae31fa0879aa7f6ee00e757949666729f' +
  '313425c8e7d00df7ef7a49d864b392fe266b042f3ca30208ea371f19b7728f15' +
  'cda34b03630d50b57c46bc15d0dd0d3dd636417a293b7ae656f9fda224161db4' +
  '9cebd3ee420970a4e09a14463496601923d855b332a5a42869a73c76d128423b' +
  'd88273beaccfd172c89630735cdbd6ebde8e707622d776beb73285f59445aefd' +
  '31c17de3f526ec6b49b5261ce0727a959bb9b6d23388954084c2c411d94f4323' +
  'd9b5b02317779d951a8f379bc849ec7e2b55d35929ce53bb6f3636bb14b3ca99' +
  '539117e9a5cffb607d32d0f1da820c347085cd4a1ef7c15a8d666ce6271e56d3' +
  'f6a4aefcb9a12cfd641d48a36a7f7d3c7389b79fc0eef4d1b52a6c4955ff2b82' +
  '8c3ec427f1dfa9ba20f34cbf83d4caea4a17ef0630a85350c4155abca0be1db7' +
  '13ef23ddbf3b3d8650b630d5824f75bb81581e62be001606d5f4480c707d06b4' +
  '90ca630f2f92907fbd3b1a493199023dd334a6a50308863b9d15026179b649c5' +
  'f7a90ead698d2f431d9178679b5bd7803a4febc6ccb78af642bfa135d278b37f' +
  'e7aa64836139d9440e2a8d78eb80a41f3b5f6dc6dd2d5fb2e27c4d466756d0c9' +
  '2ecda87597c8c121c3afc5f2973fb52d7a561bc93bf14cec25f9d662cb90b086' +
  '97b0ec99b9c422c5545bdaa50b16fa6e3e775328a34d876eeae2d95bd248484d' +
  '81e047afc73c03bbd5067093c7989622d6b45000ffff8c7f7b1a2402f05be474' +
  '011f2aa73057d8c06c13d03c6ea552404b7288a3811dc173077eb5af76a1e666' +
  '729a09f7b3f3cc16c22fe36ba692761c743548cb185a83ef7994e665ceba6010' +
  '343fd61f4f8859d114223f6831078b274ef3052343ade90da7434a790ccc665a' +
  'a21a08a5b9debaa7d7a0155d07aa0b64c98e56e303db02ea9afc184198d8e414' +
  '804996bb91a69ce4b3d65358edf347272a4286789e23f872622cb4eaaa2e529a' +
  '07039cff214b5fcd9a0c206d3226219452917d049bd80a10c4082a9a50cd645a' +
  '73b9b4a7288522aae47ab0bbf1160d1605dad8fb8a04a2999912e0fb6ce35b6e' +
  'f2721a564e44933017f60091d845f72e4f3af662314b2052dccc86fcda2d3dc6' +
  'e6eae5c39ff6245796741e4c54c58440f61206f9484a84add539a1d93fc19c40' +
  'df27a0e31ad829cf776d3c5fa1cece5225c6ced245bce9a54b3f7c73757913a0' +
  '94dcbeda82561a6a3ec4ecb441de384ed6344bf6d886eea21fa8a7af1dfeca77' +
  '12ad6171122628b2f6090f86414b2ad5e1de94b1f78d487612d0e0d3b1d3eacf' +
  '84984de96865b231f175b3edfc4b5e53722ebdecf6da7e436e5fd6f4c8ae640b';

// A published secretKeyMultibase: a two-byte Multikey prefix and the raw
// private key (Ed25519 0x1300, P-256 0x1306, P-384 0x1307).
function secretBytes(di, multikey) {
  log.debug("Entering secretBytes().");
  const bytes = di.base58Decode(multikey.slice(1));
  log.debug("Leaving secretBytes().");
  return { prefix: bytes.subarray(0, 2).toString('hex'),
           raw: bytes.subarray(2) };
}

// The node private key a published secret names, given its public JWK.
function privateKeyFor(di, multikey, publicJwk) {
  log.debug("Entering privateKeyFor().");
  const secret = secretBytes(di, multikey);
  if (publicJwk.kty === 'OKP') {
    log.debug("Leaving privateKeyFor(). Ed25519.");
    return nodeCrypto.createPrivateKey({
      key: Buffer.concat([Buffer.from('302e020100300506032b657004220420',
                                      'hex'), secret.raw]),
      format: 'der', type: 'pkcs8' });
  }
  log.debug("Leaving privateKeyFor(). EC.");
  return nodeCrypto.createPrivateKey({ format: 'jwk', key: Object.assign(
    { d: secret.raw.toString('base64url') }, publicJwk) });
}

// Two JWKs with the same members, whatever order node exported them in.
function sameJwk(a, b) {
  log.debug("Entering sameJwk().");
  const sorted = function sorted(jwk) {
    log.debug("Entering sorted().");
    log.debug("Leaving sorted().");
    return JSON.stringify(Object.keys(jwk).sort().map(function (k) {
      return [k, jwk[k]];
    }));
  };
  log.debug("Leaving sameJwk().");
  return sorted(a) === sorted(b);
}

// The one check a refusal was about, and whether it alone decided it.
function failedChecks(result) {
  log.debug("Entering failedChecks().");
  log.debug("Leaving failedChecks().");
  return result.checks.filter(function (c) {
    return !c.ok;
  }).map(function (c) {
    return c.name;
  });
}

function signedWith(document, proofValue, suite, did) {
  log.debug("Entering signedWith().");
  const out = JSON.parse(JSON.stringify(document));
  out.proof = {
    type: 'DataIntegrityProof', cryptosuite: suite,
    created: '2023-02-24T23:36:38Z',
    verificationMethod: 'did:key:' + did + '#' + did,
    proofPurpose: 'assertionMethod',
    '@context': document['@context'],
    proofValue: proofValue
  };
  log.debug("Leaving signedWith().");
  return out;
}

async function holderKeys() {
  log.debug("Entering holderKeys().");
  const pqJose = require('../common/pq_jose');
  const out = [];
  ['P-256', 'P-384'].forEach(function (crv) {
    const pair = nodeCrypto.generateKeyPairSync('ec', {
      namedCurve: crv === 'P-256' ? 'prime256v1' : 'secp384r1' });
    out.push({ label: crv, privateKey: pair.privateKey,
               jwk: pair.publicKey.export({ format: 'jwk' }) });
  });
  const ed = nodeCrypto.generateKeyPairSync('ed25519');
  out.push({ label: 'Ed25519', privateKey: ed.privateKey,
             jwk: ed.publicKey.export({ format: 'jwk' }) });
  // ML-DSA through pq_jose, which is @noble/post-quantum and needs nothing
  // of the runtime's OpenSSL — so, unlike `crypto.mlDsaAvailable()`'s
  // certificate path, there is no runtime to skip for. Guarded anyway, so a
  // library that cannot load reports itself rather than taking the file.
  // SLH-DSA-SHA2-128s (slhdsa128-jcs-2024) since 2026-09-22 (#43).
  ['ML-DSA-44', 'SLH-DSA-SHA2-128s'].forEach(function (alg) {
    try {
      const pq = pqJose.generate(alg);
      const jwk = pqJose.akpPublicJwk(alg, pq.pub);
      delete jwk.use;
      out.push({ label: alg,
                 privateKey: Object.assign({ priv: Buffer.from(pq.priv)
                   .toString('base64url') }, jwk),
                 jwk: jwk });
    } catch (e) {
      log.debug("Caught in holderKeys(): " + ((e && e.message) || e));
      out.push({ label: alg, error: (e && e.message) || String(e) });
    }
  });
  log.debug("Leaving holderKeys().");
  return out;
}

function presentation(di, jwk) {
  log.debug("Entering presentation().");
  log.debug("Leaving presentation().");
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiablePresentation'],
    holder: di.didJwkOf(jwk),
    verifiableCredential: [{ id: 'urn:example:credential' }]
  };
}

async function run(t) {
  log.debug("Entering run().");
  const di = require('../oid4vc/vc_data_integrity');
  const suites = di.SUITES;

  // -------------------------------------------------------------------------
  t.log.info('=== A. JCS and the published vectors ===');
  t.equal(di.jcs(ALUMNI), ALUMNI_CANONICAL,
          'A1. JCS gives EdDSA B.3\'s canonical credential byte for byte');
  t.equal(di.jcs({ b: [1, 2.5, -0, 1e21, '\u00e9\u2028'],
                   a: { z: null, y: true } }),
          '{"a":{"y":true,"z":null},"b":[1,2.5,0,1e+21,"\u00e9\u2028"]}',
          'A2. JCS sorts members and serialises numbers as RFC 8785 says');
  let threw = false;
  try {
    di.jcs({ n: Infinity });
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    threw = true;
  }
  t.check(threw, 'A3. a value JSON cannot carry is an error, not omitted');

  const ed = di.resolveVerificationMethod('did:key:' + ED_PUBLIC + '#' +
                                          ED_PUBLIC);
  const edConfig = Object.assign({
    type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022',
    created: '2023-02-24T23:36:38Z',
    verificationMethod: 'did:key:' + ED_PUBLIC + '#' + ED_PUBLIC,
    proofPurpose: 'assertionMethod' }, { '@context': ALUMNI['@context'] });
  t.equal(di.hashData(suites['eddsa-jcs-2022'], ed.jwk, edConfig, ALUMNI)
            .toString('hex'), ED_HASH,
          'A4. eddsa-jcs-2022\'s combined hash is B.3\'s Example 36');
  const edSecret = secretBytes(di, ED_SECRET);
  t.equal(edSecret.prefix, '8026', 'A5. the Ed25519 secret is a 0x1300 ' +
          'Multikey');
  const edPrivate = privateKeyFor(di, ED_SECRET, ed.jwk);
  t.check(sameJwk(nodeCrypto.createPublicKey(edPrivate)
                    .export({ format: 'jwk' }), ed.jwk),
          'A6. the published Ed25519 secret derives the key its did:key ' +
          'resolves to');
  const edSigned = await di.signPresentation(ALUMNI, {
    privateKey: edPrivate, publicJwk: ed.jwk, cryptosuite: 'eddsa-jcs-2022',
    created: '2023-02-24T23:36:38Z', proofPurpose: 'assertionMethod',
    verificationMethod: 'did:key:' + ED_PUBLIC + '#' + ED_PUBLIC });
  t.equal(edSigned.proof.proofValue, ED_PROOF_VALUE,
          'A7. signing B.3\'s credential with B.3\'s key gives its ' +
          'proofValue exactly (Ed25519 is deterministic)');
  let r = await di.verifyProof(signedWith(ALUMNI, ED_PROOF_VALUE,
    'eddsa-jcs-2022', ED_PUBLIC), { expectedPurpose: 'assertionMethod',
    expectedChallenge: null, expectedDomain: null });
  t.check(r.ok, 'A8. B.3\'s signed credential verifies',
          JSON.stringify(failedChecks(r)));

  const p256 = di.resolveVerificationMethod('did:key:' + P256_PUBLIC);
  const p384 = di.resolveVerificationMethod('did:key:' + P384_PUBLIC);
  [[p256, P256_PUBLIC, P256_SECRET, P256_HASH, P256_PROOF_VALUE, '8626',
    'A.5, P-256'],
   [p384, P384_PUBLIC, P384_SECRET, P384_HASH, P384_PROOF_VALUE, '8726',
    'A.6, P-384']].forEach(function (row) {
    const key = row[0];
    t.equal(di.hashData(suites['ecdsa-jcs-2019'], key.jwk, Object.assign({
      type: 'DataIntegrityProof', cryptosuite: 'ecdsa-jcs-2019',
      created: '2023-02-24T23:36:38Z',
      verificationMethod: 'did:key:' + row[1] + '#' + row[1],
      proofPurpose: 'assertionMethod',
      '@context': ALUMNI['@context'] }), ALUMNI).toString('hex'), row[3],
      'A9. ecdsa-jcs-2019\'s combined hash is ' + row[6] + '\'s');
    t.equal(secretBytes(di, row[2]).prefix, row[5],
            'A10. the ' + row[6] + ' secret has its Multikey prefix');
    t.check(sameJwk(nodeCrypto.createPublicKey(
      privateKeyFor(di, row[2], key.jwk)).export({ format: 'jwk' }),
      key.jwk), 'A11. the ' + row[6] + ' secret derives the key its ' +
      'did:key resolves to');
  });
  for (const row of [[P256_PUBLIC, P256_PROOF_VALUE, 'P-256'],
                     [P384_PUBLIC, P384_PROOF_VALUE, 'P-384']]) {
    r = await di.verifyProof(signedWith(ALUMNI, row[1], 'ecdsa-jcs-2019',
      row[0]), { expectedPurpose: 'assertionMethod',
      expectedChallenge: null, expectedDomain: null });
    t.check(r.ok, 'A12. ecdsa-jcs-2019\'s published ' + row[2] +
            ' credential verifies', JSON.stringify(failedChecks(r)));
  }

  const ml = di.resolveVerificationMethod(
    MLDSA_SIGNED.proof.verificationMethod);
  t.equal(Buffer.from(ml.jwk.pub, 'base64url').toString('hex'),
          MLDSA_PUBLIC_HEX, 'A13. the ML-DSA-44 did:key resolves to the ' +
          'published public key');
  const mlConfig = Object.assign({}, MLDSA_SIGNED.proof,
    { '@context': MLDSA_SIGNED['@context'] });
  delete mlConfig.proofValue;
  const mlDocument = Object.assign({}, MLDSA_SIGNED);
  delete mlDocument.proof;
  t.equal(di.hashData(suites['mldsa44-jcs-2024'], ml.jwk, mlConfig,
                      mlDocument).toString('hex'), MLDSA_HASH,
          'A14. mldsa44-jcs-2024\'s combined hash is the draft\'s ' +
          'Example 20');
  r = await di.verifyProof(MLDSA_SIGNED, {
    expectedPurpose: 'assertionMethod', expectedChallenge: null,
    expectedDomain: null });
  t.check(r.ok, 'A15. the draft\'s signed mldsa44-jcs-2024 credential ' +
          'verifies (a proof with no @context of its own)',
          JSON.stringify(failedChecks(r)));

  // -------------------------------------------------------------------------
  t.log.info('=== B. round trips ===');
  const keys = await holderKeys();
  const expected = { expectedChallenge: 'n-0S6_WzA2Mj',
                     expectedDomain: 'origin:https://sts.example',
                     maxAgeS: 60 };
  let p256Vp = null;
  let p256Key = null;
  for (const key of keys) {
    if (key.error) {
      t.check(false, 'B0. an ' + key.label + ' holder key could be made',
              key.error);
      continue;
    }
    const vp = await di.signPresentation(presentation(di, key.jwk), {
      privateKey: key.privateKey, publicJwk: key.jwk,
      challenge: expected.expectedChallenge,
      domain: expected.expectedDomain });
    r = await di.verifyProof(vp, expected);
    t.check(r.ok && r.cryptosuite === di.cryptosuiteForJwk(key.jwk) &&
            r.controller === vp.holder,
            'B1. a presentation signed with ' + key.label + ' (' +
            r.cryptosuite + ') verifies, and its controller is the holder',
            JSON.stringify(failedChecks(r)));
    if (key.label === 'P-256') {
      p256Vp = vp;
      p256Key = key;
    }
  }
  t.equal(keys.filter(function (k) { return k.label === 'ML-DSA-44'; })
            .map(function (k) {
              return k.jwk ? di.cryptosuiteForJwk(k.jwk) : '';
            })[0], 'mldsa44-jcs-2024',
          'B2. an ML-DSA-44 holder key signs mldsa44-jcs-2024');
  t.equal(keys.filter(function (k) {
    return k.label === 'SLH-DSA-SHA2-128s';
  }).map(function (k) {
    return k.jwk ? di.cryptosuiteForJwk(k.jwk) : '';
  })[0], 'slhdsa128-jcs-2024',
          'B2. an SLH-DSA-SHA2-128s holder key signs slhdsa128-jcs-2024');
  keys.filter(function (k) {
    return k.label === 'SLH-DSA-SHA2-128s' && k.jwk;
  }).forEach(function (k) {
    const did = di.didKeyOf(k.jwk);
    t.check(/^did:key:u/.test(did) &&
            Buffer.from(did.slice('did:key:u'.length), 'base64url')
              .subarray(0, 2).toString('hex') === 'a024' &&
            JSON.stringify(di.resolveVerificationMethod(did).jwk) ===
              JSON.stringify(di.publicJwkOf(k.jwk)),
            'B3. an SLH-DSA-SHA2-128s did:key is base64url with the draft\'s ' +
            '0xa024 prefix, and resolves back to the key', did);
  });

  // -------------------------------------------------------------------------
  t.log.info('=== C. refusals ===');
  const copy = function copy(value) {
    log.debug("Entering copy().");
    log.debug("Leaving copy().");
    return JSON.parse(JSON.stringify(value));
  };
  const refusedBy = async function refusedBy(label, document, options,
                                             name) {
    log.debug("Entering refusedBy().");
    const result = await di.verifyProof(document, options);
    const failed = failedChecks(result);
    t.check(!result.ok && failed.indexOf(name) >= 0 &&
            failed.filter(function (n) {
              return n !== name && n !== 'Signature';
            }).length === 0, label, JSON.stringify(failed));
    log.debug("Leaving refusedBy().");
  };
  await refusedBy('C1. a wrong challenge is refused by Challenge', p256Vp,
    Object.assign({}, expected, { expectedChallenge: 'another-nonce' }),
    'Challenge');
  await refusedBy('C2. a wrong domain is refused by Domain', p256Vp,
    Object.assign({}, expected, { expectedDomain: 'x509_san_dns:rp' }),
    'Domain');
  await refusedBy('C3. a wrong purpose is refused by Proof purpose', p256Vp,
    Object.assign({}, expected, { expectedPurpose: 'assertionMethod' }),
    'Proof purpose');
  await refusedBy('C4. no expected challenge at all is refused, not ' +
    'skipped', p256Vp, { expectedDomain: expected.expectedDomain },
    'Challenge');
  let bad = copy(p256Vp);
  bad.verifiableCredential = [{ id: 'urn:example:another' }];
  await refusedBy('C5. a tampered document is refused by Signature', bad,
                  expected, 'Signature');
  bad = copy(p256Vp);
  bad.proof.created = new Date(Date.now() - 1000).toISOString();
  await refusedBy('C6. a tampered proof configuration (created) is ' +
                  'refused by Signature', bad, expected, 'Signature');
  const other = nodeCrypto.generateKeyPairSync('ec',
                                               { namedCurve: 'prime256v1' });
  const otherJwk = other.publicKey.export({ format: 'jwk' });
  bad = await di.signPresentation(presentation(di, p256Key.jwk), {
    privateKey: other.privateKey, publicJwk: otherJwk,
    challenge: expected.expectedChallenge, domain: expected.expectedDomain,
    verificationMethod: di.didJwkOf(p256Key.jwk) + '#0' });
  await refusedBy('C7. a proof by a key that is not the verification ' +
                  'method\'s is refused by Signature', bad, expected,
                  'Signature');
  bad = copy(p256Vp);
  bad.proof.cryptosuite = 'ecdsa-rdfc-2019';
  await refusedBy('C8. an unsupported cryptosuite is refused by ' +
                  'Cryptosuite', bad, expected, 'Cryptosuite');
  await refusedBy('C9. a cryptosuite the caller did not allow is refused',
    p256Vp, Object.assign({}, expected,
      { allowedCryptosuites: ['mldsa44-jcs-2024'] }), 'Cryptosuite');
  bad = copy(p256Vp);
  delete bad.proof.proofValue;
  await refusedBy('C10. a missing proofValue is refused by Proof value',
                  bad, expected, 'Proof value');
  bad = copy(p256Vp);
  bad.proof.proofValue = 'u' + di.base58Decode(
    p256Vp.proof.proofValue.slice(1)).toString('base64url');
  await refusedBy('C11. a proofValue that is not base58-btc ("z") is ' +
                  'refused by Proof value', bad, expected, 'Proof value');
  const stale = await di.signPresentation(presentation(di, p256Key.jwk), {
    privateKey: p256Key.privateKey, publicJwk: p256Key.jwk,
    challenge: expected.expectedChallenge, domain: expected.expectedDomain,
    created: new Date(Date.now() - 3600 * 1000).toISOString() });
  await refusedBy('C12. a proof older than maxAgeS is refused by Created',
                  stale, expected, 'Created');
  const future = await di.signPresentation(presentation(di, p256Key.jwk), {
    privateKey: p256Key.privateKey, publicJwk: p256Key.jwk,
    challenge: expected.expectedChallenge, domain: expected.expectedDomain,
    created: new Date(Date.now() + 3600 * 1000).toISOString() });
  await refusedBy('C13. a proof made in the future is refused by Created',
                  future, expected, 'Created');
  const expired = await di.signPresentation(presentation(di, p256Key.jwk), {
    privateKey: p256Key.privateKey, publicJwk: p256Key.jwk,
    challenge: expected.expectedChallenge, domain: expected.expectedDomain,
    expires: new Date(Date.now() - 3600 * 1000).toISOString() });
  await refusedBy('C14. a proof whose expires has passed is refused by ' +
                  'Expires', expired, expected, 'Expires');
  const strangerVp = presentation(di, otherJwk);
  bad = await di.signPresentation(strangerVp, {
    privateKey: p256Key.privateKey, publicJwk: p256Key.jwk,
    challenge: expected.expectedChallenge, domain: expected.expectedDomain });
  await refusedBy('C15. a holder the proving key does not belong to is ' +
                  'refused by Holder', bad, expected, 'Holder');
  bad = copy(p256Vp);
  bad.proof.previousProof = 'urn:uuid:earlier';
  await refusedBy('C16. a proof chain is refused by Proof', bad, expected,
                  'Proof');
  bad = copy(p256Vp);
  bad.proof.verificationMethod = 'https://holder.example/keys/1';
  await refusedBy('C17. a verification method that would have to be ' +
                  'fetched is refused', bad, expected,
                  'Verification method');
  bad = copy(p256Vp);
  bad.proof.verificationMethod = di.didJwkOf(p256Key.jwk) + '#1';
  await refusedBy('C18. a did:jwk fragment other than #0 is refused', bad,
                  expected, 'Verification method');
  const edKey = keys.filter(function (k) {
    return k.label === 'Ed25519';
  })[0];
  bad = copy(p256Vp);
  bad.proof.cryptosuite = 'eddsa-jcs-2022';
  await refusedBy('C19. a P-256 method under eddsa-jcs-2022 is refused by ' +
                  'Verification method', bad, expected,
                  'Verification method');
  t.check(!!edKey, 'C20. an Ed25519 key was among the round trips');

  // What is accepted that a stricter reading might refuse.
  const domains = await di.signPresentation(presentation(di, p256Key.jwk), {
    privateKey: p256Key.privateKey, publicJwk: p256Key.jwk,
    challenge: expected.expectedChallenge,
    domain: ['https://elsewhere.example', expected.expectedDomain] });
  r = await di.verifyProof(domains, expected);
  t.check(r.ok, 'C21. a domain set containing the expected value is ' +
          'accepted', JSON.stringify(failedChecks(r)));
  const stranger = await di.signPresentation(presentation(di, p256Key.jwk), {
    privateKey: p256Key.privateKey, publicJwk: p256Key.jwk,
    challenge: 'for-another-request', domain: expected.expectedDomain });
  const set = copy(p256Vp);
  set.proof = [stranger.proof, p256Vp.proof];
  r = await di.verifyProof(set, expected);
  t.check(r.ok, 'C22. a proof set is verified by the member made for this ' +
          'request', JSON.stringify(failedChecks(r)));
  set.proof = [stranger.proof];
  await refusedBy('C23. a proof set with no member for this request is ' +
                  'refused by Challenge', set, expected, 'Challenge');
  r = await di.verifyProof({ proof: 5 }, expected);
  t.check(!r.ok, 'C24. a document with no usable proof is refused, not ' +
          'thrown');
  r = await di.verifyProof('not a document', expected);
  t.check(!r.ok, 'C25. something that is not a document is refused, not ' +
          'thrown');

  // -------------------------------------------------------------------------
  t.log.info('=== D. identifiers ===');
  const jwk = keys[0].jwk;
  const did = di.didJwkOf(jwk);
  t.check(/^did:jwk:[A-Za-z0-9_-]+$/.test(did) &&
          sameJwk(di.jwkOfDidJwk(did), { kty: 'EC', crv: jwk.crv, x: jwk.x,
                                         y: jwk.y }) &&
          sameJwk(di.jwkOfDidJwk(did + '#0'), di.jwkOfDidJwk(did)),
          'D1. did:jwk both ways, with and without its #0');
  threw = false;
  try {
    di.jwkOfDidJwk('did:jwk:' + Buffer.from(JSON.stringify(
      Object.assign({ d: 'secret' }, jwk))).toString('base64url'));
  } catch (e) {
    log.debug("Caught in run(): " + ((e && e.message) || e));
    threw = true;
  }
  t.check(threw, 'D2. a did:jwk carrying a private member is refused');
  t.equal(di.didKeyOf(ed.jwk), 'did:key:' + ED_PUBLIC,
          'D3. the published Ed25519 key\'s did:key comes back out');
  t.equal(di.didKeyOf(p256.jwk), 'did:key:' + P256_PUBLIC,
          'D4. the published P-256 key\'s did:key comes back out');
  t.equal(di.didKeyOf(p384.jwk), 'did:key:' + P384_PUBLIC,
          'D5. the published P-384 key\'s did:key comes back out');
  t.equal(di.didKeyOf(ml.jwk), MLDSA_SIGNED.proof.verificationMethod,
          'D6. the published ML-DSA-44 key\'s did:key comes back out');
  const rsa = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    .publicKey.export({ format: 'jwk' });
  const k1 = nodeCrypto.generateKeyPairSync('ec',
    { namedCurve: 'secp256k1' }).publicKey.export({ format: 'jwk' });
  const unsupported = [
    [rsa, 'RSA'], [k1, 'secp256k1'],
    [{ kty: 'AKP', alg: 'ML-DSA-65', pub: 'AA' }, 'ML-DSA-65'],
    [{ kty: 'AKP', alg: 'ML-DSA-44-ES256', pub: 'AA' }, 'composite']
  ];
  unsupported.forEach(function (row) {
    t.check(di.cryptosuiteForJwk(row[0]) === '' &&
            di.unsupportedReason(row[0]).length > 20,
            'D7. a ' + row[1] + ' key has no cryptosuite, and a reason',
            di.unsupportedReason(row[0]));
  });
  t.check(di.SUPPORTED_CRYPTOSUITES.join(',') ===
          'ecdsa-jcs-2019,eddsa-jcs-2022,mldsa44-jcs-2024,slhdsa128-jcs-2024',
          'D8. exactly the four JCS suites are supported',
          di.SUPPORTED_CRYPTOSUITES.join(','));
  log.debug("Leaving run().");
}

module.exports = {
  name: 'vc_data_integrity',
  describe: 'a holder\'s Data Integrity proof on a presentation — ' +
            'ecdsa-jcs-2019, eddsa-jcs-2022 and mldsa44-jcs-2024 over JCS, ' +
            'held to the published vectors, with challenge, domain, ' +
            'purpose, created and the verification method each refused by ' +
            'name',
  run: run
};

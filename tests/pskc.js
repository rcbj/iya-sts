// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';
//
// File: tests/pskc.js
//
// ===========================================================================
// RFC 6030 PSKC SEED FILES, READ (#1955 P4): `common/pskc.ts` and the three
// primitives under it in `common/crypto.js`.
//
//   1. RFC 6030's OWN EXAMPLES, with their published key and password:
//      Figure 2 (plaintext, no DeviceInfo — skipped, no serial), Figure 3
//      (plaintext HOTP with a serial), Figure 4 (a key by reference, no
//      secret — skipped), Figure 5 (an HOTP key and a PIN key — the PIN
//      skipped), Figure 6 (AES-128-CBC under the pre-shared key
//      12345678901234567890123456789012, HMAC-SHA1) and Figure 7 (PBKDF2 of
//      the password "qwerty"). Each opened secret is RFC 4226's test key,
//      and its first code is RFC 4226 Appendix D's.
//   2. The refusals: a wrong pre-shared key, a wrong password, no key, an
//      altered ValueMAC and an altered ciphertext (all the MAC's, before any
//      padding is read), a document type declaration, a document that is not
//      a KeyContainer, a certificate-encrypted file, and PLAINTEXT IN
//      PRODUCT MODE unless the setting allows it.
//   3. A container generated in the run: a TOTP key with a Suite and a time
//      step, AES-256-CBC, HMAC-SHA256 — and a CBC value without a ValueMAC
//      refused.
//
// The figures are the RFC's published test vectors and carry no secret of
// anybody's; the generated container's keys are drawn in the run.
// ===========================================================================

delete process.env.CONFIG_FILE;

const nodeCrypto = require('crypto');
const crypto = require('../common/crypto');
const pskcLib = require('../common/pskc');
const hotp = require('../common/hotp');
const totp = require('../common/totp');
const errorCodes = require('../common/error_codes');

const log = require('bunyan').createLogger({
  name: 'pskc', level: process.env.LOG_LEVEL || 'info' });

// RFC 6030's figures, as printed (indentation dedented, page breaks gone).
const FIGURES = {
  fig2: [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<KeyContainer Version="1.0"',
    '    Id="exampleID1"',
    '    xmlns="urn:ietf:params:xml:ns:keyprov:pskc">',
    '    <KeyPackage>',
    '        <Key Id="12345678"',
    '            Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">',
    '            <Issuer>Issuer-A</Issuer>',
    '            <Data>',
    '                <Secret>',
    '                    <PlainValue>MTIzNA==',
    '                    </PlainValue>',
    '                </Secret>',
    '            </Data>',
    '        </Key>',
    '    </KeyPackage>',
    '</KeyContainer>'
  ].join('\n'),
  fig3: [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<KeyContainer Version="1.0"',
    '    Id="exampleID1"',
    '    xmlns="urn:ietf:params:xml:ns:keyprov:pskc">',
    '    <KeyPackage>',
    '        <DeviceInfo>',
    '            <Manufacturer>Manufacturer</Manufacturer>',
    '            <SerialNo>987654321</SerialNo>',
    '            <UserId>DC=example-bank,DC=net</UserId>',
    '        </DeviceInfo>',
    '        <CryptoModuleInfo>',
    '            <Id>CM_ID_001</Id>',
    '        </CryptoModuleInfo>',
    '        <Key Id="12345678"',
    '            Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">',
    '            <Issuer>Issuer</Issuer>',
    '            <AlgorithmParameters>',
    '                <ResponseFormat Length="8" Encoding="DECIMAL"/>',
    '            </AlgorithmParameters>',
    '            <Data>',
    '                <Secret>',
    '                    <PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=',
    '                    </PlainValue>',
    '                </Secret>',
    '                <Counter>',
    '                    <PlainValue>0</PlainValue>',
    '                </Counter>',
    '            </Data>',
    '            <UserId>UID=jsmith,DC=example-bank,DC=net</UserId>',
    '        </Key>',
    '    </KeyPackage>',
    '</KeyContainer>'
  ].join('\n'),
  fig4: [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<KeyContainer Version="1.0" Id="exampleID1"',
    '     xmlns="urn:ietf:params:xml:ns:keyprov:pskc">',
    '    <KeyPackage>',
    '        <DeviceInfo>',
    '            <Manufacturer>Manufacturer</Manufacturer>',
    '            <SerialNo>987654321</SerialNo>',
    '        </DeviceInfo>',
    '        <CryptoModuleInfo>',
    '            <Id>CM_ID_001</Id>',
    '        </CryptoModuleInfo>',
    '        <Key Id="12345678"',
    '         Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">',
    '            <Issuer>Issuer</Issuer>',
    '            <AlgorithmParameters>',
    '                <ResponseFormat Length="8" Encoding="DECIMAL"/>',
    '            </AlgorithmParameters>',
    '            <KeyProfileId>keyProfile1</KeyProfileId>',
    '            <KeyReference>MasterKeyLabel',
    '            </KeyReference>',
    '            <Data>',
    '                <Counter>',
    '                    <PlainValue>0</PlainValue>',
    '                </Counter>',
    '            </Data>',
    '            <Policy>',
    '                <KeyUsage>OTP</KeyUsage>',
    '            </Policy>',
    '        </Key>',
    '    </KeyPackage>',
    '</KeyContainer>'
  ].join('\n'),
  fig5: [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<KeyContainer',
    '    Version="1.0" Id="exampleID1"',
    '    xmlns="urn:ietf:params:xml:ns:keyprov:pskc">',
    '    <KeyPackage>',
    '        <DeviceInfo>',
    '            <Manufacturer>Manufacturer</Manufacturer>',
    '            <SerialNo>987654321</SerialNo>',
    '        </DeviceInfo>',
    '        <CryptoModuleInfo>',
    '            <Id>CM_ID_001</Id>',
    '        </CryptoModuleInfo>',
    '        <Key Id="12345678"',
    '            Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">',
    '            <Issuer>Issuer</Issuer>',
    '            <AlgorithmParameters>',
    '                <ResponseFormat Length="8" Encoding="DECIMAL"/>',
    '            </AlgorithmParameters>',
    '            <Data>',
    '                <Secret>',
    '                    <PlainValue>MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=',
    '                    </PlainValue>',
    '                </Secret>',
    '                <Counter>',
    '                    <PlainValue>0</PlainValue>',
    '                </Counter>',
    '            </Data>',
    '            <Policy>',
    '                <PINPolicy MinLength="4" MaxLength="4"',
    '                    PINKeyId="123456781" PINEncoding="DECIMAL"',
    '                    PINUsageMode="Local"/>',
    '                <KeyUsage>OTP</KeyUsage>',
    '            </Policy>',
    '        </Key>',
    '    </KeyPackage>',
    '    <KeyPackage>',
    '        <DeviceInfo>',
    '            <Manufacturer>Manufacturer</Manufacturer>',
    '            <SerialNo>987654321</SerialNo>',
    '        </DeviceInfo>',
    '        <CryptoModuleInfo>',
    '            <Id>CM_ID_001</Id>',
    '        </CryptoModuleInfo>',
    '        <Key Id="123456781"',
    '            Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:pin">',
    '            <Issuer>Issuer</Issuer>',
    '            <AlgorithmParameters>',
    '                <ResponseFormat Length="4" Encoding="DECIMAL"/>',
    '            </AlgorithmParameters>',
    '            <Data>',
    '                <Secret>',
    '                    <PlainValue>MTIzNA==</PlainValue>',
    '                </Secret>',
    '            </Data>',
    '        </Key>',
    '    </KeyPackage>',
    '</KeyContainer>'
  ].join('\n'),
  fig6: [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<KeyContainer Version="1.0"',
    '    xmlns="urn:ietf:params:xml:ns:keyprov:pskc"',
    '    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"',
    '    xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">',
    '    <EncryptionKey>',
    '        <ds:KeyName>Pre-shared-key</ds:KeyName>',
    '    </EncryptionKey>',
    '    <MACMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">',
    '        <MACKey>',
    '            <xenc:EncryptionMethod',
    '            Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>',
    '            <xenc:CipherData>',
    '                <xenc:CipherValue>',
    '    ESIzRFVmd4iZABEiM0RVZgKn6WjLaTC1sbeBMSvIhRejN9vJa2BOlSaMrR7I5wSX',
    '                </xenc:CipherValue>',
    '            </xenc:CipherData>',
    '        </MACKey>',
    '    </MACMethod>',
    '    <KeyPackage>',
    '        <DeviceInfo>',
    '            <Manufacturer>Manufacturer</Manufacturer>',
    '            <SerialNo>987654321</SerialNo>',
    '        </DeviceInfo>',
    '        <CryptoModuleInfo>',
    '            <Id>CM_ID_001</Id>',
    '        </CryptoModuleInfo>',
    '        <Key Id="12345678"',
    '            Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:hotp">',
    '            <Issuer>Issuer</Issuer>',
    '            <AlgorithmParameters>',
    '                <ResponseFormat Length="8" Encoding="DECIMAL"/>',
    '            </AlgorithmParameters>',
    '            <Data>',
    '                <Secret>',
    '                    <EncryptedValue>',
    '                        <xenc:EncryptionMethod',
    '            Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>',
    '                        <xenc:CipherData>',
    '                            <xenc:CipherValue>',
    '    AAECAwQFBgcICQoLDA0OD+cIHItlB3Wra1DUpxVvOx2lef1VmNPCMl8jwZqIUqGv',
    '                            </xenc:CipherValue>',
    '                        </xenc:CipherData>',
    '                    </EncryptedValue>',
    '                    <ValueMAC>Su+NvtQfmvfJzF6bmQiJqoLRExc=',
    '                    </ValueMAC>',
    '                </Secret>',
    '                <Counter>',
    '                    <PlainValue>0</PlainValue>',
    '                </Counter>',
    '            </Data>',
    '        </Key>',
    '    </KeyPackage>',
    '</KeyContainer>'
  ].join('\n'),
  fig7: [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<pskc:KeyContainer',
    '  xmlns:pskc="urn:ietf:params:xml:ns:keyprov:pskc"',
    '  xmlns:xenc11="http://www.w3.org/2009/xmlenc11#"',
    '  xmlns:pkcs5=',
    '  "http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#"',
    '  xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Version="1.0">',
    '    <pskc:EncryptionKey>',
    '        <xenc11:DerivedKey>',
    '            <xenc11:KeyDerivationMethod',
    '              Algorithm=',
    ' "http://www.rsasecurity.com/rsalabs/pkcs/schemas/pkcs-5v2-0#pbkdf2">',
    '                <pkcs5:PBKDF2-params>',
    '                    <Salt>',
    '                        <Specified>Ej7/PEpyEpw=</Specified>',
    '                    </Salt>',
    '                    <IterationCount>1000</IterationCount>',
    '                    <KeyLength>16</KeyLength>',
    '                    <PRF/>',
    '                </pkcs5:PBKDF2-params>',
    '            </xenc11:KeyDerivationMethod>',
    '            <xenc:ReferenceList>',
    '                <xenc:DataReference URI="#ED"/>',
    '            </xenc:ReferenceList>',
    '            <xenc11:MasterKeyName>My Password 1</xenc11:MasterKeyName>',
    '        </xenc11:DerivedKey>',
    '    </pskc:EncryptionKey>',
    '    <pskc:MACMethod',
    '        Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">',
    '        <pskc:MACKey>',
    '            <xenc:EncryptionMethod',
    '            Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>',
    '            <xenc:CipherData>',
    '                <xenc:CipherValue>',
    '2GTTnLwM3I4e5IO5FkufoOEiOhNj91fhKRQBtBJYluUDsPOLTfUvoU2dStyOwYZx',
    '                </xenc:CipherValue>',
    '            </xenc:CipherData>',
    '        </pskc:MACKey>',
    '    </pskc:MACMethod>',
    '    <pskc:KeyPackage>',
    '        <pskc:DeviceInfo>',
    '            <pskc:Manufacturer>TokenVendorAcme</pskc:Manufacturer>',
    '            <pskc:SerialNo>987654321</pskc:SerialNo>',
    '        </pskc:DeviceInfo>',
    '        <pskc:CryptoModuleInfo>',
    '            <pskc:Id>CM_ID_001</pskc:Id>',
    '        </pskc:CryptoModuleInfo>',
    '        <pskc:Key Algorithm=',
    '        "urn:ietf:params:xml:ns:keyprov:pskc:hotp" Id="123456">',
    '            <pskc:Issuer>Example-Issuer</pskc:Issuer>',
    '            <pskc:AlgorithmParameters>',
    '                <pskc:ResponseFormat Length="8" Encoding="DECIMAL"/>',
    '            </pskc:AlgorithmParameters>',
    '            <pskc:Data>',
    '                <pskc:Secret>',
    '                <pskc:EncryptedValue Id="ED">',
    '                    <xenc:EncryptionMethod',
    '                        Algorithm=',
    '"http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>',
    '                        <xenc:CipherData>',
    '                            <xenc:CipherValue>',
    '      oTvo+S22nsmS2Z/RtcoF8Hfh+jzMe0RkiafpoDpnoZTjPYZu6V+A4aEn032yCr4f',
    '                        </xenc:CipherValue>',
    '                    </xenc:CipherData>',
    '                    </pskc:EncryptedValue>',
    '                    <pskc:ValueMAC>LP6xMvjtypbfT9PdkJhBZ+D6O4w=',
    '                    </pskc:ValueMAC>',
    '                </pskc:Secret>',
    '            </pskc:Data>',
    '        </pskc:Key>',
    '    </pskc:KeyPackage>',
    '</pskc:KeyContainer>'
  ].join('\n')
};

// RFC 6030 section 6.1's pre-shared key and section 6.2's password.
const FIGURE6_KEY = '12345678901234567890123456789012';
const FIGURE7_PASSWORD = 'qwerty';
// RFC 4226's test key, which every figure's secret is, and its first two
// eight-digit values (Appendix D's truncated values modulo 10^8).
const RFC4226_KEY = Buffer.from('12345678901234567890', 'ascii');
const EIGHT_DIGIT = ['84755224', '94287082'];

function codeOf(result) {
  log.debug("Entering codeOf().");
  log.debug("Leaving codeOf().");
  return errorCodes.codeOf(result) || '';
}

// A reader whose mode says product: `refusesPlaintextSeedFiles()` true.
function productReader(refuses) {
  log.debug("Entering productReader().");
  const deps = Object.assign(pskcLib.Pskc.defaultDeps(), {
    mode: { refusesPlaintextSeedFiles: function () {
      return refuses;
    } } });
  log.debug("Leaving productReader().");
  return new pskcLib.Pskc(deps);
}

// XML Encryption's CBC, IV first, and padding whose last octet counts it.
function cbc(bits, key, plain) {
  log.debug("Entering cbc().");
  const iv = nodeCrypto.randomBytes(16);
  const c = nodeCrypto.createCipheriv('aes-' + bits + '-cbc', key, iv);
  const out = Buffer.concat([iv, c.update(plain), c.final()]);
  log.debug("Leaving cbc().");
  return out;
}

// A container made in the run: one TOTP key, AES-256-CBC, HMAC-SHA256.
function generatedContainer(opts) {
  log.debug("Entering generatedContainer().");
  const o = opts || {};
  const key = o.key || nodeCrypto.randomBytes(32);
  const macKey = nodeCrypto.randomBytes(32);
  const secret = o.secret || nodeCrypto.randomBytes(20);
  const enc = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
  const macAlg = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256';
  const sealedMac = cbc(256, key, macKey);
  const sealedSecret = cbc(256, key, secret);
  const valueMac = nodeCrypto.createHmac('sha256', macKey)
    .update(sealedSecret).digest('base64');
  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<KeyContainer Version="1.0" xmlns="urn:ietf:params:xml:ns:keyprov:pskc"',
    '    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"',
    '    xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">',
    '  <EncryptionKey><ds:KeyName>run-key</ds:KeyName></EncryptionKey>',
    '  <MACMethod Algorithm="' + macAlg + '"><MACKey>',
    '    <xenc:EncryptionMethod Algorithm="' + enc + '"/>',
    '    <xenc:CipherData><xenc:CipherValue>' + sealedMac.toString('base64') +
      '</xenc:CipherValue></xenc:CipherData>',
    '  </MACKey></MACMethod>',
    '  <KeyPackage>',
    '    <DeviceInfo><Manufacturer>' + (o.vendor || 'Run Vendor') +
      '</Manufacturer><SerialNo>' + (o.serial || 'RUN-1') +
      '</SerialNo><Model>Display token</Model></DeviceInfo>',
    '    <Key Id="' + (o.keyId || 'k1') +
      '" Algorithm="urn:ietf:params:xml:ns:keyprov:pskc:totp">',
    '      <AlgorithmParameters><Suite>HMAC-SHA256</Suite>',
    '        <ResponseFormat Length="6" Encoding="DECIMAL"/>',
    '      </AlgorithmParameters>',
    '      <Data><Secret><EncryptedValue>',
    '        <xenc:EncryptionMethod Algorithm="' + enc + '"/>',
    '        <xenc:CipherData><xenc:CipherValue>' +
      sealedSecret.toString('base64') +
      '</xenc:CipherValue></xenc:CipherData>',
    '      </EncryptedValue>' + (o.noMac ? '' : '<ValueMAC>' + valueMac +
      '</ValueMAC>') + '</Secret>',
    '      <TimeInterval><PlainValue>' + (o.period || 60) +
      '</PlainValue></TimeInterval></Data>',
    '    </Key>',
    '  </KeyPackage>',
    '</KeyContainer>'
  ].join('\n');
  log.debug("Leaving generatedContainer().");
  return { xml: xml, key: key, secret: secret };
}

async function checkFigures(t) {
  log.debug("Entering checkFigures().");
  t.log.info('=== 1. RFC 6030\'s own examples ===');
  const two = pskcLib.parse(FIGURES.fig2);
  t.check(two.ok && two.keys.length === 0 && two.skipped.length === 1 &&
          two.skipped[0].errorCode === 'STS-OATH-0028',
          'Figure 2 parses, and its one key is skipped: it names no device ' +
          'serial to keep it by', JSON.stringify(two.skipped));
  const three = pskcLib.parse(FIGURES.fig3);
  t.check(three.ok && three.protection === 'none' && three.keys.length === 1,
          'Figure 3 parses: one plaintext key');
  const k3 = three.keys[0];
  t.check(k3.kind === 'hotp' && k3.serial === '987654321' &&
          k3.vendor === 'Manufacturer' && k3.keyId === '12345678' &&
          k3.digits === 8 && k3.counter === 0 && k3.issuer === 'Issuer',
          'its device, key id, issuer, eight digits and counter are read',
          JSON.stringify({ kind: k3.kind, serial: k3.serial,
                           digits: k3.digits }));
  const opened3 = await pskcLib.open(three, {});
  t.check(opened3.ok && opened3.keys[0].secret.equals(RFC4226_KEY),
          'opened in development mode, its secret is RFC 4226\'s test key');
  t.equal(crypto.hotpCode(opened3.keys[0].secret, 0, { digits: 8 }),
          EIGHT_DIGIT[0], 'and its first code is RFC 4226 Appendix D\'s');
  const four = pskcLib.parse(FIGURES.fig4);
  t.check(four.ok && four.keys.length === 0 &&
          four.skipped[0].errorCode === 'STS-OATH-0022',
          'Figure 4 (a key by reference) is skipped: it carries no secret');
  const five = pskcLib.parse(FIGURES.fig5);
  t.check(five.ok && five.keys.length === 1 && five.skipped.length === 1 &&
          /pin/.test(five.skipped[0].why),
          'Figure 5: the HOTP key is read and THE PIN KEY IS SKIPPED, never ' +
          'imported as a second factor', JSON.stringify(five.skipped));
  const six = pskcLib.parse(FIGURES.fig6);
  t.check(six.ok && six.protection === 'pre-shared' &&
          six.keyName === 'Pre-shared-key' && !!six.mac,
          'Figure 6: a pre-shared key named "Pre-shared-key", with a MAC');
  const opened6 = await pskcLib.open(six, { preSharedKey: FIGURE6_KEY });
  t.check(opened6.ok && opened6.keys[0].secret.equals(RFC4226_KEY) &&
          opened6.keys[0].digits === 8,
          'opened with RFC 6030 section 6.1\'s key, its MAC verified, its ' +
          'secret is RFC 4226\'s test key', codeOf(opened6));
  const sixB64 = await pskcLib.open(six, {
    preSharedKey: Buffer.from(FIGURE6_KEY, 'hex').toString('base64') });
  t.check(sixB64.ok, 'the same key given in base64 opens it too');
  const seven = pskcLib.parse(FIGURES.fig7);
  t.check(seven.ok && seven.protection === 'pbe' &&
          seven.pbkdf2.iterations === 1000 && seven.pbkdf2.keyLength === 16,
          'Figure 7: PBKDF2, a thousand iterations, a 16-octet key',
          JSON.stringify(seven.pbkdf2 && { i: seven.pbkdf2.iterations }));
  const opened7 = await pskcLib.open(seven, { password: FIGURE7_PASSWORD });
  t.check(opened7.ok && opened7.keys[0].secret.equals(RFC4226_KEY) &&
          opened7.keys[0].vendor === 'TokenVendorAcme',
          'opened with RFC 6030 section 6.2\'s password "qwerty"',
          codeOf(opened7));
  log.debug("Leaving checkFigures().");
}

async function checkRefusals(t) {
  log.debug("Entering checkRefusals().");
  t.log.info('=== 2. the refusals ===');
  const six = pskcLib.parse(FIGURES.fig6);
  const wrongKey = await pskcLib.open(six, {
    preSharedKey: '00112233445566778899aabbccddeeff' });
  t.check(!wrongKey.ok && codeOf(wrongKey) === 'STS-OATH-0026',
          'A WRONG PRE-SHARED KEY is refused as the MAC\'s failure',
          codeOf(wrongKey));
  const noKey = await pskcLib.open(six, {});
  t.check(!noKey.ok && codeOf(noKey) === 'STS-OATH-0025' &&
          /Pre-shared-key/.test(noKey.error),
          'no key at all is asked for by the file\'s own key name');
  const shortKey = await pskcLib.open(six, { preSharedKey: 'abcd' });
  t.equal(codeOf(shortKey), 'STS-OATH-0025', 'a key of the wrong length too');
  const tampered = pskcLib.parse(FIGURES.fig6.replace(
    'Su+NvtQfmvfJzF6bmQiJqoLRExc=', 'Tu+NvtQfmvfJzF6bmQiJqoLRExc='));
  const altered = await pskcLib.open(tampered, { preSharedKey: FIGURE6_KEY });
  t.check(!altered.ok && codeOf(altered) === 'STS-OATH-0026',
          'AN ALTERED ValueMAC is refused');
  const flipped = pskcLib.parse(FIGURES.fig6.replace(
    'AAECAwQFBgcICQoLDA0OD+cIHItlB3Wra1DUpxVvOx2lef1VmNPCMl8jwZqIUqGv',
    'AAECAwQFBgcICQoLDA0OD+cIHItlB3Wra1DUpxVvOx2lef1VmNPCMl8jwZqIUqGw'));
  const flippedOut = await pskcLib.open(flipped,
                                        { preSharedKey: FIGURE6_KEY });
  t.check(!flippedOut.ok && codeOf(flippedOut) === 'STS-OATH-0026',
          'AN ALTERED CIPHERTEXT fails the MAC before its padding is read');
  const seven = pskcLib.parse(FIGURES.fig7);
  const wrongPassword = await pskcLib.open(seven, { password: 'QWERTY' });
  t.check(!wrongPassword.ok && codeOf(wrongPassword) === 'STS-OATH-0026',
          'A WRONG PASSWORD is refused as the MAC\'s failure');
  t.equal(codeOf(await pskcLib.open(seven, {})), 'STS-OATH-0025',
          'no password is asked for');
  const dtd = pskcLib.parse('<?xml version="1.0"?>\n<!DOCTYPE KeyContainer ' +
    '[<!ENTITY x "y">]>\n' + FIGURES.fig3.replace(/^<\?xml[^>]*>\n/, ''));
  t.check(!dtd.ok && codeOf(dtd) === 'STS-OATH-0020',
          'A DOCUMENT TYPE DECLARATION is refused before the parser reads ' +
          'it (common/xml_parser.js)');
  const foreign = pskcLib.parse('<KeyContainer Version="1.0" ' +
    'xmlns="urn:example"><KeyPackage/></KeyContainer>');
  t.equal(codeOf(foreign), 'STS-OATH-0021', 'a KeyContainer in another ' +
          'namespace is not RFC 6030\'s');
  t.equal(codeOf(pskcLib.parse('not xml at all <')), 'STS-OATH-0020',
          'text that is not XML is refused');
  const certificate = pskcLib.parse(FIGURES.fig3.replace('<KeyPackage>',
    '<EncryptionKey><ds:X509Data xmlns:ds="http://www.w3.org/2000/09/' +
    'xmldsig#"/></EncryptionKey><KeyPackage>'));
  t.equal(codeOf(certificate), 'STS-OATH-0023', 'a file encrypted to a ' +
          'certificate (section 6.3) is refused');
  const three = pskcLib.parse(FIGURES.fig3);
  const inProduct = await productReader(true).open(three, {});
  t.check(!inProduct.ok && codeOf(inProduct) === 'STS-OATH-0024',
          'PLAINTEXT IS REFUSED IN PRODUCT MODE', codeOf(inProduct));
  t.check((await productReader(false).open(three, {})).ok,
          'unless pskc.allowPlaintextImport lets it in');
  t.check((await productReader(true).open(pskcLib.parse(FIGURES.fig6),
          { preSharedKey: FIGURE6_KEY })).ok,
          'and an encrypted file opens in product mode');
  log.debug("Leaving checkRefusals().");
}

async function checkGenerated(t) {
  log.debug("Entering checkGenerated().");
  t.log.info('=== 3. a container made in the run ===');
  const made = generatedContainer({});
  const parsed = pskcLib.parse(made.xml);
  t.check(parsed.ok && parsed.keys.length === 1 &&
          parsed.keys[0].kind === 'totp' && parsed.keys[0].period === 60 &&
          parsed.keys[0].algorithm === 'SHA256',
          'a TOTP key with a 60-second step under HMAC-SHA256',
          JSON.stringify(parsed.keys && parsed.keys[0] &&
                         { kind: parsed.keys[0].kind }));
  const opened = await pskcLib.open(parsed, {
    preSharedKey: made.key.toString('hex') });
  t.check(opened.ok && opened.keys[0].secret.equals(made.secret),
          'AES-256-CBC with an HMAC-SHA256 MAC opens to the secret');
  const record = { secret: totp.base32Encode(made.secret), digits: 6,
                   period: 60, algorithm: 'SHA256' };
  t.check(totp.verify(record, totp.codeAt(record.secret, Date.now(),
          record)).ok, 'and the secret verifies as the TOTP it says it is');
  const bare = generatedContainer({ noMac: true });
  const noMac = await pskcLib.open(pskcLib.parse(bare.xml), {
    preSharedKey: bare.key.toString('hex') });
  t.check(!noMac.ok && codeOf(noMac) === 'STS-OATH-0027',
          'A CBC VALUE WITHOUT A ValueMAC IS REFUSED (section 6.1.1)');
  t.equal(hotp.codeAt(totp.base32Encode(RFC4226_KEY), 1, { digits: 8 }),
          EIGHT_DIGIT[1], 'the eight-digit vector the import tests use');
  log.debug("Leaving checkGenerated().");
}

async function run(t) {
  log.debug("Entering run().");
  await checkFigures(t);
  await checkRefusals(t);
  await checkGenerated(t);
  log.debug("Leaving run().");
}

module.exports = {
  name: 'pskc',
  describe: 'issue #1955 P4: RFC 6030 PSKC seed files — the RFC\'s own ' +
            'Figures 2 to 7 with their published key and password, the MAC ' +
            'checked first, the refusals, plaintext refused in product mode',
  run: run,
  // For tests/oath_tokens.js, which imports the same files.
  FIGURES: FIGURES,
  FIGURE6_KEY: FIGURE6_KEY,
  FIGURE7_PASSWORD: FIGURE7_PASSWORD,
  EIGHT_DIGIT: EIGHT_DIGIT,
  generatedContainer: generatedContainer
};

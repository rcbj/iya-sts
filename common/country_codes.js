// @ts-check
'use strict';
//
// File: country_codes.js
//
// ===========================================================================
// ISO 3166-1 ALPHA-2 TO ALPHA-3, AND THE ICAO NATIONALITY CODE (#128,
// 2026-09-23).
//
// The directory holds a country the way SCHAC and RFC 4519 do — two letters
// (`c`, `schacCountryOfCitizenship`) — and the OpenID Connect for Identity
// Assurance Claims Registration 1.0 asks for three:
//
//   * `address.country_code` (section 4.2): ISO 3166-1 Alpha-3;
//   * `nationalities` (section 4.1): "ICAO 3-letter codes [ICAO-Doc9303]".
//
// The two are the same table but for ONE entry: ICAO Doc 9303 Part 3 writes
// Germany as `D` (padded `D<<` in a machine-readable zone), where ISO writes
// `DEU`. That is the whole of `ICAO_EXCEPTIONS`, and it is kept as an
// exception rather than folded into the table so the difference is visible.
//
// A LEAF (rule 3): `helpers` only. A value that is not a known alpha-2 code
// comes back UNCHANGED — the directory may already hold three letters, or
// something an operator typed — rather than dropped: converting what can be
// converted and passing the rest through is the rule `toClaim()` follows for
// every other row of the catalogue.
// ===========================================================================

const { log } = require('./helpers');

// alpha-2:alpha-3, ISO 3166-1 (the officially assigned codes).
const PAIRS = (
  'AD:AND AE:ARE AF:AFG AG:ATG AI:AIA AL:ALB AM:ARM AO:AGO AQ:ATA AR:ARG ' +
  'AS:ASM AT:AUT AU:AUS AW:ABW AX:ALA AZ:AZE BA:BIH BB:BRB BD:BGD BE:BEL ' +
  'BF:BFA BG:BGR BH:BHR BI:BDI BJ:BEN BL:BLM BM:BMU BN:BRN BO:BOL BQ:BES ' +
  'BR:BRA BS:BHS BT:BTN BV:BVT BW:BWA BY:BLR BZ:BLZ CA:CAN CC:CCK CD:COD ' +
  'CF:CAF CG:COG CH:CHE CI:CIV CK:COK CL:CHL CM:CMR CN:CHN CO:COL CR:CRI ' +
  'CU:CUB CV:CPV CW:CUW CX:CXR CY:CYP CZ:CZE DE:DEU DJ:DJI DK:DNK DM:DMA ' +
  'DO:DOM DZ:DZA EC:ECU EE:EST EG:EGY EH:ESH ER:ERI ES:ESP ET:ETH FI:FIN ' +
  'FJ:FJI FK:FLK FM:FSM FO:FRO FR:FRA GA:GAB GB:GBR GD:GRD GE:GEO GF:GUF ' +
  'GG:GGY GH:GHA GI:GIB GL:GRL GM:GMB GN:GIN GP:GLP GQ:GNQ GR:GRC GS:SGS ' +
  'GT:GTM GU:GUM GW:GNB GY:GUY HK:HKG HM:HMD HN:HND HR:HRV HT:HTI HU:HUN ' +
  'ID:IDN IE:IRL IL:ISR IM:IMN IN:IND IO:IOT IQ:IRQ IR:IRN IS:ISL IT:ITA ' +
  'JE:JEY JM:JAM JO:JOR JP:JPN KE:KEN KG:KGZ KH:KHM KI:KIR KM:COM KN:KNA ' +
  'KP:PRK KR:KOR KW:KWT KY:CYM KZ:KAZ LA:LAO LB:LBN LC:LCA LI:LIE LK:LKA ' +
  'LR:LBR LS:LSO LT:LTU LU:LUX LV:LVA LY:LBY MA:MAR MC:MCO MD:MDA ME:MNE ' +
  'MF:MAF MG:MDG MH:MHL MK:MKD ML:MLI MM:MMR MN:MNG MO:MAC MP:MNP MQ:MTQ ' +
  'MR:MRT MS:MSR MT:MLT MU:MUS MV:MDV MW:MWI MX:MEX MY:MYS MZ:MOZ NA:NAM ' +
  'NC:NCL NE:NER NF:NFK NG:NGA NI:NIC NL:NLD NO:NOR NP:NPL NR:NRU NU:NIU ' +
  'NZ:NZL OM:OMN PA:PAN PE:PER PF:PYF PG:PNG PH:PHL PK:PAK PL:POL PM:SPM ' +
  'PN:PCN PR:PRI PS:PSE PT:PRT PW:PLW PY:PRY QA:QAT RE:REU RO:ROU RS:SRB ' +
  'RU:RUS RW:RWA SA:SAU SB:SLB SC:SYC SD:SDN SE:SWE SG:SGP SH:SHN SI:SVN ' +
  'SJ:SJM SK:SVK SL:SLE SM:SMR SN:SEN SO:SOM SR:SUR SS:SSD ST:STP SV:SLV ' +
  'SX:SXM SY:SYR SZ:SWZ TC:TCA TD:TCD TF:ATF TG:TGO TH:THA TJ:TJK TK:TKL ' +
  'TL:TLS TM:TKM TN:TUN TO:TON TR:TUR TT:TTO TV:TUV TW:TWN TZ:TZA UA:UKR ' +
  'UG:UGA UM:UMI US:USA UY:URY UZ:UZB VA:VAT VC:VCT VE:VEN VG:VGB VI:VIR ' +
  'VN:VNM VU:VUT WF:WLF WS:WSM YE:YEM YT:MYT ZA:ZAF ZM:ZMB ZW:ZWE'
).split(' ');

const ALPHA3 = new Map();
PAIRS.forEach(function (pair) {
  const at = pair.indexOf(':');
  ALPHA3.set(pair.slice(0, at), pair.slice(at + 1));
});

// ICAO Doc 9303 Part 3's three-letter nationality codes differ from ISO
// 3166-1 alpha-3 in this one assigned country.
const ICAO_EXCEPTIONS = new Map([['DE', 'D']]);

// ISO 3166-1 alpha-3 for an alpha-2 code; anything else unchanged.
function alpha3(value) {
  log.debug("Entering alpha3().");
  const text = String(value == null ? '' : value).trim();
  const found = ALPHA3.get(text.toUpperCase());
  log.debug("Leaving alpha3().");
  return found || text;
}

// The ICAO Doc 9303 nationality code for an alpha-2 code; anything else
// unchanged.
function icaoNationality(value) {
  log.debug("Entering icaoNationality().");
  const text = String(value == null ? '' : value).trim();
  const exception = ICAO_EXCEPTIONS.get(text.toUpperCase());
  log.debug("Leaving icaoNationality().");
  return exception || alpha3(text);
}

module.exports = {
  COUNTRY_COUNT: ALPHA3.size,
  alpha3: alpha3,
  icaoNationality: icaoNationality
};

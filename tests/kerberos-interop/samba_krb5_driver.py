"""Run Samba's raw Kerberos KDC tests against one KDC, print JSON (#204).

The driver tests/vendored/sts_kerberos_samba.js runs. It is this
repository's, not Samba's: Samba runs these tests through its selftest
(waf, subunit, a provisioned AD DC per environment), and the job wants every
test's outcome as data. What it runs is Samba's own test classes, loaded by
name with unittest and run unchanged; nothing here changes what a test
SENDS or what it CHECKS.

Samba is GPL-3.0 and is never vendored: tests/Dockerfile builds a pinned
release into /opt/samba (tests/kerberos-interop/build-samba.sh), and this
file imports it from there. This file imports nothing of Samba's at its top,
so that a module that cannot even be imported is REPORTED as a result.

Arguments: the dotted names of test modules or classes, e.g.
  samba.tests.krb5.kdc_tests
  samba.tests.krb5.simple_tests.SimpleKerberosTests
Everything the tests read — SERVER, REALM, USERNAME, PASSWORD, the KRBTGT_
and SERVICE_ credentials, SMB_CONF_PATH, SERVERCONFFILE, STRICT_CHECKING and
the rest — comes from the environment the job builds, which is the tests'
own contract (raw_testcase.py's setUpClass and _get_krb5_creds_from_env).

The last line of standard output is one JSON document:
  {"results": [{"id", "outcome", "detail"}...], "load_errors": [...]}
where outcome is pass, fail, error, skip, xfail or uxsuccess. Everything
before it is what the tests themselves printed.
"""

import io
import os
import json
import sys
import traceback
import unittest

MARKER = "SAMBA-KRB5-RESULTS "


class Collect(unittest.TestResult):
    """Every test's outcome, with the part of the traceback that says why."""

    def __init__(self):
        super().__init__()
        self.rows = []

    @staticmethod
    def _why(err):
        text = "".join(traceback.format_exception(*err))
        # The assertion message is at the end; the frames above it are
        # Samba's own and are kept, trimmed, for whoever reads the log.
        return text[-4000:]

    def addSuccess(self, test):
        super().addSuccess(test)
        self.rows.append({"id": test.id(), "outcome": "pass", "detail": ""})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.rows.append({"id": test.id(), "outcome": "fail",
                          "detail": self._why(err)})

    def addError(self, test, err):
        super().addError(test, err)
        self.rows.append({"id": test.id(), "outcome": "error",
                          "detail": self._why(err)})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.rows.append({"id": test.id(), "outcome": "skip",
                          "detail": str(reason)})

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.rows.append({"id": test.id(), "outcome": "xfail",
                          "detail": self._why(err)})

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.rows.append({"id": test.id(), "outcome": "uxsuccess",
                          "detail": ""})


# THE ONE ADAPTATION, and it changes neither what a test sends to the KDC nor
# what it checks. Samba's KDCBaseTest reaches an Active Directory domain
# controller for the accounts it tests with — SamDB over LDAP to create and
# read them, DRSUAPI to replicate their keys, LSA to create trusts, SAMR and
# NETLOGON — and this service is a KDC, not an AD DC. Unpatched, every such
# test ERRORS with a connection error from our LDAP port, which reads like a
# failure of the KDC and is not one. So each door to the DC raises SkipTest
# naming what the test needed, and the job counts those as NOT APPLICABLE by
# that reason. A test that uses only the credentials the environment hands it
# (Samba's own contract: USERNAME, CLIENT_, MAC_, SERVICE_, SERVER_, DC_,
# KRBTGT_ and ADMIN_) never touches these doors and runs in full.
AD_ONLY = ("needs an Active Directory domain controller (%s) to create or "
           "read the accounts it tests with; this KDC is not one")


def _refuse(what):
    def refusal(*args, **kwargs):
        raise unittest.SkipTest(AD_ONLY % what)
    return refusal


def install_ad_refusals():
    from samba.tests.krb5 import kdc_base_test
    from samba.dcerpc import lsa, netlogon, samr
    import samba.samdb
    base = kdc_base_test.KDCBaseTest
    base.get_samdb = _refuse("SamDB over LDAP")
    base.get_rodc_samdb = _refuse("an RODC's SamDB over LDAP")
    base.get_drsuapi_connection = _refuse("DRSUAPI")
    base.get_lsarpc_connection = _refuse("LSA RPC")
    base.get_mock_rodc_ctx = _refuse("a joined RODC")
    kdc_base_test.SamDB = _refuse("SamDB")
    samba.samdb.SamDB = _refuse("SamDB over LDAP")
    samr.samr = _refuse("SAMR RPC")
    netlogon.netlogon = _refuse("NETLOGON RPC")
    lsa.lsarpc = _refuse("LSA RPC")


# THE SECOND ADAPTATION, and the only other one: an ACCOUNT. KDCBaseTest's
# create_account_opts() makes each account a test needs in SamDB and reads its
# keys back over DRSUAPI. A development trust realm of this service creates a
# person's principal on first sight, keyed from the realm's shared password
# (kerberos/CLAUDE.md, *Kerberos is the exception*), so an ordinary USER with
# no Active Directory attribute set is exactly what the KDC will answer for
# under a fresh name, and the adapter returns credentials for one: its name,
# the shared password and the realm's configured kvno. Everything else — a
# computer, server, RODC or managed-service account, and a user carrying any
# AD attribute (msDS-SupportedEncryptionTypes, a UPN, an SPN, delegation
# rights, RODC reveal lists, group membership, an authentication policy,
# logon hours, smart card, disabled, an expired password...) — is SKIPPED
# naming what it needed, because answering it would mean inventing an
# attribute this directory does not hold.
SHARED_PASSWORD = os.environ.get("SAMBA_KRB5_SHARED_PASSWORD", "")
SHARED_KVNO = int(os.environ.get("SAMBA_KRB5_SHARED_KVNO", "0") or 0)

# The defaults create_account_opts() is called with (get_cached_creds'
# opts_default); an option at its default asks for nothing.
NEUTRAL = {"name_prefix", "name_suffix", "account_type", "id",
           "kerberos_enabled", "secure_channel_type"}


def make_account_adapter(base):
    from samba.credentials import MUST_USE_KERBEROS, DONT_USE_KERBEROS
    from samba.tests.krb5.raw_testcase import KerberosCredentials

    def create_account_opts(self, samdb, use_cache, **opts):
        account_type = opts["account_type"]
        if account_type is not self.AccountType.USER:
            raise unittest.SkipTest(
                "needs a %s account, whose sAMAccountName and SPNs share one "
                "key in Active Directory (MS-KILE 3.3.5.1.1); this KDC keys "
                "a person and a service principal apart"
                % account_type.name.lower())
        defaults = {"add_dollar": None, "upn": None, "spn": None,
                    "additional_details": None, "supported_enctypes": None,
                    "sid_compression_support": True, "member_of": None,
                    "assigned_policy": None, "assigned_silo": None,
                    "logon_hours": None, "enabled": True,
                    "keycredlink": None, "delegation_to_spn": None,
                    "delegation_from_dn": None,
                    "selective_auth_allowed_sid": None}
        asked = []
        for key, value in opts.items():
            if key in NEUTRAL:
                continue
            if key in defaults:
                if value != defaults[key]:
                    asked.append(key)
            elif value:
                asked.append(key)
        if asked:
            raise unittest.SkipTest(
                "needs a user account with %s set, an Active Directory "
                "attribute or act this directory does not hold"
                % ", ".join(sorted(asked)))
        if not SHARED_PASSWORD:
            raise unittest.SkipTest("the job named no shared password")
        name = self.get_new_username()
        if opts.get("name_prefix"):
            name = opts["name_prefix"] + name
        if opts.get("name_suffix"):
            name += opts["name_suffix"]
        creds = KerberosCredentials()
        creds.set_domain(self.env_get_var("DOMAIN", None))
        creds.set_realm(self.env_get_var("REALM", None))
        creds.set_username(name)
        creds.set_password(SHARED_PASSWORD)
        creds.set_workstation("")
        if SHARED_KVNO:
            creds.set_kvno(SHARED_KVNO)
        creds.set_type(self.AccountType.USER)
        self.creds_set_default_enctypes(creds)
        if opts.get("kerberos_enabled", True):
            creds.set_kerberos_state(MUST_USE_KERBEROS)
        else:
            creds.set_kerberos_state(DONT_USE_KERBEROS)
        return creds

    base.create_account_opts = create_account_opts

    # THE DOMAIN'S FUNCTIONAL LEVEL, read from SamDB's rootDSE by
    # get_domain_functional_level(), decides only one thing these tests
    # compare: whether AES keys are expected by default (2008 or later). The
    # job states what this KDC does — it keys every account with AES — as
    # SAMBA_KRB5_DOMAIN_FUNCTIONAL_LEVEL, instead of an LDAP read of a
    # domain it is not.
    level = os.environ.get("SAMBA_KRB5_DOMAIN_FUNCTIONAL_LEVEL", "")
    if level:
        def get_domain_functional_level(self, ldb=None):
            return int(level)
        base.get_domain_functional_level = get_domain_functional_level


def adapt_fast_precondition():
    # fast_tests' check_kdc_fast_support() reads the krbtgt account's
    # msDS-SupportedEncryptionTypes from SamDB and asserts FAST, claims AND
    # compound identity — the Windows 2012 feature bundle. It is a
    # precondition about the ENVIRONMENT, not a check on any message: what
    # these tests then send and check is FAST (RFC 6113). This KDC implements
    # FAST in the AS exchange and neither claims nor compound identity, which
    # the job says as FAST_SUPPORT=1, CLAIMS_SUPPORT=0 and
    # COMPOUND_ID_SUPPORT=0 — the variables the tests already read for what
    # to expect. So the precondition is the FAST_SUPPORT the job declared.
    from samba.tests.krb5 import fast_tests

    def check_kdc_fast_support(self):
        self.assertTrue(self.kdc_fast_support,
                        "FAST_SUPPORT is not set, so these tests expect no "
                        "FAST from this KDC")
    fast_tests.FAST_Tests.check_kdc_fast_support = check_kdc_fast_support


def main(names):
    install_ad_refusals()
    from samba.tests.krb5 import kdc_base_test
    make_account_adapter(kdc_base_test.KDCBaseTest)
    adapt_fast_precondition()
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    load_errors = []
    for name in names:
        try:
            suite.addTests(loader.loadTestsFromName(name))
        except Exception:  # noqa: BLE001 -- reported, never swallowed
            load_errors.append({"name": name,
                                "detail": traceback.format_exc()[-4000:]})
    # A class whose setUpClass raises is one _ErrorHolder "test" named for
    # the class; unittest reports it through addError, so it is a row too.
    result = Collect()
    suite.run(result)
    for holder_err in loader.errors:
        load_errors.append({"name": "loader", "detail": holder_err[-4000:]})
    sys.stdout.flush()
    out = io.StringIO()
    json.dump({"results": result.rows, "load_errors": load_errors}, out)
    sys.stdout.write("\n" + MARKER + out.getvalue() + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

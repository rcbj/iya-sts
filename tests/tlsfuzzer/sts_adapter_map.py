# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: BUSL-1.1
#
# File: sts_adapter_map.py
#
# Prints the TLS 1.2 suite map tests/tlsfuzzer_plan.js asserts (#321).
# sts_adapter.py imports tlsfuzzer only after it has parsed a script, so
# this loads the two functions that do not, against a stand-in
# CipherSuite, and writes one JSON object. It decides nothing: the plan
# test does. The same shape as the other Python programs a job runs,
# rather than a script assembled on the command line.
import importlib.util
import json
import os
import sys


def load_adapter():
    """sts_adapter.py, loaded from this directory, without running it."""
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, 'sts_adapter.py')
    spec = importlib.util.spec_from_file_location('sts_adapter', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def stand_in_suite():
    """CipherSuite names as strings, so the map can be read without
    tlslite. The four targets are short labels the plan test compares."""
    class Suite(object):
        pass
    bulks = ('AES_128_CBC_SHA', 'AES_128_CBC_SHA256', 'AES_256_CBC_SHA',
             'AES_256_CBC_SHA256', 'AES_256_CBC_SHA384',
             'AES_128_GCM_SHA256', 'AES_256_GCM_SHA384')
    for kex in ('RSA', 'DHE_RSA', 'ECDHE_RSA', 'ECDHE_ECDSA'):
        for bulk in bulks:
            name = 'TLS_%s_WITH_%s' % (kex, bulk)
            setattr(Suite, name, name)
    Suite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 'ECDHE_ECDSA_128'
    Suite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 'ECDHE_ECDSA_256'
    Suite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 'ECDHE_RSA_128'
    Suite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 'ECDHE_RSA_256'
    return Suite


def main():
    mod = load_adapter()
    suite = stand_in_suite()
    ec = mod.aead_substitutes(suite, 'ec')
    rsa = mod.aead_substitutes(suite, 'rsa')
    json.dump({
        'schemes': list(mod.ecdsa_schemes()),
        'ec_rsa_gcm': ec[suite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
        'ec_rsa_cbc': ec[suite.TLS_RSA_WITH_AES_256_CBC_SHA],
        'rsa_ecdsa_gcm':
            rsa[suite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        'rsa_rsa_gcm': rsa[suite.TLS_RSA_WITH_AES_128_GCM_SHA256],
    }, sys.stdout)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()

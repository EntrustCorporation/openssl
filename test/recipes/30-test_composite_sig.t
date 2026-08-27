#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw(:DEFAULT srctop_dir bldtop_dir srctop_file bldtop_file);
use OpenSSL::Test::Utils;

BEGIN {
    setup("test_composite_sig");
}

use lib srctop_dir('Configurations');
use lib bldtop_dir('.');

plan skip_all => 'Composite signatures are not supported in this build'
    if disabled('composite');

my $no_fips = disabled('fips') || ($ENV{NO_FIPS} // 0);
my $no_ecx  = disabled('ecx');
my $provconf = srctop_file("test", "fips-and-base.cnf");

# 1 C test run + 1 FIPS skip + 1 require_ok
# + N × 2 tconversion subtests (N = 18 normally, 15 when no-ecx removes
# ML-DSA-44-Ed25519, ML-DSA-65-Ed25519, ML-DSA-87-Ed448)
plan tests => $no_ecx ? 33 : 39;

# ─── C unit test binary ──────────────────────────────────────────────────────
ok(run(test(["composite_sig_test"])), "running composite_sig_test");

# ─── FIPS variant ────────────────────────────────────────────────────────────
SKIP: {
    # Composite algorithms are not present in the FIPS provider, so the test
    # binary will fail to load them under a FIPS+base library context.
    skip "Composite signatures are not available in the FIPS provider", 1;

    ok(run(test(["composite_sig_test", "-config", $provconf])),
       "running composite_sig_test with FIPS");
}

# ─── pkey CLI conversion round-trips (PKCS#8 + public key) ──────────────────

require_ok(srctop_file('test','recipes','tconversion.pl'));

# Remove ECX-dependent composites when ECX is disabled
my @composite_pems = (
    [ "ML-DSA-44-RSA2048-PSS-SHA256",          "testcomposite44-rsa2048pss"             ],
    [ "ML-DSA-44-RSA2048-PKCS15-SHA256",        "testcomposite44-rsa2048pkcs15"          ],
    [ "ML-DSA-44-Ed25519-SHA512",               "testcomposite44-ed25519"                ],
    [ "ML-DSA-44-ECDSA-P256-SHA256",            "testcomposite44-ecdsa-p256"             ],
    [ "ML-DSA-65-RSA3072-PSS-SHA512",           "testcomposite65-rsa3072pss"             ],
    [ "ML-DSA-65-RSA3072-PKCS15-SHA512",        "testcomposite65-rsa3072pkcs15"          ],
    [ "ML-DSA-65-RSA4096-PSS-SHA512",           "testcomposite65-rsa4096pss"             ],
    [ "ML-DSA-65-RSA4096-PKCS15-SHA512",        "testcomposite65-rsa4096pkcs15"          ],
    [ "ML-DSA-65-ECDSA-P256-SHA512",            "testcomposite65-ecdsa-p256"             ],
    [ "ML-DSA-65-ECDSA-P384-SHA512",            "testcomposite65-ecdsa-p384"             ],
    [ "ML-DSA-65-ECDSA-brainpoolP256r1-SHA512", "testcomposite65-ecdsa-brainpoolp256r1"  ],
    [ "ML-DSA-65-Ed25519-SHA512",               "testcomposite65-ed25519"                ],
    [ "ML-DSA-87-ECDSA-P384-SHA512",            "testcomposite87-ecdsa-p384"             ],
    [ "ML-DSA-87-ECDSA-brainpoolP384r1-SHA512", "testcomposite87-ecdsa-brainpoolp384r1"  ],
    [ "ML-DSA-87-Ed448-SHAKE256",               "testcomposite87-ed448"                  ],
    [ "ML-DSA-87-RSA3072-PSS-SHA512",           "testcomposite87-rsa3072pss"             ],
    [ "ML-DSA-87-RSA4096-PSS-SHA512",           "testcomposite87-rsa4096pss"             ],
    [ "ML-DSA-87-ECDSA-P521-SHA512",            "testcomposite87-ecdsa-p521"             ],
);
@composite_pems = grep { $_->[0] !~ /Ed25519|Ed448/ } @composite_pems if $no_ecx;

foreach my $entry (@composite_pems) {
    my ($alg, $base) = @$entry;

    subtest "$alg conversions -- pkcs8" => sub {
        tconversion(-type   => "pkey",
                    -in     => srctop_file("test", "${base}.pem"),
                    -args   => ["pkey"],
                    -prefix => "${base}-pkcs8");
    };

    subtest "$alg conversions -- pub" => sub {
        tconversion(-type   => "pkey",
                    -in     => srctop_file("test", "${base}pub.pem"),
                    -args   => ["pkey", "-pubin", "-pubout"],
                    -prefix => "${base}-pub");
    };
}

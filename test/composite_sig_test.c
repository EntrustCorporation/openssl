/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "testutil.h"
#include "composite_sig.inc"

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_CONFIG_FILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

static OSSL_LIB_CTX *lib_ctx = NULL;
static OSSL_PROVIDER *null_prov = NULL;
static OSSL_PROVIDER *lib_prov = NULL;

/* =========================================================================
 * Key helpers
 * ========================================================================= */

/*
 * Generate a composite keypair using DRBG (no fixed seed).
 * The algorithm name must be one of the 18 composite names, e.g.
 * "ML-DSA-44-RSA2048-PSS-SHA256".
 */
static EVP_PKEY *do_gen_key(const char *alg)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_keygen_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_generate(ctx, &pkey), 1))
        pkey = NULL;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/*
 * Load a composite private key from raw DER bytes via EVP_PKEY_fromdata.
 * |priv| is the concatenated composite private key blob as exported by the
 * keymgmt (OSSL_PKEY_PARAM_PRIV_KEY).
 */
#if COMPOSITE_SIGGEN_TESTDATA_COUNT > 0
static EVP_PKEY *composite_key_from_priv(const char *alg,
    const uint8_t *priv, size_t priv_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
        (void *)priv, priv_len);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_fromdata(ctx, &pkey,
                            OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
                            params),
            1))
        pkey = NULL;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}
#endif /* COMPOSITE_SIGGEN_TESTDATA_COUNT > 0 */

/*
 * Load a composite public key from raw DER bytes via EVP_PKEY_fromdata.
 */
#if COMPOSITE_SIGVER_TESTDATA_COUNT > 0
static EVP_PKEY *composite_key_from_pub(const char *alg,
    const uint8_t *pub, size_t pub_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
        (void *)pub, pub_len);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_fromdata(ctx, &pkey,
                            OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                            params),
            1))
        pkey = NULL;

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}
#endif /* COMPOSITE_SIGVER_TESTDATA_COUNT > 0 */

/* =========================================================================
 *  DRBG round-trip tests (keygen → sign → verify)
 * ========================================================================= */

/*
 * Sign |msg| with |key| using algorithm |alg|, verify the result.
 * Also checks the buffer-too-small path (sig_len - 1).
 */
static int do_sign_verify(EVP_PKEY *key, const char *alg,
    const uint8_t *msg, size_t msg_len)
{
    int ret = 0;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;

    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, NULL), 1)
        /* query required buffer size */
        || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &sig_len, msg, msg_len), 1)
        || !TEST_ptr(sig = OPENSSL_zalloc(sig_len)))
        goto err;

    /* Sign with one byte too few — must fail */
    sig_len--;
    if (!TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len, msg, msg_len), 0))
        goto err;
    sig_len++;

    /* Actual sign */
    if (!TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len, msg, msg_len), 1))
        goto err;

    /* Verify the signature we just produced */
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len, msg, msg_len), 1))
        goto err;

    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

/* Table of all 18 composite algorithm names */
static const char *composite_alg_names[] = {
    "ML-DSA-44-RSA2048-PSS-SHA256",
    "ML-DSA-44-RSA2048-PKCS15-SHA256",
    "ML-DSA-44-Ed25519-SHA512",
    "ML-DSA-44-ECDSA-P256-SHA256",
    "ML-DSA-65-RSA3072-PSS-SHA512",
    "ML-DSA-65-RSA3072-PKCS15-SHA512",
    "ML-DSA-65-RSA4096-PSS-SHA512",
    "ML-DSA-65-RSA4096-PKCS15-SHA512",
    "ML-DSA-65-ECDSA-P256-SHA512",
    "ML-DSA-65-ECDSA-P384-SHA512",
    "ML-DSA-65-ECDSA-brainpoolP256r1-SHA512",
    "ML-DSA-65-Ed25519-SHA512",
    "ML-DSA-87-ECDSA-P384-SHA512",
    "ML-DSA-87-ECDSA-brainpoolP384r1-SHA512",
    "ML-DSA-87-Ed448-SHAKE256",
    "ML-DSA-87-RSA3072-PSS-SHA512",
    "ML-DSA-87-RSA4096-PSS-SHA512",
    "ML-DSA-87-ECDSA-P521-SHA512",
};
#define NUM_COMPOSITE_ALGS (int)(sizeof(composite_alg_names) / sizeof(composite_alg_names[0]))

static uint8_t test_msg[] = "OpenSSL composite signature test message";

/*
 * DRBG keygen + sign + verify for each of the 18 algorithms.
 * Parameterised by tst_id (0..17).
 */
static int composite_drbg_sign_verify_test(int tst_id)
{
    int ret = 0;
    const char *alg = composite_alg_names[tst_id];
    EVP_PKEY *key = NULL;

#ifdef OPENSSL_NO_EC
    if (strstr(alg, "ECDSA") != NULL) {
        TEST_note("Skipping %s - EC not available", alg);
        return 1;
    }
#endif
#ifdef OPENSSL_NO_ECX
    if (strstr(alg, "Ed25519") != NULL || strstr(alg, "Ed448") != NULL) {
        TEST_note("Skipping %s - ECX (Ed25519/Ed448) not available", alg);
        return 1;
    }
#endif
    if (!TEST_ptr(key = do_gen_key(alg)))
        goto err;

    if (!TEST_true(do_sign_verify(key, alg, test_msg, sizeof(test_msg) - 1)))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key);
    return ret;
}

/*
 * Two DRBG-generated keys of the same algorithm must not be equal.
 * Two keys of different algorithms must return -1 (incompatible types).
 * Checks EVP_PKEY_eq() and EVP_PKEY_dup() round-trips.
 */
static int composite_keygen_drbg_test(void)
{
    int ret = 0;
    EVP_PKEY *k1 = NULL, *k2 = NULL, *k3 = NULL, *k1_dup = NULL;

#ifdef OPENSSL_NO_ECX
    TEST_note("Skipping composite_keygen_drbg_test - requires ECX (Ed25519)");
    return 1;
#endif
    if (!TEST_ptr(k1 = do_gen_key("ML-DSA-44-Ed25519-SHA512"))
        || !TEST_ptr(k2 = do_gen_key("ML-DSA-44-Ed25519-SHA512"))
        || !TEST_ptr(k3 = do_gen_key("ML-DSA-44-RSA2048-PSS-SHA256"))
        /* same algorithm, different keys */
        || !TEST_int_eq(EVP_PKEY_eq(k1, k2), 0)
        /* different algorithm */
        || !TEST_int_eq(EVP_PKEY_eq(k1, k3), -1)
        /* dup must produce an equal key */
        || !TEST_ptr(k1_dup = EVP_PKEY_dup(k1))
        || !TEST_int_eq(EVP_PKEY_eq(k1, k1_dup), 1))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
    EVP_PKEY_free(k3);
    EVP_PKEY_free(k1_dup);
    return ret;
}

/* =========================================================================
 * Deterministic vector tests (composite_sig.inc)
 * ========================================================================= */

/*
 * siggen: load private key from vector, sign the fixed message, compare the
 * SHA-256 digest of the output signature against the stored reference.
 * (Same SHA-256-of-sig trick used by ml_dsa_siggen_test to keep the .inc
 * file small while still providing a complete bit-exact check.)
 */
#if COMPOSITE_SIGGEN_TESTDATA_COUNT > 0
static int composite_siggen_test(int tst_id)
{
    int ret = 0;
    const COMPOSITE_SIG_GEN_TEST_DATA *td = &composite_siggen_testdata[tst_id];
    EVP_PKEY_CTX *sctx = NULL;

#ifdef OPENSSL_NO_ECX
    if (strstr(td->alg, "Ed25519") != NULL || strstr(td->alg, "Ed448") != NULL) {
        TEST_note("Skipping %s - ECX (Ed25519/Ed448) not available", td->alg);
        return 1;
    }
#endif
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    OSSL_PARAM params[2], *p = params;
    uint8_t *psig = NULL;
    size_t psig_len = 0;
    uint8_t digest[32];
    size_t digest_len = sizeof(digest);

    if (td->add_random != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
            (void *)td->add_random, td->add_random_len);
    *p = OSSL_PARAM_construct_end();

    if (!TEST_ptr(pkey = composite_key_from_priv(td->alg, td->priv, td->priv_len)))
        goto err;

    if (!TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, pkey, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, td->alg, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, params), 1)
        || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &psig_len,
                            td->msg, td->msg_len),
            1)
        || !TEST_ptr(psig = OPENSSL_zalloc(psig_len))
        || !TEST_int_eq(EVP_PKEY_sign(sctx, psig, &psig_len,
                            td->msg, td->msg_len),
            1)
        || !TEST_int_eq(EVP_Q_digest(lib_ctx, "SHA256", NULL,
                            psig, psig_len,
                            digest, &digest_len),
            1)
        || !TEST_mem_eq(digest, digest_len,
            td->sig_digest, td->sig_digest_len))
        goto err;

    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(sctx);
    OPENSSL_free(psig);
    return ret;
}
#endif /* COMPOSITE_SIGGEN_TESTDATA_COUNT > 0 */

/*
 * sigver: load public key from vector, verify the stored signature.
 * td->expected == 1 for valid, 0 for deliberately invalid vectors.
 */
#if COMPOSITE_SIGVER_TESTDATA_COUNT > 0
static int composite_sigver_test(int tst_id)
{
    int ret = 0;
    const COMPOSITE_SIG_VER_TEST_DATA *td = &composite_sigver_testdata[tst_id];
    EVP_PKEY_CTX *vctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig_alg = NULL;

    if (!TEST_ptr(pkey = composite_key_from_pub(td->alg, td->pub, td->pub_len)))
        goto err;

    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, pkey, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, td->alg, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, td->sig, td->sig_len,
                            td->msg, td->msg_len),
            td->expected))
        goto err;

    ret = 1;
err:
    EVP_SIGNATURE_free(sig_alg);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}
#endif /* COMPOSITE_SIGVER_TESTDATA_COUNT > 0 */

/* =========================================================================
 * Negative tests
 * ========================================================================= */

/*
 * A signature produced by one composite algorithm must not verify under a
 * different composite algorithm that happens to share the same ML-DSA level
 * (cross-algorithm mismatch).
 */
static int composite_cross_alg_mismatch_test(void)
{
    int ret = 0;
    EVP_PKEY *key_pss = NULL, *key_pkcs = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_pss = NULL, *sig_pkcs = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    const char *alg_a = "ML-DSA-44-RSA2048-PSS-SHA256";
    const char *alg_b = "ML-DSA-44-RSA2048-PKCS15-SHA256";

    if (!TEST_ptr(key_pss = do_gen_key(alg_a))
        || !TEST_ptr(key_pkcs = do_gen_key(alg_b))
        || !TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key_pss, NULL))
        || !TEST_ptr(sig_pss = EVP_SIGNATURE_fetch(lib_ctx, alg_a, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_pss, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &sig_len,
                            test_msg, sizeof(test_msg) - 1),
            1)
        || !TEST_ptr(sig = OPENSSL_zalloc(sig_len))
        || !TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len,
                            test_msg, sizeof(test_msg) - 1),
            1))
        goto err;

    /*
     * Verify alg_a signature under alg_b key — must fail.
     * EVP_PKEY_verify returns 0 for "bad signature" (not -1).
     */
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key_pkcs, NULL))
        || !TEST_ptr(sig_pkcs = EVP_SIGNATURE_fetch(lib_ctx, alg_b, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_pkcs, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len,
                            test_msg, sizeof(test_msg) - 1),
            0))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key_pss);
    EVP_PKEY_free(key_pkcs);
    EVP_SIGNATURE_free(sig_pss);
    EVP_SIGNATURE_free(sig_pkcs);
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

/*
 * A tampered signature (single bit flip) must not verify.
 */
static int composite_tampered_sig_test(int tst_id)
{
    int ret = 0;
    const char *alg = composite_alg_names[tst_id];
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *sctx = NULL, *vctx = NULL;
    EVP_SIGNATURE *sig_alg = NULL;
    uint8_t *sig = NULL;
    size_t sig_len = 0;

#ifdef OPENSSL_NO_EC
    if (strstr(alg, "ECDSA") != NULL) {
        TEST_note("Skipping %s - EC not available", alg);
        return 1;
    }
#endif
#ifdef OPENSSL_NO_ECX
    if (strstr(alg, "Ed25519") != NULL || strstr(alg, "Ed448") != NULL) {
        TEST_note("Skipping %s - ECX (Ed25519/Ed448) not available", alg);
        return 1;
    }
#endif
    if (!TEST_ptr(key = do_gen_key(alg))
        || !TEST_ptr(sctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_ptr(sig_alg = EVP_SIGNATURE_fetch(lib_ctx, alg, NULL))
        || !TEST_int_eq(EVP_PKEY_sign_message_init(sctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_sign(sctx, NULL, &sig_len,
                            test_msg, sizeof(test_msg) - 1),
            1)
        || !TEST_ptr(sig = OPENSSL_zalloc(sig_len))
        || !TEST_int_eq(EVP_PKEY_sign(sctx, sig, &sig_len,
                            test_msg, sizeof(test_msg) - 1),
            1))
        goto err;

    /* Tamper: flip a bit near the middle of the signature */
    sig[sig_len / 2] ^= 0x01;

    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, key, NULL))
        || !TEST_int_eq(EVP_PKEY_verify_message_init(vctx, sig_alg, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_verify(vctx, sig, sig_len,
                            test_msg, sizeof(test_msg) - 1),
            0))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(key);
    EVP_SIGNATURE_free(sig_alg);
    OPENSSL_free(sig);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_CTX_free(vctx);
    return ret;
}

/* =========================================================================
 * Test registration
 * ========================================================================= */

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "config", OPT_CONFIG_FILE, '<',
            "The configuration file to use for the libctx" },
        { NULL }
    };
    return options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;
    char *config_file = NULL;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_CONFIG_FILE:
            config_file = opt_arg();
            break;
        case OPT_TEST_CASES:
            break;
        default:
        case OPT_ERR:
            return 0;
        }
    }
    if (!test_get_libctx(&lib_ctx, &null_prov, config_file, &lib_prov, NULL))
        return 0;

    /* Strategy 1: DRBG round-trips for all 18 algorithms */
    ADD_ALL_TESTS(composite_drbg_sign_verify_test, NUM_COMPOSITE_ALGS);
    ADD_TEST(composite_keygen_drbg_test);

    /* Strategy 2: deterministic vector tests from composite_sig.inc */
#if COMPOSITE_SIGGEN_TESTDATA_COUNT > 0
    ADD_ALL_TESTS(composite_siggen_test, COMPOSITE_SIGGEN_TESTDATA_COUNT);
#endif
#if COMPOSITE_SIGVER_TESTDATA_COUNT > 0
    ADD_ALL_TESTS(composite_sigver_test, COMPOSITE_SIGVER_TESTDATA_COUNT);
#endif

    /* Negative tests */
    ADD_TEST(composite_cross_alg_mismatch_test);
    ADD_ALL_TESTS(composite_tampered_sig_test, NUM_COMPOSITE_ALGS);

    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(null_prov);
    OSSL_PROVIDER_unload(lib_prov);
    OSSL_LIB_CTX_free(lib_ctx);
}

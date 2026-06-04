/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <openssl/types.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "crypto/evp.h"
#include "crypto/ml_dsa.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/composite.h"
#include "prov/names.h"
#include "providers/implementations/signature/composite_sig.inc"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

/*
 * Fixed 32-byte domain separation prefix per draft-ietf-lamps-pq-composite-sigs.
 * Byte encoding of the ASCII string "CompositeAlgorithmSignatures2025":
 *   436F6D706F73697465416C676F726974686D5369676E61747572657332303235
 */
static const uint8_t composite_sig_prefix[32] = {
    0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69, 0x74,  /* Composit */
    0x65, 0x41, 0x6C, 0x67, 0x6F, 0x72, 0x69, 0x74,  /* eAlgorit */
    0x68, 0x6D, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74,  /* hmSignat */
    0x75, 0x72, 0x65, 0x73, 0x32, 0x30, 0x32, 0x35   /* ures2025 */
};

static OSSL_FUNC_signature_sign_fn composite_sign;

static void *composite_newctx(void *provctx, int evp_type, const char *propq)
{
    PROV_COMPOSITE_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_COMPOSITE_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    return ctx;
}

typedef enum {
    COMPOSITE_CLASSIC_RSA_PSS,
    COMPOSITE_CLASSIC_RSA_PKCS15,
    COMPOSITE_CLASSIC_ECDSA,
    COMPOSITE_CLASSIC_ED25519,
    COMPOSITE_CLASSIC_ED448
} COMPOSITE_CLASSIC_TYPE;

typedef struct {
    const char *name;
    const char *label;       /* ASCII label for M' and ML-DSA ctx per draft §6 */
    const unsigned char *oid;
    size_t oid_sz;
    const char *prehash_alg; /* hash for M' and classic signing */
    size_t prehash_len;      /* prehash output length in bytes */
    COMPOSITE_CLASSIC_TYPE classic_type;
    int pss_salt_len;        /* RSA-PSS only; 0 otherwise */
    const char *mgf1_hash;   /* RSA-PSS MGF1 hash; NULL = same as prehash_alg */
} COMPOSITE_ALG_INFO;

static const COMPOSITE_ALG_INFO composite_alg_table[] = {
    { "ML-DSA-44-RSA2048-PSS-SHA256",
      "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
      ossl_der_oid_id_mldsa44_rsa2048_pss_sha256,
      DER_OID_SZ_id_mldsa44_rsa2048_pss_sha256,
      "SHA-256", 32, COMPOSITE_CLASSIC_RSA_PSS, 32, NULL },
    { "ML-DSA-44-RSA2048-PKCS15-SHA256",
      "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
      ossl_der_oid_id_mldsa44_rsa2048_pkcs15_sha256,
      DER_OID_SZ_id_mldsa44_rsa2048_pkcs15_sha256,
      "SHA-256", 32, COMPOSITE_CLASSIC_RSA_PKCS15, 0, NULL },
    { "ML-DSA-44-Ed25519-SHA512",
      "COMPSIG-MLDSA44-Ed25519-SHA512",
      ossl_der_oid_id_mldsa44_ed25519_sha512,
      DER_OID_SZ_id_mldsa44_ed25519_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_ED25519, 0, NULL },
    { "ML-DSA-44-ECDSA-P256-SHA256",
      "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
      ossl_der_oid_id_mldsa44_ecdsa_p256_sha256,
      DER_OID_SZ_id_mldsa44_ecdsa_p256_sha256,
      "SHA-256", 32, COMPOSITE_CLASSIC_ECDSA, 0, NULL },
    { "ML-DSA-65-RSA3072-PSS-SHA512",
      "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
      ossl_der_oid_id_mldsa65_rsa3072_pss_sha512,
      DER_OID_SZ_id_mldsa65_rsa3072_pss_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_RSA_PSS, 32, NULL },
    { "ML-DSA-65-RSA3072-PKCS15-SHA512",
      "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
      ossl_der_oid_id_mldsa65_rsa3072_pkcs15_sha512,
      DER_OID_SZ_id_mldsa65_rsa3072_pkcs15_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_RSA_PKCS15, 0, NULL },
    { "ML-DSA-65-RSA4096-PSS-SHA512",
      "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
      ossl_der_oid_id_mldsa65_rsa4096_pss_sha512,
      DER_OID_SZ_id_mldsa65_rsa4096_pss_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_RSA_PSS, 48, "SHA-384" },
    { "ML-DSA-65-RSA4096-PKCS15-SHA512",
      "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
      ossl_der_oid_id_mldsa65_rsa4096_pkcs15_sha512,
      DER_OID_SZ_id_mldsa65_rsa4096_pkcs15_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_RSA_PKCS15, 0, NULL },
    { "ML-DSA-65-ECDSA-P256-SHA512",
      "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
      ossl_der_oid_id_mldsa65_ecdsa_p256_sha512,
      DER_OID_SZ_id_mldsa65_ecdsa_p256_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_ECDSA, 0, NULL },
    { "ML-DSA-65-ECDSA-P384-SHA512",
      "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
      ossl_der_oid_id_mldsa65_ecdsa_p384_sha512,
      DER_OID_SZ_id_mldsa65_ecdsa_p384_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_ECDSA, 0, NULL },
    { "ML-DSA-65-ECDSA-brainpoolP256r1-SHA512",
      "COMPSIG-MLDSA65-ECDSA-BP256-SHA512",
      ossl_der_oid_id_mldsa65_ecdsa_brainpoolP256r1_sha512,
      DER_OID_SZ_id_mldsa65_ecdsa_brainpoolP256r1_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_ECDSA, 0, NULL },
    { "ML-DSA-65-Ed25519-SHA512",
      "COMPSIG-MLDSA65-Ed25519-SHA512",
      ossl_der_oid_id_mldsa65_ed25519_sha512,
      DER_OID_SZ_id_mldsa65_ed25519_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_ED25519, 0, NULL },
    { "ML-DSA-87-ECDSA-P384-SHA512",
      "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
      ossl_der_oid_id_mldsa87_ecdsa_p384_sha512,
      DER_OID_SZ_id_mldsa87_ecdsa_p384_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_ECDSA, 0, NULL },
    { "ML-DSA-87-ECDSA-brainpoolP384r1-SHA512",
      "COMPSIG-MLDSA87-ECDSA-BP384-SHA512",
      ossl_der_oid_id_mldsa87_ecdsa_brainpoolp384r1_sha512,
      DER_OID_SZ_id_mldsa87_ecdsa_brainpoolp384r1_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_ECDSA, 0, NULL },
    { "ML-DSA-87-Ed448-SHAKE256",
      "COMPSIG-MLDSA87-Ed448-SHAKE256",
      ossl_der_oid_id_mldsa87_ed448_shake256,
      DER_OID_SZ_id_mldsa87_ed448_shake256,
      "SHAKE256", 64, COMPOSITE_CLASSIC_ED448, 0, NULL },
    { "ML-DSA-87-RSA3072-PSS-SHA512",
      "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
      ossl_der_oid_id_mldsa87_rsa3072_pss_sha512,
      DER_OID_SZ_id_mldsa87_rsa3072_pss_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_RSA_PSS, 32, NULL },
    { "ML-DSA-87-RSA4096-PSS-SHA512",
      "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
      ossl_der_oid_id_mldsa87_rsa4096_pss_sha512,
      DER_OID_SZ_id_mldsa87_rsa4096_pss_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_RSA_PSS, 48, "SHA-384" },
    { "ML-DSA-87-ECDSA-P521-SHA512",
      "COMPSIG-MLDSA87-ECDSA-P521-SHA512",
      ossl_der_oid_id_mldsa87_ecdsa_p521_sha512,
      DER_OID_SZ_id_mldsa87_ecdsa_p521_sha512,
      "SHA-512", 64, COMPOSITE_CLASSIC_ECDSA, 0, NULL },
};
#define COMPOSITE_NUM_ALGS \
    (sizeof(composite_alg_table) / sizeof(composite_alg_table[0]))

static const COMPOSITE_ALG_INFO *composite_find_alg_info(const char *name)
{
    size_t i;

    if (name == NULL)
        return NULL;
    for (i = 0; i < COMPOSITE_NUM_ALGS; i++) {
        if (OPENSSL_strcasecmp(name, composite_alg_table[i].name) == 0)
            return &composite_alg_table[i];
    }
    return NULL;
}

/*
 * Compute PH(M) for M' construction.  Handles both regular digests and the
 * SHAKE256 XOF used by ML-DSA-87-Ed448-SHAKE256.
 */
static int composite_compute_prehash(OSSL_LIB_CTX *libctx,
                                     const COMPOSITE_ALG_INFO *info,
                                     const uint8_t *msg, size_t msg_len,
                                     uint8_t *out)
{
    if (OPENSSL_strcasecmp(info->prehash_alg, "SHAKE256") == 0) {
        EVP_MD_CTX *mctx = EVP_MD_CTX_new();
        EVP_MD *md = EVP_MD_fetch(libctx, "SHAKE256", NULL);
        int ok = (mctx != NULL && md != NULL
                  && EVP_DigestInit_ex(mctx, md, NULL)
                  && EVP_DigestUpdate(mctx, msg, msg_len)
                  && EVP_DigestFinalXOF(mctx, out, info->prehash_len));
        EVP_MD_CTX_free(mctx);
        EVP_MD_free(md);
        return ok;
    }
    return EVP_Q_digest(libctx, info->prehash_alg, NULL, msg, msg_len, out, NULL);
}

/*
 * Sign tbs/tbs_len with the traditional (non-ML-DSA) component key.
 */
static int composite_classic_sign(PROV_COMPOSITE_CTX *ctx,
                                   const COMPOSITE_ALG_INFO *info,
                                   const uint8_t *tbs, size_t tbs_len,
                                   uint8_t *sig, size_t *siglen)
{
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    if (md_ctx == NULL)
        return 0;

    switch (info->classic_type) {
    case COMPOSITE_CLASSIC_ED25519:
    case COMPOSITE_CLASSIC_ED448:
        /* Pure EdDSA: pass NULL as the digest name */
        if (!EVP_DigestSignInit_ex(md_ctx, NULL, NULL,
                                   ctx->libctx, NULL,
                                   ctx->key->classic_key, NULL))
            goto err;
        break;

    case COMPOSITE_CLASSIC_ECDSA:
        if (!EVP_DigestSignInit_ex(md_ctx, NULL, info->prehash_alg,
                                   ctx->libctx, NULL,
                                   ctx->key->classic_key, NULL))
            goto err;
        break;

    case COMPOSITE_CLASSIC_RSA_PSS:
        if (!EVP_DigestSignInit_ex(md_ctx, &pctx, info->prehash_alg,
                                   ctx->libctx, NULL,
                                   ctx->key->classic_key, NULL))
            goto err;
        {
            const char *mgf1 = (info->mgf1_hash != NULL)
                                ? info->mgf1_hash : info->prehash_alg;
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
                || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, info->pss_salt_len) <= 0
                || EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, mgf1, NULL) <= 0)
                goto err;
        }
        break;

    case COMPOSITE_CLASSIC_RSA_PKCS15:
        if (!EVP_DigestSignInit_ex(md_ctx, &pctx, info->prehash_alg,
                                   ctx->libctx, NULL,
                                   ctx->key->classic_key, NULL))
            goto err;
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
            goto err;
        break;

    default:
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        goto err;
    }

    if (!EVP_DigestSign(md_ctx, sig, siglen, tbs, tbs_len))
        goto err;

    ret = 1;
err:
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

static int composite_sign(void *vctx, uint8_t *sig, size_t *siglen, size_t sigsize,
                          const uint8_t *msg, size_t msg_len)
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    const COMPOSITE_ALG_INFO *info;
    uint8_t *tbs = NULL;
    uint8_t prehash[64]; /* max prehash output size */
    size_t tbs_len = 0;
    size_t offset;
    uint8_t rnd[32];
    size_t ml_dsa_siglen, classic_siglen, ml_dsa_sig_max;
    int ret = 0;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx->key == NULL || ctx->alg == NULL)
        return 0;

    info = composite_find_alg_info(ctx->alg);
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    ml_dsa_sig_max = ossl_ml_dsa_key_get_sig_len(ctx->key->ml_dsa_key);

    /* Size query */
    if (sig == NULL) {
        *siglen = ml_dsa_sig_max
                  + (size_t)EVP_PKEY_get_size(ctx->key->classic_key);
        return 1;
    }

    /* Compute PH(M) */
    if (!composite_compute_prehash(ctx->libctx, info, msg, msg_len, prehash))
        goto err;

    /*
     * Build M' = Prefix(32) || Label || uint8(ctx_len) || ctx || PH(M)
     * per draft-ietf-lamps-pq-composite-sigs §2.2.
     * Label is the ASCII string from §6, e.g. "COMPSIG-MLDSA44-RSA2048-PSS-SHA256".
     */
    tbs_len = 32 + strlen(info->label) + 1 + ctx->context_string_len + info->prehash_len;
    tbs = OPENSSL_malloc(tbs_len);
    if (tbs == NULL)
        goto err;

    offset = 0;
    memcpy(tbs + offset, composite_sig_prefix, 32);
    offset += 32;
    memcpy(tbs + offset, info->label, strlen(info->label));
    offset += strlen(info->label);
    tbs[offset++] = (uint8_t)ctx->context_string_len;
    if (ctx->context_string_len > 0) {
        memcpy(tbs + offset, ctx->context_string, ctx->context_string_len);
        offset += ctx->context_string_len;
    }
    memcpy(tbs + offset, prehash, info->prehash_len);

    /* ML-DSA component: pure ML-DSA on M', with Label as mldsa_ctx per §3.1 */
    if (RAND_priv_bytes_ex(ctx->libctx, rnd, sizeof(rnd), 0) <= 0)
        goto err;

    ml_dsa_siglen = ml_dsa_sig_max;
    if (!ossl_ml_dsa_sign(ctx->key->ml_dsa_key, 0,
                          tbs, tbs_len,
                          (const unsigned char *)info->label, strlen(info->label),
                          rnd, sizeof(rnd), 1,
                          sig, &ml_dsa_siglen, sigsize))
        goto err;

    /* Traditional component: sign M' with the classic key */
    classic_siglen = sigsize - ml_dsa_siglen;
    if (!composite_classic_sign(ctx, info, tbs, tbs_len,
                                sig + ml_dsa_siglen, &classic_siglen))
        goto err;

    /* Wire format: mldsaSig || tradSig (flat concatenation) */
    *siglen = ml_dsa_siglen + classic_siglen;
    ret = 1;

err:
    OPENSSL_clear_free(tbs, tbs_len);
    return ret;
}

static void composite_freectx(void *vctx)
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;

    OPENSSL_free(ctx);
}

static void *composite_dupctx(void *vctx)
{
    PROV_COMPOSITE_CTX *src = (PROV_COMPOSITE_CTX *)vctx;
    PROV_COMPOSITE_CTX *dst;

    dst = OPENSSL_memdup(src, sizeof(*src));
    return dst;
}

static int composite_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    const COMPOSITE_ALG_INFO *info;

    if (ctx == NULL || vkey == NULL)
        return 0;

    ctx->key = (COMPOSITE_KEY *)vkey;

    info = composite_find_alg_info(ctx->alg);
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    ctx->oid = info->oid;
    ctx->oid_sz = info->oid_sz;
    ctx->prehash_alg = info->prehash_alg;
    ctx->prehash_len = info->prehash_len;

    return 1;
}

static int composite_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    const COMPOSITE_ALG_INFO *info;

    if (ctx == NULL || vkey == NULL)
        return 0;

    ctx->key = (COMPOSITE_KEY *)vkey;

    info = composite_find_alg_info(ctx->alg);
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    ctx->oid = info->oid;
    ctx->oid_sz = info->oid_sz;
    ctx->prehash_alg = info->prehash_alg;
    ctx->prehash_len = info->prehash_len;

    return 1;
}

static int composite_verify(void *vctx, const uint8_t *sig, size_t siglen,
                            const uint8_t *msg, size_t msg_len)
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    const COMPOSITE_ALG_INFO *info;
    uint8_t *tbs = NULL;
    uint8_t prehash[64]; /* max prehash output size */
    size_t tbs_len = 0;
    size_t offset;
    size_t ml_dsa_sig_len;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx->key == NULL || ctx->alg == NULL || sig == NULL || msg == NULL)
        return 0;

    info = composite_find_alg_info(ctx->alg);
    if (info == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    ml_dsa_sig_len = ossl_ml_dsa_key_get_sig_len(ctx->key->ml_dsa_key);
    if (siglen <= ml_dsa_sig_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        return 0;
    }

    /* Compute PH(M) */
    if (!composite_compute_prehash(ctx->libctx, info, msg, msg_len, prehash))
        goto err;

    /* Reconstruct M' — identical to sign path */
    tbs_len = 32 + strlen(info->label) + 1 + ctx->context_string_len + info->prehash_len;
    tbs = OPENSSL_malloc(tbs_len);
    if (tbs == NULL)
        goto err;

    offset = 0;
    memcpy(tbs + offset, composite_sig_prefix, 32);
    offset += 32;
    memcpy(tbs + offset, info->label, strlen(info->label));
    offset += strlen(info->label);
    tbs[offset++] = (uint8_t)ctx->context_string_len;
    if (ctx->context_string_len > 0) {
        memcpy(tbs + offset, ctx->context_string, ctx->context_string_len);
        offset += ctx->context_string_len;
    }
    memcpy(tbs + offset, prehash, info->prehash_len);

    /* Verify ML-DSA component, with Label as mldsa_ctx per §3.2 */
    if (!ossl_ml_dsa_verify(ctx->key->ml_dsa_key, 0,
                            tbs, tbs_len,
                            (const unsigned char *)info->label, strlen(info->label),
                            1, sig, ml_dsa_sig_len))
        goto err;

    /* Verify classic component */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        goto err;

    switch (info->classic_type) {
    case COMPOSITE_CLASSIC_ED25519:
    case COMPOSITE_CLASSIC_ED448:
        if (!EVP_DigestVerifyInit_ex(md_ctx, NULL, NULL,
                                    ctx->libctx, NULL,
                                    ctx->key->classic_key, NULL))
            goto err;
        break;

    case COMPOSITE_CLASSIC_ECDSA:
        if (!EVP_DigestVerifyInit_ex(md_ctx, NULL, info->prehash_alg,
                                    ctx->libctx, NULL,
                                    ctx->key->classic_key, NULL))
            goto err;
        break;

    case COMPOSITE_CLASSIC_RSA_PSS:
        if (!EVP_DigestVerifyInit_ex(md_ctx, &pctx, info->prehash_alg,
                                    ctx->libctx, NULL,
                                    ctx->key->classic_key, NULL))
            goto err;
        {
            const char *mgf1 = (info->mgf1_hash != NULL)
                               ? info->mgf1_hash : info->prehash_alg;
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
                || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, info->pss_salt_len) <= 0
                || EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, mgf1, NULL) <= 0)
                goto err;
        }
        break;

    case COMPOSITE_CLASSIC_RSA_PKCS15:
        if (!EVP_DigestVerifyInit_ex(md_ctx, &pctx, info->prehash_alg,
                                    ctx->libctx, NULL,
                                    ctx->key->classic_key, NULL))
            goto err;
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
            goto err;
        break;

    default:
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        goto err;
    }

    if (EVP_DigestVerify(md_ctx,
                         sig + ml_dsa_sig_len,
                         siglen - ml_dsa_sig_len,
                         tbs, tbs_len) != 1)
        goto err;

    ret = 1;
err:
    EVP_MD_CTX_free(md_ctx);
    OPENSSL_clear_free(tbs, tbs_len);
    return ret;
}

static int composite_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    struct composite_get_ctx_params_st p;

    if (ctx == NULL || !composite_get_ctx_params_decoder(params, &p))
        return 0;

    if (p.id != NULL) {
        /*
         * Build DER AlgorithmIdentifier = SEQUENCE { OID }
         *   = 0x30 || oid_sz || oid_bytes (total = oid_sz + 2 bytes)
         */
        uint8_t aid[12]; /* 2 header bytes + up to 10 OID bytes */
        size_t aid_len;

        if (ctx->oid == NULL || ctx->oid_sz == 0
                || ctx->oid_sz > sizeof(aid) - 2)
            return 0;

        aid[0] = 0x30; /* SEQUENCE tag */
        aid[1] = (uint8_t)ctx->oid_sz;
        memcpy(aid + 2, ctx->oid, ctx->oid_sz);
        aid_len = 2 + ctx->oid_sz;

        if (!OSSL_PARAM_set_octet_string(p.id, aid, aid_len))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *composite_gettable_ctx_params(void *vctx, void *provctx)
{
    return composite_get_ctx_params_list;
}

static int composite_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    struct composite_set_ctx_params_st p;

    if (ctx == NULL || !composite_set_ctx_params_decoder(params, &p))
        return 0;

    if (p.ctx != NULL) {
        void *vp = ctx->context_string;

        if (!OSSL_PARAM_get_octet_string(p.ctx, &vp, sizeof(ctx->context_string),
                &ctx->context_string_len)) {
            ctx->context_string_len = 0;
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *composite_settable_ctx_params(void *vctx, void *provctx)
{
    return composite_set_ctx_params_list;
}

static int composite_sign_msg_init(void *vctx, void *vkey,
                                   const OSSL_PARAM params[])
{
    return composite_sign_init(vctx, vkey, params);
}

static int composite_signverify_msg_update(void *vctx,
                                           const unsigned char *data,
                                           size_t datalen)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
    return 0;
}

static int composite_sign_msg_final(void *vctx, unsigned char *sig,
                                    size_t *siglen, size_t sigsize)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
    return 0;
}

static int composite_verify_msg_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[])
{
    return composite_verify_init(vctx, vkey, params);
}

static int composite_verify_msg_final(void *vctx)
{
    ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
    return 0;
}

static int composite_digest_signverify_init(void *vctx, const char *mdname,
                                            void *vkey,
                                            const OSSL_PARAM params[])
{
    if (mdname != NULL && mdname[0] != '\0') {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "Explicit digest not supported for composite "
                       "signature operations");
        return 0;
    }
    return composite_sign_init(vctx, vkey, params);
}

static int composite_digest_sign(void *vctx, uint8_t *sig, size_t *siglen,
                                  size_t sigsize, const uint8_t *tbs,
                                  size_t tbslen)
{
    return composite_sign(vctx, sig, siglen, sigsize, tbs, tbslen);
}

static int composite_digest_verify(void *vctx, const uint8_t *sig,
                                    size_t siglen, const uint8_t *tbs,
                                    size_t tbslen)
{
    return composite_verify(vctx, sig, siglen, tbs, tbslen);
}

/*
 * Per-algorithm newctx functions and dispatch tables.
 * The alg string is stored in the context for domain separator selection.
 */
#define MAKE_COMPOSITE_FUNCTIONS(name, namestr)                                \
    static void *composite_##name##_newctx(void *provctx, const char *propq)   \
    {                                                                          \
        PROV_COMPOSITE_CTX *ctx = composite_newctx(provctx, 0, propq);        \
        if (ctx != NULL)                                                       \
            ctx->alg = namestr;                                                \
        return ctx;                                                            \
    }                                                                          \
    const OSSL_DISPATCH ossl_##name##_signature_functions[] = {               \
        { OSSL_FUNC_SIGNATURE_NEWCTX,                                          \
            (void (*)(void))composite_##name##_newctx },                       \
        { OSSL_FUNC_SIGNATURE_FREECTX,                                         \
            (void (*)(void))composite_freectx },                               \
        { OSSL_FUNC_SIGNATURE_DUPCTX,                                          \
            (void (*)(void))composite_dupctx },                                \
        { OSSL_FUNC_SIGNATURE_SIGN_INIT,                                       \
            (void (*)(void))composite_sign_init },                             \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,                               \
            (void (*)(void))composite_sign_msg_init },                         \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,                             \
            (void (*)(void))composite_signverify_msg_update },                 \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,                              \
            (void (*)(void))composite_sign_msg_final },                        \
        { OSSL_FUNC_SIGNATURE_SIGN,                                            \
            (void (*)(void))composite_sign },                                  \
        { OSSL_FUNC_SIGNATURE_VERIFY_INIT,                                     \
            (void (*)(void))composite_verify_init },                           \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,                             \
            (void (*)(void))composite_verify_msg_init },                       \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,                           \
            (void (*)(void))composite_signverify_msg_update },                 \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,                            \
            (void (*)(void))composite_verify_msg_final },                      \
        { OSSL_FUNC_SIGNATURE_VERIFY,                                          \
            (void (*)(void))composite_verify },                                \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,                                \
            (void (*)(void))composite_digest_signverify_init },                \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,                                     \
            (void (*)(void))composite_digest_sign },                           \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,                              \
            (void (*)(void))composite_digest_signverify_init },                \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,                                   \
            (void (*)(void))composite_digest_verify },                         \
        { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,                                  \
            (void (*)(void))composite_get_ctx_params },                        \
        { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,                             \
            (void (*)(void))composite_gettable_ctx_params },                   \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                                  \
            (void (*)(void))composite_set_ctx_params },                        \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                             \
            (void (*)(void))composite_settable_ctx_params },                   \
        OSSL_DISPATCH_END                                                      \
    }

MAKE_COMPOSITE_FUNCTIONS(mldsa44_rsa2048_pss_sha256,
                         "ML-DSA-44-RSA2048-PSS-SHA256");
MAKE_COMPOSITE_FUNCTIONS(mldsa44_rsa2048_pkcs15_sha256,
                         "ML-DSA-44-RSA2048-PKCS15-SHA256");
MAKE_COMPOSITE_FUNCTIONS(mldsa44_ed25519_sha512,
                         "ML-DSA-44-Ed25519-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa44_ecdsa_p256_sha256,
                         "ML-DSA-44-ECDSA-P256-SHA256");
MAKE_COMPOSITE_FUNCTIONS(mldsa65_rsa3072_pss_sha512,
                         "ML-DSA-65-RSA3072-PSS-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa65_rsa3072_pkcs15_sha512,
                         "ML-DSA-65-RSA3072-PKCS15-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa65_rsa4096_pss_sha512,
                         "ML-DSA-65-RSA4096-PSS-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa65_rsa4096_pkcs15_sha512,
                         "ML-DSA-65-RSA4096-PKCS15-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa65_ecdsa_p256_sha512,
                         "ML-DSA-65-ECDSA-P256-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa65_ecdsa_p384_sha512,
                         "ML-DSA-65-ECDSA-P384-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa65_ecdsa_brainpoolP256r1_sha512,
                         "ML-DSA-65-ECDSA-brainpoolP256r1-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa65_ed25519_sha512,
                         "ML-DSA-65-Ed25519-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa87_ecdsa_p384_sha512,
                         "ML-DSA-87-ECDSA-P384-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa87_ecdsa_brainpoolP384r1_sha512,
                         "ML-DSA-87-ECDSA-brainpoolP384r1-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa87_ed448_shake256,
                         "ML-DSA-87-Ed448-SHAKE256");
MAKE_COMPOSITE_FUNCTIONS(mldsa87_rsa3072_pss_sha512,
                         "ML-DSA-87-RSA3072-PSS-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa87_rsa4096_pss_sha512,
                         "ML-DSA-87-RSA4096-PSS-SHA512");
MAKE_COMPOSITE_FUNCTIONS(mldsa87_ecdsa_p521_sha512,
                         "ML-DSA-87-ECDSA-P521-SHA512");
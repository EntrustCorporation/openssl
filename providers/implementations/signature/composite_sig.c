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


static OSSL_FUNC_signature_sign_fn composite_sign;


typedef struct {
    OSSL_LIB_CTX *libctx;

    /* ML DSA */
    ML_DSA_KEY  *ml_dsa_key;
    int mu;


    /* CLASSIC */
    EVP_PKEY_CTX *classic_ctx;
    EVP_PKEY *keyParam;

    /* Signature, for verification */
    unsigned char *sig[2]; 
    size_t siglen;
} PROV_COMPOSITE_CTX;

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


static int composite_sign(void *vctx, uint8_t *sig, size_t *siglen, size_t sigsize,
                       const uint8_t *msg, size_t msg_len){

    PROV_COMPOSITE_CTX *ctx = (PROV_COMPOSITE_CTX *)vctx;
    int ret = 0;

    if (!ossl_prov_is_running())
        return 0;

    EVP_SignFinal();

    //ML-DSA Sign

    if (sig != NULL) {
        if (ctx->test_entropy_len != 0) {
            rnd = ctx->test_entropy;
        } else {
            rnd = rand_tmp;

            if (ctx->deterministic == 1)
                memset(rnd, 0, sizeof(rand_tmp));
            else if (RAND_priv_bytes_ex(ctx->libctx, rnd, sizeof(rand_tmp), 0) <= 0)
                return 0;
        }
    }
    ret = ossl_ml_dsa_sign(ctx->key, ctx->mu, msg, msg_len,
                           ctx->context_string, ctx->context_string_len,
                           rnd, sizeof(rand_tmp), ctx->msg_encode,
                           sig, siglen, sigsize);
    if (rnd != ctx->test_entropy)
        OPENSSL_cleanse(rand_tmp, sizeof(rand_tmp));

//

    unsigned char *buf;
    int i, ret = -1, aux = 0;
    int nid = OBJ_sn2nid(oqsxkey->tls_name);
    size_t classical_sig_len = 0, oqs_sig_len = 0;
    int comp_idx = get_composite_idx(oqsxkey->tls_name);
    if (comp_idx == -1)
        return ret;
    const unsigned char *oid_prefix = composite_OID_prefix[comp_idx - 1];
    char *final_tbs;
    CompositeSignature *compsig = CompositeSignature_new();
    size_t final_tbslen = COMPOSITE_OID_PREFIX_LEN /
                          2; // COMPOSITE_OID_PREFIX_LEN stores the size of
                             // the *char, but the prefix will be on memory,
                             // so each 2 chars will translate into one byte
    unsigned char *tbs_hash;
    OQS_SIG *oqs_key = oqsxkey->oqsx_provider_ctx.oqsx_qs_ctx.sig;
    EVP_PKEY *oqs_key_classic = NULL;
    EVP_PKEY_CTX *classical_ctx_sign = NULL;

    // prepare the pre hash
    for (i = 0; i < oqsxkey->numkeys; i++) {
        char *name;
        char *upcase_name;
        if ((name = get_cmpname(nid, i)) == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
            CompositeSignature_free(compsig);
            return ret;
        }
        upcase_name = get_oqsname_fromtls(name);

        if ((upcase_name != 0) &&
                ((!strcmp(upcase_name, OQS_SIG_alg_ml_dsa_65)) ||
                 (!strcmp(upcase_name, OQS_SIG_alg_ml_dsa_87))) ||
            (name[0] == 'e')) {
            aux = 1;
            OPENSSL_free(name);
            break;
        }
        OPENSSL_free(name);
    }
    switch (aux) {
    case 0:
        tbs_hash = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
        SHA256(tbs, tbslen, tbs_hash);
        final_tbslen += SHA256_DIGEST_LENGTH;
        break;
    case 1:
        tbs_hash = OPENSSL_malloc(SHA512_DIGEST_LENGTH);
        SHA512(tbs, tbslen, tbs_hash);
        final_tbslen += SHA512_DIGEST_LENGTH;
        break;
    default:
        ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
        CompositeSignature_free(compsig);
        return ret;
    }
    final_tbs = OPENSSL_malloc(final_tbslen);
    composite_prefix_conversion(final_tbs, oid_prefix);
    memcpy(final_tbs + COMPOSITE_OID_PREFIX_LEN / 2, tbs_hash,
           final_tbslen - COMPOSITE_OID_PREFIX_LEN / 2);
    OPENSSL_free(tbs_hash);

    // sign
    for (i = 0; i < oqsxkey->numkeys; i++) {
        char *name;
        if ((name = get_cmpname(nid, i)) == NULL) {
            ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
            CompositeSignature_free(compsig);
            OPENSSL_free(final_tbs);
            return ret;
        }

        if (get_oqsname_fromtls(name)) { // PQC signing
            oqs_sig_len =
                oqsxkey->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature;
            buf = OPENSSL_malloc(oqs_sig_len);
#if !defined OQS_VERSION_MINOR ||                                              \
    (OQS_VERSION_MAJOR == 0 && OQS_VERSION_MINOR < 12)
            if (OQS_SIG_sign(oqs_key, buf, &oqs_sig_len,
                             (const unsigned char *)final_tbs, final_tbslen,
                             oqsxkey->comp_privkey[i]) != OQS_SUCCESS) {
#else
            if (OQS_SIG_sign_with_ctx_str(
                    oqs_key, buf, &oqs_sig_len,
                    (const unsigned char *)final_tbs, final_tbslen,
                    poqs_sigctx->context_string,
                    poqs_sigctx->context_string_length,
                    oqsxkey->comp_privkey[i]) != OQS_SUCCESS) {
#endif
                ERR_raise(ERR_LIB_USER, OQSPROV_R_SIGNING_FAILED);
                CompositeSignature_free(compsig);
                OPENSSL_free(final_tbs);
                OPENSSL_free(name);
                OPENSSL_free(buf);
                return ret;
            }
        } else { // sign non PQC key on oqs_key
            oqs_key_classic = oqsxkey->classical_pkey;
            oqs_sig_len = oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                              ->length_signature;
            buf = OPENSSL_malloc(oqs_sig_len);
            const EVP_MD *classical_md;
            int digest_len;
            unsigned char digest[SHA512_DIGEST_LENGTH]; /* init with max
                                                           length */

            if (name[0] == 'e') { // ed25519 or ed448
                EVP_MD_CTX *evp_ctx = EVP_MD_CTX_new();
                if ((EVP_DigestSignInit_ex(evp_ctx, NULL, NULL, libctx, NULL,
                                           oqs_key_classic, NULL) <= 0) ||
                    (EVP_DigestSign(evp_ctx, buf, &oqs_sig_len,
                                    (const unsigned char *)final_tbs,
                                    final_tbslen) <= 0)) {
                    ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    OPENSSL_free(name);
                    EVP_MD_CTX_free(evp_ctx);
                    OPENSSL_free(buf);
                    return ret;
                }
                EVP_MD_CTX_free(evp_ctx);
            } else {
                if ((classical_ctx_sign = EVP_PKEY_CTX_new_from_pkey(
                         libctx, oqs_key_classic, NULL)) == NULL ||
                    (EVP_PKEY_sign_init(classical_ctx_sign) <= 0)) {
                    ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    OPENSSL_free(name);
                    OPENSSL_free(buf);
                    return ret;
                }

                if (!strncmp(name, "pss", 3)) {
                    int salt;
                    const EVP_MD *pss_mgf1;
                    if (!strncmp(name, "pss3072", 7)) {
                        salt = 64;
                        pss_mgf1 = EVP_sha512();
                    } else {
                        if (!strncmp(name, "pss2048", 7)) {
                            salt = 32;
                            pss_mgf1 = EVP_sha256();
                        } else {
                            ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                            CompositeSignature_free(compsig);
                            OPENSSL_free(final_tbs);
                            OPENSSL_free(name);
                            OPENSSL_free(buf);
                            return ret;
                        }
                    }
                    if ((EVP_PKEY_CTX_set_rsa_padding(
                             classical_ctx_sign, RSA_PKCS1_PSS_PADDING) <= 0) ||
                        (EVP_PKEY_CTX_set_rsa_pss_saltlen(classical_ctx_sign,
                                                          salt) <= 0) ||
                        (EVP_PKEY_CTX_set_rsa_mgf1_md(classical_ctx_sign,
                                                      pss_mgf1) <= 0)) {
                        ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                        CompositeSignature_free(compsig);
                        OPENSSL_free(final_tbs);
                        OPENSSL_free(name);
                        OPENSSL_free(buf);
                        return ret;
                    }
                } else if (oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                               ->keytype == EVP_PKEY_RSA) {
                    if (EVP_PKEY_CTX_set_rsa_padding(classical_ctx_sign,
                                                     RSA_PKCS1_PADDING) <= 0) {
                        ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                        CompositeSignature_free(compsig);
                        OPENSSL_free(final_tbs);
                        OPENSSL_free(name);
                        OPENSSL_free(buf);
                        return ret;
                    }
                }
                if (comp_idx < 6) {
                    classical_md = EVP_sha256();
                    digest_len = SHA256_DIGEST_LENGTH;
                    SHA256((const unsigned char *)final_tbs, final_tbslen,
                           (unsigned char *)&digest);
                } else {
                    classical_md = EVP_sha512();
                    digest_len = SHA512_DIGEST_LENGTH;
                    SHA512((const unsigned char *)final_tbs, final_tbslen,
                           (unsigned char *)&digest);
                }

                if ((EVP_PKEY_CTX_set_signature_md(classical_ctx_sign,
                                                   classical_md) <= 0) ||
                    (EVP_PKEY_sign(classical_ctx_sign, buf, &oqs_sig_len,
                                   digest, digest_len) <= 0)) {
                    ERR_raise(ERR_LIB_USER, ERR_R_FATAL);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    OPENSSL_free(name);
                    OPENSSL_free(buf);
                    return ret;
                }

                if (oqs_sig_len > oqsxkey->oqsx_provider_ctx.oqsx_evp_ctx
                                      ->evp_info->length_signature) {
                    /* sig is bigger than expected */
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_BUFFER_LENGTH_WRONG);
                    CompositeSignature_free(compsig);
                    OPENSSL_free(final_tbs);
                    OPENSSL_free(name);
                    OPENSSL_free(buf);
                    return ret;
                }
            }
        }

        if (i == 0) {
            compsig->sig1->data = OPENSSL_memdup(buf, oqs_sig_len);
            compsig->sig1->length = oqs_sig_len;
            compsig->sig1->flags = 8; // set as 8 to not check for unused bits
        } else {
            compsig->sig2->data = OPENSSL_memdup(buf, oqs_sig_len);
            compsig->sig2->length = oqs_sig_len;
            compsig->sig2->flags = 8; // set as 8 to not check for unused bits
        }

        OPENSSL_free(buf);
        OPENSSL_free(name);
    }
    oqs_sig_len = i2d_CompositeSignature(compsig, &sig);

    CompositeSignature_free(compsig);
    OPENSSL_free(final_tbs);
    return oqs_sig_len;
}


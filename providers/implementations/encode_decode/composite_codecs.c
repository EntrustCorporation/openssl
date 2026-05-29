/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include "crypto/ml_dsa.h"
#include "prov/composite_codecs.h"
#include "prov/ml_dsa_codecs.h"

#ifndef OPENSSL_NO_COMPOSITE

/*
 * Encode the classic sub-key public component to its raw wire format
 * (draft-ietf-lamps-pq-composite-sigs):
 *
 *   RSA:      RSAPublicKey DER (PKCS#1)
 *   EC:       Uncompressed X9.62 point 0x04||x||y
 *   Ed25519:  raw 32 bytes
 *   Ed448:    raw 57 bytes
 *
 * On success, *out is a newly-allocated buffer of *out_len bytes.
 * Caller must OPENSSL_free(*out).
 */
static int composite_encode_classic_pub(const EVP_PKEY *pkey,
                                         unsigned char **out,
                                         size_t *out_len)
{
    int keytype = EVP_PKEY_get_base_id(pkey);
    OSSL_ENCODER_CTX *ectx;
    size_t len;

    *out = NULL;
    *out_len = 0;

    if (keytype == EVP_PKEY_RSA) {
        ectx = OSSL_ENCODER_CTX_new_for_pkey(
            pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "DER", "type-specific", NULL);
        if (ectx == NULL)
            return 0;
        if (!OSSL_ENCODER_to_data(ectx, out, out_len))
            *out = NULL;
        OSSL_ENCODER_CTX_free(ectx);
    } else if (keytype == EVP_PKEY_EC) {
        /* Uncompressed point: 0x04 || x || y */
        if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                              NULL, 0, &len))
            return 0;
        *out = OPENSSL_malloc(len);
        if (*out == NULL)
            return 0;
        if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                              *out, len, out_len)) {
            OPENSSL_free(*out);
            *out = NULL;
        }
    } else if (keytype == EVP_PKEY_ED25519 || keytype == EVP_PKEY_ED448) {
        if (!EVP_PKEY_get_raw_public_key(pkey, NULL, &len))
            return 0;
        *out = OPENSSL_malloc(len);
        if (*out == NULL)
            return 0;
        if (!EVP_PKEY_get_raw_public_key(pkey, *out, &len)) {
            OPENSSL_free(*out);
            *out = NULL;
        } else {
            *out_len = len;
        }
    } else {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "unsupported classic key type %d", keytype);
        return 0;
    }

    return *out != NULL;
}

/*
 * Encode the classic sub-key private component to its raw wire format:
 *
 *   RSA:      RSAPrivateKey DER (PKCS#1)
 *   EC:       ECPrivateKey DER with NamedCurve (RFC5915)
 *   Ed25519:  raw 32 bytes
 *   Ed448:    raw 57 bytes
 *
 * On success, *out is a newly-allocated buffer of *out_len bytes.
 * Caller must OPENSSL_clear_free(*out, *out_len).
 */
static int composite_encode_classic_priv(const EVP_PKEY *pkey,
                                          unsigned char **out,
                                          size_t *out_len)
{
    int keytype = EVP_PKEY_get_base_id(pkey);
    OSSL_ENCODER_CTX *ectx;
    size_t len;

    *out = NULL;
    *out_len = 0;

    if (keytype == EVP_PKEY_RSA) {
        ectx = OSSL_ENCODER_CTX_new_for_pkey(
            pkey, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
            "DER", "type-specific", NULL);
        if (ectx == NULL)
            return 0;
        if (!OSSL_ENCODER_to_data(ectx, out, out_len))
            *out = NULL;
        OSSL_ENCODER_CTX_free(ectx);
    } else if (keytype == EVP_PKEY_EC) {
        /*
         * ECPrivateKey DER (RFC5915) with NamedCurve but WITHOUT publicKey,
         * per composite draft section 4:
         *   "The private key MUST be encoded as ECPrivateKey specified in
         *    [RFC5915] with the 'NamedCurve' parameter set to the OID of
         *    the curve, but without the 'publicKey' field."
         */
        int include_pub = 0;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
                                     &include_pub),
            OSSL_PARAM_construct_end()
        };
        EVP_PKEY *ec_copy = EVP_PKEY_dup(pkey);

        if (ec_copy == NULL)
            return 0;
        if (!EVP_PKEY_set_params(ec_copy, params)) {
            EVP_PKEY_free(ec_copy);
            return 0;
        }
        ectx = OSSL_ENCODER_CTX_new_for_pkey(
            ec_copy, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
            "DER", "type-specific", NULL);
        if (ectx != NULL) {
            if (!OSSL_ENCODER_to_data(ectx, out, out_len))
                *out = NULL;
            OSSL_ENCODER_CTX_free(ectx);
        }
        EVP_PKEY_free(ec_copy);
    } else if (keytype == EVP_PKEY_ED25519 || keytype == EVP_PKEY_ED448) {
        if (!EVP_PKEY_get_raw_private_key(pkey, NULL, &len))
            return 0;
        *out = OPENSSL_malloc(len);
        if (*out == NULL)
            return 0;
        if (!EVP_PKEY_get_raw_private_key(pkey, *out, &len)) {
            OPENSSL_clear_free(*out, len);
            *out = NULL;
        } else {
            *out_len = len;
        }
    } else {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
                       "unsupported classic key type %d", keytype);
        return 0;
    }

    return *out != NULL;
}

/*
 * Encode the composite public key: mldsaPK || tradPK
 * Returns total byte length (>0) on success, 0 on error.
 * If |out| is NULL, only the length is computed (no allocation).
 */
int ossl_composite_i2d_pubkey(const COMPOSITE_KEY *key, unsigned char **out)
{
    const ML_DSA_PARAMS *kp;
    const uint8_t *ml_dsa_pub;
    unsigned char *classic_pub = NULL;
    size_t classic_pub_len = 0;
    int total, ret = 0;

    if (key == NULL || key->classic_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        return 0;
    }

    kp = ossl_ml_dsa_key_params(key->ml_dsa_key);
    ml_dsa_pub = ossl_ml_dsa_key_get_pub(key->ml_dsa_key);
    if (ml_dsa_pub == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        return 0;
    }

    if (!composite_encode_classic_pub(key->classic_key,
                                      &classic_pub, &classic_pub_len))
        return 0;

    total = (int)(kp->pk_len + classic_pub_len);

    if (out != NULL) {
        *out = OPENSSL_malloc((size_t)total);
        if (*out == NULL)
            goto done;
        memcpy(*out, ml_dsa_pub, kp->pk_len);
        memcpy(*out + kp->pk_len, classic_pub, classic_pub_len);
    }

    ret = total;
done:
    OPENSSL_free(classic_pub);
    return ret;
}

/*
 * Encode the composite private key: mldsaSeed[32] || tradSK
 * Returns total byte length (>0) on success, 0 on error.
 * If |out| is NULL, only the length is computed (no allocation).
 */
int ossl_composite_i2d_prvkey(const COMPOSITE_KEY *key, unsigned char **out)
{
    const uint8_t *seed;
    unsigned char *classic_priv = NULL;
    size_t classic_priv_len = 0;
    int total, ret = 0;

    if (key == NULL || key->classic_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }

    seed = ossl_ml_dsa_key_get_seed(key->ml_dsa_key);
    if (seed == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }

    if (!composite_encode_classic_priv(key->classic_key,
                                       &classic_priv, &classic_priv_len))
        return 0;

    total = (int)(ML_DSA_SEED_BYTES + classic_priv_len);

    if (out != NULL) {
        *out = OPENSSL_malloc((size_t)total);
        if (*out == NULL)
            goto done;
        memcpy(*out, seed, ML_DSA_SEED_BYTES);
        memcpy(*out + ML_DSA_SEED_BYTES, classic_priv, classic_priv_len);
    }

    ret = total;
done:
    OPENSSL_clear_free(classic_priv, classic_priv_len);
    return ret;
}

/*
 * Print a human-readable description of a composite key to |out|.
 */
int ossl_composite_key_to_text(BIO *out, const COMPOSITE_KEY *key,
                                int selection)
{
    const ML_DSA_PARAMS *kp;
    int is_priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    int ret = 0;

    if (out == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    kp = ossl_ml_dsa_key_params(key->ml_dsa_key);

    if (BIO_printf(out, "Composite %s Key (%s)\n",
                   is_priv ? "Private" : "Public",
                   kp != NULL ? kp->alg : "unknown") <= 0)
        return 0;

    /* ML-DSA component */
    if (BIO_printf(out, "ML-DSA component:\n") <= 0)
        return 0;
    if (!ossl_ml_dsa_key_to_text(out, key->ml_dsa_key, selection))
        return 0;

    /* Classic component */
    if (BIO_printf(out, "Classic component:\n") <= 0)
        return 0;
    if (key->classic_key == NULL) {
        if (BIO_printf(out, "    (none)\n") <= 0)
            return 0;
    } else {
        if (is_priv)
            ret = EVP_PKEY_print_private(out, key->classic_key, 4, NULL);
        else
            ret = EVP_PKEY_print_public(out, key->classic_key, 4, NULL);
        if (ret <= 0)
            return 0;
    }

    return 1;
}

#endif /* OPENSSL_NO_COMPOSITE */

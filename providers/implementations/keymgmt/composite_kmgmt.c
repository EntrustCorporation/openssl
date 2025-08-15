/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/proverr.h>
#include <openssl/self_test.h>
#include "crypto/ml_dsa.h"
#include "internal/fips.h"
#include "internal/param_build_set.h"
#include "internal/param_names.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/ml_dsa.h"
#include "prov/composite.h"

COMPOSITE_KEY *ossl_prov_composite_new(PROV_CTX *ctx, const char *propq, int evp_type)
{
    ML_DSA_KEY *key;

    if (!ossl_prov_is_running())
        return 0;

    key = ossl_ml_dsa_key_new(PROV_LIBCTX_OF(ctx), propq, evp_type);
    /*
     * When decoding, if the key ends up "loaded" into the same provider, these
     * are the correct config settings, otherwise, new values will be assigned
     * on import into a different provider.  The "load" API does not pass along
     * the provider context.
     */
    if (key != NULL) {
        int flags_set = 0, flags_clr = 0;

        if (ossl_prov_ctx_get_bool_param(
                ctx, OSSL_PKEY_PARAM_ML_DSA_RETAIN_SEED, 1))
            flags_set |= ML_DSA_KEY_RETAIN_SEED;
        else
            flags_clr = ML_DSA_KEY_RETAIN_SEED;

        if (ossl_prov_ctx_get_bool_param(
                ctx, OSSL_PKEY_PARAM_ML_DSA_PREFER_SEED, 1))
            flags_set |= ML_DSA_KEY_PREFER_SEED;
        else
            flags_clr |= ML_DSA_KEY_PREFER_SEED;

        ossl_ml_dsa_set_prekey(key, flags_set, flags_clr, NULL, 0, NULL, 0);
    }
    return key;
}
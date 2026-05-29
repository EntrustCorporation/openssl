/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef PROV_COMPOSITE_CODECS_H
# define PROV_COMPOSITE_CODECS_H
# pragma once

# ifndef OPENSSL_NO_COMPOSITE
#  include <openssl/bio.h>
#  include <openssl/e_os2.h>
#  include "prov/composite.h"

/*
 * Encode the composite public key (mldsaPK || tradPK) into *out.
 * Returns the total byte length on success, 0 on error.
 * If out is NULL, only the length is returned (no allocation).
 */
__owur int ossl_composite_i2d_pubkey(const COMPOSITE_KEY *key,
                                     unsigned char **out);

/*
 * Encode the composite private key (mldsaSeed[32] || tradSK) into *out.
 * Returns the total byte length on success, 0 on error.
 * If out is NULL, only the length is returned (no allocation).
 */
__owur int ossl_composite_i2d_prvkey(const COMPOSITE_KEY *key,
                                     unsigned char **out);

/*
 * Print a human-readable description of the composite key to |out|.
 * |selection| is an OSSL_KEYMGMT_SELECT_* mask.
 */
__owur int ossl_composite_key_to_text(BIO *out, const COMPOSITE_KEY *key,
                                      int selection);

# endif /* OPENSSL_NO_COMPOSITE */
#endif /* PROV_COMPOSITE_CODECS_H */

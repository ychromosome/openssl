/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_TEST_TLS_PROVIDER_H)
#define OSSL_TEST_TLS_PROVIDER_H

#include <openssl/params.h>
#include <openssl/provider.h>

int tls_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx);

static ossl_inline OSSL_PROVIDER *tls_provider_load(OSSL_LIB_CTX *ctx,
    const char *name, const char *mode)
{
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("tls-ciphersuite-mode", (char *)mode, 0),
        OSSL_PARAM_END
    };

    return OSSL_PROVIDER_load_ex(ctx, name, params);
}

#endif /* !defined(OSSL_TEST_TLS_PROVIDER_H) */

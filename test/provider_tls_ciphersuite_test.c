/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"

int tls_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx);
void tls_provider_set_ciphersuite_mode(const char *mode);

typedef struct {
    const char *mode;
    int expect_success;
    int expected_count;
} CIPHERSUITE_TEST;

static const CIPHERSUITE_TEST ciphersuite_tests[] = {
    { "unsupported", 1, 0 },
    { "empty", 1, 0 },
    { "valid", 1, 1 },
    { "valid-unknown-param", 1, 1 },
    { "valid-two", 1, 2 },
    { "bad-name", 0, 0 },
    { "builtin-name", 0, 0 },
    { "zero-codepoint", 0, 0 },
    { "grease-codepoint", 0, 0 },
    { "builtin-codepoint", 0, 0 },
    { "non-aead", 0, 0 },
    { "ccm", 0, 0 },
    { "unavailable-aead", 0, 0 },
    { "oversized-key", 0, 0 },
    { "bad-digest", 0, 0 },
    { "low-security", 0, 0 },
    { "excess-security", 0, 0 },
    { "missing-param", 0, 0 },
    { "wrong-type", 0, 0 },
    { "duplicate-descriptor", 0, 0 },
    { "valid-then-invalid", 0, 0 },
    { "valid-then-abort", 0, 0 }
};

static OSSL_LIB_CTX *libctx;
static OSSL_PROVIDER *defprov, *tlsprov;
static char *cert, *privkey;

#define TLS_TEST_SHA256_NAME "TLS_TEST_PROVIDER_AES_128_GCM_SHA256"
#define TLS_TEST_SHA384_NAME "TLS_TEST_PROVIDER_AES_256_GCM_SHA384"
#define TLS_TEST_OVERSIZED_AEAD_NAME "TLS-TEST-AEAD-65"

static int test_oversized_aead_fixture(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx,
                      TLS_TEST_OVERSIZED_AEAD_NAME, "provider=tls-provider"))
        || !TEST_int_eq(EVP_CIPHER_get_key_length(cipher),
            EVP_MAX_KEY_LENGTH + 1)
        || !TEST_int_eq(EVP_CIPHER_get_block_size(cipher), 1)
        || !TEST_int_eq(EVP_CIPHER_get_iv_length(cipher), 12)
        || !TEST_true((EVP_CIPHER_get_flags(cipher)
                          & EVP_CIPH_FLAG_AEAD_CIPHER)
            != 0)
        || !TEST_int_eq(EVP_CIPHER_get_mode(cipher), EVP_CIPH_GCM_MODE)
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL))
        || !TEST_int_eq(EVP_CIPHER_CTX_get_tag_length(ctx),
            EVP_GCM_TLS_TAG_LEN))
        goto end;

    ret = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

static void count_server_hellos_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    int *count = arg;
    const unsigned char *msg = buf;

    if (!write_p && content_type == SSL3_RT_HANDSHAKE && len > 0
        && msg[0] == SSL3_MT_SERVER_HELLO)
        (*count)++;
}

typedef struct {
    SSL_CTX *first;
    SSL_CTX *second;
    int set_ciphersuites;
    int set_cipher_list;
    int calls;
} SNI_SWITCH_DATA;

static int sni_switch_cb(SSL *ssl, int *alert, void *arg)
{
    SNI_SWITCH_DATA *data = arg;

    data->calls++;
    if (SSL_set_SSL_CTX(ssl, data->first) == NULL
        || (data->set_ciphersuites
            && !SSL_set_ciphersuites(ssl, TLS_TEST_SHA256_NAME))
        || (data->set_cipher_list
            && !SSL_set_cipher_list(ssl, "DEFAULT"))
        || (data->second != NULL
            && SSL_set_SSL_CTX(ssl, data->second) == NULL)
        || (data->set_ciphersuites && data->second != NULL
            && !SSL_set_ciphersuites(ssl, TLS_TEST_SHA256_NAME))) {
        *alert = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    SSL_CTX_free(data->first);
    data->first = NULL;
    if (data->second != NULL) {
        SSL_CTX_free(data->second);
        data->second = NULL;
    }
    return SSL_TLSEXT_ERR_OK;
}

static int check_valid_suite(const SSL_CIPHER *suite, int index)
{
    if (!TEST_ptr(suite)
        || !TEST_int_eq(suite->origin, SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_uint_eq(suite->id,
            SSL3_CK_CIPHERSUITE_FLAG | (0xfea0U + (unsigned int)index))
        || !TEST_int_eq(suite->min_tls, TLS1_3_VERSION)
        || !TEST_int_eq(suite->max_tls, TLS1_3_VERSION)
        || !TEST_int_eq(suite->min_dtls, 0)
        || !TEST_int_eq(suite->max_dtls, 0)
        || !TEST_true((suite->algo_strength & SSL_NOT_DEFAULT) != 0)
        || !TEST_int_eq(suite->strength_bits, 128)
        || !TEST_uint_eq(suite->alg_bits, 128)
        || !TEST_ptr(suite->provider_cipher)
        || !TEST_ptr(suite->provider_digest))
        return 0;

    return 1;
}

static int test_ciphersuite_mode(int idx)
{
    const CIPHERSUITE_TEST *test = &ciphersuite_tests[idx];
    SSL_CTX *ctx = NULL;
    int i, ret = 0;

    tls_provider_set_ciphersuite_mode(test->mode);
    ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method());
    if (test->expect_success) {
        if (!TEST_ptr(ctx)
            || !TEST_int_eq(sk_SSL_CIPHER_num(ctx->provider_ciphersuites),
                test->expected_count))
            goto end;
        for (i = 0; i < test->expected_count; i++) {
            if (!check_valid_suite(
                    sk_SSL_CIPHER_value(ctx->provider_ciphersuites, i), i))
                goto end;
        }
        for (i = 0; i < sk_SSL_CIPHER_num(ctx->tls13_ciphersuites); i++) {
            if (!TEST_int_ne(sk_SSL_CIPHER_value(ctx->tls13_ciphersuites, i)->origin,
                    SSL_CIPHER_ORIGIN_PROVIDER))
                goto end;
        }
    } else if (!TEST_ptr_null(ctx)) {
        goto end;
    }

    ret = 1;
end:
    ERR_clear_error();
    SSL_CTX_free(ctx);
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_provider_handshake(int idx)
{
    const char *mode = idx == 0 ? "valid" : "valid-sha384";
    const char *name = idx == 0 ? TLS_TEST_SHA256_NAME : TLS_TEST_SHA384_NAME;
    const char *digest_name = idx == 0 ? "SHA2-256" : "SHA2-384";
    const char *cipher_name = idx == 0 ? "AES-128-GCM" : "AES-256-GCM";
    int cipher_nid = idx == 0 ? NID_aes_128_gcm : NID_aes_256_gcm;
    int digest_nid = idx == 0 ? NID_sha256 : NID_sha384;
    unsigned int codepoint = idx == 0 ? 0xfea0U : 0xfea2U;
    unsigned char wire_id[] = {
        (unsigned char)(codepoint >> 8), (unsigned char)codepoint
    };
    static const unsigned char message[] = "provider ciphersuite record";
    unsigned char received[sizeof(message)];
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const SSL_CIPHER *client_cipher, *server_cipher;
    char description[256];
    size_t written = 0, readbytes = 0;
    int ret = 0;

    tls_provider_set_ciphersuite_mode(mode);
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, name))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, name))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_ptr(client_cipher = SSL_CIPHER_find(clientssl, wire_id))
        || !TEST_uint_eq(SSL_CIPHER_get_protocol_id(client_cipher), codepoint)
        || !TEST_int_eq(SSL_CIPHER_get_cipher_nid(client_cipher), cipher_nid)
        || !TEST_int_eq(SSL_CIPHER_get_digest_nid(client_cipher), digest_nid)
        || !TEST_true(SSL_CIPHER_is_aead(client_cipher))
        || !TEST_true(EVP_MD_is_a(SSL_CIPHER_get_handshake_digest(client_cipher),
            digest_name))
        || !TEST_ptr(SSL_CIPHER_description(client_cipher, description,
            sizeof(description)))
        || !TEST_ptr(strstr(description, cipher_name))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    client_cipher = SSL_get_current_cipher(clientssl);
    server_cipher = SSL_get_current_cipher(serverssl);
    if (!TEST_ptr(client_cipher)
        || !TEST_ptr(server_cipher)
        || !TEST_uint_eq(SSL_CIPHER_get_protocol_id(client_cipher), codepoint)
        || !TEST_uint_eq(SSL_CIPHER_get_protocol_id(server_cipher), codepoint)
        || !TEST_int_eq(client_cipher->origin, SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_int_eq(server_cipher->origin, SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_true(SSL_write_ex(clientssl, message, sizeof(message), &written))
        || !TEST_size_t_eq(written, sizeof(message))
        || !TEST_true(SSL_read_ex(serverssl, received, sizeof(received),
            &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(message))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message)))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_provider_hrr(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const SSL_CIPHER *cipher;
    int server_hellos = 0, ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        /* Group lists from tls13groupselection_test. */
        || !TEST_true(SSL_CTX_set1_groups_list(cctx,
            "secp521r1:secp384r1:X25519:prime256v1:X448"))
        || !TEST_true(SSL_CTX_set1_groups_list(sctx,
            "X25519:secp384r1:prime256v1"))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    SSL_set_msg_callback_arg(clientssl, &server_hellos);
    SSL_set_msg_callback(clientssl, count_server_hellos_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_int_eq(server_hellos, 2)
        || !TEST_ptr(cipher = SSL_get_current_cipher(clientssl))
        || !TEST_int_eq(cipher->origin, SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_sni_context_switch(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const SSL_CIPHER *expected = NULL, *negotiated;
    SNI_SWITCH_DATA data = { 0 };
    int ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_ptr(expected = ssl_provider_ciphersuite_by_id(sctx,
                         SSL3_CK_CIPHERSUITE_FLAG | 0xfea0U)))
        goto end;

    if (idx != 1) {
        data.set_ciphersuites = 1;
        data.set_cipher_list = idx == 0;
        if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(), NULL,
                TLS1_3_VERSION, TLS1_3_VERSION, &data.first, NULL,
                cert, privkey))
            || !TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(), NULL,
                TLS1_3_VERSION, TLS1_3_VERSION, &data.second, NULL,
                cert, privkey))
            || !TEST_true(SSL_CTX_set_ciphersuites(data.first,
                TLS_TEST_SHA256_NAME))
            || !TEST_true(SSL_CTX_set_ciphersuites(data.second,
                TLS_TEST_SHA256_NAME)))
            goto end;
    } else {
        tls_provider_set_ciphersuite_mode("unsupported");
        if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(), NULL,
                TLS1_3_VERSION, TLS1_3_VERSION, &data.first, NULL,
                cert, privkey))
            || !TEST_int_eq(sk_SSL_CIPHER_num(
                                data.first->provider_ciphersuites),
                0)
            /* Trigger HRR after the context switch. */
            || !TEST_true(SSL_CTX_set1_groups_list(cctx,
                "secp521r1:secp384r1:X25519:prime256v1:X448"))
            || !TEST_true(SSL_CTX_set1_groups_list(sctx,
                "X25519:secp384r1:prime256v1")))
            goto end;
    }

    if (!TEST_true(SSL_CTX_set_tlsext_servername_callback(sctx,
            sni_switch_cb))
        || !TEST_true(SSL_CTX_set_tlsext_servername_arg(sctx, &data))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_tlsext_host_name(clientssl,
            "provider.example")))
        goto end;

    SSL_CTX_free(sctx);
    sctx = NULL;
    SSL_CTX_free(cctx);
    cctx = NULL;

    if (idx != 1) {
        if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                SSL_ERROR_NONE))
            || !TEST_int_eq(data.calls, 1)
            || !TEST_ptr(negotiated = SSL_get_current_cipher(serverssl))
            || !TEST_ptr_eq(negotiated, expected))
            goto end;
    } else if (!TEST_false(create_ssl_connection(serverssl, clientssl,
                   SSL_ERROR_NONE))
        || !TEST_int_eq(data.calls, 1)) {
        goto end;
    }

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(data.first);
    SSL_CTX_free(data.second);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_ssl_dup_canonicalisation(void)
{
    SSL_CTX *sctx = NULL, *altctx = NULL, *cctx = NULL;
    SSL *original = NULL, *serverssl = NULL, *clientssl = NULL;
    SSL_CONNECTION *sc;
    const SSL_CIPHER *alt_suite, *negotiated;
    int idx, ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(), NULL,
            TLS1_3_VERSION, TLS1_3_VERSION, &altctx, NULL, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(altctx, 0))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(altctx,
            TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_ptr(alt_suite = ssl_provider_ciphersuite_by_id(altctx,
                         SSL3_CK_CIPHERSUITE_FLAG | 0xfea0U))
        || !TEST_ptr(original = SSL_new(sctx))
        || !TEST_ptr(SSL_set_SSL_CTX(original, altctx))
        || !TEST_true(SSL_set_ciphersuites(original, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_set_cipher_list(original, "DEFAULT"))
        || !TEST_ptr(serverssl = SSL_dup(original))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL_ONLY(serverssl))
        || !TEST_int_ge(idx = ssl_cipher_stack_find(sc->cipher_list,
                            alt_suite),
            0)
        || !TEST_ptr_eq(sk_SSL_CIPHER_value(sc->cipher_list, idx), alt_suite)
        || !TEST_true(create_ssl_objects(NULL, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    SSL_free(original);
    original = NULL;
    SSL_CTX_free(sctx);
    sctx = NULL;
    SSL_CTX_free(altctx);
    altctx = NULL;
    SSL_CTX_free(cctx);
    cctx = NULL;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_ptr(negotiated = SSL_get_current_cipher(serverssl))
        || !TEST_ptr_eq(negotiated, alt_suite))
        goto end;

    ret = 1;
end:
    SSL_free(original);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(altctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_one_sided_offer(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx,
            "TLS_AES_128_GCM_SHA256"))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_false(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_tls12_exclusion(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const SSL_CIPHER *cipher;
    int ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_2_VERSION, TLS1_2_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(cipher = SSL_get_current_cipher(clientssl))
        || !TEST_int_ne(cipher->origin, SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_quic_exclusion(void)
{
#ifndef OPENSSL_NO_QUIC
    static const unsigned char wire_id[] = { 0xfe, 0xa0 };
    SSL_CTX *ctx = NULL;
    SSL *quic = NULL;
    int ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL,
                      OSSL_QUIC_client_method()))
        || !TEST_int_eq(sk_SSL_CIPHER_num(ctx->provider_ciphersuites), 1)
        || !TEST_true(SSL_CTX_set_ciphersuites(ctx, TLS_TEST_SHA256_NAME))
        || !TEST_ptr(quic = SSL_new(ctx))
        || !TEST_ptr_null(SSL_CIPHER_find(quic, wire_id)))
        goto end;

    ret = 1;
end:
    SSL_free(quic);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
#else
    return TEST_skip("QUIC is disabled");
#endif
}

static int test_provider_unload_lifetime(void)
{
    static const unsigned char message[] = "provider unloaded";
    unsigned char received[sizeof(message)];
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    size_t written = 0, readbytes = 0;
    int ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(OSSL_PROVIDER_unload(tlsprov)))
        goto end;
    tlsprov = NULL;

    SSL_CTX_free(sctx);
    sctx = NULL;
    SSL_CTX_free(cctx);
    cctx = NULL;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_true(SSL_write_ex(clientssl, message, sizeof(message),
            &written))
        || !TEST_size_t_eq(written, sizeof(message))
        || !TEST_true(SSL_read_ex(serverssl, received, sizeof(received),
            &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(message))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message)))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()
        || !TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1))
        || !TEST_ptr(libctx = OSSL_LIB_CTX_new())
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "tls-provider",
            tls_provider_init))
        || !TEST_ptr(defprov = OSSL_PROVIDER_load(libctx, "default"))
        || !TEST_ptr(tlsprov = OSSL_PROVIDER_load(libctx, "tls-provider")))
        return 0;

    ADD_TEST(test_oversized_aead_fixture);
    ADD_ALL_TESTS(test_ciphersuite_mode, OSSL_NELEM(ciphersuite_tests));
    ADD_ALL_TESTS(test_provider_handshake, 2);
    ADD_TEST(test_provider_hrr);
    ADD_ALL_TESTS(test_sni_context_switch, 3);
    ADD_TEST(test_ssl_dup_canonicalisation);
    ADD_TEST(test_one_sided_offer);
    ADD_TEST(test_tls12_exclusion);
    ADD_TEST(test_quic_exclusion);
    /* Must remain last because it unloads tlsprov. */
    ADD_TEST(test_provider_unload_lifetime);
    return 1;
}

void cleanup_tests(void)
{
    if (tlsprov != NULL)
        OSSL_PROVIDER_unload(tlsprov);
    OSSL_PROVIDER_unload(defprov);
    OSSL_LIB_CTX_free(libctx);
}

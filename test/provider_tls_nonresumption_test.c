/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

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

#define TLS_TEST_CIPHERSUITE "TLS_TEST_PROVIDER_AES_128_GCM_SHA256"

static OSSL_LIB_CTX *libctx;
static OSSL_PROVIDER *defprov, *tlsprov;
static char *cert, *privkey;
static int nst_written, nst_read, new_session_calls;

static const unsigned char builtin_ciphersuite_id[] = { 0x13, 0x01 };
static const unsigned char test_session_id[] = { 0x01 };

static void ticket_msg_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    const unsigned char *msg = buf;

    if (content_type != SSL3_RT_HANDSHAKE || len == 0
        || msg[0] != SSL3_MT_NEWSESSION_TICKET)
        return;
    if (write_p)
        nst_written++;
    else
        nst_read++;
}

static int new_session_cb(SSL *ssl, SSL_SESSION *session)
{
    new_session_calls++;
    return 0;
}

static int check_provider_session_error(int result)
{
    unsigned long err = ERR_peek_last_error();
    int ret = TEST_false(result)
        && TEST_int_eq(ERR_GET_LIB(err), ERR_LIB_SSL)
        && TEST_int_eq(ERR_GET_REASON(err),
            SSL_R_PROVIDER_CIPHERSUITE_SESSION_UNSUPPORTED);

    ERR_clear_error();
    return ret;
}

static int make_ctx_pair(const char *mode, const char *ciphersuite,
    int tickets, SSL_CTX **sctx, SSL_CTX **cctx)
{
    tls_provider_set_ciphersuite_mode(mode);
    return create_ssl_ctx_pair(libctx, TLS_server_method(), TLS_client_method(),
               TLS1_3_VERSION, TLS1_3_VERSION, sctx, cctx, cert, privkey)
        && SSL_CTX_set_num_tickets(*sctx, tickets)
        && SSL_CTX_set_ciphersuites(*sctx, ciphersuite)
        && SSL_CTX_set_ciphersuites(*cctx, ciphersuite);
}

static int test_builtin_nonresumable_serialises(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *session = NULL;
    int ret = 0;

    nst_written = nst_read = 0;
    if (!TEST_true(make_ctx_pair("unsupported", "TLS_AES_128_GCM_SHA256", 1,
            &sctx, &cctx))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;
    SSL_set_msg_callback(serverssl, ticket_msg_cb);
    SSL_set_msg_callback(clientssl, ticket_msg_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_int_gt(nst_written, 0)
        || !TEST_int_gt(nst_read, 0)
        || !TEST_ptr(session = SSL_get1_session(clientssl))
        || !TEST_false(session->provider_cipher_seen))
        goto end;

    session->not_resumable = 1;
    if (!TEST_int_gt(i2d_SSL_SESSION(session, NULL), 0))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(session);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_provider_nonresumption_gates(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL, *probe = NULL;
    SSL_SESSION *server_session = NULL, *client_session = NULL;
    SSL_SESSION *public_dup = NULL, *internal_dup = NULL;
    const SSL_CIPHER *builtin = NULL;
    int ret = 0;

    nst_written = nst_read = new_session_calls = 0;
    if (!TEST_true(make_ctx_pair("valid", TLS_TEST_CIPHERSUITE, 2,
            &sctx, &cctx)))
        goto end;
    SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    if (!TEST_long_eq(SSL_CTX_get_session_cache_mode(sctx),
            SSL_SESS_CACHE_SERVER)
        || !TEST_long_eq(SSL_CTX_get_session_cache_mode(cctx),
            SSL_SESS_CACHE_CLIENT)
        || !TEST_true(SSL_CTX_set_max_early_data(sctx, 1024))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;
    SSL_CTX_sess_set_new_cb(sctx, new_session_cb);
    SSL_CTX_sess_set_new_cb(cctx, new_session_cb);
    SSL_set_msg_callback(serverssl, ticket_msg_cb);
    SSL_set_msg_callback(clientssl, ticket_msg_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_int_eq(nst_written, 0)
        || !TEST_int_eq(nst_read, 0)
        || !TEST_int_eq(new_session_calls, 0)
        || !TEST_long_eq(SSL_CTX_sess_number(sctx), 0)
        || !TEST_long_eq(SSL_CTX_sess_number(cctx), 0)
        || !TEST_ptr(server_session = SSL_get1_session(serverssl))
        || !TEST_ptr(client_session = SSL_get1_session(clientssl))
        || !TEST_true(server_session->provider_cipher_seen)
        || !TEST_true(client_session->provider_cipher_seen)
        || !TEST_false(SSL_SESSION_is_resumable(client_session))
        || !TEST_true(check_provider_session_error(
            SSL_new_session_ticket(serverssl)))
        || !TEST_true(check_provider_session_error(
            i2d_SSL_SESSION(client_session, NULL)))
        || !TEST_true(check_provider_session_error(
            SSL_CTX_add_session(cctx, client_session)))
        || !TEST_ptr(probe = SSL_new(cctx))
        || !TEST_true(check_provider_session_error(
            SSL_set_session(probe, client_session)))
        || !TEST_ptr_null(SSL_get_session(probe))
        || !TEST_ptr(public_dup = SSL_SESSION_dup(client_session))
        || !TEST_true(public_dup->provider_cipher_seen)
        || !TEST_ptr(internal_dup = ssl_session_dup(client_session, 1))
        || !TEST_true(internal_dup->provider_cipher_seen)
        || !TEST_false(internal_dup->not_resumable)
        || !TEST_true(SSL_SESSION_set1_id(internal_dup, test_session_id,
            sizeof(test_session_id)))
        || !TEST_false(SSL_SESSION_is_resumable(internal_dup))
        || !TEST_ptr(builtin = SSL_CIPHER_find(probe, builtin_ciphersuite_id))
        || !TEST_true(SSL_SESSION_set_cipher(internal_dup, builtin))
        || !TEST_true(internal_dup->provider_cipher_seen)
        || !TEST_false(SSL_SESSION_is_resumable(internal_dup))
        || !TEST_true(check_provider_session_error(
            i2d_SSL_SESSION(internal_dup, NULL)))
        || !TEST_true(check_provider_session_error(
            SSL_set_session(probe, internal_dup)))
        || !TEST_true(check_provider_session_error(
            SSL_CTX_add_session(cctx, internal_dup)))
        || !TEST_long_eq(SSL_CTX_sess_number(cctx), 0))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(server_session);
    SSL_SESSION_free(client_session);
    SSL_SESSION_free(public_dup);
    SSL_SESSION_free(internal_dup);
    SSL_free(probe);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_injected_ticket_preserves_marker(void)
{
    static const unsigned char message[] = { 0x42 };
    unsigned char received[sizeof(message)];
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL, *probe = NULL;
    SSL_CONNECTION *serverconn;
    SSL_SESSION *client_session = NULL;
    const SSL_CIPHER *builtin;
    size_t written = 0, readbytes = 0;
    int ret = 0;

    nst_written = nst_read = new_session_calls = 0;
    if (!TEST_true(make_ctx_pair("valid", TLS_TEST_CIPHERSUITE, 0,
            &sctx, &cctx)))
        goto end;
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    if (!TEST_long_eq(SSL_CTX_get_session_cache_mode(cctx),
            SSL_SESS_CACHE_CLIENT)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_ptr(serverconn = SSL_CONNECTION_FROM_SSL_ONLY(serverssl)))
        goto end;
    SSL_CTX_sess_set_new_cb(cctx, new_session_cb);
    SSL_set_msg_callback(serverssl, ticket_msg_cb);
    SSL_set_msg_callback(clientssl, ticket_msg_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_int_eq(nst_written, 0)
        || !TEST_int_eq(nst_read, 0)
        || !TEST_ptr(builtin = SSL_CIPHER_find(serverssl,
                         builtin_ciphersuite_id))
        || !TEST_true(ssl_session_set_cipher(serverconn->session, builtin)))
        goto end;

    /* Inject a ticket from a non-conforming peer. */
    serverconn->session->provider_cipher_seen = 0;
    serverconn->session->not_resumable = 0;
    nst_written = nst_read = new_session_calls = 0;
    if (!TEST_true(SSL_new_session_ticket(serverssl))
        || !TEST_true(SSL_write_ex(serverssl, message, sizeof(message),
            &written))
        || !TEST_size_t_eq(written, sizeof(message)))
        goto end;
    if (!TEST_true(SSL_read_ex(clientssl, received, sizeof(received),
            &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(received))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message))
        || !TEST_int_eq(nst_written, 1)
        || !TEST_int_eq(nst_read, 1)
        || !TEST_ptr(client_session = SSL_get1_session(clientssl))
        || !TEST_true(client_session->provider_cipher_seen)
        || !TEST_true(client_session->not_resumable)
        || !TEST_size_t_eq(client_session->ext.ticklen, 0)
        || !TEST_false(SSL_SESSION_is_resumable(client_session))
        || !TEST_int_eq(new_session_calls, 0)
        || !TEST_long_eq(SSL_CTX_sess_number(cctx), 0)
        || !TEST_true(check_provider_session_error(
            i2d_SSL_SESSION(client_session, NULL)))
        || !TEST_true(check_provider_session_error(
            SSL_CTX_add_session(cctx, client_session)))
        || !TEST_ptr(probe = SSL_new(cctx))
        || !TEST_true(check_provider_session_error(
            SSL_set_session(probe, client_session)))
        || !TEST_int_ge(SSL_shutdown(clientssl), 0)
        || !TEST_int_ge(SSL_shutdown(serverssl), 0)
        || !TEST_int_ge(SSL_shutdown(clientssl), 0)
        || !TEST_true(SSL_clear(clientssl))
        || !TEST_ptr_null(SSL_get_session(clientssl)))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(client_session);
    SSL_free(probe);
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
        || !TEST_ptr(tlsprov = OSSL_PROVIDER_load(libctx, "tls-provider"))
        || !TEST_true(EVP_set_default_properties(libctx,
            "?provider=tls-provider")))
        return 0;

    ADD_TEST(test_builtin_nonresumable_serialises);
    ADD_TEST(test_provider_nonresumption_gates);
    ADD_TEST(test_injected_ticket_preserves_marker);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(tlsprov);
    OSSL_PROVIDER_unload(defprov);
    OSSL_LIB_CTX_free(libctx);
}

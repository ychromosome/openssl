/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "helpers/ssltestlib.h"
#include "internal/ktls.h"
#include "testutil.h"
#include "threadstest.h"

int tls_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx);
void tls_provider_set_ciphersuite_mode(const char *mode);

#define PROV_SHA256_NAME "TLS_TEST_PROVIDER_AES_128_GCM_SHA256"
#define PROV_SHA384_NAME "TLS_TEST_PROVIDER_AES_256_GCM_SHA384"
#define BUILTIN_SHA256_NAME "TLS_AES_128_GCM_SHA256"
#define BUILTIN_SHA384_NAME "TLS_AES_256_GCM_SHA384"
#define PROV_SHA256_CP 0xffa0U
#define PROV_SHA384_CP 0xffa2U

static OSSL_LIB_CTX *libctx;
static OSSL_PROVIDER *defprov, *tlsprov;
static char *cert, *privkey, *ecdsacert, *ecdsakey;

typedef struct {
    const char *mode;
    const char *provname;
    const char *builtinname;
    unsigned int codepoint;
    size_t mdsize;
} SUITE_VARIANT;

static const SUITE_VARIANT variants[] = {
    { "valid", PROV_SHA256_NAME, BUILTIN_SHA256_NAME, PROV_SHA256_CP,
        SHA256_DIGEST_LENGTH },
    { "valid-sha384", PROV_SHA384_NAME, BUILTIN_SHA384_NAME, PROV_SHA384_CP,
        SHA384_DIGEST_LENGTH }
};

static int nst_written, server_hellos;
static unsigned char ch_ciphers[512];
static size_t ch_cipherslen;
static unsigned int sh_cipher;

static void wire_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    const unsigned char *m = buf, *p, *end;
    size_t clen;

    if (content_type != SSL3_RT_HANDSHAKE || len < SSL3_HM_HEADER_LENGTH)
        return;
    end = m + len;
    if (m[0] == SSL3_MT_NEWSESSION_TICKET && write_p)
        nst_written++;
    if (m[0] == SSL3_MT_CLIENT_HELLO && write_p) {
        p = m + SSL3_HM_HEADER_LENGTH + 2 + SSL3_RANDOM_SIZE;
        if (p >= end)
            return;
        p += 1 + p[0];
        if (p + 2 > end)
            return;
        clen = ((size_t)p[0] << 8) | p[1];
        p += 2;
        if (p + clen > end || clen > sizeof(ch_ciphers))
            return;
        memcpy(ch_ciphers, p, clen);
        ch_cipherslen = clen;
    }
    if (m[0] == SSL3_MT_SERVER_HELLO && !write_p) {
        server_hellos++;
        p = m + SSL3_HM_HEADER_LENGTH + 2 + SSL3_RANDOM_SIZE;
        if (p >= end)
            return;
        p += 1 + p[0];
        if (p + 2 > end)
            return;
        sh_cipher = ((unsigned int)p[0] << 8) | p[1];
    }
}

static void reset_counters(void)
{
    nst_written = server_hellos = 0;
    ch_cipherslen = 0;
    sh_cipher = 0;
}

static SSL_SESSION *captured_session;
static SSL_SESSION *captured_server_session;
static SSL_SESSION *external_cache_session;

static int capture_session_cb(SSL *ssl, SSL_SESSION *sess)
{
    SSL_SESSION_free(captured_session);
    captured_session = sess;
    return 1;
}

static int capture_server_session_cb(SSL *ssl, SSL_SESSION *sess)
{
    SSL_SESSION_free(captured_server_session);
    captured_server_session = sess;
    return 1;
}

static SSL_SESSION *external_cache_cb(ossl_unused SSL *ssl,
    ossl_unused const unsigned char *id, ossl_unused int idlen, int *copy)
{
    *copy = 1;
    return external_cache_session;
}

static int make_pair(const char *mode, const char *sciph, const char *cciph,
    char *scert, char *skey, SSL_CTX **sctx, SSL_CTX **cctx)
{
    tls_provider_set_ciphersuite_mode(mode);
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            sctx, cctx, scert, skey)))
        return 0;
    return TEST_true(SSL_CTX_set_ciphersuites(*sctx, sciph))
        && TEST_true(SSL_CTX_set_ciphersuites(*cctx, cciph));
}

static int exchange_data(SSL *a, SSL *b, const unsigned char *msg, size_t len)
{
    unsigned char *buf = OPENSSL_malloc(len);
    size_t written = 0, readbytes = 0, total = 0;
    int ret = 0;

    if (!TEST_ptr(buf))
        return 0;
    if (!TEST_true(SSL_write_ex(a, msg, len, &written))
        || !TEST_size_t_eq(written, len))
        goto end;
    while (total < len) {
        if (!TEST_true(SSL_read_ex(b, buf + total, len - total, &readbytes))
            || !TEST_size_t_gt(readbytes, 0))
            goto end;
        total += readbytes;
    }
    ret = TEST_mem_eq(buf, total, msg, len);
end:
    OPENSSL_free(buf);
    return ret;
}

static int check_negotiated(SSL *serverssl, SSL *clientssl, unsigned int cp,
    int expect_origin)
{
    const SSL_CIPHER *sc = SSL_get_current_cipher(serverssl);
    const SSL_CIPHER *cc = SSL_get_current_cipher(clientssl);
    static const unsigned char msg[] = "provider ciphersuite ext";

    return TEST_ptr(sc) && TEST_ptr(cc)
        && TEST_uint_eq(SSL_CIPHER_get_protocol_id(sc), cp)
        && TEST_uint_eq(SSL_CIPHER_get_protocol_id(cc), cp)
        && TEST_int_eq(sc->origin, expect_origin)
        && TEST_int_eq(cc->origin, expect_origin)
        && exchange_data(clientssl, serverssl, msg, sizeof(msg))
        && exchange_data(serverssl, clientssl, msg, sizeof(msg));
}

static int test_resume_into_provider_suite(int idx)
{
    const SUITE_VARIANT *v = &variants[idx & 1];
    int with_hrr = (idx & 2) != 0;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *sess = NULL, *after = NULL;
    char both[128];
    int ret = 0;

    snprintf(both, sizeof(both), "%s:%s", v->provname, v->builtinname);

    /* First handshake: built-in suite only, obtain a ticket. */
    if (!make_pair(v->mode, v->builtinname, v->builtinname, cert, privkey,
            &sctx, &cctx))
        goto end;
    SSL_CTX_set_session_cache_mode(cctx,
        SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(cctx, capture_session_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(captured_session)
        || !TEST_true(SSL_SESSION_is_resumable(captured_session)))
        goto end;
    sess = captured_session;
    captured_session = NULL;
    /* A clean shutdown; SSL_free() without it marks the session unusable. */
    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;

    /*
     * Second handshake: server prefers the provider suite (same transcript
     * hash), client offers the PSK from the built-in session. RFC 8446
     * section 4.2.11 permits the switch.
     */
    if (!TEST_true(SSL_CTX_set_ciphersuites(sctx, both))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, both)))
        goto end;
    SSL_CTX_set_options(sctx, SSL_OP_SERVER_PREFERENCE);
    if (with_hrr
        && (!TEST_true(SSL_CTX_set1_groups_list(cctx,
                "secp521r1:secp384r1:prime256v1"))
            || !TEST_true(SSL_CTX_set1_groups_list(sctx,
                "prime256v1:secp384r1"))))
        goto end;
    reset_counters();
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_session(clientssl, sess)))
        goto end;
    SSL_set_msg_callback(clientssl, wire_cb);
    SSL_set_msg_callback(serverssl, wire_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_int_eq(server_hellos, with_hrr ? 2 : 1)
        || !TEST_true(SSL_session_reused(serverssl))
        || !TEST_true(SSL_session_reused(clientssl))
        || !check_negotiated(serverssl, clientssl, v->codepoint,
            SSL_CIPHER_ORIGIN_PROVIDER)
        /* No NewSessionTicket may be issued on a provider-suite connection */
        || !TEST_int_eq(nst_written, 0)
        || !TEST_ptr(after = SSL_get1_session(clientssl))
        || !TEST_false(SSL_SESSION_is_resumable(after))
        || !TEST_int_eq(SSL_SESSION_get0_cipher(after)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(after);
    SSL_SESSION_free(sess);
    SSL_SESSION_free(captured_session);
    captured_session = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_stateful_cache_provider_transition(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *sess = NULL, *replay = NULL, *cached = NULL;
    char both[128];
    int ret = 0;

    snprintf(both, sizeof(both), "%s:%s", PROV_SHA256_NAME,
        BUILTIN_SHA256_NAME);
    if (!make_pair("valid", BUILTIN_SHA256_NAME, BUILTIN_SHA256_NAME,
            cert, privkey, &sctx, &cctx))
        goto end;
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    SSL_CTX_sess_set_new_cb(sctx, capture_server_session_cb);
    SSL_CTX_set_session_cache_mode(cctx,
        SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_sess_set_new_cb(cctx, capture_session_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(captured_session)
        || !TEST_ptr(captured_server_session)
        || !TEST_ptr(replay = SSL_SESSION_dup(captured_session)))
        goto end;
    sess = captured_session;
    captured_session = NULL;
    cached = captured_server_session;
    captured_server_session = NULL;
    if (!TEST_int_eq(cached->cipher->origin, SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_false(cached->provider_cipher_seen))
        goto end;
    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;

    if (!TEST_true(SSL_CTX_set_ciphersuites(sctx, both))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, both)))
        goto end;
    SSL_CTX_set_options(sctx, SSL_OP_SERVER_PREFERENCE);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_session(clientssl, sess))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(serverssl))
        || !TEST_int_eq(SSL_get_current_cipher(serverssl)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_int_eq(cached->cipher->origin, SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_false(cached->provider_cipher_seen))
        goto end;
    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_session(clientssl, replay))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(serverssl))
        || !TEST_int_eq(SSL_get_current_cipher(serverssl)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(cached);
    SSL_SESSION_free(replay);
    SSL_SESSION_free(sess);
    SSL_SESSION_free(captured_session);
    captured_session = NULL;
    SSL_SESSION_free(captured_server_session);
    captured_server_session = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_external_cache_rejects_provider_session(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_SESSION *marked = NULL, *dup = NULL, *found;
    const SSL_CIPHER *suite;
    static const unsigned char id[] = { 1 };
    int ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(suite = ssl_provider_ciphersuite_by_name(ctx,
                         PROV_SHA256_NAME))
        || !TEST_ptr(marked = SSL_SESSION_new())
        || !TEST_true(SSL_SESSION_set_cipher(marked, suite))
        || !TEST_ptr(dup = ssl_session_dup(marked, 0))
        || !TEST_true(dup->provider_cipher_seen)
        || !TEST_false(dup->not_resumable)
        || !TEST_ptr(ssl = SSL_new(ctx)))
        goto end;
    external_cache_session = dup;
    SSL_CTX_set_session_cache_mode(ctx,
        SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP);
    SSL_CTX_sess_set_get_cb(ctx, external_cache_cb);
    found = lookup_sess_in_cache(SSL_CONNECTION_FROM_SSL(ssl), id,
        sizeof(id));
    if (!TEST_ptr_null(found)) {
        SSL_SESSION_free(found);
        goto end;
    }

    ret = 1;
end:
    external_cache_session = NULL;
    SSL_SESSION_free(dup);
    SSL_SESSION_free(marked);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static SSL_SESSION *clientpsk, *serverpsk;
static const char pskid[] = "provider-psk-identity";

static int use_session_cb(SSL *ssl, const EVP_MD *md, const unsigned char **id,
    size_t *idlen, SSL_SESSION **sess)
{
    if (clientpsk == NULL || !SSL_SESSION_up_ref(clientpsk))
        return 0;
    *sess = clientpsk;
    *id = (const unsigned char *)pskid;
    *idlen = strlen(pskid);
    return 1;
}

static int find_session_cb(SSL *ssl, const unsigned char *identity,
    size_t identity_len, SSL_SESSION **sess)
{
    *sess = NULL;
    if (identity_len != strlen(pskid)
        || memcmp(identity, pskid, identity_len) != 0)
        return 1;
    if (serverpsk == NULL || !SSL_SESSION_up_ref(serverpsk))
        return 0;
    *sess = serverpsk;
    return 1;
}

static SSL_SESSION *make_provider_psk(SSL *ssl, const SUITE_VARIANT *v,
    uint32_t max_early)
{
    static const unsigned char key[SHA384_DIGEST_LENGTH] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f
    };
    unsigned char wire[2] = { (unsigned char)(v->codepoint >> 8),
        (unsigned char)v->codepoint };
    const SSL_CIPHER *cipher = SSL_CIPHER_find(ssl, wire);
    SSL_SESSION *sess = SSL_SESSION_new();

    if (!TEST_ptr(cipher) || !TEST_ptr(sess)
        || !TEST_int_eq(cipher->origin, SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_true(SSL_SESSION_set1_master_key(sess, key, v->mdsize))
        || !TEST_true(SSL_SESSION_set_cipher(sess, cipher))
        || !TEST_true(SSL_SESSION_set_protocol_version(sess, TLS1_3_VERSION))
        || !TEST_true(SSL_SESSION_set_max_early_data(sess, max_early))) {
        SSL_SESSION_free(sess);
        return NULL;
    }
    return sess;
}

static int test_external_psk_provider(int idx)
{
    static const unsigned char early[] = "0-RTT under a provider suite";
    static const char label[] = "early exporter";
    const SUITE_VARIANT *v = &variants[idx & 1];
    int early_data = (idx & 2) != 0;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    unsigned char buf[64], cexp[32], sexp[32];
    size_t written = 0, readbytes = 0;
    int ret = 0;

    if (!make_pair(v->mode, v->provname, v->provname, cert, privkey,
            &sctx, &cctx))
        goto end;
    SSL_CTX_set_psk_use_session_callback(cctx, use_session_cb);
    SSL_CTX_set_psk_find_session_callback(sctx, find_session_cb);
    if (early_data
        && !TEST_true(SSL_CTX_set_max_early_data(sctx, 1024)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_ptr(clientpsk = make_provider_psk(clientssl, v,
                         early_data ? 1024 : 0))
        || !TEST_ptr(serverpsk = make_provider_psk(serverssl, v,
                         early_data ? 1024 : 0)))
        goto end;

    if (early_data) {
        if (!TEST_true(SSL_write_early_data(clientssl, early, sizeof(early),
                &written))
            || !TEST_size_t_eq(written, sizeof(early))
            || !TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                &readbytes),
                SSL_READ_EARLY_DATA_SUCCESS)
            || !TEST_mem_eq(buf, readbytes, early, sizeof(early))
            || !TEST_int_eq(SSL_get_early_data_status(serverssl),
                SSL_EARLY_DATA_ACCEPTED)
            /* Client finishes: EndOfEarlyData, Finished, then app data. */
            || !TEST_true(SSL_write_ex(clientssl, early, sizeof(early),
                &written))
            || !TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                                &readbytes),
                SSL_READ_EARLY_DATA_FINISH)
            || !TEST_size_t_eq(readbytes, 0))
            goto end;
    }

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(clientssl))
        || !TEST_true(SSL_session_reused(serverssl)))
        goto end;
    if (early_data
        && (!TEST_true(SSL_read_ex(serverssl, buf, sizeof(buf), &readbytes))
            || !TEST_mem_eq(buf, readbytes, early, sizeof(early))))
        goto end;
    if (!check_negotiated(serverssl, clientssl, v->codepoint,
            SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    if (early_data
        && (!TEST_int_eq(SSL_get_early_data_status(clientssl),
                SSL_EARLY_DATA_ACCEPTED)
            || !TEST_int_eq(SSL_get_early_data_status(serverssl),
                SSL_EARLY_DATA_ACCEPTED)
            || !TEST_int_gt(SSL_export_keying_material_early(clientssl, cexp,
                                sizeof(cexp), label, sizeof(label) - 1,
                                NULL, 0),
                0)
            || !TEST_int_gt(SSL_export_keying_material_early(serverssl, sexp,
                                sizeof(sexp), label, sizeof(label) - 1,
                                NULL, 0),
                0)
            || !TEST_mem_eq(cexp, sizeof(cexp), sexp, sizeof(sexp))))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(clientpsk);
    SSL_SESSION_free(serverpsk);
    clientpsk = serverpsk = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_provider_psk_early_data_admissibility(void)
{
    const SUITE_VARIANT *v = &variants[0];
    SSL_CTX *sctx = NULL, *cctx = NULL, *foreignctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL, *foreignssl = NULL;
    SSL_CONNECTION *serversc, *clientsc;
    SSL_SESSION *serverlocal = NULL, *clientlocal = NULL, *foreign = NULL;
    int ret = 0;

    if (!make_pair(v->mode, v->provname, v->provname, cert, privkey,
            &sctx, &cctx))
        goto end;

    tls_provider_set_ciphersuite_mode("valid-conflicting-sha256");
    if (!TEST_ptr(foreignctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_true(SSL_CTX_set_ciphersuites(foreignctx, v->provname)))
        goto end;
    tls_provider_set_ciphersuite_mode("valid");

    if (!TEST_ptr(serverssl = SSL_new(sctx))
        || !TEST_ptr(clientssl = SSL_new(cctx))
        || !TEST_ptr(foreignssl = SSL_new(foreignctx))
        || !TEST_ptr(serversc = SSL_CONNECTION_FROM_SSL_ONLY(serverssl))
        || !TEST_ptr(clientsc = SSL_CONNECTION_FROM_SSL_ONLY(clientssl))
        || !TEST_ptr(serverlocal = make_provider_psk(serverssl, v, 1024))
        || !TEST_ptr(clientlocal = make_provider_psk(clientssl, v, 1024))
        || !TEST_ptr(foreign = make_provider_psk(foreignssl, v, 1024)))
        goto end;

    SSL_set_accept_state(serverssl);
    SSL_set_connect_state(clientssl);
    serversc->s3.tmp.min_ver = serversc->s3.tmp.max_ver = TLS1_3_VERSION;
    clientsc->s3.tmp.min_ver = clientsc->s3.tmp.max_ver = TLS1_3_VERSION;
    if (!TEST_true(ssl_session_cipher_is_early_data_admissible(serversc,
            serverlocal))
        || !TEST_true(ssl_session_cipher_is_early_data_admissible(clientsc,
            clientlocal))
        || !TEST_false(ssl_session_cipher_is_early_data_admissible(serversc,
            foreign))
        || !TEST_false(ssl_session_cipher_is_early_data_admissible(clientsc,
            foreign)))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(serverlocal);
    SSL_SESSION_free(clientlocal);
    SSL_SESSION_free(foreign);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(foreignssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(foreignctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_provider_psk_early_context_switch(void)
{
    static const unsigned char early[] = "provider early data";
    const SUITE_VARIANT *v = &variants[0];
    SSL_CTX *sctx = NULL, *cctx = NULL, *missing = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    size_t written = 0;
    int ret = 0;

    if (!make_pair(v->mode, v->provname, v->provname, cert, privkey,
            &sctx, &cctx)
        || !TEST_true(SSL_CTX_set_max_early_data(sctx, 1024)))
        goto end;

    tls_provider_set_ciphersuite_mode("unsupported");
    if (!TEST_ptr(missing = SSL_CTX_new_ex(libctx, NULL, TLS_client_method())))
        goto end;
    tls_provider_set_ciphersuite_mode("valid");

    SSL_CTX_set_psk_use_session_callback(cctx, use_session_cb);
    SSL_CTX_set_psk_find_session_callback(sctx, find_session_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_ptr(clientpsk = make_provider_psk(clientssl, v, 1024))
        || !TEST_ptr(serverpsk = make_provider_psk(serverssl, v, 1024))
        || !TEST_true(SSL_write_early_data(clientssl, early, sizeof(early),
            &written))
        || !TEST_size_t_eq(written, sizeof(early))
        || !TEST_ptr_null(SSL_set_SSL_CTX(clientssl, missing))
        || !TEST_false(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(clientpsk);
    SSL_SESSION_free(serverpsk);
    clientpsk = serverpsk = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(missing);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_external_psk_foreign_server_rejects_early_data(void)
{
    static const unsigned char early[] = "foreign provider early data";
    const SUITE_VARIANT *v = &variants[0];
    SSL_CTX *sctx = NULL, *cctx = NULL, *foreignctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL, *foreignssl = NULL;
    unsigned char buf[sizeof(early)];
    size_t written = 0, readbytes = 0;
    int ret = 0;

    if (!make_pair(v->mode, v->provname, v->provname, cert, privkey,
            &sctx, &cctx)
        || !TEST_true(SSL_CTX_set_max_early_data(sctx, 1024)))
        goto end;

    tls_provider_set_ciphersuite_mode("valid-conflicting-sha256");
    if (!TEST_ptr(foreignctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_true(SSL_CTX_set_ciphersuites(foreignctx, v->provname))
        || !TEST_ptr(foreignssl = SSL_new(foreignctx)))
        goto end;
    tls_provider_set_ciphersuite_mode("valid");

    SSL_CTX_set_psk_use_session_callback(cctx, use_session_cb);
    SSL_CTX_set_psk_find_session_callback(sctx, find_session_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_ptr(clientpsk = make_provider_psk(clientssl, v, 1024))
        || !TEST_ptr(serverpsk = make_provider_psk(foreignssl, v, 1024))
        || !TEST_true(SSL_write_early_data(clientssl, early, sizeof(early),
            &written))
        || !TEST_size_t_eq(written, sizeof(early))
        || !TEST_int_eq(SSL_read_early_data(serverssl, buf, sizeof(buf),
                            &readbytes),
            SSL_READ_EARLY_DATA_FINISH)
        || !TEST_size_t_eq(readbytes, 0)
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(clientssl))
        || !TEST_true(SSL_session_reused(serverssl))
        || !TEST_int_ne(SSL_get_early_data_status(clientssl),
            SSL_EARLY_DATA_ACCEPTED)
        || !TEST_int_ne(SSL_get_early_data_status(serverssl),
            SSL_EARLY_DATA_ACCEPTED)
        || !check_negotiated(serverssl, clientssl, v->codepoint,
            SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(clientpsk);
    SSL_SESSION_free(serverpsk);
    clientpsk = serverpsk = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(foreignssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(foreignctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_provider_psk_nonstream_rejected(void)
{
    SSL_CTX *tlsctx = NULL, *dtlsctx = NULL;
    SSL *tlsssl = NULL, *serverssl = NULL;
#if !defined(OPENSSL_NO_DTLS) && !defined(OPENSSL_NO_DTLS1_3)
    SSL *dtlsssl = NULL, *dtlsserverssl = NULL;
#endif
    SSL_SESSION *sess = NULL;
    SSL_CONNECTION *sc;
    WPACKET wpkt = { 0 };
    PACKET packet = { 0 };
    unsigned char early_data_ext[16];
    unsigned char psk_ext[2 + 2 + sizeof(pskid) - 1 + 4];
    size_t idlen = sizeof(pskid) - 1;
    int wpkt_init = 0;
    int ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_ptr(tlsctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_true(SSL_CTX_set_ciphersuites(tlsctx, PROV_SHA256_NAME)))
        goto end;
    SSL_CTX_set_psk_use_session_callback(tlsctx, use_session_cb);
    SSL_CTX_set_psk_find_session_callback(tlsctx, find_session_cb);
    if (!TEST_ptr(tlsssl = SSL_new(tlsctx))
        || !TEST_ptr(serverssl = SSL_new(tlsctx))
        || !TEST_ptr(sess = make_provider_psk(tlsssl, &variants[0], 1024)))
        goto end;

    if (!TEST_true(SSL_SESSION_up_ref(sess)))
        goto end;
    clientpsk = sess;
    if (!TEST_true(SSL_SESSION_up_ref(sess)))
        goto end;
    serverpsk = sess;

    SSL_set_connect_state(tlsssl);
    sc = SSL_CONNECTION_FROM_SSL(tlsssl);
    sc->s3.flags |= TLS1_FLAGS_QUIC;
    if (!TEST_false(ssl_session_cipher_is_transport_admissible(sc, sess))
        || !TEST_true(WPACKET_init_static_len(&wpkt, early_data_ext,
            sizeof(early_data_ext), 0)))
        goto end;
    wpkt_init = 1;
    ERR_clear_error();
    if (!TEST_int_eq(tls_construct_ctos_early_data(sc, &wpkt,
                         SSL_EXT_CLIENT_HELLO, NULL, 0),
            EXT_RETURN_FAIL)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), SSL_R_BAD_PSK))
        goto end;
    WPACKET_cleanup(&wpkt);
    wpkt_init = 0;

    psk_ext[0] = 0;
    psk_ext[1] = (unsigned char)(sizeof(psk_ext) - 2);
    psk_ext[2] = 0;
    psk_ext[3] = (unsigned char)idlen;
    memcpy(psk_ext + 4, pskid, idlen);
    memset(psk_ext + 4 + idlen, 0, 4);
    SSL_set_accept_state(serverssl);
    sc = SSL_CONNECTION_FROM_SSL(serverssl);
    sc->s3.flags |= TLS1_FLAGS_QUIC;
    sc->ext.psk_kex_mode = TLSEXT_KEX_MODE_FLAG_KE_DHE;
    if (!TEST_true(PACKET_buf_init(&packet, psk_ext, sizeof(psk_ext))))
        goto end;
    ERR_clear_error();
    if (!TEST_false(tls_parse_ctos_psk(sc, &packet,
            SSL_EXT_CLIENT_HELLO, NULL, 0))
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), SSL_R_BAD_PSK))
        goto end;

#if !defined(OPENSSL_NO_DTLS) && !defined(OPENSSL_NO_DTLS1_3)
    if (!TEST_true(SSL_SESSION_set_protocol_version(sess,
            DTLS1_3_VERSION))
        || !TEST_ptr(dtlsctx = SSL_CTX_new_ex(libctx, NULL,
                         DTLS_method())))
        goto end;
    SSL_CTX_set_psk_use_session_callback(dtlsctx, use_session_cb);
    SSL_CTX_set_psk_find_session_callback(dtlsctx, find_session_cb);
    if (!TEST_ptr(dtlsssl = SSL_new(dtlsctx))
        || !TEST_ptr(dtlsserverssl = SSL_new(dtlsctx)))
        goto end;

    SSL_set_connect_state(dtlsssl);
    sc = SSL_CONNECTION_FROM_SSL(dtlsssl);
    if (!TEST_false(ssl_session_cipher_is_transport_admissible(sc, sess))
        || !TEST_true(WPACKET_init_static_len(&wpkt, early_data_ext,
            sizeof(early_data_ext), 0)))
        goto end;
    wpkt_init = 1;
    ERR_clear_error();
    if (!TEST_int_eq(tls_construct_ctos_early_data(sc, &wpkt,
                         SSL_EXT_CLIENT_HELLO, NULL, 0),
            EXT_RETURN_FAIL)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), SSL_R_BAD_PSK))
        goto end;
    WPACKET_cleanup(&wpkt);
    wpkt_init = 0;

    SSL_set_accept_state(dtlsserverssl);
    sc = SSL_CONNECTION_FROM_SSL(dtlsserverssl);
    sc->ext.psk_kex_mode = TLSEXT_KEX_MODE_FLAG_KE_DHE;
    if (!TEST_true(PACKET_buf_init(&packet, psk_ext, sizeof(psk_ext))))
        goto end;
    ERR_clear_error();
    if (!TEST_false(tls_parse_ctos_psk(sc, &packet,
            SSL_EXT_CLIENT_HELLO, NULL, 0))
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), SSL_R_BAD_PSK))
        goto end;
#endif

    ret = 1;
end:
    if (wpkt_init)
        WPACKET_cleanup(&wpkt);
    SSL_SESSION_free(clientpsk);
    SSL_SESSION_free(serverpsk);
    clientpsk = serverpsk = NULL;
    SSL_SESSION_free(sess);
    SSL_free(tlsssl);
    SSL_free(serverssl);
#if !defined(OPENSSL_NO_DTLS) && !defined(OPENSSL_NO_DTLS1_3)
    SSL_free(dtlsssl);
    SSL_free(dtlsserverssl);
#endif
    SSL_CTX_free(tlsctx);
    SSL_CTX_free(dtlsctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int gen_cookie_cb(SSL *ssl, unsigned char *cookie, size_t *cookie_len)
{
    memcpy(cookie, "provider-cookie", 15);
    *cookie_len = 15;
    return 1;
}

static int verify_cookie_cb(SSL *ssl, const unsigned char *cookie,
    size_t cookie_len)
{
    return cookie_len == 15 && memcmp(cookie, "provider-cookie", 15) == 0;
}

static int test_stateless_cookie(int idx)
{
    const SUITE_VARIANT *v = &variants[idx];
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int ret = 0;

    if (!make_pair(v->mode, v->provname, v->provname, cert, privkey,
            &sctx, &cctx))
        goto end;
    SSL_CTX_set_stateless_cookie_generate_cb(sctx, gen_cookie_cb);
    SSL_CTX_set_stateless_cookie_verify_cb(sctx, verify_cookie_cb);
    /* A middlebox-compat CCS between the ClientHellos would confuse the test */
    SSL_CTX_clear_options(cctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
    reset_counters();
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;
    SSL_set_msg_callback(clientssl, wire_cb);
    if (!TEST_false(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_WANT_READ))
        /* No cookie yet: HRR with cookie is sent */
        || !TEST_int_eq(SSL_stateless(serverssl), 0)
        || !TEST_false(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_WANT_READ))
        /* Cookie present and verified */
        || !TEST_int_eq(SSL_stateless(serverssl), 1)
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_int_eq(server_hellos, 2)
        || !check_negotiated(serverssl, clientssl, v->codepoint,
            SSL_CIPHER_ORIGIN_PROVIDER))
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

static int sec_min_bits, sec_seen_bits, sec_seen_provider;

static int sec_cb(const SSL *s, const SSL_CTX *ctx, int op, int bits, int nid,
    void *other, void *ex)
{
    const SSL_CIPHER *c = other;

    if (op == SSL_SECOP_CIPHER_SUPPORTED || op == SSL_SECOP_CIPHER_SHARED
        || op == SSL_SECOP_CIPHER_CHECK) {
        if (c != NULL && c->origin == SSL_CIPHER_ORIGIN_PROVIDER) {
            sec_seen_provider++;
            sec_seen_bits = bits;
            if (bits < sec_min_bits)
                return 0;
        }
    }
    return 1;
}

static int test_security_callback(int idx)
{
    const SUITE_VARIANT *v = &variants[idx & 1];
    int veto = (idx & 2) != 0;
    int expect_bits = v->mdsize == SHA384_DIGEST_LENGTH ? 256 : 128;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int ret = 0;

    sec_min_bits = veto ? expect_bits + 1 : expect_bits;
    sec_seen_bits = sec_seen_provider = 0;
    if (!make_pair(v->mode, v->provname, v->provname, cert, privkey,
            &sctx, &cctx))
        goto end;
    SSL_CTX_set_security_callback(sctx, sec_cb);
    SSL_CTX_set_security_callback(cctx, sec_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;
    if (veto) {
        if (!TEST_false(create_ssl_connection(serverssl, clientssl,
                SSL_ERROR_NONE)))
            goto end;
    } else if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                   SSL_ERROR_NONE))
        || !check_negotiated(serverssl, clientssl, v->codepoint,
            SSL_CIPHER_ORIGIN_PROVIDER)) {
        goto end;
    }
    if (!TEST_int_gt(sec_seen_provider, 0)
        || !TEST_int_eq(sec_seen_bits, expect_bits))
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

static int test_preference_and_wire(int idx)
{
    int server_pref = idx != 0;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    size_t i, prov_count = 0;
    unsigned int expect = server_pref ? 0x1301U : PROV_SHA256_CP;
    int ret = 0;

    if (!make_pair("valid", BUILTIN_SHA256_NAME ":" PROV_SHA256_NAME,
            PROV_SHA256_NAME ":" BUILTIN_SHA256_NAME, cert, privkey,
            &sctx, &cctx))
        goto end;
    if (server_pref)
        SSL_CTX_set_options(sctx, SSL_OP_SERVER_PREFERENCE);
    reset_counters();
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;
    SSL_set_msg_callback(clientssl, wire_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_size_t_ge(ch_cipherslen, 4)
        || !TEST_size_t_eq(ch_cipherslen % 2, 0))
        goto end;
    /* The client offered the provider suite first and exactly once. */
    if (!TEST_uint_eq(((unsigned int)ch_ciphers[0] << 8) | ch_ciphers[1],
            PROV_SHA256_CP))
        goto end;
    for (i = 0; i < ch_cipherslen; i += 2)
        if ((((unsigned int)ch_ciphers[i] << 8) | ch_ciphers[i + 1])
            == PROV_SHA256_CP)
            prov_count++;
    if (!TEST_size_t_eq(prov_count, 1)
        || !TEST_uint_eq(sh_cipher, expect)
        || !check_negotiated(serverssl, clientssl, expect,
            server_pref ? SSL_CIPHER_ORIGIN_STATIC
                        : SSL_CIPHER_ORIGIN_PROVIDER))
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

static int verify_accept_cb(int ok, X509_STORE_CTX *ctx)
{
    return 1;
}

static int test_ecdsa_and_client_auth(int idx)
{
    const SUITE_VARIANT *v = &variants[idx];
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int ret = 0;

    if (!make_pair(v->mode, v->provname, v->provname, ecdsacert, ecdsakey,
            &sctx, &cctx))
        goto end;
    if (!TEST_int_eq(SSL_CTX_use_certificate_file(cctx, cert,
                         SSL_FILETYPE_PEM),
            1)
        || !TEST_int_eq(SSL_CTX_use_PrivateKey_file(cctx, privkey,
                            SSL_FILETYPE_PEM),
            1))
        goto end;
    SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_accept_cb);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(SSL_get0_peer_certificate(serverssl))
        || !TEST_ptr(SSL_get0_peer_certificate(clientssl))
        || !TEST_int_eq(EVP_PKEY_get_base_id(
                            X509_get0_pubkey(SSL_get0_peer_certificate(clientssl))),
            EVP_PKEY_EC)
        || !check_negotiated(serverssl, clientssl, v->codepoint,
            SSL_CIPHER_ORIGIN_PROVIDER))
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

static int test_key_updates(int idx)
{
    static const unsigned char msg[] = "after key update";
    const SUITE_VARIANT *v = &variants[idx];
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int i, ret = 0;

    if (!make_pair(v->mode, v->provname, v->provname, cert, privkey,
            &sctx, &cctx)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    for (i = 0; i < 4; i++) {
        SSL *initiator = (i & 1) ? serverssl : clientssl;
        SSL *peer = (i & 1) ? clientssl : serverssl;
        int type = (i & 2) ? SSL_KEY_UPDATE_NOT_REQUESTED
                           : SSL_KEY_UPDATE_REQUESTED;

        if (!TEST_true(SSL_key_update(initiator, type))
            || !exchange_data(initiator, peer, msg, sizeof(msg))
            || !exchange_data(peer, initiator, msg, sizeof(msg)))
            goto end;
    }
    if (!TEST_int_eq(SSL_get_key_update_type(clientssl), SSL_KEY_UPDATE_NONE)
        || !TEST_int_eq(SSL_get_key_update_type(serverssl),
            SSL_KEY_UPDATE_NONE))
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

static int test_records_and_shutdown(int idx)
{
    static const size_t sizes[] = { 1, 15, 16, 17, 255, 256, 4097,
        SSL3_RT_MAX_PLAIN_LENGTH };
    int middlebox = idx != 0;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    unsigned char *msg = NULL;
    size_t i, j;
    int ret = 0;

    msg = OPENSSL_malloc(SSL3_RT_MAX_PLAIN_LENGTH);
    if (!TEST_ptr(msg))
        goto end;
    for (i = 0; i < SSL3_RT_MAX_PLAIN_LENGTH; i++)
        msg[i] = (unsigned char)(i * 7);

    if (!make_pair("valid", PROV_SHA256_NAME, PROV_SHA256_NAME, cert, privkey,
            &sctx, &cctx)
        || !TEST_true(SSL_CTX_set_block_padding(sctx, 256))
        || !TEST_true(SSL_CTX_set_block_padding(cctx, 64)))
        goto end;
    if (!middlebox) {
        SSL_CTX_clear_options(sctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
        SSL_CTX_clear_options(cctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
    }
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;
    for (j = 0; j < OSSL_NELEM(sizes); j++) {
        if (!exchange_data(clientssl, serverssl, msg, sizes[j])
            || !exchange_data(serverssl, clientssl, msg, sizes[j]))
            goto end;
    }
    shutdown_ssl_connection(serverssl, clientssl);
    serverssl = clientssl = NULL;

    ret = 1;
end:
    OPENSSL_free(msg);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

#define TEST_AEAD_ENCRYPTION_LIMIT 4

static int test_provider_aead_limit_failure(void)
{
    static const unsigned char msg[] = "limit";
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    size_t written = 0;
    int i, write_ret, ret = 0;

    if (!make_pair("valid-limit", PROV_SHA256_NAME, PROV_SHA256_NAME, cert,
            privkey, &sctx, &cctx)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    for (i = 0; i < TEST_AEAD_ENCRYPTION_LIMIT / 2; i++) {
        if (!exchange_data(clientssl, serverssl, msg, sizeof(msg)))
            goto end;
    }

    if (!TEST_true(SSL_key_update(clientssl, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;

    for (i = 0; i < TEST_AEAD_ENCRYPTION_LIMIT; i++) {
        if (!exchange_data(clientssl, serverssl, msg, sizeof(msg)))
            goto end;
    }

    write_ret = SSL_write_ex(clientssl, msg, sizeof(msg), &written);
    if (!TEST_false(write_ret)
        || !TEST_int_eq(SSL_get_error(clientssl, write_ret), SSL_ERROR_SSL))
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

#if !defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_KTLS)
static int test_provider_ciphersuite_disables_ktls(void)
{
    static const unsigned char msg[] = "provider kTLS exclusion";
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_CONNECTION *clientsc;
    int cfd = -1, sfd = -1, ret = 0;

    tls_provider_set_ciphersuite_mode(NULL);
    if (!TEST_true(create_test_sockets(&cfd, &sfd, SOCK_STREAM, NULL)))
        goto end;
    if (!ktls_enable(cfd)) {
        ret = TEST_skip("Kernel does not support kTLS");
        goto end;
    }
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, BUILTIN_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, BUILTIN_SHA256_NAME))
        || !TEST_true(create_ssl_objects2(sctx, cctx, &serverssl, &clientssl,
            sfd, cfd))
        || !TEST_true(SSL_set_options(clientssl, SSL_OP_ENABLE_KTLS))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(clientsc = SSL_CONNECTION_FROM_SSL_ONLY(clientssl)))
        goto end;
    if (!BIO_get_ktls_send(clientsc->wbio)) {
        ret = TEST_skip("Kernel does not offload AES-128-GCM");
        goto end;
    }

    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    BIO_closesocket(sfd);
    BIO_closesocket(cfd);
    serverssl = clientssl = NULL;
    sctx = cctx = NULL;
    sfd = cfd = -1;

    if (!TEST_true(create_test_sockets(&cfd, &sfd, SOCK_STREAM, NULL))
        || !TEST_true(ktls_enable(cfd))
        || !make_pair("valid-composed", PROV_SHA256_NAME, PROV_SHA256_NAME,
            cert, privkey, &sctx, &cctx)
        || !TEST_true(create_ssl_objects2(sctx, cctx, &serverssl, &clientssl,
            sfd, cfd))
        || !TEST_true(SSL_set_options(clientssl, SSL_OP_ENABLE_KTLS))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(clientsc = SSL_CONNECTION_FROM_SSL_ONLY(clientssl))
        || !TEST_int_eq(SSL_get_current_cipher(clientssl)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_false(BIO_get_ktls_send(clientsc->wbio))
        || !exchange_data(clientssl, serverssl, msg, sizeof(msg)))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    if (sfd != -1)
        BIO_closesocket(sfd);
    if (cfd != -1)
        BIO_closesocket(cfd);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}
#endif

static int stack_has_name(STACK_OF(SSL_CIPHER) *sk, const char *name)
{
    int i, n = 0;

    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++)
        if (strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, i)), name) == 0)
            n++;
    return n;
}

static int test_public_accessors(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    STACK_OF(SSL_CIPHER) *supported = NULL;
    const SSL_CIPHER *c;
    char shared[256], desc[256];
    int bits, alg_bits, ret = 0;

    if (!make_pair("valid", PROV_SHA256_NAME ":" PROV_SHA256_NAME,
            PROV_SHA256_NAME, cert, privkey, &sctx, &cctx))
        goto end;
    /* Duplicate names in the list must be suppressed. */
    if (!TEST_int_eq(stack_has_name(SSL_CTX_get_ciphers(sctx),
                         PROV_SHA256_NAME),
            1)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_ptr(supported = SSL_get1_supported_ciphers(clientssl))
        || !TEST_int_eq(stack_has_name(supported, PROV_SHA256_NAME), 1)
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(c = SSL_get_current_cipher(clientssl))
        || !TEST_str_eq(SSL_CIPHER_get_name(c), PROV_SHA256_NAME)
        || !TEST_str_eq(SSL_get_cipher_name(clientssl), PROV_SHA256_NAME)
        || !TEST_str_eq(SSL_CIPHER_get_version(c), "TLSv1.3")
        || !TEST_int_eq(bits = SSL_CIPHER_get_bits(c, &alg_bits), 128)
        || !TEST_int_eq(alg_bits, 128)
        || !TEST_int_eq(SSL_CIPHER_get_kx_nid(c), NID_kx_any)
        || !TEST_int_eq(SSL_CIPHER_get_auth_nid(c), NID_auth_any)
        || !TEST_int_eq(SSL_CIPHER_get_digest_nid(c), NID_undef)
        || !TEST_true(SSL_CIPHER_is_aead(c))
        || !TEST_uint_eq(SSL_CIPHER_get_id(c),
            SSL3_CK_CIPHERSUITE_FLAG | PROV_SHA256_CP)
        || !TEST_uint_eq(SSL_CIPHER_get_protocol_id(c), PROV_SHA256_CP)
        || !TEST_ptr(SSL_CIPHER_get_handshake_digest(c))
        || !TEST_true(EVP_MD_is_a(SSL_CIPHER_get_handshake_digest(c),
            OSSL_DIGEST_NAME_SHA2_256))
        || !TEST_ptr(SSL_CIPHER_description(c, desc, sizeof(desc)))
        || !TEST_ptr(strstr(desc, "Kx=any"))
        || !TEST_ptr(strstr(desc, "Mac=AEAD"))
        || !TEST_ptr(SSL_get_shared_ciphers(serverssl, shared, sizeof(shared)))
        || !TEST_ptr(strstr(shared, PROV_SHA256_NAME))
        || !TEST_ptr(SSL_get_pending_cipher(serverssl))
        || !TEST_uint_eq(SSL_CIPHER_get_id(SSL_get_pending_cipher(serverssl)),
            SSL_CIPHER_get_id(c))
        || !TEST_str_eq(OPENSSL_cipher_name(PROV_SHA256_NAME), "(NONE)"))
        goto end;

    ret = 1;
end:
    sk_SSL_CIPHER_free(supported);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_provider_standard_name_is_null(void)
{
    SSL_CTX *ctx = NULL;
    const SSL_CIPHER *c;
    int ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(c = ssl_provider_ciphersuite_by_name(ctx,
                         PROV_SHA256_NAME))
        || !TEST_ptr_null(SSL_CIPHER_standard_name(c)))
        goto end;

    ret = 1;
end:
    SSL_CTX_free(ctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_conf_and_case(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_CONF_CTX *confctx = NULL;
    int ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_ptr(confctx = SSL_CONF_CTX_new()))
        goto end;
    SSL_CONF_CTX_set_flags(confctx, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER);
    SSL_CONF_CTX_set_ssl_ctx(confctx, sctx);
    if (!TEST_int_eq(SSL_CONF_cmd(confctx, "Ciphersuites",
                         "tls_test_provider_aes_128_gcm_sha256"),
            2)
        || !TEST_true(SSL_CONF_CTX_finish(confctx))
        /* Client: context has built-ins only, the SSL object overrides. */
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, BUILTIN_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_ciphersuites(clientssl,
            "Tls_Test_Provider_Aes_128_Gcm_Sha256"))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !check_negotiated(serverssl, clientssl, PROV_SHA256_CP,
            SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    ret = 1;
end:
    SSL_CONF_CTX_free(confctx);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_session_outlives_ctx(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *sess = NULL, *dup = NULL;
    const SSL_CIPHER *c;
    int ret = 0;

    if (!make_pair("valid", PROV_SHA256_NAME, PROV_SHA256_NAME, cert, privkey,
            &sctx, &cctx)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(sess = SSL_get1_session(serverssl)))
        goto end;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    serverssl = clientssl = NULL;
    sctx = cctx = NULL;

    /* The descriptor and its EVP objects must still be alive. */
    if (!TEST_ptr(c = SSL_SESSION_get0_cipher(sess))
        || !TEST_str_eq(SSL_CIPHER_get_name(c), PROV_SHA256_NAME)
        || !TEST_ptr(SSL_CIPHER_get_handshake_digest(c))
        || !TEST_int_gt(EVP_MD_get_size(SSL_CIPHER_get_handshake_digest(c)),
            0)
        || !TEST_ptr(dup = SSL_SESSION_dup(sess))
        || !TEST_ptr_eq(SSL_SESSION_get0_cipher(dup), c)
        || !TEST_false(SSL_SESSION_is_resumable(dup)))
        goto end;
    SSL_SESSION_free(sess);
    sess = NULL;
    if (!TEST_str_eq(SSL_CIPHER_get_name(SSL_SESSION_get0_cipher(dup)),
            PROV_SHA256_NAME))
        goto end;

    ret = 1;
end:
    SSL_SESSION_free(dup);
    SSL_SESSION_free(sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

/*
 * d2i_SSL_SESSION() into an existing session that holds a provider suite
 * must release that reference without clearing unrelated non-resumable state.
 */
static int test_d2i_into_provider_session(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_SESSION *prov = NULL, *builtin = NULL, *reuse = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    int derlen, ret = 0;

    /* A serialisable built-in session. */
    if (!make_pair("valid", BUILTIN_SHA256_NAME, BUILTIN_SHA256_NAME, cert,
            privkey, &sctx, &cctx)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(builtin = SSL_get1_session(serverssl))
        || !TEST_int_gt(derlen = i2d_SSL_SESSION(builtin, &der), 0))
        goto end;
    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = clientssl = NULL;

    /* A session holding a provider suite as the d2i target. */
    if (!TEST_true(SSL_CTX_set_ciphersuites(sctx, PROV_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, PROV_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(prov = SSL_get1_session(serverssl))
        || !TEST_int_eq(SSL_SESSION_get0_cipher(prov)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;
    p = der;
    if (!TEST_ptr_eq(d2i_SSL_SESSION_ex(&prov, &p, derlen, libctx, NULL), prov)
        || !TEST_int_eq(SSL_SESSION_get0_cipher(prov)->origin,
            SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_false(prov->provider_cipher_seen)
        || !TEST_true(prov->not_resumable)
        || !TEST_false(SSL_SESSION_is_resumable(prov))
        || !TEST_ptr(reuse = SSL_SESSION_dup(builtin)))
        goto end;

    reuse->not_resumable = 1;
    p = der;
    if (!TEST_ptr_eq(d2i_SSL_SESSION_ex(&reuse, &p, derlen, libctx, NULL),
            reuse)
        || !TEST_false(reuse->provider_cipher_seen)
        || !TEST_true(reuse->not_resumable)
        || !TEST_false(SSL_SESSION_is_resumable(reuse)))
        goto end;

    ret = 1;
end:
    OPENSSL_free(der);
    SSL_SESSION_free(prov);
    SSL_SESSION_free(builtin);
    SSL_SESSION_free(reuse);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_multiple_providers_collide(void)
{
    OSSL_PROVIDER *second = NULL, *third = NULL;
    SSL_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_true(OSSL_PROVIDER_add_builtin(libctx, "tls-provider-b",
            tls_provider_init))
        || !TEST_ptr(second = OSSL_PROVIDER_load(libctx, "tls-provider-b"))
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "tls-provider-c",
            tls_provider_init))
        || !TEST_ptr(third = OSSL_PROVIDER_load(libctx, "tls-provider-c")))
        goto end;

    /* Same code point and name from two providers: context creation fails */
    tls_provider_set_ciphersuite_mode("valid");
    ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method());
    if (!TEST_ptr_null(ctx)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), SSL_R_BAD_CIPHER))
        goto end;
    ERR_clear_error();

    /* Neither provider advertising anything: context creation succeeds */
    tls_provider_set_ciphersuite_mode("unsupported");
    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_int_eq(sk_SSL_CIPHER_num(ctx->provider_ciphersuites), 0))
        goto end;

    ret = 1;
end:
    SSL_CTX_free(ctx);
    if (third != NULL)
        OSSL_PROVIDER_unload(third);
    if (second != NULL)
        OSSL_PROVIDER_unload(second);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

#define THREAD_COUNT 8
#define HANDSHAKES_PER_THREAD 6

static SSL_CTX *th_sctx, *th_cctx;
static CRYPTO_RWLOCK *th_lock;
static int th_failures;

static void thread_worker(void)
{
    static const unsigned char msg[] = "threaded";
    SSL *serverssl = NULL, *clientssl = NULL;
    int i, ok = 1, tmp;

    for (i = 0; ok && i < HANDSHAKES_PER_THREAD; i++) {
        ok = create_ssl_objects(th_sctx, th_cctx, &serverssl, &clientssl,
                 NULL, NULL)
            && create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)
            && SSL_get_current_cipher(serverssl)->origin
                == SSL_CIPHER_ORIGIN_PROVIDER
            && exchange_data(clientssl, serverssl, msg, sizeof(msg))
            && SSL_key_update(serverssl, SSL_KEY_UPDATE_REQUESTED)
            && exchange_data(serverssl, clientssl, msg, sizeof(msg));
        SSL_free(serverssl);
        SSL_free(clientssl);
        serverssl = clientssl = NULL;
    }
    if (!ok)
        CRYPTO_atomic_add(&th_failures, 1, &tmp, th_lock);
}

static int test_concurrent_handshakes_prebuilt_contexts(void)
{
    thread_t threads[THREAD_COUNT];
    int i, started = 0, ret = 0;

    th_failures = 0;
    if (!TEST_ptr(th_lock = CRYPTO_THREAD_lock_new())
        || !make_pair("valid", PROV_SHA256_NAME, PROV_SHA256_NAME, cert,
            privkey, &th_sctx, &th_cctx))
        goto end;
    for (i = 0; i < THREAD_COUNT; i++) {
        if (!TEST_true(run_thread(&threads[i], thread_worker)))
            break;
        started++;
    }
    for (i = 0; i < started; i++)
        (void)wait_for_thread(threads[i]);
    if (!TEST_int_eq(started, THREAD_COUNT) || !TEST_int_eq(th_failures, 0))
        goto end;

    ret = 1;
end:
    SSL_CTX_free(th_sctx);
    SSL_CTX_free(th_cctx);
    th_sctx = th_cctx = NULL;
    CRYPTO_THREAD_lock_free(th_lock);
    th_lock = NULL;
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

static int test_provider_discovery_reload_lifecycle(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *local_default = NULL, *provider = NULL;
    SSL_CTX *sslctx = NULL;
    int i, ret = 0;

    tls_provider_set_ciphersuite_mode("valid");
    for (i = 0; i < 64; i++) {
        if (!TEST_ptr(ctx = OSSL_LIB_CTX_new())
            || !TEST_true(OSSL_PROVIDER_add_builtin(ctx, "tls-provider-reload",
                tls_provider_init))
            || !TEST_ptr(local_default = OSSL_PROVIDER_load(ctx, "default"))
            || !TEST_ptr(provider = OSSL_PROVIDER_load(ctx,
                             "tls-provider-reload"))
            || !TEST_ptr(sslctx = SSL_CTX_new_ex(ctx, NULL, TLS_method()))
            || !TEST_int_eq(sk_SSL_CIPHER_num(
                                sslctx->provider_ciphersuites),
                1))
            goto end;
        OSSL_PROVIDER_unload(provider);
        provider = NULL;
        if (!TEST_true(SSL_CTX_set_ciphersuites(sslctx, PROV_SHA256_NAME)))
            goto end;
        SSL_CTX_free(sslctx);
        sslctx = NULL;
        OSSL_PROVIDER_unload(local_default);
        local_default = NULL;
        OSSL_LIB_CTX_free(ctx);
        ctx = NULL;
    }
    ret = 1;
end:
    SSL_CTX_free(sslctx);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(local_default);
    OSSL_LIB_CTX_free(ctx);
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

#define RELOADS_PER_THREAD 32

static CRYPTO_RWLOCK *reload_lock;
static int reload_failures;

static void provider_discovery_reload_worker(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *local_default = NULL, *provider = NULL;
    SSL_CTX *sslctx = NULL;
    int i, ok = 1, tmp;

    for (i = 0; ok && i < RELOADS_PER_THREAD; i++) {
        ok = (ctx = OSSL_LIB_CTX_new()) != NULL
            && OSSL_PROVIDER_add_builtin(ctx, "tls-provider-reload-thread",
                tls_provider_init)
            && (local_default = OSSL_PROVIDER_load(ctx, "default")) != NULL
            && (provider = OSSL_PROVIDER_load(ctx,
                    "tls-provider-reload-thread"))
                != NULL
            && (sslctx = SSL_CTX_new_ex(ctx, NULL, TLS_method())) != NULL
            && sk_SSL_CIPHER_num(sslctx->provider_ciphersuites) == 1;
        OSSL_PROVIDER_unload(provider);
        provider = NULL;
        if (ok)
            ok = SSL_CTX_set_ciphersuites(sslctx, PROV_SHA256_NAME);
        SSL_CTX_free(sslctx);
        sslctx = NULL;
        OSSL_PROVIDER_unload(local_default);
        local_default = NULL;
        OSSL_LIB_CTX_free(ctx);
        ctx = NULL;
    }
    SSL_CTX_free(sslctx);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(local_default);
    OSSL_LIB_CTX_free(ctx);
    if (!ok)
        CRYPTO_atomic_add(&reload_failures, 1, &tmp, reload_lock);
}

static int test_concurrent_provider_discovery_reload(void)
{
    thread_t threads[THREAD_COUNT];
    int i, started = 0, ret = 0;

    reload_failures = 0;
    tls_provider_set_ciphersuite_mode("valid");
    if (!TEST_ptr(reload_lock = CRYPTO_THREAD_lock_new()))
        goto end;
    for (i = 0; i < THREAD_COUNT; i++) {
        if (!TEST_true(run_thread(&threads[i],
                provider_discovery_reload_worker)))
            break;
        started++;
    }
    for (i = 0; i < started; i++)
        (void)wait_for_thread(threads[i]);
    if (!TEST_int_eq(started, THREAD_COUNT)
        || !TEST_int_eq(reload_failures, 0))
        goto end;

    ret = 1;
end:
    CRYPTO_THREAD_lock_free(reload_lock);
    reload_lock = NULL;
    ERR_clear_error();
    tls_provider_set_ciphersuite_mode(NULL);
    return ret;
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile ecdsacertfile ecdsakeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()
        || !TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1))
        || !TEST_ptr(ecdsacert = test_get_argument(2))
        || !TEST_ptr(ecdsakey = test_get_argument(3))
        || !TEST_ptr(libctx = OSSL_LIB_CTX_new())
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, "tls-provider",
            tls_provider_init))
        || !TEST_ptr(defprov = OSSL_PROVIDER_load(libctx, "default"))
        || !TEST_ptr(tlsprov = OSSL_PROVIDER_load(libctx, "tls-provider"))
        || !TEST_true(EVP_set_default_properties(libctx,
            "?provider=tls-provider")))
        return 0;

    ADD_ALL_TESTS(test_resume_into_provider_suite, 4);
    ADD_TEST(test_stateful_cache_provider_transition);
    ADD_TEST(test_external_cache_rejects_provider_session);
    ADD_ALL_TESTS(test_external_psk_provider, 4);
    ADD_TEST(test_provider_psk_early_data_admissibility);
    ADD_TEST(test_provider_psk_early_context_switch);
    ADD_TEST(test_external_psk_foreign_server_rejects_early_data);
    ADD_TEST(test_provider_psk_nonstream_rejected);
    ADD_ALL_TESTS(test_stateless_cookie, 2);
    ADD_ALL_TESTS(test_security_callback, 4);
    ADD_ALL_TESTS(test_preference_and_wire, 2);
    ADD_ALL_TESTS(test_ecdsa_and_client_auth, 2);
    ADD_ALL_TESTS(test_key_updates, 2);
    ADD_ALL_TESTS(test_records_and_shutdown, 2);
    ADD_TEST(test_provider_aead_limit_failure);
#if !defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_KTLS)
    ADD_TEST(test_provider_ciphersuite_disables_ktls);
#endif
    ADD_TEST(test_public_accessors);
    ADD_TEST(test_provider_standard_name_is_null);
    ADD_TEST(test_conf_and_case);
    ADD_TEST(test_session_outlives_ctx);
    ADD_TEST(test_d2i_into_provider_session);
    ADD_TEST(test_multiple_providers_collide);
    ADD_TEST(test_concurrent_handshakes_prebuilt_contexts);
    ADD_TEST(test_concurrent_provider_discovery_reload);
    /* Keep last: tls-provider.c uses process-global test capability data. */
    ADD_TEST(test_provider_discovery_reload_lifecycle);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(tlsprov);
    OSSL_PROVIDER_unload(defprov);
    OSSL_LIB_CTX_free(libctx);
}

Provider-defined TLS 1.3 ciphersuites
=====================================

Scope
-----

The `TLS-CIPHERSUITE` capability adds TLS 1.3 ciphersuites to an `SSL_CTX`.
It is not used by TLS 1.2, DTLS or QUIC. Provider suites are absent from the
default list and require explicit selection.

DTLS 1.3 record-number encryption and QUIC header protection require a
companion algorithm derived from the ciphersuite. The capability declares no
such algorithm, so both protocols are excluded.

The capability adds public source API macros but no public function or ABI
symbol. Discovery after `SSL_CTX` creation and session resumption are not
supported.

Capability
----------

Every callback supplies these mandatory parameters. Unknown parameters are
ignored.

| Parameter | Type | Constraint |
|-----------|------|------------|
| `tls-ciphersuite-name` | UTF8 | Bytes 0x21--0x7e except colon, 1--255 bytes, unique ignoring case across built-in OpenSSL names, standard names and provider names |
| `tls-ciphersuite-code-point` | unsigned integer | Nonzero 16-bit value, not GREASE, unique in the context and not used by a built-in suite |
| `tls-ciphersuite-aead-name` | UTF8 | AEAD fetch name, 1--255 bytes; reported key length from 1 through `EVP_MAX_KEY_LENGTH`, 12-byte IV, block size 1, non-CCM; AES-128-GCM reports 16 bytes and AES-256-GCM or ChaCha20-Poly1305 reports 32 bytes |
| `tls-ciphersuite-digest-name` | UTF8 | Fetch name of 1--255 bytes; SHA2-256 with 32-byte output or SHA2-384 with 48-byte output |
| `tls-ciphersuite-security-bits` | unsigned integer | 128 or more; no greater than the AEAD key size |
| `tls-ciphersuite-tag-length` | unsigned integer | 16 |

String parameters contain the exact string bytes, with or without one final
NUL. Embedded NULs and trailing bytes are invalid.
Unsigned integer parameters use between 1 and 8 data bytes.

This version supports the existing stream TLS 1.3 record shape: a 12-byte IV,
16-byte tag, and SHA-256 or SHA-384 transcript digest. Other nonce, tag, and
digest profiles require a separate record-layer contract. Discovery checks
metadata; it does not execute record operations. The provider declares the tag
length because `EVP_CIPHER` has no general static tag-length accessor.
Successful context creation therefore does not guarantee that record setup or
the first record operation will succeed. Libssl derives and supplies the key
length reported by the fetched cipher; discovery does not prove that the
cipher rejects other lengths.

A provider AEAD must refuse an encryption that would exceed an
algorithm-specific per-key sending limit. The record layer treats cipher
failure as fatal. This capability does not expose a threshold for proactive
KeyUpdate; an AEAD that
cannot enforce its limit by refusing encryption is unsupported.
Provider suites do not use kTLS because offload would bypass the provider AEAD.

Code points are not restricted to Private Use because an allocated suite may
also be supplied by a provider. A deployment without an allocation should use
Private Use. Libssl rejects GREASE values and collisions but does not determine
allocation status.

Libssl fetches the AEAD and digest using the context library context and
property query and retains both objects. The implementations need not come
from the provider that advertises the suite. This follows TLS-GROUP's
name-based availability check and permits provider composition.

Discovery
---------

Discovery runs during `SSL_CTX_new_ex()` for methods that can negotiate TLS
1.3. The owned descriptors are sorted by wire ID and a shallow name index is
built for binary lookup. The registry is then immutable. A provider that does
not implement the capability, or implements it with no entries, does not
affect context creation.

An entry whose AEAD or digest cannot be fetched under the context property
query is skipped. A malformed entry, a collision, a profile violation, or a
provider that aborts after supplying an entry causes context creation to fail.
Allocation and registry failures are also fatal.
Failing context creation prevents descriptor order from determining a partial
registry.

Selection and context changes
-----------------------------

`SSL_CTX_set_ciphersuites()` and `SSL_set_ciphersuites()` select a provider
suite by its capability name. `SSL_CIPHER_get_name()` returns this name.
The capability does not supply a standard name, so
`SSL_CIPHER_standard_name()` returns `NULL`.

Wire IDs resolve through the connection's original `session_ctx`.
`SSL_set_SSL_CTX()` keeps its existing behavior. Switching to a context with
a provider suite requires the same fetched cipher and digest implementations
and equivalent metadata in both contexts. A different resolved implementation
fails closed. The suite must also remain enabled in the connection's
ciphersuite list.

Ownership and sessions
----------------------

The context registry owns each descriptor. A descriptor retains its AEAD and
digest. `SSL_SESSION` holds a counted descriptor reference; other SSL stacks
borrow descriptors kept alive by `session_ctx`.

Once a session has held a provider suite, it cannot be resumed, cached,
serialised or ticketed. This state survives session duplication and later
cipher assignment. A successful `d2i_SSL_SESSION()` clears the provider-cipher
marker but preserves any existing `not_resumable` state.

Stream TLS 1.3 external-PSK callbacks may explicitly supply a session
containing a provider suite, including for 0-RTT. DTLS and QUIC reject such
sessions.
The session remains ineligible for
`SSL_set_session()`, caches, serialisation and tickets. A session produced by
the completed connection remains subject to the same restrictions.

Public `SSL_CIPHER` pointers are borrowed. Values returned by
`SSL_CIPHER_find()`, `SSL_get1_supported_ciphers()` and
`SSL_bytes_to_cipher_list()` remain valid only while the originating `SSL`
exists. `SSL_SESSION_set_cipher()` retains a provider descriptor.
`SSL_SESSION_get0_cipher()` remains valid until the session is freed, its
cipher is replaced, or an in-place session decode succeeds.

Deferred work
-------------

An optional provider-origin restriction may be considered. The default must
continue to permit composition through the `SSL_CTX` library context and
property query.

Discovery work grows linearly with the number of descriptors. Lookup uses
sorted stacks after discovery. A descriptor limit requires a defined bound and
failure policy.

Stronger AEAD compatibility probing requires a defined, side-effect-free EVP
contract. Metadata checks do not prove that record operations will succeed.

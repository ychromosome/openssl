Provider-defined TLS 1.3 ciphersuites
=====================================

Scope
-----

The `TLS-CIPHERSUITE` capability adds TLS 1.3 ciphersuites to an `SSL_CTX`.
It is not used by TLS 1.2, DTLS or QUIC. Provider suites are absent from the
default list and require explicit selection.

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
| `tls-ciphersuite-aead-name` | UTF8 | AEAD fetch name; fixed positive key length no greater than `EVP_MAX_KEY_LENGTH`, 12-byte IV, block size 1, non-CCM |
| `tls-ciphersuite-digest-name` | UTF8 | SHA2-256 or SHA2-384 fetch name |
| `tls-ciphersuite-security-bits` | unsigned integer | 128 or more; no greater than the AEAD key size |
| `tls-ciphersuite-tag-length` | unsigned integer | 16 |

String parameters contain the exact string bytes, with or without one final
NUL. Embedded NULs and trailing bytes are invalid.

The AEAD profile has the TLS 1.3 fixed-expansion shape. It must support the
IV-length, tag, AAD, in-place encryption and in-place decryption operations
used by `ssl/record/methods/tls13_meth.c`. Discovery checks metadata; it does
not execute these operations. The provider declares the tag length because
`EVP_CIPHER` has no general static tag-length accessor.

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

Selection and context changes
-----------------------------

`SSL_CTX_set_ciphersuites()` and `SSL_set_ciphersuites()` select a provider
suite by its capability name. `SSL_CIPHER_get_name()` returns this name.
The capability does not supply a standard name, so
`SSL_CIPHER_standard_name()` returns `NULL`.

Wire IDs resolve through the connection's original `session_ctx`.
`SSL_set_SSL_CTX()` keeps its existing behavior. Switching to a context with
a different library context or property query is outside this version's
scope.

Ownership and sessions
----------------------

The context registry owns each descriptor. A descriptor retains its AEAD and
digest. `SSL_SESSION` holds a counted descriptor reference; other SSL stacks
borrow descriptors kept alive by `session_ctx`.

Once a session has held a provider suite, it cannot be resumed, cached,
serialised or ticketed. This state survives session duplication and later
cipher assignment. A successful `d2i_SSL_SESSION()` replaces the logical
session with its decoded built-in state.

TLS 1.3 external-PSK callbacks may explicitly supply a session containing a
provider suite, including for 0-RTT. The session remains ineligible for
`SSL_set_session()`, caches, serialisation and tickets. A session produced by
the completed connection remains subject to the same restrictions.

Public `SSL_CIPHER` pointers are borrowed. Values returned by
`SSL_CIPHER_find()`, `SSL_get1_supported_ciphers()` and
`SSL_bytes_to_cipher_list()` remain valid only while the originating `SSL`
exists. `SSL_SESSION_set_cipher()` retains a provider descriptor, and
`SSL_SESSION_get0_cipher()` remains valid for the session lifetime.

Deferred work
-------------

Per-suite record limits need a generic specification-backed contract and
enforcement across every record path. This version adds neither.

An optional provider-origin restriction may be considered. The default must
continue to permit composition through the `SSL_CTX` library context and
property query.

Provider suites across `SSL_set_SSL_CTX()` calls with different library
contexts or property queries remain out of scope.

The registry uses sorted stacks. A descriptor limit requires a defined bound
and failure policy.

Libssl cannot validate live IANA allocation state. Code-point policy remains
the responsibility of the provider and deployment.

Stronger AEAD compatibility probing requires a defined, side-effect-free EVP
contract. Metadata checks do not prove that record operations will succeed.

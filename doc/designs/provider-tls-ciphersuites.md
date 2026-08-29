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
| `tls-ciphersuite-name` | UTF8 | Printable ASCII, 1--255 bytes, no colon, unique ignoring case |
| `tls-ciphersuite-code-point` | unsigned integer | Nonzero 16-bit value, not GREASE, unique in the context and not assigned to a built-in suite |
| `tls-ciphersuite-aead-name` | UTF8 | AEAD fetch name; fixed positive key length no greater than `EVP_MAX_KEY_LENGTH`, 12-byte IV, block size 1, non-CCM |
| `tls-ciphersuite-digest-name` | UTF8 | SHA2-256 or SHA2-384 fetch name |
| `tls-ciphersuite-security-bits` | unsigned integer | 128 or more; no greater than the AEAD key size |
| `tls-ciphersuite-tag-length` | unsigned integer | 16 |

The AEAD profile has the TLS 1.3 fixed-expansion shape: no length pre-set and
a 16-byte authentication tag. The provider declares the tag length because
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
cipher replacement. `d2i_SSL_SESSION()` resolves built-in suites only.

Record usage limits remain governed by libssl's existing TLS 1.3 behavior.
This capability does not add per-suite limits.

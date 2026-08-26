Provider-defined TLS 1.3 ciphersuites
=====================================

Overview
--------

The `TLS-CIPHERSUITE` capability adds provider-defined TLS 1.3 ciphersuites to
an `SSL_CTX`.  Providers supply the wire ID, security bits and EVP algorithm
names.  Libssl retains the fetched algorithms and owns the TLS 1.3 key schedule
and record layer.

Provider ciphersuites are discovered during `SSL_CTX_new_ex()`, require
explicit selection and are not available to TLS 1.2, DTLS or QUIC.  Sessions
using them cannot be resumed, cached or serialised and do not issue tickets.

No public API or ABI symbol is added.  Resumption, write limits, QUIC, kTLS,
custom record methods and discovery after context creation are out of scope.

Capability
----------

Each callback describes one ciphersuite.  The following parameters are
mandatory; unknown parameters are ignored.

| Parameter | Type | Constraint |
|-----------|------|------------|
| `tls-ciphersuite-name` | UTF8 | Printable ASCII, 1--255 bytes, no colon, unique ignoring case |
| `tls-ciphersuite-code-point` | unsigned integer | Nonzero 16-bit value; no GREASE or collision |
| `tls-ciphersuite-aead-name` | UTF8 | Fetchable fixed-length AEAD; 12-byte IV, 16-byte tag, block size 1, non-CCM |
| `tls-ciphersuite-digest-name` | UTF8 | Fetchable SHA2-256 or SHA2-384 |
| `tls-ciphersuite-security-bits` | unsigned integer | At least 128 and no greater than the AEAD key size |

Libssl fetches the `EVP_CIPHER` and `EVP_MD` with the `SSL_CTX` library context
and property query and retains both objects.  The implementations need not
come from the provider advertising the capability.  This follows TLS-GROUP
name and property lookup rather than TLS-SIGALG origin matching.

Discovery
---------

The registry is populated while the `SSL_CTX` is created and is immutable
afterwards.  Providers loaded later are not added to an existing context.

| Callbacks | Validation failure | Provider return | Result |
|-----------|--------------------|-----------------|--------|
| none | no | 0 or 1 | Continue |
| one or more | no | 1 | Accept |
| any | yes | any | Fail context creation |
| one or more | no | 0 | Fail context creation |

A provider that does not implement the capability is ignored, as for
TLS-SIGALG.  Once a provider returns a descriptor, invalid data or an aborted
enumeration fails context creation.  `SSL_CTX` cleanup releases any partial
registry.

Discovery is method-independent.  DTLS and QUIC contexts can contain a
registry, but their lookup paths do not expose its entries.

Selection
---------

`SSL_CTX_set_ciphersuites()` and `SSL_set_ciphersuites()` select provider
ciphersuites by name.  The default list is unchanged.  Wire IDs are resolved
against the connection's original `session_ctx` registry after the built-in
lookup.

Descriptors are local to an `SSL_CTX`.  Dynamic list matching uses the wire ID
and canonicalises the result to `session_ctx`.  Built-in suites retain
pointer-identity matching.

Ownership
---------

The context registry owns each dynamic descriptor.  A descriptor owns its
fetched cipher and digest.  An `SSL_SESSION` can hold a counted descriptor
reference.  Other SSL-side stacks borrow descriptors canonicalised to the
registry kept alive by the connection's `session_ctx` reference.  Refcount
operations remain no-ops for static table entries.

Stored dynamic descriptors are either in the `session_ctx` registry, held by an
`SSL_SESSION` reference, or borrowed through a stack owned by the descriptor's
context.

`SSL_set_SSL_CTX()`
-------------------

`SSL_set_SSL_CTX()` keeps its existing behaviour.  Provider ciphersuites
continue to resolve through `session_ctx`; no context-equivalence policy is
added.  Switching to a context with a different library context or property
query remains out of scope.  A context that lacks the suite fails cleanly.

Sessions
--------

Assigning a provider ciphersuite sets a marker that survives session
duplication and later assignment of a built-in cipher.  The marker is not
encoded in ASN.1.  It prevents resumption, automatic and direct cache
insertion, serialisation and automatic or explicit ticket generation.

`d2i_SSL_SESSION()` resolves only built-in ciphersuites and cannot create a
marked session.

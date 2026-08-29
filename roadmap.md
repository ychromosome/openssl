# Provider TLS ciphersuite follow-up

These items are outside the initial implementation. They require a separate
design and review before code is added.

## Per-suite record limits

Allow a suite to declare confidentiality and integrity limits. Proceed only
with a generic contract tied to the relevant TLS specifications and enforcement
that cannot be bypassed by another record path.

## Optional provider-origin restriction

Consider an opt-in policy that requires the advertised AEAD and digest to come
from a selected provider. The default must continue to allow provider
composition through the `SSL_CTX` library context and property query.

## Cross-library-context switching

Define provider-suite behavior when `SSL_set_SSL_CTX()` switches to a context
with a different library context or property query. Coordinate this with any
future replacement or deprecation plan for that API.

## Registry limit

Wire-ID and name lookups use sorted OpenSSL stacks. Add a descriptor limit only
if a policy defines the bound and the `SSL_CTX_new_ex()` failure behavior.

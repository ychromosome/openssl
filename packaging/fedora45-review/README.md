# Fedora 45 review RPM

This packaging pins OpenSSL commit
`7d9c89d9fe4ee02f62f6d80df06fc031d352284d` and Fedora 45 dist-git commit
`07e26394a799dee4210c52c320487f84b96cb45d`.

Run `generate-source.sh` from this repository before using the spec. Build in
an isolated Fedora 45 environment. The resulting EVR is
`1:4.1.0~dev.1-0.3.git7d9c89d.fc45`.

Patch `0017-Fix-evp-extra-nondefault-libctx.patch` affects tests only. The other
patches derive from the pinned Fedora dist-git tree.

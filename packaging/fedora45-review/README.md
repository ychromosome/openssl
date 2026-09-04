# Fedora 45 review RPM

This packaging pins OpenSSL commit
`9bbfc53b7af48db30db455ed10f20782470e03a7` and Fedora 45 dist-git commit
`07e26394a799dee4210c52c320487f84b96cb45d`.

From the repository root, generate the pinned source archive:

```sh
packaging/fedora45-review/generate-source.sh
```

The archive is written to `packaging/fedora45-review/SOURCES/`. Build in an
isolated Fedora 45 environment. The resulting EVR is
`1:4.1.0~dev.1-0.4.git9bbfc53.fc45`.

Patch `0017-Fix-evp-extra-nondefault-libctx.patch` affects tests only. The other
patches derive from the pinned Fedora dist-git tree.

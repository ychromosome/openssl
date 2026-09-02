#!/bin/sh
set -eu

commit=7d9c89d9fe4ee02f62f6d80df06fc031d352284d
expected=f22fef688323db38bc73ea2ea84ce4bbd4646573af05b29d7587718ed4fe810b
repository=${1:-$(git rev-parse --show-toplevel)}
output=${2:-SOURCES/openssl-4.1.0~dev.1.tar.gz}

test "$(git -C "$repository" rev-parse "${commit}^{commit}")" = "$commit"
git -C "$repository" archive --format=tar \
    --prefix=openssl-4.1.0~dev.1/ "$commit" | gzip -9 -n >"$output"
test "$(sha256sum "$output" | awk '{ print $1 }')" = "$expected"

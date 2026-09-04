#!/bin/sh
set -eu

commit=9bbfc53b7af48db30db455ed10f20782470e03a7
expected=825f72b650f829fa2184f80ef50a48f17da910290c1f52ff265257bbef8f377f
repository=${1:-$(git rev-parse --show-toplevel)}
output=${2:-SOURCES/openssl-4.1.0~dev.1.tar.gz}

test "$(git -C "$repository" rev-parse "${commit}^{commit}")" = "$commit"
git -C "$repository" archive --format=tar \
    --prefix=openssl-4.1.0~dev.1/ "$commit" | gzip -9 -n >"$output"
test "$(sha256sum "$output" | awk '{ print $1 }')" = "$expected"

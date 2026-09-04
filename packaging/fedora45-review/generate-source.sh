#!/bin/sh
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
commit=9bbfc53b7af48db30db455ed10f20782470e03a7
expected=825f72b650f829fa2184f80ef50a48f17da910290c1f52ff265257bbef8f377f
repository=${1:-$(git -C "$here" rev-parse --show-toplevel)}
output=${2:-$here/SOURCES/openssl-4.1.0~dev.1.tar.gz}

test "$(git -C "$repository" rev-parse "${commit}^{commit}")" = "$commit"
git -C "$repository" archive --format=tar \
    --prefix=openssl-4.1.0~dev.1/ "$commit" | gzip -9 -n >"$output"
test "$(sha256sum "$output" | awk '{ print $1 }')" = "$expected"

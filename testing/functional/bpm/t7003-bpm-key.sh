#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHIRUDO=${SHIRUDO:-../shirudo}

command -v python3 >/dev/null 2>&1 || test_skip_all 'python3 unavailable'
command -v openssl >/dev/null 2>&1 || test_skip_all 'openssl unavailable'

if unshare --mount --propagation private true 2>/dev/null; then
	test_expect_success 'bpm installs keys and repository certificates in private directories' '
		python3 helper/test-bpm-key.py "$SHIRUDO" --isolated-keys
	'
else
	echo "# private mount namespace unavailable, skipping key installation cases"
	test_expect_success 'bpm keys fingerprint certificates, packages, and OCI references' '
		python3 helper/test-bpm-key.py "$SHIRUDO"
	'
fi

test_done

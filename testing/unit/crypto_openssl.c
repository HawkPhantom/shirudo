// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "crypto.h"
#include "hex.h"
#include "unit.h"

static void sha256_matches_fips_180_vector(void)
{
	static const char want[] =
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	char hex[2 * CRYPTO_SHA256_LEN + 1];
	__u8 d[CRYPTO_SHA256_LEN];

	ASSERT_EQ(sha256_buffer("abc", 3, d), 0);
	hex_encode(d, sizeof(d), hex);
	EXPECT_STREQ(hex, want);
}

static void sha256_buffer_zeroes_a_failed_digest(void)
{
	__u8 out[CRYPTO_SHA256_LEN], zero[CRYPTO_SHA256_LEN] = {};

	memset(out, 0xff, sizeof(out));
	EXPECT_NE(sha256_buffer(NULL, 3, out), 0);
	EXPECT_MEMEQ(out, zero, sizeof(out));
}

static EVP_PKEY *keygen(const char *alg)
{
	EVP_PKEY *key;

	if (!strcmp(alg, "EC"))
		key = EVP_EC_gen("P-256");
	else
		key = EVP_PKEY_Q_keygen(NULL, NULL, alg);
	ASSERT_TRUE(key);
	return key;
}

/* With a subject key identifier, which a keyid signer is named by. */
static X509 *self_signed(EVP_PKEY *key)
{
	const EVP_MD *md = EVP_PKEY_is_a(key, "EC") ? EVP_sha256() : NULL;
	X509V3_CTX ctx = {};
	X509 *x = X509_new();
	X509_EXTENSION *ski;
	X509_NAME *name;

	ASSERT_TRUE(x);
	ASSERT_EQ(X509_set_version(x, X509_VERSION_3), 1);
	ASSERT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(x), 1), 1);
	ASSERT_TRUE(X509_gmtime_adj(X509_getm_notBefore(x), 0));
	ASSERT_TRUE(X509_gmtime_adj(X509_getm_notAfter(x), 86400));
	ASSERT_EQ(X509_set_pubkey(x, key), 1);
	name = X509_get_subject_name(x);
	ASSERT_EQ(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
					     (const __u8 *)"unit", -1, -1, 0), 1);
	ASSERT_EQ(X509_set_issuer_name(x, name), 1);
	X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
	ski = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier,
				  "hash");
	ASSERT_TRUE(ski);
	ASSERT_EQ(X509_add_ext(x, ski, -1), 1);
	X509_EXTENSION_free(ski);
	ASSERT_TRUE(X509_sign(x, key, md) > 0);
	return x;
}

/* The DER of x, which the caller frees with OPENSSL_free(). */
static size_t der_of(X509 *x, __u8 **der)
{
	int len;

	*der = NULL;
	len = i2d_X509(x, der);
	ASSERT_TRUE(len > 0);
	return (size_t)len;
}

static void read_cert(X509 *x, struct cert *cert)
{
	__u8 *der;
	size_t len;

	len = der_of(x, &der);
	ASSERT_EQ(cert_read_der(der, len, cert), 0);
	OPENSSL_free(der);
}

/* cert_der_require_mldsa87() on a self-signed certificate of alg. */
static int require_mldsa87(const char *alg, char *name, size_t name_sz)
{
	EVP_PKEY *key = keygen(alg);
	X509 *x = self_signed(key);
	__u8 *der;
	size_t len;
	int ret;

	len = der_of(x, &der);
	ret = cert_der_require_mldsa87(der, len, name, name_sz);
	OPENSSL_free(der);
	X509_free(x);
	EVP_PKEY_free(key);
	return ret;
}

static void cert_require_mldsa87_accepts_ml_dsa_87_only(void)
{
	static const struct {
		const char	*alg;
		int		ret;
	} keys[] = {
		{ "ML-DSA-87", 0 },
		{ "ML-DSA-65", -EKEYREJECTED },
		{ "EC", -EKEYREJECTED },
	};
	size_t i;

	EXPECT_EQ(cert_require_mldsa87(NULL, NULL, 0), -EKEYREJECTED);
	EXPECT_EQ(cert_require_mldsa87(NULL, NULL, 32), -EKEYREJECTED);
	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		EVP_PKEY *key = keygen(keys[i].alg);
		X509 *x = self_signed(key);
		struct cert cert = {};

		read_cert(x, &cert);
		EXPECT_EQ(cert_require_mldsa87(&cert, NULL, 0), keys[i].ret);
		cert_free(&cert);
		X509_free(x);
		EVP_PKEY_free(key);
	}
}

static void cert_der_require_mldsa87_names_a_refused_algorithm(void)
{
	static const __u8 no_cert[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
	char name[32] = {};
	int ret;

	EXPECT_EQ(require_mldsa87("ML-DSA-87", name, sizeof(name)), 0);
	EXPECT_STREQ(name, "");
	EXPECT_EQ(require_mldsa87("ML-DSA-65", name, sizeof(name)),
		  -EKEYREJECTED);
	EXPECT_STREQ(name, "ML-DSA-65");
	EXPECT_EQ(require_mldsa87("EC", name, sizeof(name)), -EKEYREJECTED);
	EXPECT_STREQ(name, "EC");
	ret = cert_der_require_mldsa87(no_cert, sizeof(no_cert), name,
				       sizeof(name));
	EXPECT_NE(ret, 0);
	EXPECT_NE(ret, -EKEYREJECTED);
}

static const struct unit_case cases[] = {
	UNIT_CASE(sha256_matches_fips_180_vector),
	UNIT_CASE(sha256_buffer_zeroes_a_failed_digest),
	UNIT_CASE(cert_require_mldsa87_accepts_ml_dsa_87_only),
	UNIT_CASE(cert_der_require_mldsa87_names_a_refused_algorithm),
	{}
};

UNIT_SUITE(crypto_openssl, cases);

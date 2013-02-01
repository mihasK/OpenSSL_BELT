/*
 * belt_pmeth.c
 *
 *  Created on: 01.02.2013
 *      Author: denis
 */

#include "belt.h"

struct belt_mac_pmeth_data {
	int key_set;
	EVP_MD *md;
	unsigned char key[BELT_CIPHER_KEY_SIZE];
};

static int pkey_belt_mac_init(EVP_PKEY_CTX *ctx);
static void pkey_belt_mac_cleanup(EVP_PKEY_CTX *ctx);
static int pkey_belt_mac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);

static int pkey_belt_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

static int pkey_belt_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
static int pkey_belt_mac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
		size_t *siglen, EVP_MD_CTX *mctx);

int pkey_belt_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
int pkey_belt_mac_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
		const char *value);

EVP_PKEY_METHOD belt_pmeth_mac = {

	NID_undef,
	0, /* flags */

	pkey_belt_mac_init, /* init */
	pkey_belt_mac_copy, /* copy */
	pkey_belt_mac_cleanup, /* cleanup */

	NULL, /* paramgen_init */
	NULL, /* paramgen */

	NULL, /* keygen_init */
	pkey_belt_mac_keygen, /* keygen */

	NULL, /* sign_init */
	NULL, /* sign */

	NULL, /* verify_init */
	NULL, /* verify */

	NULL, /* verify_recover_init */
	NULL, /* verify_recover */

	pkey_belt_mac_signctx_init, /* signctx_init */
	pkey_belt_mac_signctx, /* signctx */

	NULL, /* verifyctx_init */
	NULL, /* verifyctx */

	NULL, /* encrypt_init */
	NULL, /* encrypt */

	NULL, /* decrypt_init */
	NULL, /* decrypt */

	NULL, /* derive_init */
	NULL, /* derive */

	pkey_belt_mac_ctrl, /* ctrl */
	pkey_belt_mac_ctrl_str /* ctrl_str */
};

static int pkey_belt_mac_init(EVP_PKEY_CTX *ctx) {
	struct belt_mac_pmeth_data *data;
	data = OPENSSL_malloc(sizeof(struct belt_mac_pmeth_data));
	if (!data) {
		return 0;
	}
	memSetZero(data, sizeof(struct belt_mac_pmeth_data));
	EVP_PKEY_CTX_set_data(ctx, data);
	return 1;
}

static void pkey_belt_mac_cleanup(EVP_PKEY_CTX *ctx) {
	struct belt_mac_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
	memSetZero(data, sizeof(struct belt_mac_pmeth_data));
	OPENSSL_free(data);
}

static int pkey_belt_mac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) {
	struct belt_mac_pmeth_data *dst_data, *src_data;
	if (!pkey_belt_mac_init(dst)) {
		return 0;
	}
	src_data = EVP_PKEY_CTX_get_data(src);
	dst_data = EVP_PKEY_CTX_get_data(dst);
	*dst_data = *src_data;
	return 1;
}

static int pkey_belt_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
	struct belt_mac_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
	unsigned char *keydata;
	if (!data->key_set) {
		// TODO: handle errors
		printf("MAC key don't set");
		return 0;
	}
	keydata = OPENSSL_malloc(BELT_CIPHER_KEY_SIZE);
	memCopy(keydata, data->key, BELT_CIPHER_KEY_SIZE);
	EVP_PKEY_assign(pkey, belt_imit.type, keydata);
	return 1;
}

static int pkey_belt_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
	return 1;
}

static int pkey_belt_mac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
		size_t *siglen, EVP_MD_CTX *mctx) {
	unsigned int tmpsiglen = *siglen; /* for platforms where sizeof(int)!=sizeof(size_t)*/
	int ret;
	if (!sig) {
		*siglen = BELT_IMIT_RESULT_SIZE;
		return 1;
	}
	ret = EVP_DigestFinal_ex(mctx, sig, &tmpsiglen);
	*siglen = tmpsiglen;
	return ret;
}

/*
 * belt_pmeth.c
 *
 *  Created on: 01.02.2013
 *      Author: denis
 */

#include "belt.h"
#include "belt_mac.h"
#include <openssl/x509v3.h> /*For string_to_hex */

static int pkey_belt_mac_init(EVP_PKEY_CTX *ctx);
static void pkey_belt_mac_cleanup(EVP_PKEY_CTX *ctx);
static int pkey_belt_mac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);

static int pkey_belt_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);



static int pkey_belt_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
static int pkey_belt_mac_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
		const char *value);


#ifdef __belt_pmeth_static__
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
#endif

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

static int pkey_belt_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
	{
	struct belt_mac_pmeth_data *data =
(struct belt_mac_pmeth_data*)EVP_PKEY_CTX_get_data(ctx);

	switch (type)
		{
		case EVP_PKEY_CTRL_MD:
		{
		/*if (EVP_MD_type((const EVP_MD *)p2) != NID_id_Gost28147_89_MAC)
			{
			GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL, GOST_R_INVALID_DIGEST_TYPE);
			return 0;
			}*/
		data->md = (EVP_MD *)p2;
		return 1;
		}
		break;

		case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
		case EVP_PKEY_CTRL_PKCS7_DECRYPT:
		case EVP_PKEY_CTRL_PKCS7_SIGN:
			return 1;
		case EVP_PKEY_CTRL_SET_MAC_KEY:
			if (p1 != BELT_CIPHER_KEY_SIZE)
				{
				//TODO ERROR!
				return 0;
				}

			memcpy(data->key,p2,BELT_CIPHER_KEY_SIZE);
			data->key_set = 1;
			return 1;
		case EVP_PKEY_CTRL_DIGESTINIT:
			{
			EVP_MD_CTX *mctx = p2;
			void *key;
			if (!data->key_set)
				{
				EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
				if (!pkey)
					{
					//TODO ERROR!
					return 0;
					}
				key = EVP_PKEY_get0(pkey);
				if (!key)
					{
					//TODO ERROR!
					return 0;
					}
				} else {
				key = &(data->key);
				}
			return mctx->digest->md_ctrl(mctx,EVP_MD_CTRL_SET_KEY,BELT_CIPHER_KEY_SIZE,key);
			}
		}
	return -2;
	}



static int pkey_belt_mac_ctrl_str(EVP_PKEY_CTX *ctx,
	const char *type, const char *value)
	{
	if (!strcmp(type, "key"))
		{
		if (strlen(value)!=BELT_CIPHER_KEY_SIZE)
			{
			//TODO ERROR!
			return 0;
			}
		return pkey_belt_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY,
			BELT_CIPHER_KEY_SIZE,(char *)value);
		}
	if (!strcmp(type, "hexkey"))
		{
			long keylen;
			int ret;
			unsigned char *keybuf = string_to_hex(value, &keylen);
			if (keylen != BELT_CIPHER_KEY_SIZE)
				{
				//TODO ERROR!
				OPENSSL_free(keybuf);
				return 0;
				}
			ret = pkey_belt_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY,
				BELT_CIPHER_KEY_SIZE, keybuf);
			OPENSSL_free(keybuf);
			return ret;
		}
	return -2;
	}

int register_pmeth_belt(int id, EVP_PKEY_METHOD **pmeth, int flags) {
	*pmeth = EVP_PKEY_meth_new(id, flags);
	if (!*pmeth) return 0;

	if (id == belt_imit.type) {
		EVP_PKEY_meth_set_ctrl(*pmeth, pkey_belt_mac_ctrl,
				pkey_belt_mac_ctrl_str);
		EVP_PKEY_meth_set_signctx(*pmeth, pkey_belt_mac_signctx_init,
				pkey_belt_mac_signctx);
		EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_belt_mac_keygen);
		EVP_PKEY_meth_set_init(*pmeth, pkey_belt_mac_init);
		EVP_PKEY_meth_set_cleanup(*pmeth, pkey_belt_mac_cleanup);
		EVP_PKEY_meth_set_copy(*pmeth, pkey_belt_mac_copy);
		return 1;
	} else {
		/*Unsupported method*/
		return 0;
	}
}

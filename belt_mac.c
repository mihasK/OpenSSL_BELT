
/*
 * belt_pmeth.c
 *
 *  Created on: 01.02.2013
 *      Author: mihas
 */

#include "belt_mac.h"


int pkey_belt_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
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
			EVP_MD * pp = p2;
		data->md = pp;
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



int pkey_belt_mac_ctrl_str(EVP_PKEY_CTX *ctx,
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
	/*if (!strcmp(type, "hexkey"))
		{
			long keylen; int ret;
			unsigned char *keybuf=string_to_hex(value,&keylen);
			if (keylen != 32)
				{
				GOSTerr(GOST_F_PKEY_GOST_MAC_CTRL_STR,
					GOST_R_INVALID_MAC_KEY_LENGTH);
				OPENSSL_free(keybuf);
				return 0;
				}
			ret= pkey_gost_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY,
				32,keybuf);
			OPENSSL_free(keybuf);
			return ret;

		}
		*/
	return -2;
	}

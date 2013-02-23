
#include "bign.h"

#define param_ctrl_string "paramset"
#define EVP_PKEY_CTRL_BIGN_PARAMSET 1313

/* --------------------- control functions  ------------------------------*/
static int pkey_bign_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
	{
	struct bign_pmeth_data *pctx = (struct bign_pmeth_data*)EVP_PKEY_CTX_get_data(ctx);
	switch (type)
		{
		case EVP_PKEY_CTRL_MD:
		{
/*		if (EVP_MD_type((const EVP_MD *)p2) != NID_id_GostR3411_94)
			{
			GOSTerr(GOST_F_PKEY_GOST_CTRL, GOST_R_INVALID_DIGEST_TYPE);
			return 0;
			}*/
		pctx->md = (EVP_MD *)p2;
		return 1;
		}
		break;

		case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
		case EVP_PKEY_CTRL_PKCS7_DECRYPT:
		case EVP_PKEY_CTRL_PKCS7_SIGN:
		case EVP_PKEY_CTRL_DIGESTINIT:
#ifndef OPENSSL_NO_CMS
		case EVP_PKEY_CTRL_CMS_ENCRYPT:
		case EVP_PKEY_CTRL_CMS_DECRYPT:
		case EVP_PKEY_CTRL_CMS_SIGN:
#endif
			return 1;

		case EVP_PKEY_CTRL_BIGN_PARAMSET:
//			pctx->sign_param_nid = (int)p1;
			return 1;
		case EVP_PKEY_CTRL_SET_IV:
	//		pctx->shared_ukm=OPENSSL_malloc((int)p1);
		//	memcpy(pctx->shared_ukm,p2,(int) p1);
			return 1;
		case EVP_PKEY_CTRL_PEER_KEY:
			if (p1 == 0 || p1 == 1) /* call from EVP_PKEY_derive_set_peer */
				return 1;
//			if (p1 == 2)		/* TLS: peer key used? */
	//			return pctx->peer_key_used;
		//	if (p1 == 3)		/* TLS: peer key used! */
//				return (pctx->peer_key_used = 1);
//			return -2;
//		}
	return -2;
	}


static int pkey_bign_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
	{

	if(!strcmp(type, param_ctrl_string))
		{
		int param_nid=0;//TODO
		return pkey_gost_ctrl(ctx, EVP_PKEY_CTRL_BIGN_PARAMSET,
			param_nid, NULL);
		}
	return -2;
	}




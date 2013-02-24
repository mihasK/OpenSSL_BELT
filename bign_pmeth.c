
#include "bign.h"

#define param_ctrl_string "paramset"
#define EVP_PKEY_CTRL_BIGN_PARAMSET 1313

/*-------init, cleanup, copy - uniform for all algs  ---------------*/
/* Allocates new bign_pmeth_data structure and assigns it as data */
static int pkey_bign_init(EVP_PKEY_CTX *ctx)
	{
	struct bign_pmeth_data *data;
	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	data = OPENSSL_malloc(sizeof(struct bign_pmeth_data));
	if (!data) return 0;
	memset(data,0,sizeof(struct bign_pmeth_data));
	//TODO additional initiating (maybe OID)
	EVP_PKEY_CTX_set_data(ctx,data);
	return 1;
	}

/* Copies contents of bign_pmeth_data structure */
static int pkey_gost_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
	{
	struct bign_pmeth_data *dst_data,*src_data;
	if (!pkey_bign_init(dst)){
		return 0;
	}
	src_data = EVP_PKEY_CTX_get_data(src);
	dst_data = EVP_PKEY_CTX_get_data(dst);
	*dst_data = *src_data;
	return 1;
	}

/* Frees up bign_pmeth_data structure */
static void pkey_gost_cleanup (EVP_PKEY_CTX *ctx)
	{
	struct bign_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
	OPENSSL_free(data);
	}


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


/* Generates Bign key */
static int pkey_bign_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
	{

	//generate long-term parameters
	bign_params params;
	bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.3");

	//generate keys
	octet* priv_key, pub_key;//TODO mallocs
	bignGenKeypair(priv_key, pub_key, params NULL, NULL);


	fillBignKeyToPKEY(params, priv_key, pub_key, pkey);

	return 1;
	}

void fillBignKeyToPKEY(bign_params* params, octet* priv_key,octet* pub_key, EVP_PKEY *pkey) {
	//TODO implement filling
	//EVP_PKEY_assign(...
}

void fillPKEYtoBignKey(bign_params* params, octet* priv_key,octet* pub_key, EVP_PKEY *pkey) {
	//TODO implement filling
	//vice versa
}



static int pkey_bign_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbs_len)
	{

	EVP_PKEY *evp_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (!siglen) return 0;

	bign_params* params;
	octet* priv_key, pub_key;//TODO maloc
	fillPKEYtoBignKey(params, priv_key, pub_key, evp_pkey);

	octet* sign;//TODO maloc

	bignSign(sign, params, tbs, priv_key, NULL, NULL); //TODO control lengths???


	return 1;
	}

/* ------------------- verify callbacks ---------------------------*/

static int pkey_bign_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
	size_t siglen, const unsigned char *tbs, size_t tbs_len)
	{
	int ok = 0;
	EVP_PKEY* evp_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	bign_params* params;
	octet* priv_key, pub_key;//TODO maloc
	fillPKEYtoBignKey(params, priv_key, pub_key, evp_pkey);

	if(bignVerify(params, tbs, sig, pub_key) == ERR_SUCCESS) {//TODO check parameters order
		ok = 1;
	}
	return ok;
}


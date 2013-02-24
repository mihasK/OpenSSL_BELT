
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

	DSA* dsa = DSA_new();


	if (!pkey_gost94_paramgen(ctx,pkey)) return 0;
	dsa = EVP_PKEY_get0(pkey);
	gost_sign_keygen(dsa);
	return 1;
	}

void int fillBignKeyToDSA(bign_params* params, octet* priv_key,octet* pub_key, DSA* dsa) {
	//TODO implement filling
}
/* ----------- sign callbacks --------------------------------------*/

static int pkey_bign_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
	const unsigned char *tbs, size_t tbs_len)
	{
	DSA_SIG *unpacked_sig=NULL;
	EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (!siglen) return 0;
	if (!sig)
		{
		*siglen= BIGN_SIGNATURE_SIZE; /* better to check size of pkey->pkey.dsa-q */
		return 1;
		}
	unpacked_sig = bignSign()(tbs,tbs_len,EVP_PKEY_get0(pkey));
	if (!unpacked_sig)
		{
		return 0;
		}
	return pack_sign_cp(unpacked_sig,32,sig,siglen);
	}

/* ------------------- verify callbacks ---------------------------*/

static int pkey_gost94_cp_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
	size_t siglen, const unsigned char *tbs, size_t tbs_len)
	{
	int ok = 0;
	EVP_PKEY* pub_key = EVP_PKEY_CTX_get0_pkey(ctx);
	DSA_SIG *s=unpack_cp_signature(sig,siglen);
	if (!s) return 0;
	if (pub_key) ok = gost_do_verify(tbs,tbs_len,s,EVP_PKEY_get0(pub_key));
	DSA_SIG_free(s);
	return ok;
	}


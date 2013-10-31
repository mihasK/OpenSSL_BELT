/*
*******************************************************************************
\file btls_bign_ameth.c
\brief Форматы данных для алгоритмов bign
*******************************************************************************
\author (С) Олег Соловей, Денис Веремейчик, http://apmi.bsu.by
\created 2013.05.14
\version 2013.10.21
*******************************************************************************
*/

#ifndef OPENSSL_NO_CMS
#include <openssl/cms.h>
#endif
#include "btls_bign.h"

#include "btls_err.h"
#include "btls_oids.h"
#include "btls_utl.h"

static void reverseOctets(octet *out, const octet *in, int inSize) 
{
	int i, j;
	for (i = 0, j = inSize - 1; i < inSize; i++, j--) 
	{
		out[i] = in[j];
	}
	return;
}

/* performs computing public key from given params and private key */
static octet* computePublicKey(const bign_params *params, const octet *privKey) 
{
	octet *newPubKey;

	newPubKey = (octet*) OPENSSL_malloc(params->l / 4);
	if (newPubKey == NULL) return NULL;
	if (bignCalcPubkey(newPubKey, params, privKey) != ERR_SUCCESS)
	{
		OPENSSL_free(newPubKey);
		return NULL;
	}
	return newPubKey;
}

static ASN1_STRING *encode_bign_algor_params(const EVP_PKEY *key) 
{
	ASN1_STRING *params = NULL;
	BIGN_KEY_PARAMS *bkp = NULL;
	struct bign_key_data *key_data = NULL;
	int pkey_param_nid;

	params = ASN1_STRING_new();
	if (!params)
	{
		ERR_BTLS(BTLS_F_ENCODE_BIGN_ALGOR_PARAMS, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	bkp = BIGN_KEY_PARAMS_new();
	if (!bkp) 
	{
		ERR_BTLS(BTLS_F_ENCODE_BIGN_ALGOR_PARAMS, ERR_R_MALLOC_FAILURE);
		ASN1_STRING_free(params);
		return NULL;
	}

	key_data = (struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)key);
	if (!key_data)
	{
		ERR_BTLS(BTLS_F_ENCODE_BIGN_ALGOR_PARAMS, ERR_R_MALLOC_FAILURE);
		ASN1_STRING_free(params);
		BIGN_KEY_PARAMS_free(bkp);
		return NULL;
	}

	pkey_param_nid = key_data->param_nid;
	bkp->d.key_params = OBJ_nid2obj(pkey_param_nid);
	bkp->type = 0;
	params->length = i2d_BIGN_KEY_PARAMS(bkp, &params->data);
	if (params->length <= 0) 
	{
		ERR_BTLS(BTLS_F_ENCODE_BIGN_ALGOR_PARAMS, BTLS_R_BAD_KEY_PARAMETERS_FORMAT);
		ASN1_STRING_free(params);
		BIGN_KEY_PARAMS_free(bkp);
		return NULL;
	}
	params->type = V_ASN1_SEQUENCE;
	BIGN_KEY_PARAMS_free(bkp);
	return params;
}

/*
 * Parses BIGN algorithm parameters from X509_ALGOR and
 * modifies pkey setting NID and parameters
 */
static int decode_bign_algor_params(EVP_PKEY *pkey, X509_ALGOR *palg) 
{
	ASN1_OBJECT *palg_obj;
	int ptype;
	int pkey_nid, param_nid;
	void *_pval;
	ASN1_STRING *pval;
	const unsigned char *p;
	BIGN_KEY_PARAMS *bkp;
	struct bign_key_data *key_data = NULL;

	palg_obj = NULL;
	ptype = V_ASN1_UNDEF;
	pkey_nid = NID_undef;
	param_nid = NID_undef;
	pval = NULL;
	bkp = NULL;

	X509_ALGOR_get0(&palg_obj, &ptype, &_pval, palg);
	pval = (ASN1_STRING *) _pval;
	if (ptype != V_ASN1_SEQUENCE) 
	{
		ERR_BTLS(BTLS_F_DECODE_BIGN_ALGOR_PARAMS, BTLS_R_BAD_KEY_PARAMETERS_FORMAT);
		return 0;
	}
	p = pval->data;
	pkey_nid = OBJ_obj2nid(palg_obj); 

	bkp = d2i_BIGN_KEY_PARAMS(NULL, &p, pval->length);
	if (!bkp) 
	{
		ERR_BTLS(BTLS_F_DECODE_BIGN_ALGOR_PARAMS, BTLS_R_BAD_KEY_PARAMETERS_FORMAT);
		return 0;
	}
	param_nid = OBJ_obj2nid(bkp->d.key_params);
	BIGN_KEY_PARAMS_free(bkp);
	EVP_PKEY_set_type(pkey, pkey_nid);
	if (bign_nid == pkey_nid) 
	{
		key_data = (struct bign_key_data *) EVP_PKEY_get0(pkey);
		if (!key_data) 
		{
			key_data = (struct bign_key_data *) OPENSSL_malloc(sizeof(struct bign_key_data));
			if (!key_data) 
			{
				ERR_BTLS(BTLS_F_DECODE_BIGN_ALGOR_PARAMS, BTLS_R_MALLOC_FAILURE);
				return 0;
			}
			memSet(key_data, 0, sizeof(struct bign_key_data));
			if (!EVP_PKEY_btls_assign(pkey, pkey_nid, key_data))  return 0; 
		}
		if (!fill_bign_params(key_data, param_nid)) 
		{
			ERR_BTLS(BTLS_F_DECODE_BIGN_ALGOR_PARAMS, BTLS_R_UNSUPPORTED_PARAMETER_SET);
			return 0;
		}
	}

	return 1;
}


static int bign_set_priv_key(EVP_PKEY *pkey, octet *priv) 
{
	struct bign_key_data *key_data;
	int privKeyLength;

	if (bign_nid == EVP_PKEY_btls_base_id(pkey)) 
	{
		key_data = (struct bign_key_data *) EVP_PKEY_get0(pkey);
		privKeyLength = key_data->params.l / 4;
		if (key_data->privKey) 
		{
			OPENSSL_cleanse(key_data->privKey, privKeyLength);
			OPENSSL_free(key_data->privKey);
			key_data->privKey = NULL;
		}
		key_data->privKey = (octet*) OPENSSL_malloc(privKeyLength);
		if (!key_data->privKey) 
		{
			ERR_BTLS(BTLS_F_BIGN_SET_PRIV_KEY, BTLS_R_MALLOC_FAILURE);
			return 0;
		}
		memCopy(key_data->privKey, priv, privKeyLength);
		if (!EVP_PKEY_missing_parameters(pkey)) 
		{
			key_data->pubKey = computePublicKey(&key_data->params, key_data->privKey);
		}
	}
	else
	{
		ERR_BTLS(BTLS_F_BIGN_SET_PRIV_KEY, BTLS_R_INCOMPATIBLE_ALGORITHMS);
		return 0;
	}
	return 1;
}

static octet* bign_get_priv_key(const EVP_PKEY *pkey) 
{
	struct bign_key_data *key_data;
	if (bign_nid == EVP_PKEY_btls_base_id(pkey)) 
	{
		key_data = (struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)pkey);
		if (!key_data)  return NULL;
		return key_data->privKey;
	}
	return NULL ;
}

static int bign_get_priv_key_length(const EVP_PKEY *pkey) 
{
	struct bign_key_data *key_data;
	if (bign_nid == EVP_PKEY_btls_base_id(pkey)) 
	{
		key_data = (struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)pkey);
		if (!key_data) return 0;
		return key_data->params.l / 4;
	}
	return 0;
}

static int pkey_ctrl_bign(EVP_PKEY *pkey, int op, long arg1, void *arg2) 
{
	X509_ALGOR *alg1, *alg2;
	int nid;
	X509_ALGOR *alg;
	ASN1_STRING * params;

	switch (op) {
	case ASN1_PKEY_CTRL_PKCS7_SIGN:
		if (arg1 == 0) 
		{
			alg1 = NULL; alg2 = NULL;
			nid = EVP_PKEY_btls_base_id(pkey);
			PKCS7_SIGNER_INFO_get0_algs((PKCS7_SIGNER_INFO*) arg2, NULL, &alg1, &alg2);
			X509_ALGOR_set0(alg1, OBJ_nid2obj(belt_hash.type), V_ASN1_NULL, 0);
			if (nid == NID_undef) 
			{
				return (-1);
			}
			X509_ALGOR_set0(alg2, OBJ_nid2obj(nid), V_ASN1_NULL, 0);
		}
		return 1;
#ifndef OPENSSL_NO_CMS
	case ASN1_PKEY_CTRL_CMS_SIGN:
		if (arg1 == 0) 
		{
			alg1 = NULL, alg2 = NULL;
			nid = EVP_PKEY_btls_base_id(pkey);
			CMS_SignerInfo_get0_algs((CMS_SignerInfo *) arg2, NULL, NULL, &alg1,
					&alg2);
			X509_ALGOR_set0(alg1, OBJ_nid2obj(belt_hash.type), V_ASN1_NULL, 0);
			if (nid == NID_undef) 
			{
				return (-1);
			}
			X509_ALGOR_set0(alg2, OBJ_nid2obj(nid), V_ASN1_NULL, 0);
		}
		return 1;
#endif
	case ASN1_PKEY_CTRL_PKCS7_ENCRYPT:
		if (arg1 == 0) 
		{
			params = encode_bign_algor_params(pkey);
			if (!params) 
			{
				return -1;
			}
			PKCS7_RECIP_INFO_get0_alg((PKCS7_RECIP_INFO*) arg2, &alg);
			X509_ALGOR_set0(alg, OBJ_nid2obj(pkey->type), V_ASN1_SEQUENCE,
					params);
		}
		return 1;
#ifndef OPENSSL_NO_CMS
	case ASN1_PKEY_CTRL_CMS_ENVELOPE:
		if (arg1 == 0) 
		{
			params = encode_bign_algor_params(pkey);
			if (!params) 
			{
				return -1;
			}
			CMS_RecipientInfo_ktri_get0_algs((CMS_RecipientInfo *) arg2, NULL,
					NULL, &alg);
			X509_ALGOR_set0(alg, OBJ_nid2obj(pkey->type), V_ASN1_SEQUENCE,
					params);
		}
		return 1;
#endif
	case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
		*(int *) arg2 = belt_hash.type;
		return 2;
	}

	return -2;
}

/*----------------------- free function * ------------------------------*/
static void pkey_free_bign(EVP_PKEY *key) 
{
	struct bign_key_data *key_data;
	key_data = (struct bign_key_data *) EVP_PKEY_get0(key);
	if (key_data) 
	{
		if (key_data->privKey) 
		{
			OPENSSL_cleanse(key_data->privKey, key_data->params.l / 4);
			OPENSSL_free(key_data->privKey);
			key_data->privKey = NULL;
		}
		if (key_data->pubKey) 
		{
			OPENSSL_free(key_data->pubKey);
			key_data->pubKey = NULL;
		}
		OPENSSL_free(key_data);
		key->pkey.ptr = NULL;
	}
}

/* ------------------ private key functions  -----------------------------*/
static int priv_decode_bign(EVP_PKEY *pk, PKCS8_PRIV_KEY_INFO *p8inf) 
{
	const unsigned char *priv_key;
	int priv_len;
	int ret;
	X509_ALGOR *palg;
	ASN1_OBJECT *palg_obj;

	priv_key = NULL;
	priv_len = 0;
	ret = 0;
	palg = NULL;
	palg_obj = NULL;

	if (!PKCS8_pkey_get0(&palg_obj, &priv_key, &priv_len, &palg, p8inf)) 
	{
		ERR_BTLS(BTLS_F_PRIV_DECODE_BIGN, EVP_R_DECODE_ERROR);
		return 0;
	}
	if (!decode_bign_algor_params(pk, palg)) 
	{
		ERR_BTLS(BTLS_F_PRIV_DECODE_BIGN, EVP_R_DECODE_ERROR);
		return 0;
	}

	ret = bign_set_priv_key(pk, (octet*)priv_key);
	OPENSSL_cleanse((octet*)priv_key, priv_len);
	OPENSSL_free((octet*)priv_key);
	return ret;
}

static int priv_encode_bign(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk) 
{
	ASN1_OBJECT *algobj;
	ASN1_STRING *params;
	octet *privKey;
	int privKeyLength;
	octet *privKeyBuf = NULL;

	algobj = OBJ_nid2obj(EVP_PKEY_btls_base_id(pk));
	params = encode_bign_algor_params(pk);
	privKey = bign_get_priv_key(pk);
	privKeyLength = bign_get_priv_key_length(pk);
	privKeyBuf = (octet *) OPENSSL_malloc(privKeyLength);
	if (!privKeyBuf)
	{
		ERR_BTLS(BTLS_F_PRIV_ENCODE_BIGN, BTLS_R_MALLOC_FAILURE);
		return 0;
	}

	if (!params) 
	{
		ERR_BTLS(BTLS_F_PRIV_ENCODE_BIGN, EVP_R_ENCODE_ERROR);
		return 0;
	}

	memCopy(privKeyBuf, privKey, privKeyLength);
	return PKCS8_pkey_set0(p8, algobj, 0, V_ASN1_SEQUENCE, params, privKeyBuf, privKeyLength);
}

/* --------- printing keys --------------------------------*/

static void print_octets(BIO *out, octet *octets, int length) 
{
	int i;
	for (i = 0; i < length; i++) 
		BIO_printf(out, "%02X", octets[i]);
}

static int print_bign(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx, int type) 
{
	int param_nid;
	int max_indent;
	struct bign_key_data *key_data;
	int priv_key_length;
	octet *key;

	param_nid = NID_undef;
	max_indent = 128;
	key_data = (struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)pkey);
	priv_key_length = key_data->params.l / 4;

	if (type == 2) 
	{
		if (!BIO_indent(out, indent, max_indent))  return 0;
		BIO_printf(out, "Private key: ");
		key = bign_get_priv_key(pkey);
		if (!key) 
			BIO_printf(out, "<undefined)");
		 else 
			print_octets(out, key, priv_key_length);
		BIO_printf(out, "\n");
	}
	if (type >= 1) {
		if (!BIO_indent(out, indent, max_indent))  return 0;
		BIO_printf(out, "Public key: ");
		print_octets(out, key_data->pubKey, priv_key_length * 2);
		BIO_printf(out, "\n");
	}

	param_nid = key_data->param_nid;
	if (!BIO_indent(out, indent, max_indent))  return 0;
	BIO_printf(out, "Parameter set: %s\n", OBJ_nid2ln(param_nid));
	return 1;
}

static int param_print_bign(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx) 
{
	return print_bign(out, pkey, indent, pctx, 0);
}

static int pub_print_bign(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx) 
{
	return print_bign(out, pkey, indent, pctx, 1);
}

static int priv_print_bign(BIO *out, const EVP_PKEY *pkey, int indent, ASN1_PCTX *pctx) 
{
	return print_bign(out, pkey, indent, pctx, 2);
}

static int param_missing_bign(const EVP_PKEY *pk) 
{
	const struct bign_key_data *key_data = NULL;
	
	key_data = (const struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)pk);
	if (!key_data) return 1;
	if (key_data->param_nid == NID_undef) return 1;

	return 0;
}

static int param_copy_bign(EVP_PKEY *to, const EVP_PKEY *from) 
{
	struct bign_key_data *eto = NULL;
	const struct bign_key_data *efrom = NULL;

	eto = (struct bign_key_data *) EVP_PKEY_get0(to);
	efrom = (const struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)from);

	if (EVP_PKEY_btls_base_id(from) != EVP_PKEY_btls_base_id(to)) 
	{
		ERR_BTLS(BTLS_F_PARAM_COPY_BIGN, BTLS_R_INCOMPATIBLE_ALGORITHMS);
		return 0;
	}
	if (!efrom) 
	{
		ERR_BTLS(BTLS_F_PARAM_COPY_BIGN, BTLS_R_KEY_PARAMETERS_MISSING);
		return 0;
	}
	if (!eto) 
	{
		eto = (struct bign_key_data *) OPENSSL_malloc(sizeof (struct bign_key_data));
		if (!eto) 
		{
			ERR_BTLS(BTLS_F_PARAM_COPY_BIGN, BTLS_R_MALLOC_FAILURE);
			return 0;
		}
		memSet(eto, 0, sizeof (struct bign_key_data));
		if (EVP_PKEY_btls_assign(to, EVP_PKEY_btls_base_id(from), eto) <= 0) return 0;
	}
	eto->param_nid = efrom->param_nid;
	eto->params = efrom->params;
	if (eto->privKey) 
	{
		eto->pubKey = computePublicKey(&eto->params, eto->privKey);
		if (!eto->pubKey) 
		{
			ERR_BTLS(BTLS_F_PARAM_COPY_BIGN, BTLS_R_NO_PARAMETERS_SET);
			return 0;
		}
	}
	return 1;
}

static int param_cmp_bign(const EVP_PKEY *a, const EVP_PKEY *b) 
{
	const struct bign_key_data *data_a;
	const struct bign_key_data *data_b;

	data_a = (const struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)a);
	data_b = (const struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)b);
	
	if (data_a->param_nid == data_b->param_nid) 
		return 1;

	return 0;
}

/* ---------- Public key functions * --------------------------------------*/

static int pub_decode_bign(EVP_PKEY *pk, X509_PUBKEY *pub) 
{
	X509_ALGOR *palg;
	const unsigned char *pubkey_buf;
	ASN1_OBJECT *palgobj;
	int pub_len;
	octet *pub_key = NULL;
	struct bign_key_data *key_data;

	palg = NULL;
	pubkey_buf = NULL;
	palgobj = NULL;

	if (!X509_PUBKEY_get0_param(&palgobj, &pubkey_buf, &pub_len, &palg, pub))  return 0;
	
	//if(!btls_сhange_оbj_data(&palgobj, OID_bign)) 
	//{
	//	ERR_BTLS(BTLS_F_PUB_DECODE_BIGN, BTLS_R_DECODE_ERR);
	//	return 0;
	//}

	EVP_PKEY_btls_assign(pk, OBJ_obj2nid(palgobj), NULL);

	if (!decode_bign_algor_params(pk, palg)) 
	{
		ERR_BTLS(BTLS_F_PUB_DECODE_BIGN, BTLS_R_DECODE_ERR);
		return 0;
	}
	pub_key = (octet *) OPENSSL_malloc(pub_len);
	if (!pub_key) 
	{
		ERR_BTLS(BTLS_F_PUB_DECODE_BIGN, BTLS_R_MALLOC_FAILURE);
		return 0;
	}
	memCopy(pub_key, pubkey_buf, pub_len);

	key_data = (struct bign_key_data *) EVP_PKEY_get0(pk);
	key_data->pubKey = pub_key;

	return 1;
}

static int pub_encode_bign(X509_PUBKEY *pub, const EVP_PKEY *pk) 
{
	ASN1_OBJECT *algobj;
	void *pval;
	octet *pub_key;
	struct bign_key_data *key_data;
	int ptype;
	int pub_key_length;
	octet *pub_key_buf = NULL;

	algobj = NULL;
	pval = NULL;
	pub_key = NULL;
	key_data = (struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)pk);
	ptype = V_ASN1_UNDEF;

	algobj = OBJ_nid2obj(EVP_PKEY_btls_base_id(pk));
	//algobj = ASN1_OBJECT_new();
	//memSet(algobj, 0, sizeof(ASN1_OBJECT));
	//algobj->nid = EVP_PKEY_btls_base_id(pk);
	//algobj->ln = LN_bign; /* LN_bign_pubkey; */
	//algobj->sn = SN_bign; /* SN_bign_pubkey; */
	//algobj->flags = ASN1_OBJECT_FLAG_DYNAMIC | ASN1_OBJECT_FLAG_DYNAMIC_DATA; 
	//if(!btls_сhange_оbj_data(&algobj, OID_bign_pubkey)) 
	//{
	//	ERR_BTLS(BTLS_F_PUB_ENCODE_BIGN, BTLS_R_ENCODE_ERR);
	//	return 0;
	//}

	if (pk->save_parameters) 
	{
		ASN1_STRING *params = encode_bign_algor_params(pk);
		if (params == NULL)
		{
			ERR_BTLS(BTLS_F_PUB_ENCODE_BIGN, BTLS_R_ENCODE_ERR);
			return 0;
		}
		pval = params;
		ptype = V_ASN1_SEQUENCE; 
	}
	pub_key = key_data->pubKey;
	if (!pub_key)  return 0;

	pub_key_length = key_data->params.l / 2;
	pub_key_buf = (octet *) OPENSSL_malloc(pub_key_length);
	if (!pub_key_buf) 
	{	
		ERR_BTLS(BTLS_F_PUB_ENCODE_BIGN, BTLS_R_MALLOC_FAILURE);
		return 0;
	}
	memCopy(pub_key_buf, pub_key, pub_key_length);

	return X509_PUBKEY_set0_param(pub, algobj, ptype, pval, pub_key_buf, pub_key_length);
}

static int pub_cmp_bign(const EVP_PKEY *a, const EVP_PKEY *b) 
{
	const struct bign_key_data *data_a;
	const struct bign_key_data *data_b;
	const octet *ka, *kb;

	data_a = (const struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)a);
	data_b = (const struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)b);

	if (!data_a || !data_b) return 0;
	ka = data_a->pubKey;
	kb = data_b->pubKey;
	if (!ka || !kb) return 0;
	
	return (memcmp(ka, kb, data_a->params.l / 2) == 0);
}

static int pkey_size_bign(const EVP_PKEY *pk) 
{
	const struct bign_key_data *key_data;
	key_data = (const struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)pk);
	return key_data->params.l * 3 / 8;
}

static int pkey_bits_bign(const EVP_PKEY *pk) 
{
	return pkey_size_bign(pk) << 3;
}

static int bign_param_encode(const EVP_PKEY *pkey, unsigned char **pder) 
{
	struct bign_key_data *key_data;
	key_data = (struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)pkey);
	return i2d_ASN1_OBJECT(OBJ_nid2obj(key_data->param_nid), pder);
}

static int bign_param_decode(EVP_PKEY *pkey, const unsigned char **pder, int derlen) 
{
	ASN1_OBJECT *obj;
	int nid;
	struct bign_key_data *key_data = NULL;

	obj = NULL;
	key_data = (struct bign_key_data *) EVP_PKEY_get0(pkey);

	if (d2i_ASN1_OBJECT(&obj, pder, derlen) == NULL )  return 0;
	nid = OBJ_obj2nid(obj);
	ASN1_OBJECT_free(obj);
	if (!key_data) 
	{
		key_data = (struct bign_key_data *) OPENSSL_malloc(sizeof (struct bign_key_data));
		if(!key_data) return 0;
		memSet(key_data, 0, sizeof (struct bign_key_data));
		if (!EVP_PKEY_btls_assign(pkey, bign_nid, key_data))  return 0; 
	}
	if (!fill_bign_params(key_data, nid)) 
	{
		ERR_BTLS(BTLS_F_BIGN_PARAM_DECODE, BTLS_R_UNSUPPORTED_PARAMETER_SET);
		return 0;
	}
	return 1;
}

/* ----------------------------------------------------------------------*/
int register_ameth_bign(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char* pemstr, const char* info) 
{
	*ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
	if (!*ameth) return 0;
	if (bign_nid == nid) 
	{
		EVP_PKEY_asn1_set_free(*ameth, pkey_free_bign);
		EVP_PKEY_asn1_set_private(*ameth, priv_decode_bign, priv_encode_bign,
				priv_print_bign);

		EVP_PKEY_asn1_set_param(*ameth, bign_param_decode,
				bign_param_encode, param_missing_bign, param_copy_bign,
				param_cmp_bign, param_print_bign);
		EVP_PKEY_asn1_set_public(*ameth, pub_decode_bign, pub_encode_bign,
				pub_cmp_bign, pub_print_bign, pkey_size_bign,
				pkey_bits_bign);

		EVP_PKEY_asn1_set_ctrl(*ameth, pkey_ctrl_bign);
	}
	else
	{
		EVP_PKEY_asn1_free(*ameth);
		return 0;
	}
	return 1;
}

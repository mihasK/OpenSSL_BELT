/*
 * bign_ameth.c
 *
 *  Created on: 04.05.2013
 *      Author: denis
 */

#ifndef OPENSSL_NO_CMS
#include <openssl/cms.h>
#endif
#include "btls_bign.h"

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

// performs computing public key from given params and private key
static octet* computePublicKey(const bign_params *params, const octet *privKey) 
{
	int ok;
	octet *newPubKey;
	int privSize;
	octet *revPrivKey;
	BIGNUM *privBn;
	BIGNUM *p, *q, *a, *b, *x, *y;
	bign_params rev_params;
	EC_POINT *P;
	EC_GROUP *grp;
	BN_CTX *ctx;
	octet *revOct;
	int shift;
	EC_KEY *eckey;
	EC_POINT *pub_key;
	octet *octX;
	octet *octY;

	ok = 0;
	privSize = params->l / 4;
	revPrivKey = (octet*) OPENSSL_malloc(privSize);
	reverseOctets(revPrivKey, privKey, privSize);
	privBn = BN_new();
	BN_bin2bn(revPrivKey, privSize, privBn);
	p = NULL; q = NULL; a = NULL; b = NULL; x = NULL; y = NULL;
	P = NULL;
	grp = NULL;
	ctx = BN_CTX_new();

	BN_CTX_start(ctx);
	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	q = BN_CTX_get(ctx);

	reverseOctets(rev_params.p, params->p, privSize);
	reverseOctets(rev_params.a, params->a, privSize);
	reverseOctets(rev_params.b, params->b, privSize);

	BN_bin2bn(rev_params.p, privSize, p);
	BN_bin2bn(rev_params.a, privSize, a);
	BN_bin2bn(rev_params.b, privSize, b);

	grp = EC_GROUP_new_curve_GFp(p, a, b, ctx);

	P = EC_POINT_new(grp);

	
	BN_zero(x);
	reverseOctets(rev_params.yG, params->yG, privSize);
	BN_bin2bn(rev_params.yG, privSize, y);
	EC_POINT_set_affine_coordinates_GFp(grp, P, x, y, ctx);
	reverseOctets(rev_params.q, params->q, privSize);
	BN_bin2bn(rev_params.q, privSize, q);

	EC_GROUP_set_generator(grp, P, q, NULL );
	eckey = EC_KEY_new();

	EC_KEY_set_group(eckey, grp);

	pub_key = EC_POINT_new(grp);
	if (!EC_POINT_mul(grp, pub_key, privBn, NULL, NULL, ctx)) 
	{
		//printf("\nError in mult");
		goto compute_public_err;
	} else 
	{
		if (EC_POINT_get_affine_coordinates_GFp(grp, pub_key, x, y, ctx)) 
		{
			revOct = (octet *) OPENSSL_malloc(privSize);
			octX = (octet *) OPENSSL_malloc(privSize);
			octY = (octet *) OPENSSL_malloc(privSize);

			memSetZero(revOct, privSize);
			shift = privSize - BN_num_bytes(x);
			BN_bn2bin(x, revOct + shift);
			reverseOctets(octX, revOct, privSize);

			memSetZero(revOct, privSize);
			shift = privSize - BN_num_bytes(y);
			BN_bn2bin(y, revOct + shift);
			reverseOctets(octY, revOct, privSize);
			newPubKey = (octet*) OPENSSL_malloc(privSize * 2);
			memCopy(newPubKey, octX, privSize);
			memCopy(newPubKey + privSize, octY, privSize);

			OPENSSL_free(revOct);
			OPENSSL_free(octX);
			OPENSSL_free(octY);
		} else 
		{
			//printf("\nError in get affine coordinate");
			goto compute_public_err;
		}
	}
	ok = 1;

compute_public_err:

	OPENSSL_free(revPrivKey);

	BN_free(privBn);
	BN_free(p);
	BN_free(a);
	BN_free(b);
	BN_free(x);
	BN_free(y);
	BN_free(q);

	EC_POINT_free(P);
	EC_GROUP_free(grp);
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_POINT_free(pub_key);
	EC_KEY_free(eckey);

	return ok ? newPubKey : NULL;
}

static ASN1_STRING *encode_bign_algor_params(const EVP_PKEY *key) 
{
	ASN1_STRING *params;
	BIGN_KEY_PARAMS *bkp;
	struct bign_key_data *key_data;
	int pkey_param_nid;

	params = ASN1_STRING_new();
	bkp = BIGN_KEY_PARAMS_new();
	key_data = (struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)key);
	pkey_param_nid = key_data->param_nid;

	if (!params || !bkp) 
	{
		// handle error
		ASN1_STRING_free(params);
		params = NULL;
		goto err;
	}

	bkp->key_params = OBJ_nid2obj(pkey_param_nid);

	params->length = i2d_BIGN_KEY_PARAMS(bkp, &params->data);
	if (params->length <= 0) 
	{
		// handle error
		ASN1_STRING_free(params);
		params = NULL;
		goto err;
	}
	params->type = V_ASN1_SEQUENCE;

err:
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
	struct bign_key_data *key_data;

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
		// handle error
		return 0;
	}
	p = pval->data;
	pkey_nid = OBJ_obj2nid(palg_obj);

	bkp = d2i_BIGN_KEY_PARAMS(NULL, &p, pval->length);
	if (!bkp) 
	{
		// handle error
		return 0;
	}
	param_nid = OBJ_obj2nid(bkp->key_params);
	BIGN_KEY_PARAMS_free(bkp);
	EVP_PKEY_set_type(pkey, pkey_nid);
	if (bign_nid == pkey_nid) 
	{
		key_data = (struct bign_key_data *) EVP_PKEY_get0(pkey);
		if (!key_data) 
		{
			key_data = (struct bign_key_data *) OPENSSL_malloc(sizeof(struct bign_key_data));
			if (!EVP_PKEY_btls_assign(pkey, pkey_nid, key_data)) 
			{
				return 0;
			}
		}
		if (!fill_bign_params(key_data, param_nid)) 
		{
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
		}
		key_data->privKey = (octet*) OPENSSL_malloc(privKeyLength);
		memCopy(key_data->privKey, priv, privKeyLength);
		if (!EVP_PKEY_missing_parameters(pkey)) 
		{
			key_data->pubKey = computePublicKey(&key_data->params, key_data->privKey);
		}
	}
	return 1;
}

static octet* bign_get_priv_key(const EVP_PKEY *pkey) 
{
	struct bign_key_data *key_data;
	if (bign_nid == EVP_PKEY_btls_base_id(pkey)) 
	{
		key_data = (struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)pkey);
		if (!key_data) 
		{
			return NULL;
		}
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
		if (!key_data) 
		{
			return 0;
		}
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
		}
		if (key_data->pubKey) 
		{
			OPENSSL_free(key_data->pubKey);
		}
		OPENSSL_free(key_data);
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
		return 0;
	}
	if (!decode_bign_algor_params(pk, palg)) 
	{
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
	octet *privKeyBuf;

	algobj = OBJ_nid2obj(EVP_PKEY_btls_base_id(pk));
	params = encode_bign_algor_params(pk);
	privKey = bign_get_priv_key(pk);
	privKeyLength = bign_get_priv_key_length(pk);
	privKeyBuf = (octet *) OPENSSL_malloc(privKeyLength);

	if (!params) 
	{
		return 0;
	}

	memCopy(privKeyBuf, privKey, privKeyLength);
	return PKCS8_pkey_set0(p8, algobj, 0, V_ASN1_SEQUENCE, params,
			privKeyBuf, privKeyLength);
}

/* --------- printing keys --------------------------------*/

static void print_octets(BIO *out, octet *octets, int length) 
{
	int i;
	for (i = 0; i < length; i++) 
	{
		BIO_printf(out, "%02X", octets[i]);
	}
}

static int print_bign(BIO *out, const EVP_PKEY *pkey, int indent,
		ASN1_PCTX *pctx, int type) 
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
		if (!BIO_indent(out, indent, max_indent)) 
		{
			return 0;
		}
		BIO_printf(out, "Private key: ");
		key = bign_get_priv_key(pkey);
		if (!key) 
		{
			BIO_printf(out, "<undefined)");
		} else 
		{
			print_octets(out, key, priv_key_length);
		}
		BIO_printf(out, "\n");
	}
	if (type >= 1) {
		if (!BIO_indent(out, indent, max_indent)) 
		{
			return 0;
		}
		BIO_printf(out, "Public key: ");
		print_octets(out, key_data->pubKey, priv_key_length * 2);
		BIO_printf(out, "\n");
	}

	param_nid = key_data->param_nid;
	if (!BIO_indent(out, indent, max_indent)) 
	{
		return 0;
	}
	BIO_printf(out, "Parameter set: %s\n", OBJ_nid2ln(param_nid));
	return 1;
}

static int param_print_bign(BIO *out, const EVP_PKEY *pkey, int indent,
		ASN1_PCTX *pctx) 
{
	return print_bign(out, pkey, indent, pctx, 0);
}

static int pub_print_bign(BIO *out, const EVP_PKEY *pkey, int indent,
		ASN1_PCTX *pctx) 
{
	return print_bign(out, pkey, indent, pctx, 1);
}

static int priv_print_bign(BIO *out, const EVP_PKEY *pkey, int indent,
		ASN1_PCTX *pctx) 
{
	return print_bign(out, pkey, indent, pctx, 2);
}

static int param_missing_bign(const EVP_PKEY *pk) 
{
	const struct bign_key_data *key_data;
	
	key_data = (const struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)pk);

	if (!key_data) 
	{
		return 1;
	}
	if (key_data->param_nid == NID_undef) 
	{
		return 1;
	}
	return 0;
}

static int param_copy_bign(EVP_PKEY *to, const EVP_PKEY *from) 
{
	struct bign_key_data *eto;
	const struct bign_key_data *efrom;

	eto = (struct bign_key_data *) EVP_PKEY_get0(to);
	efrom = (const struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)from);

	if (EVP_PKEY_btls_base_id(from) != EVP_PKEY_btls_base_id(to)) 
	{
		// handle error
		return 0;
	}
	if (!efrom) 
	{
		// handle error
		return 0;
	}
	if (!eto) 
	{
		eto = (struct bign_key_data *) OPENSSL_malloc(sizeof (struct bign_key_data));;
		if (EVP_PKEY_btls_assign(to, EVP_PKEY_btls_base_id(from), eto) <= 0)
			return 0;
	}
	eto->param_nid = efrom->param_nid;
	eto->params = efrom->params;
	if (eto->privKey) 
	{
		eto->pubKey = computePublicKey(&eto->params, eto->privKey);
		if (!eto->pubKey) 
		{
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
	{
		return 1;
	}
	return 0;
}

/* ---------- Public key functions * --------------------------------------*/

static int pub_decode_bign(EVP_PKEY *pk, X509_PUBKEY *pub) 
{
	X509_ALGOR *palg;
	const unsigned char *pubkey_buf;
	ASN1_OBJECT *palgobj;
	int pub_len;
	octet *pub_key;
	struct bign_key_data *key_data;

	palg = NULL;
	pubkey_buf = NULL;
	palgobj = NULL;

	if (!X509_PUBKEY_get0_param(&palgobj, &pubkey_buf, &pub_len, &palg, pub)) 
	{
		return 0;
	}
	if (EVP_PKEY_btls_assign(pk, OBJ_obj2nid(palgobj), NULL) <= 0)
		return 0;
	if (!decode_bign_algor_params(pk, palg)) 
	{
		return 0;
	}
	pub_key = (octet *) OPENSSL_malloc(pub_len);
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
	octet *pub_key_buf;

	algobj = NULL;
	pval = NULL;
	pub_key = NULL;
	key_data = (struct bign_key_data *) EVP_PKEY_get0((EVP_PKEY *)pk);
	ptype = V_ASN1_UNDEF;

	algobj = OBJ_nid2obj(EVP_PKEY_btls_base_id(pk));
	if (pk->save_parameters) 
	{
		ASN1_STRING *params = encode_bign_algor_params(pk);
		pval = params;
		ptype = V_ASN1_SEQUENCE;
	}
	pub_key = key_data->pubKey;

	if (!pub_key) {
		// handle error
		return 0;
	}

	pub_key_length = key_data->params.l / 2;
	pub_key_buf = (octet *) OPENSSL_malloc(pub_key_length);
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

	if (!data_a || !data_b) 
	{
		return 0;
	}
	ka = data_a->pubKey;
	kb = data_b->pubKey;
	if (!ka || !kb) {
		return 0;
	}
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
	// TODO: think about this value
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
	struct bign_key_data *key_data;

	obj = NULL;
	key_data = (struct bign_key_data *) EVP_PKEY_get0(pkey);

	if (d2i_ASN1_OBJECT(&obj, pder, derlen) == NULL ) 
	{
		return 0;
	}
	nid = OBJ_obj2nid(obj);
	ASN1_OBJECT_free(obj);
	if (!key_data) 
	{
		key_data = (struct bign_key_data *) OPENSSL_malloc(sizeof (struct bign_key_data));
		if (!EVP_PKEY_btls_assign(pkey, bign_nid, key_data)) 
		{
			return 0;
		}
	}
	if (!fill_bign_params(key_data, nid)) 
	{
		return 0;
	}
	return 1;
}

/* ----------------------------------------------------------------------*/
int register_ameth_bign(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char* pemstr, const char* info) 
{
	*ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
	if (!*ameth) 
	{
		return 0;
	}
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
	return 1;
}

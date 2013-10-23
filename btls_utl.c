#include "btls_utl.h"
#include "btls_eng.h"


int EVP_PKEY_btls_assign(EVP_PKEY *pkey, int type, void *key)
{
	ENGINE *e = NULL;
	EVP_PKEY_ASN1_METHOD *ameth;

	if (pkey)
	{
		if (pkey->pkey.ptr)
		{
			if (pkey->ameth && pkey->ameth->pkey_free)
			{
				pkey->ameth->pkey_free(pkey);
				pkey->pkey.ptr = NULL;
			}
#ifndef OPENSSL_NO_ENGINE
			if (pkey->engine)
			{
				ENGINE_finish(pkey->engine);
				pkey->engine = NULL;
			}
#endif
		}
		if ((type == pkey->save_type) && pkey->ameth)
			return 1;


#ifndef OPENSSL_NO_ENGINE
		if (pkey->engine)
		{
			ENGINE_finish(pkey->engine);
			pkey->engine = NULL;
		}
#endif
	}

	if (type == belt_mac_nid) 
	{
		ameth = mac_ameth;
	} 
	else if (type == bign_nid) 
	{
		ameth = bign_ameth;
	}
	else
		return 0;

	e = ENGINE_by_id(ENGINE_NAME);

#ifndef OPENSSL_NO_ENGINE
	if (!pkey && e)
		ENGINE_finish(e);
#endif
	if (!ameth)
	{
	//	EVPerr(EVP_F_PKEY_SET_TYPE, EVP_R_UNSUPPORTED_ALGORITHM);
		return 0;
	}
	if (pkey)
	{
		pkey->ameth = ameth;
		pkey->engine = e;

		pkey->type = pkey->ameth->pkey_id;
		pkey->save_type = type;
	}

	pkey->pkey.ptr = (char*) key;
	return (key != NULL);
}


int EVP_PKEY_btls_base_id(const EVP_PKEY *pkey)
{
	int ret;
	const EVP_PKEY_ASN1_METHOD *ameth = NULL;
	ENGINE *e;

	if (pkey->type == belt_mac_nid) 
	{
		ameth = mac_ameth;
	} 
	else if (pkey->type == bign_nid) 
	{
		ameth = bign_ameth;
	}
	else
		ameth = NULL;

	if (ameth)
		ret = ameth->pkey_id;
	else
		ret = NID_undef;

	e = ENGINE_by_id(ENGINE_NAME);

#ifndef OPENSSL_NO_ENGINE
	if (e)
		ENGINE_finish(e);
#endif
	return ret;
}
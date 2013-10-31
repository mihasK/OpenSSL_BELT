/*!
*******************************************************************************
\file btls_bign.h
\brief Определения для алгоритмов СТБ 34.101.45 (bign)
*//****************************************************************************
\author (С) Олег Соловей, Денис Веремейчик, http://apmi.bsu.by
\created 2013.08.01
\version 2013.09.26
*******************************************************************************
*/

#ifndef __BTLS_BIGN_H
#define __BTLS_BIGN_H

#include <openssl/asn1t.h>
#include "btls_belt.h"
#include "../bee2/bign.h"

#define BIGN_PRIVKEY_SIZE  32
#define BIGN_PUBKEY_SIZE   64
#define BIGN_SIGN_SIZE     48

#define EVP_PKEY_CTRL_BIGN_PARAMSET (EVP_PKEY_ALG_CTRL+1)
#define param_ctrl_string "paramset"

struct bign_pmeth_data 
{
	int param_nid; /* Should be set whenever parameters are filled */
	EVP_MD *md;
	int peer_key_used; 
	int key_set;
	unsigned char *rng_stack;
};

struct bign_key_data 
{
	bign_params params;
	int param_nid;
	octet *privKey;
	octet *pubKey;
};

/* method registration */
int register_pmeth_bign(int id, EVP_PKEY_METHOD **pmeth, int flags);
int register_ameth_bign(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char* pemstr, const char* info);

/* ASN1 structures */
typedef struct 
{
	int type;
	union 
	{
		ASN1_OBJECT *key_params; /* for bign-pubkey*/
		/* ... Add from choise DomainParameters */ 
	} d;
} BIGN_KEY_PARAMS;

DECLARE_ASN1_FUNCTIONS(BIGN_KEY_PARAMS)

int fill_bign_params(struct bign_key_data *key_data, int params_nid);

#endif /* __BTLS_BIGN_H */

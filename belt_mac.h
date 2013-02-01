/*
 * belt_mac.h
 *
 *  Created on: Feb 1, 2013
 *      Author: mihas
 */

#ifndef BELT_MAC_H_
#define BELT_MAC_H_

#include "belt.h"

struct belt_mac_pmeth_data {
	int key_set;
	EVP_MD *md;
	unsigned char key[BELT_CIPHER_KEY_SIZE];
};

static int pkey_belt_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

static int pkey_belt_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
static int pkey_belt_mac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
		size_t *siglen, EVP_MD_CTX *mctx);

int pkey_belt_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
int pkey_belt_mac_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
		const char *value);


#endif /* BELT_MAC_H_ */

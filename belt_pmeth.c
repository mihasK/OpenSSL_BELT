/*
 * belt_pmeth.c
 *
 *  Created on: 01.02.2013
 *      Author: denis
 */

#include "belt.h"

struct belt_mac_pmeth_data {
	int key_set;
	EVP_MD *md;
	unsigned char key[BELT_CIPHER_KEY_SIZE];
};

EVP_PKEY_METHOD belt_pmeth_mac = {

	NID_undef,
	0, /* flags */

	NULL, /* init */
	NULL, /* copy */
	NULL, /* cleanup */

	NULL, /* paramgen_init */
	NULL, /* paramgen */

	NULL, /* keygen_init */
	NULL, /* keygen */

	NULL, /* sign_init */
	NULL, /* sign */

	NULL, /* verify_init */
	NULL, /* verify */

	NULL, /* verify_recover_init */
	NULL, /* verify_recover */

	NULL, /* signctx_init */
	NULL, /* signctx */

	NULL, /* verifyctx_init */
	NULL, /* verifyctx */

	NULL, /* encrypt_init */
	NULL, /* encrypt */

	NULL, /* decrypt_init */
	NULL, /* decrypt */

	NULL, /* derive_init */
	NULL, /* derive */

	NULL, /* ctrl */
	NULL /* ctrl_str */
};

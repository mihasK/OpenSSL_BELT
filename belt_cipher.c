/*
 * belt_cipher.c
 *
 *  Created on: 10.01.2013
 *      Author: denis
 */

#include "belt.h"

// TODO: set correct values
#define BELT_CIPHER_BLOCK_SIZE 1
#define BELT_CIPHER_KEY_SIZE 32
#define BELT_CIPHER_IV_SIZE 8

static int belt_cipher_do_cnt(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, unsigned int inl);
static int belt_cipher_init_cnt(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		const unsigned char *iv, int enc);
static int belt_cipher_cleanup_cnt(EVP_CIPHER_CTX *ctx);

EVP_CIPHER belt_cipher_cnt = {
	NID_undef,
	BELT_CIPHER_BLOCK_SIZE, /*block_size*/
	BELT_CIPHER_KEY_SIZE, /*key_size*/
	BELT_CIPHER_IV_SIZE, /*iv_len */
	EVP_CIPH_OFB_MODE| EVP_CIPH_NO_PADDING |
		EVP_CIPH_CUSTOM_IV| EVP_CIPH_RAND_KEY | EVP_CIPH_ALWAYS_CALL_INIT,
	belt_cipher_init_cnt, /* init key */
	belt_cipher_do_cnt, /* encrypt/decrypt data */
	belt_cipher_cleanup_cnt, /* cleanup ctx */
	/*sizeof(struct ossl_gost_cipher_ctx)*/32, /* ctx_size */
	NULL, /* set asn1 params */
	NULL, /* get asn1 params */
	NULL, /* control function */
	NULL  /* application data */
};

static int belt_cipher_do_cnt(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, unsigned int inl) {
	return 1;
}

static int belt_cipher_init_cnt(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		const unsigned char *iv, int enc) {
	return 1;
}

/* Cleaning up of EVP_CIPHER_CTX */
static int belt_cipher_cleanup_cnt(EVP_CIPHER_CTX *ctx) {
	return 1;
}

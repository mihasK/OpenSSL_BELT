/*
 * belt_cipher.c
 *
 *  Created on: 10.01.2013
 *      Author: denis
 */

#include "belt.h"

#define BELT_CIPHER_CTR_BLOCK_SIZE 1
#define BELT_CIPHER_KEY_SIZE 32
#define BELT_CIPHER_IV_SIZE 16

static int belt_cipher_do_ctr(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, unsigned int inl);
static int belt_cipher_init_ctr(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		const unsigned char *iv, int enc);
static int belt_cipher_cleanup_ctr(EVP_CIPHER_CTX *ctx);

EVP_CIPHER belt_cipher_ctr = {
	NID_undef,
	BELT_CIPHER_CTR_BLOCK_SIZE, /*block_size*/
	BELT_CIPHER_KEY_SIZE, /*key_size*/
	BELT_CIPHER_IV_SIZE, /*iv_len */
	EVP_CIPH_CTR_MODE | EVP_CIPH_NO_PADDING |
		EVP_CIPH_CUSTOM_IV /*| EVP_CIPH_ALWAYS_CALL_INIT*/,
	belt_cipher_init_ctr, /* init key */
	belt_cipher_do_ctr, /* encrypt/decrypt data */
	belt_cipher_cleanup_ctr, /* cleanup ctx */
	32, /* ctx_size (will be initialize in bind function) */
	NULL, /* set asn1 params */
	NULL, /* get asn1 params */
	NULL, /* control function */
	NULL  /* application data */
};

static int belt_cipher_do_ctr(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, unsigned int inl) {
	memCopy(out, in, inl);
	if (ctx->encrypt) {
		beltCTRStepE(out, inl, ctx->cipher_data);
	} else {
		beltCTRStepD(out, inl, ctx->cipher_data);
	}
	return 1;
}

static int belt_cipher_init_ctr(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		const unsigned char *iv, int enc) {
	beltCTRStart(key, BELT_CIPHER_KEY_SIZE, iv, ctx->cipher_data);
	return 1;
}

/* Cleaning up of EVP_CIPHER_CTX */
static int belt_cipher_cleanup_ctr(EVP_CIPHER_CTX *ctx) {
	memSetZero(ctx->cipher_data, beltCTRStackDeep());
	return 1;
}

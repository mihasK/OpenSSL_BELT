/*
 * belt_cipher.c
 *
 *  Created on: 10.01.2013
 *      Author: denis
 */

#include "belt.h"

#define BELT_CIPHER_CTR_BLOCK_SIZE 1
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

/* Implementation of BELT in MAC (imitovstavka) mode */

#define BELT_IMIT_BLOCK_SIZE 16

/* Init functions which set specific parameters */
static int belt_imit_init(EVP_MD_CTX *ctx);
/* process block of data */
static int belt_imit_update(EVP_MD_CTX *ctx, const void *data, size_t count);
/* Return computed value */
static int belt_imit_final(EVP_MD_CTX *ctx, unsigned char *md);
/* Copies context */
static int belt_imit_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int belt_imit_cleanup(EVP_MD_CTX *ctx);
/* Control function, knows how to set MAC key.*/
static int belt_imit_ctrl(EVP_MD_CTX *ctx, int type, int arg, void *ptr);

EVP_MD belt_imit = {
	NID_undef,
	NID_undef,
	BELT_IMIT_RESULT_SIZE,
	0,
	belt_imit_init,
	belt_imit_update,
	belt_imit_final,
	belt_imit_copy,
	belt_imit_cleanup,
	NULL,
	NULL,
	{0,0,0,0,0},
	BELT_IMIT_BLOCK_SIZE,
	1, /* ctx_size (will be initialize in bind function) */
	belt_imit_ctrl
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

static int belt_imit_init(EVP_MD_CTX *ctx) {
	// initialization will be done after setting key
	return 1;
}

static int belt_imit_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
	beltMACStepA(data, count, ctx->md_data);
	return 1;
}

static int belt_imit_final(EVP_MD_CTX *ctx, unsigned char *md) {
	beltMACStepG(md, ctx->md_data);
	return 1;
}

static int belt_imit_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from) {
	memCopy(to->md_data, from->md_data, beltMACStackDeep());
	return 1;
}

static int belt_imit_cleanup(EVP_MD_CTX *ctx) {
	memSetZero(ctx->md_data, beltMACStackDeep());
	return 1;
}

static int belt_imit_ctrl(EVP_MD_CTX *ctx, int type, int arg, void *ptr) {
	switch (type) {
	case EVP_MD_CTRL_KEY_LEN:
		*((unsigned int*) (ptr)) = BELT_CIPHER_KEY_SIZE;
		return 1;
	case EVP_MD_CTRL_SET_KEY:
		if (arg != BELT_CIPHER_KEY_SIZE) {
			// TODO: handle error
			printf("Wrong key size");
			return 0;
		}
		beltMACStart(ptr, arg, ctx->md_data);
		return 1;
	default:
		return 0;
	}
}

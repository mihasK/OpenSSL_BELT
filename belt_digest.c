/*
 * belt_digest.c
 *
 *  Created on: Jan 1, 2013
 *      Author: mihas
 */

#include "belt.h"

//TODO:: what this is means?

#define BELT_DGST_TYPE BELT_DGST_NID //for namec.c : EVP_add_digest
#define BELT_DGST_PKEY_TYPE 0 //??????
#define BELT_DGST_SIZE 32 //??????
#define BELT_DGST_BLOCK_SIZE 1
//#define BELT_DGST_CONTEXT_SIZE 32
#define BELT_DGST_FLAGS EVP_MD_CTX_FLAG_ONESHOT

static int belt_digest_init(EVP_MD_CTX *ctx);
static int belt_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int belt_digest_final(EVP_MD_CTX *ctx, unsigned char *md);
static int belt_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int belt_digest_cleanup(EVP_MD_CTX *ctx);

EVP_MD belt_md = {
	NID_undef,
	BELT_DGST_PKEY_TYPE,
	BELT_DGST_SIZE,
	BELT_DGST_FLAGS,
	belt_digest_init,
	belt_digest_update,
	belt_digest_final,
	belt_digest_copy,
	belt_digest_cleanup,

	/* TODO: may be this use as ЭЦП ? */
	NULL,	//sign
	NULL,//verigy
	{NID_undef,NID_undef,0,0,0}, /*EVP_PKEY_xxx */
	BELT_DGST_BLOCK_SIZE,

	/* how big does the ctx->md_data need to be */
	//TODO:: beltHashStackDeep() - error that is not a constant
	32,//BELT_DGST_CONTEXT_SIZE,/* ctx_size (will be initialize in bind function) */

	/* control function */
	NULL
};

static int belt_digest_init(EVP_MD_CTX *ctx) {

	beltHashStart(ctx->md_data);
	return 1;
}

static int belt_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count){
	beltHashStepH(data, count, ctx->md_data);
	return 1;
}


static int belt_digest_final(EVP_MD_CTX *ctx, unsigned char *md){
	beltHashStepG(md, ctx->md_data);
	return 1;
}

static int belt_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from){
	memcpy(to->md_data,from->md_data, belt_md.ctx_size);
	return 1;
}

static int belt_digest_cleanup(EVP_MD_CTX *ctx){
	memSetZero(ctx->md_data, belt_md.ctx_size);
	return 1;
}

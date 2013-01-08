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
	BELT_DGST_SIZE,
	BELT_DGST_SIZE, /* how big does the ctx->md_data need to be */
	/* control function */
	NULL
};

static int belt_digest_init(EVP_MD_CTX *ctx) {
	return 1;
}

static int belt_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count){
	return 1;
}


static int belt_digest_final(EVP_MD_CTX *ctx, unsigned char *md){
	md = malloc(BELT_DGST_SIZE * sizeof(char));
	//for(int i=0; i< BELT_DGST_SIZE; i++){
		//md[i] = 0;
	//}
	md[0] = 1;
	md[1] = 2;
	md[2] = 3;
	return 1;
}

static int belt_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from){
	return 1;
}

static int belt_digest_cleanup(EVP_MD_CTX *ctx){
	return 1;
}

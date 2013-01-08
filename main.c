/*
 * main.c
 *
 *  Created on: 04.12.2012
 *      Author: 1278
 */


#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "belt.h"


static int belt_ciphers(ENGINE * e, const EVP_CIPHER ** cipher, const int ** nids, int nid) {
	if(cipher == NULL) {
		//TODO:: original nid (see obj_dat.c & .h)
		int belt_nids[] = {301};
		*nids=belt_nids;
		return 1;
	} else {
		//TODO:: implement ciphers
		*cipher = NULL;
		return 1;
	}

	return 0;
}

static int belt_digest(ENGINE * engine, const EVP_MD ** evp_md, const int ** nids, int nid) {
	if(evp_md == NULL) {
		//TODO:: original nid (see obj_dat.c & .h) EVP_add_digest_alias - ????
		int belt_nids[] = {BELT_DGST_NID};
		*nids=belt_nids;
		return 1;
	} else {
		//TODO:: implement ciphers
		*evp_md = &belt_md;
		return 1;
	}

	return 0;
}


static void add() {
	EVP_add_digest(&belt_md);
}
int io(){

}

static int bind_belt(ENGINE * e, const char *id)
 {
	if (!ENGINE_set_id(e, "belt_01")) {
		printf("ENGINE_set_id failed\n");
		return 0;
	}
	if (!ENGINE_set_name(e, "Belt")) {
		printf("ENGINE_set_name failed\n");
		return 0;
	}
	if (!ENGINE_set_digests(e, belt_digest)) {
		printf("ENGINE_set_digests failed\n");
		return 0;
	}

	add();


	if (!ENGINE_set_ciphers(e, belt_ciphers)) {
		printf("ENGINE_set_ciphers failed\n");
		return 0;
	}

	//register algorithms
	if(!ENGINE_register_ciphers(e) || !ENGINE_register_digests(e)) {
		printf("ENGINE register fails\n");
		return 0;
	}

	return 1;

}


IMPLEMENT_DYNAMIC_CHECK_FN();
IMPLEMENT_DYNAMIC_BIND_FN(bind_belt);

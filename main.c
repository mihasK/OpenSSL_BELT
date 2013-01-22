/*
 * main.c
 *
 *  Created on: 04.12.2012
 *      Author: 1278
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "belt.h"
#include "oids.h"

static const char *engine_belt_id = "belt";
static const char *engine_belt_name = "BELT engine";

static int belt_digest_nids[] = { NID_undef, 0 };
static int belt_cipher_nids[] = { NID_undef, 0 };

#define REGISTER_NID(var,alg) tmpnid=OBJ_ln2nid(LN_ ## alg);\
	var = (tmpnid == NID_undef)?\
		OBJ_create(OID_ ## alg, strdup(SN_ ## alg) ,strdup(LN_ ##alg)) : tmpnid;\
	if (var == NID_undef) { goto err;}

static int register_belt_NIDs() {
	int tmpnid; /* Used by REGISTER_NID macro */
	REGISTER_NID(belt_digest_nids[0], belt_md)
	REGISTER_NID(belt_cipher_nids[0], belt_cipher_ctr)
	return 1;

err:
	belt_digest_nids[0] = NID_undef;
	belt_cipher_nids[0] = NID_undef;
	return 0;
}

static int belt_ciphers(ENGINE * e, const EVP_CIPHER ** cipher,
		const int ** nids, int nid) {
	if (cipher == NULL ) {
		*nids = belt_cipher_nids;
		return 1;
	}
	if (nid == belt_cipher_nids[0]) {
		//TODO:: implement ciphers
		*cipher = &belt_cipher_ctr;
		return 1;
	}

	return 0;
}

static int belt_digest(ENGINE * engine, const EVP_MD ** evp_md,
		const int ** nids, int nid) {
	if (evp_md == NULL ) {
		*nids = belt_digest_nids;
		return 1;
	}
	if (nid == belt_digest_nids[0]) {
		//TODO:: implement digest
		*evp_md = &belt_md;
		return 1;
	}
	return 0;
}

static int add() {
	if (!EVP_add_digest(&belt_md)) {
		return 0;
	}
	if (!EVP_add_cipher(&belt_cipher_ctr)) {
		return 0;
	}
	return 1;
}

int io() {
	return 1;
}

static int bind_belt(ENGINE * e, const char *id) {

	if (!register_belt_NIDs()) {
		printf("Register belt nids failed\n");
		return 0;
	}

	// Set up NIDs
	belt_md.type = belt_digest_nids[0];
	belt_cipher_ctr.nid = belt_cipher_nids[0];

	belt_cipher_ctr.ctx_size = beltCTRStackDeep();

	if (!ENGINE_set_id(e, engine_belt_id)) {
		printf("ENGINE_set_id failed\n");
		return 0;
	}
	if (!ENGINE_set_name(e, engine_belt_name)) {
		printf("ENGINE_set_name failed\n");
		return 0;
	}
	if (!ENGINE_set_digests(e, belt_digest)) {
		printf("ENGINE_set_digests failed\n");
		return 0;
	}

	if (!ENGINE_set_ciphers(e, belt_ciphers)) {
		printf("ENGINE_set_ciphers failed\n");
		return 0;
	}

	if (!add()) {
		printf("Adding algorithms failed\n");
		return 0;
	}

	//register algorithms
	if (!ENGINE_register_ciphers(e) || !ENGINE_register_digests(e)) {
		printf("ENGINE register fails\n");
		return 0;
	}

	return 1;

}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_belt)

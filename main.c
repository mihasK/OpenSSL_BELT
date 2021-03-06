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

static int belt_digest_nids[] = { NID_undef, NID_undef, 0 };
static int belt_cipher_nids[] = { NID_undef, 0 };
static int belt_pmeth_nids[] = { NID_undef, 0 };

static EVP_PKEY_METHOD *belt_pmeth_mac = NULL;

static EVP_PKEY_ASN1_METHOD *belt_ameth_mac = NULL;

#define REGISTER_NID(var,alg) tmpnid=OBJ_ln2nid(LN_ ## alg);\
	var = (tmpnid == NID_undef)?\
		OBJ_create(OID_ ## alg, strdup(SN_ ## alg) ,strdup(LN_ ##alg)) : tmpnid;\
	if (var == NID_undef) { goto err;}

static int register_belt_NIDs() {
	int tmpnid; /* Used by REGISTER_NID macro */
	REGISTER_NID(belt_digest_nids[0], belt_md)
	REGISTER_NID(belt_digest_nids[1], belt_mac)
	REGISTER_NID(belt_cipher_nids[0], belt_cipher_ctr)
	return 1;

err:
	belt_digest_nids[0] = NID_undef;
	belt_digest_nids[1] = NID_undef;
	belt_cipher_nids[0] = NID_undef;
	return 0;
}

static int belt_ciphers(ENGINE * e, const EVP_CIPHER ** cipher,
		const int ** nids, int nid) {
	if (cipher == NULL) {
		*nids = belt_cipher_nids;
		return 1;
	}
	if (nid == belt_cipher_nids[0]) {
		*cipher = &belt_cipher_ctr;
		return 1;
	}

	return 0;
}

static int belt_digest(ENGINE * engine, const EVP_MD ** evp_md,
		const int ** nids, int nid) {
	if (evp_md == NULL) {
		*nids = belt_digest_nids;
		return 2;
	}
	if (nid == belt_digest_nids[0]) {
		*evp_md = &belt_md;
		return 1;
	} else if (nid == belt_digest_nids[1]) {
		*evp_md = &belt_imit;
		return 1;
	}
	return 0;
}

static int belt_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids,
		int nid) {
	if (!pmeth) {
		*nids = belt_pmeth_nids;
		return 1;
	}

	if (nid == belt_pmeth_nids[0]) {
		*pmeth = belt_pmeth_mac;
		return 1;
	}

	*pmeth = NULL;
	return 0;
}

static int belt_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,
		const int **nids, int nid) {
	if (!ameth) {
		*nids = belt_pmeth_nids;
		return 1;
	}

	if (nid == belt_pmeth_nids[0]) {
		*ameth = belt_ameth_mac;
		return 1;
	}

	*ameth = NULL;
	return 0;
}

static int add() {
	if (!EVP_add_digest(&belt_md)) {
		return 0;
	}
	if (!EVP_add_digest(&belt_imit)) {
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

	// Set up NIDs and context-sizes
	belt_md.type = belt_digest_nids[0];
	belt_md.ctx_size = beltHashStackDeep();

	belt_imit.type = belt_digest_nids[1];
	belt_imit.ctx_size = beltMACStackDeep();

	belt_cipher_ctr.nid = belt_cipher_nids[0];
	belt_cipher_ctr.ctx_size = beltCTRStackDeep();

	// pkey method part of BELT MAC
	belt_pmeth_nids[0] = belt_imit.type;

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

	if (!ENGINE_set_pkey_meths(e, belt_pkey_meths)) {
		printf("ENGINE_set_pkey_meths failed\n");
		return 0;
	}

	if (!ENGINE_set_pkey_asn1_meths(e, belt_pkey_asn1_meths)) {
		printf("ENGINE_set_pkey_asn1_meths failed\n");
		return 0;
	}

	if (!register_ameth_belt(belt_imit.type, &belt_ameth_mac,
			"BELT-MAC", "BELT spec27 MAC")) {
		printf("register_ameth_belt for MAC failed\n");
		return 0;
	}

	if (!register_pmeth_belt(belt_imit.type, &belt_pmeth_mac, 0)) {
		printf("register_pmeth_belt for MAC failed\n");
		return 0;
	}

	if (!add()) {
		printf("Adding algorithms failed\n");
		return 0;
	}

	// register algorithms
	if (!ENGINE_register_ciphers(e) || !ENGINE_register_digests(e) ||
			!ENGINE_register_pkey_meths(e)) {
		printf("ENGINE register fails\n");
		return 0;
	}

	return 1;

}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_belt)

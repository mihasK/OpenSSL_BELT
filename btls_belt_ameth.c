/*
 * belt_ameth.c
 *
 *  Created on: 12.02.2013
 *      Author: denis
 */

#include "btls_belt.h"

static void mackey_free_belt(EVP_PKEY *pk) {
	if (pk->pkey.ptr) {
		OPENSSL_free(pk->pkey.ptr);
	}
}

static int mac_ctrl_belt(EVP_PKEY *pkey, int op, long arg1, void *arg2) {
	switch (op) {
	case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
		*(int *) arg2 = belt_mac.type;
		return 2;
	}
	return -2;
}

int register_ameth_belt(int nid, EVP_PKEY_ASN1_METHOD **ameth,
		const char* pemstr, const char* info) {
	*ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
	if (!*ameth) {
		return 0;
	}

	if (nid == belt_mac.type) {
		EVP_PKEY_asn1_set_free(*ameth, mackey_free_belt);
		EVP_PKEY_asn1_set_ctrl(*ameth, mac_ctrl_belt);
	}

	return 1;
}

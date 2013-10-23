#ifndef BTLS_UTL_H
#define BTLS_UTL_H

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <asn1/asn1_locl.h>
#include <x509v3/x509v3.h>

extern int belt_digest_nids[];
extern int bign_nid;
extern int bign_prm1_nid;

extern EVP_PKEY_METHOD *mac_pmeth;
extern EVP_PKEY_METHOD *bign_pmeth;
extern EVP_PKEY_ASN1_METHOD *mac_ameth;
extern EVP_PKEY_ASN1_METHOD *bign_ameth;

#define belt_stream_nid belt_cipher_nids[0]
#define belt_ctr_nid belt_cipher_nids[1]
#define belt_cfb_nid belt_cipher_nids[2]
#define belt_dwp_nid belt_cipher_nids[3]
#define belt_hash_nid belt_digest_nids[0]
#define belt_mac_nid belt_digest_nids[1]
#define pmeth_mac_nid pmeth_nids[0]
#define pmeth_bign_nid pmeth_nids[1]


int EVP_PKEY_btls_assign(EVP_PKEY *pkey,int type,void *key);
int EVP_PKEY_btls_base_id(const EVP_PKEY *pkey);

#endif


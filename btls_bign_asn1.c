/*
 * bign_asn1.c
 *
 * Author: denis
 */

#include <openssl/x509.h>
#include "btls_bign.h"

ASN1_NDEF_SEQUENCE(BIGN_KEY_PARAMS) = 
{
	ASN1_SIMPLE(BIGN_KEY_PARAMS, key_params, ASN1_OBJECT)
} ASN1_NDEF_SEQUENCE_END(BIGN_KEY_PARAMS)

IMPLEMENT_ASN1_FUNCTIONS(BIGN_KEY_PARAMS)

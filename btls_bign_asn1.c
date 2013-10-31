/*
*******************************************************************************
\file btls_bign_asn1.c
\brief АСН.1 для форматов bign
*******************************************************************************
\author (С) Денис Веремейчик, http://apmi.bsu.by
\created 2013.06.14
\version 2013.07.21
*******************************************************************************
*/

#include <openssl/x509.h>
#include "btls_bign.h"

ASN1_CHOICE(BIGN_KEY_PARAMS) = 
{
	ASN1_SIMPLE(BIGN_KEY_PARAMS, d.key_params, ASN1_OBJECT),
} ASN1_CHOICE_END(BIGN_KEY_PARAMS)

IMPLEMENT_ASN1_FUNCTIONS(BIGN_KEY_PARAMS)

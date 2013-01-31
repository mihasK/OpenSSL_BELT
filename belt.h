/*
 * belt.h
 *
 *  Created on: Jan 1, 2013
 *      Author: mihas
 */


//needed for definitions of different symbols

#ifndef BELT_H_
#define BELT_H_

#include <stddef.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <bee2/belt.h>
#include <bee2/mem.h>

#define BELT_DGST_NID 51

// Ctrls to set Belt MAC key
#define EVP_MD_CTRL_KEY_LEN (EVP_MD_CTRL_ALG_CTRL+3)
#define EVP_MD_CTRL_SET_KEY (EVP_MD_CTRL_ALG_CTRL+4)

extern EVP_MD belt_md;
extern EVP_MD belt_imit;
extern EVP_CIPHER belt_cipher_ctr;

//int bind_belt(ENGINE * e, const char *id);

#endif /* BELT_H_ */

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

#define BELT_DGST_NID 51

extern EVP_MD belt_md;

//int bind_belt(ENGINE * e, const char *id);

#endif /* BELT_H_ */

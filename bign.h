/*
 * bign.h
 *
 *  Created on: Feb 23, 2013
 *      Author: mihas
 */

#ifndef BIGN_H_
#define BIGN_H_

#include "belt.h"
#include <bee2/bign.h>

#define BIGN_KEY_SIZE  32//TODO find right value
#define BIGN_SIGNATURE_SIZE 64

struct bign_pmeth_data {
	int key_set;
	EVP_MD *md;
	unsigned char key[BIGN_KEY_SIZE];
};



#endif /* BIGN_H_ */

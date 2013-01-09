/*
 * oids.h
 *
 *  Created on: 09.01.2013
 *      Author: denis
 */

#ifndef BELT_OIDS_H_
#define BELT_OIDS_H_

// OIDs for BELT objects should start with "1.2.653.2.2"

// Defines description of HBELT message digest algorithm
#define OID_belt_md "1.2.653.2.2.9"
#define SN_belt_md "belt_md"
#define LN_belt_md "HBELT digest algorithm"

// Defines description of BELT symmetric cipher in counter mode
#define OID_belt_cipher_cnt "1.2.653.2.2.10"
#define SN_belt_cipher_cnt "belt-cnt"
#define LN_belt_cipher_cnt "BELT symmetric cipher in counter mode"

#endif /* BELT_OIDS_H_ */

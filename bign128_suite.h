#ifndef __GDATA_H
#define __GDATA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "..\\bee2\\include\\defs.h"

/* ñòàíäàðòíûå ïàðàìåòðû è êëþ÷è,
*  óðîâåíü l=128
*/
extern const octet d_128[32];
extern const octet Q_128[64];
extern const octet h_Id_128[32];
extern const octet S_128[48];
extern const octet e_128[32];
extern const octet R_128[64];

extern const octet hBelT_OID_128[11];

extern const octet	ECS_01_DATA[54];
extern const octet	ECS_01_HASH[32];
extern const octet	ECS_01_SIGN[48];

extern const octet ECS_01_M[54];
extern const octet ECS_01_H[32];
extern const octet ECS_01_K[32];
extern const octet ECS_01_S[48];


#ifdef __cplusplus
}
#endif


#endif /* __GDATA_H */


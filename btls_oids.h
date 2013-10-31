/*!
*******************************************************************************
\file btls_oids.h
\brief Идентификаторы для алгоритмов встраиваемого модуля btls 
*//****************************************************************************
\author (С) Олег Соловей, http://apmi.bsu.by
\created 2013.05.14
\version 2013.09.26
*******************************************************************************
*/
#ifndef __BTLS_OIDS_H
#define __BTLS_OIDS_H

/* Defines description of belt-ecb256 */
#define OID_belt_ecb "1.2.112.0.2.0.34.101.31.13"
#define SN_belt_ecb "belt-ecb"
#define LN_belt_ecb "belt-ecb"

/* Defines description of belt-cbc256 */
#define OID_belt_cbc "1.2.112.0.2.0.34.101.31.23"
#define SN_belt_cbc "belt-cfb"
#define LN_belt_cbc "belt-cfb"

/* Defines description of belt-cfb256 */
#define OID_belt_cfb "1.2.112.0.2.0.34.101.31.33"
#define SN_belt_cfb "belt-cfb"
#define LN_belt_cfb "belt-cfb"

/* Defines description of belt-ctr256 */
#define OID_belt_ctr "1.2.112.0.2.0.34.101.31.43"
#define SN_belt_ctr "belt-ctr"
#define LN_belt_ctr "belt-ctr"

#define OID_belt_stream OID_belt_ctr
#define SN_belt_stream "belt-stream"
#define LN_belt_stream "belt-stream"

/* Defines description of belt-mac256 */
#define OID_belt_mac "1.2.112.0.2.0.34.101.31.53"
#define SN_belt_mac "belt-mac"
#define LN_belt_mac "belt-mac"

/* Defines description of belt-datawrap256 */
#define OID_belt_dwp "1.2.112.0.2.0.34.101.31.63"
#define SN_belt_dwp "belt-dwp"
#define LN_belt_dwp "belt-dwp"

/* Defines description of belt-hash256 */
#define OID_belt_hash "1.2.112.0.2.0.34.101.31.81"
#define SN_belt_hash "belt-hash"
#define LN_belt_hash "belt-hash"

/* Defines bign algorithms */
#define OID_bign "1.2.112.0.2.0.34.101.45.12"
#define SN_bign "bign"
#define LN_bign "bign"

/* Defines description of bign params  bign-curve256  (l=128) */
#define OID_bign_prm1 "1.2.112.0.2.0.34.101.45.3.1"
#define SN_bign_prm1 "bign-curve256v1"
#define LN_bign_prm1 "bign-curve256v1"

/* Defines description of bign pubkey */
#define OID_bign_pubkey "1.2.112.0.2.0.34.101.45.2.1"
#define SN_bign_pubkey "bign-pubkey"
#define LN_bign_pubkey "bign-pubkey"

#endif /* __BTLS_OIDS_H */

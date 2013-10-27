#ifndef __BELT_SUITE_H
#define __BELT_SUITE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Äàííûå äëÿ òåñòîâ BELT_ECB */
extern const unsigned char ECB_1_X[32];	
extern const unsigned char ECB_1_M[16];	

extern const unsigned char ECB_2_X[24];	
extern const unsigned char ECB_2_M[54];	
	
extern const unsigned char ECB_3_X[16];	
extern const unsigned char ECB_3_M[32];	

/* Äàííûå äëÿ òåñòîâ BELT_CBC */
extern const unsigned char CBC_1_X[32];	
extern const unsigned char CBC_1_M[32];	
extern const unsigned char CBC_1_S[16];	
	
extern const unsigned char CBC_2_X[24];	
extern const unsigned char CBC_2_M[54];	
extern const unsigned char CBC_2_S[16];	

extern const unsigned char CBC_3_X[16];	
extern const unsigned char CBC_3_S[16];	

/* Äàííûå äëÿ òåñòîâ BELT_CFB */
extern const unsigned char CFB_1_X[32];	
extern const unsigned char CFB_1_M[64];	
extern const unsigned char CFB_1_S[16];	

extern const unsigned char CFB_2_X[24];	
extern const unsigned char CFB_2_M[54];	
extern const unsigned char CFB_2_S[16];	
	
extern const unsigned char CFB_3_X[16];	
extern const unsigned char CFB_3_M[32];	
extern const unsigned char CFB_3_S[16];	

/* Äàííûå äëÿ òåñòîâ BELT_CTR */
extern const unsigned char CTR_1_X[32];	
extern const unsigned char CTR_1_S[16];	
	
extern const unsigned char CTR_2_X[24];	
extern const unsigned char CTR_2_M[54];	
extern const unsigned char CTR_2_S[16];	

extern const unsigned char CTR_3_X[16];	
extern const unsigned char CTR_3_M[16];	
extern const unsigned char CTR_3_S[16];	
	
/* Äàííûå äëÿ òåñòîâ BELT_MAC */
extern const unsigned char MAC_1_X[32];	
extern const unsigned char MAC_1_M[12];	
	
extern const unsigned char MAC_2_X[24];	
extern const unsigned char MAC_2_M[32];	

extern const unsigned char MAC_3_X[16];	
extern const unsigned char MAC_3_M[54];	

/* Äàííûå äëÿ òåñòîâ BELT_HSH */
extern const unsigned char HSH_1_M[12];	
	
extern const unsigned char HSH_2_M[32];	

extern const unsigned char HSH_3_M[54];	

/* Äàííûå äëÿ òåñòîâ BELT_DWR */
extern const unsigned char DWR_1_X[32];	
extern const unsigned char DWR_1_M[32];	
extern const unsigned char DWR_1_P[54];	
extern const unsigned char DWR_1_S[16];	

extern const unsigned char DWR_2_X[32];	
extern const unsigned char DWR_2_P[32];	
extern const unsigned char DWR_2_M[54];	
extern const unsigned char DWR_2_S[16];	
	
extern const unsigned char DWR_3_X[32];	
extern const unsigned char DWR_3_P[12];	
extern const unsigned char DWR_3_S[16];	

/* Äàííûå äëÿ òåñòîâ BELT_KWR */
extern const unsigned char KWR_1_X[32];	
extern const unsigned char KWR_1_K[32];	
extern const unsigned char KWR_1_U[16];	

extern const unsigned char KWR_2_X[32];	
extern const unsigned char KWR_2_K[24];	
extern const unsigned char KWR_2_U[16];	
	
extern const unsigned char KWR_3_X[32];	
extern const unsigned char KWR_3_K[16];	
extern const unsigned char KWR_3_U[16];	

/* Äàííûå äëÿ òåñòîâ BELT_REP */
extern const unsigned char REP_1_X[32];
extern const unsigned char REP_1_L[12];
extern const unsigned char REP_1_U[16];

extern const unsigned char REP_2_X[32];
extern const unsigned char REP_2_L[12];
extern const unsigned char REP_2_U[16];
extern const unsigned char REP_2_R[24];
	
extern const unsigned char REP_3_X[32];
extern const unsigned char REP_3_L[12];
extern const unsigned char REP_3_U[16];
extern const unsigned char REP_4_X[24];
extern const unsigned char REP_4_L[12];
extern const unsigned char REP_4_U[16];
	
extern const unsigned char REP_5_X[24];
extern const unsigned char REP_5_L[12];
extern const unsigned char REP_5_U[16];

extern const unsigned char REP_6_X[16];
extern const unsigned char REP_6_L[12];
extern const unsigned char REP_6_U[16];

#ifdef __cplusplus
}
#endif
#endif /* __BELT_SUITE_H */
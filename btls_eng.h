#ifndef __BTLS_ENG_H
#define __BTLS_ENG_H

#ifdef __cplusplus
extern "C" {
#endif

#define ENGINE_NAME "btls"

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
void ENGINE_load_btls(void);
int get_bign_nid();
int get_belt_mac_nid();
#endif	/* OPENSSL_NO_DYNAMIC_ENGINE */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BTLS_ENG_H */
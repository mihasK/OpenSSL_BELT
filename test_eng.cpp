// btls_test.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <tchar.h>

#include "btls_utl.h"
#include "btls_eng.h"
#include "belt_suite.h"
#include "bign128_suite.h"

// макрос для вывода данных на консоль
#define DATA2CONSOLE(data, name) {\
	printf("\n"); \
	printf(name); printf("[%02u] =", sizeof(data)); \
	for (j=0; j<sizeof(data); j++) \
		if (j%4 == 0) printf(" %02X", data[j]);\
		else printf("%02X", data[j]);\
	} 

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

int _tmain(int argc, _TCHAR* argv[])
{
	int j, ret = 0;
	ENGINE *e;
	int encr;
	EVP_PKEY *pkey = NULL;
	const EVP_MD * pbelt_hash;
	EVP_PKEY_CTX *pkey_ctx;
	EVP_MD_CTX hash_ctx;
	unsigned char data[54];
	unsigned char sign[48];
	size_t		  sl;	
	BIO	*out;
		
	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	RAND_seed(rnd_seed, sizeof(rnd_seed));

	RAND_pseudo_bytes(data, sizeof(data));

	// Для вывода ошибок (почему-то ошибки не выводятся ....)
	/*out=BIO_new(BIO_s_file());
	if (out == NULL) return -1;
	BIO_set_fp(out, stdout, BIO_NOCLOSE);*/

	ENGINE_load_btls();

	e = ENGINE_by_id(ENGINE_NAME);
	if(!e) return -1;  // the engine isn't available 
	if(!ENGINE_init(e)) 
	{
         ENGINE_free(e); // the engine couldn't initialise, release 'e'
		 return -1;
	}

	/* Код, который не работает в функциях OpenSSL при статическом
	подключении "нашего" энжайна (поэтому были реализованы функции 
	из модуля btls_utl.c). Желательно разобараться, может так и надо ...

	const EVP_PKEY_ASN1_METHOD *ameth;
	ameth = EVP_PKEY_asn1_find(&e, bign_nid); 
	*/

	// Выработаем ЭЦП
	pkey_ctx =  EVP_PKEY_CTX_new_id(get_bign_nid(), e);
	if (!pkey_ctx) return -1;

	ret = EVP_PKEY_keygen_init(pkey_ctx);
	if (ret <= 0) return -1;

	ret = EVP_PKEY_keygen(pkey_ctx, &pkey);
	if (ret <= 0) return -1;

	pbelt_hash = EVP_get_digestbyname("belt-hash");
	if (!pbelt_hash) return -1;

	EVP_MD_CTX_init(&hash_ctx);

	ret = EVP_SignInit(&hash_ctx, pbelt_hash);
	if (ret <= 0) return -1;

	ret = EVP_SignUpdate(&hash_ctx, data, sizeof(data));
	if (ret <= 0) return -1;

	ret = EVP_SignFinal(&hash_ctx, sign, &sl, pkey);
	if (ret <= 0) return -1;

	// Проверим ранее выработанную ЭЦП
	EVP_MD_CTX_init(&hash_ctx);

	ret = EVP_VerifyInit(&hash_ctx, pbelt_hash);
	if (ret <= 0) return -1;

	ret = EVP_VerifyUpdate(&hash_ctx, data, sizeof(data));
	if (ret <= 0) return -1;

	ret = EVP_VerifyFinal(&hash_ctx, sign, sizeof(sign), pkey);
	if (ret <= 0) return -1;

	EVP_MD_CTX_cleanup(&hash_ctx);
	EVP_PKEY_CTX_free(pkey_ctx);
	EVP_PKEY_free(pkey);
	pkey = NULL;
	pkey_ctx = NULL;

	/*
	Вычисли и проверим ЭЦП по-другому
	*/
	pkey_ctx =  EVP_PKEY_CTX_new_id(get_bign_nid(), e);
	if (!pkey_ctx) return -1;

	ret = EVP_PKEY_keygen_init(pkey_ctx);
	if (ret <= 0) return -1;

	ret = EVP_PKEY_keygen(pkey_ctx, &pkey);
	if (ret <= 0) return -1;

	pbelt_hash = EVP_get_digestbyname("belt-hash");
	if (!pbelt_hash) return -1;

	ret = EVP_DigestSignInit(&hash_ctx, &pkey_ctx, pbelt_hash, e, pkey);
	if (ret <= 0) return -1;

	ret = EVP_DigestSignUpdate(&hash_ctx, ECS_01_M, sizeof(ECS_01_M));
	if (ret <= 0) return -1;

	ret = EVP_DigestSignFinal(&hash_ctx, sign, &sl);
	if (ret <= 0) return -1;
	
	ret = EVP_DigestVerifyInit(&hash_ctx, &pkey_ctx, pbelt_hash, e, pkey);
	if (ret <= 0) return -1;

	ret = EVP_DigestVerifyUpdate(&hash_ctx, ECS_01_M, sizeof(ECS_01_M));
	if (ret <= 0) return -1;

	ret = EVP_DigestVerifyFinal(&hash_ctx, sign, sl);
	if (ret <= 0) return -1;
	
	EVP_MD_CTX_cleanup(&hash_ctx);
	EVP_PKEY_free(pkey);
	pkey = NULL;
	pkey_ctx = NULL;

	// тестирование алгоритмов ассиметричного шифрования
	/*EVP_PKEY_CTX * pctx;
	size_t eklen;
	size_t kklen;
	unsigned char *ek;
	unsigned char k[54];
	unsigned char kk[54];

	memset(k, 0xAA, sizeof(k));
	memset(kk, 0x00, sizeof(k));

	pkey_ctx =  EVP_PKEY_CTX_new_id(get_bign_nid(), e);
	if (!pkey_ctx) return -1;

	ret = EVP_PKEY_keygen_init(pkey_ctx);
	if (ret <= 0) return -1;

	ret = EVP_PKEY_keygen(pkey_ctx, &pkey);
	if (ret <= 0) return -1;

	pbelt_hash = EVP_get_digestbyname("belt-hash");
	if (!pbelt_hash) return -1;

	ret = EVP_DigestVerifyInit(&hash_ctx, &pkey_ctx, pbelt_hash, e, pkey);
	if (ret <= 0) return -1;

	pctx = pkey_ctx;

	if (EVP_PKEY_encrypt_init(pctx) <= 0) 
		return -1;
	if (EVP_PKEY_encrypt(pctx, NULL, &eklen, k, sizeof(k)) <= 0) 
		return -1;

	ek = (unsigned char*) OPENSSL_malloc(eklen);
	if (ek == NULL) return -1;
		
	if (EVP_PKEY_encrypt(pctx, ek, &eklen, k, sizeof(k)) <= 0)
		return -1;

	if (EVP_PKEY_decrypt_init(pctx) <= 0) 
		return -1;

	if (EVP_PKEY_decrypt(pctx, kk, &kklen, ek, eklen) <= 0)
		return -1;

	if (pctx)
		EVP_PKEY_CTX_free(pctx);
	if (ek)
		OPENSSL_free(ek);*/

	// Вычислим имитовставку
	EVP_MD_CTX ctx;
	EVP_PKEY *mac_key;
	unsigned char A1[EVP_MAX_MD_SIZE];
	size_t A1_len;
	const EVP_MD *md;

	EVP_MD_CTX_init(&ctx);
	mac_key = EVP_PKEY_new_mac_key(get_belt_mac_nid(), e, MAC_1_X, sizeof(MAC_1_X));

	md = EVP_get_digestbyname("belt-mac");
	if (!md) return -1;

	if (EVP_DigestSignInit(&ctx, NULL, md, e, mac_key) <= 0) return -1;
	if (EVP_DigestSignUpdate(&ctx, MAC_1_M, sizeof(MAC_1_M)) <= 0) return -1;
	if (EVP_DigestSignFinal(&ctx,A1,&A1_len) <= 0) return -1;

	EVP_PKEY_free(mac_key);
	EVP_MD_CTX_cleanup(&ctx);
	OPENSSL_cleanse(A1,sizeof(A1));

	// Протестируем режим счетчика
	const EVP_CIPHER * pbelt_ctr = EVP_get_cipherbyname("belt-ctr");
	if (!pbelt_ctr) return -1;

	EVP_CIPHER_CTX cipher_ctx;
	int partl = 5;
	int outl;

	unsigned char CTR_1_M[64], CTR_1_E[64];
	memset(CTR_1_M, 0, sizeof(CTR_1_M));

	EVP_CIPHER_CTX_init(&cipher_ctx);
	encr = 1;
	ret = EVP_CipherInit_ex(&cipher_ctx, pbelt_ctr, NULL, CTR_1_X, CTR_1_S, encr);
	if (ret <= 0) return -1;

	ret = EVP_CipherUpdate(&cipher_ctx, CTR_1_E, &outl, CTR_1_M, sizeof(CTR_1_M) - partl);
	if (ret <= 0) return -1;

	ret = EVP_CipherUpdate(&cipher_ctx, CTR_1_E + sizeof(CTR_1_E) - partl, &outl, CTR_1_M + sizeof(CTR_1_M) - partl, partl);
	if (ret <= 0) return -1;
	
	ret = EVP_CipherFinal_ex(&cipher_ctx, NULL, &outl);
	if (ret <= 0) return -1;

	EVP_CIPHER_CTX_cleanup(&cipher_ctx);

	DATA2CONSOLE(CTR_1_E, "CTR_1_E");

	// Тестирование режима одновременного шифрования и имитозащиты
	unsigned char DWR_1_E[sizeof(DWR_1_M)];
	unsigned char DWR_1_I[8];
	unsigned char DWR_1_MM[sizeof(DWR_1_M)];

	const EVP_CIPHER * gcm = EVP_get_cipherbyname("belt-dwp");
	if (!gcm) return -1;
	
	EVP_CIPHER_CTX_init(&cipher_ctx);
	/*
	 * Init the cipher and set the key and iv
	 */
	ret = EVP_CipherInit_ex(&cipher_ctx, gcm, NULL, DWR_1_X, DWR_1_S, 1);
	if (ret <= 0) return -1;
	/*
	 * Process the AAD
	 */
	ret = EVP_Cipher(&cipher_ctx, NULL, DWR_1_P, sizeof(DWR_1_P));
	if (ret != sizeof(DWR_1_P)) return -1;
	/*
	 * Process the plaintext
	 */
	ret = EVP_Cipher(&cipher_ctx, DWR_1_E, DWR_1_M, sizeof(DWR_1_M));
	if (ret <= 0) return -1;

	DATA2CONSOLE(DWR_1_E, "DWR_1_E");
	/*
	 * This is goofy, but we need to invoke EVP_Cipher again to calculate the tag
	 */
	ret = EVP_Cipher(&cipher_ctx, NULL, NULL, 0);
	if (ret < 0) return -1;
	/*
	 * OK, now that the tag has been calculated, get the TAG and display it.
	 * A real application would typically include the tag along with the
	 * ciphertext when transmitting to a peer.
	 */
	ret = EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_GET_TAG, sizeof(DWR_1_I), DWR_1_I);
	if (ret <= 0) return -1;
	DATA2CONSOLE(DWR_1_I, "DWR_1_I");
	/*
	 * Note, if you fail to cleanup, there will be a memory leak.
	 */
	ret = EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	if (ret <= 0) return -1;
	/************************************************************************************
	 * OK, now let's decrypt and see if the original plaintext matches
	 ************************************************************************************/
	EVP_CIPHER_CTX_init(&cipher_ctx);
	/*
	 * Init the cipher and set the key
	 */
	ret = EVP_CipherInit_ex(&cipher_ctx, gcm, NULL, DWR_1_X, DWR_1_S, 0);
	if (ret <= 0) return -1;
	/*
	 * Set dummy tag before processing AAD.  Otherwise the AAD can
	 * not be processed.  
	 */
	ret = EVP_CIPHER_CTX_ctrl(&cipher_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(DWR_1_I), DWR_1_I);
	if (ret <= 0) return -1;
	/*
	 * Process the AAD
	 */
	ret = EVP_Cipher(&cipher_ctx, NULL, DWR_1_P, sizeof(DWR_1_P));
	if (ret != sizeof(DWR_1_P)) return -1;
	/*
	 * Decrypt the ciphertext
	 */
	ret = EVP_Cipher(&cipher_ctx, DWR_1_MM, DWR_1_E, sizeof(DWR_1_E));
	if (ret <= 0) return -1;
	/*
	 * Check the tag
	 */
	ret = EVP_Cipher(&cipher_ctx, NULL, NULL, 0);
	if (ret < 0) return -1;
	/*
	 * Cleanup again to avoid memory leak
	 */
	EVP_CIPHER_CTX_cleanup(&cipher_ctx);
	/*
	 * Compare to original plaintext to see if the test passed
	 */
	DATA2CONSOLE(DWR_1_MM, "DWR_1_MM");
	
	ENGINE_finish(e);
	ENGINE_free(e);

	return 0;
}


/*
 * test.c
 *
 *  Created on: Jan 1, 2013
 *      Author: mihas
 */
#include <stddef.h>
#include "../belt.h"
#include <openssl/evp.h>

//#include <openssl/eng_dyn.h>


int testAddDigest(){

	int r = EVP_add_digest(&belt_md);
	printf("add_digest result: %i \n",r);
	EVP_MD * md = EVP_get_digestbyname("messageDigest");

	if(md != &belt_md){
		printf("Error, md is %i \n", md);
		return 0;
	}


	printf("md type is : %i \n", md->type);
	printf("testAddDigest: passed!\n");
	return 1;
}


int test_load_engine() {
/* TODO: try to implement fair cmd-load
	char* args[] = {
			"engine",
			"dynamic",
			"-pre",
			"SO_PATH://home//mihas//eclipse//workspace//Belt_Engine//sharedDebug//libBelt_Engine.so",
			"-pre",
			"LIST_ADD:1",
			"-pre",
			"LOAD"
	};
	int argCount = 8;
	engine_main(argCount, args);
	*/

	ENGINE* engine = ENGINE_new();
	//bind_belt(engine, "belt_01");
	io();
	//ENGINE_add(engine);

	EVP_MD * md = EVP_get_digestbyname("messageDigest");
	if(!md){
		printf("Error, md was not added \n");
		return 0;
	}
	printf("md type is : %i \n", md->type);

	printf("test_load_engine: passed!\n");
	return 1;
}

int main() {
	printf("Hello world");
	//testAddDigest();
	test_load_engine();
	return 0;
}


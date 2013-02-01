/*
 * belt_error.c
 *
 *  Created on: Feb 1, 2013
 *      Author: mihas
 */

#include <openssl/err.h>

static int BELT_lib_error_code=0;


void errorBelt(int function, int reason, char *file, int line) {
	if (BELT_lib_error_code == 0)
		BELT_lib_error_code=ERR_get_next_error_library();
	ERR_PUT_error(BELT_lib_error_code,function,reason,file,line);
}

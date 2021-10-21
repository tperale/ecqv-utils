#ifndef __SCHNORR_H_
#define __SCHNORR_H_

#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void schnorr_sign(char* priv_key_hex, char* message);
void schnorr_verify(char* pub_key, char* v_pub_hex, char* schnorr_sign, char* message);

#endif

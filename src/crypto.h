#ifndef __ECQV_CRYPTO_H_
#define __ECQV_CRYPTO_H_

#include <stddef.h>

void ecqv_pk_extract(char* key);
void ecqv_priv_extract(char* key_str);
size_t ecqv_encrypt(const char* msg, const char* key, char* ciphertext);
size_t ecqv_decrypt(const char* msg, const char* key, char* plaintext);

#endif

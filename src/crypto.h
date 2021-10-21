#ifndef __ECQV_CRYPTO_H_
#define __ECQV_CRYPTO_H_

#include <stddef.h>

size_t ecqv_encrypt(const char* msg, const char* key, char* ciphertext);
size_t ecqv_decrypt(const char* msg, const char* key, char* plaintext);

#endif

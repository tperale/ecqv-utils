#ifndef __ECQV_CRYPTO_H_
#define __ECQV_CRYPTO_H_

#include <stddef.h>

void ecqv_pk_extract(char* key);
void ecqv_priv_extract(char* key_str);
size_t ecqv_encrypt_len(const unsigned char* msg, size_t msg_len, const char* key, unsigned char* ciphertext);
size_t ecqv_encrypt(const unsigned char* msg, const char* key, unsigned char* ciphertext);
size_t ecqv_decrypt(const unsigned char* msg, const char* key, unsigned char* plaintext);
void ecqv_ecdh(char* pub_hex, char* priv_hex);
void ecqv_gen_key();

#endif

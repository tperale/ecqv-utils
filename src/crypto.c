#include "crypto.h"
#include "utils.h"

#include <string.h>
#include <openssl/evp.h>

size_t ecqv_encrypt(const char* msg, const char* key, char* ciphertext) {
    EVP_CIPHER_CTX *ctx;
    unsigned char *iv = (unsigned char *)"0123456789012345";
    int len;
    int ciphertext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*) key, iv);
    EVP_EncryptUpdate(ctx, (unsigned char*) ciphertext, &len, (const unsigned char*) msg, strlen((const char*) msg));

    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, (unsigned char*) (ciphertext + len), &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return (size_t) ciphertext_len;
}

size_t ecqv_decrypt(const char* msg, const char* key, char* plaintext) {
    EVP_CIPHER_CTX *ctx;
    unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char ciphertext[128];
    int len, cipher_len, plaintext_len;

    cipher_len = ecqv_decrypt_b64(msg, strlen(msg), (char*) ciphertext);

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*) key, iv);
    EVP_DecryptUpdate(ctx, (unsigned char*) plaintext, &len, (unsigned char*) ciphertext, cipher_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, (unsigned char*) plaintext + len, &len);
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';

    EVP_CIPHER_CTX_free(ctx);

    return (size_t) plaintext_len;
}



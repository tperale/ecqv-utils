#include "crypto.h"
#include "utils.h"

#include <openssl/ossl_typ.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

void ecqv_pk_extract(char* key_str) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    EC_POINT* pk = EC_POINT_new(group);
    if (access(key_str, F_OK) == 0) {
        EC_KEY *key = ecqv_import_pem(key_str);
        if (key == NULL) {
            exit(EXIT_FAILURE);
        }
        EC_POINT_copy(pk, EC_KEY_get0_public_key(key));
        EC_KEY_free(key);
    } else {
        BIGNUM* priv = BN_new();
        BN_hex2bn(&priv, key_str);
        EC_POINT_mul(group, pk, priv, NULL, NULL, NULL);
        BN_free(priv);
    }
 
    ecqv_point_print(group, pk);
    EC_POINT_free(pk);
}

void ecqv_priv_extract(char* key_str) {
    if (access(key_str, F_OK) == 0) {
        EC_KEY *key = ecqv_import_pem(key_str);
        if (key == NULL) {
            exit(EXIT_FAILURE);
        }
        const BIGNUM* priv = EC_KEY_get0_private_key(key);
        ecqv_bn_print(priv);
        EC_KEY_free(key);
    } 
}

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
    unsigned char ciphertext[256];
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

EC_POINT* ecqv_mul(BIGNUM* priv, EC_POINT* pub) {
    /* EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx); */    
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* res = EC_POINT_new(group);
    EC_POINT_mul(group, res, NULL, pub, priv, NULL);

    return res;
}

void ecqv_ecdh(char* pub_hex, char* priv_hex) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* pub = import_public_key(group, pub_hex);
    BIGNUM* priv = import_priv_key(priv_hex);

    EC_POINT* mul = ecqv_mul(priv, pub);
    ecqv_point_print(group, mul);

    EC_POINT_free(mul);
    BN_free(priv);
    EC_POINT_free(pub);
}


BIGNUM* _ecqv_gen_key() {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, NULL);

    BIGNUM* rand = BN_new();
    BN_rand_range(rand, order);

    BN_free(order);

    return rand;
}

void ecqv_gen_key() {
    BIGNUM* rand = _ecqv_gen_key();
    ecqv_bn_print(rand);
    BN_free(rand);
}

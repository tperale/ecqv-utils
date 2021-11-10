#include "utils.h"
#include <openssl/ossl_typ.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

unsigned char* print_b64_stream(const unsigned char* msg, size_t len) {
    BIO *bio = NULL, *b64 = NULL;
    BUF_MEM *buffer_ptr = NULL;
    unsigned char *b64text = NULL;

    if(len <= 0) goto cleanup;

    b64 = BIO_new(BIO_f_base64());
    if(b64 == NULL) goto cleanup;

    bio = BIO_new(BIO_s_mem());
    if(bio == NULL) goto cleanup;

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_push(b64, bio);

    if(BIO_write(bio, msg, (int) len) <= 0) goto cleanup;

    if(BIO_flush(bio) != 1) goto cleanup;

    BIO_get_mem_ptr(bio, &buffer_ptr);

    b64text = (unsigned char*) malloc((buffer_ptr->length + 1) * sizeof(unsigned char));
    if(b64text == NULL) goto cleanup;

    memcpy(b64text, buffer_ptr->data, buffer_ptr->length);
    b64text[buffer_ptr->length] = '\0';
    BIO_set_close(bio, BIO_NOCLOSE);

cleanup:
    BIO_free_all(bio);
    return b64text;
}

void print_b64(const unsigned char* msg, size_t len) {
    unsigned char* out = print_b64_stream(msg, len);
    printf("%s\n", out);
    free(out);
}

size_t ecqv_decrypt_b64(const unsigned char* b64_msg, size_t length, unsigned char* out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf(b64_msg, length);
    bio = BIO_push(b64, bio);
    int ret = BIO_read(bio, out, length);
    out[ret] = '\0';
    BIO_free_all(bio);
    return (size_t) ret;
}

void ecqv_bn_print_hex(const BIGNUM* bn) {
    char* str = BN_bn2hex(bn);
    printf("%s\n", str);
    OPENSSL_free(str);
}

unsigned char* ecqv_bn2b64(const BIGNUM* bn) {
    unsigned char *out = (unsigned char*) OPENSSL_malloc(BN_num_bytes(bn) * sizeof(unsigned char));
    int len = BN_bn2bin(bn, out);
    unsigned char* ret = print_b64_stream(out, len);
    OPENSSL_free(out);

    return ret;
}

void ecqv_bn_print(const BIGNUM* bn) {
    unsigned char* out = ecqv_bn2b64(bn);
    printf("%s\n", out);
    free(out);
}

void ecqv_point_print_hex(const EC_GROUP* group, const EC_POINT* point) {
    char *str = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL);
    printf("%s\n", str);
    OPENSSL_free(str);
}

void ecqv_point_print(const EC_GROUP* group, const EC_POINT* point) {
    unsigned char *out = NULL;
    int len = EC_POINT_point2buf(group, point, POINT_CONVERSION_UNCOMPRESSED, &out, NULL);
    print_b64(out, len);
    OPENSSL_free(out);
}

/**
 * @desc Import a key from a .pem file filename
 *
 * @args{filename}
 *
 * @return
 */
EC_KEY *ecqv_import_pem(char* filename)
{
    FILE *file;
    EVP_PKEY *pk;
    EC_KEY *key;

    if ((file = fopen(filename, "rb")) == 0) {
        fprintf(stderr, "Error opening file '%s'\n", filename);
        exit(EXIT_FAILURE);
    }

    if ((pk = PEM_read_PrivateKey(file, NULL, NULL, NULL)) == 0) {
        fprintf(stderr, "Error importing the .PEM file with the private key.\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    if ((key = EVP_PKEY_get1_EC_KEY(pk)) == 0) {
        fprintf(stderr, "Error loading EC private key from EVP_PKEY.\n");
        fclose(file);
        EVP_PKEY_free(pk);
        exit(EXIT_FAILURE);
    }

    fclose(file);
    EVP_PKEY_free(pk);
    return key;
}

/**
 * @desc Import a string in the b64 format representing an EC public key.
 *
 * @args{group}
 * @args{pk_str} Hex format public key string
 *
 * @return Point on the curve representing the public key.
 */
EC_POINT *ecqv_import_point(const EC_GROUP *group, char* pk_str)
{
    EC_POINT *pk = EC_POINT_new(group);
    /* EC_POINT_hex2point(group, pk_str, pk, NULL); */
    unsigned char bin[256];
    int len = ecqv_decrypt_b64((unsigned char*) pk_str, strlen(pk_str), bin);
    EC_POINT_oct2point(group, pk, bin, len, NULL);

    return pk;
}

EC_POINT* import_public_key(const EC_GROUP *group, char* key_str)
{
    EC_POINT* pk = EC_POINT_new(group);
    if (access(key_str, F_OK) == 0) {
        EC_KEY *key = ecqv_import_pem(key_str);
        if (key == NULL) {
            exit(EXIT_FAILURE);
        }
        EC_POINT_copy(pk, EC_KEY_get0_public_key(key));
        EC_KEY_free(key);
    } else {
        unsigned char bin[256];
        int len = ecqv_decrypt_b64((unsigned char*) key_str, strlen(key_str), bin);
        EC_POINT_oct2point(group, pk, bin, len, NULL);

    }
    return pk;
}

BIGNUM* import_priv_key(char* priv_str)
{
    BIGNUM* priv = BN_new();
    if (access(priv_str, F_OK) == 0) {
        EC_KEY *key = ecqv_import_pem(priv_str);
        if (key == NULL) {
            exit(EXIT_FAILURE);
        }
        BN_copy(priv, EC_KEY_get0_private_key(key));
        EC_KEY_free(key);
    } else {
        unsigned char bin[256];
        int len = ecqv_decrypt_b64((unsigned char*) priv_str, strlen(priv_str), bin);
        BN_bin2bn(bin, len, priv);
        /* BN_hex2bn(&priv, priv_str); */
    }
    return priv;
}

EC_POINT* ecqv_pk_extract_from_bn(const EC_GROUP *group, BIGNUM* bn) {
    EC_POINT* pk = EC_POINT_new(group);
    EC_POINT_mul(group, pk, bn, NULL, NULL, NULL);
    return pk;
}

/* EC_POINT* ecqv_pk_extract_from_hex(const EC_GROUP *group, char* bn_hex) { */
/*     BIGNUM *priv_k = BN_new(); */
/*     BN_hex2bn(&priv_k, bn_hex); */
/*     EC_POINT* pk = EC_POINT_new(group); */
/*     EC_POINT_mul(group, pk, priv_k, NULL, NULL, NULL); */
/*     BN_free(priv_k); */
/*     return pk; */
/* } */

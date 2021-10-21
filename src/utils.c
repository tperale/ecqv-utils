#include "utils.h"
#include <openssl/ossl_typ.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

void ecqv_bn_print(const BIGNUM* bn) {
    char *str = BN_bn2hex(bn);
    printf("%s\n", str);
    OPENSSL_free(str);
}

void ecqv_point_print(const EC_GROUP* group, const EC_POINT* point) {
    char *str = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL);
    printf("%s\n", str);
    OPENSSL_free(str);
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


const EC_POINT* import_public_key(const EC_GROUP *group, char* ca_pk)
{
    EC_POINT* pk = EC_POINT_new(group);
    if (access(ca_pk, F_OK) == 0) {
        EC_KEY *key = ecqv_import_pem(ca_pk);
        if (key == NULL) {
            exit(EXIT_FAILURE);
        }
        EC_POINT_copy(pk, EC_KEY_get0_public_key(key));
        EC_KEY_free(key);
    } else {
        EC_POINT_hex2point(group, ca_pk, pk, NULL);
    }
    return pk;
}

const BIGNUM* import_priv_key(char* priv_str)
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
        BN_hex2bn(&priv, priv_str);
    }
    return priv;
}

/**
 * @desc Import a string in the HEX format representing an EC public key.
 *
 * @args{group}
 * @args{pk_str} Hex format public key string
 *
 * @return Point on the curve representing the public key.
 */
EC_POINT *ecqv_import_point(const EC_GROUP *group, char* pk_str)
{
    EC_POINT *pk = EC_POINT_new(group);
    EC_POINT_hex2point(group, pk_str, pk, NULL);

    return pk;
}

EC_POINT* ecqv_pk_extract_from_bn(const EC_GROUP *group, BIGNUM* bn) {
    EC_POINT* pk = EC_POINT_new(group);
    EC_POINT_mul(group, pk, bn, NULL, NULL, NULL);
    return pk;
}

EC_POINT* ecqv_pk_extract_from_hex(const EC_GROUP *group, char* bn_hex) {
    BIGNUM *priv_k = BN_new();
    BN_hex2bn(&priv_k, bn_hex);
    EC_POINT* pk = EC_POINT_new(group);
    EC_POINT_mul(group, pk, priv_k, NULL, NULL, NULL);
    BN_free(priv_k);
    return pk;
}

void print_b64(const char* msg, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, 0);
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_write(bio, msg, len);
    (void)BIO_flush(bio);
    BIO_free_all(bio);
}

size_t ecqv_decrypt_b64(const char* b64_msg, size_t length, char* out) {
    BIO *b64 = BIO_new(BIO_f_base64());
    /* BIO_set_flags(b64, 0); */
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf(b64_msg, length);
    bio = BIO_push(b64, bio);
    int ret = BIO_read(bio, out, length);
    out[ret] = '\0';
    BIO_free_all(bio);
    return (size_t) ret;
}



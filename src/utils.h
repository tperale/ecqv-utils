#ifndef __UTILS_H_
#define __UTILS_H_

#include <openssl/bn.h>
#include <openssl/ec.h>


#ifndef ECQV_DEBUG_MODE
#define ECQV_DEBUG_MODE 0
#endif

#ifndef ECQV_DEBUG
#define ECQV_DEBUG(args) \
    do { if (ECQV_DEBUG_MODE) { args; } } while (0)
#endif

unsigned char* ecqv_bn2b64(const BIGNUM* bn);
void ecqv_bn_print(const BIGNUM* bn);
void ecqv_bn_print_hex(const BIGNUM* bn);

void ecqv_point_print(const EC_GROUP* group, const EC_POINT* point);
void ecqv_point_print_hex(const EC_GROUP* group, const EC_POINT* point);

/**
 * @desc Import a key from a .pem file filename
 *
 * @args{filename}
 *
 * @return
 */
EC_KEY *ecqv_import_pem(char* filename);

EC_POINT* import_public_key(const EC_GROUP *group, char* pk);

BIGNUM* import_priv_key(char* priv_str);

/**
 * @desc Import a string in the HEX format representing an EC public key.
 *
 * @args{group}
 * @args{pk_str} Hex format public key string
 *
 * @return Point on the curve representing the public key.
 */
EC_POINT *ecqv_import_point(const EC_GROUP *group, char* pk_str);

EC_POINT* ecqv_pk_extract_from_bn(const EC_GROUP *group, BIGNUM* bn);

unsigned char* print_b64_stream(const unsigned char* msg, size_t len);

void print_b64(const unsigned char* msg, size_t len);

size_t ecqv_decrypt_b64(const unsigned char* b64_msg, size_t length, unsigned char* out);

#endif

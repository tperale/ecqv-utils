#include "schnorr.h"
#include "utils.h"

#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

/* #include <openssl/bn.h> */
/* #include <openssl/bio.h> */
/* #include <openssl/ecdh.h> */
/* #include <openssl/objects.h> */
/* #include <openssl/rand.h> */
/* #include <openssl/ec.h> */
/* #include <openssl/pem.h> */

static BIGNUM* schnorr_hash(const EC_GROUP *group, char* msg, EC_POINT* V) {
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_create();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    BIGNUM *result = BN_new();
 
    char* V_hex = EC_POINT_point2hex(group, V, POINT_CONVERSION_UNCOMPRESSED, NULL);
   
    EVP_DigestInit_ex(hash_ctx, EVP_sha1(), 0);
    EVP_DigestUpdate(hash_ctx, msg, strlen(msg));
    EVP_DigestUpdate(hash_ctx, V_hex, strlen(V_hex));
    EVP_DigestFinal_ex(hash_ctx, hash, &hash_len);

    OPENSSL_free(V_hex);
    EVP_MD_CTX_free(hash_ctx);
    BN_bin2bn(hash, hash_len, result);
    return result;
}


void schnorr_sign(char* priv_key_hex, char* message) {
    BN_CTX *ctx = BN_CTX_new();
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    EC_KEY* _keypair = ecqv_import_pem(priv_key_hex);
    const BIGNUM* priv = EC_KEY_get0_private_key(_keypair);

    BIGNUM* v = BN_new();
    EC_POINT *vG = EC_POINT_new(group);

    BN_rand_range(v, order);
    EC_POINT_mul(group, vG, v, NULL, NULL, ctx); // Calculate the private key using the same generator as the CA key

    BIGNUM* h = schnorr_hash(group, message, vG);
   
    BIGNUM* hds = BN_new();
    /* BN_mul(hds, h, priv, ctx); */
    BN_mod_mul(hds, h, priv, order, ctx);

    BIGNUM* schnorr_sign = BN_new();
    /* BN_sub(schnorr_sign, v, hds); */
    BN_mod_sub(schnorr_sign, v, hds, order, ctx);

    ecqv_point_print(group, vG);
    ecqv_bn_print(schnorr_sign);

    EC_POINT* puub = EC_POINT_new(group);
    EC_POINT_mul(group, puub, schnorr_sign, NULL, NULL, NULL);
    ecqv_point_print(group, puub);

    BN_free(v);
    BN_free(hds);
    EC_KEY_free(_keypair);
    BN_free(order);
    BN_CTX_free(ctx);
}

void schnorr_verify(char* pub_key, char* v_pub_hex, char* schnorr_sign, char* message) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    const EC_POINT* pub = import_public_key(group, pub_key);

    EC_POINT *V = ecqv_import_point(group, v_pub_hex);
    EC_POINT *res = EC_POINT_new(group);

    BIGNUM* h = schnorr_hash(group, message, V);

    const BIGNUM* sign = import_priv_key(schnorr_sign);

    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_mul(group, res, sign, pub, h, ctx);

   
    /* BIGNUM* hds = BN_new(); */
    /* BN_mul(hds, h, priv, ctx); */

    /* EC_POINT_ */

    /* BN_sub(schnorr_sign, v, hds); */

    ecqv_point_print(group, res);

    BN_CTX_free(ctx);
    /* BN_free(v); */
    /* BN_free(hds); */
    /* EC_KEY_free(_keypair); */
    BN_free(order);
}

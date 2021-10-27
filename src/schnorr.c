#include "schnorr.h"
#include "opt.h"
#include "utils.h"

#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

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


static BIGNUM* _schnorr_sign(const EC_GROUP *group, BIGNUM* priv, BIGNUM* rand, char* message) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    EC_POINT *rand_pub = EC_POINT_new(group);
    BIGNUM* hds = BN_new();
    BIGNUM* schnorr_sign = BN_new();

    // Get the public key from the random number
    EC_POINT_mul(group, rand_pub, rand, NULL, NULL, ctx);

    BIGNUM* h = schnorr_hash(group, message, rand_pub);
   
    BN_mod_mul(hds, h, priv, order, ctx);

    BN_mod_sub(schnorr_sign, rand, hds, order, ctx);

    BN_free(h);
    BN_free(hds);
    EC_POINT_free(rand_pub);
    BN_free(order);
    BN_CTX_free(ctx);

    return schnorr_sign;
}

void schnorr_sign(char* priv_key, char* message) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(ECQV_EC_CURVE);
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    BIGNUM* priv = import_priv_key(priv_key);
    BIGNUM* v = BN_new();
    BN_rand_range(v, order);

    BIGNUM* sign = _schnorr_sign(group, priv, v, message);

    EC_POINT* vG = EC_POINT_new(group);
    EC_POINT_mul(group, vG, v, NULL, NULL, NULL);
    ecqv_point_print(group, vG);
    ecqv_bn_print(sign);

    BN_free(sign);
    BN_free(order);
    BN_free(priv);
    BN_free(v);
}

static EC_POINT* _schnorr_verify(const EC_GROUP* group, EC_POINT* pub, EC_POINT* rand_pub, BIGNUM* schnorr_sign, char* message) {
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT* res = EC_POINT_new(group);

    BIGNUM* h = schnorr_hash(group, message, rand_pub);
    EC_POINT_mul(group, res, schnorr_sign, pub, h, ctx);

    BN_CTX_free(ctx);

    return res;
}

void schnorr_verify(char* pub_key, char* v_pub_hex, char* schnorr_sign, char* message) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(ECQV_EC_CURVE);
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    EC_POINT* pub = import_public_key(group, pub_key);
    BIGNUM* sign = import_priv_key(schnorr_sign);
    EC_POINT *V = ecqv_import_point(group, v_pub_hex);

    EC_POINT *res = _schnorr_verify(group, pub, V, sign, message);
    
    printf("%i\n", !EC_POINT_cmp(group, res, V, NULL));

    EC_POINT_free(V);
    BN_free(sign);
    EC_POINT_free(pub);
    BN_free(order);
    EC_POINT_free(res);
}

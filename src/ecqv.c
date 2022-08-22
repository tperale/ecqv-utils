#include "ecqv.h"
#include "backend/io.h"
#include "opt.h"
#include "crypto.h"
#include "utils.h"

#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define ECQV_HASH EVP_sha1()

static BIGNUM* ecqv_hash_implicit_cert(const EC_GROUP* group, EC_POINT* P_u, char* U)
{
    EVP_MD_CTX *cert_ctx = EVP_MD_CTX_create();
    size_t Pu_buf_len;
    unsigned char* Pu_buf = NULL;
    unsigned char cert[EVP_MAX_MD_SIZE];
    unsigned int cert_len;
    BIGNUM *result = BN_new();
 
    // Step 5: Convert P_u to hex format
    Pu_buf_len = EC_POINT_point2oct(group, P_u, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    Pu_buf = OPENSSL_malloc(Pu_buf_len);
    EC_POINT_point2oct(group, P_u, POINT_CONVERSION_UNCOMPRESSED, Pu_buf, Pu_buf_len, NULL);
   
    // Step 6: Certificate encoding method call
    EVP_DigestInit_ex(cert_ctx, EVP_sha1(), 0);
    EVP_DigestUpdate(cert_ctx, Pu_buf, Pu_buf_len);
    EVP_DigestUpdate(cert_ctx, U, strlen(U));
    EVP_DigestFinal_ex(cert_ctx, cert, &cert_len);

    OPENSSL_free(Pu_buf);
    EVP_MD_CTX_free(cert_ctx);
    BN_bin2bn(cert, cert_len, result);
 
    return result;
}

void ecqv_cert_request(char* requester_key_path) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(ECQV_EC_CURVE);
    EC_POINT* pk = import_public_key(group, requester_key_path);

    ECQV_DEBUG(ecqv_point_print_hex(group, pk));

    ecqv_point_print(group, pk);

    EC_POINT_free(pk);
}

void ecqv_cert_generate(char* ca_key_path, char* requester_pk, char* identity, char* serv_key_path) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(ECQV_EC_CURVE);
    BIGNUM* ca_key = import_priv_key(ca_key_path);
    ECQV_DEBUG(printf("ca priv : "));
    ECQV_DEBUG(ecqv_bn_print_hex(ca_key));
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    EC_POINT *R_u = ecqv_import_point(group, requester_pk);
    ECQV_DEBUG(printf("R_u : "));
    ECQV_DEBUG(ecqv_point_print_hex(group, R_u));
    EC_POINT *kG = EC_POINT_new(group);
    BIGNUM *k;
    EC_POINT *P_u = EC_POINT_new(group);
    BIGNUM *e = NULL;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *ek = BN_new();
    BIGNUM *r = BN_new();

    // Step 1: Conversion from the hex format to a point on the elliptic curve

    // Step 2: Validate the R_u

    // Step 3: Generate an EC key pair (k, kG)
    if (serv_key_path) {
        k = import_priv_key(serv_key_path);
    } else {
        k = BN_new();
        BN_rand_range(k, order);
    }
    EC_POINT_mul(group, kG, k, NULL, NULL, NULL); // Calculate the private key using the same generator as the CA key
                                                  //
    // Step 4: Compute the EC point P_u = R_u + kG
    EC_POINT_add(group, P_u, R_u, kG, NULL);

    // Step 5: Convert P_u to hex format
    // Step 6: Certificate encoding method call
    // Step 7: Use the hash function to compute e = H_n(Cert_U)
    e = ecqv_hash_implicit_cert(group, P_u, identity);

    // Step 8: r = ek + d_ca
    BN_mul(ek, e, k, ctx);
    BN_mod_add(r, ek, ca_key, order, ctx);

    // Printing the implicit certificate
    ECQV_DEBUG(printf("P_u : "));
    ECQV_DEBUG(ecqv_point_print_hex(group, P_u));
    ECQV_DEBUG(printf("r : "));
    ECQV_DEBUG(ecqv_bn_print_hex(r));
    ecqv_point_print(group, P_u);
    ecqv_bn_print(r);

    // Freeing memory
    BN_free(ca_key);
    EC_POINT_free(R_u);
    EC_POINT_free(kG);
    BN_free(k);
    EC_POINT_free(P_u);
    BN_free(e);
    BN_free(ek);
    BN_free(r);
    BN_CTX_free(ctx);
}

void ecqv_cert_reception(char* requester_key_path, char* ca_pk, char* cert, char* U, char* r_str) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(ECQV_EC_CURVE);
    BIGNUM* req_key = import_priv_key(requester_key_path);
    EC_POINT *Q_ca = ecqv_import_point(group, ca_pk);
    EC_KEY *key = EC_KEY_new();
    EC_POINT *P_u = ecqv_import_point(group, cert);
    ECQV_DEBUG(printf("P_u : "));
    ECQV_DEBUG(ecqv_point_print_hex(group, P_u));
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = import_priv_key(r_str);
    ECQV_DEBUG(printf("r : "));
    ECQV_DEBUG(ecqv_bn_print_hex(r));
    BIGNUM *e = BN_new();
    BIGNUM *ek_u = BN_new();
    BIGNUM *d_u = BN_new();
    EC_POINT *ePu = EC_POINT_new(group);
    EC_POINT *Q_u = EC_POINT_new(group);

    // Step 2: Import 'r' parameter passed as CLI argument

    // Step 3: Calculate 'e' based on the hash of the implicit certificate 
    e = ecqv_hash_implicit_cert(group, P_u, U);
    
    BN_mul(ek_u, e, req_key, ctx);

    BIGNUM* order = BN_new();
    if (EC_GROUP_get_order(group, order, ctx) == 0) {
        printf("error\n");
    }
    BN_mod_add(d_u, ek_u, r, order, ctx);

    EC_POINT_mul(group, ePu, NULL, P_u, e, NULL);
 
    EC_POINT_add(group, Q_u, ePu, Q_ca, 0);

    ECQV_DEBUG(printf("Q_u : "));
    ECQV_DEBUG(ecqv_point_print_hex(group, Q_u));

    EC_KEY_set_group(key, group);
    EC_KEY_set_private_key(key, d_u);
    EC_KEY_set_public_key(key, Q_u);

    if (EC_KEY_check_key(key)) {
        ECQV_DEBUG(printf("d_u : "));
        ECQV_DEBUG(ecqv_bn_print_hex(d_u));
        ecqv_bn_print(d_u);
    } else {
        printf("Verification failed\n");
    }

    EC_POINT_free(Q_u);
    EC_POINT_free(Q_ca);
    EC_POINT_free(ePu);
    EC_POINT_free(P_u);
    BN_free(d_u);
    BN_free(ek_u);
    BN_free(e);
    BN_free(r);
    BN_CTX_free(ctx);
    EC_KEY_free(key);
    BN_free(req_key);
}

void ecqv_cert_pk_extract(char* ca_pk, char* cert, char* identity) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(ECQV_EC_CURVE);
    EC_POINT *Q_ca = import_public_key(group, ca_pk);
    EC_KEY *key = EC_KEY_new();
    EC_POINT *P_u = ecqv_import_point(group, cert);
    ECQV_DEBUG(printf("P_u : "));
    ECQV_DEBUG(ecqv_point_print_hex(group, P_u));
    char* U = identity;
    EC_POINT *ePu = EC_POINT_new(group);
    EC_POINT *Q_u = EC_POINT_new(group);

    BIGNUM *e = ecqv_hash_implicit_cert(group, P_u, U);
    
    EC_POINT_mul(group, ePu, NULL, P_u, e, NULL);
 
    EC_POINT_add(group, Q_u, ePu, Q_ca, 0);

    ECQV_DEBUG(printf("Q_u : "));
    ECQV_DEBUG(ecqv_point_print_hex(group, Q_u));

    ecqv_point_print(group, Q_u);

    EC_POINT_free(Q_u);
    EC_POINT_free(Q_ca);
    EC_POINT_free(ePu);
    EC_POINT_free(P_u);
    BN_free(e);
    EC_KEY_free(key);
}

void ecqv_generate_confirmation(char* cert_private_key, char* ca_pk, char* g_path) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(ECQV_EC_CURVE);
    EC_POINT *Q_ca = import_public_key(group, ca_pk);
    BIGNUM *d_i = import_priv_key(cert_private_key);
    EC_KEY *g = ecqv_import_pem(g_path);
    const BIGNUM *g_i = EC_KEY_get0_private_key(g);
    BIGNUM *verif = BN_new();

    // Step 1
    // Generate the verification number from the private key extracted from the
    // certificate and a randomly generated big number.
    BN_add(verif, d_i, g_i);

    // Step 2
    // Generate the key that will be used to encrypt the content of the
    // previous addtion
    // K = d_i . Q_ca
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT* K = EC_POINT_new(group);
    EC_POINT_mul(group, K, NULL, Q_ca, d_i, ctx);
    char *K_str = EC_POINT_point2hex(group, K, POINT_CONVERSION_UNCOMPRESSED, NULL);

    ECQV_DEBUG(printf("K : %s\n", K_str));

    // Step 3
    // Encrypt the verification calculated in `step 1` with the key from 
    unsigned char *verif_str = (unsigned char*) OPENSSL_malloc(BN_num_bytes(verif) * sizeof(unsigned char));
    int verif_str_len = BN_bn2bin(verif, verif_str);

    ECQV_DEBUG(printf("verif : "));
    ECQV_DEBUG(ecqv_bn_print_hex(verif));

    unsigned char output[128];
    size_t output_len = ecqv_encrypt_len(verif_str, verif_str_len, K_str, output);
    print_b64(output, output_len);

    OPENSSL_free(verif_str);
    OPENSSL_free(K_str);

    EC_POINT_free(K);
    EC_POINT_free(Q_ca);
    BN_CTX_free(ctx);
    BN_free(verif);
    EC_KEY_free(g);
    BN_free(d_i);
}

void ecqv_verify_confirmation(char* ca_path, char* cert_pk, char* g_pk, char* verification_number)
{
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(ECQV_EC_CURVE);

    const BIGNUM *d_ca = import_priv_key(ca_path);
    EC_POINT *Q_i = import_public_key(group, cert_pk);
    EC_POINT *G_i = import_public_key(group, g_pk);

    // Generation of the private key to decrypt the incoming verification number
    // K = d_ca . Q_i
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT* K = EC_POINT_new(group);
    EC_POINT_mul(group, K, NULL, Q_i, d_ca, ctx);
    char *K_str = EC_POINT_point2hex(group, K, POINT_CONVERSION_UNCOMPRESSED, NULL);

    ECQV_DEBUG(printf("K : %s\n", K_str));

    // Q_i + G_i
    EC_POINT *verif = EC_POINT_new(group);
    EC_POINT_add(group, verif, Q_i, G_i, NULL);

    // (d_i + g_i)G
    unsigned char decyphered_verif[256];
    size_t received_verif_len = ecqv_decrypt((unsigned char*) verification_number, K_str, decyphered_verif);
    BIGNUM* received_verif = BN_new();
    BN_bin2bn(decyphered_verif, received_verif_len, received_verif);

    ECQV_DEBUG(printf("verif : "));
    ECQV_DEBUG(ecqv_bn_print_hex(received_verif));


    EC_POINT *verif_pub = EC_POINT_new(group);
    EC_POINT_mul(group, verif_pub, received_verif, NULL, NULL, NULL);

    // Verification of the two confirmation number generated by each side
    // (d_i + g_i)G == Q_i + G_i
    if (EC_POINT_cmp(group, verif, verif_pub, NULL) == 0) {
        ecqv_bn_print(received_verif);
    }

    EC_POINT_free(K);
    BN_CTX_free(ctx);
    EC_POINT_free(verif);
    EC_POINT_free(verif_pub);
    EC_POINT_free(G_i);
    EC_POINT_free(Q_i);
}

static BIGNUM* ecqv_build_group_private_key(EC_KEY* ca_key, char** ids, size_t ids_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    unsigned char priv_key[EVP_MAX_MD_SIZE];
    unsigned int priv_key_len;
    BIGNUM *result = BN_new();
  
    EVP_DigestInit_ex(ctx, EVP_sha1(), 0);
    for (size_t i = 0; i < ids_len; ++i) {
        EVP_DigestUpdate(ctx, ids[i], strlen(ids[i]));
    }
    char* ca_priv_key = BN_bn2hex(EC_KEY_get0_private_key(ca_key));
    EVP_DigestUpdate(ctx, ca_priv_key, strlen(ca_priv_key));
    EVP_DigestFinal_ex(ctx, priv_key, &priv_key_len);

    EVP_MD_CTX_free(ctx);
    BN_bin2bn(priv_key, priv_key_len, result);
 
    return result;
}

static EC_POINT* ecqv_build_pubsub_public_key(const EC_GROUP* group, char** cert_pks, char** g_pks, size_t n, EC_POINT* Q_CAg)
{
    EC_POINT** pks = malloc(n * sizeof(EC_POINT*));
    EC_POINT** g = malloc(n * sizeof(EC_POINT*));
    for (size_t i = 0; i < n; ++i) {
        pks[i] = ecqv_import_point(group, cert_pks[i]);
        g[i] = ecqv_import_point(group, g_pks[i]);
    }

    EC_POINT* acc = EC_POINT_new(group);
    for (size_t i = 0; i < n; ++i) {
        EC_POINT_add(group, acc, acc, pks[i], NULL);
    }

    for (size_t i = 0; i < n; ++i) {
        EC_POINT_add(group, acc, acc, g[i], NULL);
    }

    EC_POINT_add(group, acc, acc, Q_CAg, NULL);

    for (size_t i = 0; i < n; ++i) {
        EC_POINT_free(g[i]);
        EC_POINT_free(pks[i]);
    }

    return acc;
}

static BIGNUM* ecqv_build_pubsub_private_key(char** verify_nums, size_t n, BIGNUM *d_CAg)
{
    if (!n) {
        return BN_new();
    }

    BIGNUM** verify = malloc(n * sizeof(BIGNUM*));
    for (size_t i = 0; i < n; ++i) {
        verify[i] = import_priv_key(verify_nums[i]);
    }
    BIGNUM* acc = BN_new();

    for (size_t i = 0; i < n; ++i) {
        BN_add(acc, acc, verify[i]);
    }

    BN_add(acc, acc, d_CAg);

    for (size_t i = 0; i < n; ++i) {
        BN_free(verify[i]);
    }

    return acc;
}

void ecqv_cert_group_generate(char* ca_path, char** ids, char** cert_pks, char** g_pks, char** verify_nums, size_t n)
{
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(ECQV_EC_CURVE);

    EC_KEY* ca_key = ecqv_import_pem(ca_path);
    BIGNUM *d_CAg = ecqv_build_group_private_key(ca_key, ids, n);
    EC_POINT *Q_CAg = ecqv_pk_extract_from_bn(group, d_CAg);

    EC_POINT* pk = ecqv_build_pubsub_public_key(group, cert_pks, g_pks, n, Q_CAg);
    BIGNUM* priv = ecqv_build_pubsub_private_key(verify_nums, n, d_CAg);

    ecqv_point_print(group, pk);
    ecqv_bn_print(priv);
}

#include "ecqv.h"

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

/**
 * @desc Import a key from a .pem file filename
 *
 * @args{filename}
 *
 * @return
 */
static EC_KEY *ecqv_import_pem(char* filename)
{
    FILE *file;
    EVP_PKEY *pk;
    EC_KEY *key;

    if ((file = fopen(filename, "rb")) == 0) {
        fprintf(stderr, "Error opening file '%s': %s.\n", filename, strerror(errno));
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
 * @desc Import a string in the HEX format representing an EC public key.
 *
 * @args{group}
 * @args{pk_str} Hex format public key string
 *
 * @return Point on the curve representing the public key.
 */
static EC_POINT *ecqv_import_point(const EC_GROUP *group, char* pk_str)
{
    EC_POINT *pk = EC_POINT_new(group);
    EC_POINT_hex2point(group, pk_str, pk, NULL);

    return pk;
}

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

static void ecqv_export_implicit_cert(const EC_GROUP *group, EC_POINT *P_u)
{
    /* size_t Pu_buf_len = EC_POINT_point2oct(group, P_u, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL); */
    /* unsigned char* Pu_buf = OPENSSL_malloc(Pu_buf_len); */
    /* EC_POINT_point2oct(group, P_u, POINT_CONVERSION_UNCOMPRESSED, Pu_buf, Pu_buf_len, NULL); */


    /* BIO *b64 = BIO_new(BIO_f_base64()); */
    /* BIO_set_flags(b64, 0); */
    /* BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE); */
    /* bio = BIO_push(b64, bio); */
    /* BIO_write(bio, Pu_buf, Pu_buf_len); */
    /* (void)BIO_flush(bio); */
    /* BIO_free_all(bio); */

    char *str = EC_POINT_point2hex(group, P_u, POINT_CONVERSION_UNCOMPRESSED, NULL);
    printf("%s\n", str);
}

static EC_POINT* ecqv_import_implicit_cert(const EC_GROUP *group, char* cert_str)
{
    /* BIO *b64 = BIO_new(BIO_f_base64()); */
    /* BIO_set_flags(b64, 0); */
    /* BIO *bio = BIO_new_mem_buf(cert_str, strlen(cert_str)); */
    /* bio = BIO_push(b64, bio); */
    /* BIO_(bio, result, length); */
    /* BIO_free_all(bio); */

    EC_POINT *point = EC_POINT_new(group);
    EC_POINT_hex2point(group, cert_str, point, NULL);

    return point;
}

void ecqv_pk_extract(const struct ecqv_opt_t *opt) {
    const EC_GROUP *group;
    if (opt->ca_key) {
        EC_KEY *key = ecqv_import_pem(opt->ca_key);
        group = EC_KEY_get0_group(key);

        char *str = EC_POINT_point2hex(group, EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, NULL);
        printf("%s\n", str);
        OPENSSL_free(str);
    } else if (opt->ca_pk) {
        BIGNUM *priv_k = BN_new();
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        BN_hex2bn(&priv_k, opt->ca_pk);
        EC_POINT* pk = EC_POINT_new(group);
        EC_POINT_mul(group, pk, priv_k, NULL, NULL, NULL);

        char *str = EC_POINT_point2hex(group, pk, POINT_CONVERSION_UNCOMPRESSED, NULL);
        printf("%s\n", str);
        OPENSSL_free(str);
    } else {
        fprintf(stderr, "No CA private key given.\n");
        return;
    }

    fflush(stdout);
}

void ecqv_cert_request(char* requester_key_path) {
    EC_KEY *key;
    
    if (NULL == (key = ecqv_import_pem(requester_key_path))) {
        return;
    }

    const EC_GROUP *group = EC_KEY_get0_group(key);

    char *str = EC_POINT_point2hex(group, EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, NULL);

    if (!str) {
        fprintf(stderr, "Log: error converting point to hex.\n");
        return;
    }

    printf("%s\n", str);

    OPENSSL_free(str);
    EC_KEY_free(key);

}

void ecqv_cert_generate(char* ca_key_path, char* requester_pk, char* identity) {
    EC_KEY *ca_key = ecqv_import_pem(ca_key_path);
    const EC_GROUP *group = EC_KEY_get0_group(ca_key);
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    EC_POINT *R_u = ecqv_import_point(group, requester_pk);
    EC_POINT *kG = EC_POINT_new(group);
    BIGNUM *k = BN_new();
    EC_POINT *P_u = EC_POINT_new(group);
    BIGNUM *e = NULL;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *ek = BN_new();
    BIGNUM *r = BN_new();

    // Step 1: Conversion from the hex format to a point on the elliptic curve

    // Step 2: Validate the R_u

    // Step 3: Generate an EC key pair (k, kG)
    BN_rand_range(k, order);
    EC_POINT_mul(group, kG, k, NULL, NULL, NULL); // Calculate the private key using the same generator as the CA key

    // Step 4: Compute the EC point P_u = R_u + kG
    EC_POINT_add(group, P_u, R_u, kG, NULL);

    // Step 5: Convert P_u to hex format
    // Step 6: Certificate encoding method call
    // Step 7: Use the hash function to compute e = H_n(Cert_U)
    e = ecqv_hash_implicit_cert(group, P_u, identity);

    // Step 8: r = ek + d_ca
    BN_mul(ek, e, k, ctx);
    BN_mod_add(r, ek, EC_KEY_get0_private_key(ca_key), order, ctx);

    // Printing the implicit certificate
    ecqv_export_implicit_cert(group, P_u);
    BN_print_fp(stdout, r);
    printf("\n");

    // Freeing memory
    EC_KEY_free(ca_key);
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
    EC_KEY *req_key = ecqv_import_pem(requester_key_path);
    const EC_GROUP *group = EC_KEY_get0_group(req_key);
    EC_POINT *Q_ca = ecqv_import_point(group, ca_pk);
    EC_KEY *key = EC_KEY_new();
    EC_POINT *P_u = ecqv_import_implicit_cert(group, cert);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *ek_u = BN_new();
    BIGNUM *d_u = BN_new();
    EC_POINT *ePu = EC_POINT_new(group);
    EC_POINT *Q_u = EC_POINT_new(group);

    // Step 2: Import 'r' parameter passed as CLI argument
    BN_hex2bn(&r, r_str);

    // Step 3: Calculate 'e' based on the hash of the implicit certificate 
    e = ecqv_hash_implicit_cert(group, P_u, U);
    
    BN_mul(ek_u, e, EC_KEY_get0_private_key(req_key), ctx);

    BIGNUM* order = BN_new();
    if (EC_GROUP_get_order(group, order, ctx) == 0) {
        printf("error\n");
    }
    BN_mod_add(d_u, ek_u, r, order, ctx);

    EC_POINT_mul(group, ePu, NULL, P_u, e, NULL);
 
    EC_POINT_add(group, Q_u, ePu, Q_ca, 0);

    EC_KEY_set_group(key, group);
    EC_KEY_set_private_key(key, d_u);
    EC_KEY_set_public_key(key, Q_u);

    if (EC_KEY_check_key(key)) {
        /* char *str = EC_POINT_point2hex(group, EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, NULL); */
        /* char *str = BN_bn2hex(EC_KEY_get0_private_key(key)); */
        char *str = BN_bn2hex(d_u);
        printf("%s\n", str);
        FILE* pem = fopen("cl_key.pem", "wb");
        PEM_write_ECPrivateKey(pem, key, NULL, NULL, 0, NULL, NULL);
        fclose(pem);
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
    EC_KEY_free(req_key);
}

void ecqv_cert_pk_extract(const struct ecqv_opt_t *opt) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT *Q_ca = ecqv_import_point(group, opt->ca_pk);
    EC_KEY *key = EC_KEY_new();
    EC_POINT *P_u = ecqv_import_implicit_cert(group, opt->cert);
    char* U = opt->identity;
    BIGNUM *e = BN_new();
    EC_POINT *ePu = EC_POINT_new(group);
    EC_POINT *Q_u = EC_POINT_new(group);

    e = ecqv_hash_implicit_cert(group, P_u, U);
    
    EC_POINT_mul(group, ePu, NULL, P_u, e, NULL);
 
    EC_POINT_add(group, Q_u, ePu, Q_ca, 0);

    EC_KEY_set_group(key, group);
    EC_KEY_set_public_key(key, Q_u);

    if (EC_KEY_check_key(key)) {
        char *str = EC_POINT_point2hex(group, EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, NULL);
        printf("%s\n", str);
    } else {
        printf("Verification failed\n");
    }

    EC_POINT_free(Q_u);
    EC_POINT_free(Q_ca);
    EC_POINT_free(ePu);
    EC_POINT_free(P_u);
    BN_free(e);
    EC_KEY_free(key);
}

void ecqv_sign(const struct ecqv_opt_t *opt) {
    (void) opt;
    /* EC_KEY *cl_key = ecqv_import_pem(opt->cl_key); */
    /* ECDSA_SIG sign = ECDSA_do_sign(opt->msg, strlen(opt->msg), cl_key); */
    /* ECDSA_SIG_get0(sign, NULL, NULL); */
}

void ecqv_generate_confirmation(char* cert_private_key, char* ca_pk, char* g_path) {
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM *Q_ca = BN_new();
    BN_hex2bn(&Q_ca, ca_pk);
    BIGNUM *d_i = BN_new();
    BN_hex2bn(&d_i, cert_private_key);
    EC_KEY *g = ecqv_import_pem(g_path);
    const BIGNUM *g_i = EC_KEY_get0_private_key(g);
    BIGNUM *verif = BN_new();
    BIGNUM *K = BN_new();

    // Step 1
    // Generate the verification number from the private key extracted from the
    // certificate and a randomly generated big number.
    BN_add(verif, d_i, g_i);

    // Step 2
    // Generate the key that will be used to encrypt the content of the
    // previous addtion
    // K = d_i . Q_ca
    BN_CTX *ctx = BN_CTX_new();
    BN_mul(K, d_i, Q_ca, ctx);

    EC_KEY *key = EC_KEY_new();
    EC_KEY_set_group(key, group);
    EC_KEY_set_private_key(key, K);
    /* EC_KEY_set_public_key(key, K); */

    // Step 3
    // Encrypt the verification calculated in `step 1` with the key from 
    // `step 2`
    /* ECDSA_SIG *sig; */
    /* sig = ECDSA_do_sign(NULL, 0, key); */

    char *str = BN_bn2hex(verif);
    printf("%s\n", str);
    OPENSSL_free(str);

    EC_KEY_free(key);
    BN_free(K);
    BN_free(verif);
    EC_KEY_free(g);
    BN_free(d_i);
    BN_free(Q_ca);
}

void ecqv_verify_confirmation(char* cert_pk, char* g_pk, char* verification_number)
{
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    // (d_i + g_i)G == Q_i + G_i
    EC_POINT *Q_i = EC_POINT_new(group);
    EC_POINT_hex2point(group, cert_pk, Q_i, NULL);
    EC_POINT *G_i = EC_POINT_new(group);
    EC_POINT_hex2point(group, g_pk, G_i, NULL);

    EC_POINT *verif = EC_POINT_new(group);
    EC_POINT_add(group, verif, Q_i, G_i, NULL);

    BIGNUM *received_verif = BN_new();
    BN_hex2bn(&received_verif, verification_number);
    EC_POINT *verif_priv = EC_POINT_new(group);
    EC_POINT_mul(group, verif_priv, received_verif, NULL, NULL, NULL);

    char* verif_str = EC_POINT_point2hex(group, verif, POINT_CONVERSION_UNCOMPRESSED, NULL);
    char* received_verif_str = EC_POINT_point2hex(group, verif_priv, POINT_CONVERSION_UNCOMPRESSED, NULL);
    printf("%s\n%s\n", verif_str, received_verif_str);
}


void ecqv_cert_group_generate(const struct ecqv_opt_t *opt)
{
    (void) opt;
}

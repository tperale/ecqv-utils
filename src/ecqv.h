#ifndef __ECQV_H_
#define __ECQV_H_

#include <stddef.h>

struct ecqv_opt_t {
    char *ca_key; /* Path to .pem file of CA authority priv key (-k) */
    char *ca_pk; /* HEX formatted plain text PK of CA authority */
    char *requester_pk;
    char *requester_key; /* Path to .pem file of the cert requester */
    char *identity;
    char *r;
    char *cl_key;
    char *msg;
    char *g_path;
    char *g_pk;
    char *cert;
    char *cert_priv;
    char *cert_pk;
};

void ecqv_export_ca_generator(const struct ecqv_opt_t *opt);

/**
 * @desc First step of the Elliptic Curve Qu-Vanstone Implicit 
 *   Certificate Scheme executed by the requester. In this
 *   step the requester generate a EC public key in the hex
 *   format readable by the OpenSSL library.
 * 
 * @arg{opt} A struct containing the command line arguments.
 */
void ecqv_cert_request(char* requester_key_path);

/**
 * @desc Generate the certificate from a `cert_request`.
 * 
 * @arg{opt} A struct containing the command line arguments.
 */
void ecqv_cert_generate(char* ca_key_path, char* requester_pk, char* identity);

/**
 * @desc Extracting the private and public key from the implicit certificate 
 *   received from the CA.
 * 
 * @arg{opt} A struct containing the command line arguments.
 */
void ecqv_cert_reception(char* requester_key_path, char* ca_pk, char* cert, char* U, char* r_str);

/**
 * @desc Extracting the PK from the implicit certificate received
 *   from the CA.
 * 
 * @arg{opt} A struct containing the command line arguments.
 */
void ecqv_cert_pk_extract(const struct ecqv_opt_t *opt);

/**
 * @desc Generate a confirmation EC point from the certificate
 *   extracted private key.
 *   This point is meant to be sent to the CA.
 *
 * @arg{opt} A struct containing the command line arguments.
 */
void ecqv_generate_confirmation(char* cert_private_key, char* ca_pk, char* g_path);

/**
 * @desc Reception and verification of the confirmation point
 *   coming from the device.
 *
 * @arg{opt} A struct containing the command line arguments.
 */
void ecqv_verify_confirmation(char* ca_path, char* cert_pk, char* g_pk, char* verification_number);

void ecqv_cert_group_generate(char* ca_priv_key, char** ids, char** pubsub_pks, char** g_pks, char** verify_nums, size_t n);

#endif

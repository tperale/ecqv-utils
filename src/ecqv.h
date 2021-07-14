#ifndef __ECQV_H_
#define __ECQV_H_

struct ecqv_opt_t {
    char *cert;
    char *ca_key;
    char *ca_pk;
    char *requester_pk;
    char *requester_key;
    char *identity;
    char *r;
    char *cl_key;
    char *msg;
};

void ecqv_export_ca_public_key(const struct ecqv_opt_t *opt);
void ecqv_export_ca_generator(const struct ecqv_opt_t *opt);

/**
 * @desc First step of the Elliptic Curve Qu-Vanstone Implicit 
 *   Certificate Scheme executed by the requester. In this
 *   step the requester generate a EC public key in the hex
 *   format readable by the OpenSSL library.
 * 
 * @arg{opt} A struct containing the command line arguments.
 */
void ecqv_cert_request(const struct ecqv_opt_t *opt);

/**
 * @desc Generate the certificate from a `cert_request`.
 * 
 * @arg{opt} A struct containing the command line arguments.
 */
void ecqv_cert_generate(const struct ecqv_opt_t *opt);

/**
 * @desc Extracting the private and public key from the implicit certificate 
 *   received from the CA.
 * 
 * @arg{opt} A struct containing the command line arguments.
 */
void ecqv_cert_reception(const struct ecqv_opt_t *opt);

/**
 * @desc Extracting the PK from the implicit certificate received
 *   from the CA.
 * 
 * @arg{opt} A struct containing the command line arguments.
 */
void ecqv_cert_pk_extract(const struct ecqv_opt_t *opt);

void ecqv_sign(const struct ecqv_opt_t *opt);

#endif

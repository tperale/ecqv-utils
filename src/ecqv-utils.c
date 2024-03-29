#include "ecqv.h"

#include "schnorr.h"
#include "crypto.h"
#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#define ECQV_KG_VERSION "0.1"

#define ECQV_INFO \
    "ECQV Public/Private Key Pair Generator\n" \
    "Create EC key pair with implicit certificate.\n" \
    "Usage: ecqv-utils CMD [OPTION...] \n" \
    "\n"

static void print_usage_and_exit(void);

static size_t parse_cmd_list(char* input, char*** output)
{
    int len;
    char* s;
    for (len = 0, s = input; s[len]; s[len] == ',' ? len++ : *s++);
    int input_len = s - input;
    len++;

    *output = malloc(sizeof(char*) * len);

    (*output)[0] = input;
    for (int i = 0, n = 1; i < input_len && n < len; i++) {
        if (input[i] == ',') {
            (*output)[n] = (input + i + 1);
            input[i] = '\0';
            n++;
        }
    }

    return len;
}

#define ECQV_PK_EXTRACT_CMD_INFO \
    "<CMD>: <pk_extract - priv_extract>\n" \
    "<Options>\n" \
    "  -c <arg>     The PEM file containing the EC private key\n" \
    "  -k <arg>     B64 formatted string of the EC private key\n" \
    "\n"

static void parse_cmd_options_pk_extract(int argc, char **argv, char** key)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "k:c:")) != -1) {
        switch (opt) {
            case 'k':
                *key = optarg;
                break;
            case 'c':
                *key = optarg;
                break;
            default:
                /* If unknown option print info */
                print_usage_and_exit();
                break;
        }
    }

    if (!*key) {
        fprintf(stderr, ECQV_PK_EXTRACT_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}


#define ECQV_CERT_REQUEST_CMD_INFO \
    "<CMD>: cert_request\n" \
    "<Options>\n" \
    "  -i <arg>     Identity of the requester\n" \
    "  -k <arg>     The PEM file containing the EC private key of the requester\n" \
    "\n" 
static void parse_cmd_options_cert_request(int argc, char **argv, char** requester_key)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "i:k:")) != -1) {
        switch (opt) {
            case 'i':
                break;
            case 'k':
                *requester_key = optarg;
                break;
            default:
                /* If unknown option print info */
                print_usage_and_exit();
                break;
        }
    }

    if (!*requester_key) {
        fprintf(stderr, ECQV_INFO ECQV_CERT_REQUEST_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}

#define ECQV_CERT_GENERATE_CMD_INFO \
    "<CMD>: cert_generate\n" \
    "<Options>\n" \
    "  -i <arg>     Identity of the requester\n" \
    "  -r <arg>     The B64 representation EC public key of the requester\n" \
    "  -k <arg>     The PEM file containing the EC private key of the CA\n" \
    "  -s <arg>     The server key (optional)\n" \
    "\n"
static void parse_cmd_options_cert_generate(int argc, char **argv, char** identity, char** requester_pk, char** ca_key, char** serv_key)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "i:r:k:s:")) != -1) {
        switch (opt) {
            case 'i':
                *identity = optarg;
                break;
            case 'r':
                *requester_pk = optarg;
                break;
            case 'k':
                *ca_key = optarg;
                break;
            case 's':
                *serv_key = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!*identity || !*requester_pk || !*ca_key) {
        fprintf(stderr, ECQV_INFO ECQV_CERT_GENERATE_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}

#define ECQV_CERT_GENERATE_CONFIRMATION \
    "<CMD>: generate_confirmation \n" \
    "<Options>\n" \
    "  -c <arg>     CA Public Key\n" \
    "  -d <arg>     Ceritificate private key\n" \
    "  -g <arg>     Random big number generated\n" \
    "\n"
static void parse_cmd_options_generate_confirmation(int argc, char **argv, char** cert_priv, char** ca_pk, char** g_path)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "c:d:g:")) != -1) {
        switch (opt) {
            case 'c':
                *ca_pk = optarg;
                break;
            case 'd':
                *cert_priv = optarg;
                break;
            case 'g':
                *g_path = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!*ca_pk || !*cert_priv || !*g_path) {
        fprintf(stderr, ECQV_INFO ECQV_CERT_GENERATE_CONFIRMATION);
        exit(EXIT_FAILURE);
    }
}

#define ECQV_CERT_VERIFY_CONFIRMATION \
    "<CMD>: verify_confirmation \n" \
    "<Options>\n" \
    "  -k <arg>     CA '.pem' file.\n" \
    "  -v <arg>     Encrypted verification number generated by the client.\n" \
    "  -d <arg>     Certificate public key.\n" \
    "  -g <arg>     Random big number generated public key.\n" \
    "\n"
static void parse_cmd_options_verify_confirmation(int argc, char **argv, char** ca_key, char** cert_pk, char** g_pk, char** msg)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "k:d:v:g:")) != -1) {
        switch (opt) {
            case 'k':
                *ca_key = optarg;
                break;
            case 'd':
                *cert_pk = optarg;
                break;
            case 'v':
                *msg = optarg;
                break;
            case 'g':
                *g_pk = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!*cert_pk || !*g_pk || !*msg || !*ca_key) {
        fprintf(stderr, ECQV_INFO ECQV_CERT_VERIFY_CONFIRMATION);
        exit(EXIT_FAILURE);
    }
}

#define ECQV_INFO_ECQV_GROUP_GENERATE_CMD_INFO \
    "<CMD>: group_generate \n" \
    "<Options>\n" \
    "  -c <arg>     CA Path to EC '.pem' key.\n" \
    "  -i <arg>     Lists of comma separated ids.\n"  \
    "  -g <arg>     Lists of comma separated of the random number public key\n"  \
    "  -d <arg>     Lists of comma separated public key of the cert.\n"  \
    "  -v <arg>     Lists of comma separated verification number generated by each participants.\n"  \
    "\n"
static void parse_cmd_options_cert_group_generate(int argc, char **argv, char** ca_path, char*** ids, char*** cert_pks, char*** g_pks, char*** verify_nums, size_t* n)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "c:i:g:d:v:")) != -1) {
        switch (opt) {
            case 'c':
                *ca_path = optarg;
                break;
            case 'i':
                *n = parse_cmd_list(optarg, ids);
                break;
            case 'g':
                *n = parse_cmd_list(optarg, g_pks);
                break;
            case 'd':
                *n = parse_cmd_list(optarg, cert_pks);
                break;
            case 'v':
                *n = parse_cmd_list(optarg, verify_nums);
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!(*ca_path && *ids && *cert_pks && *g_pks && *verify_nums)) {
        fprintf(stderr, ECQV_INFO_ECQV_GROUP_GENERATE_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}

#define ECQV_CERT_PK_EXTRACT_CMD_INFO \
    "<CMD>: cert_pk_extract \n" \
    "<Options>\n" \
    "  -i <arg>     Identity of the requester\n" \
    "  -c <arg>     The CA public key in B64 format\n" \
    "  -a <arg>     The implicit certificate in B64 format\n" \
    "\n"
static void parse_cmd_options_cert_pk_extract(int argc, char **argv, char** identity, char** ca_pk, char** cert)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "i:c:a:")) != -1) {
        switch (opt) {
            case 'i':
                *identity = optarg;
                break;
            case 'c':
                *ca_pk = optarg;
                break;
            case 'a':
                *cert = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!*identity || !*cert || !*ca_pk) {
        fprintf(stderr, ECQV_INFO ECQV_CERT_PK_EXTRACT_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}

#define ECQV_CERT_RECEPTION_CMD_INFO \
    "<CMD>: cert_reception \n" \
    "<Options>\n" \
    "  -i <arg>     Identity of the requester\n" \
    "  -k <arg>     The PEM file containing the EC key of the requester\n" \
    "  -c <arg>     The CA public key in B64 format\n" \
    "  -a <arg>     The implicit certificate in B64 format\n" \
    "  -r <arg>     The number 'r' calculated by the CA\n" \
    "\n"
static void parse_cmd_options_cert_reception(int argc, char **argv, char** requester_key, char** ca_pk, char** cert, char** identity, char** r)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "i:r:c:k:a:")) != -1) {
        switch (opt) {
            case 'i':
                *identity = optarg;
                break;
            case 'k':
                *requester_key = optarg;
                break;
            case 'c':
                *ca_pk = optarg;
                break;
            case 'a':
                *cert = optarg;
                break;
            case 'r':
                *r = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!*identity || !*requester_key || !*cert || !*ca_pk || !*r) {
        fprintf(stderr, ECQV_INFO ECQV_CERT_RECEPTION_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}

#define ECQV_INFO_ENCRYPT \
    "<CMD>: <encrypt-decrypt> \n" \
    "<Options>\n" \
    "  -m <arg>     Message to encrypt.\n" \
    "  -k <arg>     Encryption key.\n"  \
    "\n"
static void parse_cmd_options_encrypt(int argc, char** argv, char** msg, char** key)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "m:k:")) != -1) {
        switch (opt) {
            case 'm':
                *msg = optarg;
                break;
            case 'k':
                *key = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!*msg || !*key) {
        fprintf(stderr, ECQV_INFO ECQV_INFO_ENCRYPT);
        exit(EXIT_FAILURE);
    }
}

#define ECQV_INFO_SIGN \
    "<CMD>: sign\n" \
    "<Options>\n" \
    "  -m <arg>     Message to encrypt.\n" \
    "  -k <arg>     Signing key.\n"  \
    "\n"
static void parse_cmd_schnorr_sign(int argc, char **argv, char** priv_b64, char** msg)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "k:m:")) != -1) {
        switch (opt) {
            case 'k':
                *priv_b64 = optarg;
                break;
            case 'm':
                *msg = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!*msg || !*priv_b64) {
        fprintf(stderr, ECQV_INFO_SIGN);
        exit(EXIT_FAILURE);
    }
}

#define ECQV_INFO_VERIFY \
    "<CMD>: verify\n" \
    "<Options>\n" \
    "  -m <arg>     Message to encrypt.\n" \
    "  -k <arg>     Signing key.\n"  \
    "  -v <arg>     Random number generated by the signing.\n"  \
    "  -s <arg>     Signature.\n"  \
    "\n"
static void parse_cmd_schnorr_verify(int argc, char **argv, char** pub_key, char** sign, char** v, char** msg)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "k:m:s:v:")) != -1) {
        switch (opt) {
            case 's':
                *sign = optarg;
                break;
            case 'v':
                *v = optarg;
                break;
            case 'k':
                *pub_key = optarg;
                break;
            case 'm':
                *msg = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!*msg || !*sign || !*v || !*pub_key) {
        fprintf(stderr, ECQV_INFO_VERIFY);
        exit(EXIT_FAILURE);
    }

}

#define ECQV_INFO_CMD_MUL \
    "<CMD>: mul\n" \
    "<Options>\n" \
    "  -k <arg>     Private key in B64 format.\n"  \
    "  -p <arg>     Public key B64 in format.\n"  \
    "\n"
static void parse_cmd_mul(int argc, char **argv, char** pub_key, char** priv_key)
{
    int opt;

    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "k:p:")) != -1) {
        switch (opt) {
            case 'k':
                *priv_key = optarg;
                break;
            case 'p':
                *pub_key = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!*pub_key || !*priv_key) {
        fprintf(stderr, ECQV_INFO_CMD_MUL);
        exit(EXIT_FAILURE);
    }
}

static void print_usage_and_exit(void)
{
    fprintf(stderr, ECQV_INFO ECQV_PK_EXTRACT_CMD_INFO ECQV_CERT_REQUEST_CMD_INFO ECQV_CERT_GENERATE_CMD_INFO ECQV_CERT_RECEPTION_CMD_INFO ECQV_CERT_PK_EXTRACT_CMD_INFO ECQV_CERT_GENERATE_CONFIRMATION ECQV_CERT_VERIFY_CONFIRMATION ECQV_INFO_ECQV_GROUP_GENERATE_CMD_INFO ECQV_INFO_ENCRYPT ECQV_INFO_SIGN ECQV_INFO_VERIFY);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage_and_exit();
    }

    char* cmd = argv[1];

    argc--;
    argv++;

    if (strcmp(cmd, "pk_extract") == 0) {
        char* key = NULL;
        parse_cmd_options_pk_extract(argc, argv, &key);
        ecqv_pk_extract(key);
    } else if (strcmp(cmd, "priv_extract") == 0) {
        char* key = NULL;
        parse_cmd_options_pk_extract(argc, argv, &key);
        ecqv_priv_extract(key);
    } else if (strcmp(cmd, "cert_request") == 0) {
        char* requester_key = NULL;
        parse_cmd_options_cert_request(argc, argv, &requester_key);
        ecqv_cert_request(requester_key);
    } else if (strcmp(cmd, "cert_generate") == 0) {
        char* identity = NULL;
        char* requester_pk = NULL;
        char* ca_key = NULL;
        char* serv_key = NULL;
        parse_cmd_options_cert_generate(argc, argv, &identity, &requester_pk, &ca_key, &serv_key);
        ecqv_cert_generate(ca_key, requester_pk, identity, serv_key);
    } else if (strcmp(cmd, "cert_reception") == 0) {
        char* requester_key = NULL;
        char* ca_pk = NULL; 
        char* cert = NULL; 
        char* identity = NULL; 
        char* r = NULL;
        parse_cmd_options_cert_reception(argc, argv, &requester_key, &ca_pk, &cert, &identity, &r);
        ecqv_cert_reception(requester_key, ca_pk, cert, identity, r);
    } else if (strcmp(cmd, "cert_pk_extract") == 0) {
        char* identity = NULL;
        char* ca_pk = NULL;
        char* cert = NULL;
        parse_cmd_options_cert_pk_extract(argc, argv, &identity, &ca_pk, &cert);
        ecqv_cert_pk_extract(ca_pk, cert, identity);
    } else if (strcmp(cmd, "generate_confirmation") == 0) {
        char* cert_priv = NULL;
        char* ca_pk = NULL;
        char* g_path = NULL;
        parse_cmd_options_generate_confirmation(argc, argv, &cert_priv, &ca_pk, &g_path);
        ecqv_generate_confirmation(cert_priv, ca_pk, g_path);
    } else if (strcmp(cmd, "verify_confirmation") == 0) {
        char* ca_key = NULL;
        char* cert_pk = NULL;
        char* g_pk = NULL;
        char* msg = NULL;
        parse_cmd_options_verify_confirmation(argc, argv, &ca_key, &cert_pk, &g_pk, &msg);
        ecqv_verify_confirmation(ca_key, cert_pk, g_pk, msg);
    } else if (strcmp(cmd, "group_generate") == 0) {
        char* ca_path = NULL;
        char** ids = NULL;
        char** cert_pks = NULL; 
        char** g_pks = NULL;
        char** verify_nums = NULL;
        size_t n = 0;
        parse_cmd_options_cert_group_generate(argc, argv, &ca_path, &ids, &cert_pks, &g_pks, &verify_nums, &n);
        ecqv_cert_group_generate(ca_path, ids, cert_pks, g_pks, verify_nums, n);
    } else if (strcmp(cmd, "encrypt") == 0) {
        char* msg = NULL;
        char* key = NULL;
        parse_cmd_options_encrypt(argc, argv, &msg, &key);
        unsigned char result[256];
        size_t len = ecqv_encrypt((unsigned char*) msg, key, result);
        print_b64(result, len);
    } else if (strcmp(cmd, "decrypt") == 0) {
        char* msg = NULL;
        char* key = NULL;
        parse_cmd_options_encrypt(argc, argv, &msg, &key);
        unsigned char result[256];
        ecqv_decrypt((unsigned char*) msg, key, result);
        printf("%s\n", result);
    } else if (strcmp(cmd, "sign") == 0) {
        char* priv_b64 = NULL;
        char* msg = NULL;
        parse_cmd_schnorr_sign(argc, argv, &priv_b64, &msg);
        schnorr_sign(priv_b64, msg);
    } else if (strcmp(cmd, "verify") == 0) {
        char* pub_key = NULL;
        char* msg = NULL;
        char* sign = NULL;
        char* v = NULL;
        parse_cmd_schnorr_verify(argc, argv, &pub_key, &sign, &v, &msg);
        schnorr_verify(pub_key, v, sign, msg);
    } else if (strcmp(cmd, "mul") == 0) {
        char* pub_key = NULL;
        char* priv_key = NULL;
        parse_cmd_mul(argc, argv, &pub_key, &priv_key);
        ecqv_ecdh(pub_key, priv_key);
    } else if (strcmp(cmd, "random") == 0) {
        ecqv_gen_key();
    } else {
        print_usage_and_exit();
    }

    return EXIT_SUCCESS;
}

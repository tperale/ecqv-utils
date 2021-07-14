#include "ecqv.h"

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
    "\n" \

#define ECQV_CA_PUBLIC_KEY_CMD_INFO \
    "<CMD>: ca_public_key\n" \
    "<Options>\n" \
    "  -k <arg>     The PEM file containing the EC private key\n" \
    "\n" \

#define ECQV_CERT_REQUEST_CMD_INFO \
    "<CMD>: cert_request\n" \
    "<Options>\n" \
    "  -i <arg>     Identity of the requester\n" \
    "  -r <arg>     The PEM file containing the EC private key of the requester\n" \
    "\n" \

#define ECQV_CERT_GENERATE_CMD_INFO \
    "<CMD>: cert_generate\n" \
    "<Options>\n" \
    "  -i <arg>     Identity of the requester\n" \
    "  -r <arg>     The HEX representation EC public key of the CA\n" \
    "  -c <arg>     The PEM file containing the EC private key of the CA\n" \
    "\n" \

#define ECQV_CERT_RECEPTION_CMD_INFO \
    "<CMD>: cert_reception \n" \
    "<Options>\n" \
    "  -i <arg>     Identity of the requester\n" \
    "  -k <arg>     The PEM file containing the EC key of the requester\n" \
    "  -c <arg>     The CA public key in hex format\n" \
    "  -a <arg>     The implicit certificate in hex format\n" \
    "  -r <arg>     The number 'r' calculated by the CA\n" \
    "\n"\

#define ECQV_CERT_PK_EXTRACT_CMD_INFO \
    "<CMD>: cert_pk_extract \n" \
    "<Options>\n" \
    "  -i <arg>     Identity of the requester\n" \
    "  -c <arg>     The CA public key in hex format\n" \
    "  -a <arg>     The implicit certificate in hex format\n" \
    "\n"\
 
static struct ecqv_opt_t ecqv_opt;

static void print_usage_and_exit(void)
{
    fprintf(stderr, ECQV_INFO ECQV_CA_PUBLIC_KEY_CMD_INFO ECQV_CERT_REQUEST_CMD_INFO ECQV_CERT_GENERATE_CMD_INFO ECQV_CERT_RECEPTION_CMD_INFO ECQV_CERT_PK_EXTRACT_CMD_INFO);
    exit(EXIT_FAILURE);
}

static void parse_cmd_options_ca_public_key(int argc, char **argv)
{
    int opt;

    memset(&ecqv_opt, 0, sizeof(ecqv_opt));
    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "k:")) != -1) {
        switch (opt) {
            case 'k':
                ecqv_opt.ca_key = optarg;
                break;
            default:
                /* If unknown option print info */
                print_usage_and_exit();
                break;
        }
    }

    if (!ecqv_opt.ca_key) {
        fprintf(stderr, ECQV_INFO ECQV_CA_PUBLIC_KEY_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}



static void parse_cmd_options_cert_request(int argc, char **argv)
{
    int opt;

    memset(&ecqv_opt, 0, sizeof(ecqv_opt));
    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "i:k:")) != -1) {
        switch (opt) {
            case 'i':
                ecqv_opt.identity = optarg;
                break;
            case 'k':
                ecqv_opt.requester_key = optarg;
                break;
            default:
                /* If unknown option print info */
                print_usage_and_exit();
                break;
        }
    }

    if (!ecqv_opt.identity || !ecqv_opt.requester_key) {
        fprintf(stderr, ECQV_INFO ECQV_CERT_REQUEST_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}

static void parse_cmd_options_cert_generate(int argc, char **argv)
{
    int opt;

    memset(&ecqv_opt, 0, sizeof(ecqv_opt));
    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "i:r:k:")) != -1) {
        switch (opt) {
            case 'i':
                ecqv_opt.identity = optarg;
                break;
            case 'r':
                ecqv_opt.requester_pk = optarg;
                break;
            case 'k':
                ecqv_opt.ca_key = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!ecqv_opt.identity || !ecqv_opt.requester_key || !ecqv_opt.ca_key) {
        fprintf(stderr, ECQV_INFO ECQV_CERT_GENERATE_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}

static void parse_cmd_options_cert_pk_extract(int argc, char **argv)
{
    int opt;

    memset(&ecqv_opt, 0, sizeof(ecqv_opt));
    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "i:r:c:k:a:")) != -1) {
        switch (opt) {
            case 'i':
                ecqv_opt.identity = optarg;
                break;
            case 'c':
                ecqv_opt.ca_pk = optarg;
                break;
            case 'a':
                ecqv_opt.cert = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!ecqv_opt.identity || !ecqv_opt.cert || !ecqv_opt.ca_pk) {
        fprintf(stderr, ECQV_INFO ECQV_CERT_PK_EXTRACT_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}

static void parse_cmd_options_cert_reception(int argc, char **argv)
{
    int opt;

    memset(&ecqv_opt, 0, sizeof(ecqv_opt));
    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "i:r:c:k:a:")) != -1) {
        switch (opt) {
            case 'i':
                ecqv_opt.identity = optarg;
                break;
            case 'k':
                ecqv_opt.requester_key = optarg;
                break;
            case 'c':
                ecqv_opt.ca_pk = optarg;
                break;
            case 'a':
                ecqv_opt.cert = optarg;
                break;
            case 'r':
                ecqv_opt.r = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }

    if (!ecqv_opt.identity || !ecqv_opt.requester_key || !ecqv_opt.cert || !ecqv_opt.ca_pk || !ecqv_opt.r) {
        fprintf(stderr, ECQV_INFO ECQV_CERT_RECEPTION_CMD_INFO);
        exit(EXIT_FAILURE);
    }
}

static void parse_cmd_options_sign(int argc, char **argv)
{
    int opt;

    memset(&ecqv_opt, 0, sizeof(ecqv_opt));
    opterr = 0; /* To inhibit error messages */

    while ((opt = getopt(argc, argv, "k:m:")) != -1) {
        switch (opt) {
            case 'k':
                ecqv_opt.cl_key = optarg;
                break;
            case 'm':
                ecqv_opt.msg = optarg;
                break;
            default:
                print_usage_and_exit();
                break;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage_and_exit();
    }

    char* cmd = argv[1];

    if (strcmp(cmd, "ca_public_key") == 0) {
        parse_cmd_options_ca_public_key(argc - 1, argv + 1);
        ecqv_export_ca_public_key(&ecqv_opt);
    } else if (strcmp(cmd, "cert_request") == 0) {
        parse_cmd_options_cert_request(argc - 1, argv + 1);
        ecqv_cert_request(&ecqv_opt);
    } else if (strcmp(cmd, "cert_generate") == 0) {
        parse_cmd_options_cert_generate(argc - 1, argv + 1);
        ecqv_cert_generate(&ecqv_opt);
    } else if (strcmp(cmd, "cert_reception") == 0) {
        parse_cmd_options_cert_reception(argc - 1, argv + 1);
        ecqv_cert_reception(&ecqv_opt);
    } else if (strcmp(cmd, "cert_pk_extract") == 0) {
        parse_cmd_options_cert_pk_extract(argc - 1, argv + 1);
        ecqv_cert_pk_extract(&ecqv_opt);
    } else if (strcmp(cmd, "sign") == 0) {
        parse_cmd_options_sign(argc - 1, argv + 1);
        ecqv_sign(&ecqv_opt);
    } else if (strcmp(cmd, "verify") == 0) {
    }

    return EXIT_SUCCESS;
}

# Elliptic Curve Qu-Vanstone (ECQV) Implicit Certificates

Set of tool to perform the different steps of the request, generation and
interpretation of ECQV implicit certificate.
The program interract with the OpenSSL library.

For more information about ECQV Implicit Certificates see
[SEC 4](https://www.secg.org/sec4-1.0.pdf)
and [Wikipedia](https://en.wikipedia.org/wiki/Implicit_certificate).

## Prerequisite

Before using the commands you must generate a `.pem` key for both the requester
and the CA.

```sh
openssl ecparam -name secp256k1 -genkey -noout -out ca_key.pem
openssl ecparam -name secp256k1 -genkey -noout -out r_key.pem
```

## Commands

### CA get public key

```sh
<CMD>: ca_public_key
<Options>
  -k <arg>     The PEM file containing the EC private key
```

### Certificate request

Export the EC public key of the requester EC private key in a hex format
readable by the OpenSSL library

```sh
<CMD>: cert_request
<Options>
  -i <arg>     Identity of the requester
  -r <arg>     The PEM file containing the EC private key of the requester
```

### Certificate generation

Generate an implicit certificate based on the _requester_ identity and its request
made with the previous command.

```sh
<CMD>: cert_generate
<Options>
  -i <arg>     Identity of the requester
  -r <arg>     The HEX representation EC public key of the CA
  -c <arg>     The PEM file containing the EC private key of the CA
```

Usage exemple

```sh
./ecqv-utils cert_generate \
   -r 04458DF72811A1B871EE986058BEB913909CB1E8EF49A550ED4532B0FBA0EFFFF47DCDC70C1F6C6E87C819EF6F495DCF8A4F954E660A48C9376CF93E1D191F8FFF \
   -i 12345 \
   -k ca_key.pem
```

### Certificate reception

Receive the certificate that originated from a `cert_request` command and
retrieve the private and public key from that certificate.
The private key will be used to proove the origin of the message we send.

```sh
<CMD>: cert_reception
<Options>
  -i <arg>     Identity of the requester
  -k <arg>     The PEM file containing the EC key of the requester
  -c <arg>     The CA public key in hex format
  -a <arg>     The implicit certificate in hex format
  -r <arg>     The number 'r' calculated by the CA
```

Usage exemple

```sh
./ecqv-utils cert_reception \
   -i 12345 \
   -k u_key.pem \
   -c 045FF951401C84AC6BD26A1977F71903A0389581CA0E61F41E5B09D1B54385AE4BCA956049237A3DF86F9D00401C6978F4A2F8843DEEC8DD1E88E02E2A2E7034D1 \
   -a 048BF5CA86F50474E64BD7E6607EE2AFD0F653DBC8DD3916E02C36884B6DF8535B7A94C5B6BE7F9ADE7E1F44E0F11DDDB1477FCAAD13B6F5C05050AD48CACF70B2 \
   -r 2B7E0766C264521AD9048E9ACC8937087E62E7FFE7807698D3A48963EB0C862D
```

### Certificate PK extraction

Extract the CA certificate public key from an implicit certificate. This public
key will be used to verify the origin of a message signed with the certificate
private key.

```sh
<CMD>: cert_pk_extract
<Options>
  -i <arg>     Identity of the requester
  -c <arg>     The CA public key in hex format
  -a <arg>     The implicit certificate in hex format
```

Usage exemple

```sh
./ecqv-utils cert_pk_extract \
   -i 12345 \
   -c 045FF951401C84AC6BD26A1977F71903A0389581CA0E61F41E5B09D1B54385AE4BCA956049237A3DF86F9D00401C6978F4A2F8843DEEC8DD1E88E02E2A2E7034D1 \
   -a 048BF5CA86F50474E64BD7E6607EE2AFD0F653DBC8DD3916E02C36884B6DF8535B7A94C5B6BE7F9ADE7E1F44E0F11DDDB1477FCAAD13B6F5C05050AD48CACF70B2
```

## Credits

* [jpellikk/ecqv-keygen](https://github.com/jpellikk/ecqv-keygen)

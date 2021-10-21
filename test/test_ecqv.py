import unittest
import os
from pathlib import Path

TEST_PATH = str(Path(__file__).resolve().parent) + "/"

ECQV_PATH = TEST_PATH + "../ecqv-utils"
CA_PATH = TEST_PATH + "ca_key.pem"
CL_PATH = TEST_PATH + "cl_key.pem"
G_PATH = TEST_PATH + "g_key.pem"
_CL_PATH = TEST_PATH + "_cl_key.pem"
_G_PATH = TEST_PATH + "_g_key.pem"


def ecqv_pk_extract(ecqv_utils_path, priv):
    s = os.popen("%s pk_extract -k %s" % (ecqv_utils_path, priv))
    return s.read().strip()


def ecqv_priv_extract(ecqv_utils_path, priv):
    s = os.popen("%s priv_extract -k %s" % (ecqv_utils_path, priv))
    return s.read().strip()


def ecqv_cert_request(ecqv_utils_path, identity, key_path):
    s = os.popen("%s cert_request -i %s -k %s" %
                 (ecqv_utils_path, identity, key_path))
    return s.read().strip()


def ecqv_cert_generate(ecqv_utils_path, identity, requester_pk, key_path):
    s = os.popen(
        "%s cert_generate -i %s -r %s -k %s"
        % (ecqv_utils_path, identity, requester_pk, key_path)
    )
    return s.read().strip().split("\n")


def ecqv_cert_reception(ecqv_utils_path, identity, key_path, ca_pk, cert, r):
    s = os.popen(
        "%s cert_reception -i %s -k %s -c %s -a %s -r %s"
        % (
            ecqv_utils_path,
            identity,
            key_path,
            ca_pk,
            cert,
            r,
        )
    )
    return s.read().strip()


def ecqv_generate_confirmation(ecqv_utils_path, ca_pk, cert_priv_key, g_path):
    s = os.popen(
        "%s generate_confirmation -c %s -d %s -g %s"
        % (
            ecqv_utils_path,
            ca_pk,
            cert_priv_key,
            g_path,
        )
    )
    return "".join(s.read().strip().split())


def ecqv_verify_confirmation(ecqv_utils_path, verify, cert_pk, g_pk, ca_path):
    print(
        "%s verify_confirmation -v %s -d %s -g %s -k %s"
        % (
            ecqv_utils_path,
            verify,
            cert_pk,
            g_pk,
            ca_path,
        )
    )

    s = os.popen(
        "%s verify_confirmation -v %s -d %s -g %s -k %s"
        % (
            ecqv_utils_path,
            verify,
            cert_pk,
            g_pk,
            ca_path,
        )
    )
    response = s.read().strip().split()
    if len(response) and (response[0] == response[1]):
        return response[0]
    else:
        return None


def ecqv_group_generate(ecqv_utils_path, ca_path, ids, g_pks, cert_pks, verify_numbers):
    s = os.popen(
        "%s group_generate -c %s -i %s -g %s -d %s -v %s"
        % (
            ecqv_utils_path,
            ca_path,
            ",".join(ids),
            ",".join(g_pks),
            ",".join(cert_pks),
            ",".join(verify_numbers),
        )
    )
    response = s.read().strip().split()
    return tuple(response)


def ecqv_cert_pk_extract(ecqv_utils_path, identity, ca_pk, cert):
    s = os.popen(
        "%s cert_pk_extract -i %s -c %s -a %s"
        % (
            ecqv_utils_path,
            identity,
            ca_pk,
            cert,
        )
    )
    return s.read().strip()


def ecqv_encrypt(ecqv_utils_path, key, message):
    s = os.popen(
        "%s encrypt -k %s -m %s" % (ecqv_utils_path, key, message)
    )

    return s.read().strip()


def ecqv_decrypt(ecqv_utils_path, key, cypher):
    s = os.popen(
        "%s decrypt -k %s -m %s" % (ecqv_utils_path, key, cypher)
    )

    return s.read().strip()


IDENTITY = "12345"
IDENTITY_ = "11111"


class TestEcqv(unittest.TestCase):
    def test_public_key(self):
        PK = "043E15031CAD572A280EFBE3E6B43F3D0D4859D32754C7AE8CBF86433802AA05BBA1FDFD401C95B7B6E30AEC55FBD4A9D601F8EE324BE916ECAC6F334565F28D36"
        pk = ecqv_pk_extract(ECQV_PATH, CA_PATH)
        self.assertEqual(PK, pk)

    def test_priv_key(self):
        pk = ecqv_pk_extract(ECQV_PATH, CA_PATH)
        priv = ecqv_priv_extract(ECQV_PATH, CA_PATH)
        self.assertEqual(pk, ecqv_pk_extract(ECQV_PATH, priv))

    def test_cert_request(self):
        ca_pub = ecqv_pk_extract(ECQV_PATH, CA_PATH)
        req = ecqv_cert_request(ECQV_PATH, IDENTITY, CL_PATH)
        cert, r = ecqv_cert_generate(ECQV_PATH, IDENTITY, req, CA_PATH)
        cert_priv = ecqv_cert_reception(
            ECQV_PATH, IDENTITY, CL_PATH, ca_pub, cert, r)
        cert_pub = ecqv_pk_extract(ECQV_PATH, cert_priv)
        cert_pub_ = ecqv_cert_pk_extract(ECQV_PATH, IDENTITY, ca_pub, cert)
        self.assertEqual(cert_pub, cert_pub_)

    def test_cert_confirmation(self):
        ca_pub = ecqv_pk_extract(ECQV_PATH, CA_PATH)
        g_pub = ecqv_pk_extract(ECQV_PATH, G_PATH)
        req = ecqv_cert_request(ECQV_PATH, IDENTITY_, CL_PATH)
        cert, r = ecqv_cert_generate(ECQV_PATH, IDENTITY, req, CA_PATH)
        cert_priv = ecqv_cert_reception(
            ECQV_PATH, IDENTITY, CL_PATH, ca_pub, cert, r)
        cert_pub = ecqv_pk_extract(ECQV_PATH, cert_priv)
        self.assertEqual(cert_pub, ecqv_pk_extract(ECQV_PATH, cert_priv))
        conf = ecqv_generate_confirmation(ECQV_PATH, ca_pub, cert_priv, G_PATH)
        print("heeeeeeeeeeeeeeeeeere ", conf)
        decrypted_conf = ecqv_verify_confirmation(
            ECQV_PATH, conf, cert_pub, g_pub, CA_PATH)
        self.assertIsNotNone(decrypted_conf)

    def test_group_generation(self):
        ca_pub = ecqv_pk_extract(ECQV_PATH, CA_PATH)

        # FIRST PARTICIPANT
        g_pub = ecqv_pk_extract(ECQV_PATH, G_PATH)
        req = ecqv_cert_request(ECQV_PATH, IDENTITY, CL_PATH)
        cert, r = ecqv_cert_generate(ECQV_PATH, IDENTITY, req, CA_PATH)
        cert_priv = ecqv_cert_reception(
            ECQV_PATH, IDENTITY, CL_PATH, ca_pub, cert, r)
        cert_pub = ecqv_pk_extract(ECQV_PATH, cert_priv)
        conf = ecqv_generate_confirmation(ECQV_PATH, ca_pub, cert_priv, G_PATH)
        decrypted_conf = ecqv_verify_confirmation(
            ECQV_PATH, conf, cert_pub, g_pub, CA_PATH)

        self.assertIsNotNone(decrypted_conf)

        priv, pub = ecqv_group_generate(ECQV_PATH, CA_PATH, [IDENTITY], [
                                        g_pub], [cert_pub], [decrypted_conf])

        self.assertEqual(priv, ecqv_pk_extract(ECQV_PATH, pub))

    def test_group_generation_second(self):
        ca_pub = ecqv_pk_extract(ECQV_PATH, CA_PATH)

        # FIRST PARTICIPANT
        g_pub = ecqv_pk_extract(ECQV_PATH, G_PATH)
        req = ecqv_cert_request(ECQV_PATH, IDENTITY, CL_PATH)
        cert, r = ecqv_cert_generate(ECQV_PATH, IDENTITY, req, CA_PATH)
        cert_priv = ecqv_cert_reception(
            ECQV_PATH, IDENTITY, CL_PATH, ca_pub, cert, r)
        cert_pub = ecqv_pk_extract(ECQV_PATH, cert_priv)
        conf = ecqv_generate_confirmation(ECQV_PATH, ca_pub, cert_priv, G_PATH)
        decrypted_conf = ecqv_verify_confirmation(
            ECQV_PATH, conf, cert_pub, g_pub, CA_PATH)

        self.assertIsNotNone(decrypted_conf)

        # SECOND PARTICIPANT
        _g_pub = ecqv_pk_extract(ECQV_PATH, _G_PATH)
        _req = ecqv_cert_request(ECQV_PATH, IDENTITY_, _CL_PATH)
        _cert, _r = ecqv_cert_generate(ECQV_PATH, IDENTITY_, _req, CA_PATH)
        _cert_priv = ecqv_cert_reception(
            ECQV_PATH, IDENTITY_, _CL_PATH, ca_pub, _cert, _r)
        _cert_pub = ecqv_pk_extract(ECQV_PATH, _cert_priv)
        _conf = ecqv_generate_confirmation(
            ECQV_PATH, ca_pub, _cert_priv, _G_PATH)
        _decrypted_conf = ecqv_verify_confirmation(
            ECQV_PATH, _conf, _cert_pub, _g_pub, CA_PATH)

        self.assertIsNotNone(_decrypted_conf)

        priv, pub = ecqv_group_generate(ECQV_PATH, CA_PATH, [IDENTITY, IDENTITY_], [
                                        g_pub, _g_pub], [cert_pub, _cert_pub], [decrypted_conf, _decrypted_conf])

        self.assertEqual(priv, ecqv_pk_extract(ECQV_PATH, pub))

    def test_encrypt(self):
        KEY = "04B868B4B5491E2A1E9530248EFF926C800609A1F541C14DBB566368CC2989E4D0BAE4F55D3E07BF63692132992CFE4381FC535AC717EA6BA232CD24F2DFA27DF8"
        BASE_MESSAGE = "hello"
        enc = ecqv_encrypt(ECQV_PATH, KEY, BASE_MESSAGE)
        dec = ecqv_decrypt(ECQV_PATH, KEY, enc)
        self.assertEqual(BASE_MESSAGE, dec)

    def test_import_public_key(self):
        ca_pub = ecqv_pk_extract(ECQV_PATH, CA_PATH)
        g_pub = ecqv_pk_extract(ECQV_PATH, G_PATH)
        req = ecqv_cert_request(ECQV_PATH, IDENTITY_, CL_PATH)
        cert, r = ecqv_cert_generate(ECQV_PATH, IDENTITY, req, CA_PATH)
        cert_priv = ecqv_cert_reception(
            ECQV_PATH, IDENTITY, CL_PATH, ca_pub, cert, r)
        cert_pub = ecqv_pk_extract(ECQV_PATH, cert_priv)
        OUT1 = ecqv_generate_confirmation(ECQV_PATH, ca_pub, cert_priv, G_PATH)
        OUT2 = ecqv_generate_confirmation(
            ECQV_PATH, CA_PATH, cert_priv, G_PATH)
        self.assertEqual(OUT1, OUT2)


if __name__ == "__main__":
    unittest.main()

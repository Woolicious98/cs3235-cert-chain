from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from binascii import unhexlify
from datetime import datetime
import json

ca_public_key_str = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9ZnK18bHQAroAi9jHMGlh/olY
j3y8xQlEoG3vuTRmL6SqqTXjiV60+YdE2Q22SeoTGWC6JdiCHvZZ7Fk1zTumepnv
Q0QMmlX5kyAtlNaX89JY9PSGKCsrGJJxCOJPuOaK2QfDKnODPrM4JdHNa5R+JBkI
VWcuG7xNp+4/0h6dkwIDAQAB
-----END PUBLIC KEY-----"""

trusted_ca_name = "bigca.com"
trusted_cas = {
    trusted_ca_name: RSA.import_key(ca_public_key_str),
}


def get_cert_data_hash(cert):
    return SHA256.new(json.dumps(cert["data"]).encode())


def verify_cert(name, certs, trusted_cas):
    if len(certs) < 1:
        return False, None
    cert = certs[0]

    if name != cert["data"]["name"]:
        return False, None

    if datetime.fromisoformat(cert["data"]["expiry"]) < datetime.now():
        return False, None

    h = get_cert_data_hash(cert)
    try:
        key = None
        issuer = cert["issuer"]
        if issuer in trusted_cas:
            key = trusted_cas[issuer]
        else:
            valid, key = verify_cert(issuer, certs[1:], trusted_cas)
            if not valid:
                return False, None

        pkcs1_15.new(key).verify(h, unhexlify(cert["sig"]))
        return True, RSA.import_key(unhexlify(cert["data"]["pub_key"]))
    except (ValueError, TypeError):
        return False, None


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("usage: verify_cert.py domain [filename]")
        print("If filename is not given, read from stdin")
        sys.exit(1)

    name = sys.argv[1]
    file = sys.stdin
    if len(sys.argv) == 3:
        file = open(sys.argv[2], "r")

    cert = json.loads(file.read())
    valid, key = verify_cert(name, cert, trusted_cas)
    if valid:
        print("Certificate is valid and has key:")
        print(key.export_key().decode())
    else:
        print("Certificate fails validation!")
        sys.exit(2)

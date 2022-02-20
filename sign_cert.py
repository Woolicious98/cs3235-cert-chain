from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from binascii import unhexlify
from datetime import datetime
import json
import sys
import base64

eve_private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDEHCy9NLFzk3bLh5YxDxGew4BghRcQtAC8IvKZvj664Wf6a3A6
TjChOULF8qaa8IyGLli9G2/jOVwNtxzsnSAUl+Q5AOcEtwO9iDRj6lA2nlH6GsbZ
7aeGN0nfNHv9x57v/WP2vsIKiyX4KjhStggzJeLii+79oOWe3YZE0KlBfwIDAQAB
AoGAKYWdo2HowIPUfztx/WknXeoe4FDNlWfHUA5GN28kcQUQsuDUnkO34CrzjF3Y
EK4l0rM1brTEd+PJLc47fY23IMXSopC5v6OoGnd+b9EnWlbOF2YzG4CYl4y1dKf3
aCIpJsShmpTRmJCI6rz6WPXp5Q6aaGMznRravtFHGbJAYQECQQDMp3ihlC9oSPAC
qng8xqKfHuCryNCfkwLn5CT1wV9cKwFQs4QsnZ77DncNN82vkvQZyT/5a9T+Ax/e
5q/1DQLfAkEA9U/ubuOKmX2DN0w9TemYwPsx2tYnpA0hbphAv/IJw8N3wWtQlG07
VZ4fXy1tCVtvvmb+DN3sOadar7MVKj01YQJABOCw9Vjs0FV8svORLhGl6pj3zeBZ
aJQ+a3x6jQjw1ueHfn7o1Y9kLKOpnr0Hv/mGq96qEa3KQ8ubRNrGstZ+jQJBAIQz
8oRyPkSf/rIzdSpjBL6j4WdVWIGxzd2jUenfz+Ffm09yvTdwcrSehbuuaH/Ndjg/
mxRmGSOtDFN6CKL936ECQQCV+e6Anxf0scsVWlFq2y9XVD8H6cXpMHk6pohrHJy9
Y4fpPMHcagBYI6E/d6LHIu9WCkczk300QHTWSiwrjpLL
-----END RSA PRIVATE KEY-----"""

eve_public_key = "30819f300d06092a864886f70d010101050003818d0030818902818100c41c2cbd34b1739376cb8796310f119ec38060851710b400bc22f299be3ebae167fa6b703a4e30a13942c5f2a69af08c862e58bd1b6fe3395c0db71cec9d201497e43900e704b703bd883463ea50369e51fa1ac6d9eda7863749df347bfdc79eeffd63f6bec20a8b25f82a3852b6083325e2e28beefda0e59edd8644d0a9417f0203010001"

def get_cert_data_hash(cert):
    return SHA256.new(json.dumps(cert["data"]).encode())

def sign_data(rawdata):
    rawdata = rawdata[0]
    key = RSA.import_key(eve_private_key)
    hash_data = get_cert_data_hash(rawdata)
    answer = pkcs1_15.new(key).sign(hash_data)
    pubkey = RSA.import_key(unhexlify(eve_public_key))
    print(pubkey.export_key().decode())
    a = """MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDEHCy9NLFzk3bLh5YxDxGew4Bg
hRcQtAC8IvKZvj664Wf6a3A6TjChOULF8qaa8IyGLli9G2/jOVwNtxzsnSAUl+Q5
AOcEtwO9iDRj6lA2nlH6GsbZ7aeGN0nfNHv9x57v/WP2vsIKiyX4KjhStggzJeLi
i+79oOWe3YZE0KlBfwIDAQAB"""
    print(base64.b64decode(a).hex())
    print("hex form = ",answer.hex())    
    try:
        pkcs1_15.new(pubkey).verify(hash_data,answer)
    except(ValueError, TypeError):
        print("does not match")
    return answer


def main():
    if len(sys.argv) < 1 or len(sys.argv) > 2:
        print("usage: sign_cert.py [JSON filename]")
        sys.exit(1)
    filename = sys.argv[1]
    file = open(filename,"r")
    rawdata = json.loads(file.read())
    result = sign_data(rawdata)
    print("Result = ",result.hex())


if __name__ == "__main__":
    main()
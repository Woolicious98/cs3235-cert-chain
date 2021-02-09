# CS3235 (Computer Security) Certificate Chain Homework

This repo provides code for a homework problem in CS3235. In a simplified site certificate scheme, certificates are represented as JSON objects, such as:

```
[
    {
        "data": {
            "name": "brokenchain.com",
            "expiry": "2021-12-31 23:59:59",
            "pub_key": "..."
        },
        "issuer": "someauthority.com",
        "sig": "..."
    }
]
```

Notice that the "data" section includes the actual certificate data, following by the issuer and signature.

## Requirements

While the homework can be completed in any language compliant with the specifications here, it will be checked using the Python code in this repo, and therefore we strongly recommend at least checking your answers with Python before submitting, if not actually implementing in Python.

**All answers will be verified with verify_cert.py. Answers that do not pass this step will be considered incorrect.**

Python 3 and PyCryptoDome are required to run the code here. Use `python -m pip install -r requirements.txt` to ensure you have all required packages.

## Signature

The signature is computed as a SHA256 hash of the "data" section when printed as JSON with all whitespace condensed to a single space (i.e. the output of the Python `json.dumps` function), and then computed with PKCS#1 v1.5 / RSA, before being output as a string of bytes in hexadecimal.

## Public Keys

Public keys are in DER format output as hexadecimal strings.

## Chains

Certificate chains are possible by giving a list of several certificates. The issuer of the first certificate must match the name of the next certificate and so on, and must terminate in a root trusted CA. For example:

```
[
    {
        "data": {
            "name": "something.mychain.com",
            "expiry": "2021-12-31 23:59:59",
            "pub_key": "..."
        },
        "issuer": "mychain.com",
        "sig": "..."
    }
    {
        "data": {
            "name": "mychain.com",
            "expiry": "2021-12-31 23:59:59",
            "pub_key": "..."
        },
        "issuer": "someauthority.com",
        "sig": "..."
    }
]
```

## Verification

The verify_cert.py file implements the verification algorithm, which works roughly as follows:

1.  If the name on the certificate does not match the domain name being queried, return false
2.  If the certificate has expired, return false
3.  If the issuer is a trusted root CA, then use the root CA public key to verify the signature. If the signature is valid, return true along with the public key in the certificate
4.  If the issuer is some other authority, then call verify_cert again on the next certificate in the chain with the name of the issuer. If the recursive call fails, return false.
5.  Verify the signature with the public key retrieved in the previous step, return true if the validation is successful and false otherwise.

You can verify a certificate by calling verify_cert as follows:

    python verify_cert.py domainname.com cert_file.json

If a filename is not given, the certificate is read from stdin.

## Academic Honesty

We expect that all students will submit their own answers using code they have written themselves. Despite the fixed inputs, the correct solution to this problem uses randomized encryption, and thus any cheating will become very obvious. Please don't do it. Write your own answers, and ask the TAs / the forum if you run into any problems.

# Note for collaborators

For any collaborators / facilitators: please *do not* edit the student-facing repo directly. Instead, update the main branch of the solutions repo, and then push the main branch of the solutions repo to the student repo. Also: be careful not to edit any student facing code on the solutions branch of the solutions repo, and definitely *do not push the solutions branch to any other repo!*

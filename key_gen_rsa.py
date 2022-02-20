from Crypto.PublicKey import RSA
import base64

key = RSA.generate(2048)
print(key.publickey())
f = open('mykey.pem','wb')
f.write(key.export_key('PEM'))
f.write(b"\n")
f.write(key.publickey().export_key('PEM'))
f.close()
print("Pub key = ",key.publickey().export_key('PEM').decode())
print()



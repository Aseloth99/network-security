import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import random, string

def KeyMaker():
    backend = default_backend()
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend)
    return base64.urlsafe_b64encode(kdf.derive(bytes(randomword(20),"utf-8"))).decode("ascii")

def Encrypt(text,key):
    return Fernet(key).encrypt(text.encode("UTF-16")).decode("UTF-16")

def Decrypt(data,key):
    return  Fernet(key).decrypt(data.encode("UTF-16")).decode("UTF-16")

def randomword(length):
   letters = string.ascii_lowercase+string.ascii_uppercase+"0123456789"
   return ''.join(random.choice(letters) for i in range(length))

if __name__=="__main__":
    key=KeyMaker()
    enc=Encrypt("selam",key)
    print(enc) #䅧䅁䅁杂汷䔹䉱奎猴塬到牚䱥氷橐䭇䵄䩏㜳湺睬奅彆㙖礳ⵢ歊㕈䕗牶牊児䩉䔭党卵䝔塣摍卤焲奣䍁偌楴䉍海䥉朷㴽
    dec=Decrypt(enc,key)
    print(dec)

import os, random, struct
from Crypto.Cipher import AES
from AES import AESCipher
from Crypto.Random import get_random_bytes



AESObject=AESCipher()
#encrypt_file(AESObject,"asd.txt","123.txt")
a=encrypt("asd.txt")
decrypt(a)
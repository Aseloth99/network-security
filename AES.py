from Crypto.Cipher import AES
import binascii, os

class AESCipher():
    #def __init__(self,msg):
    #    self.secretKey = os.urandom(32)

    def encrypt_AES_GCM(msg,secretKey):
        print("secretKey",secretKey)
        aesCipher = AES.new(secretKey, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(bytes(msg, 'utf-8'))
        return (ciphertext, aesCipher.nonce, authTag)

    def decrypt_AES_GCM(encryptedMsg,secretKey):
        ciphertext, nonce, authTag = encryptedMsg
        aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
        plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
        return plaintext

# if __name__ == "__main__":
#     plainText="Knowledge is Power"
#     AESObject=AESCipher(plainText)

#     print("AES Encryption")
#     print(binascii.hexlify(AESObject.secretKey))
#     encryptedAESMsg = AESObject.encrypt_AES_GCM()
#     print(encryptedAESMsg)

#     print("AES Decryption")
#     decryptedAESMsg = AESObject.decrypt_AES_GCM(encryptedAESMsg)
#     print(f"\t{decryptedAESMsg.decode('utf-8')}")
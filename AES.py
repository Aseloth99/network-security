from Crypto.Cipher import AES
import os

class AESCipher():

    def encrypt_AES_GCM(self,msg,secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(bytes(msg, 'utf-8'))
        return (ciphertext, aesCipher.nonce, authTag)

    def decrypt_AES_GCM(self,encryptedMsg,secretKey):
        ciphertext, nonce, authTag = encryptedMsg
        aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
        plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
        return plaintext
        


if __name__=="__main__":
    AESObject=AESCipher()
    secretKey=os.urandom(32)
    print(secretKey)
    encryptedMsg = AESObject.encrypt_AES_GCM("anan",secretKey)
    print("Encrypted Message:",encryptedMsg)
    ciphertext, nonce, authTag = encryptedMsg
    print(nonce)
    print(type(nonce))
    print(len(nonce))
    decryptedMsg = AESObject.decrypt_AES_GCM(encryptedMsg,secretKey)
    print("Decrypted Message:",str(decryptedMsg)[2:-1:])
    print(type(decryptedMsg))
    print(len(decryptedMsg))

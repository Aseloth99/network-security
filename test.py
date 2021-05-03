import AES
import binascii,os

MailHead="asd"
MailBody="asdadsasd"

headAESObject=AES.AESCipher(MailHead)
bodyAESObject=AES.AESCipher(MailBody)

encMailHead = headAESObject.encrypt_AES_GCM()
encMailBody = bodyAESObject.encrypt_AES_GCM()

a=binascii.hexlify(headAESObject.secretKey)
b=binascii.hexlify(bodyAESObject.secretKey)
print(a) #anahtar head
print(b) #anahtar body

print(binascii.unhexlify(a))
print(binascii.unhexlify(b))

decMailHead = headAESObject.decrypt_AES_GCM(encMailHead,headAESObject.secretKey)
decMailBody = bodyAESObject.decrypt_AES_GCM(encMailBody,bodyAESObject.secretKey)

print(decMailHead.decode('utf-8'))
print(decMailBody.decode('utf-8'))

#decryptedAESMsg = AES.AESCipher(Mail).decrypt_AES_GCM(encryptedAESMsg)
#print(f"\t{decryptedAESMsg.decode('utf-8')}")

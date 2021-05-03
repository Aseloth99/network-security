from Crypto.Util.number import bytes_to_long, long_to_bytes

def EncryptTextWithRSA(msg,rsaPrivate,n): #Signature with root private key
    m=  bytes_to_long(str(msg).encode('utf-8')) 
    return pow(m,int(rsaPrivate), int(n))

def DecryptTextWithRSA(encText,rsaPublic,n):  #Signature with root public key
    res=pow(encText,int(rsaPublic) ,int(n))  #(****,65537,******)
    return str((long_to_bytes(res)).decode("utf-8"))

def CreateSignatureRSA(publicKey,publicKeyN,rootRsaPrivate,rootN): #65537, n, ***,n 
    m=  bytes_to_long(str(publicKey).encode('utf-8')) 
    return pow(m,int(rootRsaPrivate), int(rootN))
import rsa

class RS:
    def encryptMsg(message, n,e):                   #Target Public key (e,n)
        public_key=rsa.PublicKey(n,e)
        return rsa.encrypt(message, public_key)
    def decryptMsg(encrypted_message, n,e,d,p,q):   #Bizim Private key (d,n)
        private_key=rsa.PrivateKey(n,e,d,p,q)
        return rsa.decrypt(encrypted_message, private_key)

if __name__=="__main__":
    message = b"gxf"
    
    public_key, private_key = rsa.newkeys(2048)
    #print(public_key.n,public_key.e)
    #print("d",private_key.d)
    #print("p",private_key.p)
    #print("q",private_key.q)

    #public_key=rsa.PublicKey(n,e)
    #private_key=rsa.PrivateKey(n,e,d,p,q)
    
    encrypted_message = rsa.encrypt(message, public_key)
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    print(encrypted_message,decrypted_message)
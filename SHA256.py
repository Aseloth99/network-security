import hashlib

class SHA256():
    def encrypter(self,text):    
        #print(type(str.encode(text) ))
        text=text.encode('utf-8')
        h=hashlib.sha256()
        h.update(text)
        return str(h.hexdigest())

if __name__=="__main__":
    print(SHA256().encrypter("elma"))
    

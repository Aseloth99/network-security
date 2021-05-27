import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

BUFFER_SIZE = 1024 * 1024

class Encrypt(inputFileFullPath,aesKey):

    outputFileFullPath=inputFileFullPath+".encrypted"
    file_in = open(inputFileFullPath, 'rb')
    file_out = open(output_filename, 'wb')

    salt = get_random_bytes(32) 
    key = scrypt(aesKey, salt, key_len=32, N=2**17, r=8, p=1) 
    file_out.write(salt)

    cipher = AES.new(key, AES.MODE_GCM)
    file_out.write(cipher.nonce)

    data = file_in.read(BUFFER_SIZE) 
    while len(data) != 0:
        encrypted_data = cipher.encrypt(data)
        file_out.write(encrypted_data)
        data = file_in.read(BUFFER_SIZE)

    tag = cipher.digest()
    file_out.write(tag)
    file_in.close()
    file_out.close()

class Decrypt(encFileFullPath,aesKey):

    outputFilePath=encFileFullPath.split("/").pop().split(".encrypted")[0]

    file_in = open(encFileFullPath, 'rb')
    file_out = open(outputFilePath, 'wb')

    salt = file_in.read(32)
    key = scrypt(aesKey, salt, key_len=32, N=2**17, r=8, p=1) 

    nonce = file_in.read(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    file_in_size = os.path.getsize(encFileFullPath)
    encrypted_data_size = file_in_size - 32 - 16 - 16

    for _ in range(int(encrypted_data_size / BUFFER_SIZE)): 
        data = file_in.read(BUFFER_SIZE) 
        decrypted_data = cipher.decrypt(data) 
        file_out.write(decrypted_data)  
    data = file_in.read(int(encrypted_data_size % BUFFER_SIZE)) 
    decrypted_data = cipher.decrypt(data)
    file_out.write(decrypted_data) 

    tag = file_in.read(16)

    try:
        cipher.verify(tag)
    except ValueError as e:
      
        file_in.close()
        file_out.close()
        os.remove(output_filename)
        raise e

    file_in.close()
    file_out.close()
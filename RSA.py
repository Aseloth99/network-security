import rsa

message = b"Hadi canım sen de var ya öçşiğü"
public_key, private_key = rsa.newkeys(2048)
encrypted_message = rsa.encrypt(message, public_key)
decrypted_message = rsa.decrypt(encrypted_message, private_key)
print(encrypted_message,decrypted_message)
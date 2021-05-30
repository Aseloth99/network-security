import os
from base64 import b64encode,b64decode

original=os.urandom(32)
targetAESKey = b64encode(original)

print(targetAESKey)
print(type(targetAESKey))




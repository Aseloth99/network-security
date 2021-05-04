import os
from base64 import b64encode,b64decode

orijinal=os.urandom(32)
print(orijinal)
print(type(orijinal))
print(len(orijinal))

stringer = b64encode(orijinal).decode('utf-8')
print(stringer)
print(type(stringer))
print(len(stringer))

byter=b64decode(stringer)

print(byter)
print(type(byter))
print(len(byter))
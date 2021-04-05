#Only works in @gmail.com

#pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib

import FBConf as fb

print(fb.db.child("Açık").get().val())




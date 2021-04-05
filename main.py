#Only works in @gmail.com
#https://app.diagrams.net/?src=about#HAseloth99%2Fnetwork-security%2Fmain%2FdatabaseMA  #diagram link
#pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib

import FBConf as fb

print(fb.db.child("Açık").get().val())




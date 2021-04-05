import pyrebase

pyrebaseConfig = {
    "apiKey": "AIzaSyBoFLL9n122ZcSrbvjtpuHQpJ4OFTwthss",
    "authDomain": "network-security-mail.firebaseapp.com",
    "projectId": "network-security-mail",
    "databaseURL": "https://network-security-mail-default-rtdb.firebaseio.com",
    "storageBucket": "network-security-mail.appspot.com",
    "messagingSenderId": "4386264647",
    "appId": "1:4386264647:web:6a7f3f289163d3189d0362"
}

firebase=pyrebase.initialize_app(pyrebaseConfig)
auth=firebase.auth()
db=firebase.database()
storage=firebase.storage()
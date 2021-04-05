import pyrebase

pyrebaseConfig = {
    "Here is FB Conf Infos"
}

firebase=pyrebase.initialize_app(pyrebaseConfig)
auth=firebase.auth()
db=firebase.database()
storage=firebase.storage()
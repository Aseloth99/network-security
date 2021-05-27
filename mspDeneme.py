import FBConf

pyrebase_storage_path="images/example10.jpg"
file_path="test.jpg"

FBConf.storage.child(pyrebase_storage_path).put(file_path)
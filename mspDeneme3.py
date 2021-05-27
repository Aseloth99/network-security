import FBConf



print(FBConf.db.generate_key())

FBConf.db.child("Emrah Koş").child(FBConf.db.generate_key()).set("asd")
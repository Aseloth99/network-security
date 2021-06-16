from PyQt5.QtWidgets import QMessageBox
from validate_email import validate_email
from PyQt5 import QtCore, QtGui, QtWidgets
import FBConf
import RSAGenerator
import sqlite3
import Signature
from base64 import b64encode,b64decode
import Cryptology
import time
import os

class Ui_Register(object):
    def setupUi(self, Register):
        Register.setObjectName("Register")
        Register.setFixedSize(592, 463)

        self.centralwidget = QtWidgets.QWidget(Register)
        self.centralwidget.setObjectName("centralwidget")

        self.edtTxtUsername = QtWidgets.QLineEdit(self.centralwidget)
        self.edtTxtUsername.setGeometry(QtCore.QRect(150, 40, 311, 41))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.edtTxtUsername.setFont(font)
        self.edtTxtUsername.setAlignment(QtCore.Qt.AlignCenter)
        self.edtTxtUsername.setObjectName("edtTxtUsername")

        self.edtTxtPassword = QtWidgets.QLineEdit(self.centralwidget)
        self.edtTxtPassword.setEchoMode(QtWidgets.QLineEdit.Password)
        self.edtTxtPassword.setGeometry(QtCore.QRect(150, 120, 311, 41))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.edtTxtPassword.setFont(font)
        self.edtTxtPassword.setAlignment(QtCore.Qt.AlignCenter)
        self.edtTxtPassword.setObjectName("edtTxtPassword")

        self.edtTxtGmail = QtWidgets.QLineEdit(self.centralwidget)
        self.edtTxtGmail.setGeometry(QtCore.QRect(20, 200, 550, 41))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.edtTxtGmail.setFont(font)
        self.edtTxtGmail.setAlignment(QtCore.Qt.AlignCenter)
        self.edtTxtGmail.setObjectName("edtTxtGmail")

        self.btnReg = QtWidgets.QPushButton(self.centralwidget)
        self.btnReg.setGeometry(QtCore.QRect(240, 370, 112, 41))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.btnReg.setFont(font)
        self.btnReg.setObjectName("btnReg")

        Register.setCentralWidget(self.centralwidget)

        self.retranslateUi(Register)
        QtCore.QMetaObject.connectSlotsByName(Register)

        self.btnReg.clicked.connect(lambda:self.goReg())

    def retranslateUi(self, Register):
        _translate = QtCore.QCoreApplication.translate
        Register.setWindowTitle(_translate("Register", "Register"))

        self.btnReg.setText(_translate("Register", "Register"))
        self.edtTxtUsername.setPlaceholderText(_translate("Register", "App Username"))
        self.edtTxtPassword.setPlaceholderText(_translate("Register", "App Password"))
        self.edtTxtGmail.setPlaceholderText(_translate("Register", "Enter Gmail"))
        self.edtTxtUsername.setText("Klavye")
        self.edtTxtPassword.setText("KlavyeFL0.")
        self.edtTxtGmail.setText("klavyefl@gmail.com")

    def goReg(self):
        self.Registering(self.edtTxtUsername.text(), self.edtTxtPassword.text(), self.edtTxtGmail.text())

    def Registering(self,username,password,gmail):
        if validate_email(gmail):
            if not username:       
                msg = QMessageBox()
                msg.setWindowTitle("Error ")
                msg.setText("Empty invalid")
                x = msg.exec_()
                msg.setIcon(QMessageBox.Critical)
                return False
            else:
                if not password:
                    msg = QMessageBox()
                    msg.setWindowTitle("Error ")
                    msg.setText("Empty Password")
                    x = msg.exec_()
                    msg.setIcon(QMessageBox.Critical)
                    return False
                else:
                    cntrlUsername=False
                    results=FBConf.db.child("User").get().val()         #User table 
                    
                    try:
                        for result in results:
                            if username == result.child("Username").get().val():
                                cntrlUsername=True
                    except:pass
 
                    if cntrlUsername==True:
                        print("Username Already Exists")
                        return False

                    else:
                        user= FBConf.auth.create_user_with_email_and_password(gmail,password)


                        #Kullanıcı Oluşturuldu username ve gmail adresleri kaydedildi
                        FBConf.db.child("User").child(user['localId']).child('Username').set(username,token=user['idToken'])
                        FBConf.db.child("User").child(user['localId']).child('Gmail').set(gmail,token=user['idToken'])
                        
                        cryptoKey=Cryptology.KeyMaker()
                        FBConf.db.child("User").child(user['localId']).child('CyrptologyKey').set(cryptoKey,token=user['idToken'])
                        ###

                        #Kullanıcı için RSA keyler oluşturuldu ve database kaydedidli
                        rsaGenerator=RSAGenerator.RSAGenerator()

                        # con = sqlite3.connect("Key.db") # Tabloya bağlanıyoruz.
                        # cursor = con.cursor()
                        # cursor.execute("CREATE TABLE IF NOT EXISTS Key (PrivateKey Text,PrivateP Text, PrivateQ Text,PublicKey Text,n Text)") 
                        # con.commit() #execute sorgusunun çalışması için
                        # #cursor.execute(f"Insert into Key Values({str(rsaGenerator.privateKey)},{str(rsaGenerator.privateP)},{str(rsaGenerator.privateQ)},{str(rsaGenerator.publicKey[0])},{str(rsaGenerator.publicKey[1])})")
                        # con.commit()

                        try:
                            fileInfos = open("Keys/"+gmail+"/Keys.txt", "w+", encoding="UTF-16")
                        except:
                            os.makedirs("Keys/"+gmail+"/") #iç içe klasör oluşturma
                            fileInfos = open("Keys/"+gmail+"/Keys.txt", "w+", encoding="UTF-16")
                        
                        TimeStamp=time.time()

                        EncPrivateKey = Cryptology.Encrypt(str(rsaGenerator.privateKey),cryptoKey)
                        EncPrivateP = Cryptology.Encrypt(str(rsaGenerator.privateP),cryptoKey)
                        EncPrivateQ = Cryptology.Encrypt(str(rsaGenerator.privateQ),cryptoKey)
                        EncN = Cryptology.Encrypt(str(rsaGenerator.publicKey[1]),cryptoKey)
                        EncPublicKey = Cryptology.Encrypt(str(rsaGenerator.publicKey[0]),cryptoKey)
                        EncTimeStamp = Cryptology.Encrypt(str(TimeStamp),cryptoKey)

                        fileInfos.write(EncPrivateKey+"\n")
                        fileInfos.write(EncPrivateP+"\n")
                        fileInfos.write(EncPrivateQ+"\n")
                        fileInfos.write(EncN+"\n")
                        fileInfos.write(EncPublicKey+"\n")
                        fileInfos.write(EncTimeStamp+"\n")
                        fileInfos.close()

                        PublicRSAInfos={"PublicKey":str(rsaGenerator.publicKey[0]),"n":str(rsaGenerator.publicKey[1]),"Timestamp":TimeStamp}
                        FBConf.db.child("Rings").child(user['localId']).push(PublicRSAInfos)
                        
                        #Kullanıcı RSA public keyi RootRSA private key tarafından imzalandı
                        
                        RootRSAN=FBConf.db.child("RootRSA").child("n").get().val() 
                        RootRSAPublic=FBConf.db.child("RootRSA").child("public").get().val() 
                        RootRSAPrivate=FBConf.db.child("RootRSA").child("private").get().val() 

                        signatureObj = Signature.Signature(RootRSAN,RootRSAPublic,RootRSAPrivate) #n,e,d
                        signature=signatureObj.Signaturing(gmail) #n'yi alıyor   Public key (e,n) ,e hepsinde aynı çünkü

                        myNewObj=Signature.Verifyer(RootRSAN,RootRSAPublic)
                        signature = b64encode(signature).decode('utf-8')
                        
                        FBConf.db.child("User").child(user['localId']).child('RSASignature').set(str(signature),token=user['idToken'])

                        return True
                    
        else:
            msg = QMessageBox()
            msg.setWindowTitle("Error ")
            msg.setText("Error Gmail")
            x = msg.exec_()
            msg.setIcon(QMessageBox.Critical)
            return False

if __name__ == '__main__':
    import sys
    app = QtWidgets.QApplication(sys.argv)
    window = QtWidgets.QMainWindow()
    ui = Ui_Register()
    ui.setupUi(window)
    window.show()
    sys.exit(app.exec_())
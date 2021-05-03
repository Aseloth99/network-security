from PyQt5 import QtCore, QtGui, QtWidgets
import os, binascii
import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from validate_email import validate_email

import FBConf
import AES

#os.system("pyuic5 -x arayüz.ui -o uiHome.py")
from uiHome import Ui_Home  #import interface

class HomeStarter():
    def __init__(self,ui,window):
        self.ui = ui
        self.window=window
        self.GetUserName()
        self.ui.sendButton.clicked.connect(lambda:self.SendMail())
        self.ui.toLineEdit.setText("ggg28@gggg.co")
        self.targetN=""
        #self.showMaximized()
        #self.threading()
        #self.themes=["windowsvista","Windows","Fusion","Koyu","Açık"]

    def GetUserName(self):
        user = FBConf.auth.current_user
        self.ui.nameLabel.setText("Welcome "+str(FBConf.db.child("User").child(user['localId']).child('Username').get(token=user['idToken']).val()))
    
    def GetTargetPublicKey(self):
        print("aaa")
        users=FBConf.db.child("User").get()
        print(users.val())

        for user in users.each():
            print("user.key()   ",user.key())
            if user.val()["Gmail"] == self.ui.toLineEdit.text():
                self.targetDBKey=user.key()
                self.targetN=user.val()["RSA"]["n"]
                self.targetPublicKey=user.val()["RSA"]["PublicKey"]
                self.targetEmail=self.ui.toLineEdit.text()
                print(self.targetEmail)
                break
                
        print(self.targetN)
    

    def CheckAES(self):
        user = FBConf.auth.current_user
        self.targetAESKey=binascii.unhexlify(FBConf.db.child("AES").child(user['localId']).child(self.targetEmail).get(token=user['idToken']).val())

    def CreateAndGetAES(self):
        user = FBConf.auth.current_user
        self.targetAESKey = os.urandom(32)
        print(binascii.hexlify(self.targetAESKey))

        FBConf.db.child("AES").child(user['localId']).child(self.targetEmail).push(binascii.hexlify(self.targetAESKey),token=user['idToken'])
    
    def AESEncryption(self):
        subject=self.ui.subjectLineEdit.text()
        body=self.ui.messageTextEdit.text()
        
        #(ciphertext, nonce, authTag)
        self.encSubjectAES=AES.AESCipher.encrypt_AES_GCM(subject,self.targetAESKey)
        self.encBodyAES =  AES.AESCipher.encrypt_AES_GCM(body,self.targetAESKey)

    def AESDecryption(self,encText,targetAESKey):    
        pass
        
    def SendMail(self):
    
        if validate_email(self.ui.toLineEdit.text()):
            
            try:
                self.GetTargetPublicKey()
            except Exception as e:
                print(e.__class__)
                print(e)
                print("Geçersiz Target Email")
            
            try:
                self.CheckAES()

            except:
                self.CreateAndGetAES()
            
            self.AESEncryption()

                

            
        '''
        if validate_email(self.ui.toLineEdit.text()):
            myMail="klavyefl@gmail.com"
            myPassword="KlavyeFL0."
            
            msg = MIMEMultipart()  
            msg["From"] =  myMail
            msg["To"] = self.ui.toLineEdit.text()
            msg["Subject"] =  self.ui.subjectLineEdit.text()

            mail = smtplib.SMTP("smtp.gmail.com",587)  # SMTP objemizi oluşturuyoruz ve gmail smtp server'ına bağlanıyoruz.
            mail.starttls() # Adresimizin ve Parolamızın şifrelenmesi için gerekli
            mail.ehlo() # SMTP serverına kendimizi tanıtıyoruz.
            mail.login(myMail,myPassword) 

            body = self.ui.messageTextEdit.toPlainText()

            msg_govdesi =  MIMEText(body,"plain")  # Mailimizin gövdesini bu sınıftan oluşturuyoruz.
            msg.attach(msg_govdesi) # Mailimizin gövdesini mail yapımıza ekliyoruz.

            try:
                mail.sendmail(msg["From"],msg["To"],msg.as_string())  # Mailimizi gönderiyoruz.
                self.ui.toLineEdit.clear()
                self.ui.subjectLineEdit.clear()
                self.ui.messageTextEdit.clear()
                self.ui.messageTextEdit.setPlaceholderText("Mail gönderildi.")
                
            except Exception as e:
                print(e)
                print("Oops!", e.__class__, "occurred.")
            mail.close()  # Smtp serverımızın bağlantısını koparıyoz.
        else:
            print("Mail adresi yok")
        '''

# if __name__ == "__main__":
#     app = QtWidgets.QApplication(sys.argv)
#     win = Home()
#     win.show()
#     sys.exit(app.exec_())
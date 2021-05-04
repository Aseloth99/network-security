from PyQt5 import QtCore, QtGui, QtWidgets
import os, binascii
import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from validate_email import validate_email
from base64 import b64encode,b64decode
import time;


import FBConf
import AES, SHA256, RSA

#os.system("pyuic5 -x arayüz.ui -o uiHome.py")
from uiHome import Ui_Home  #import interface

class HomeStarter():
    def __init__(self,ui,window,myEmail):
        self.ui = ui
        self.window=window
        self.GetUserName()
        self.ui.sendButton.clicked.connect(lambda:self.SendMail())
        self.ui.toLineEdit.setText("ggg28@gggg.co")
        self.targetN=""
        self.myEmail=myEmail
        
        #self.showMaximized()
        #self.threading()
        #self.themes=["windowsvista","Windows","Fusion","Koyu","Açık"]

    def GetUserName(self):
        self.user = FBConf.auth.current_user
        self.ui.nameLabel.setText("Welcome "+str(FBConf.db.child("User").child(self.user['localId']).child('Username').get(token=self.user['idToken']).val()))
    
    def GetTargetPublicKey(self):
        users=FBConf.db.child("User").get()

        for user in users.each():

            if user.val()["Gmail"] == self.ui.toLineEdit.text():
                self.targetDBKey=user.key()
                self.targetN=user.val()["RSA"]["n"]
                self.targetPublicKey=user.val()["RSA"]["PublicKey"]
                self.targetEmail=self.ui.toLineEdit.text()
                break

    def CheckAES(self):

        try:
            self.targetAESKey=FBConf.db.child("AES").child(self.user['localId']).child(self.targetDBKey).get(token=self.user['idToken']).val()
            
            if self.targetAESKey == None:
                return False
            else:
                return True

        except:return False
            

    def CreateAndGetAES(self):
        
        original=os.urandom(32)
        self.targetAESKey = b64encode(original).decode('utf-8')
        FBConf.db.child("AES").child(self.user['localId']).child(self.targetDBKey).set(self.targetAESKey,token=self.user['idToken'])
    
    def AESEncryption(self):
        
        subject=self.ui.subjectLineEdit.text()
        body=self.ui.messageTextEdit.toPlainText()

        #(ciphertext, nonce, authTag)
        self.encSubjectAES = AES.AESCipher.encrypt_AES_GCM(subject, self.targetAESKey)
        self.encBodyAES = AES.AESCipher.encrypt_AES_GCM(body, self.targetAESKey)

    def AESDecryption(self,encText,targetAESKey):    
        pass
        
    def SendMail(self):
    
        if validate_email(self.ui.toLineEdit.text()):
            
            try:
                self.GetTargetPublicKey()
            except:
                print("Geçersiz Target Email")
 
            try:
                if self.CheckAES():
                    pass
                else:
                    self.CreateAndGetAES()
            except:
                self.CreateAndGetAES()

            self.targetAESKey = b64decode(self.targetAESKey)

            self.AESEncryption()
            self.GoSendMail()
            self.SaveMailToDB()

            self.GetPassword()
            
    def GetPassword(self):
        pass

    def SaveMailToDB(self):
        ts = time.time()
        outboxData={"To":str(self.targetEmail),"Subject":str(self.encSubjectAES),"Body":str(self.encBodyAES),"TimeStamp":str(ts),"AES":str(self.targetAESKey),
            "HashTo":str(self.hash(self.targetEmail)),"HashSubject":str(self.hash(self.encSubjectAES)),"HashBody":str(self.hash(self.encBodyAES)),
            "HashTimeStamp":str(self.hash(ts)),"HashAES":str(self.hash(self.targetAESKey))
            }
        FBConf.db.child("Outbox").child(self.user['localId']).child(self.targetDBKey).push(outboxData)
        #Şu ana kadar gönderen kişinin outboxına düştü
        
        EncRSAaes=RSA.RS.encryptMsg(self.targetAESKey,int(self.targetN),int(self.targetPublicKey))

        myRSAN=FBConf.db.child("User").child(self.user['localId']).child("RSA").child('n').get(token=self.user['idToken']).val()
        fromSignature=FBConf.db.child("User").child(self.user['localId']).child("RSASignature").get(token=self.user['idToken']).val()

        inboxData={"From":str(self.myEmail),"Subject":str(self.encSubjectAES),"Body":str(self.encBodyAES),"TimeStamp":str(ts),
            "HashFrom":str(self.hash(self.myEmail)),"HashSubject":str(self.hash(self.encSubjectAES)),"HashBody":str(self.hash(self.encBodyAES)),
            "HashTimeStamp":str(self.hash(ts)),"EncRSAaes":str(EncRSAaes),"FromPublicN":str(myRSAN),"FromSignature":str(fromSignature),
            "HashEncRSAaes":str(self.hash(EncRSAaes)),"HashFromPublicN":str(self.hash(myRSAN)),"HashFromSignature":str(self.hash(fromSignature))
                }

        FBConf.db.child("Inbox").child(self.targetDBKey).child(self.user['localId']).push(inboxData)


    def hash(self,text):
           #filename classname funcname
        #print(SHA256.SHA256().encrypter(text))
        return SHA256.SHA256().encrypter(str(text))

    def GoSendMail(self):
        myPassword="KlavyeFL0."
        
        msg = MIMEMultipart()  
        msg["From"] =  self.myEmail
        #msg["To"] = self.targetEmail
        msg["To"] = "mustafaacik92@gmail.com"
        msg["Subject"] = str(self.encSubjectAES)

        mail = smtplib.SMTP("smtp.gmail.com",587)  # SMTP objemizi oluşturuyoruz ve gmail smtp server'ına bağlanıyoruz.
        mail.starttls() # Adresimizin ve Parolamızın şifrelenmesi için gerekli
        mail.ehlo() # SMTP serverına kendimizi tanıtıyoruz.
        mail.login(self.myEmail,myPassword) 

        body = str(self.encBodyAES)

        msg_govdesi =  MIMEText(body,"plain")  # Mailimizin gövdesini bu sınıftan oluşturuyoruz.
        msg.attach(msg_govdesi) # Mailimizin gövdesini mail yapımıza ekliyoruz.

        try:
            mail.sendmail(msg["From"],msg["To"],msg.as_string())  # Mailimizi gönderiyoruz.
            #self.ui.toLineEdit.clear()
            
            self.ui.subjectLineEdit.clear()
            self.ui.messageTextEdit.clear()
            self.ui.messageTextEdit.setPlaceholderText("Mail gönderildi.")
            
        except Exception as e:
            print(e)
            print("Oops!", e.__class__, "occurred.")
        mail.close()  # Smtp serverımızın bağlantısını koparıyoz.
    
# if __name__ == "__main__":
#     app = QtWidgets.QApplication(sys.argv)
#     win = Home()
#     win.show()
#     sys.exit(app.exec_())
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog,QTableWidgetItem 
from PyQt5.QtCore import Qt
import os, binascii
import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from validate_email import validate_email
from base64 import b64encode,b64decode
import time
import mspDenemeAesFileEnc

import FBConf
import AES, SHA256, RSA

os.system("pyuic5 -x arayüz.ui -o uiHome.py")
from uiHome import Ui_Home  #import interface

class HomeStarter(QtWidgets.QMainWindow):
    def __init__(self,ui,window,myEmail):
        super(HomeStarter, self).__init__()
        #self.ui = Ui_Home
        #self.ui.setupUi(self)
        self.ui=ui
        self.window=window
        #self.ui.setAcceptDrops(True)
        self.GetUserName()
        self.ui.sendButton.clicked.connect(lambda:self.SendMail())
        self.ui.pushButton.clicked.connect(lambda:self.__openFileNamesDialog())
        self.ui.toLineEdit.setText("ggg28@gggg.co")
        self.targetN=""
        self.myEmail=myEmail
        self.filename=""
        self.loadView()
        
     #self.showMaximized()
        #self.threading()
        #self.themes=["windowsvista","Windows","Fusion","Koyu","Açık"]
        
    #Gönderme  Baş

    def GetUserName(self):
        self.user = FBConf.auth.current_user
        self.ui.nameLabel.setText("Welcome "+str(FBConf.db.child("User").child(self.user['localId']).child('Username').get(token=self.user['idToken']).val()))


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
            
            self.SaveMailToDB()

            self.GoSendMail()

            self.GetPassword()

    def GetTargetPublicKey(self):

        users=FBConf.db.child("User").get()

        for user in users.each():

            if user.val()["Gmail"] == self.ui.toLineEdit.text():
                self.targetDBKey=user.key()
                self.targetN=user.val()["RSA"]["n"]
                self.targetPublicKey=user.val()["RSA"]["PublicKey"]
                self.targetEmail=self.ui.toLineEdit.text()
                break

    def CreateAndGetAES(self):
        original=os.urandom(32)
        self.targetAESKey = b64encode(original).decode('utf-8')
        FBConf.db.child("AES").child(self.user['localId']).child(self.targetDBKey).set(self.targetAESKey,token=self.user['idToken'])

    def __openFileNamesDialog(self):
        dlg = QFileDialog()
        dlg.setFileMode(QFileDialog.ExistingFiles)
        if dlg.exec_():
            self.InputFiles = dlg.selectedFiles()
            print(self.InputFiles)
            tmp = ""
            for i in self.InputFiles:
                tmp += os.path.basename(i)
                tmp += "; "
            self.ui.lineEdit.setText(tmp)
            self.filename=self.InputFiles[0]

    def CheckAES(self):
        try:
            self.targetAESKey=FBConf.db.child("AES").child(self.user['localId']).child(self.targetDBKey).get(token=self.user['idToken']).val()
            
            if self.targetAESKey == None:
                return False
            else:
                return True
        except:return False

    def AESEncryption(self):
        subject=self.ui.subjectLineEdit.text()
        body=self.ui.messageTextEdit.toPlainText()

        #(ciphertext, nonce, authTag)
        self.encSubjectAES = AES.AESCipher.encrypt_AES_GCM(self,subject, self.targetAESKey)
        self.encBodyAES = AES.AESCipher.encrypt_AES_GCM(self,body, self.targetAESKey)

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

        self.childKey=FBConf.db.generate_key()

        IdFbDb4Target=FBConf.db.child("Inbox").child(self.targetDBKey).child(self.user['localId']).child(self.childKey).set(inboxData)
        fbDb4Own=FBConf.db.child("Outbox").child(self.user['localId']).child(self.targetDBKey).child(self.childKey).set(inboxData)

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

        if(self.filename==""):
            pass
        else:
            filename = mspDenemeAesFileEnc.AESFile.fileEnc(self.targetAESKey,self.filename)

            self.PutFiletoDB(filename)

            attach_file = open(filename, 'rb') # Open the file as binary mode
            payload = MIMEBase('application', 'octate-stream')
            payload.set_payload(attach_file.read())
            encoders.encode_base64(payload) #encode the attachment
            #add payload header with filename
            payload.add_header('Content-Disposition', 'attachment', filename=filename)
            msg.attach(payload)
            
        try:
            mail.sendmail(msg["From"],msg["To"],msg.as_string())  # Mailimizi gönderiyoruz.
            #self.ui.toLineEdit.clear()
            
            self.ui.subjectLineEdit.clear()
            self.ui.messageTextEdit.clear()
            self.ui.messageTextEdit.setPlaceholderText("Mailiniz gönderildi.")
            
        except Exception as e:
            print(e)
            print("Oops!", e.__class__, "occurred.")
        mail.close()  # Smtp serverımızın bağlantısını koparıyoz.

    def PutFiletoDB(self,filename):

        FBConf.storage.child("Outbox").child(self.user['localId']).child(self.targetDBKey).child(self.childKey).child(filename.split("/").pop()).put(filename)
        FBConf.storage.child("InBox").child(self.targetDBKey).child(self.user['localId']).child(self.childKey).child(filename.split("/").pop()).put(filename)

    def GetPassword():
        pass

    # def dragEnterEvent(self, event):
    #     if event.mimeData().hasUrls():
    #         event.accept()
    #     else:
    #         event.ignore()
    # def dropEvent(self, event):
    #     files = [u.toLocalFile() for u in event.mimeData().urls()]
    #     for f in files:
    #         self.filename=f

    #Gönderme Son

    def AESDecryption(self,encText,targetAESKey): 
        pass
    
    def DBGetInbox(self):
        myInboxs=FBConf.db.child("Inbox").child(self.user['localId']).get(token=self.user['idToken'])
        mails=[]
        for myInbox in myInboxs.each():
            for elementInbox in myInbox.each():

                mails.add(
                    "From":elementInbox.val()["From"],
                    "Subject":elementInbox.val()["Subject"],
                    "Body":elementInbox.val()["Body"],
                    "TimeStamp":elementInbox.val()["TimeStamp"],
                    "HashSubject":elementInbox.val()["HashSubject"],
                    "HashBody":elementInbox.val()["HashBody"],
                    "HashTimeStamp":elementInbox.val()["HashTimeStamp"],
                    "EncRSAaes":elementInbox.val()["EncRSAaes"],
                    "FromPublicN":elementInbox.val()["FromPublicN"]
                    "FromSignature":elementInbox.val()["FromSignature"],
                    "HashEncRSAaes":elementInbox.val()["HashEncRSAaes"],
                    "HashFromPublicN":elementInbox.val()["HashFromPublicN"],
                    "HashFromSignature":elementInbox.val()["HashFromSignature"]
                )
                
        #Tüm veriler mails sözlüğünün içinde kardeş

               
                
    

    def loadView(self):
        mails =[{"subject":"selamlar1", "body":232},
                {"subject":"selamlar2", "body":232},
                {"subject":"selamlar3", "body":232}]
            
        self.ui.inboxTableView.setRowCount(len(mails))
        self.ui.inboxTableView.setColumnCount(2)
        self.ui.inboxTableView.setGridStyle(Qt.NoPen)
        self.ui.inboxTableView.setHorizontalHeaderLabels(("subject","body"))
        self.ui.inboxTableView.setColumnWidth(0,200)
        self.ui.inboxTableView.setColumnWidth(1,400)

        rowIndex = 0
        for mail in mails:
            self.ui.inboxTableView.setItem(rowIndex,0,QTableWidgetItem(mail["subject"]))
            self.ui.inboxTableView.setItem(rowIndex,1,QTableWidgetItem(str(mail["body"])))
            rowIndex+=1

#if __name__ == "__main__":
    # app = QtWidgets.QApplication(sys.argv)
    # win = HomeStarter()
    # win.show()
    # sys.exit(app.exec_())
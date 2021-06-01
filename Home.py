from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog,QTableWidgetItem 
from PyQt5.QtCore import Qt
import os, time
import sys, binascii
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from validate_email import validate_email
from base64 import b64encode,b64decode
import uuid
import Signature

import mspDenemeAesFileEnc
import FBConf
import AES, SHA256, RSA

os.system("pyuic5 -x arayüz.ui -o uiHome.py")
from uiHome import Ui_Home  #import interface

class OutboxObject: 
    def __init__(self, myId, to, subject, body, timeStamp ): 

        self.id = myId 
        self.to = to 
        self.subject = subject 
        self.body = body 
        self.timeStamp = timeStamp

class InboxObject: 
    def __init__(self, myId, From, subject, body, timeStamp ): 

        self.id = myId
        self.From = From 
        self.subject = subject 
        self.body = body 
        self.timeStamp = timeStamp

class HomeStarter(QtWidgets.QMainWindow):
    def __init__(self,ui,window,myEmail):
        super(HomeStarter, self).__init__()
        
        self.ui=ui
        self.window=window
        
        self.GetUserName()
        self.ui.sendButton.clicked.connect(lambda:self.SendMail())
        self.ui.pushButton.clicked.connect(lambda:self.__openFileNamesDialog())
        self.ui.toLineEdit.setText("klavyefl@gmail.com")
        self.targetN=""
        self.myEmail=myEmail
        self.filename=""
        self.inboxMails=[]
        self.outboxMails=[]
        self.ui.reloadOutbox.clicked.connect(lambda: self.updateView())
        self.ui.reloadInbox.clicked.connect (lambda: self.updateView())
        self.DBGetInbox()
        self.DBGetOutbox()
        #self.themes = ["windowsvista","Windows","Fusion","Koyu","Açık"]
        
    #Gönderme Başlangıç

    def updateView(self):
        self.inboxMails = []
        self.outboxMails = []
        self.ui.outboxTableView.clear()
        self.ui.inboxTableView.clear()
        self.DBGetInbox()
        self.DBGetOutbox()
        self.outboxLoadView()
        self.inboxLoadView()

    def GetUserName(self):
        self.user = FBConf.auth.current_user
        self.ui.nameLabel.setText("Welcome "+str(FBConf.db.child("User").child(self.user['localId']).child('Username').get(token=self.user['idToken']).val()))

    def SendMail(self):
        if validate_email(self.ui.toLineEdit.text()):
            
            try:
                self.GetTargetPublicKey()
            except:
                pass
            try:
                if self.CheckAES():
                    pass
                else:
                    self.CreateAndGetAES()
            except:
                self.CreateAndGetAES()

            self.targetAESKey = b64decode(self.targetAESKey)

            self.AESEncryption()
            
            self.ControlReplayAttack()

    def ControlReplayAttack(self):

        currentTime = time.time()
        targetInboxes = FBConf.db.child("Inbox").child(self.targetDBKey).child(self.user['localId']).get()

        dbTimeStamp=0

        try:
            for i in targetInboxes.each():
                i=i.val()
                
                if float(i["TimeStamp"]) > dbTimeStamp and i["HashTimeStamp"]==self.hash(i["TimeStamp"]):
                    dbTimeStamp=float(i["TimeStamp"])

            if currentTime < (dbTimeStamp + 5) :  #aynı kişiden son 10 saniyeden gelen maili iptal ediyoruz
                self.ui.toLineEdit.setText("Now Reply Attack")
                self.ui.lineEdit.setText("Now Reply Attack")
            else:
                self.SaveMailToDB()
                self.GoSendMail() 
        except: 
            self.SaveMailToDB()
            self.GoSendMail()  
                                             
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
        
        self.encSubjectAESstr=""
        self.encBodyAESstr=""

        for i in self.encSubjectAES:
            #liste.append(b64encode(i).decode('utf-8'))
            self.encSubjectAESstr+=b64encode(i).decode('utf-8')+"₺"
            
        for j in self.encBodyAES:
            self.encBodyAESstr+=b64encode(j).decode('utf-8')+"₺"

    def SaveMailToDB(self):
        ts = time.time()

        EncRSAaes=RSA.RS.encryptMsg(self.targetAESKey,int(self.targetN),int(self.targetPublicKey))
        EncRSAaes=b64encode(EncRSAaes).decode('utf-8')

        myRSAN=FBConf.db.child("User").child(self.user['localId']).child("RSA").child('n').get(token=self.user['idToken']).val()
        fromSignature=FBConf.db.child("User").child(self.user['localId']).child("RSASignature").get(token=self.user['idToken']).val()
        

        inboxData={"From":str(self.myEmail),"Subject":self.encSubjectAESstr,"Body":str(self.encBodyAESstr),"TimeStamp":str(ts),
            "HashFrom":str(self.hash(self.myEmail)),"HashSubject":str(self.hash(self.encSubjectAESstr)),"HashBody":str(self.hash(self.encBodyAESstr)),
            "HashTimeStamp":str(self.hash(ts)),"EncRSAaes":str(EncRSAaes),"FromPublicN":str(myRSAN),"FromSignature":str(fromSignature),
            "HashEncRSAaes":str(self.hash(EncRSAaes)),"HashFromPublicN":str(self.hash(myRSAN)),"HashFromSignature":str(self.hash(fromSignature))
        }

        outboxData={"To":str(self.targetEmail),"Subject":str(self.encSubjectAESstr),"Body":str(self.encBodyAESstr),"TimeStamp":str(ts),
            "HashTo":str(self.hash(self.targetEmail)),"HashSubject":str(self.hash(self.encSubjectAESstr)),"HashBody":str(self.hash(self.encBodyAESstr)),
            "HashTimeStamp":str(self.hash(ts)),"EncRSAaes":str(EncRSAaes),"FromPublicN":str(myRSAN),"HashEncRSAaes":str(self.hash(EncRSAaes)),
            "HashFromPublicN":str(self.hash(myRSAN))
        }

        self.childKey=FBConf.db.generate_key()

        FBConf.db.child("Inbox").child(self.targetDBKey).child(self.user['localId']).child(self.childKey).set(inboxData)
        FBConf.db.child("Outbox").child(self.user['localId']).child(self.targetDBKey).child(self.childKey).set(outboxData)

    def hash(self,text):
           #filename classname funcname
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
        try:
            mail.login(self.myEmail,myPassword) 
        except:
            self.ui.nameLabel.setText("Your account is not real gmail or password")
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
            self.ui.messageTextEdit.setPlaceholderText("Mailiniz başarılı bir şekilde gönderildi.")
            
        except Exception as e:
            print(e)
            print("Oops!", e.__class__, "occurred.")
        mail.close()  # Smtp serverımızın bağlantısını koparıyoz.

    def PutFiletoDB(self,filename):

        FBConf.storage.child("Outbox").child(self.user['localId']).child(self.targetDBKey).child(self.childKey).child(filename.split("/").pop()).put(self.filename)
        FBConf.storage.child("InBox").child(self.targetDBKey).child(self.user['localId']).child(self.childKey).child(filename.split("/").pop()).put(filename)
    
    def RSADecryptionInbox(self,encRSAaes):  #encRSAaes,   n,publickey,privatekey,privateP,privateQ
        
        RSAInfos=FBConf.db.child("User").child(self.user['localId']).child("RSA").get().val()

        privatekey,privateP,privateQ,publickey,n=RSAInfos.values()    
        
        AesKey=RSA.RS.decryptMsg(b64decode(encRSAaes),int(n),int(publickey),int(privatekey),int(privateP),int(privateQ))

        return AesKey

    def AESDecryptionInbox(self,encText,encText2,encRSAaes):
        AesKey = self.RSADecryptionInbox(encRSAaes)
        newEncText=[]
        for i in encText.split("₺"):
            newEncText.append(b64decode(i))

        a,b,c,_ = newEncText

        newEncText=(a,b,c)

        decSubjectAES = AES.AESCipher.decrypt_AES_GCM(self, newEncText, AesKey)

        newEncText2=[]
        for i in encText2.split("₺"):
            newEncText2.append(b64decode(i))
        a,b,c,_ = newEncText2
        newEncText2=(a,b,c)
        decBodyAES = AES.AESCipher.decrypt_AES_GCM(self, newEncText2, AesKey)
        
        return decSubjectAES, decBodyAES

    def AESDecryptionOutbox(self,encText,encText2,AesKey):
        AesKey=b64decode(AesKey)
        newEncText=[]
        for i in encText.split("₺"):
            newEncText.append(b64decode(i))

        a,b,c,_ = newEncText
        
        newEncText=(a,b,c)

        decSubjectAES = AES.AESCipher.decrypt_AES_GCM(self, newEncText, AesKey)

        newEncText2=[]
        for i in encText2.split("₺"):
            newEncText2.append(b64decode(i))
        a,b,c,_ = newEncText2
        newEncText2=(a,b,c)
        decBodyAES = AES.AESCipher.decrypt_AES_GCM(self, newEncText2, AesKey)
        
        return decSubjectAES, decBodyAES
    
    def DBGetInbox(self):

        myInboxs=FBConf.db.child("Inbox").child(self.user['localId']).get(token=self.user['idToken'])

        n=FBConf.db.child("RootRSA").child("n").get().val() 
        e=FBConf.db.child("RootRSA").child("public").get().val() 
               
        myVerifyer=Signature.Verifyer(n,e)

        try:
            for myInbox in myInboxs.each():
                inboxDict = myInbox.val()
                for i in inboxDict.values():

                    if myVerifyer.Verify(b64decode(i['FromSignature']),i["From"]) \
                    and self.hash(i['FromSignature']) == i['HashFromSignature'] and i["HashEncRSAaes"] == self.hash(i["EncRSAaes"]) \
                    and self.hash(i["Body"]) == i["HashBody"] and self.hash(i["Subject"]) == i["HashSubject"]:
                        
                        decSubjectAES, decBodyAES= self.AESDecryptionInbox(i["Subject"],i["Body"],i["EncRSAaes"])
                        i["Subject"] = str(decSubjectAES)  
                        i["Body"] = str(decBodyAES)

                        self.inboxMails.append(
                            InboxObject(
                                uuid.uuid1(),
                                i["From"],
                                i["Subject"],
                                i["Body"],
                                i["TimeStamp"]
                            )
                        )
                    
            self.inboxLoadView()
        except Exception as e:
            print(e,"inbox")
            print("Oops!", e.__class__, "occurred.")

    def DBGetOutbox(self):
        myOutboxs=FBConf.db.child("Outbox").child(self.user['localId']).get(token=self.user['idToken'])
        
        n=FBConf.db.child("RootRSA").child("n").get().val() 
        e=FBConf.db.child("RootRSA").child("public").get().val() 
               
        myVerifyer=Signature.Verifyer(n,e)

        try:
            for myOutbox in myOutboxs.each():
                outboxDict = myOutbox.val()
                outBoxChildKey = myOutbox.key()
                AesKey=myOutboxs=FBConf.db.child("AES").child(self.user['localId']).child(outBoxChildKey).get(token=self.user['idToken']).val()
                
                for i in outboxDict.values():

                    if self.hash(i['To']) == i['HashTo'] \
                    and i["HashEncRSAaes"] == self.hash(i["EncRSAaes"]) \
                    and self.hash(i["Body"]) == i["HashBody"] and self.hash(i["Subject"]) == i["HashSubject"]:

                        decSubjectAES, decBodyAES= self.AESDecryptionOutbox(i["Subject"],i["Body"],AesKey)
                        i["Subject"] = str(decSubjectAES)
                        i["Body"] = str(decBodyAES)
                        self.outboxMails.append(
                            OutboxObject(
                                uuid.uuid1(),
                                i["To"],
                                i["Subject"],
                                i["Body"],
                                i["TimeStamp"]
                            )
                        )
                    
            self.outboxLoadView()

        except Exception as e:
            print(e)
            print("Oops!", e.__class__, "occurred.")

    def inboxLoadView(self):
        self.ui.inboxTableView.setRowCount(len(self.inboxMails))
        self.ui.inboxTableView.setColumnCount(4)
        self.ui.inboxTableView.setGridStyle(Qt.NoPen)
        self.ui.inboxTableView.setHorizontalHeaderLabels(("From","Subject","Body","Timestamp"))
        self.ui.inboxTableView.setColumnWidth(0,100)
        self.ui.inboxTableView.setColumnWidth(1,300)

        rowIndex = 0
        for mail in self.inboxMails:
            self.ui.inboxTableView.setItem(rowIndex,0,QTableWidgetItem(mail.From))
            self.ui.inboxTableView.setItem(rowIndex,1,QTableWidgetItem(mail.subject))
            self.ui.inboxTableView.setItem(rowIndex,2,QTableWidgetItem(mail.body))
            self.ui.inboxTableView.setItem(rowIndex,3,QTableWidgetItem(mail.timeStamp))
            rowIndex+=1

    def outboxLoadView(self):
        
        self.ui.outboxTableView.setRowCount(len(self.outboxMails))
        self.ui.outboxTableView.setColumnCount(4)
        self.ui.outboxTableView.setGridStyle(Qt.NoPen)
        self.ui.outboxTableView.setHorizontalHeaderLabels(("To","Subject","Body","Timestamp"))
        self.ui.outboxTableView.setColumnWidth(0,100)
        self.ui.outboxTableView.setColumnWidth(1,300)

        rowIndex = 0
        for mail in self.outboxMails:
            self.ui.outboxTableView.setItem(rowIndex,0,QTableWidgetItem(mail.to))
            self.ui.outboxTableView.setItem(rowIndex,1,QTableWidgetItem(mail.subject))
            self.ui.outboxTableView.setItem(rowIndex,2,QTableWidgetItem(mail.body))
            self.ui.outboxTableView.setItem(rowIndex,3,QTableWidgetItem(mail.timeStamp))
            rowIndex+=1

#if __name__ == "__main__":
    # app = QtWidgets.QApplication(sys.argv)
    # win = HomeStarter()
    # win.show()
    # sys.exit(app.exec_())
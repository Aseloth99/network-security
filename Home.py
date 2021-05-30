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

import mspDenemeAesFileEnc
import FBConf
import AES, SHA256, RSA

#os.system("pyuic5 -x arayüz.ui -o uiHome.py")
from uiHome import Ui_Home  #import interface

class OutboxObject: 
    def __init__(self, myId, to, subject, body, timeStamp, hashSubject, hashBody, hashTimeStamp, encRSAaes, 
    fromPublicN, fromSignature, hashEncRSAaes, hashFromPublicN, hashFromSignature ): 

        self.id = myId 
        self.to = to 
        self.subject = subject 
        self.body = body 
        self.timeStamp = timeStamp
        self.hashSubject = hashSubject
        self.hashBody = hashBody
        self.hashTimeStamp = hashTimeStamp
        self.encRSAaes = encRSAaes
        self.fromPublicN = fromPublicN
        self.fromSignature = fromSignature
        self.hashEncRSAaes = hashEncRSAaes
        self.hashFromPublicN = hashFromPublicN
        self.hashFromSignature = hashFromSignature

class InboxObject: 
    def __init__(self, myId, From, subject, body, timeStamp, hashSubject, hashBody, hashTimeStamp, encRSAaes, 
    fromPublicN, fromSignature, hashEncRSAaes, hashFromPublicN, hashFromSignature ): 

        self.id = myId
        self.From = From 
        self.subject = subject 
        self.body = body 
        self.timeStamp = timeStamp
        self.hashSubject = hashSubject
        self.hashBody = hashBody
        self.hashTimeStamp = hashTimeStamp
        self.encRSAaes = encRSAaes
        self.fromPublicN = fromPublicN
        self.fromSignature = fromSignature
        self.hashEncRSAaes = hashEncRSAaes
        self.hashFromPublicN = hashFromPublicN
        self.hashFromSignature = hashFromSignature

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
        self.inboxMails=[]
        self.outboxMails=[]
        
        self.DBGetInbox()
        self.DBGetOutbox()
     #self.showMaximized()
        #self.threading()
        #self.themes=["windowsvista","Windows","Fusion","Koyu","Açık"]
        
    #Gönderme Başlangıç

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
            
            self.SaveMailToDB()

            self.GoSendMail()

            #self.GetPassword()

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
        print(self.encSubjectAES,self.encBodyAES)
        print(len(self.encSubjectAES[0]))
        print(len(self.encSubjectAES[1]))
        print(len(self.encSubjectAES[2]))
        print(len(self.encBodyAES[0]))
        print(len(self.encBodyAES[1]))
        print(len(self.encBodyAES[2]))
        #print("self.encSubjectAES",self.encSubjectAES[0])
        #print(type(self.encSubjectAES[0]))
        #print(len(self.encSubjectAES[0]))
        #liste=[]
        self.encSubjectAESstr=""
        self.encBodyAESstr=""

        for i in self.encSubjectAES:
            #liste.append(b64encode(i).decode('utf-8'))
            self.encSubjectAESstr+=b64encode(i).decode('utf-8')+"₺"
            
        for j in self.encBodyAES:
            self.encBodyAESstr+=b64encode(j).decode('utf-8')+"₺"

        #print(liste)
        print(self.encSubjectAESstr)
        print(self.encBodyAESstr)
        #print(type(liste[0]))

        # for c,i in enumerate(liste):
        #     liste[c]=b64decode(i)
        # print("decode",liste)
        # print(liste[0])
        # print(type(liste[0]))
        # print(len(liste[0]))

    def SaveMailToDB(self):
        ts = time.time()
        print(self.targetAESKey)
        EncRSAaes=RSA.RS.encryptMsg(self.targetAESKey,int(self.targetN),int(self.targetPublicKey))
        EncRSAaes=b64encode(EncRSAaes).decode('utf-8')

        myRSAN=FBConf.db.child("User").child(self.user['localId']).child("RSA").child('n').get(token=self.user['idToken']).val()
        fromSignature=FBConf.db.child("User").child(self.user['localId']).child("RSASignature").get(token=self.user['idToken']).val()

        inboxData={"From":str(self.myEmail),"Subject":self.encSubjectAESstr,"Body":str(self.encBodyAESstr),"TimeStamp":str(ts),
            "HashFrom":str(self.hash(self.myEmail)),"HashSubject":str(self.hash(self.encSubjectAES)),"HashBody":str(self.hash(self.encBodyAES)),
            "HashTimeStamp":str(self.hash(ts)),"EncRSAaes":str(EncRSAaes),"FromPublicN":str(myRSAN),"FromSignature":str(fromSignature),
            "HashEncRSAaes":str(self.hash(EncRSAaes)),"HashFromPublicN":str(self.hash(myRSAN)),"HashFromSignature":str(self.hash(fromSignature))
        }

        outboxData={"To":str(self.targetEmail),"Subject":str(self.encSubjectAES),"Body":str(self.encBodyAES),"TimeStamp":str(ts),
            "HashTo":str(self.hash(self.targetEmail)),"HashSubject":str(self.hash(self.encSubjectAES)),"HashBody":str(self.hash(self.encBodyAES)),
            "HashTimeStamp":str(self.hash(ts)),"EncRSAaes":str(EncRSAaes),"FromPublicN":str(myRSAN),"HashEncRSAaes":str(self.hash(EncRSAaes)),
            "HashFromPublicN":str(self.hash(myRSAN)),"FromSignature":str(fromSignature),"HashFromSignature":str(self.hash(fromSignature))
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
            self.ui.messageTextEdit.setPlaceholderText("Mailiniz başarılı bir şekilde gönderildi.")
            
        except Exception as e:
            print(e)
            print("Oops!", e.__class__, "occurred.")
        mail.close()  # Smtp serverımızın bağlantısını koparıyoz.

    def PutFiletoDB(self,filename):

        FBConf.storage.child("Outbox").child(self.user['localId']).child(self.targetDBKey).child(self.childKey).child(filename.split("/").pop()).put(self.filename)
        FBConf.storage.child("InBox").child(self.targetDBKey).child(self.user['localId']).child(self.childKey).child(filename.split("/").pop()).put(filename)

    def GetPassword():
        pass

    #Gönderme Son
    
    def RSADecryption(self,encRSAaes):  #encRSAaes,   n,publickey,privatekey,privateP,privateQ
        
        RSAInfos=FBConf.db.child("User").child(self.user['localId']).child("RSA").get().val()
        
        privatekey,privateP,privateQ,publickey,n=RSAInfos.values()    
        print(encRSAaes)   
        AesKey=RSA.RS.decryptMsg(b64decode(encRSAaes),int(n),int(publickey),int(privatekey),int(privateP),int(privateQ))

        print("RSADecryption3")
        print("AESKEY",AesKey)
        return AesKey

    def AESDecryption(self,encText,encText2,encRSAaes):
        AesKey = self.RSADecryption(encRSAaes)
        print(encText, encText2)
        newEncText=[]
        for i in encText.split("₺"):
            
            print(i)
            newEncText.append(b64decode(i))

        a,b,c,_ = newEncText
        
        print("A: ",a)
        print(type(a))
        print(len(a))
        print("B: ",b)
        print(type(b))
        print(len(b))
        print("C: ",c)
        print(type(c))
        print(len(c))

        newEncText=(a,b,c)

        print("newEncText   ",newEncText)
        print("targetAESKey     ",AesKey)

        decSubjectAES = AES.AESCipher.decrypt_AES_GCM(self, newEncText, AesKey)

        print("AESDecryption1")

        newEncText2=[]
        for i in encText2.split("₺"):
            newEncText2.append(b64decode(i))
        a,b,c,_ = newEncText2
        newEncText2=(a,b,c)
        decBodyAES = AES.AESCipher.decrypt_AES_GCM(self, newEncText2, AesKey)
        
        print(decSubjectAES, decBodyAES)
        return decSubjectAES, decBodyAES
    
    def DBGetInbox(self):

        myInboxs=FBConf.db.child("Inbox").child(self.user['localId']).get(token=self.user['idToken'])
        id=0
        try:
            for myInbox in myInboxs.each():
                targetAESKey=FBConf.db.child("AES").child(self.user['localId']).child(myInbox.key()).get().val()
                
                inboxDict = myInbox.val()
                
                for i in inboxDict.values():
                    print(targetAESKey)
                    decSubjectAES, decBodyAES= self.AESDecryption(i["Subject"],i["Body"],i["EncRSAaes"])
                    i["Subject"] = str(decSubjectAES)
                    i["Body"] = str(decBodyAES)
                    self.inboxMails.append(
                        InboxObject(
                            id,
                            i["From"],
                            i["Subject"],
                            i["Body"],
                            i["TimeStamp"],
                            i["HashSubject"],
                            i["HashBody"],
                            i["HashTimeStamp"],
                            i["EncRSAaes"],
                            i["FromPublicN"],
                            i["FromSignature"],
                            i["HashEncRSAaes"],
                            i["HashFromPublicN"],
                            i["HashFromSignature"]
                        )
                    )
                    id+=1
            print("DBGetInbox3")
            self.inboxLoadView()

        except Exception as e:
            print(e,"inbox")
            print("Oops!", e.__class__, "occurred.")

    def DBGetOutbox(self):

        myOutboxs=FBConf.db.child("Outbox").child(self.user['localId']).get(token=self.user['idToken'])
        id=0
        try:
            for myOutbox in myOutboxs.each():
                
                outboxDict = myOutbox.val()
                
                for i in outboxDict.values():
                    EncRSAaes=i["EncRSAaes"]
                    
                    #decSubjectAES, decBodyAES= self.AESDecryption(i["Subject"],i["Body"],i["EncRSAaes"])
                    #i["Subject"] = str(decSubjectAES)
                    #i["Body"] = str(decBodyAES)
                    self.outboxMails.append(
                        OutboxObject(
                            id,
                            i["To"],
                            i["Subject"],
                            i["Body"],
                            i["TimeStamp"],
                            i["HashSubject"],
                            i["HashBody"],
                            i["HashTimeStamp"],
                            i["EncRSAaes"],
                            i["FromPublicN"],
                            i["FromSignature"],
                            i["HashEncRSAaes"],
                            i["HashFromPublicN"],
                            i["HashFromSignature"]
                        )
                    )
                    id+=1
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
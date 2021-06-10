from uiHome import Ui_Home  # import interface
from PyQt5 import QtWidgets
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QFileDialog, QTableWidgetItem, QMenu, QMessageBox, qApp, QAction, QSystemTrayIcon
from PyQt5.QtCore import Qt
import os
import time
import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from validate_email import validate_email
from base64 import b64encode, b64decode
import uuid
import Signature
import qdarkstyle
import AesFileEnc
import FBConf
import AES
import SHA256
import RSA
import Cryptology

os.system("pyuic5 -x arayüz.ui -o uiHome.py")

class OutboxObject:  # Burada Outbox maillerin obje yapısı oluşturulmuştur.
    def __init__(self, myId, to, subject, body, timeStamp):

        self.id = myId
        self.to = to
        self.subject = subject
        self.body = body
        self.timeStamp = timeStamp

class InboxObject:  # Burada Inbbox maillerin obje yapısı oluşturulmuştur.
    def __init__(self, myId, From, subject, body, timeStamp):

        self.id = myId
        self.From = From
        self.subject = subject
        self.body = body
        self.timeStamp = timeStamp

class MyLocalRings:
    def __init__(self, EncPrivateKey, EncPrivateP, EncPrivateQ, EncN, EncPublicKey, EncTimeStamp, cryptoKey):

        self.privateKey = Cryptology.Decrypt(EncPrivateKey, cryptoKey)
        self.privateP = Cryptology.Decrypt(EncPrivateP, cryptoKey)
        self.privateQ = Cryptology.Decrypt(EncPrivateQ, cryptoKey)
        self.n = Cryptology.Decrypt(EncN, cryptoKey)
        self.publicKey = Cryptology.Decrypt(EncPublicKey, cryptoKey)
        self.timeStamp = Cryptology.Decrypt(EncTimeStamp, cryptoKey)

        #AES'İ KARŞI RSA İLE ŞİFRELİCEM
        #AES'İ KENDİ RSA İLE ŞİFRELİCEM

class HomeStarter(QtWidgets.QMainWindow):
    def __init__(self, ui, window, myEmail, cryptoKey):
        super(HomeStarter, self).__init__()
        qApp.setStyleSheet(qdarkstyle.load_stylesheet(qt_api='pyqt5'))
        print("HomeStarter cryptoKey'i  ",cryptoKey)
        
        self.cryptoKey = cryptoKey
        self.ui = ui
        self.window = window
        self.ui.menubar.triggered.connect(self.menuResponse)
        self.GetUserName()
        self.ui.sendButton.clicked.connect(lambda: self.SendMail())
        self.ui.pushButton.clicked.connect(lambda: self.__openFileNamesDialog())

        self.targetN = ""
        self.myEmail = myEmail
        self.filename = ""
        self.inboxMails = []
        self.outboxMails = []
        self.keys = []
        self.ui.reloadOutbox.clicked.connect(lambda: self.updateView())
        self.ui.reloadInbox.clicked.connect(lambda: self.updateView())

        try:
            fileKeys = open("Keys.txt", "r", encoding="UTF-16")
            swiftLine=fileKeys.readline().rstrip("\n")
            
            while swiftLine!="":
                
                self.keys.append(
                    MyLocalRings(
                        str(swiftLine),
                        str(fileKeys.readline().rstrip("\n")),
                        str(fileKeys.readline().rstrip("\n")),
                        str(fileKeys.readline().rstrip("\n")),
                        str(fileKeys.readline().rstrip("\n")),
                        str(fileKeys.readline().rstrip("\n")),
                        self.cryptoKey
                    )
                )
                fileKeys.readline()
                swiftLine=fileKeys.readline().rstrip("\n")
                
            fileKeys.close()
        except:
            pass

        self.DBGetInbox()
        self.DBGetOutbox()

        #self.themes = ["windowsvista","Windows","Fusion","Koyu","Açık"]

    # Gönderme Başlangıç

    def updateView(self):  # Gelen ve Giden Kutularındaki Mailler Kullanıcıya Gösteriliyor
        self.inboxMails = []
        self.outboxMails = []
        self.ui.outboxTableView.clear()
        self.ui.inboxTableView.clear()
        self.DBGetInbox()
        self.DBGetOutbox()
        self.outboxLoadView()
        self.inboxLoadView()

    def GetUserName(self):  # Kullanıcı Username'i Getirilip Ekranda Gösteriliyor
        self.user = FBConf.auth.current_user
        self.ui.nameLabel.setText("Welcome "+str(FBConf.db.child("User").child(
            self.user['localId']).child('Username').get(token=self.user['idToken']).val()))

    def SendMail(self):  # Mail gönderme butonuna basınca gerçekleşecek eylmeler
        if validate_email(self.ui.toLineEdit.text()):
            try:
                self.GetTargetPublicKey()
                self.GetMyPublicKey()
            except:
                pass
            self.CreateAES()

            self.AESKey = b64decode(self.AESKey)

            self.AESEncryption()

            self.RSAEncryptionAes()

            #self.ControlReplayAttack() #Burada Daha önce Çekmiş olduğumuz Outboxlar arasında targetEmaili eşleşenlerin Timestampinden Replay Atağı Tespit Edeceğiz
            
            self.GoSendMail()

    def RSAEncryptionAes(self):
        EncRSAAes4Target = RSA.RS.encryptMsg(self.AESKey, int(self.targetN), int(self.targetPublicKey))
        self.EncRSAAes4Target = b64encode(EncRSAAes4Target).decode('utf-8')

        EncRSAAes4From = RSA.RS.encryptMsg(self.AESKey, int(self.actualMyN), int(self.actualMyPublicKey))
        self.EncRSAAes4From = b64encode(EncRSAAes4From).decode('utf-8')

    def ControlReplayAttack(self):  # Replay Attack Engelleniyor

        currentTime = time.time()
        targetInboxes = FBConf.db.child("Inbox").child(
            self.targetDBKey).child(self.user['localId']).get()

        dbTimeStamp = 0

        try:
            for i in targetInboxes.each():
                i = i.val()

                if float(i["TimeStamp"]) > dbTimeStamp and i["HashTimeStamp"] == self.hash(i["TimeStamp"]):
                    dbTimeStamp = float(i["TimeStamp"])

            # aynı kişiden son 5 saniyeden gelen maili iptal ediyoruz
            if currentTime < (dbTimeStamp + 5):
                self.ui.toLineEdit.setText("Now Reply Attack")
                self.ui.lineEdit.setText("Now Reply Attack")
            else:
                self.GoSendMail()

        except:  # Daha önce hiç mail gelmemiştir.
            self.GoSendMail()

    def GetTargetPublicKey(self):  # Hedef Adresin RSA Public Keyi Alınıyor
        users = FBConf.db.child("User").get()

        for user in users.each():

            if user.val()["Gmail"] == self.ui.toLineEdit.text():
                self.targetDBKey = user.key()

                targetRings=FBConf.db.child("Rings").child(self.targetDBKey).get()
                
                self.targetRingTS=0
                for targetRing in targetRings.each():
                    if float(targetRing.val()["Timestamp"]) > self.targetRingTS:
                        
                        self.targetRingTS=targetRing.val()["Timestamp"]

                        self.targetPublicKey = targetRing.val()["PublicKey"]
                        self.targetTimeStamp=self.targetRingTS
                        self.targetN=targetRing.val()["n"]

                # Şu anda en güncel timestamp'in ringsi var
                self.targetEmail = self.ui.toLineEdit.text()
                break

    def GetMyPublicKey(self): 
        controlTS=0

        for key in self.keys:
            if (float(key.timeStamp) > controlTS):
                controlTS=key.timeStamp
                self.actualMyPublicKey=key.publicKey
                self.actualMyN=key.n
                

    def CreateAES(self):  # Aes Oluşturuluyor ve DB'ye kaydediliyor.
        original = os.urandom(32)
        self.AESKey = b64encode(original).decode('utf-8')

    def __openFileNamesDialog(self):  # Dosya Seçtiriliyor
        dlg = QFileDialog()
        dlg.setFileMode(QFileDialog.ExistingFiles)
        if dlg.exec_():
            self.InputFiles = dlg.selectedFiles()
            tmp = ""
            for i in self.InputFiles:
                tmp += os.path.basename(i)
                tmp += "; "
            self.ui.lineEdit.setText(tmp)
            self.filename = self.InputFiles[0]

    def AESEncryption(self):  # Metinler Aes anahtarla şifreleniyor
        subject = self.ui.subjectLineEdit.text()
        body = self.ui.messageTextEdit.toPlainText()
        self.ts= time.time()

        #(ciphertext, nonce, authTag)
        self.encSubjectAES = AES.AESCipher.encrypt_AES_GCM(
            self, subject, self.AESKey)
        self.encBodyAES = AES.AESCipher.encrypt_AES_GCM(
            self, body, self.AESKey)
        self.encTs=AES.AESCipher.encrypt_AES_GCM(
            self,str(self.ts),self.AESKey)

        self.encTargetEmail=AES.AESCipher.encrypt_AES_GCM(
            self,self.targetEmail,self.AESKey)

        self.encFromEmail=AES.AESCipher.encrypt_AES_GCM(
            self,self.myEmail,self.AESKey)

        self.encSubjectAESstr = ""
        self.encBodyAESstr = ""
        self.encTsStr=""
        self.encTargetEmailStr=""
        self.encFromEmailStr=""

        for j in self.encSubjectAES:
            self.encSubjectAESstr += b64encode(j).decode('utf-8')

        for j in self.encBodyAES:
            self.encBodyAESstr += b64encode(j).decode('utf-8')

        for j in self.encTs:
            self.encTsStr += b64encode(j).decode('utf-8')

        for j in self.encTargetEmail:
            self.encTargetEmailStr += b64encode(j).decode('utf-8')

        for j in self.encFromEmail:
            self.encFromEmailStr += b64encode(j).decode('utf-8')
            

    def SaveMailToDB(self):  # Mailler gerekli yerlere kaydediliyor (Inbox ve Outbox)
        ts = time.time()

        EncRSAaes = RSA.RS.encryptMsg(self.AESKey, int(
            self.targetN), int(self.targetPublicKey))
        EncRSAaes = b64encode(EncRSAaes).decode('utf-8')

        myRSAN = FBConf.db.child("User").child(self.user['localId']).child(
            "RSA").child('n').get(token=self.user['idToken']).val()
        fromSignature = FBConf.db.child("User").child(self.user['localId']).child(
            "RSASignature").get(token=self.user['idToken']).val()

        self.childKey = FBConf.db.generate_key()

        inboxData = {"From": str(self.myEmail), "Subject": self.encSubjectAESstr, "Body": str(self.encBodyAESstr), "TimeStamp": str(ts),
                     "HashFrom": str(self.hash(self.myEmail)), "HashSubject": str(self.hash(self.encSubjectAESstr)), "HashBody": str(self.hash(self.encBodyAESstr)),
                     "HashTimeStamp": str(self.hash(ts)), "EncRSAaes": str(EncRSAaes), "FromPublicN": str(myRSAN), "FromSignature": str(fromSignature),
                     "HashEncRSAaes": str(self.hash(EncRSAaes)), "HashFromPublicN": str(self.hash(myRSAN)), "HashFromSignature": str(self.hash(fromSignature)),
                     "childKey": self.childKey
                     }

        outboxData = {"To": str(self.targetEmail), "Subject": str(self.encSubjectAESstr), "Body": str(self.encBodyAESstr), "TimeStamp": str(ts),
                      "HashTo": str(self.hash(self.targetEmail)), "HashSubject": str(self.hash(self.encSubjectAESstr)), "HashBody": str(self.hash(self.encBodyAESstr)),
                      "HashTimeStamp": str(self.hash(ts)), "EncRSAaes": str(EncRSAaes), "FromPublicN": str(myRSAN), "HashEncRSAaes": str(self.hash(EncRSAaes)),
                      "HashFromPublicN": str(self.hash(myRSAN)), "childKey": self.childKey
                      }

        FBConf.db.child("Inbox").child(self.targetDBKey).child(
            self.user['localId']).child(self.childKey).set(inboxData)
        FBConf.db.child("Outbox").child(self.user['localId']).child(
            self.targetDBKey).child(self.childKey).set(outboxData)

    def hash(self, text):  # Metinlerin Hash'i alınıyor
        return SHA256.SHA256().encrypter(str(text))

    def GoSendMail(self):  # Kontroller Sonunda Gönderilmesine karar verilen maillerin Gmaille gönderilmesi sağlanıyor
        myPassword = "KlavyeFL0."

        msg = MIMEMultipart()
        msg["From"] = self.myEmail
        msg["To"] = self.targetEmail
        msg["Subject"] = str(self.encSubjectAESstr)

        # SMTP objemizi oluşturuyoruz ve gmail smtp server'ına bağlanıyoruz.
        mail = smtplib.SMTP("smtp.gmail.com", 587)
        mail.starttls()  # Adresimizin ve Parolamızın şifrelenmesi için gerekli
        mail.ehlo()  # SMTP serverına kendimizi tanıtıyoruz.
        try:
            mail.login(self.myEmail, myPassword)
        except:
            self.ui.nameLabel.setText("Your account is not real gmail or password")

        body = str(self.EncRSAAes4From+"₺"+self.EncRSAAes4Target+"₺"+self.encBodyAESstr+"₺"
        +self.encFromEmailStr+"₺"+encTargetEmailStr+"₺"+self.encTsStr+"₺"+str(self.ts))

        # Mailimizin gövdesini bu sınıftan oluşturuyoruz.
        msg_govdesi = MIMEText(body, "plain")
        # Mailimizin gövdesini mail yapımıza ekliyoruz.
        msg.attach(msg_govdesi)

        if(self.filename == ""):
            pass
        else:
            filename = AesFileEnc.AESFile.fileEnc(
                self.AESKey, self.filename)

            self.PutFiletoDB(filename)

            attach_file = open(filename, 'rb')  # Open the file as binary mode
            payload = MIMEBase('application', 'octate-stream')
            payload.set_payload(attach_file.read())
            encoders.encode_base64(payload)  # encode the attachment
            # add payload header with filename
            payload.add_header('Content-Disposition',
                               'attachment', filename=filename)
            msg.attach(payload)

        try:
            # Mailimizi gönderiyoruz.
            mail.sendmail(msg["From"], msg["To"], msg.as_string())
            # self.ui.toLineEdit.clear()

            self.ui.subjectLineEdit.clear()
            self.ui.messageTextEdit.clear()
            self.ui.messageTextEdit.setPlaceholderText(
                "Mailiniz başarılı bir şekilde gönderildi.")

        except Exception as e:
            print(e)
            print("Oops!", e.__class__, "occurred.")
        mail.close()  # Smtp serverımızın bağlantısını koparıyoz.

    def PutFiletoDB(self, filename):  # Şifrelenmiş Dosya DB'ye kaydediliyor

        FBConf.storage.child("Outbox").child(self.user['localId']).child(
            self.targetDBKey).child(self.childKey).child(filename.split("/").pop()).put(filename)
        FBConf.storage.child("InBox").child(self.targetDBKey).child(self.user['localId']).child(
            self.childKey).child(filename.split("/").pop()).put(filename)

    # Inbox kutusu için Şifrelenmiş Aes anahtarları çözülüyor
    def RSADecryptionInbox(self, encRSAaes):

        RSAInfos = FBConf.db.child("User").child(
            self.user['localId']).child("RSA").get().val()

        privatekey, privateP, privateQ, publickey, n = RSAInfos.values()

        AesKey = RSA.RS.decryptMsg(b64decode(encRSAaes), int(n), int(
            publickey), int(privatekey), int(privateP), int(privateQ))

        return AesKey

    # Inbox kutusu için Elde edilen Aes şifresiyle metinler çözülüyor
    def AESDecryptionInbox(self, encText, encText2, encRSAaes):
        AesKey = self.RSADecryptionInbox(encRSAaes)
        newEncText = []
        for i in encText.split("₺"):
            newEncText.append(b64decode(i))

        a, b, c, _ = newEncText

        newEncText = (a, b, c)

        decSubjectAES = AES.AESCipher.decrypt_AES_GCM(self, newEncText, AesKey)

        newEncText2 = []
        for i in encText2.split("₺"):
            newEncText2.append(b64decode(i))
        a, b, c, _ = newEncText2
        newEncText2 = (a, b, c)
        decBodyAES = AES.AESCipher.decrypt_AES_GCM(self, newEncText2, AesKey)

        return decSubjectAES, decBodyAES

    # Outbox kutusu için Elde edilen Aes şifresiyle metinler çözülüyor
    def AESDecryptionOutbox(self, encText, encText2, AesKey):
        AesKey = b64decode(AesKey)
        newEncText = []
        for i in encText.split("₺"):
            newEncText.append(b64decode(i))

        a, b, c, _ = newEncText

        newEncText = (a, b, c)

        decSubjectAES = AES.AESCipher.decrypt_AES_GCM(self, newEncText, AesKey)

        newEncText2 = []
        for i in encText2.split("₺"):
            newEncText2.append(b64decode(i))
        a, b, c, _ = newEncText2
        newEncText2 = (a, b, c)
        decBodyAES = AES.AESCipher.decrypt_AES_GCM(self, newEncText2, AesKey)

        return decSubjectAES, decBodyAES

    def DBGetInbox(self):  # Database'den Inbox kutusundaki mailler getiriliyor

        myInboxs = FBConf.db.child("Inbox").child(
            self.user['localId']).get(token=self.user['idToken'])

        n = FBConf.db.child("RootRSA").child("n").get().val()
        e = FBConf.db.child("RootRSA").child("public").get().val()

        myVerifyer = Signature.Verifyer(n, e)

        try:
            for myInbox in myInboxs.each():
                inboxDict = myInbox.val()
                senderChildKey = myInbox.key()
                for i in inboxDict.values():

                    if myVerifyer.Verify(b64decode(i['FromSignature']), i["From"]) \
                            and self.hash(i['FromSignature']) == i['HashFromSignature'] and i["HashEncRSAaes"] == self.hash(i["EncRSAaes"]) \
                            and self.hash(i["Body"]) == i["HashBody"] and self.hash(i["Subject"]) == i["HashSubject"]:

                        decSubjectAES, decBodyAES = self.AESDecryptionInbox(
                            i["Subject"], i["Body"], i["EncRSAaes"])
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
            print(e, "inbox")

    def DBGetOutbox(self):  # Database'den Outbox kutusundaki mailler getiriliyor
        myOutboxs = FBConf.db.child("Outbox").child(
            self.user['localId']).get(token=self.user['idToken'])

        n = FBConf.db.child("RootRSA").child("n").get().val()
        e = FBConf.db.child("RootRSA").child("public").get().val()

        myVerifyer = Signature.Verifyer(n, e)

        try:
            for myOutbox in myOutboxs.each():
                outboxDict = myOutbox.val()
                outBoxChildKey = myOutbox.key()
                AesKey = myOutboxs = FBConf.db.child("AES").child(self.user['localId']).child(
                    outBoxChildKey).get(token=self.user['idToken']).val()

                for i in outboxDict.values():

                    if self.hash(i['To']) == i['HashTo'] \
                            and i["HashEncRSAaes"] == self.hash(i["EncRSAaes"]) \
                            and self.hash(i["Body"]) == i["HashBody"] and self.hash(i["Subject"]) == i["HashSubject"]:

                        decSubjectAES, decBodyAES = self.AESDecryptionOutbox(
                            i["Subject"], i["Body"], AesKey)
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
            print(e,"outbox")

    def inboxLoadView(self):  # Inbox kutusu için Veriler Gösteriliyor
        self.ui.inboxTableView.setRowCount(len(self.inboxMails))
        self.ui.inboxTableView.setColumnCount(4)
        self.ui.inboxTableView.setGridStyle(Qt.NoPen)
        self.ui.inboxTableView.setHorizontalHeaderLabels(
            ("From", "Subject", "Body", "Timestamp"))
        self.ui.inboxTableView.setColumnWidth(0, 100)
        self.ui.inboxTableView.setColumnWidth(1, 300)

        rowIndex = 0
        for mail in self.inboxMails:
            self.ui.inboxTableView.setItem(
                rowIndex, 0, QTableWidgetItem(mail.From))
            self.ui.inboxTableView.setItem(
                rowIndex, 1, QTableWidgetItem(mail.subject))
            self.ui.inboxTableView.setItem(
                rowIndex, 2, QTableWidgetItem(mail.body))
            self.ui.inboxTableView.setItem(
                rowIndex, 3, QTableWidgetItem(mail.timeStamp))
            rowIndex += 1

    def outboxLoadView(self):  # Outbox kutusu için Veriler Gösteriliyor

        self.ui.outboxTableView.setRowCount(len(self.outboxMails))
        self.ui.outboxTableView.setColumnCount(4)
        self.ui.outboxTableView.setGridStyle(Qt.NoPen)
        self.ui.outboxTableView.setHorizontalHeaderLabels(
            ("To", "Subject", "Body", "Timestamp"))
        self.ui.outboxTableView.setColumnWidth(0, 100)
        self.ui.outboxTableView.setColumnWidth(1, 300)

        rowIndex = 0
        for mail in self.outboxMails:
            self.ui.outboxTableView.setItem(
                rowIndex, 0, QTableWidgetItem(mail.to))
            self.ui.outboxTableView.setItem(
                rowIndex, 1, QTableWidgetItem(mail.subject))
            self.ui.outboxTableView.setItem(
                rowIndex, 2, QTableWidgetItem(mail.body))
            self.ui.outboxTableView.setItem(
                rowIndex, 3, QTableWidgetItem(mail.timeStamp))
            rowIndex += 1

    def about(self):  # Hakkımızda
        MESSAGE = '<p>Mustafa Sungur POLATER,Mustafa AÇIK<p>'\
            f'<p>{time.localtime()[0]}<p>'\
            '<p>mustafaacik92@hotmail.com<p>'\
            '<p>polaterms@gmail.com<p>'\
            '<p><a href="https://github.com/Aseloth99/network-security">Github</a><p>'\
            'Secure Mail'
        reply = QMessageBox.information(self, "Hakkımızda", MESSAGE)
        if reply == QMessageBox.Ok:
            pass

    def closeEvent(self, event):  # Kapatma Eylemi
        if self.ui.Minimize_edilebilir.isChecked():
            event.ignore()
            self.hide()
        else:
            event.accept()

    def menuResponse(self, action):  # Menu
        if action.text() == "Vista":
            qApp.setStyle("windowsvista")
        elif action.text() == "Windows":
            qApp.setStyle("Windows")
        elif action.text() == "Füzyon":
            qApp.setStyle("Fusion")
        elif action.text() == "Koyu":
            qApp.setStyleSheet(qdarkstyle.load_stylesheet(qt_api='pyqt5'))
        elif action.text() == "Açık":
            qApp.setStyleSheet(qdarkstyle.load_stylesheet(
                qt_api='pyqt5', palette='light'))
            # qp = QPalette()
            # qp.setColor(QPalette.Window, Qt.white)
            # qp.setColor(QPalette.Button, Qt.white)
            # app.setPalette(qp)
        elif action.text() == "Minimize edilebilir":
            import sqlite3
            con = sqlite3.connect("Key.db")  # Tabloya bağlanıyoruz.
            cursor = con.cursor()
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS ayarlar (minimize bool)")
            con.commit()  # execute sorgusunun çalışması için
            cursor.execute(f"Insert into ayarlar Values(False)")
            con.commit()
            cursor.execute(
                f"Update ayarlar set minimize={self.ui.Minimize_edilebilir.isChecked()} where minimize={not self.ui.Minimize_edilebilir.isChecked()}")
            con.commit()
        elif action.text() == "Hakkımda":
            self.about()
        elif action.text() == "Exit":
            qApp.quit()

# if __name__ == "__main__":
    # app = QtWidgets.QApplication(sys.argv)
    # win = HomeStarter()
    # win.show()
    # sys.exit(app.exec_())

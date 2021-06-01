from PyQt5 import QtCore, QtGui, QtWidgets
#from PyQt5.QtWidgets import QMessageBox
import FBConf
import Home,sys

class Ui_Login(object):
    def setupUi(self,Login):
        Login.setObjectName("Login")
        Login.setFixedSize(592, 463)

        self.centralwidget = QtWidgets.QWidget(Login)
        self.centralwidget.setObjectName("centralwidget")
        font = QtGui.QFont()
        font.setPointSize(16)
        
        Login.setAcceptDrops(True)

        self.edtLineMail = QtWidgets.QLineEdit(self.centralwidget)
        self.edtLineMail.setGeometry(QtCore.QRect(150, 40, 311, 41))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.edtLineMail.setFont(font)
        self.edtLineMail.setMouseTracking(True)
        self.edtLineMail.setFocusPolicy(QtCore.Qt.ClickFocus)
        self.edtLineMail.setInputMask("")
        self.edtLineMail.setText("")
        self.edtLineMail.setAlignment(QtCore.Qt.AlignCenter)
        self.edtLineMail.setReadOnly(False)
        self.edtLineMail.setObjectName("edtLineMail")
        self.edtLineMail.setText("klavyefl@gmail.com")

        self.edtLineAppPassword = QtWidgets.QLineEdit(self.centralwidget)
        self.edtLineAppPassword.setGeometry(QtCore.QRect(20, 200, 550, 41))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.edtLineAppPassword.setEchoMode(QtWidgets.QLineEdit.Password)
        self.edtLineAppPassword.setFont(font)
        self.edtLineAppPassword.setMouseTracking(True)
        self.edtLineAppPassword.setFocusPolicy(QtCore.Qt.ClickFocus)
        self.edtLineAppPassword.setInputMask("")
        self.edtLineAppPassword.setText("123456")
        self.edtLineAppPassword.setAlignment(QtCore.Qt.AlignCenter)
        self.edtLineAppPassword.setReadOnly(False)
        self.edtLineAppPassword.setObjectName("edtLineAppPassword")

        self.btnGo = QtWidgets.QPushButton(self.centralwidget)
        self.btnGo.setGeometry(QtCore.QRect(240, 370, 112, 41))
        self.btnGo.setFont(font)
        self.btnGo.setObjectName("btnGo")

        Login.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(Login)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 592, 21))
        self.menubar.setObjectName("menubar")
        Login.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(Login)
        self.statusbar.setObjectName("statusbar")
        Login.setStatusBar(self.statusbar)
        
        self.retranslateUi(Login)
        QtCore.QMetaObject.connectSlotsByName(Login)
        self.controlAlsoLogin = False
        try:
            self.GetLoginText()
        except:pass

        self.btnGo.clicked.connect(lambda:self.btnGoClick(Login))
        
    def retranslateUi(self, Login):
        _translate = QtCore.QCoreApplication.translate
        Login.setWindowTitle(_translate("Login", "Login"))

        self.btnGo.setText(_translate("Login", "Login"))
        self.edtLineMail.setPlaceholderText(_translate("Login", "Mail"))
        self.edtLineAppPassword.setPlaceholderText(_translate("Login","App Password"))

    def btnGoClick(self,_Login): #buton register click

        #try:
        FBConf.auth.sign_in_with_email_and_password(self.edtLineMail.text(), self.edtLineAppPassword.text())
        user = FBConf.auth.current_user
        
        _Login.close()
        
        self.window = QtWidgets.QMainWindow()
        self.ui = Home.Ui_Home()
        self.ui.setupUi(self.window)
        self.window.show()
        Home.HomeStarter(self.ui,self.window,self.edtLineMail.text())
            
        # except Exception as e:
        #     print(e)
        #     print("Oops!", e.__class__, "occurred.")
            # msg = QMessageBox()
            # msg.setWindowTitle("Error")
            # msg.setText("Error Check Email and Password")
            # x = msg.exec_()
            # msg.setIcon(QMessageBox.Critical)

if __name__ == "__main__":

    app = QtWidgets.QApplication(sys.argv)
    Login = QtWidgets.QMainWindow()
    ex = Ui_Login()
    w = QtWidgets.QMainWindow()
    ex.setupUi(w)
    w.show()
    sys.exit(app.exec_())

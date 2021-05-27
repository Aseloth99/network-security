#Only works in @gmail.com
#https://app.diagrams.net/?src=about#HAseloth99%2Fnetwork-security%2Fmain%2FdatabaseMA  #diagram link
#pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib

from PyQt5 import QtCore, QtGui, QtWidgets
from Login import Ui_Login
from Register import Ui_Register

class Ui_Main(object):

    def setupUi(self, RegisterorLogin,numberSFBURun):
        RegisterorLogin.setObjectName("RegisterorLogin")
        RegisterorLogin.setFixedSize(591, 439)

        self.centralwidget = QtWidgets.QWidget(RegisterorLogin)
        self.centralwidget.setObjectName("centralwidget")

        self.btnLogIn = QtWidgets.QPushButton(self.centralwidget)
        self.btnLogIn.setGeometry(QtCore.QRect(360, 150, 161, 81))
        font = QtGui.QFont()
        font.setPointSize(18)
        self.btnLogIn.setFont(font)
        self.btnLogIn.setObjectName("btnLogIn")

        self.btnRegister = QtWidgets.QPushButton(self.centralwidget)
        self.btnRegister.setGeometry(QtCore.QRect(90, 150, 151, 81))
        font = QtGui.QFont()
        font.setPointSize(18)
        self.btnRegister.setFont(font)
        self.btnRegister.setObjectName("btnRegister")

        RegisterorLogin.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(RegisterorLogin)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 592, 21))
        self.menubar.setObjectName("menubar")
        RegisterorLogin.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(RegisterorLogin)
        self.statusbar.setObjectName("statusbar")
        RegisterorLogin.setStatusBar(self.statusbar)

        self.retranslateUi(RegisterorLogin)
        QtCore.QMetaObject.connectSlotsByName(RegisterorLogin)

        self.btnLogIn.clicked.connect(lambda:self.openLogin(RegisterorLogin,numberSFBURun))
        self.btnRegister.clicked.connect(lambda:self.openRegister(RegisterorLogin))

    def retranslateUi(self, RegisterorLogin):
        _translate = QtCore.QCoreApplication.translate
        
        RegisterorLogin.setWindowTitle(_translate("RegisterorLogin", "Register Or Login"))
        self.btnLogIn.setText(_translate("RegisterorLogin", "Login"))
        self.btnRegister.setText(_translate("RegisterorLogin", "Register"))

    def openLogin(self, _RegisterorLogin,numberSFBURun):
        _RegisterorLogin.close()

        self.window = QtWidgets.QMainWindow()
        self.ui = Ui_Login()
        self.ui.setupUi(self.window,numberSFBURun)
        self.window.show()

    def openRegister(self, _RegisterorLogin):
        _RegisterorLogin.close()

        self.window = QtWidgets.QMainWindow()
        self.ui = Ui_Register()
        self.ui.setupUi(self.window)
        self.window.show()


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    main = QtWidgets.QMainWindow()
    ui = Ui_Main()
    ui.setupUi(main,1)
    main.show()
    sys.exit(app.exec_())


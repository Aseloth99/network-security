# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'arayüz.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Home(object):
    def setupUi(self, Home):
        Home.setObjectName("Home")
        Home.resize(693, 622)
        self.centralwidget = QtWidgets.QWidget(Home)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 30, 671, 531))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.toLineEdit = QtWidgets.QLineEdit(self.tab)
        self.toLineEdit.setGeometry(QtCore.QRect(10, 30, 161, 21))
        self.toLineEdit.setObjectName("toLineEdit")
        self.fromLabel = QtWidgets.QLabel(self.tab)
        self.fromLabel.setGeometry(QtCore.QRect(10, 10, 161, 16))
        self.fromLabel.setObjectName("fromLabel")
        self.subjectLineEdit = QtWidgets.QLineEdit(self.tab)
        self.subjectLineEdit.setGeometry(QtCore.QRect(10, 60, 311, 20))
        self.subjectLineEdit.setText("")
        self.subjectLineEdit.setObjectName("subjectLineEdit")
        self.messageTextEdit = QtWidgets.QTextEdit(self.tab)
        self.messageTextEdit.setGeometry(QtCore.QRect(10, 90, 651, 381))
        self.messageTextEdit.setObjectName("messageTextEdit")
        self.sendButton = QtWidgets.QPushButton(self.tab)
        self.sendButton.setGeometry(QtCore.QRect(460, 480, 75, 23))
        self.sendButton.setObjectName("sendButton")
        self.pushButton = QtWidgets.QPushButton(self.tab)
        self.pushButton.setGeometry(QtCore.QRect(540, 40, 75, 23))
        self.pushButton.setObjectName("pushButton")
        self.label = QtWidgets.QLabel(self.tab)
        self.label.setGeometry(QtCore.QRect(450, 10, 51, 16))
        self.label.setObjectName("label")
        self.lineEdit = QtWidgets.QLineEdit(self.tab)
        self.lineEdit.setEnabled(True)
        self.lineEdit.setGeometry(QtCore.QRect(500, 10, 161, 20))
        self.lineEdit.setAutoFillBackground(False)
        self.lineEdit.setInputMask("")
        self.lineEdit.setText("")
        self.lineEdit.setReadOnly(True)
        self.lineEdit.setObjectName("lineEdit")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.iSearchLineEdit = QtWidgets.QLineEdit(self.tab_2)
        self.iSearchLineEdit.setGeometry(QtCore.QRect(10, 10, 161, 20))
        self.iSearchLineEdit.setObjectName("iSearchLineEdit")
        self.reloadPushButton = QtWidgets.QPushButton(self.tab_2)
        self.reloadPushButton.setGeometry(QtCore.QRect(470, 10, 75, 23))
        self.reloadPushButton.setObjectName("reloadPushButton")
        self.inboxTableView = QtWidgets.QTableWidget(self.tab_2)
        self.inboxTableView.setGeometry(QtCore.QRect(0, 40, 661, 461))
        self.inboxTableView.setObjectName("inboxTableView")
        self.inboxTableView.setColumnCount(0)
        self.inboxTableView.setRowCount(0)
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.oSearchLineEdit = QtWidgets.QLineEdit(self.tab_3)
        self.oSearchLineEdit.setGeometry(QtCore.QRect(10, 10, 161, 20))
        self.oSearchLineEdit.setObjectName("oSearchLineEdit")
        self.reloadPushButton_2 = QtWidgets.QPushButton(self.tab_3)
        self.reloadPushButton_2.setGeometry(QtCore.QRect(470, 10, 75, 23))
        self.reloadPushButton_2.setObjectName("reloadPushButton_2")
        self.outboxTableView = QtWidgets.QTableWidget(self.tab_3)
        self.outboxTableView.setGeometry(QtCore.QRect(0, 40, 661, 461))
        self.outboxTableView.setObjectName("outboxTableView")
        self.outboxTableView.setColumnCount(0)
        self.outboxTableView.setRowCount(0)
        self.tabWidget.addTab(self.tab_3, "")
        self.nameLabel = QtWidgets.QLabel(self.centralwidget)
        self.nameLabel.setGeometry(QtCore.QRect(10, 0, 221, 31))
        self.nameLabel.setObjectName("nameLabel")
        Home.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(Home)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 693, 21))
        self.menubar.setObjectName("menubar")
        self.menu_k = QtWidgets.QMenu(self.menubar)
        self.menu_k.setObjectName("menu_k")
        Home.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(Home)
        self.statusbar.setObjectName("statusbar")
        Home.setStatusBar(self.statusbar)
        self.action_k = QtWidgets.QAction(Home)
        self.action_k.setObjectName("action_k")
        self.actionMinimize_edilebilir = QtWidgets.QAction(Home)
        self.actionMinimize_edilebilir.setCheckable(True)
        self.actionMinimize_edilebilir.setChecked(True)
        self.actionMinimize_edilebilir.setObjectName("actionMinimize_edilebilir")
        self.menu_k.addAction(self.actionMinimize_edilebilir)
        self.menu_k.addSeparator()
        self.menu_k.addAction(self.action_k)
        self.menubar.addAction(self.menu_k.menuAction())

        self.retranslateUi(Home)
        self.tabWidget.setCurrentIndex(2)
        QtCore.QMetaObject.connectSlotsByName(Home)

    def retranslateUi(self, Home):
        _translate = QtCore.QCoreApplication.translate
        Home.setWindowTitle(_translate("Home", "MainWindow"))
        self.toLineEdit.setPlaceholderText(_translate("Home", "To"))
        self.fromLabel.setText(_translate("Home", "From: "))
        self.subjectLineEdit.setPlaceholderText(_translate("Home", "Subject"))
        self.sendButton.setText(_translate("Home", "Send"))
        self.pushButton.setText(_translate("Home", "Gözat"))
        self.label.setText(_translate("Home", "Dosya"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("Home", "Send Mail"))
        self.iSearchLineEdit.setPlaceholderText(_translate("Home", "Search"))
        self.reloadPushButton.setText(_translate("Home", "Reload"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("Home", "Inbox"))
        self.oSearchLineEdit.setPlaceholderText(_translate("Home", "Search"))
        self.reloadPushButton_2.setText(_translate("Home", "Reload"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("Home", "Outbox"))
        self.nameLabel.setText(_translate("Home", "TextLabel"))
        self.menu_k.setTitle(_translate("Home", "Menü"))
        self.action_k.setText(_translate("Home", "Çıkış"))
        self.actionMinimize_edilebilir.setText(_translate("Home", "Minimize edilebilir"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Home = QtWidgets.QMainWindow()
    ui = Ui_Home()
    ui.setupUi(Home)
    Home.show()
    sys.exit(app.exec_())

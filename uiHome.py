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
        Home.resize(802, 440)
        self.centralwidget = QtWidgets.QWidget(Home)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.nameLabel = QtWidgets.QLabel(self.centralwidget)
        self.nameLabel.setObjectName("nameLabel")
        self.gridLayout_2.addWidget(self.nameLabel, 0, 0, 1, 1)
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.gridLayout = QtWidgets.QGridLayout(self.tab)
        self.gridLayout.setObjectName("gridLayout")
        self.fromLabel = QtWidgets.QLabel(self.tab)
        self.fromLabel.setObjectName("fromLabel")
        self.gridLayout.addWidget(self.fromLabel, 0, 0, 1, 1)
        self.toLineEdit = QtWidgets.QLineEdit(self.tab)
        self.toLineEdit.setObjectName("toLineEdit")
        self.gridLayout.addWidget(self.toLineEdit, 1, 0, 1, 1)
        self.subjectLineEdit = QtWidgets.QLineEdit(self.tab)
        self.subjectLineEdit.setText("")
        self.subjectLineEdit.setObjectName("subjectLineEdit")
        self.gridLayout.addWidget(self.subjectLineEdit, 2, 0, 1, 3)
        self.messageTextEdit = QtWidgets.QTextEdit(self.tab)
        self.messageTextEdit.setObjectName("messageTextEdit")
        self.gridLayout.addWidget(self.messageTextEdit, 3, 0, 1, 3)
        self.label = QtWidgets.QLabel(self.tab)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 4, 0, 1, 1)
        self.lineEdit = QtWidgets.QLineEdit(self.tab)
        self.lineEdit.setEnabled(True)
        self.lineEdit.setAutoFillBackground(False)
        self.lineEdit.setInputMask("")
        self.lineEdit.setText("")
        self.lineEdit.setReadOnly(True)
        self.lineEdit.setObjectName("lineEdit")
        self.gridLayout.addWidget(self.lineEdit, 5, 0, 1, 1)
        self.pushButton = QtWidgets.QPushButton(self.tab)
        self.pushButton.setObjectName("pushButton")
        self.gridLayout.addWidget(self.pushButton, 5, 1, 1, 1)
        self.sendButton = QtWidgets.QPushButton(self.tab)
        self.sendButton.setObjectName("sendButton")
        self.gridLayout.addWidget(self.sendButton, 5, 2, 1, 1)
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.gridLayout_3 = QtWidgets.QGridLayout(self.tab_2)
        self.gridLayout_3.setObjectName("gridLayout_3")
        self.iSearchLineEdit = QtWidgets.QLineEdit(self.tab_2)
        self.iSearchLineEdit.setObjectName("iSearchLineEdit")
        self.gridLayout_3.addWidget(self.iSearchLineEdit, 0, 0, 1, 1)
        self.reloadInbox = QtWidgets.QPushButton(self.tab_2)
        self.reloadInbox.setObjectName("reloadInbox")
        self.gridLayout_3.addWidget(self.reloadInbox, 0, 1, 1, 1)
        self.inboxTableView = QtWidgets.QTableWidget(self.tab_2)
        self.inboxTableView.setObjectName("inboxTableView")
        self.inboxTableView.setColumnCount(0)
        self.inboxTableView.setRowCount(0)
        self.gridLayout_3.addWidget(self.inboxTableView, 1, 0, 1, 2)
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.gridLayout_4 = QtWidgets.QGridLayout(self.tab_3)
        self.gridLayout_4.setObjectName("gridLayout_4")
        self.oSearchLineEdit = QtWidgets.QLineEdit(self.tab_3)
        self.oSearchLineEdit.setObjectName("oSearchLineEdit")
        self.gridLayout_4.addWidget(self.oSearchLineEdit, 0, 0, 1, 1)
        self.reloadOutbox = QtWidgets.QPushButton(self.tab_3)
        self.reloadOutbox.setObjectName("reloadOutbox")
        self.gridLayout_4.addWidget(self.reloadOutbox, 0, 1, 1, 1)
        self.outboxTableView = QtWidgets.QTableWidget(self.tab_3)
        self.outboxTableView.setObjectName("outboxTableView")
        self.outboxTableView.setColumnCount(0)
        self.outboxTableView.setRowCount(0)
        self.gridLayout_4.addWidget(self.outboxTableView, 1, 0, 1, 2)
        self.tabWidget.addTab(self.tab_3, "")
        self.gridLayout_2.addWidget(self.tabWidget, 1, 0, 1, 1)
        Home.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(Home)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 802, 21))
        self.menubar.setObjectName("menubar")
        self.menu_k = QtWidgets.QMenu(self.menubar)
        self.menu_k.setObjectName("menu_k")
        self.menuTema = QtWidgets.QMenu(self.menubar)
        self.menuTema.setObjectName("menuTema")
        Home.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(Home)
        self.statusbar.setObjectName("statusbar")
        Home.setStatusBar(self.statusbar)
        self.Exit = QtWidgets.QAction(Home)
        self.Exit.setObjectName("Exit")
        self.Minimize_edilebilir = QtWidgets.QAction(Home)
        self.Minimize_edilebilir.setCheckable(True)
        self.Minimize_edilebilir.setChecked(True)
        self.Minimize_edilebilir.setObjectName("Minimize_edilebilir")
        self.Hakkimda = QtWidgets.QAction(Home)
        self.Hakkimda.setObjectName("Hakkimda")
        self.actionWindows = QtWidgets.QAction(Home)
        self.actionWindows.setObjectName("actionWindows")
        self.actionVista = QtWidgets.QAction(Home)
        self.actionVista.setObjectName("actionVista")
        self.actionF_zyon = QtWidgets.QAction(Home)
        self.actionF_zyon.setObjectName("actionF_zyon")
        self.actionA_k = QtWidgets.QAction(Home)
        self.actionA_k.setObjectName("actionA_k")
        self.actionKoyu = QtWidgets.QAction(Home)
        self.actionKoyu.setObjectName("actionKoyu")
        self.menu_k.addAction(self.Minimize_edilebilir)
        self.menu_k.addAction(self.Hakkimda)
        self.menu_k.addSeparator()
        self.menu_k.addAction(self.Exit)
        self.menuTema.addAction(self.actionWindows)
        self.menuTema.addAction(self.actionVista)
        self.menuTema.addAction(self.actionF_zyon)
        self.menuTema.addSeparator()
        self.menuTema.addAction(self.actionA_k)
        self.menuTema.addAction(self.actionKoyu)
        self.menubar.addAction(self.menu_k.menuAction())
        self.menubar.addAction(self.menuTema.menuAction())

        self.retranslateUi(Home)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(Home)

    def retranslateUi(self, Home):
        _translate = QtCore.QCoreApplication.translate
        Home.setWindowTitle(_translate("Home", "Secure Mail Program"))
        self.nameLabel.setText(_translate("Home", "TextLabel"))
        self.fromLabel.setText(_translate("Home", "From: "))
        self.toLineEdit.setPlaceholderText(_translate("Home", "To"))
        self.subjectLineEdit.setPlaceholderText(_translate("Home", "Subject"))
        self.label.setText(_translate("Home", "File"))
        self.pushButton.setText(_translate("Home", "Browse"))
        self.sendButton.setText(_translate("Home", "Send"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("Home", "Send Mail"))
        self.iSearchLineEdit.setPlaceholderText(_translate("Home", "Search"))
        self.reloadInbox.setText(_translate("Home", "Reload"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("Home", "Inbox"))
        self.oSearchLineEdit.setPlaceholderText(_translate("Home", "Search"))
        self.reloadOutbox.setText(_translate("Home", "Reload"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("Home", "Outbox"))
        self.menu_k.setTitle(_translate("Home", "Menü"))
        self.menuTema.setTitle(_translate("Home", "Tema"))
        self.Exit.setText(_translate("Home", "Exit"))
        self.Minimize_edilebilir.setText(_translate("Home", "Minimize edilebilir"))
        self.Hakkimda.setText(_translate("Home", "Hakkımda"))
        self.actionWindows.setText(_translate("Home", "Windows"))
        self.actionVista.setText(_translate("Home", "Vista"))
        self.actionF_zyon.setText(_translate("Home", "Füzyon"))
        self.actionA_k.setText(_translate("Home", "Açık"))
        self.actionKoyu.setText(_translate("Home", "Koyu"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Home = QtWidgets.QMainWindow()
    ui = Ui_Home()
    ui.setupUi(Home)
    Home.show()
    sys.exit(app.exec_())

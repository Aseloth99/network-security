import Mail
import time

def __init__(self,to,rsaPublicKey):
    self.to=to
    self.rsaPublicKey=rsaPublicKey

def CreateWelcomeMail():
    welcomeMail=Mail(1,"Network Security Mail",self.to,"Welcome Among Us","Welcome",time.time(),self.rsaPublicKey)
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

"""SMTP Modülü ile mail gönderme
İlk olarak daha az güvenli uygulamalar için öncelikle aşağıdaki linke gidiyoruz ve güvenliği kaldırıyoruz.
https://myaccount.google.com/lesssecureapps"""

Mail="mustafaacik92@gmail.com"
Şifre=""
mesaj = MIMEMultipart()  
mesaj["From"] =  Mail
mesaj["To"] = "031790010@ogr.uludag.edu.tr"
mesaj["Subject"] = "Konu" 

mail =  smtplib.SMTP("smtp.gmail.com",587)  # SMTP objemizi oluşturuyoruz ve gmail smtp server'ına bağlanıyoruz.
mail.starttls() # Adresimizin ve Parolamızın şifrelenmesi için gerekli
mail.ehlo() # SMTP serverına kendimizi tanıtıyoruz.
mail.login(Mail,Şifre) # SMTP server'ına giriş yapıyoruz. Kendi mail adresimizi ve parolamızı yapıyoruz.

yazi = """
seasd
"""

mesaj_govdesi =  MIMEText(yazi,"plain")  # Mailimizin gövdesini bu sınıftan oluşturuyoruz.
mesaj.attach(mesaj_govdesi) # Mailimizin gövdesini mail yapımıza ekliyoruz.

try:
    mail.sendmail(mesaj["From"],mesaj["To"],mesaj.as_string())  # Mailimizi gönderiyoruz.
    print(Mail)
    
except Exception as e:
    print(e)
    print("Oops!", e.__class__, "occurred.")
    import sys
    sys.stderr.write("Mail göndermesi başarısız oldu...") # Herhangi bir bağlanma sorunu veya mail gönderme sorunu olursa
    sys.stderr.flush()
mail.close()  # Smtp serverımızın bağlantısını koparıyoz.
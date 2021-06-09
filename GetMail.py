import imaplib
import email

username = 'klavyefl@gmail.com'
password = 'KlavyeFL0.'

def get_inbox():
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(username, password)
    mail.select("INBOX")
    _, search_data = mail.search(None,"ALL")
    my_message = []
    for num in search_data[0].split():
        email_data = {}
        _, data = mail.fetch(num, '(RFC822)')
        #print(data[0])
        _, b = data[0]
        email_message = email.message_from_bytes(b)
        for part in email_message.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True)
        for header in ['subject', 'to', 'from', 'date']:
            #print("{}: {}".format(header, email_message[header]))
            if(header=='from'):
                email_data['from'] = email_message['from'].split("<")[1].strip(">")
            else:
                email_data[header] = email_message[header]
        email_data['body'] = body.decode()
        my_message.append(email_data)
    return my_message

if __name__ == "__main__":
    my_inbox = get_inbox()
    print(my_inbox)
    for i in my_inbox:
        print()
        for j in i.items():
            print(f"{j[0]:<8}{j[1]}")
    
"""import imaplib
import email
from email.header import decode_header
import webbrowser
import os

username = "klavyefl@gmail.com"
password = "KlavyeFL0."

def clean(text):
    # clean text for creating a folder
    return "".join(c if c.isalnum() else "_" for c in text)

# create an IMAP4 class with SSL 
try:
    imap = imaplib.IMAP4_SSL("imap.gmail.com",993)
    # authenticate
    imap.login(username, password)
except TimeoutError:
    print("İnternet bağlantısı yok.")

status, messages = imap.select('inbox')

# total number of emails
messages = int(messages[0])
for i in range(messages, -1, -1):
    # fetch the email message by ID
    res,msg = imap.fetch(str(i), "(RFC822)")
    for response in msg:
        if isinstance(response, tuple):
            # parse a bytes email into a message object
            msg = email.message_from_bytes(response[1])
            # decode the email subject
            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                # if it's a bytes, decode to str
                subject = subject.decode(encoding)
            # decode email sender
            From, encoding = decode_header(msg.get("From"))[0]
            if isinstance(From, bytes):
                From = From.decode(encoding)
            print("From:", From)
            print("Subject:", subject)
            # if the email message is multipart
            if msg.is_multipart():
                # iterate over email parts
                for part in msg.walk():
                    # extract content type of email
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    try:
                        # get the email body
                        body = part.get_payload(decode=True).decode()
                    except:
                        pass
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        # print text/plain emails and skip attachments
                        print(body)
                    elif "attachment" in content_disposition:
                        # download attachment
                        filename = part.get_filename()
                        if filename:
                            folder_name = clean(subject)
                            if not os.path.isdir(folder_name):
                                # make a folder for this email (named after the subject)
                                os.mkdir(folder_name)
                            filepath = os.path.join(folder_name, filename)
                            # download attachment and save it
                            open(filepath, "wb").write(part.get_payload(decode=True))
            else:
                # extract content type of email
                content_type = msg.get_content_type()
                # get the email body
                body = msg.get_payload(decode=True).decode()
                if content_type == "text/plain":
                    # print only text email parts
                    print(body)
            if content_type == "text/html":
                # if it's HTML, create a new HTML file and open it in browser
                folder_name = clean(subject)
                if not os.path.isdir(folder_name):
                    # make a folder for this email (named after the subject)
                    os.mkdir(folder_name)
                filename = "index.html"
                filepath = os.path.join(folder_name, filename)
                # write the file
                open(filepath, "w").write(body)
                # open in the default browser
                webbrowser.open(filepath)
            print("="*100)
# close the connection and logout
imap.close()
imap.logout()"""


"""
import smtplib
import time
import imaplib
import email
import traceback 

ORG_EMAIL = "@gmail.com" 
FROM_EMAIL = "klavyefl" + ORG_EMAIL 
FROM_PWD = "KlavyeFL0." 
SMTP_SERVER = "imap.gmail.com" 
SMTP_PORT = 993

def read_email_from_gmail():
    try:
        mail = imaplib.IMAP4_SSL(SMTP_SERVER)
        mail.login(FROM_EMAIL,FROM_PWD)
        mail.select('inbox')

        data = mail.search(None, 'ALL')
        mail_ids = data[1]
        print(mail_ids)
        id_list = mail_ids[0].split()   
        first_email_id = int(id_list[0])
        latest_email_id = int(id_list[-1])
        print(first_email_id,latest_email_id)
        for i in range(latest_email_id,first_email_id+1, 1):
            data = mail.fetch(str(i), '(RFC822)' )
            for response_part in data:
                arr = response_part[0]
                if isinstance(arr, tuple):
                    msg = email.message_from_string(str(arr[1],'utf-8'))
                    email_subject = msg['subject']
                    email_from = msg['from']
                    print('From : ' + email_from + '\n')
                    print('Subject : ' + email_subject + '\n')
    except IndexError:
        print("Gelen kutusu boş")
    except Exception as e:
        traceback.print_exc() 
        print(str(e))

read_email_from_gmail()"""
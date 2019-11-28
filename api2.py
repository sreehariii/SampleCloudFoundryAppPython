from flask import Flask
from flask_pymongo import PyMongo
from flask import Flask, render_template
import logging
logging.basicConfig()
import requests
from flask import Flask, render_template 
from flask_sqlalchemy import SQLAlchemy 
import socket, ssl
import OpenSSL
from cryptography import x509
import cryptography
from datetime import datetime
import base64
from cryptography.hazmat.backends import default_backend
from apscheduler.scheduler import Scheduler
import time
import sqlite3
from flask_mail import Mail, Message

app = Flask(__name__)


app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb+srv://dbuser:dbuserpassword@cluster0-o5lsl.mongodb.net/test?retryWrites=true&w=majority"
mongo = PyMongo(app)


#fetch the issuer CN 
def get_issuer_cn(hosturl):
    port = 443
    context = ssl.create_default_context()
    with socket.create_connection((hosturl, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hosturl) as sslsock:
                der_cert = sslsock.getpeercert(True)
            # from binary DER format to PEM
                pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)          
            #print(pem_cert)   
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
                issuercn = x509.get_issuer().commonName
                return issuercn

def get_cert_val(hosturl):
    import subprocess
    cert = subprocess.check_output("openssl s_client -connect {0}:443 -servername {1} 2>/dev/null </dev/null |  sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'".format(hosturl, hosturl), shell=True)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    validity_till = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    return validity_till

def save_cacerts(hosturl):
    port = 443
    ctx = OpenSSL.SSL.Context(ssl.PROTOCOL_TLSv1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hosturl, port))
    cnx = OpenSSL.SSL.Connection(ctx, s)
    cnx.set_connect_state()
    byteurl = hosturl.encode()
    cnx.set_tlsext_host_name(byteurl)
    cnx.do_handshake()
    certs=cnx.get_client_ca_list()
    with open('%s.txt' % hosturl, "w") as hashes:  
        for cert in certs:
            hashgg = (cert.commonName)
            hashes.write("%s\n" % hashgg)
    hashes.close()
    return certs

def get_ca_count(hosturl):
    port = 443
    ctx = OpenSSL.SSL.Context(ssl.PROTOCOL_TLSv1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hosturl, port))
    cnx = OpenSSL.SSL.Connection(ctx, s)
    cnx.set_connect_state()
    byteurl = hosturl.encode()
    cnx.set_tlsext_host_name(byteurl)
    cnx.do_handshake()
    certs=cnx.get_client_ca_list()
    return len(certs)

def get_extracerts(hosturl):
    certs = save_cacerts(hosturl)
    extralist = []
    with open('mcbundle.txt', 'r') as cas:
        data = cas.readlines()
        for cert in certs:
            components = str(cert.commonName)
            if components not in str(data):
                extralist.append(cert.commonName)
    return str(extralist)


def get_missingcerts(hosturl):
    with open("%s.txt" % hosturl, 'r') as loadedcerts:
       data1 = loadedcerts.readlines()
    missinglist = []
    with open("mcbundle.txt", "r") as cas:
            data = cas.readlines()
            for item in data:
                if item not in data1:
                    missinglist.append(item.strip())
    return str(missinglist)

@app.route("/<runtime_host>/<dt_host>", methods=['GET'])
def index(runtime_host,dt_host):
    runtime_host_issuercn = get_issuer_cn(runtime_host)
    runtime_dccode = runtime_host.split('.')[0]
    runtime_validuntil = get_cert_val(runtime_host)
    runtime_cacount = get_ca_count(runtime_host)
    runtime_daysleft = (runtime_validuntil - datetime.now()).days
    runtime_extracerts = get_extracerts(runtime_host)
    runtime_missingcerts = get_missingcerts(runtime_host)

    dt_host_issuercn = get_issuer_cn(dt_host)
    dt_validuntil = get_cert_val(dt_host)
    dt_daysleft = (dt_validuntil - datetime.now()).days

    user_collection = mongo.db.users
    user_collection.insert({
    runtime_dccode :{
                "Designtime": {
                            "Host_Name" : dt_host,
                            "Status_Ind" : "Green",
                            "Days_Left" : dt_daysleft,
                            "Valid_Until": dt_validuntil,
                            "Issuer" : dt_host_issuercn,
                            "CA_Count" : "NA"
                },
                "Runtime": {
                            "Host_Name" : runtime_host,
                            "Status_Ind" : "Green",
                            "Days_Left" : runtime_daysleft,
                            "Valid_Until": runtime_validuntil,
                            "Issuer" : runtime_host_issuercn,
                            "ExtraCerts" : runtime_extracerts,
                            "MissingCerts" : runtime_missingcerts,
                            "CA_Count" : runtime_cacount
      }
   }
})
    
    return '<h1> hosts added </h1>'


def update_db():
    db.users.find()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=9000, use_reloader=False)

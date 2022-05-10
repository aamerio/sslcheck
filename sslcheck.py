import os
import ssl
import socket
import time
from dotenv import load_dotenv
from dateutil.parser import parse
from datetime import datetime, timedelta
import pytz
import boto3
from snswrapper import SnsWrapper


load_dotenv()


def certificationInfo(hostname):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.connect((hostname, 443))
        cert = s.getpeercert()

    #subject = dict(x[0] for x in cert['subject'])
    #issued_to = subject['commonName']
    #issuer = dict(x[0] for x in cert['issuer'])
    #issued_by = issuer['commonName']
    return cert


def expiringInfo(domains_list):
    listdate = {"valid": [], "30days": [], "expired": [], "error": []}
    with open(domains_list) as f:
        domains = f.readlines()
    for domain in domains:
        if domain != "":
            domain = domain.replace("\n", "")
            cert = certificationInfo(domain)
            dateCertificateExpire = parse(
                cert['notAfter']).replace(tzinfo=pytz.utc)
            today = datetime.now().replace(tzinfo=pytz.utc)
            thirtyDaysAgo = (today + timedelta(-30)).replace(tzinfo=pytz.utc)
            if dateCertificateExpire > thirtyDaysAgo:
                listdate['valid'].append([domain, dateCertificateExpire])
            elif dateCertificateExpire < thirtyDaysAgo:
                listdate['30days'].append([domain, dateCertificateExpire])
            elif dateCertificateExpire >= today:
                listdate['expired'].append([domain, dateCertificateExpire])
            else:
                listdate['error'].append([domain, dateCertificateExpire])
    return listdate

def analyzeInfo(result):
    body = ""
    for area in result:
        if area != 'valid' and len(result[area]) > 0:
            body = f"{body}<h1>{area}</h1><hr /><ul>"
            for domain in result[area]:
                body = f"{body}<li>{domain[0]}: {domain[1]}"
            body = f"{body}</li></ul>"
    return body


def snsSendMessage(sns, topic_arn, body):
    subject = f"OgilvyIT: check certificati-{datetime.now()}"
    sns.publish(TopicArn=topic_arn,
                Message=body,
                Subject=subject)


if __name__ == "__main__":
    sns_topic_arn = os.getenv("SNS_TOPIC_ARN")
    sns = boto3.client("sns",
                       region_name=os.getenv("AWS_REGION"),
                       aws_access_key_id=os.getenv("AWS_KEY_ID"),
                       aws_secret_access_key= os.getenv("AWS_SECRET"))

    domains_list = f"{os.getcwd()}/domains.list"
    result = expiringInfo(domains_list)
    body = analyzeInfo(result)
    if len(body) > 0:
        snsSendMessage(sns, sns_topic_arn, body)
    else:
        snsSendMessage(sns, sns_topic_arn, "Nessun certificato da rinnovare")

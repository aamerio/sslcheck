import os
import ssl
import socket
import time
from dotenv import load_dotenv
from dateutil.parser import parse
from datetime import datetime, timedelta
import pytz
import boto3

load_dotenv()

def certificateInfo(hostname):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.connect((hostname, 443))
        cert = s.getpeercert()

    #subject = dict(x[0] for x in cert['subject'])
    #issued_to = subject['commonName']
    #issuer = dict(x[0] for x in cert['issuer'])
    #issued_by = issuer['commonName']
    return cert


def listCertificatesAWS(profile_name, region_name):
    session = boto3.session.Session(
        profile_name=profile_name, region_name=region_name)
    acm = session.client('acm')
    resp = acm.list_certificates()
    certs = resp.get('CertificateSummaryList')
    certificates = []
    for cert in certs:
        cert = acm.describe_certificate(CertificateArn=cert["CertificateArn"])
        dateCertificateExpire = cert['Certificate']['NotAfter']
        domain_name = f"AWS-{profile_name}-{region_name}-{cert['Certificate']['DomainName']}"
        certificates.append(
            {"env": 'aws', "domain_name": domain_name, "expire": dateCertificateExpire})

    return certificates


def groupCertificatesByDates(domains):
    listdate = {"valid": [], "30days": [], "expired": [], "error": []}
    today = datetime.now().replace(tzinfo=pytz.utc)
    for domain in domains:
        domain_name = domain['domain_name']
        dateCertificateExpire = domain['expire']
        thirtyDaysAgo = (today + timedelta(-30)).replace(tzinfo=pytz.utc)
        if dateCertificateExpire > thirtyDaysAgo:
            listdate['valid'].append([domain_name, dateCertificateExpire])
        elif dateCertificateExpire < thirtyDaysAgo:
            listdate['30days'].append([domain_name, dateCertificateExpire])
        elif dateCertificateExpire >= today:
            listdate['expired'].append(
                [domain_name, dateCertificateExpire])
        else:
            listdate['error'].append([domain_name, dateCertificateExpire])
    return listdate


def formatInfoHTML(result):
    body = "<table>"
    for area in result:
        body += f"<tr><td colspan='2'><h2>{area}</h2></td>></tr>"
        for domain in result[area]:
            body += f"<tr><td>{domain[0]}</td><td>{domain[1]}</td></tr>"
    body += "</table>"
    return body


def formatInfoText(result):
    body = ""
    for area in result:
        body += f"\n{'=' * 20}{area}{'=' * 20}\n\n"
        for domain in result[area]:
            body += f"- {domain[0]}: {domain[1]}\n"

    return body

def snsSendMessage(sns, topic_arn, body):
    subject = f"OgilvyIT: check certificati-{datetime.now()}"
    sns.publish(TopicArn=topic_arn,
                Message=body,
                Subject=subject,
                MessageStructure='html')


if __name__ == "__main__":
    sns_topic_arn = os.getenv("SNS_TOPIC_ARN")
    session = boto3.session.Session(
        profile_name='aa-oint', region_name='eu-west-1')
    sns = session.client("sns")

    domains_list = f"{os.getcwd()}/domains.csv"
    nocloud_domains = []
    cloud_domains = []

    with open(domains_list) as f:
        domains = f.readlines()
        for d in domains:
            d = d.replace("\n", "").replace(" ", "").split(",")
            if d[0] == 'aws':
                certificates = listCertificatesAWS(d[1],d[2])
                for aws_cert in certificates:
                    cloud_domains.append(aws_cert)
            else:
                cert = certificateInfo(d[1])
                dateCertificateExpire = parse(
                cert['notAfter']).replace(tzinfo=pytz.utc)
                nocloud_domains.append(
                    {"env": d[0], "domain_name": d[1], "expire": dateCertificateExpire})
    domains = nocloud_domains + cloud_domains
    results = groupCertificatesByDates(domains)
    
    # format and print table
#    table = texttable.Texttable()
#    headers = ['Domain', 'Date expire', 'Type']
#    table.header(headers)
#    for r in results:
#        table.add_rows(rows=results[r], header=False)
#    table.set_cols_align(['c' for name in headers])
#    print(table.draw())


    body = formatInfoText(results)

    print(body)

    if len(body) > 0:
        snsSendMessage(sns, sns_topic_arn, body)
    else:
        snsSendMessage(sns, sns_topic_arn, "Nessun certificato da rinnovare")

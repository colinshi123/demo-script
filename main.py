#! /usr/bin/env python3
# -*- coding:utf-8 -*-
# Author:ColinShi

import boto3
import logging
import os
from configparser import ConfigParser
import datetime
import subprocess
import re
import sys

DIRPATH = os.path.dirname(os.path.abspath(__file__))
sys.path.append(DIRPATH)
# logging.basicConfig(filename=f'{DIRPATH}/auto-rotate-cdn-certs.log', encoding='utf-8', level=logging.INFO)
print(DIRPATH)
config = ConfigParser()
config.read(f"{DIRPATH}/config.ini")


# Let's use Amazon S3
# cf = boto3.client('cloudfront')
# iam = boto3.resource('iam')
# server_certificate = iam.ServerCertificate('name')

# Print out bucket names
# print(cf.get_app())


# Upload a new file
# data = open('test.jpg', 'rb')
# s3.Bucket('my-bucket').put_object(Key='test.jpg', Body=data)


# 获取AWS CDN证书
def get_aws_cdn_cert():
    pass


def get_cert_shell(domain):
    cmd = f"curl  https://{domain} -k -v -s -o /dev/null"
    code, std_out = subprocess.getstatusoutput(cmd)
    # output = re.search('SSL connection using (.*?)\n.*?start date: (.*?)\n.*?expire date: (.*?)\n.*?issuer: (.*?)\n.*?',
    #                   std_out, re.S)
    output = re.search('start date: (.*?)\n.*?expire date: (.*?)\n.*?issuer: (.*?)\n.*?',
                       std_out, re.S)
    if output:
        cert_exprie_date = datetime.datetime.strptime(output.groups()[1], '%b %d %H:%M:%S %Y GMT')
        return cert_exprie_date
    else:
        return


# 获取指定证书
# def get_cert(domain):
#     domain_name, *_ = domain.split(":")
#     *_, domain_port = domain.split(":")
#     if domain_name == domain_port:
#         domain_port = "443"
#     res = requests.get("https://"+domain_name+":"+domain_port, verify=False)
#     return res


import socket


# 获取指定证书
# def get_cert(domain):
#     logging.info(f"证书验证: {domain} 开始")
#     domain_name, *_ = domain.split(":")
#     *_, domain_port = domain.split(":")
#     if domain_name == domain_port:
#         domain_port = 443
#     cert = ssl.get_server_certificate((domain_name, 443), ssl_version=3)  # 一般是443端口,并且这里默认返回
#     logging.info(f"证书获取: {domain} 完成")
#     certification = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
#     return datetime.datetime.strptime(str(certification.get_notAfter(), encoding="utf-8"), '%Y%m%d%H%M%SZ')
# return cert


# 验证证书过期时间
# def get_cert_expiry(cert):
#     certification = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
#     return datetime.datetime.strptime(str(certification.get_notAfter(), encoding="utf-8"), '%Y%m%d%H%M%SZ')


# 上传证书至AWS_CDN
def post_aws_cdn_cert(domain):
    client = boto3.client('iam', region_name="cn-northwest-1")
    with open('/opt/cert/tls.crt', 'r') as f:
        ca = f.read()
    with open('/opt/cert/tls.key', 'r') as f:
        ca_key = f.read()
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    response = client.upload_server_certificate(
        CertificateBody=ca,
        Path='/cloudfront/mmota-cdn/',
        PrivateKey=ca_key,
        ServerCertificateName='mmota-cdn-aws-cn-staging-' + date,
    )
    return response


# import urllib3
#
# urllib3.disable_warnings()
exp_day = int(config.get('base', 'expiryday'))
# domains = ["mmota-cdn.p1.tmc79.cn", "mmota-cdn.p0.tmc79.cn", "mmota-cdn.beta.tmc79.cn"]
domains = ["mmota-cdn.beta.tmc79.cn"]
for domain in domains:
    print(domain)
    cert_expiry = get_cert_shell(domain)
    print(cert_expiry)
    # cert_expiry = get_cert_expiry(cert)
    # print(cert_expiry)
    if (cert_expiry - datetime.datetime.now()).days < exp_day:
        print(f'将在{exp_day}天内过期，证书进行更换')
        print(f'开始更新{domain}域名证书')
        post_aws_cdn_cert(domain)
    else:
        print('证书无需更换')

"""
那些域名需要监控,有可以测试的域名吗？
域名获取证书方式？直接访问？还是通过AWS获取？
需要那些认证？
过期后更新证书从哪里获得
aws更新证书需要那些权限？
获取失败后需要如何处理
"""

#!/bin/bash

# Install git package in instance
yum -y install git

#Install pip package
yum -y install python-pip

#Install awcli
pip install awscli

# Clone drop github repository in /tmp/ansible/
mkdir /tmp/ansible/ && cd /tmp/ansible/ && git clone https://github.com/djaodjin/drop

# Upload ldap certificates
aws s3 cp s3://ansible-deployutils/identities/dbs.internal/etc/pki/tls/certs/dbs.internal.crt /etc/pki/tls/certs/dbs.internal.crt
aws s3 cp s3://ansible-deployutils/identities/dbs.internal/etc/pki/tls/private/dbs.internal.key /etc/pki/tls/private/dbs.internal.key

# Run dservices scripts
sudo chmod -R 755 /tmp/ansible/drop/
sudo /tmp/ansible/drop/src/dservices.py /tmp/ansible/drop/share/tero/databases.xml

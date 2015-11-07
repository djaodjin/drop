Starting with the Ansible playbooks
===================================

First we must install the minimal prerequisites

    $ virtualenv deploy
    $ source deploy/bin/activate
    $ pip install awscli boto ansible
    Successfully installed ... awscli-1.8.2 boto-2.38.0 ansible-1.9.4 ...
    # We also need some of the extra modules (ex: cloudtrail)
    $ git clone https://github.com/ansible/ansible-modules-extras.git
    $ cp -r ansible-modules-extras/cloud/amazon \
        $VIRTUAL_ENV/lib/python2.7/site-packages/ansible/modules/extras/cloud


If you do not have a key pair that you will use to connect to the EC2 instances
allocated by the playbooks, now is a good time to create one

    $ ssh-keygen -q -f ~/.ssh/*key_name* -b 2048 -t rsa

Then we create configuration files with specific information about our
infrastructure such as AWS region, AWS credentials, etc.

    $ cd playbooks
    $ mkdir -p group_vars
    $ cat group_vars/all
    # Variables to connect to AWS
    aws_account: *AWS accountID (used in S3 bucket policies)*
    aws_region: *AWS region where resources are allocated*

    # Variables to create EC2 instances
    key_name: *Key used to first ssh into an instance*
    aws_zone: *EBS volumes and EC2 instances must be in the same zone.*
    instance_type: *EC2 instance type (t2.micro, etc.)*
    ami_id: *Image on which an EC2 instance is based.*

    # Application variables
    tag_prefix: *All resource names will be prefixed by tag_prefix*
    castle_gate_name: *Name of the security group for http front machines*
    courtyard_name: *Name of the security group for the worker machines*
    kitchen_door_name: *Name of the security group for backstage machines*
    vault_name: *Name of the security group for the databases machines*
    watch_tower_name: *Name of the security group for the smtp front machines*
    domain_name: *Domain name for your organization, ex: example.com*

    # Directories on local machine
    identities_dir: *Where keys and certificates could be found*

    # URLs to fetch code repositories
    remote_src_top: *Root of where git repositories are found*

    $ cat $VIRTUAL_ENV/etc/ansible/hosts
    [local]
    localhost ansible_python_interpreter=*VIRTUAL_ENV*/bin/python

Here are the identities file we need to deploy to the instance profiles

    *identities_dir*/dbs.internal/
        etc/pki/tls/certs/dbs.internal.crt
        etc/pki/tls/private/dbs.internal.key
    *identities_dir*/web.internal/
        etc/pki/tls/certs/dbs.internal.crt
        etc/pki/tls/certs/*example.com*.crt
        etc/pki/tls/certs/*wildcard-example.com*.crt
        etc/pki/tls/private/*example.com*.key
        etc/pki/tls/certs/*wildcard-example.com*.key

In development, we will generate throw away, self-signed, certificates
for all identities:

    $ openssl req -new -sha256 -newkey rsa:2048 -nodes \
        -keyout *example.com*.key -out *example.com*.csr
    $ openssl x509 -req -days 365 -in *example.com*.csr \
        -signkey *example.com*.key -out *example.com*.crt

It is now time to run the playbooks! Our playbooks are organized
in `provisioning, deploying and decommisioning groups<https://djaodjin.com/blog/organizing-ansible-playbooks.blog>`_.
We run them in order:

    # Provisioning the S3 bucket, EC2 security groups and IAM roles
    $ ansible-playbook -i $VIRTUAL_ENV/etc/ansible/hosts \
        aws-create-authorized.yml

    # Deploying EC2 instances
    $ ansible-playbook -i $VIRTUAL_ENV/etc/ansible/hosts \
        aws-create-instances.yml

    # Decommisioning
    $ ansible-playbook -i ../vendor/ec2.py aws-delete-instances.yml
    $ ansible-playbook -i $VIRTUAL_ENV/etc/ansible/hosts \
         aws-delete-authorized.yml


Starting with the Ansible playbooks
===================================

First we must install the minimal prerequisites

    $ virtualenv deploy
    $ source deploy/bin/activate
    $ pip install awscli boto ansible
    Successfully installed ... awscli-1.10.22 boto-2.39.0 ansible-2.0.2.0 ...

(Optional) If you are using Ansible before version 2.0, you will also need to
install some extra modules (ex: cloudtrail)

    $ git clone https://github.com/ansible/ansible-modules-extras.git
    $ cp -r ansible-modules-extras/cloud/amazon \
        $VIRTUAL_ENV/lib/python2.7/site-packages/ansible/modules/extras/cloud

If you do not have a key pair that you will use to connect to the EC2 instances
allocated by the playbooks, now is a good time to create one

    $ ssh-keygen -q -f ~/.ssh/*key_name* -b 2048 -t rsa

If it the first time you install the awscli on your machine, you will want
to also setup the ~/.aws/config and ~/.aws/credentials file.

    $ cat ~/.aws/credentials
    [default]
    aws_access_key_id = *from AWS*
    aws_secret_access_key = *from AWS*

    $ cat ~/.aws/config
    [default]
    region = *region we run commands against*

Let's clone the drop repository to a known place on our local machine.

    $ mkdir -p deploy/reps
    $ cd deploy/reps
    $ git clone https://github.com/djaodjin/drop.git

Then we create configuration files with specific information about our
infrastructure such as AWS region, AWS credentials, etc.

    $ cd drop
    $ mkdir -p playbooks/group_vars
    $ cat playbooks/group_vars/all
    # Variables to connect to AWS
    aws_account: *AWS accountID (used in S3 bucket policies)*
    aws_region: *AWS region where resources are allocated*

    # Variables to create EC2 instances
    key_name: *Key used to first ssh into an instance*
    aws_zone: *EBS/EC2 must be in the same zone.*
    instance_type: *EC2 instance type (t2.micro, etc.)*
    ami_id: *Image on which an EC2 instance is based.*

    # Application variables
    ssh_port: *Public port on which SSH daemon listens*
    tag_prefix: *All resources will be prefixed by tag_prefix*
    castle_gate_name: *Security group for http servers*
    courtyard_name: *Security group for the worker machines*
    kitchen_door_name: *Security group for backstage servers*
    vault_name: *Security group for the databases machines*
    watch_tower_name: *Security group for the smtp servers*
    domain_name: *Domain name for your organization*
    webapp: *name of the web application to deploy*
    ldapPasswordHash: *hash of the root password for LDAP*

    # Directories on local machine
    identities_dir: *Where keys and certificates could be found*

    # URLs to fetch code repositories
    remote_src_top: *Root of where git repositories are found*
    remote_dservices_repo: *where the deployment scripts can be found*

    $ cat $VIRTUAL_ENV/etc/ansible/hosts
    [local]
    localhost ansible_python_interpreter=*VIRTUAL_ENV*/bin/python

Here are the identities file we need to deploy to the instance profiles

    *identities_dir*/identities/dbs.internal/
        etc/pki/tls/certs/dbs.internal.crt
        etc/pki/tls/private/dbs.internal.key
    *identities_dir*/identities/web.internal/
        etc/pki/tls/certs/dbs.internal.crt
        etc/pki/tls/certs/*example.com*.crt
        etc/pki/tls/certs/*wildcard-example.com*.crt
        etc/pki/tls/private/*example.com*.key
        etc/pki/tls/certs/*wildcard-example.com*.key
        etc/pki/tls/certs/dhparam.pem (optional to speed-up deployment)
        home/fedora/.ssh/config
        home/fedora/.ssh/*remote_src_top*_rsa
        home/fedora/.ssh/*remote_src_top*_rsa.pub
    *identities_dir*/*webapp*/
        credentials
        site.conf

In development, we will generate throw away, self-signed, certificates
for all identities:

    $ openssl req -new -sha256 -newkey rsa:2048 -nodes \
        -keyout *example.com*.key -out *example.com*.csr
    $ openssl x509 -req -days 365 -in *example.com*.csr \
        -signkey *example.com*.key -out *example.com*.crt

It is now time to run the playbooks! Our playbooks are organized
in `provisioning, deploying and decommisioning groups<https://djaodjin.com/blog/organizing-ansible-playbooks.blog>`_.
We run them in order:

    # Provisioning the S3 bucket, VPC, EC2 security groups and IAM roles
    $ ansible-playbook -i $VIRTUAL_ENV/etc/ansible/hosts \
        aws-create-authorized.yml

    # Deploying EC2 instances
    $ ansible-playbook -i $VIRTUAL_ENV/etc/ansible/hosts \
        aws-create-instances.yml

    # Decommisioning
    $ ansible-playbook -i ../vendor/ec2.py aws-delete-instances.yml
    $ ansible-playbook -i $VIRTUAL_ENV/etc/ansible/hosts \
         aws-delete-authorized.yml


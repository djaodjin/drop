Starting with the Ansible playbooks
===================================

First we must install the minimal prerequisites

    $ virtualenv deploy
    $ source deploy/bin/activate
    $ pip install awscli boto ansible
    Successfully installed ... awscli-1.8.2 boto-2.38.0 ansible-1.9.3 ...
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
    aws_region: *AWS region where resources are allocated*

    # Variables to create EC2 instances
    key_name: *Key used to first ssh into an instance*
    aws_zone: *EBS volumes and EC2 instances must be in the same zone.*
    instance_type: *EC2 instance type (t2.micro, etc.)*
    ami_id: *Image on which an EC2 instance is based.*

    # Logical grouping
    tag_prefix: *All resource names will be prefixed by tag_prefix*

    # Directories on local machine
    identities_dir: *Where keys and certificates could be found*

    $ cat $VIRTUAL_ENV/etc/ansible/hosts
    [local]
    localhost ansible_python_interpreter=*VIRTUAL_ENV*/bin/python

It is now time to run the playbooks! Our playbooks are organized
in `provisioning, deploying and decommisioning groups<https://djaodjin.com/blog/organizing-ansible-playbooks.blog>`_.
We run them in order:

    # Provisioning
    $ ansible-playbook -i $VIRTUAL_ENV/etc/ansible/hosts \
        aws-create-authorized.yml
    $ ansible-playbook -i $VIRTUAL_ENV/etc/ansible/hosts \
        aws-create-instances.yml

    # Deploying
    $ ansible-playbook -i ../vendor/ec2.py deploy-kitchen-door.yml
    $ ansible-playbook -i ../vendor/ec2.py deploy-watch-tower.yml

    # Decommisioning
    $ ansible-playbook -i ../vendor/ec2.py aws-delete-instances.yml
    $ ansible-playbook -i $VIRTUAL_ENV/etc/ansible/hosts \
         aws-delete-authorized.yml


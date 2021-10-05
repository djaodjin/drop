Provisioning AWS resources
==========================

Notes on command line snipsets
------------------------------

On command line snipsets, lines starting with a `$` character indicate
a shell prompt, or a command for you to type. Lines that do not start
with a `$` character, indicate a sample output from that command.
Example:

    $ whoami
    ec2-user

Sometimes you will see `diff` command lines looking like this:

    $ diff -u ~/.aws/djaoapp
    [default]
    -ssh_key_name = ec2-stage-key
    +ssh_key_name = ec2-production-key

These `diff` commands should not be executed. They represent the lines
you should remove (starting with `-`) and the lines you should add (starting
with `+`) from the file specified on the `diff` command line (~/.aws/djaoapp
in the example above). Other lines are used for context and should remain
unchanged.


Step by step
-------------

Create the network environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Create a configuration file in ~/.aws
The filename will be used to tag all resources created by the provisioning
script. Inside that configuration file, define the region you want to deploy
into and the CIDR block you want to use for the VPC.
Example:

    $ cat ~/.aws/djaoapp

    [default]
    region_name = __region_name__
    vpc_cidr = 192.168.0.0/16

2. Create a ssh key to connect to the EC2 instances (optional)

    $ ssh-keygen -f ~/.ssh/ec2-production-key -t rsa -b 4096 -a 100
    $ diff -u ~/.aws/djaoapp
    +ssh_key_name = ec2-production-key

4. Run dcloud

    $ dcloud --dry-run


Add a postgresql database
~~~~~~~~~~~~~~~~~~~~~~~~~

1. Create TLS certificates

    $ cd /Volumes/identities/__region_name__/__internal_domain_name__
    $ openssl req -new -sha256 -newkey rsa:2048 -nodes \
        -keyout /etc/pki/tls/private/__internal_domain_name__.key \
        -out /etc/pki/tls/certs/__internal_domain_name__.csr

    # Self-signing
    $ openssl x509 -req -days 365 \
        -in /etc/pki/tls/certs/__internal_domain_name__.csr \
        -signkey /etc/pki/tls/private/__internal_domain_name__.key \
        -out /etc/pki/tls/certs/__internal_domain_name__.crt

2. Upload identities

    $ cd /Volumes/identities/__region_name__
    $ aws s3 cp __internal_domain_name__ \
        s3://__identities_bucket__/identities/__region_name__/__internal_domain_name__ \
        --recursive

3. Update configuration file in ~/.aws

    $ diff -u ~/.aws/djaoapp
    [default]
    # ImageID for AWS Linux in __region_name__
    +image_name = ami-******

    +[dbs-1]
    +db_password = [*** REDACTED ***]

4. Run dcloud

    $ dcloud --skip-create-network --dry-run


(When using RDS)
    $ diff -u ~/.aws/djaoapp
    +[dbs-1]
    +db_master_user =
    +db_master_password =
    +db_user =
    +db_password =
    +provider = rds


Add an application container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    $ cat ~/.aws/djaoapp
    ...
    [djaodjin]
    instance_type = t3a.medium
    app_subnet_id = ???


Create a webfront AMI
~~~~~~~~~~~~~~~~~~~~~

The webfront AMI is used as a base for all proxy instances.

1. Create a djaoapp.tar.bz2 package and upload it to
s3://__identities_bucket__/identities/__region_name__/djaoapp-__tag_name__/var/www/djaoapp.tar.bz2

2. Create config

    $ cat ~/.aws/djaoapp
    ...
    [djaoapp-*tag*]
    identities_url = s3://__identities_bucket__/identities/__region_name__/djaoapp-__tag_name__
    ami = 1

3. Run dcloud

    $ dcloud --skip-create-network --dry-run

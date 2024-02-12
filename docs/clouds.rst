Provisioning AWS resources
==========================

Notes on command line snipsets
------------------------------

On command line snipsets, lines starting with a `$` character indicate
a shell prompt, or a command for you to type. Lines that do not start
with a `$` character, indicate a sample output from that command.
Example:

.. code-block:: bash

    $ whoami
    ec2-user

Sometimes you will see `diff` command lines looking like this:

.. code-block:: bash

    $ diff -u ~/.aws/djaoapp
    [default]
    -ssh_key_name = ec2-stage-key
    +ssh_key_name = ec2-production-key

These `diff` commands should not be executed. They represent the lines
you should remove (starting with `-`) and the lines you should add (starting
with `+`) from the file specified on the `diff` command line (~/.aws/djaoapp
in the example above). Other lines are used for context and should remain
unchanged.

The `dcloud` command supports a `--dry-run` command line argument that
can be used to run through a configuration without making any change
to the AWS infrastructure. This is useful for debugging.

The `dcloud` command also supports a `--skip-create-network` command line
argument that skips creating/checking VPCs, Subnets, etc. This is useful
to speed up deployment when you have only made modifications affecting
applications and databases.


Step by step
-------------

Create the network environment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Create a configuration file in ~/.aws
The filename will be used to tag all resources created by the provisioning
script. Inside that configuration file, define the region you want to deploy
into and the CIDR block you want to use for the VPC.
Example:

.. code-block:: bash

    $ cat ~/.aws/djaoapp

    [default]
    region_name = *region_name*
    vpc_cidr = 192.168.0.0/16

2. Create a ssh key to connect to the EC2 instances (optional)

.. code-block:: bash

    $ ssh-keygen -f ~/.ssh/ec2-production-key -t rsa -b 4096 -a 100
    $ diff -u ~/.aws/djaoapp
    +ssh_key_name = ec2-production-key

4. Run dcloud

.. code-block:: bash

    $ dcloud


Add a sally instance
~~~~~~~~~~~~~~~~~~~~

1. Check the LDAP TLS certificate is in the identities directory

.. code-block:: bash

    $ cd /Volumes/identities/*region_name*/sally
    $ find . -type f
        etc/pki/tls/certs/ldaps.*region_name*.internal.crt

2. Upload identities

.. code-block:: bash

    $ cd /Volumes/identities/*region_name*
    $ aws s3 cp sally \
        s3://*identities_bucket*/identities/*region_name*/sally \
        --recursive

3. Update configuration file in ~/.aws

.. code-block:: bash

    $ diff -u ~/.aws/djaoapp
    [default]
    # ImageID for AWS Linux in *region_name*
    +image_name = ami-******

    +[sally]
    +identities_url = s3://*identities_bucket*/identities/*region_name*/sally
    +ssh_port = *ssh_port*

4. Run dcloud

.. code-block:: bash

    $ dcloud --skip-create-network


Add a postgresql database
~~~~~~~~~~~~~~~~~~~~~~~~~

1. Create TLS certificates

.. code-block:: bash

    $ cd /Volumes/identities/*region_name*/*internal_domain_name*
    $ openssl req -new -sha256 -newkey rsa:2048 -nodes \
        -keyout /etc/pki/tls/private/*internal_domain_name*.key \
        -out /etc/pki/tls/certs/*internal_domain_name*.csr

    # Self-signing
    $ openssl x509 -req -days 365 \
        -in /etc/pki/tls/certs/*internal_domain_name*.csr \
        -signkey /etc/pki/tls/private/*internal_domain_name*.key \
        -out /etc/pki/tls/certs/*internal_domain_name*.crt

2. Upload identities

.. code-block:: bash

    $ cd /Volumes/identities/*region_name*
    $ aws s3 cp *internal_domain_name* \
        s3://*identities_bucket*/identities/*region_name*/*internal_domain_name* \
        --recursive

3. Update configuration file in ~/.aws

.. code-block:: bash

    $ diff -u ~/.aws/djaoapp
    [default]
    # ImageID for AWS Linux in *region_name*
    +image_name = ami-******

    +[dbs-1]
    +db_password = [*** REDACTED ***]

4. Run dcloud

.. code-block:: bash

    $ dcloud --skip-create-network

(When using RDS)

.. code-block:: bash

    $ diff -u ~/.aws/djaoapp
    +[dbs-1]
    +db_master_user =
    +db_master_password =
    +db_user =
    +db_password =
    +provider = rds


Restore a postgresql database
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Copy the backup of each database you want to restore into the
*identities_bucket* S3 bucket, add the names of those databases
in the config section and follow the steps from the previous
section "Add a postgresql database".

1. Prepare the identities

.. code-block:: bash

    $ aws s3 cp *db_name*.sql.gz \
        s3://*identities_bucket*/identities/*region_name*/dbs-1

2. Update configuration file

.. code-block:: bash

    $ diff -u ~/.aws/djaoapp
    [default]
    # ImageID for AWS Linux in *region_name*
    +image_name = ami-******

    +[dbs-1]
    +db_password = [*** REDACTED ***]
    db_names=*db_name*

3. Run dcloud

.. code-block:: bash

    $ dcloud --skip-create-network


Add an application container
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    $ cat ~/.aws/djaoapp
    ...
    [djaodjin]
    instance_type = t3a.medium
    app_subnet_id = subnet-*****


Create a webfront AMI
~~~~~~~~~~~~~~~~~~~~~

The webfront AMI is used as a base for all proxy instances.

1. Create a djaoapp.tar.bz2 package and upload it to
s3://*identities_bucket*/identities/*region_name*/djaoapp-*tag_name*/var/www/djaoapp.tar.bz2

2. Create config

.. code-block:: bash

    $ cat ~/.aws/djaoapp
    ...
    [djaoapp-*tag*]
    identities_url = s3://*identities_bucket*/identities/*region_name*/djaoapp-*tag_name*
    ami = 1

3. Run dcloud

.. code-block:: bash

    $ dcloud --skip-create-network

Reference for dcloud config
===========================

The dcloud config file (defaults to ~/.aws/djaoapp) is an INI-formatted text
file that describes instances running in a environment. The structure of the
network is implicitely described by dcloud itself.

Each section contains the following configuration variables. When the variable
is not defined, it defaults to the definition in the region section, then
the default section when the variable is not defined in the region section
either.

- ``aws_account_id``
  AWS account ID

- ``app_subnet_id``
  The Subnet ID to create the instance hosting applications

- ``company_domain``
  The company name used to configure LDAP domain

- ``elb_arn``
  The Elastic load balancer (cache)

- ``hosted_zone_id``
  The Route53 zone to create internal DNS

- ``identities_url``
  Where to copy the identities file from.

- ``image_name``
  The image to use to create an instance

- ``instance_type``
  The type of instance created (ex: t3.micro)

- ``ldap_host``
  The LDAP hosting identities that can SSH into the instances

- ``profiles``
  The profiles to configure the instance with

- ``region_name``
  The region in which instances are created.

- ``sally_ip``
  The IP address / domainname to SSH into the instances

- ``sally_port``
  The port to SSH into the instances

- ``security_group_name``
  The security group to create the instance in.

- ``ssh_key_name``
  The SSH key name to login with the default cloud user (ec2-user, centos,
  fedora, etc.)

- ``storage_enckey``
  The KMS key used to encrypt storage

- ``subnet_id``
  The Subnet ID to create the instance in.

- ``s3_logs_bucket``
  The S3 bucket where logs are stored

- ``s3_identities_bucket``
  The S3 bucket where identities file are copied from into the instance
  on creation.

- ``vpc_cidr``
  The VPC CIDR (defaults to `172.31.0.0/16`)

- ``vpc_id``
  The VPC ID that matches the VCP CIDR



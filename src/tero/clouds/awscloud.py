# Copyright (c) 2019, Djaodjin Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import argparse, configparser, json, logging, os, random, time

import boto3
import botocore.exceptions


LOGGER = logging.getLogger(__name__)
NB_RETRIES = 2
RETRY_WAIT_DELAY = 15


def _split_fullchain(fullchain):
    """
    Returns a tuple (certificate, chain) from a fullchain certificate.
    """
    header = '\n-----END CERTIFICATE-----\n'
    crts = fullchain.split(header)
    if crts:
        if crts[-1] == '':
            crts = crts[0:-1]
        certs = [crt + header for crt in crts]
        cert = certs[0]
        chain = ''.join(certs[1:])
        return cert, chain
    raise RuntimeError('invalid fullchain certificate')


def create_network(region_name, dbs_zone_name, vpc_cidr,
                   tls_priv_key=None, tls_fullchain_cert=None,
                   ssh_key_name=None, ssh_key_content=None,
                   sally_ip=None, tag_prefix=None,
                   dry_run=False):
    """
    This function creates in a specified AWS region the network infrastructure
    required to run a SaaS product. It will:

    - create a VPC
    - create a Gateway
    - create proxy and db security groups
    - create an Application ELB
    - create uploads and logs S3 buckets
    - create IAM roles and instance profiles

    (Optional)
    - adds permission to connect from SSH port to security groups
    - import SSH keys
    """
    dot_parts, length = vpc_cidr.split('/')
    dot_parts = dot_parts.split('.')
    cidr_prefix = '.'.join(dot_parts[:2])
    web_subnet_cidrs = [
        '%s.0.0/20' % cidr_prefix,
        '%s.16.0/20' % cidr_prefix,
        '%s.32.0/20' % cidr_prefix,
        '%s.48.0/20' % cidr_prefix]
    dbs_subnet_cidrs = [
        '%s.64.0/20' % cidr_prefix]

    if not tag_prefix:
        tag_prefix = [random.choice("abcdef")] + "".join(
            [random.choice("abcdef0123456789") for i in range(4)])

    ec2_client = boto3.client('ec2', region_name=region_name)
    resp = ec2_client.describe_availability_zones()
    zone_ids = sorted([zone['ZoneId'] for zone in resp['AvailabilityZones']])
    LOGGER.info("%s creates web subnets using zone to cidr mapping: %s",
        tag_prefix,
        {zone_id: web_subnet_cidrs[idx]
         for idx, zone_id in enumerate(zone_ids)})
    LOGGER.info("%s creates dbs subnets using zone to cidr mapping: %s",
        tag_prefix,
        {dbs_zone_name: dbs_subnet_cidrs[0]})

    # Create a VPC
    resp = ec2_client.describe_vpcs(
        Filters=[{'Name': 'tag:Prefix', 'Values': [tag_prefix]}])
    if resp['Vpcs']:
        vpc_id = resp['Vpcs'][0]['VpcId']
        LOGGER.info("%s found VPC %s", tag_prefix, vpc_id)
    else:
        resp = ec2_client.create_vpc(
            DryRun=dry_run,
            CidrBlock=vpc_cidr,
            AmazonProvidedIpv6CidrBlock=False,
            InstanceTenancy='default')
        vpc_id = resp['Vpc']['VpcId']
        ec2_client.create_tags(
            DryRun=dry_run,
            Resources=[vpc_id],
            Tags=[
                {'Key': "Prefix", 'Value': tag_prefix},
                {'Key': "Name", 'Value': "%s-vpc" % tag_prefix}])
        LOGGER.info("%s created VPC %s", tag_prefix, vpc_id)

    # Create subnets for app, dbs and web services
    dbs_subnet_id = None
    web_subnet_by_zones = {zone_id: None for zone_id in zone_ids}
    resp = ec2_client.describe_subnets(
        Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]},
                 {'Name': 'availability-zone', 'Values': [dbs_zone_name]},
                 {'Name': 'tag:Prefix', 'Values': [tag_prefix]}])
    for subnet in resp['Subnets']:
        if subnet['CidrBlock'] == dbs_subnet_cidrs[0]:
            dbs_subnet_id = subnet['SubnetId']
            LOGGER.info("%s found dbs subnet %s", tag_prefix, dbs_subnet_id)
    if not dbs_subnet_id:
        resp = ec2_client.create_subnet(
            AvailabilityZone=dbs_zone_name,
            CidrBlock=dbs_subnet_cidrs[0],
            VpcId=vpc_id,
            DryRun=dry_run)
        dbs_subnet_id = resp['Subnet']['SubnetId']
        ec2_client.create_tags(
            DryRun=dry_run,
            Resources=[dbs_subnet_id],
            Tags=[
                {'Key': "Prefix", 'Value': tag_prefix},
                {'Key': "Name", 'Value': "%s databases subnet" % tag_prefix}])
        LOGGER.info("%s created dbs subnet %s", tag_prefix, dbs_subnet_id)
        resp = ec2_client.modify_subnet_attribute(
            SubnetId=dbs_subnet_id,
            MapPublicIpOnLaunch={'Value': False})

    for idx, zone_id in enumerate(zone_ids):
        resp = ec2_client.describe_subnets(Filters=[
            {'Name': 'vpc-id', 'Values': [vpc_id]},
            {'Name': 'availability-zone-id', 'Values': [zone_id]},
            {'Name': 'tag:Prefix', 'Values': [tag_prefix]}])
        for subnet in resp['Subnets']:
            if subnet['CidrBlock'] == web_subnet_cidrs[idx]:
                web_subnet_by_zones[zone_id] = subnet['SubnetId']
                LOGGER.info("%s found web subnet %s in zone %s",
                    tag_prefix, web_subnet_by_zones[zone_id], zone_id)

    for idx, zone_id in enumerate(zone_ids):
        web_subnet_id = web_subnet_by_zones[zone_id]
        if not web_subnet_id:
            resp = ec2_client.create_subnet(
                AvailabilityZoneId=zone_id,
                CidrBlock=web_subnet_cidrs[idx],
                VpcId=vpc_id,
                DryRun=dry_run)
            web_subnet_by_zones[zone_id] = resp['Subnet']['SubnetId']
            web_subnet_id = web_subnet_by_zones[zone_id]
            ec2_client.create_tags(
                DryRun=dry_run,
                Resources=[web_subnet_id],
                Tags=[
                    {'Key': "Prefix", 'Value': tag_prefix},
                    {'Key': "Name",
                     'Value': "%s web subnet" % tag_prefix}])
            LOGGER.info("%s created web subnet %s in zone %s",
                        tag_prefix, web_subnet_id, zone_id)
            resp = ec2_client.modify_subnet_attribute(
                SubnetId=web_subnet_id,
                MapPublicIpOnLaunch={'Value': False})
    app_subnet_id = web_subnet_by_zones[zone_ids[0]]

    # Ensure that the VPC has an Internet Gateway.
    resp = ec2_client.describe_internet_gateways(
        Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])
    if resp['InternetGateways']:
        igw_id = resp['InternetGateways'][0]['InternetGatewayId']
        LOGGER.info("%s found Internet Gateway %s", tag_prefix, igw_id)
    else:
        resp = ec2_client.describe_internet_gateways(
            Filters=[{'Name': 'tag:Prefix', 'Values': [tag_prefix]}])
        if resp['InternetGateways']:
            igw_id = resp['InternetGateways'][0]['InternetGatewayId']
            LOGGER.info("%s found Internet Gateway %s", tag_prefix, igw_id)
        else:
            resp = ec2_client.create_internet_gateway(DryRun=dry_run)
            igw_id = resp['InternetGateway']['InternetGatewayId']
            ec2_client.create_tags(
                DryRun=dry_run,
                Resources=[igw_id],
                Tags=[{'Key': "Prefix", 'Value': tag_prefix},
                      {'Key': "Name",
                       'Value': "%s internet gateway" % tag_prefix}])
            LOGGER.info("%s created Internet Gateway %s", tag_prefix, igw_id)
        resp = ec2_client.attach_internet_gateway(
            DryRun=dry_run,
            InternetGatewayId=igw_id,
            VpcId=vpc_id)

    # Create the NAT gateway by which private subnet connects to Internet
    # XXX Why do we have a Network interface eni-****?
    resp = ec2_client.describe_addresses(
        Filters=[{'Name': 'tag:Prefix', 'Values': [tag_prefix]}])
    if resp['Addresses']:
        nat_elastic_ip = resp['Addresses'][0]['AllocationId']
        LOGGER.info("%s found NAT gateway public IP %s",
            tag_prefix, nat_elastic_ip)
    else:
        resp = ec2_client.allocate_address(
            DryRun=dry_run,
            Domain='vpc')
        nat_elastic_ip = resp['AllocationId']
        ec2_client.create_tags(
            DryRun=dry_run,
            Resources=[nat_elastic_ip],
            Tags=[{'Key': "Prefix", 'Value': tag_prefix},
                  {'Key': "Name",
                   'Value': "%s NAT gateway public IP" % tag_prefix}])
        LOGGER.info("%s created NAT gateway public IP %s",
            tag_prefix, nat_elastic_ip)

    client_token = tag_prefix
    resp = ec2_client.describe_nat_gateways(Filters=[
        {'Name': "subnet-id", 'Values': [app_subnet_id]},
        {'Name': "state", 'Values': ['pending', 'available']}])
    if resp['NatGateways']:
        nat_gateway_id = resp['NatGateways'][0]['NatGatewayId']
        LOGGER.info("%s found NAT gateway %s", tag_prefix, nat_gateway_id)
    else:
        resp = ec2_client.create_nat_gateway(
            AllocationId=nat_elastic_ip,
            ClientToken=client_token,
            SubnetId=app_subnet_id)
        nat_gateway_id = resp['NatGateway']['NatGatewayId']
        ec2_client.create_tags(
            DryRun=dry_run,
            Resources=[nat_gateway_id],
            Tags=[{'Key': "Prefix", 'Value': tag_prefix},
                  {'Key': "Name",
                   'Value': "%s NAT gateway" % tag_prefix}])
        LOGGER.info("%s created NAT gateway %s",
            tag_prefix, nat_gateway_id)

    # Set up public and NAT-protected route tables
    resp = ec2_client.describe_route_tables(
        Filters=[{'Name': "vpc-id", 'Values': [vpc_id]}])
    public_route_table_id = None
    private_route_table_id = None
    for route_table in resp['RouteTables']:
        for route in route_table['Routes']:
            if 'GatewayId' in route and route['GatewayId'] == igw_id:
                public_route_table_id = route_table['RouteTableId']
                LOGGER.info("%s found public route table %s",
                    tag_prefix, public_route_table_id)
                break
            elif ('NatGatewayId' in route and
                  route['NatGatewayId'] == nat_gateway_id):
                private_route_table_id = route_table['RouteTableId']
                LOGGER.info("%s found private route table %s",
                    tag_prefix, private_route_table_id)
    if not public_route_table_id:
        resp = ec2_client.create_route_table(
            DryRun=dry_run,
            VpcId=vpc_id)
        public_route_table_id = resp['RouteTable']['RouteTableId']
        ec2_client.create_tags(
            DryRun=dry_run,
            Resources=[public_route_table_id],
            Tags=[
                {'Key': "Prefix", 'Value': tag_prefix},
                {'Key': "Name", 'Value': "%s public" % tag_prefix}])
        LOGGER.info("%s created public subnet route table %s",
            tag_prefix, public_route_table_id)
        resp = ec2_client.create_route(
            DryRun=dry_run,
            DestinationCidrBlock='0.0.0.0/0',
            GatewayId=igw_id,
            RouteTableId=public_route_table_id)
        resp = ec2_client.associate_route_table(
            DryRun=dry_run,
            RouteTableId=public_route_table_id,
            SubnetId=app_subnet_id)
        LOGGER.info(
            "%s associated public route table %s to first web subnet %s",
            tag_prefix, public_route_table_id, app_subnet_id)

    if not private_route_table_id:
        resp = ec2_client.create_route_table(
            DryRun=dry_run,
            VpcId=vpc_id)
        private_route_table_id = resp['RouteTable']['RouteTableId']
        ec2_client.create_tags(
            DryRun=dry_run,
            Resources=[private_route_table_id],
            Tags=[
                {'Key': "Prefix", 'Value': tag_prefix},
                {'Key': "Name", 'Value': "%s internal" % tag_prefix}])
        private_route_table_id = resp['RouteTable']['RouteTableId']
        LOGGER.info("%s created private route table %s",
            tag_prefix, private_route_table_id)
        for _ in range(0, NB_RETRIES):
            # The NAT Gateway takes some time to be fully operational.
            try:
                resp = ec2_client.create_route(
                    DryRun=dry_run,
                    DestinationCidrBlock='0.0.0.0/0',
                    NatGatewayId=nat_gateway_id,
                    RouteTableId=private_route_table_id)
                resp = ec2_client.associate_route_table(
                    DryRun=dry_run,
                    RouteTableId=private_route_table_id,
                    SubnetId=dbs_subnet_id)
                LOGGER.info(
                    "%s associated private route table %s to dbs subnet %s",
                    tag_prefix, private_route_table_id, dbs_subnet_id)
            except botocore.exceptions.ClientError as err:
                if not err.response.get('Error', {}).get(
                        'Code', 'Unknown') == 'InvalidNatGatewayID.NotFound':
                    raise
            time.sleep(RETRY_WAIT_DELAY)

    # Create the ELB, proxies and databases security groups
    # The app security group (as the instance role) will be specific
    # to the application.
    moat_sg_id = None
    vault_sg_id = None
    gate_sg_id = None
    kitchen_door_sg_id = None
    moat_name = '%s-moat' % tag_prefix
    vault_name = '%s-vault' % tag_prefix
    gate_name = '%s-castle-gate' % tag_prefix
    kitchen_door_name = '%s-kitchen-door' % tag_prefix
    resp = ec2_client.describe_security_groups(
        Filters=[{'Name': "vpc-id", 'Values': [vpc_id]}])
    for security_group in resp['SecurityGroups']:
        if security_group['GroupName'] == moat_name:
            moat_sg_id = security_group['GroupId']
            LOGGER.info("%s found %s security group %s",
                tag_prefix, moat_name, moat_sg_id)
        elif security_group['GroupName'] == vault_name:
            vault_sg_id = security_group['GroupId']
            LOGGER.info("%s found %s security group %s",
                tag_prefix, vault_name, vault_sg_id)
        elif security_group['GroupName'] == gate_name:
            gate_sg_id = security_group['GroupId']
            LOGGER.info("%s found %s security group %s",
                tag_prefix, gate_name, gate_sg_id)
        elif security_group['GroupName'] == kitchen_door_name:
            kitchen_door_sg_id = security_group['GroupId']
            LOGGER.info("%s found %s security group %s",
                tag_prefix, kitchen_door_name, kitchen_door_sg_id)
    if not moat_sg_id:
        resp = ec2_client.create_security_group(
            Description='%s ELB' % tag_prefix,
            GroupName=moat_name,
            VpcId=vpc_id,
            DryRun=dry_run)
        moat_sg_id = resp['GroupId']
        LOGGER.info("%s created %s security group %s",
            tag_prefix, moat_name, moat_sg_id)
    if not gate_sg_id:
        resp = ec2_client.create_security_group(
            Description='%s session managers' % tag_prefix,
            GroupName=gate_name,
            VpcId=vpc_id,
            DryRun=dry_run)
        gate_sg_id = resp['GroupId']
        LOGGER.info("%s created %s security group %s",
            tag_prefix, gate_name, gate_sg_id)
    if not vault_sg_id:
        resp = ec2_client.create_security_group(
            Description='%s databases' % tag_prefix,
            GroupName=vault_name,
            VpcId=vpc_id,
            DryRun=dry_run)
        vault_sg_id = resp['GroupId']
        LOGGER.info("%s created %s security group %s",
            tag_prefix, vault_name, vault_sg_id)
    # moat allow rules
    try:
        resp = ec2_client.authorize_security_group_ingress(
            DryRun=dry_run,
            GroupId=moat_sg_id,
            CidrIp='0.0.0.0/0',
            IpProtocol='tcp',
            FromPort=80,
            ToPort=80)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'InvalidPermission.Duplicate':
            raise
    try:
        resp = ec2_client.authorize_security_group_ingress(
            DryRun=dry_run,
            GroupId=moat_sg_id,
            CidrIp='0.0.0.0/0',
            IpProtocol='tcp',
            FromPort=443,
            ToPort=443)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'InvalidPermission.Duplicate':
            raise
    # castle-gate allow rules
    try:
        resp = ec2_client.authorize_security_group_ingress(
            DryRun=dry_run,
            GroupId=gate_sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 80,
                'ToPort': 80,
                'UserIdGroupPairs': [{'GroupId': moat_sg_id}]
            }])
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'InvalidPermission.Duplicate':
            raise
    try:
        resp = ec2_client.authorize_security_group_ingress(
            DryRun=dry_run,
            GroupId=gate_sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 443,
                'ToPort': 443,
                'UserIdGroupPairs': [{'GroupId': moat_sg_id}]
            }])
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'InvalidPermission.Duplicate':
            raise
    try:
        resp = ec2_client.authorize_security_group_egress(
            DryRun=dry_run,
            GroupId=gate_sg_id,
            IpPermissions=[{
                'IpProtocol': '-1',
                'IpRanges': [{
                    'CidrIp': '0.0.0.0/0',
                }]}])
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'InvalidPermission.Duplicate':
            raise
    # vault allow rules
    try:
        resp = ec2_client.authorize_security_group_ingress(
            DryRun=dry_run,
            GroupId=vault_sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 5432,
                'ToPort': 5432,
                'UserIdGroupPairs': [{'GroupId': gate_sg_id}]
            }])
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'InvalidPermission.Duplicate':
            raise
    try:
        resp = ec2_client.authorize_security_group_egress(
            DryRun=dry_run,
            GroupId=vault_sg_id,
            IpPermissions=[{
                'IpProtocol': '-1',
                'IpRanges': [{
                    'CidrIp': '0.0.0.0/0',
                }]}])
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'InvalidPermission.Duplicate':
            raise

    # Create a Application ELB
    elb_client = boto3.client('elbv2', region_name=region_name)
    resp = elb_client.create_load_balancer(
        Name='%s-elb' % tag_prefix,
        Subnets=list(web_subnet_by_zones.values()),
        SecurityGroups=[
            gate_sg_id,
        ],
        Scheme='internet-facing',
        Type='application',
        Tags=[{'Key': "Prefix", 'Value': tag_prefix}])
    load_balancer = resp['LoadBalancers'][0]
    load_balancer_arn = load_balancer['LoadBalancerArn']
    load_balancer_dns = load_balancer['DNSName']
    LOGGER.info("%s found/created application load balancer %s available at %s",
        tag_prefix, load_balancer_arn, load_balancer_dns)

    resp = elb_client.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol='HTTP',
        Port=80,
        DefaultActions=[{
            "Type": "redirect",
            "RedirectConfig": {
                "Protocol": "HTTPS",
                "Port": "443",
                "Host": "#{host}",
                "Path": "/#{path}",
                "Query": "#{query}",
                "StatusCode": "HTTP_301"
            }
        }])
    LOGGER.info("%s found/created application HTTP listener for %s",
        tag_prefix, load_balancer_arn)

    # We will need a default TLS certificate for creating an HTTPS listener.
    default_cert_location = None
    resp = elb_client.describe_listeners(
        LoadBalancerArn=load_balancer_arn)
    for listener in resp['Listeners']:
        if listener['Protocol'] == 'HTTPS':
            for certificate in listener['Certificates']:
                print("XXX certificate: %s" % str(certificate))
                if 'IsDefault' not in certificate or certificate['IsDefault']:
                    default_cert_location = certificate['CertificateArn']
                    LOGGER.info("%s found default TLS certificate %s",
                        tag_prefix, default_cert_location)
                    break
    if not default_cert_location:
        if tls_priv_key and tls_fullchain_cert:
            acm_client = boto3.client('acm', region_name=region_name)
            cert, chain = _split_fullchain(tls_fullchain_cert)
            resp = acm_client.import_certificate(
                Certificate=cert.encode('ascii'),
                PrivateKey=tls_priv_key.encode('ascii'),
                CertificateChain=chain.encode('ascii'))
            default_cert_location = resp['CertificateArn']
            LOGGER.info("%s imported TLS certificate %s",
                tag_prefix, default_cert_location)
        else:
            LOGGER.warning("default_cert_location is not set and there are no"\
                " tls_priv_key and tls_fullchain_cert either.")

    resp = elb_client.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol='HTTPS',
        Port=443,
        Certificates=[{'CertificateArn': default_cert_location}],
        DefaultActions=[{
            'Type': 'fixed-response',
            'FixedResponseConfig': {
                'MessageBody': '%s ELB' % tag_prefix,
                'StatusCode': '200',
                'ContentType': 'text/plain'
            }
        }])
    LOGGER.info("%s found/created application load balancer listeners for %s",
        tag_prefix, load_balancer_arn)

    # Create uploads and logs S3 buckets
#XXX    s3_logs_bucket = '%-logs' % tag_prefix
    s3_logs_bucket = 'djaodjin-logs'
    s3_uploads_bucket = '%s-uploads' % tag_prefix
    s3_client = boto3.client('s3')
    try:
        resp = s3_client.create_bucket(
            ACL='private',
            Bucket=s3_logs_bucket,
            CreateBucketConfiguration={
                'LocationConstraint': region_name
            })
        LOGGER.info("%s found/created S3 bucket for logs %s",
            tag_prefix, s3_logs_bucket)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'BucketAlreadyOwnedByYou':
            raise
    try:
        resp = s3_client.create_bucket(
            ACL='private',
            Bucket=s3_uploads_bucket,
            CreateBucketConfiguration={
                'LocationConstraint': region_name
            })
        LOGGER.info("%s found/created S3 bucket for uploads %s",
            tag_prefix, s3_uploads_bucket)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'BucketAlreadyOwnedByYou':
            raise

    # Create instance profiles
    gate_role = gate_name
    vault_role = vault_name
    iam_client = boto3.client('iam')
    try:
        resp = iam_client.create_role(
            RoleName=gate_role,
            AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }))
        iam_client.put_role_policy(
            RoleName=gate_role,
            PolicyName='SendsControlMessagesToAgent',
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": [
                        "sqs:ReceiveMessage",
                        "sqs:DeleteMessage"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }]}))
        iam_client.put_role_policy(
            RoleName=gate_role,
            PolicyName='WriteslogsToStorage',
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": [
                        "s3:PutObject"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::%s/*" % s3_logs_bucket,
                        "arn:aws:s3:::%s" % s3_logs_bucket
                    ]
                }]}))
        iam_client.put_role_policy(
            RoleName=gate_role,
            PolicyName='AccessesUploadedDocuments',
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": [
                        "s3:GetObject",
                        # XXX Without `s3:GetObjectAcl` and `s3:ListBucket`
                        # cloud-init cannot run
                        # `aws s3 cp s3://... / --recursive`
                        "s3:GetObjectAcl",
                        "s3:ListBucket",
                        "s3:PutObject"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::%s" % s3_uploads_bucket,
                        "arn:aws:s3:::%s/*" % s3_uploads_bucket
                    ]
                }]}))
        LOGGER.info("%s created IAM role %s", tag_prefix, gate_role)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'EntityAlreadyExists':
            raise
        LOGGER.info("%s found IAM role %s", tag_prefix, gate_role)
    try:
        resp = iam_client.create_instance_profile(
            InstanceProfileName=gate_role)
        iam_instance_profile = resp['InstanceProfile']['Arn']
        LOGGER.info("%s created IAM instance profile '%s'",
            tag_prefix, iam_instance_profile)
        iam_client.add_role_to_instance_profile(
            InstanceProfileName=gate_role,
            RoleName=gate_role)
        LOGGER.info("%s created IAM instance profile for %s: %s",
            tag_prefix, gate_role, iam_instance_profile)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'EntityAlreadyExists':
            raise
        LOGGER.info("%s found IAM instance profile for %s",
            tag_prefix, gate_role)

    # Create role and instance profile for databases
    try:
        resp = iam_client.create_role(
            RoleName=vault_name,
            AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }))
        iam_client.put_role_policy(
            RoleName=vault_role,
            PolicyName='WriteslogsToStorage',
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    # XXX We are uploading logs
                    "Action": [
                        "s3:PutObject"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::%s/*" % s3_logs_bucket,
                        "arn:aws:s3:::%s" % s3_logs_bucket
                    ]
                }]
            }))
        LOGGER.info("%s created IAM role %s", tag_prefix, vault_name)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'EntityAlreadyExists':
            raise
        LOGGER.info("%s found IAM role %s", tag_prefix, vault_name)

    try:
        resp = iam_client.create_instance_profile(
            InstanceProfileName=vault_role)
        iam_instance_profile = resp['InstanceProfile']['Arn']
        LOGGER.info("%s created IAM instance profile '%s'",
            tag_prefix, iam_instance_profile)
        iam_client.add_role_to_instance_profile(
            InstanceProfileName=vault_role,
            RoleName=vault_role)
        LOGGER.info("%s created IAM instance profile for %s: %s",
            tag_prefix, vault_role, iam_instance_profile)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'EntityAlreadyExists':
            raise
        LOGGER.info("%s found IAM instance profile for %s",
            tag_prefix, vault_role)

    if ssh_key_name and ssh_key_content and sally_ip:
        # import SSH keys
        try:
            resp = ec2_client.import_key_pair(
                DryRun=dry_run,
                KeyName=ssh_key_name,
                PublicKeyMaterial=ssh_key_content)
            LOGGER.info("%s imported SSH key %s", tag_prefix, ssh_key_name)
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'InvalidKeyPair.Duplicate':
                raise
            LOGGER.info("%s found SSH key %s", tag_prefix, ssh_key_name)

        # Create role and instance profile for sally (aka kitchen door)
        kitchen_door_role = kitchen_door_name
        try:
            resp = iam_client.create_role(
                RoleName=kitchen_door_role,
                AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }))
            iam_client.put_role_policy(
                RoleName=kitchen_door_role,
                PolicyName='WriteslogsToStorage',
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        # XXX We are uploading logs
                        "Action": [
                            "s3:PutObject"
                        ],
                        "Effect": "Allow",
                        "Resource": [
                            "arn:aws:s3:::%s/*" % s3_logs_bucket,
                            "arn:aws:s3:::%s" % s3_logs_bucket
                        ]
                    }]
                }))
            LOGGER.info("%s created IAM role %s", tag_prefix, kitchen_door_role)
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'EntityAlreadyExists':
                raise
            LOGGER.info("%s found IAM role %s", tag_prefix, kitchen_door_role)

        try:
            resp = iam_client.create_instance_profile(
                InstanceProfileName=kitchen_door_role)
            iam_instance_profile = resp['InstanceProfile']['Arn']
            LOGGER.info("%s created IAM instance profile '%s'",
                tag_prefix, iam_instance_profile)
            iam_client.add_role_to_instance_profile(
                InstanceProfileName=kitchen_door_role,
                RoleName=kitchen_door_role)
            LOGGER.info("%s created IAM instance profile for %s: %s",
                tag_prefix, kitchen_door_role, iam_instance_profile)
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'EntityAlreadyExists':
                raise
            LOGGER.info("%s found IAM instance profile for %s",
                tag_prefix, kitchen_door_role)

        # allows SSH connection to instances for debugging
        if not kitchen_door_sg_id:
            resp = ec2_client.create_security_group(
                Description='%s ELB' % tag_prefix,
                GroupName=kitchen_door_name,
                VpcId=vpc_id,
                DryRun=dry_run)
            kitchen_door_sg_id = resp['GroupId']
            LOGGER.info("%s created %s security group %s",
                tag_prefix, kitchen_door_name, kitchen_door_sg_id)

        try:
            resp = ec2_client.authorize_security_group_ingress(
                DryRun=dry_run,
                GroupId=kitchen_door_sg_id,
                CidrIp='%s/32' % sally_ip,
                IpProtocol='tcp',
                FromPort=22,
                ToPort=22)
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'InvalidPermission.Duplicate':
                raise
        try:
            resp = ec2_client.authorize_security_group_egress(
                DryRun=dry_run,
                GroupId=kitchen_door_sg_id,
                IpPermissions=[{
                    'IpProtocol': '-1',
                    'IpRanges': [{
                        'CidrIp': '0.0.0.0/0',
                    }]}])
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'InvalidPermission.Duplicate':
                raise
        try:
            resp = ec2_client.authorize_security_group_ingress(
                DryRun=dry_run,
                GroupId=gate_sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'UserIdGroupPairs': [{'GroupId': kitchen_door_sg_id}]
                }])
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'InvalidPermission.Duplicate':
                raise
        try:
            resp = ec2_client.authorize_security_group_ingress(
                DryRun=dry_run,
                GroupId=vault_sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'UserIdGroupPairs': [{'GroupId': kitchen_door_sg_id}]
                }])
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'InvalidPermission.Duplicate':
                raise


def create_datastores(region_name):
    """
    This function creates in a specified AWS region the disk storage (S3) and
    databases (SQL) to run a SaaS product. It will:

    - create S3 buckets for media uploads and write-only logs
    - create a SQL database
    """
    pass


def main(input_args):
    """
    Main entry point to run creation of AWS resources
    """
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--dry-run', action='store_true',
        default=False,
        help='Do not create resources')
    parser.add_argument(
        '--prefix', action='store',
        default='djaoapp', # XXX defaults to None
        help='prefix used to tag the resources created.')
    parser.add_argument(
        '--config', action='store',
        default=os.path.join(os.getenv('HOME'), '.aws', 'djaoapp'),
        help='configuration file')

    args = parser.parse_args(input_args[1:])
    config = configparser.ConfigParser()
    params = config.read(args.config)
    LOGGER.info("read configuration from %s", args.config)
    for section in config.sections():
        LOGGER.info("[%s]", section)
        for key, val in config.items(section):
            LOGGER.info("%s = %s", key, val)

    tls_priv_key = None
    tls_fullchain_cert = None
    tls_priv_key_path = config['default']['tls_priv_key_path']
    tls_fullchain_path = config['default']['tls_fullchain_path']
    if tls_priv_key_path and tls_fullchain_path:
        with open(tls_priv_key_path) as priv_key_file:
            tls_priv_key = priv_key_file.read()
        with open(tls_fullchain_path) as fullchain_file:
            tls_fullchain_cert = fullchain_file.read()

    ssh_key_name = config['default']['ssh_key_name']
    with open(os.path.join(os.getenv('HOME'), '.ssh', '%s.pub' % ssh_key_name),
              'rb') as ssh_key_obj:
        ssh_key_content = ssh_key_obj.read()

    create_network(
        config['default']['region_name'],
        config['default']['dbs_zone_name'],
        config['default']['vpc_cidr'],
        tls_priv_key=tls_priv_key,
        tls_fullchain_cert=tls_fullchain_cert,
        ssh_key_name=ssh_key_name,
        ssh_key_content=ssh_key_content,
        sally_ip=config['default']['sally_ip'],
        tag_prefix=args.prefix,
        dry_run=args.dry_run)

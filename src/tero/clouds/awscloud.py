# Copyright (c) 2020, Djaodjin Inc.
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

#pylint:disable=too-many-statements,too-many-locals,too-many-arguments
#pylint:disable=too-many-lines

import argparse, configparser, datetime, json, logging, os, re, time

import boto3
import botocore.exceptions
import jinja2
import OpenSSL.crypto
from pyasn1.codec.der.decoder import decode as asn1_decoder
from pyasn1_modules.rfc2459 import SubjectAltName
from pyasn1.codec.native.encoder import encode as nat_encoder
import six


LOGGER = logging.getLogger(__name__)

EC2_PENDING = 'pending'
EC2_RUNNING = 'running'
EC2_SHUTTING_DOWN = 'shutting-down'
EC2_TERMINATED = 'terminated'
EC2_STOPPING = 'stopping'
EC2_STOPPED = 'stopped'

NB_RETRIES = 2
RETRY_WAIT_DELAY = 15


def _check_certificate(public_cert_content, priv_key_content,
                       domain=None, at_time=None):
    """
    Extract the domain names out of the `public_cert_content`.
    """
    result = {}
    # Read the private key and public certificate
    try:
        priv_key = OpenSSL.crypto.load_privatekey(
            OpenSSL.crypto.FILETYPE_PEM, priv_key_content)
    except OpenSSL.crypto.Error as err:
        result.update({'ssl_certificate_key': {
            'state': 'invalid', 'detail': str(err)}})
        priv_key = None

    try:
        public_cert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, public_cert_content)
    except OpenSSL.crypto.Error as err:
        result.update({'ssl_certificate': {
            'state': 'invalid', 'detail': str(err)}})
        public_cert = None

    if priv_key and public_cert:
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        context.use_privatekey(priv_key)
        context.use_certificate(public_cert)
        try:
            context.check_privatekey()
        except OpenSSL.SSL.Error:
            result.update({'ssl_certificate': {'state': 'invalid',
                'detail': "certificate does not match private key."}})

    if result:
        raise RuntimeError(result)

    not_after = public_cert.get_notAfter()
    if not isinstance(not_after, six.string_types):
        not_after = not_after.decode('utf-8')
    not_after = datetime.datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
    common_name = public_cert.get_subject().commonName
    alt_names = []
    for ext_idx in range(0, public_cert.get_extension_count()):
        extension = public_cert.get_extension(ext_idx)
        if extension.get_short_name().decode('utf-8') == 'subjectAltName':
            # data of the X509 extension, encoded as ASN.1
            decoded_alt_names, _ = asn1_decoder(
                extension.get_data(), asn1Spec=SubjectAltName())
            for alt in nat_encoder(decoded_alt_names):
                alt_name = alt['dNSName'].decode('utf-8')
                if alt_name != common_name:
                    alt_names += [alt_name]
    if domain:
        found = False
        for alt_name in [common_name] + alt_names:
            regex = alt_name.replace('.', r'\.').replace('*', r'.*') + '$'
            if re.match(regex, domain) or alt_name == domain:
                found = True
                break
        if not found:
            result.update({'ssl_certificate': {'state': 'invalid',
                'detail': "domain name (%s) does not match common or alt names"\
                " present in certificate (%s, %s)." % (
                    domain, common_name, ','.join(alt_names))}})
    if at_time:
        if not_after <= at_time:
            result.update({'ssl_certificate': {'state': 'invalid',
                'detail': "certificate is only valid until %s." % not_after}})

    if result:
        raise RuntimeError(result)

    result.update({'ssl_certificate': {
        'common_name': common_name,
        'alt_names': alt_names,
        'state': result.get('ssl_certificate', {}).get('state', 'valid'),
        'issuer': public_cert.get_issuer().organizationName,
        'ends_at': not_after.isoformat()}})
    return result


def _clean_tag_prefix(tag_prefix):
    if tag_prefix:
        if not tag_prefix.endswith('-'):
            tag_prefix = tag_prefix + '-'
    else:
        tag_prefix = ""
    return tag_prefix


def _get_instance_profile(role_name, iam_client=None,
                          region_name=None, tag_prefix=None):
    """
    Returns the instance profile arn based of its name.
    """
    tag_prefix = _clean_tag_prefix(tag_prefix)
    if not iam_client:
        iam_client = boto3.client('iam', region_name=region_name)
    try:
        resp = iam_client.get_instance_profile(
            InstanceProfileName=role_name)
        instance_profile_arn = resp['InstanceProfile']['Arn']
        LOGGER.info("%s found IAM instance profile '%s'",
            tag_prefix, instance_profile_arn)
    except botocore.exceptions.ClientError as err:
        instance_profile_arn = None
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'NoSuchEntity':
            raise
    return instance_profile_arn


def _get_load_balancer(tag_prefix, region_name=None, elb_client=None):
    tag_prefix = _clean_tag_prefix(tag_prefix)
    if not elb_client:
        elb_client = boto3.client('elbv2', region_name=region_name)
    resp = elb_client.describe_load_balancers(
        Names=['%selb' % tag_prefix], # XXX matching `create_load_balancer`
    )
    load_balancer = resp['LoadBalancers'][0]
    load_balancer_arn = load_balancer['LoadBalancerArn']
    load_balancer_dns = load_balancer['DNSName']
    LOGGER.info("%s found application load balancer %s available at %s",
        tag_prefix, load_balancer_arn, load_balancer_dns)
    return load_balancer_arn, load_balancer_dns


def _get_listener(tag_prefix, load_balancer_arn=None,
                  elb_client=None, region_name=None):
    tag_prefix = _clean_tag_prefix(tag_prefix)
    if not elb_client:
        elb_client = boto3.client('elbv2', region_name=region_name)
    if not load_balancer_arn:
        #pylint:disable=unused-variable
        load_balancer_arn, load_balancer_dns = _get_load_balancer(
            tag_prefix, region_name=region_name, elb_client=elb_client)
    resp = elb_client.describe_listeners(
        LoadBalancerArn=load_balancer_arn)
    for listener in resp['Listeners']:
        if listener['Protocol'] == 'HTTPS':
            https_listener_arn = listener['ListenerArn']
    LOGGER.info("%s found HTTPS listener %s for %s",
        tag_prefix, https_listener_arn, load_balancer_arn)
    return https_listener_arn


def _get_or_create_storage_enckey(region_name, tag_prefix, kms_client=None):
    kms_key_arn = None
    if not kms_client:
        kms_client = boto3.client('kms', region_name=region_name)
    resp = kms_client.list_keys()
    for key in resp['Keys']:
        try:
            tags_resp = kms_client.list_resource_tags(KeyId=key['KeyId'])
            for tag in tags_resp['Tags']:
                if tag['TagKey'] == 'Prefix' and tag['TagValue'] == tag_prefix:
                    kms_key_arn = key['KeyArn']
                    LOGGER.info("%s found KMS key %s", tag_prefix, kms_key_arn)
                    break
        except botocore.exceptions.ClientError as err:
            # It is possible we can list and use a key but not list the tags
            # This is the case for the "Default master key that protects
            # my ACM private keys when no other key is defined"
            if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'AccessDeniedException':
                raise
        if kms_key_arn:
            break
    if not kms_key_arn:
        resp = kms_client.create_key(
            Description='%s storage encrypt/decrypt' % tag_prefix,
            Tags=[{'TagKey': "Prefix", 'TagValue': tag_prefix}])
        kms_key_arn = resp['KeyMetadata']['KeyArn']
        LOGGER.info("%s created KMS key %s", tag_prefix, kms_key_arn)
    return kms_key_arn


def _get_subnet_by_zones(subnet_cidrs, tag_prefix,
                         vpc_id=None,
                         zone_ids=None, zone_names=None,
                         ec2_client=None, region_name=None):
    """
    Returns the subnet_id in which databases should be created.

    If neither `zone_ids` nor `zone_names` are specified,
    all zones are considered.
    """
    if not ec2_client:
        ec2_client = boto3.client('ec2', region_name=region_name)
    if not vpc_id:
        vpc_id = _get_vpc_id(tag_prefix, ec2_client=ec2_client)
    zone_id_to_name = {}
    if not zone_ids:
        resp = ec2_client.describe_availability_zones()
        if zone_names:
            zone_ids = sorted([
                zone['ZoneId'] for zone in resp['AvailabilityZones']
                if zone['ZoneName'] in zone_names])
        else:
            zone_ids = sorted([
                zone['ZoneId'] for zone in resp['AvailabilityZones']])
        zone_id_to_name = {zone['ZoneId']:zone['ZoneName']
            for zone in resp['AvailabilityZones']}
    subnet_by_zones = {}
    for zone_id in zone_ids:
        resp = ec2_client.describe_subnets(Filters=[
            {'Name': 'vpc-id', 'Values': [vpc_id]},
            {'Name': 'availability-zone-id', 'Values': [zone_id]}])
        for subnet in resp['Subnets']:
            for subnet_cidr in subnet_cidrs:
                if subnet['CidrBlock'] == subnet_cidr:
                    subnet_by_zones[zone_id] = subnet['SubnetId']
                    LOGGER.info(
                        "%s found subnet %s in zone %s (%s) for cidr %s",
                        tag_prefix, subnet_by_zones[zone_id], zone_id,
                        zone_id_to_name.get(zone_id, 'ukwn'),
                        subnet_cidr)
                    break
            if (zone_id in subnet_by_zones and subnet_by_zones[zone_id]):
                break
    return subnet_by_zones


def _get_security_group_names(base_names, tag_prefix=None):
    results = []
    for base_name in base_names:
        results += [(
            '%s-%s' % (base_name, tag_prefix) if tag_prefix else base_name)]
    return results


def _get_security_group_ids(group_names, tag_prefix,
                            vpc_id=None, ec2_client=None, region_name=None):
    """
    Returns a list of VPC security Group IDs matching one-to-one
    with the `group_names` passed as argument.
    """
    if not ec2_client:
        ec2_client = boto3.client('ec2', region_name=region_name)
    if not vpc_id:
        vpc_id = _get_vpc_id(tag_prefix, ec2_client=ec2_client)
    resp = ec2_client.describe_security_groups(
        Filters=[{'Name': "vpc-id", 'Values': [vpc_id]}])
    group_ids = [None for _ in group_names]
    for security_group in resp['SecurityGroups']:
        for idx, group_name in enumerate(group_names):
            if security_group['GroupName'] == group_name:
                group_ids[idx] = security_group['GroupId']
                LOGGER.info("%s found %s security group %s",
                    tag_prefix, group_name, group_ids[idx])
    return group_ids


def _get_vpc_id(tag_prefix, ec2_client=None, region_name=None):
    """
    Returns the vpc_id for the application.
    """
    if not ec2_client:
        ec2_client = boto3.client('ec2', region_name=region_name)
    vpc_id = None
    resp = ec2_client.describe_vpcs(
        Filters=[{'Name': 'tag:Prefix', 'Values': [tag_prefix]}])
    if resp['Vpcs']:
        vpc_id = resp['Vpcs'][0]['VpcId']
        LOGGER.info("%s found VPC %s", tag_prefix, vpc_id)
    return vpc_id


def _split_cidrs(vpc_cidr, region_name=None):
    """
    Returns web and dbs subnets cidrs from a `vpc_cidr`.
    """
    dot_parts, length = vpc_cidr.split('/')  #pylint:disable=unused-variable

    dot_parts = dot_parts.split('.')
    cidr_prefix = '.'.join(dot_parts[:2])
    if region_name and region_name == 'us-west-2':
        # XXX 4 availability zones
        web_subnet_cidrs = [
            '%s.0.0/20' % cidr_prefix,
            '%s.16.0/20' % cidr_prefix,
            '%s.32.0/20' % cidr_prefix]
        dbs_subnet_cidrs = [
            '%s.48.16/28' % cidr_prefix]
    else:
        # XXX 4 availability zones
        web_subnet_cidrs = [
            '%s.0.0/20' % cidr_prefix,
            '%s.16.0/20' % cidr_prefix,
            '%s.32.0/20' % cidr_prefix,
            '%s.48.0/20' % cidr_prefix]
        # XXX We need 2 availability regions for RDS?
        dbs_subnet_cidrs = [
            '%s.64.0/20' % cidr_prefix,
            '%s.128.0/20' % cidr_prefix]
    return web_subnet_cidrs, dbs_subnet_cidrs


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


def _store_certificate(fullchain, key, domain=None, tag_prefix=None,
                       region_name=None, acm_client=None):
    """
    This will import or replace an ACM certificate for `domain`.

    aws acm import-certificate \
      --certificate file://cert.pem \
      --private-key file://privkey.pem \
      --private-key file://chain.pem \
      --certificate-arn *arn*
    """
    #pylint:disable=unused-argument
    result = _check_certificate(fullchain, key, domain=domain)
    if not domain:
        domain = result['ssl_certificate']['common_name']
    cert, chain = _split_fullchain(fullchain)
    if not acm_client:
        acm_client = boto3.client('acm', region_name=region_name)
    kwargs = {}
    resp = acm_client.list_certificates()
    for acm_cert in resp['CertificateSummaryList']:
        if acm_cert['DomainName'] == domain:
            LOGGER.info("A certificate for domain %s has already been"\
                " imported as %s - replacing",
                domain, acm_cert['CertificateArn'])
            kwargs['CertificateArn'] = acm_cert['CertificateArn']
            break
    resp = acm_client.import_certificate(
        Certificate=cert.encode('ascii'),
        PrivateKey=key.encode('ascii'),
        CertificateChain=chain.encode('ascii'),
        **kwargs)
    LOGGER.info("%s (re-)imported TLS certificate %s as %s",
                tag_prefix, result['ssl_certificate'], resp['CertificateArn'])
    result.update({'CertificateArn': resp['CertificateArn']})
    return result

def is_aws_ecr(container_location):
    """
    return `True` if the container looks like it is stored in an AWS repository.
    """
    look = re.match(r'^https?://(.*)', container_location)
    if look:
        container_location_no_scheme = look.group(1)
    else:
        container_location_no_scheme = container_location
    return bool(re.match(
            r'^[0-9]+\.dkr\.ecr\.[a-z0-9\-]+\.amazonaws\.com\/.*',
            container_location_no_scheme))


def check_security_group(security_group):
    for rule in security_group['IpPermissions']:
        LOGGER.info("%s: from %d to %d (%s)", security_group['GroupName'],
            rule['FromPort'], rule['ToPort'], str(rule))
    print("XXX %s" % str(security_group['IpPermissionsEgress']))
    for rule in security_group['IpPermissionsEgress']:
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        if from_port and to_port:
            LOGGER.info("%s: from %d to %d (%s)", security_group['GroupName'],
                from_port, to_port, str(rule))
        else:
            LOGGER.info("%s: %s", security_group['GroupName'], str(rule))


def create_elb(tag_prefix, web_subnet_by_zones, moat_sg_id,
               tls_priv_key=None, tls_fullchain_cert=None,
               region_name=None, elb_name=None):
    """
    Creates the Application Load Balancer.
    """
    if not elb_name:
        elb_name = '%s-elb' % tag_prefix
    elb_client = boto3.client('elbv2', region_name=region_name)
    resp = elb_client.create_load_balancer(
        Name=elb_name,
        Subnets=list(web_subnet_by_zones.values()),
        SecurityGroups=[
            moat_sg_id,
        ],
        Scheme='internet-facing',
        Type='application',
        Tags=[{'Key': "Prefix", 'Value': tag_prefix}])
    load_balancer = resp['LoadBalancers'][0]
    load_balancer_arn = load_balancer['LoadBalancerArn']
    load_balancer_dns = load_balancer['DNSName']
    LOGGER.info("%s found/created application load balancer %s available at %s",
        tag_prefix, load_balancer_arn, load_balancer_dns)

    try:
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
        LOGGER.info("%s created HTTP application load balancer listener for %s",
            tag_prefix, load_balancer_arn)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'DuplicateListener':
            raise
        LOGGER.info("%s found HTTP application load balancer listener for %s",
            tag_prefix, load_balancer_arn)

    # We will need a default TLS certificate for creating an HTTPS listener.
    default_cert_location = None
    resp = elb_client.describe_listeners(
        LoadBalancerArn=load_balancer_arn)
    for listener in resp['Listeners']:
        if listener['Protocol'] == 'HTTPS':
            for certificate in listener['Certificates']:
                if 'IsDefault' not in certificate or certificate['IsDefault']:
                    default_cert_location = certificate['CertificateArn']
                    LOGGER.info("%s found default TLS certificate %s",
                        tag_prefix, default_cert_location)
                    break
    if not default_cert_location:
        if tls_priv_key and tls_fullchain_cert:
            resp = _store_certificate(
                tls_fullchain_cert, tls_priv_key,
                tag_prefix=tag_prefix, region_name=region_name)
            default_cert_location = resp['CertificateArn']
        else:
            LOGGER.warning("default_cert_location is not set and there are no"\
                " tls_priv_key and tls_fullchain_cert either.")

    try:
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
        LOGGER.info(
            "%s created HTTPS application load balancer listener for %s",
            tag_prefix, load_balancer_arn)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'DuplicateListener':
            raise
        LOGGER.info("%s found HTTPS application load balancer listener for %s",
            tag_prefix, load_balancer_arn)


def create_network(region_name, vpc_cidr,
                   web_zone_names, dbs_zone_names,
                   tls_priv_key=None, tls_fullchain_cert=None,
                   ssh_key_name=None, ssh_key_content=None,
                   sally_ip=None, tag_prefix=None,
                   storage_enckey=None, s3_logs_bucket=None,
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
#XXX    sg_tag_prefix = tag_prefix
    elb_name = 'webfront-elb'
    sg_tag_prefix = None

    LOGGER.info("Provisions network ...")
    web_subnet_cidrs, dbs_subnet_cidrs = _split_cidrs(
        vpc_cidr, region_name=region_name)

    ec2_client = boto3.client('ec2', region_name=region_name)
    resp = ec2_client.describe_availability_zones()
    zone_ids = sorted([zone['ZoneId'] for zone in resp['AvailabilityZones']])
    zone_id_to_name = {
        zone['ZoneId']:zone['ZoneName'] for zone in resp['AvailabilityZones']}

    web_zone_ids = []
    if web_zone_names:
        for zone_name in web_zone_names:
            for zone in resp['AvailabilityZones']:
                if zone['ZoneName'] == zone_name:
                    web_zone_ids += [zone['ZoneId']]
                    break
    else:
        web_zone_ids = zone_ids[:len(web_subnet_cidrs)]
    LOGGER.info("%s web subnets use zone to cidr mapping: %s",
        tag_prefix,
        {zone_id_to_name[zone_id]: web_subnet_cidrs[idx]
         for idx, zone_id in enumerate(web_zone_ids)})

    # makes sure the db_zone_ids is in the same order as the db_zone_names.
    db_zone_ids = []
    for zone_name in dbs_zone_names:
        for zone in resp['AvailabilityZones']:
            if zone['ZoneName'] == zone_name:
                db_zone_ids += [zone['ZoneId']]
                break
    LOGGER.info("%s dbs subnets use zone to cidr mapping: %s",
        tag_prefix,
        {zone_id_to_name[zone_id]: dbs_subnet_cidrs[idx]
         for idx, zone_id in enumerate(db_zone_ids)})

    # Create a VPC
    vpc_id = _get_vpc_id(tag_prefix, ec2_client=ec2_client)
    if not vpc_id:
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
    dbs_subnet_by_zones = _get_subnet_by_zones(
        dbs_subnet_cidrs, tag_prefix,
        vpc_id=vpc_id, zone_ids=zone_ids, ec2_client=ec2_client)
    for idx, zone_id in enumerate(db_zone_ids):
        dbs_subnet_id = dbs_subnet_by_zones.get(zone_id, None)
        if not dbs_subnet_id:
            resp = ec2_client.create_subnet(
                AvailabilityZoneId=zone_id,
                CidrBlock=dbs_subnet_cidrs[idx],
                VpcId=vpc_id,
                DryRun=dry_run)
            dbs_subnet_by_zones[zone_id] = resp['Subnet']['SubnetId']
            dbs_subnet_id = dbs_subnet_by_zones[zone_id]
            ec2_client.create_tags(
                DryRun=dry_run,
                Resources=[dbs_subnet_id],
                Tags=[
                    {'Key': "Prefix", 'Value': tag_prefix},
                    {'Key': "Name",
                     'Value': "%s databases subnet" % tag_prefix}])
            LOGGER.info("%s created dbs subnet %s", tag_prefix, dbs_subnet_id)
            resp = ec2_client.modify_subnet_attribute(
                SubnetId=dbs_subnet_id,
                MapPublicIpOnLaunch={'Value': False})

    web_subnet_by_zones = _get_subnet_by_zones(
        web_subnet_cidrs, tag_prefix,
        vpc_id=vpc_id, zone_ids=zone_ids, ec2_client=ec2_client)
    for idx, zone_id in enumerate(web_zone_ids):
        web_subnet_id = web_subnet_by_zones.get(zone_id, None)
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
            LOGGER.info("%s created web subnet %s in zone %s (%s)",
                tag_prefix, web_subnet_id, zone_id, zone_id_to_name[zone_id])
            if idx > 0:
                # We are going to associate `web_subnet_by_zones[zone_ids[0]]`
                # to the Internet Gateway. Instances created in that subnet
                # will need a public IP to communicate with rest of the world.
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
    nat_elastic_ip = None
    sally_elastic_ip = None
    resp = ec2_client.describe_addresses(
        Filters=[{'Name': 'tag:Prefix', 'Values': [tag_prefix]}])
    if resp['Addresses']:
        for resp_address in resp['Addresses']:
            for resp_tag in resp_address['Tags']:
                if resp_tag['Key'] == 'Name':
                    if 'NAT gateway' in resp_tag['Value']:
                        nat_elastic_ip = resp_address['AllocationId']
                        break
                    if 'Sally' in resp_tag['Value']:
                        sally_elastic_ip = resp_address['AllocationId']
                        break
    if nat_elastic_ip:
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
    if sally_elastic_ip:
        LOGGER.info("%s found Sally public IP %s",
            tag_prefix, sally_elastic_ip)
    else:
        resp = ec2_client.allocate_address(
            DryRun=dry_run,
            Domain='vpc')
        sally_elastic_ip = resp['AllocationId']
        ec2_client.create_tags(
            DryRun=dry_run,
            Resources=[sally_elastic_ip],
            Tags=[{'Key': "Prefix", 'Value': tag_prefix},
                  {'Key': "Name",
                   'Value': "%s Sally public IP" % tag_prefix}])
        LOGGER.info("%s created Sally public IP %s",
            tag_prefix, sally_elastic_ip)

    client_token = tag_prefix
    # XXX shouldn't it be the first web subnet instead?
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
            if ('NatGatewayId' in route and
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
            except botocore.exceptions.ClientError as err:
                if not err.response.get('Error', {}).get(
                        'Code', 'Unknown') == 'InvalidNatGatewayID.NotFound':
                    raise
            time.sleep(RETRY_WAIT_DELAY)

    associate_route_tables = False # XXX Bypass
    if associate_route_tables:
        resp = ec2_client.associate_route_table(
            DryRun=dry_run,
            RouteTableId=public_route_table_id,
            SubnetId=app_subnet_id)
        LOGGER.info(
            "%s associated public route table %s to first web subnet %s",
            tag_prefix, public_route_table_id, app_subnet_id)
        for idx, zone_id in enumerate(web_zone_ids[1:]):
            web_subnet_id = web_subnet_by_zones[zone_id]
            resp = ec2_client.associate_route_table(
                DryRun=dry_run,
                RouteTableId=private_route_table_id,
                SubnetId=web_subnet_id)
            LOGGER.info(
                "%s associated private route table %s to web subnet %s",
                tag_prefix, private_route_table_id, web_subnet_id)
        for idx, zone_id in enumerate(db_zone_ids):
            db_subnet_id = dbs_subnet_by_zones[zone_id]
            resp = ec2_client.associate_route_table(
                DryRun=dry_run,
                RouteTableId=private_route_table_id,
                SubnetId=db_subnet_id)
            LOGGER.info(
                "%s associated private route table %s to db subnet %s",
                tag_prefix, private_route_table_id, db_subnet_id)

    # Create the ELB, proxies and databases security groups
    # The app security group (as the instance role) will be specific
    # to the application.
    moat_name, vault_name, gate_name, kitchen_door_name = \
        _get_security_group_names([
            'moat', 'vault', 'castle-gate', 'kitchen-door'],
        tag_prefix=sg_tag_prefix)
    moat_sg_id, vault_sg_id, gate_sg_id, kitchen_door_sg_id = \
        _get_security_group_ids(
            [moat_name, vault_name, gate_name, kitchen_door_name],
            tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)

    update_moat_rules = (not moat_sg_id)
    update_gate_rules = (not gate_sg_id)
    update_vault_rules = (not vault_sg_id)
    update_kitchen_door_rules = (not kitchen_door_sg_id)

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
    # kitchen_door_sg_id: Kitchen door security group is created later on
    # if we have ssh keys.

    resp = ec2_client.describe_security_groups(
        DryRun=dry_run,
        GroupIds=[moat_sg_id, vault_sg_id, gate_sg_id])
    for security_group in resp['SecurityGroups']:
        if security_group['GroupId'] == moat_sg_id:
            # moat rules
            check_security_group(security_group)
        elif security_group['GroupId'] == gate_sg_id:
            # castle-gate rules
            check_security_group(security_group)
        elif security_group['GroupId'] == vault_sg_id:
            # vault rules
            check_security_group(security_group)

    # moat allow rules
    if update_moat_rules:
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
    if update_gate_rules:
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
    if update_vault_rules:
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

    # Create uploads and logs S3 buckets
    # XXX need to force private.
    if not s3_logs_bucket:
        s3_logs_bucket = '%s-logs' % tag_prefix
    s3_uploads_bucket = tag_prefix
    s3_client = boto3.client('s3')
    if s3_logs_bucket:
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
    if s3_uploads_bucket:
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
            PolicyName='AgentCtrlMessages',
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
                        "arn:aws:s3:::%s/*" % s3_logs_bucket
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
                        # XXX Without `s3:ListBucket` (and `s3:GetObjectAcl`?)
                        # we cannot do a recursive copy
                        # (i.e. aws s3 cp ... --recursive)
                        "s3:GetObjectAcl",
                        "s3:ListBucket",
                        "s3:PutObject"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::%s" % s3_uploads_bucket,
                        "arn:aws:s3:::%s/*" % s3_uploads_bucket
                    ]
                }, {
                    "Action": [
                        "s3:PutObject"
                    ],
                    "Effect": "Disallow",
                    "Resource": [
                        "arn:aws:s3:::%s/identities/" % s3_uploads_bucket
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
        LOGGER.info("%s add IAM role to instance profile for %s: %s",
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
                        "arn:aws:s3:::%s/*" % s3_logs_bucket
                    ]
                }]
            }))
        iam_client.put_role_policy(
            RoleName=vault_role,
            PolicyName='GetIdentities',
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": [
                        "s3:ListBucket"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::%s" % s3_uploads_bucket
                    ]
                }, {
                    "Action": [
                        "s3:GetObject"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::%s/*" % s3_uploads_bucket
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
        LOGGER.info("%s add IAM role to instance profile for %s: %s",
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
        update_kitchen_door_rules = (not kitchen_door_sg_id)
        if not kitchen_door_sg_id:
            resp = ec2_client.create_security_group(
                Description='%s SSH access' % tag_prefix,
                GroupName=kitchen_door_name,
                VpcId=vpc_id,
                DryRun=dry_run)
            kitchen_door_sg_id = resp['GroupId']
            LOGGER.info("%s created %s security group %s",
                tag_prefix, kitchen_door_name, kitchen_door_sg_id)

        if update_kitchen_door_rules:
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

    # Creates encryption keys (KMS) in region
    if not storage_enckey:
        storage_enckey = _get_or_create_storage_enckey(region_name, tag_prefix)

    # Create an Application ELB
    create_elb(
        tag_prefix, web_subnet_by_zones, moat_sg_id,
        tls_priv_key=tls_priv_key, tls_fullchain_cert=tls_fullchain_cert,
        region_name=region_name, elb_name=elb_name)



def create_datastores(region_name, vpc_cidr, dbs_zone_names,
                      tag_prefix, storage_enckey=None,
                      db_master_user=None, db_master_password=None,
                      identities_url=None, s3_identities_bucket=None,
                      image_name=None, ssh_key_name=None,
                      app_name=None, company_domain=None,
                      ldap_host=None, ldap_password_hash=None):
    """
    This function creates in a specified AWS region the disk storage (S3) and
    databases (SQL) to run a SaaS product. It will:

    - create S3 buckets for media uploads and write-only logs
    - create a SQL database

    `vpc_cidr` is the network mask used for the private IPs.
    `dbs_zone_names` contains the zones in which the SQL databases
    will be hosted.
    """
    native = True   # Use EC2 instances for SQL databases.
    instance_type = 'm3.medium'
    sg_tag_prefix = None

    LOGGER.info("Provisions datastores ...")
    if not app_name:
        app_name = '%s-dbs' % tag_prefix if tag_prefix else "dbs"
    if not identities_url:
        identities_url = "s3://%s/identities/%s" % (
            s3_identities_bucket, app_name)

    # XXX same vault_name as in `create_network`
    vault_name = _get_security_group_names(
        ['vault'], tag_prefix=sg_tag_prefix)[0]
    ec2_client = boto3.client('ec2', region_name=region_name)

    vpc_id = _get_vpc_id(tag_prefix, ec2_client=ec2_client)
    _, dbs_subnet_cidrs = _split_cidrs(vpc_cidr, region_name=region_name)
    dbs_subnet_by_zones = _get_subnet_by_zones(dbs_subnet_cidrs,
        tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    db_subnet_group_subnet_ids = list(dbs_subnet_by_zones.values())

    group_ids = _get_security_group_ids(
        [vault_name], tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    vault_sg_id = group_ids[0]

    if not storage_enckey:
        storage_enckey = _get_or_create_storage_enckey(region_name, tag_prefix)

    if not native:
        # We are going to provision the SQL databases through RDS.
        rds_client = boto3.client('rds', region_name=region_name)
        db_param_group_name = tag_prefix
        try:
            # aws rds describe-db-engine-versions --engine postgres \
            #     --query "DBEngineVersions[].DBParameterGroupFamily"
            rds_client.create_db_parameter_group(
                DBParameterGroupName=db_param_group_name,
                DBParameterGroupFamily='postgres9.6',
                Description='%s parameter group for postgres9.6' % tag_prefix,
                Tags=[
                    {'Key': "Prefix", 'Value': tag_prefix},
                    {'Key': "Name",
                     'Value': "%s-db-parameter-group" % tag_prefix}])
            rds_client.modify_db_parameter_group(
                DBParameterGroupName=db_param_group_name,
                Parameters=[{
                    'ParameterName': "rds.force_ssl",
                    'ParameterValue': "1",
                    'ApplyMethod': "pending-reboot"}])
            LOGGER.info("%s created rds db parameter group '%s'",
                        tag_prefix, db_param_group_name)
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'DBParameterGroupAlreadyExists':
                raise
            LOGGER.info("%s found rds db parameter group '%s'",
                        tag_prefix, db_param_group_name)

        db_subnet_group_name = tag_prefix
        try:
            resp = rds_client.create_db_subnet_group(
                DBSubnetGroupName=db_subnet_group_name,
                SubnetIds=db_subnet_group_subnet_ids,
                DBSubnetGroupDescription='%s db subnet group' % tag_prefix,
                Tags=[
                    {'Key': "Prefix", 'Value': tag_prefix},
                    {'Key': "Name",
                     'Value': "%s-db-subnet-group" % tag_prefix}])
            LOGGER.info("%s created rds db subnet group '%s'",
                        tag_prefix, db_subnet_group_name)
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'DBSubnetGroupAlreadyExists':
                raise
            LOGGER.info("%s found rds db subnet group '%s'",
                        tag_prefix, db_subnet_group_name)

        db_name = tag_prefix
        try:
            resp = rds_client.create_db_instance(
                DBName=db_name,
                DBInstanceIdentifier=tag_prefix,
                AllocatedStorage=20,
                DBInstanceClass='db.t3.medium',
                Engine='postgres',
                # aws rds describe-db-engine-versions --engine postgres
                EngineVersion='9.6.14',
                MasterUsername=db_master_user,
                MasterUserPassword=db_master_password,
                VpcSecurityGroupIds=[vault_sg_id],
                AvailabilityZone=dbs_zone_names[0],
                DBSubnetGroupName=db_subnet_group_name,
                DBParameterGroupName=db_param_group_name,
                BackupRetentionPeriod=30,
                #XXX? CharacterSetName='string',
                #StorageType='string', defaults to 'gp2'
                StorageEncrypted=True,
                KmsKeyId=storage_enckey,
                #XXX MonitoringInterval=123,
                #XXX MonitoringRoleArn='string',
                #XXX EnableIAMDatabaseAuthentication=True|False,
                #XXX EnablePerformanceInsights=True|False,
                #XXX PerformanceInsightsKMSKeyId='string',
                #XXX PerformanceInsightsRetentionPeriod=123,
                #XXX EnableCloudwatchLogsExports=['string'],
                #XXX DeletionProtection=True|False,
                #XXX MaxAllocatedStorage=123
                Tags=[
                    {'Key': "Prefix", 'Value': tag_prefix},
                    {'Key': "Name", 'Value': "%s-db" % tag_prefix}])
            print("XXX [create_db_instance] resp=%s" % str(resp))
            LOGGER.info("%s created rds db '%s'", tag_prefix, db_name)
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'DBInstanceAlreadyExists':
                raise
            LOGGER.info("%s found rds db '%s'", tag_prefix, db_name)
        return db_name # XXX do we have an aws id?
    else:
        # We are going to provision the SQL databases as EC2 instances
        resp = ec2_client.describe_instances(
            Filters=[
                {'Name': 'tag:Name', 'Values': [app_name]},
                {'Name': 'instance-state-name', 'Values': [EC2_RUNNING]}])
        previous_instances_ids = []
        for reserv in resp['Reservations']:
            for instance in reserv['Instances']:
                previous_instances_ids += [instance['InstanceId']]
        if previous_instances_ids:
            LOGGER.info("%s found already running '%s' on instances %s",
                tag_prefix, app_name, previous_instances_ids)
            return previous_instances_ids

        search_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'templates')
        template_loader = jinja2.FileSystemLoader(searchpath=search_path)
        template_env = jinja2.Environment(loader=template_loader)
        template = template_env.get_template("dbs-cloud-init-script.j2")
        user_data = template.render(
            identities_url=identities_url,
            remote_drop_repo="https://github.com/djaodjin/drop.git",
            company_domain=company_domain,
            ldapHost=ldap_host,
            ldapPasswordHash=ldap_password_hash,
            vpc_cidr=vpc_cidr)

        # Find the ImageId
        instance_profile_arn = _get_instance_profile(vault_name)
        image_id = image_name
        if not image_name.startswith('ami-'):
            look = re.match(r'arn:aws:iam::(\d+):', instance_profile_arn)
            aws_account_id = look.group(1)
            resp = ec2_client.describe_images(
                Filters=[
                    {'Name': 'name', 'Values': [image_name]},
                    {'Name': 'owner-id', 'Values': [aws_account_id]}])
            if len(resp['Images']) != 1:
                raise RuntimeError(
                    "Found more than one image named '%s' in account '%s'" % (
                        image_name, aws_account_id))
            image_id = resp['Images'][0]['ImageId']

        # XXX adds encrypted volume
        block_devices = [
            {
                'DeviceName': '/dev/sda1',
                #'VirtualName': 'string',
        # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html
                'Ebs': {
                    'DeleteOnTermination': False,
                    #'Iops': 100, # 'not supported for gp2'
                    #'SnapshotId': 'string',
                    'VolumeSize': 20,
                    'VolumeType': 'gp2'
                },
                #'NoDevice': 'string'
            },
        ]
        if storage_enckey:
            for block_device in block_devices:
                block_device['Ebs'].update({
                    'KmsKeyId': storage_enckey,
                    'Encrypted': True
                })
        resp = ec2_client.run_instances(
            BlockDeviceMappings=block_devices,
            ImageId=image_id,
            KeyName=ssh_key_name,
            InstanceType=instance_type,
            MinCount=1,
            MaxCount=1,
            SubnetId=db_subnet_group_subnet_ids[0],
            # Cannot use `SecurityGroups` with `SubnetId` but can
            # use `SecurityGroupIds`.
            SecurityGroupIds=group_ids,
            IamInstanceProfile={'Arn': instance_profile_arn},
            TagSpecifications=[{
                'ResourceType': "instance",
                'Tags': [{
                    'Key': 'Name',
                    'Value': app_name
                }]}],
            UserData=user_data)
        instance_ids = [
            instance['InstanceId'] for instance in resp['Instances']]
        LOGGER.info("%s started ec2 instances %s for '%s'",
                    tag_prefix, instance_ids, app_name)
        return instance_ids



def create_app_resources(region_name, app_name, image_name,
                         ecr_access_role_arn=None,
                         settings_location=None, settings_crypt_key=None,
                         s3_logs_bucket=None, s3_uploads_bucket=None,
                         ssh_key_name=None,
                         app_subnet_id=None, vpc_id=None, vpc_cidr=None,
                         tag_prefix=None,
                         hosted_zone_id=None,
                         dry_run=False):
    """
    Create the application servers
    """
    tag_prefix = _clean_tag_prefix(tag_prefix)
    gate_name = '%scastle-gate' % tag_prefix
    kitchen_door_name = '%skitchen-door' % tag_prefix
    app_sg_name = '%s%s' % (tag_prefix, app_name)

    ec2_client = boto3.client('ec2', region_name=region_name)
    resp = ec2_client.describe_instances(
        Filters=[
            {'Name': 'tag:Name', 'Values': [app_name]},
            {'Name': 'instance-state-name',
             'Values': [EC2_RUNNING, EC2_STOPPED, EC2_PENDING]}])

    stopped_instances_ids = []
    previous_instances_ids = []
    for reserv in resp['Reservations']:
        for instance in reserv['Instances']:
            previous_instances_ids += [instance['InstanceId']]
            if instance['State']['Name'] == EC2_STOPPED:
                stopped_instances_ids += [instance['InstanceId']]
    if stopped_instances_ids:
        ec2_client.start_instances(
            InstanceIds=stopped_instances_ids,
            DryRun=dry_run)
        LOGGER.info("%s restarted instances %s for '%s'",
            tag_prefix, stopped_instances_ids, app_name)
    if previous_instances_ids:
        LOGGER.info("%s found already running '%s' on instances %s",
            tag_prefix, app_name, previous_instances_ids)
        return previous_instances_ids

    # Create a Queue to communicate with the agent on the EC2 instance.
    # Implementation Note:
    #   strange but no exception thrown when queue already exists.
    sqs = boto3.client('sqs', region_name=region_name)
    resp = sqs.create_queue(QueueName=app_name)
    queue_url = resp.get("QueueUrl")

    search_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'templates')
    template_loader = jinja2.FileSystemLoader(searchpath=search_path)
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template("app-cloud-init-script.j2")
    user_data = template.render(
        settings_location=settings_location if settings_location else "",
        settings_crypt_key=settings_crypt_key if settings_crypt_key else "",
        queue_url=queue_url)

    if not vpc_id:
        vpc_id = _get_vpc_id(tag_prefix, ec2_client=ec2_client)
    if not app_subnet_id:
        #pylint:disable=unused-variable
        web_subnet_cidrs, dbs_subnet_cidrs = _split_cidrs(
            vpc_cidr, region_name=region_name)
        resp = ec2_client.describe_availability_zones()
        zone_ids = sorted([
            zone['ZoneId'] for zone in resp['AvailabilityZones']])
        web_subnet_by_zones = _get_subnet_by_zones(
            web_subnet_cidrs, tag_prefix,
            zone_ids=zone_ids, vpc_id=vpc_id, ec2_client=ec2_client)
        # Use first valid subnet that does not require a public IP.
        for zone_id in zone_ids[1:]:
            subnet_id = web_subnet_by_zones[zone_id]
            if subnet_id:
                app_subnet_id = subnet_id
                break

    group_ids = _get_security_group_ids(
        [app_sg_name, gate_name, kitchen_door_name], tag_prefix,
        vpc_id=vpc_id, ec2_client=ec2_client)
    app_sg_id = group_ids[0]
    gate_sg_id = group_ids[1]
    kitchen_door_sg_id = group_ids[2]
    if not app_sg_id:
        if tag_prefix and tag_prefix.endswith('-'):
            descr = '%s %s' % (tag_prefix[:-1], app_name)
        elif tag_prefix:
            descr = ('%s %s' % (tag_prefix, app_name)).strip()
        else:
            descr = app_name
        resp = ec2_client.create_security_group(
            Description=descr,
            GroupName=app_sg_name,
            VpcId=vpc_id)
        app_sg_id = resp['GroupId']
        LOGGER.info("%s created %s security group %s",
            tag_prefix, app_sg_name, app_sg_id)
    # app_sg_id allow rules
    try:
        resp = ec2_client.authorize_security_group_ingress(
            DryRun=dry_run,
            GroupId=app_sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 80,
                'ToPort': 80,
                'UserIdGroupPairs': [{'GroupId': gate_sg_id}]
            }])
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'InvalidPermission.Duplicate':
            raise
    try:
        resp = ec2_client.authorize_security_group_ingress(
            DryRun=dry_run,
            GroupId=app_sg_id,
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 443,
                'ToPort': 443,
                'UserIdGroupPairs': [{'GroupId': gate_sg_id}]
            }])
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'InvalidPermission.Duplicate':
            raise
    if ssh_key_name:
        try:
            resp = ec2_client.authorize_security_group_ingress(
                DryRun=dry_run,
                GroupId=app_sg_id,
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

    app_role = app_sg_name
    iam_client = boto3.client('iam')
    try:
        resp = iam_client.create_role(
            RoleName=app_role,
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
            RoleName=app_role,
            PolicyName='AgentCtrlMessages',
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
        if ecr_access_role_arn:
            iam_client.put_role_policy(
                RoleName=app_role,
                PolicyName='DeployContainer',
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": [
                            "sts:AssumeRole"
                        ],
                        "Resource": [
                            ecr_access_role_arn
                        ]
                    }, {
                        "Effect": "Allow",
                        "Action": [
                            "ecr:GetAuthorizationToken",
                            "ecr:BatchCheckLayerAvailability",
                            "ecr:GetDownloadUrlForLayer",
                            "ecr:BatchGetImage"
                        ],
                        "Resource": "*"
                    }]}))
        if s3_logs_bucket:
            iam_client.put_role_policy(
                RoleName=app_role,
                PolicyName='WriteslogsToStorage',
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Action": [
                            "s3:PutObject"
                        ],
                        "Effect": "Allow",
                        "Resource": [
                            "arn:aws:s3:::%s/%s/var/log/*" % (
                                s3_logs_bucket, app_name)
                        ]
                    }]}))
        if s3_uploads_bucket:
            iam_client.put_role_policy(
                RoleName=app_role,
                PolicyName='AccessesUploadedDocuments',
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Action": [
                            "s3:GetObject",
                            "s3:PutObject",
                            # XXX Without `s3:GetObjectAcl` and `s3:ListBucket`
                            # cloud-init cannot run a recursive copy
                            # (i.e. `aws s3 cp s3://... / --recursive`)
                            "s3:GetObjectAcl",
                            "s3:ListBucket"
                        ],
                        "Effect": "Allow",
                        "Resource": [
                            "arn:aws:s3:::%s" % s3_uploads_bucket,
                            "arn:aws:s3:::%s/*" % s3_uploads_bucket
                        ]
                    }, {
                        "Action": [
                            "s3:PutObject"
                        ],
                        "Effect": "Disallow",
                        "Resource": [
                            "arn:aws:s3:::%s/identities/" % s3_uploads_bucket
                        ]
                    }]}))
        LOGGER.info("%s created IAM role %s", tag_prefix, app_role)
    except botocore.exceptions.ClientError as err:
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'EntityAlreadyExists':
            raise
        LOGGER.info("%s found IAM role %s", tag_prefix, app_role)

    instance_profile_arn = _get_instance_profile(
        app_role, iam_client=iam_client,
        region_name=region_name, tag_prefix=tag_prefix)
    if not instance_profile_arn:
        resp = iam_client.create_instance_profile(
            InstanceProfileName=app_role)
        instance_profile_arn = resp['InstanceProfile']['Arn']
        LOGGER.info("%s created IAM instance profile '%s'",
            tag_prefix, instance_profile_arn)
        iam_client.add_role_to_instance_profile(
            InstanceProfileName=app_role,
            RoleName=app_role)
        LOGGER.info("%s created IAM instance profile for %s: %s",
            tag_prefix, app_role, instance_profile_arn)

    # Find the ImageId
    look = re.match(r'arn:aws:iam::(\d+):', instance_profile_arn)
    aws_account_id = look.group(1)
    resp = ec2_client.describe_images(
        Filters=[
            {'Name': 'name', 'Values': [image_name]},
            {'Name': 'owner-id', 'Values': [aws_account_id]}])
    if len(resp['Images']) != 1:
        raise RuntimeError(
            "Found more than one image named '%s' in account '%s'" % (
                image_name, aws_account_id))
    image_id = resp['Images'][0]['ImageId']

    instance_ids = None
    instances = None
    for _ in range(0, NB_RETRIES):
        # The IAM instance profile take some time to be visible.
        try:
            # XXX adds encrypted volume
            resp = ec2_client.run_instances(
                ImageId=image_id,
                KeyName=ssh_key_name,
                InstanceType='t3.small',
                MinCount=1,
                MaxCount=1,
                SubnetId=app_subnet_id,
                # Cannot use `SecurityGroups` with `SubnetId` but can
                # use `SecurityGroupIds`.
                SecurityGroupIds=[app_sg_id],
                IamInstanceProfile={'Arn': instance_profile_arn},
                TagSpecifications=[{
                    'ResourceType': "instance",
                    'Tags': [{
                        'Key': 'Name',
                        'Value': app_name
                    }]}],
                UserData=user_data)
            instances = resp['Instances']
            instance_ids = [instance['InstanceId'] for instance in instances]
            break
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'InvalidParameterValue':
                raise
            LOGGER.info("%s waiting for IAM instance profile %s to be"\
                " operational ...", tag_prefix, instance_profile_arn)
        time.sleep(RETRY_WAIT_DELAY)

    LOGGER.info("%s started ec2 instances %s for '%s'",
                tag_prefix, instance_ids, app_name)

    # Associates an internal domain name to the instance
    update_dns_record = True
    if update_dns_record:
        hosted_zone = None
        default_hosted_zone = None
        hosted_zone_name = 'ec2.internal.'
        route53 = boto3.client('route53')
        if hosted_zone_id:
            hosted_zone = route53.get_hosted_zone(Id=hosted_zone_id)
        else:
            hosted_zones_resp = route53.list_hosted_zones()
            hosted_zones = hosted_zones_resp.get('HostedZones')
            for hzone in hosted_zones:
                if hzone.get('Name').startswith(region_name):
                    hosted_zone = hzone
                    break
                if hzone.get('Name') == hosted_zone_name:
                    default_hosted_zone = hzone
        if hosted_zone:
            hosted_zone_name = hosted_zone.get('Name')
            LOGGER.info("found hosted zone %s", hosted_zone_name)
        else:
            hosted_zone_id = default_hosted_zone.get('Id')
            LOGGER.info(
                "cannot find hosted zone for region %s, defaults to %s",
                region_name, hosted_zone_name)

        host_name = "%(app_name)s.%(hosted_zone_name)s" % {
            'app_name': app_name, 'hosted_zone_name': hosted_zone_name}
        LOGGER.info("update DNS record for %s ...", host_name)
        route53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': host_name,
                    'Type': 'A',
                    # 'Region': DEFAULT_REGION
                    'TTL': 60,
                    'ResourceRecords': [
                        {'Value': instance.private_ip_address}
                        for instance in instances]
                }}]})

    return instance_ids

#XXX deprecated...
def create_instances_dbs(region_name, app_name, image_name,
                         identities_url=None, ssh_key_name=None,
                         storage_enckey=None,
                         dbs_subnet_id=None, vpc_id=None, vpc_cidr=None,
                         tag_prefix=None):
    """
    Create the SQL databases server.
    """
    instance_type = 'm3.medium'
    sg_tag_prefix = None

    # XXX same vault_name as in `create_network`
    vault_name = _get_security_group_names(
        ['vault'], tag_prefix=sg_tag_prefix)[0]

    ec2_client = boto3.client('ec2', region_name=region_name)
    resp = ec2_client.describe_instances(
        Filters=[
            {'Name': 'tag:Name', 'Values': [app_name]},
            {'Name': 'instance-state-name', 'Values': [EC2_RUNNING]}])
    previous_instances_ids = []
    for reserv in resp['Reservations']:
        for instance in reserv['Instances']:
            previous_instances_ids += [instance['InstanceId']]
    if previous_instances_ids:
        LOGGER.info("%s found already running '%s' on instances %s",
            tag_prefix, app_name, previous_instances_ids)
        return previous_instances_ids

    search_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'templates')
    template_loader = jinja2.FileSystemLoader(searchpath=search_path)
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template("dbs-cloud-init-script.j2")
    user_data = template.render(identities_url=identities_url)

    if not vpc_id:
        vpc_id = _get_vpc_id(tag_prefix, ec2_client=ec2_client)
    if not dbs_subnet_id:
        #pylint:disable=unused-variable
        web_subnet_cidrs, dbs_subnet_cidrs = _split_cidrs(
            vpc_cidr, region_name=region_name)
        resp = ec2_client.describe_availability_zones()
        zone_ids = sorted([
            zone['ZoneId'] for zone in resp['AvailabilityZones']])
        dbs_subnet_by_zones = _get_subnet_by_zones(
            dbs_subnet_cidrs, tag_prefix,
            zone_ids=zone_ids, vpc_id=vpc_id, ec2_client=ec2_client)
        # Use first valid subnet that does not require a public IP.
        for zone_id in zone_ids[1:]:
            subnet_id = dbs_subnet_by_zones[zone_id]
            if subnet_id:
                dbs_subnet_id = subnet_id
                break

    group_ids = _get_security_group_ids(
        [vault_name], tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    instance_profile_arn = _get_instance_profile(vault_name)

    # Find the ImageId
    image_id = image_name
    if not image_name.startswith('ami-'):
        look = re.match(r'arn:aws:iam::(\d+):', instance_profile_arn)
        aws_account_id = look.group(1)
        resp = ec2_client.describe_images(
            Filters=[
                {'Name': 'name', 'Values': [image_name]},
                {'Name': 'owner-id', 'Values': [aws_account_id]}])
        if len(resp['Images']) != 1:
            raise RuntimeError(
                "Found more than one image named '%s' in account '%s'" % (
                    image_name, aws_account_id))
        image_id = resp['Images'][0]['ImageId']

    # XXX adds encrypted volume
    block_devices = [
        {
            #'DeviceName': '/dev/sda1',
            #'VirtualName': 'string',
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html
            'Ebs': {
                'DeleteOnTermination': False,
                'Iops': 100,
                #'SnapshotId': 'string',
                'VolumeSize': 20,
                'VolumeType': 'gp2'
            },
            #'NoDevice': 'string'
        },
    ]
    if storage_enckey:
        for block_device in block_devices:
            block_device['Ebs'].update({
                'KmsKeyId': storage_enckey,
                'Encrypted': True
            })
    resp = ec2_client.run_instances(
        BlockDeviceMappings=block_devices,
        ImageId=image_id,
        KeyName=ssh_key_name,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=dbs_subnet_id,
        # Cannot use `SecurityGroups` with `SubnetId` but can
        # use `SecurityGroupIds`.
        SecurityGroupIds=group_ids,
        IamInstanceProfile={'Arn': instance_profile_arn},
        TagSpecifications=[{
            'ResourceType': "instance",
            'Tags': [{
                'Key': 'Name',
                'Value': app_name
            }]}],
        UserData=user_data)
    instance_ids = [instance['InstanceId'] for instance in resp['Instances']]
    LOGGER.info("%s started ec2 instances %s for '%s'",
                tag_prefix, instance_ids, app_name)
    return instance_ids


def create_instances_webfront(region_name, app_name, image_name,
                              identities_url=None, ssh_key_name=None,
                              storage_enckey=None,
                              web_subnet_id=None, vpc_id=None, vpc_cidr=None,
                              tag_prefix=None):
    """
    Create the proxy session server connected to the target group.
    """
    gate_name = '%s-castle-gate' % tag_prefix # XXX same as in `create_network`

    ec2_client = boto3.client('ec2', region_name=region_name)
    resp = ec2_client.describe_instances(
        Filters=[
            {'Name': 'tag:Name', 'Values': [app_name]},
            {'Name': 'instance-state-name', 'Values': [EC2_RUNNING]}])
    previous_instances_ids = []
    for reserv in resp['Reservations']:
        for instance in reserv['Instances']:
            previous_instances_ids += [instance['InstanceId']]
    if previous_instances_ids:
        LOGGER.info("%s found already running '%s' on instances %s",
            tag_prefix, app_name, previous_instances_ids)
        return previous_instances_ids

    search_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'templates')
    template_loader = jinja2.FileSystemLoader(searchpath=search_path)
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template("web-cloud-init-script.j2")
    user_data = template.render(identities_url=identities_url)

    if not vpc_id:
        vpc_id = _get_vpc_id(tag_prefix, ec2_client=ec2_client)
    if not web_subnet_id:
        #pylint:disable=unused-variable
        web_subnet_cidrs, dbs_subnet_cidrs = _split_cidrs(
            vpc_cidr, region_name=region_name)
        resp = ec2_client.describe_availability_zones()
        zone_ids = sorted([
            zone['ZoneId'] for zone in resp['AvailabilityZones']])
        web_subnet_by_zones = _get_subnet_by_zones(
            web_subnet_cidrs, tag_prefix,
            zone_ids=zone_ids, vpc_id=vpc_id, ec2_client=ec2_client)
        # Use first valid subnet that does not require a public IP.
        for zone_id in zone_ids[1:]:
            subnet_id = web_subnet_by_zones[zone_id]
            if subnet_id:
                web_subnet_id = subnet_id
                break

    group_ids = _get_security_group_ids(
        [gate_name], tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    instance_profile_arn = _get_instance_profile(gate_name)

    # Find the ImageId
    image_id = image_name
    if not image_name.startswith('ami-'):
        look = re.match(r'arn:aws:iam::(\d+):', instance_profile_arn)
        aws_account_id = look.group(1)
        resp = ec2_client.describe_images(
            Filters=[
                {'Name': 'name', 'Values': [image_name]},
                {'Name': 'owner-id', 'Values': [aws_account_id]}])
        if len(resp['Images']) != 1:
            raise RuntimeError(
                "Found more than one image named '%s' in account '%s'" % (
                    image_name, aws_account_id))
        image_id = resp['Images'][0]['ImageId']

    # XXX adds encrypted volume
    resp = ec2_client.run_instances(
        ImageId=image_id,
        KeyName=ssh_key_name,
        InstanceType='t3.small',
        MinCount=1,
        MaxCount=1,
        SubnetId=web_subnet_id,
        # Cannot use `SecurityGroups` with `SubnetId` but can
        # use `SecurityGroupIds`.
        SecurityGroupIds=group_ids,
        IamInstanceProfile={'Arn': instance_profile_arn},
        TagSpecifications=[{
            'ResourceType': "instance",
            'Tags': [{
                'Key': 'Name',
                'Value': app_name
            }]}],
        UserData=user_data)
    instance_ids = [instance['InstanceId'] for instance in resp['Instances']]
    LOGGER.info("%s started ec2 instances %s for '%s'",
                tag_prefix, instance_ids, app_name)
    return instance_ids

def create_domain_forward(region_name, app_name, valid_domains=None,
                          tls_priv_key=None, tls_fullchain_cert=None,
                          listener_arn=None, target_group=None,
                          tag_prefix=None):
    """
    Create the rules in the load-balancer necessary to forward
    requests for a domain to a specified target group.
    """
    # We attach the certificate to the load balancer listener
    cert_location = None
    if not valid_domains:
        resp = _store_certificate(tls_fullchain_cert, tls_priv_key,
            tag_prefix=tag_prefix, region_name=region_name)
        cert_location = resp['CertificateArn']
        valid_domains = ([resp['ssl_certificate']['common_name']]
            + resp['ssl_certificate']['alt_names'])

    elb_client = boto3.client('elbv2', region_name=region_name)
    #pylint:disable=unused-variable
    load_balancer_arn, load_balancer_dns = _get_load_balancer(
        tag_prefix, region_name=region_name, elb_client=elb_client)
    if not listener_arn:
        listener_arn = _get_listener(tag_prefix,
            load_balancer_arn=load_balancer_arn, elb_client=elb_client,
            region_name=region_name)

    # We add the certificate matching the domain such that we can answer
    # requests for the domain over https.
    if cert_location:
        resp = elb_client.add_listener_certificates(
            ListenerArn=listener_arn,
            Certificates=[{'CertificateArn': cert_location}])

    if not target_group:
        resp = elb_client.describe_target_groups(
            LoadBalancerArn=load_balancer_arn,
            Names=[app_name])
        target_group = resp.get('TargetGroups')[0].get('TargetGroupArn')

    # We create a listener rule to forward https requests to the app.
    rule_arn = None
    resp = elb_client.describe_rules(ListenerArn=listener_arn)
    candidates = set([])
    for rule in resp['Rules']:
        for cond in rule['Conditions']:
            if cond['Field'] == 'host-header':
                for rule_domain in cond['HostHeaderConfig']['Values']:
                    if rule_domain in valid_domains:
                        candidates |= set([rule['RuleArn']])
    if len(candidates) > 1:
        LOGGER.error("%s found multiple rule candidates matching domains %s",
            tag_prefix, candidates)
    if len(candidates) == 1:
        rule_arn = list(candidates)[0]
    if rule_arn:
        elb_client.modify_rule(
            RuleArn=rule_arn,
            Actions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': target_group,
                }
            ])
        LOGGER.info("%s found and modified matching listener rule %s",
            tag_prefix, rule_arn)
    else:
        priority = 1
        for rule in resp['Rules']:
            try:
                rule_priority = int(rule['Priority'])
                if rule_priority >= priority:
                    priority = rule_priority + 1
            except ValueError:
                # When priority == 'default'
                pass
        resp = elb_client.create_rule(
            ListenerArn=listener_arn,
            Priority=priority,
            Conditions=[
                {
                    'Field': 'host-header',
                    'HostHeaderConfig': {
                        'Values': valid_domains
                    }
                }],
            Actions=[
                {
                    'Type': 'forward',
                    'TargetGroupArn': target_group,
                }
            ])
        rule_arn = resp['Rules'][0]['RuleArn']
        LOGGER.info("%s created matching listener rule %s",
            tag_prefix, rule_arn)


def create_target_group(region_name, app_name, instance_ids=None,
                        image_name=None, identities_url=None, ssh_key_name=None,
                        vpc_id=None, vpc_cidr=None, tag_prefix=None):
    """
    Create TargetGroup to forward HTTPS requests to application service.
    """
    if not vpc_id:
        vpc_id = _get_vpc_id(tag_prefix)

    elb_client = boto3.client('elbv2', region_name=region_name)

    resp = elb_client.create_target_group(
        Name=app_name,
        Protocol='HTTPS',
        Port=443,
        VpcId=vpc_id,
        TargetType='instance',
        HealthCheckEnabled=True,
        HealthCheckProtocol='HTTP',
        HealthCheckPort='80',
        HealthCheckPath='/',
        #HealthCheckIntervalSeconds=30,
        #HealthCheckTimeoutSeconds=5,
        #HealthyThresholdCount=5,
        #UnhealthyThresholdCount=2,
        Matcher={
            'HttpCode': '200'
        })
    target_group = resp.get('TargetGroups')[0].get('TargetGroupArn')

    # It is time to attach the instance that will respond to http requests
    # to the target group.
    if not instance_ids:
        instance_ids = create_instances_webfront(
            region_name, app_name, image_name,
            identities_url=identities_url, ssh_key_name=ssh_key_name,
            vpc_id=vpc_id, vpc_cidr=vpc_cidr,
            tag_prefix=tag_prefix)
    if instance_ids:
        for _ in range(0, NB_RETRIES):
            # The EC2 instances take some time to be fully operational.
            try:
                resp = elb_client.register_targets(
                    TargetGroupArn=target_group,
                    Targets=[{
                        'Id': instance_id,
                        'Port': 443
                    } for instance_id in instance_ids])
                LOGGER.info("%s registers instances %s with target group %s",
                    tag_prefix, instance_ids, target_group)
                break
            except botocore.exceptions.ClientError as err:
                LOGGER.info("%s waiting for EC2 instances %s to be"\
                    " in running state ...", tag_prefix, instance_ids)
                if not err.response.get('Error', {}).get(
                        'Code', 'Unknown') == 'InvalidTarget':
                    raise
            time.sleep(RETRY_WAIT_DELAY)

    return target_group


def deploy_app_container(app_name, container_location,
                         role_name=None, external_id=None, env=None,
                         region_name=None, sqs_client=None):
    """
    Sends the message to the agent to (re-)deploy the Docker container.
    """
    queue_name = app_name
    if not sqs_client:
        sqs_client = boto3.client('sqs', region_name=region_name)
    queue_url = sqs_client.get_queue_url(QueueName=queue_name).get('QueueUrl')
    msg = {
        'event': "deploy_container",
        'app_name': app_name,
        'container_location': container_location
    }
    if role_name:
        msg.update({'role_name': role_name})
    if external_id:
        msg.update({'external_id': external_id})
    if env:
        msg.update({'env': env})
    sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(msg))


def upload_app_logs(app_name,
                    region_name=None, sqs_client=None):
    """
    Sends the message to upload the container logs.
    """
    queue_name = app_name
    if not sqs_client:
        sqs_client = boto3.client('sqs', region_name=region_name)
    queue_url = sqs_client.get_queue_url(QueueName=queue_name).get('QueueUrl')
    msg = {
        'event': "upload_logs",
        'app_name': app_name
    }
    sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(msg))


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
        '--skip-create-network', action='store_true',
        default=False,
        help='Assume network resources have already been provisioned')
    parser.add_argument(
        '--prefix', action='store',
        default=None,
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
    tls_priv_key_path = config['default'].get('tls_priv_key_path')
    tls_fullchain_path = config['default'].get('tls_fullchain_path')
    if tls_priv_key_path and tls_fullchain_path:
        with open(tls_priv_key_path) as priv_key_file:
            tls_priv_key = priv_key_file.read()
        with open(tls_fullchain_path) as fullchain_file:
            tls_fullchain_cert = fullchain_file.read()

    ssh_key_content = None
    ssh_key_name = config['default'].get('ssh_key_name')
    if ssh_key_name:
        with open(os.path.join(os.getenv('HOME'),
            '.ssh', '%s.pub' % ssh_key_name), 'rb') as ssh_key_obj:
            ssh_key_content = ssh_key_obj.read()

    tag_prefix = args.prefix
# XXX
#    if not tag_prefix:
#        tag_prefix = [random.choice("abcdef")] + "".join(
#            [random.choice("abcdef0123456789") for i in range(4)])

    storage_enckey = config['default'].get('storage_enckey')
    web_zone_names = config['default'].get('web_zone_names')
    dbs_zone_names = config['default'].get('dbs_zone_names')

    if web_zone_names:
        web_zone_names = [
            zone_name.strip() for zone_name in web_zone_names.split(',')]
    else:
        web_zone_names = []
    if dbs_zone_names:
        dbs_zone_names = [
            zone_name.strip() for zone_name in dbs_zone_names.split(',')]
    else:
        dbs_zone_names = []

    if not args.skip_create_network:
        create_network(
            config['default']['region_name'],
            config['default']['vpc_cidr'],
            web_zone_names,
            dbs_zone_names,
            tls_priv_key=tls_priv_key,
            tls_fullchain_cert=tls_fullchain_cert,
            ssh_key_name=ssh_key_name,
            ssh_key_content=ssh_key_content,
            sally_ip=config['default'].get('sally_ip'),
            storage_enckey=storage_enckey,
            s3_logs_bucket=config['default'].get('s3_logs_bucket'),
            tag_prefix=tag_prefix,
            dry_run=args.dry_run)

    if (('db_master_user' in config['default'] and
        'db_master_password' in config['default']) or
        'dbs_identities_url' in config['default']):
        create_datastores(
            config['default']['region_name'],
            config['default']['vpc_cidr'],
            dbs_zone_names,
            tag_prefix=tag_prefix,
            storage_enckey=storage_enckey,
            db_master_user=config['default'].get('db_master_user'),
            db_master_password=config['default'].get('db_master_password'),
            identities_url=config['default'].get('dbs_identities_url'),
            s3_identities_bucket=config['default'].get('s3_identities_bucket'),
            company_domain=config['default'].get('company_domain'),
            ldap_host=config['default'].get('ldap_host'),
            ldap_password_hash=config['default'].get('ldap_password_hash'),
            image_name=config['default']['image_name'],
            ssh_key_name=ssh_key_name)

    # Create target groups for the applications.
    for app_name in config:
        if app_name.lower() == 'default':
            continue

        if tag_prefix and app_name.startswith(tag_prefix):
            tls_priv_key_path = config[app_name].get('tls_priv_key_path')
            tls_fullchain_path = config[app_name].get('tls_fullchain_path')
            if not tls_priv_key_path or not tls_fullchain_path:
                tls_priv_key_path = config['default']['tls_priv_key_path']
                tls_fullchain_path = config['default']['tls_fullchain_path']
            with open(tls_priv_key_path) as priv_key_file:
                tls_priv_key = priv_key_file.read()
            with open(tls_fullchain_path) as fullchain_file:
                tls_fullchain_cert = fullchain_file.read()
            create_target_group(
                config['default']['region_name'],
                app_name,
                image_name=config[app_name]['image_name'],
                identities_url=config[app_name]['identities_url'],
                ssh_key_name=ssh_key_name,
                vpc_cidr=config['default']['vpc_cidr'],
                tag_prefix=tag_prefix)
            create_domain_forward(
                config['default']['region_name'],
                app_name,
                tls_priv_key=tls_priv_key,
                tls_fullchain_cert=tls_fullchain_cert,
                tag_prefix=tag_prefix)
        else:
            container_location = config[app_name].get('container_location')
            if container_location and is_aws_ecr(container_location):
                ecr_access_role_arn = config[app_name].get(
                    'ecr_access_role_arn')
                role_name = ecr_access_role_arn
            else:
                ecr_access_role_arn = None
                role_name = config[app_name].get('container_access_token')
            create_app_resources(
                config['default']['region_name'],
                app_name,
                config[app_name]['image_name'],
                ecr_access_role_arn=ecr_access_role_arn,
                settings_location=config[app_name].get('settings_location'),
                settings_crypt_key=config[app_name].get('settings_crypt_key'),
                ssh_key_name=ssh_key_name,
                s3_logs_bucket=config['default'].get('s3_logs_bucket'),
                s3_uploads_bucket=config[app_name].get('s3_uploads_bucket'),
                app_subnet_id=config['default'].get('app_subnet_id'),
                vpc_id=config['default'].get('vpc_id'),
                vpc_cidr=config['default'].get('vpc_cidr'),
                tag_prefix=tag_prefix)
            create_domain_forward(
                config['default']['region_name'],
                app_name,
                tls_priv_key=tls_priv_key,
                tls_fullchain_cert=tls_fullchain_cert,
                tag_prefix=tag_prefix)

            # Environment variables is an array of name/value.
            if container_location:
                env = config[app_name].get('env')
                if env:
                    env = json.loads(env)
                deploy_app_container(
                    app_name,
                    container_location,
                    role_name=role_name,
                    external_id=config[app_name].get('external_id'),
                    env=env,
                    region_name=config['default']['region_name'])


if __name__ == '__main__':
    import sys
    main(sys.argv)

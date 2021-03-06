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
from collections import OrderedDict

import boto3
import botocore.exceptions
import jinja2
import OpenSSL.crypto
from pyasn1.codec.der.decoder import decode as asn1_decoder
from pyasn1_modules.rfc2459 import SubjectAltName
from pyasn1.codec.native.encoder import encode as nat_encoder
import six
#pylint:disable=import-error
from six.moves.urllib.parse import urlparse


LOGGER = logging.getLogger(__name__)

APP_NAME = 'djaoapp'

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


def _get_image_id(image_name, instance_profile_arn=None,
                  ec2_client=None, region_name=None):
    """
    Finds an image_id from its name.
    """
    image_id = image_name
    if not image_name.startswith('ami-'):
        if not instance_profile_arn:
            raise RuntimeError("instance_profile_arn must be defined when"\
                " image_name is not already an id.")
        look = re.match(r'arn:aws:iam::(\d+):', instance_profile_arn)
        aws_account_id = look.group(1)
        if not ec2_client:
            ec2_client = boto3.client('ec2', region_name=region_name)
        resp = ec2_client.describe_images(
            Filters=[
                {'Name': 'name', 'Values': [image_name]},
                {'Name': 'owner-id', 'Values': [aws_account_id]}])
        if len(resp['Images']) != 1:
            raise RuntimeError(
                "Found more than one image named '%s' in account '%s': %s" % (
                    image_name, aws_account_id,
                    [image['ImageId'] for image in resp['Images']]))
        image_id = resp['Images'][0]['ImageId']
    return image_id


def _get_instance_profile(role_name, iam_client=None, region_name=None):
    """
    Returns the instance profile arn based of its name.
    """
    if not iam_client:
        iam_client = boto3.client('iam', region_name=region_name)
    try:
        resp = iam_client.get_instance_profile(
            InstanceProfileName=role_name)
        instance_profile_arn = resp['InstanceProfile']['Arn']
    except botocore.exceptions.ClientError as err:
        instance_profile_arn = None
        if not err.response.get('Error', {}).get(
                'Code', 'Unknown') == 'NoSuchEntity':
            raise
    return instance_profile_arn


def _get_load_balancer(tag_prefix, region_name=None, elb_client=None):
    elb_name = None
    tag_prefix = _clean_tag_prefix(tag_prefix)
    if not elb_name:
        elb_name = '%selb' % tag_prefix
    if not elb_client:
        elb_client = boto3.client('elbv2', region_name=region_name)
    resp = elb_client.describe_load_balancers(
        Names=[elb_name], # XXX matching `create_load_balancer`
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


def _get_or_create_storage_enckey(region_name, tag_prefix, kms_client=None,
                                  dry_run=False):
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
        if not dry_run:
            resp = kms_client.create_key(
                Description='%s storage encrypt/decrypt' % tag_prefix,
                Tags=[{'TagKey': "Prefix", 'TagValue': tag_prefix}])
            kms_key_arn = resp['KeyMetadata']['Arn']
        LOGGER.info("%s created KMS key %s", tag_prefix, kms_key_arn)
    return kms_key_arn


def _get_subnet_by_cidrs(subnet_cidrs, tag_prefix,
                         vpc_id=None, ec2_client=None, region_name=None):
    """
    Returns a dictionary keyed by CIDR block that contains the subnet
    and availability zone for that block or `None` if none can be retrieved.
    """
    subnet_by_cidrs = OrderedDict()
    if not ec2_client:
        ec2_client = boto3.client('ec2', region_name=region_name)
    if not vpc_id:
        vpc_id, _ = _get_vpc_id(tag_prefix, ec2_client=ec2_client,
            region_name=region_name)
    for cidr_block in subnet_cidrs:
        resp = ec2_client.describe_subnets(Filters=[
            {'Name': 'vpc-id', 'Values': [vpc_id]},
            {'Name': 'cidr-block', 'Values': [cidr_block]}])
        if len(resp['Subnets']) > 1:
            raise RuntimeError(
                "%s There are more than one subnet for CIDR block %s" % (
                    tag_prefix, cidr_block))
        if resp['Subnets']:
            subnet = resp['Subnets'][0]
            LOGGER.info(
                "%s found subnet %s in zone %s for cidr %s",
                tag_prefix, subnet['SubnetId'], subnet['AvailabilityZone'],
                cidr_block)
            subnet_by_cidrs[cidr_block] = subnet
        else:
            subnet_by_cidrs[cidr_block] = None
    return subnet_by_cidrs


def _get_security_group_names(base_names, tag_prefix=None):
    tag_prefix = _clean_tag_prefix(tag_prefix)
    results = []
    for base_name in base_names:
        if base_name == 'kitchen-door':
            results += [base_name]
        else:
            results += ['%s%s' % (tag_prefix, base_name)]
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
        vpc_id, _ = _get_vpc_id(tag_prefix, ec2_client=ec2_client,
            region_name=region_name)
    resp = ec2_client.describe_security_groups(
        Filters=[{'Name': "vpc-id", 'Values': [vpc_id]}])
    group_ids = [None for _ in group_names]
    for security_group in resp['SecurityGroups']:
        for idx, group_name in enumerate(group_names):
            if security_group['GroupName'] == group_name:
                group_ids[idx] = security_group['GroupId']
    for group_id, group_name in zip(group_ids, group_names):
        if group_id:
            LOGGER.info("%s found %s security group %s",
                tag_prefix, group_name, group_id)
        else:
            LOGGER.warning("%s cannot find security group %s",
                tag_prefix, group_name)
    return group_ids


def _get_vpc_id(tag_prefix, ec2_client=None, region_name=None):
    """
    Returns the vpc_id for the application.
    """
    if not ec2_client:
        ec2_client = boto3.client('ec2', region_name=region_name)
    vpc_id = None
    vpc_cidr = None
    LOGGER.debug("ec2_client.describe_vpcs(Filters=[{'Name': 'tag:Prefix',"\
        " 'Values': ['%s']}])", tag_prefix)
    resp = ec2_client.describe_vpcs(
        Filters=[{'Name': 'tag:Prefix', 'Values': [tag_prefix]}])
    if resp['Vpcs']:
        vpc_data = resp['Vpcs'][0]
        vpc_id = vpc_data['VpcId']
        vpc_cidr = vpc_data['CidrBlock']
        LOGGER.info("%s found VPC %s covering cidr block %s",
            tag_prefix, vpc_id, vpc_cidr)
    return vpc_id, vpc_cidr


def _split_cidrs(vpc_cidr, zones=None, ec2_client=None, region_name=None):
    """
    Returns web and dbs subnets cidrs from a `vpc_cidr`.
    """
    if not zones:
        if not ec2_client:
            ec2_client = boto3.client('ec2', region_name=region_name)
        resp = ec2_client.describe_availability_zones()
        zones = {(zone['ZoneId'], zone['ZoneName'])
            for zone in resp['AvailabilityZones']}

    dot_parts, length = vpc_cidr.split('/')  #pylint:disable=unused-variable

    dot_parts = dot_parts.split('.')
    cidr_prefix = '.'.join(dot_parts[:2])
    if len(zones) >= 3:
        web_subnet_cidrs = [
            '%s.0.0/20' % cidr_prefix,
            '%s.16.0/20' % cidr_prefix,
            '%s.32.0/20' % cidr_prefix]
    if len(zones) >= 4:
        web_subnet_cidrs += [
            '%s.48.0/20' % cidr_prefix]
    # We need 2 availability regions for RDS?
    dbs_subnet_cidrs = [
        '%s.64.0/20' % cidr_prefix,
        '%s.80.0/20' % cidr_prefix]
    app_subnet_cidrs = [
        '%s.128.0/20' % cidr_prefix,
        '%s.144.0/20' % cidr_prefix]
    return web_subnet_cidrs, dbs_subnet_cidrs, app_subnet_cidrs


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
                       region_name=None, acm_client=None, dry_run=False):
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
    if not dry_run:
        resp = acm_client.import_certificate(
            Certificate=cert.encode('ascii'),
            PrivateKey=key.encode('ascii'),
            CertificateChain=chain.encode('ascii'),
            **kwargs)
        LOGGER.info("%s (re-)imported TLS certificate %s as %s",
            tag_prefix, result['ssl_certificate'], resp['CertificateArn'])
        result.update({'CertificateArn': resp['CertificateArn']})
    return result


def get_bucket_prefix(location):
    bucket_name = None
    prefix = None
    if location and location.startswith('s3://'):
        _, bucket_name, prefix = urlparse(location)[:3]
    return bucket_name, prefix


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


def check_security_group_ingress(security_group, expected_rules=None,
                                 tag_prefix=None):
    security_group_basic_rules = []
    for security_group_rule in security_group['IpPermissions']:
        basic_rules = [{
                'FromPort': security_group_rule.get('FromPort'),
                'IpProtocol': security_group_rule.get('IpProtocol'),
                'IpRanges': [],
                'Ipv6Ranges': [],
                'PrefixListIds': [],
                'ToPort': security_group_rule.get('ToPort'),
                'UserIdGroupPairs': []
            }]
        if security_group_rule.get('IpRanges'):
            prev_basic_rules = basic_rules
            basic_rules = []
            for ip_range in security_group_rule.get('IpRanges'):
                for rule in prev_basic_rules:
                    basic_rules += [{
                        'FromPort': rule.get('FromPort'),
                        'IpProtocol': rule.get('IpProtocol'),
                        'IpRanges': [ip_range],
                        'Ipv6Ranges': rule.get('Ipv6Ranges'),
                        'PrefixListIds': rule.get('PrefixListIds'),
                        'ToPort': rule.get('ToPort'),
                        'UserIdGroupPairs': rule.get('UserIdGroupPairs'),
                    }]
        if security_group_rule.get('Ipv6Ranges'):
            prev_basic_rules = basic_rules
            basic_rules = []
            for ipv6_range in security_group_rule.get('Ipv6Ranges'):
                for rule in prev_basic_rules:
                    basic_rules += [{
                        'FromPort': rule.get('FromPort'),
                        'IpProtocol': rule.get('IpProtocol'),
                        'IpRanges': rule.get('IpRanges'),
                        'Ipv6Ranges': [ipv6_range],
                        'PrefixListIds': rule.get('PrefixListIds'),
                        'ToPort': rule.get('ToPort'),
                        'UserIdGroupPairs': rule.get('UserIdGroupPairs'),
                    }]
        if security_group_rule.get('PrefixListIds'):
            prev_basic_rules = basic_rules
            basic_rules = []
            for prefix_list_id in security_group_rule.get('PrefixListIds'):
                for rule in prev_basic_rules:
                    basic_rules += [{
                        'FromPort': rule.get('FromPort'),
                        'IpProtocol': rule.get('IpProtocol'),
                        'IpRanges': rule.get('IpRanges'),
                        'Ipv6Ranges': rule.get('Ipv6Ranges'),
                        'PrefixListIds': [prefix_list_id],
                        'ToPort': rule.get('ToPort'),
                        'UserIdGroupPairs': rule.get('UserIdGroupPairs'),
                    }]
        if security_group_rule.get('UserIdGroupPairs'):
            prev_basic_rules = basic_rules
            basic_rules = []
            for user_id_group_pair in security_group_rule.get(
                    'UserIdGroupPairs'):
                for rule in prev_basic_rules:
                    basic_rules += [{
                        'FromPort': rule.get('FromPort'),
                        'IpProtocol': rule.get('IpProtocol'),
                        'IpRanges': rule.get('IpRanges'),
                        'Ipv6Ranges': rule.get('Ipv6Ranges'),
                        'PrefixListIds': rule.get('PrefixListIds'),
                        'ToPort': rule.get('ToPort'),
                        'UserIdGroupPairs': [user_id_group_pair],
                    }]
        security_group_basic_rules += basic_rules

    for rule in security_group_basic_rules:
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')
        ip_ranges = [block.get('CidrIp') for block in rule.get('IpRanges')]
        ipv6_ranges = [block.get('CidrIp') for block in rule.get('Ipv6Ranges')]
        dest = ip_ranges
        if not dest:
            dest = ipv6_ranges
        group_ids = [
            group.get('GroupId') for group in rule.get('UserIdGroupPairs')]
        if not dest:
            dest = group_ids
        matched_rule = None
        for expected_rule in expected_rules:
            match = True
            expected_port = expected_rule.get('port')
            expected_dest = expected_rule.get('source')
            if rule.get('PrefixListIds'):
                match = False
            if from_port != expected_port or to_port != expected_port:
                match = False
            if expected_dest.startswith('sg-'):
                if ip_ranges or ipv6_ranges or expected_dest not in group_ids:
                    match = False
            else:
                if ipv6_ranges or group_ids:
                    match = False
                if expected_dest != ip_ranges[0]:
                    match = False
            if match:
                matched_rule = expected_rule
                break
        if matched_rule:
            LOGGER.info(
                "%s found ingress rule from source %s port %d as expected",
                tag_prefix, dest, from_port)
        else:
            LOGGER.warning("%s unexpected ingress rule %s", tag_prefix, rule)


def create_cdn(tag_prefix, cdn_name=None, elb_domain=None,
               s3_logs_bucket=None,
               tls_priv_key=None, tls_fullchain_cert=None,
               region_name=None, dry_run=False):
    """
    Creates the Content Delivery Network (CloudFront).
    """
    if not cdn_name:
        cdn_name = '%scloudfront' % _clean_tag_prefix(tag_prefix)
    cdn_client = boto3.client('cloudfront', region_name='us-east-1')
    domains = []

    default_cert_location = None
    if not default_cert_location:
        if tls_priv_key and tls_fullchain_cert:
            resp = _store_certificate(
                tls_fullchain_cert, tls_priv_key,
                tag_prefix=tag_prefix, region_name=region_name,
                dry_run=dry_run)
            default_cert_location = resp['CertificateArn']
        else:
            LOGGER.warning("default_cert_location is not set and there are no"\
                " tls_priv_key and tls_fullchain_cert either.")

    try:
        resp = cdn_client.create_distribution(
            DistributionConfig={
                'CallerReference': datetime.datetime.now(),
                'DefaultRootObject': 'index.html',
                'Aliases': {
                    'Quantity': len(domains),
                    'Items': domains
                },
                'Origins': {
                    'Quantity': 1,
                    'Items': [{
                        'Id': tag_prefix,
                        'DomainName': elb_domain,
                        'CustomOriginConfig': {
                            'HTTPPort': 80,
                            'HTTPSPort': 443,
                            'OriginProtocolPolicy': 'match-viewer',
                        }
                    }]
                },
                'DefaultCacheBehavior': {
                    'TargetOriginId': tag_prefix,
                    'TrustedSigners': {
                        'Enabled': False,
                        'Quantity': 0
                    },
                    'ViewerProtocolPolicy': 'redirect-to-https',
                },
                #https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/PriceClass.html
                'PriceClass': 'XXX',
                'Enabled': True,
                'ViewerCertificate': {
                    #https://aws.amazon.com/premiumsupport/knowledge-center/associate-ssl-certificates-cloudfront/
                    'CloudFrontDefaultCertificate': False,
                    'ACMCertificateArn': default_cert_location,
                    'SSLSupportMethod': 'sni-only'
                }
            })
    except botocore.exceptions.ClientError as err:
        raise


def create_waf(tag_prefix, acl_name=None, elb_arn=None,
               s3_logs_bucket=None,
               region_name=None, dry_run=False):
    """
    Attach a Web Application Firewall to the Load Balancer
    """
    if not acl_name:
        acl_name = '%sacl' % _clean_tag_prefix(tag_prefix)
    if not elb_arn:
        elb_arn, elb_dns = _get_load_balancer(
            tag_prefix, region_name=region_name)

    waf_client = boto3.client('wafv2', region_name=region_name)
    resp = waf_client.create_web_acl(Name=acl_name)
    resp = waf_client.associate_web_acl(
        WebACLArn=acl_arn,
        ResourceArn=elb_arn)
    # XXX Add managed rule groups
    # AWS Core rule set
    # Known bad inputs
    # SQL database
    # Amazon IP reputation list??


def create_elb(tag_prefix, web_subnet_by_cidrs, moat_sg_id,
               elb_name=None, s3_logs_bucket=None,
               tls_priv_key=None, tls_fullchain_cert=None,
               region_name=None, dry_run=False):
    """
    Creates the Application Load Balancer.
    """
    if not elb_name:
        elb_name = '%selb' % _clean_tag_prefix(tag_prefix)

    elb_client = boto3.client('elbv2', region_name=region_name)
    resp = elb_client.create_load_balancer(
        Name=elb_name,
        Subnets=[subnet['SubnetId'] for subnet in web_subnet_by_cidrs.values()],
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

    attributes = [{
        'Key': 'deletion_protection.enabled',
        'Value': 'true'
    }, {
        #https://stackoverflow.com/questions/58848623/what-does-alb-consider-a-valid-header-field
        'Key': 'routing.http.drop_invalid_header_fields.enabled',
        'Value': 'true'
    }]
    if s3_logs_bucket:
        attributes += [{
                'Key': 'access_logs.s3.enabled',
                'Value': 'true'
            }, {
                'Key': 'access_logs.s3.bucket',
                'Value': s3_logs_bucket
            }, {
                'Key': 'access_logs.s3.prefix',
                'Value': 'var/log/elb'
            }]

    update_load_balancer_attributes = False
    resp = elb_client.describe_load_balancer_attributes(
        LoadBalancerArn=load_balancer_arn)
    for attr in attributes:
        for curr_attr in resp['Attributes']:
            if attr['Key'] == curr_attr['Key']:
                if attr['Value'] != curr_attr['Value']:
                    update_load_balancer_attributes = True
                break
    if update_load_balancer_attributes:
        resp = elb_client.modify_load_balancer_attributes(
            LoadBalancerArn=load_balancer_arn,
            Attributes=attributes)
        LOGGER.info("%s updated attributes for load balancer %s",
            tag_prefix, load_balancer_arn)
    else:
        LOGGER.info("%s found expected attributes for load balancer %s",
            tag_prefix, load_balancer_arn)

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
                tag_prefix=tag_prefix, region_name=region_name,
                dry_run=dry_run)
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


def create_network(region_name, vpc_cidr, tag_prefix,
                   tls_priv_key=None, tls_fullchain_cert=None,
                   ssh_key_name=None, ssh_key_content=None, sally_ip=None,
                   s3_logs_bucket=None, s3_identities_bucket=None,
                   storage_enckey=None,
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
    sg_tag_prefix = tag_prefix

    LOGGER.info("Provisions network ...")
    ec2_client = boto3.client('ec2', region_name=region_name)

    # Create a VPC
    vpc_id, vpc_cidr_read = _get_vpc_id(tag_prefix, ec2_client=ec2_client,
        region_name=region_name)
    if vpc_id:
        if vpc_cidr != vpc_cidr_read:
            raise RuntimeError(
                "%s cidr block for VPC is %s while it was expected to be %s" %
                (tag_prefix, vpc_cidr_read, vpc_cidr))
    else:
        if not vpc_cidr:
            raise RuntimeError(
                "%s could not find VPC and no cidr block is specified"\
                " to create one." % tag_prefix)
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
    # ELB will require that there is at least one subnet per availability zones.
    # RDS will require that there is at least two subnets for databases.
    resp = ec2_client.describe_availability_zones()
    zones = {(zone['ZoneId'], zone['ZoneName'])
        for zone in resp['AvailabilityZones']}
    web_subnet_cidrs, dbs_subnet_cidrs, app_subnet_cidrs = _split_cidrs(
        vpc_cidr, zones=zones, region_name=region_name)

    LOGGER.info("%s provisioning web subnets..." % tag_prefix)
    web_zones = set([])
    web_subnet_by_cidrs = _get_subnet_by_cidrs(
        web_subnet_cidrs, tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    for cidr_block, subnet in web_subnet_by_cidrs.items():
        if subnet:
            web_zones |= {
                (subnet['AvailabilityZoneId'], subnet['AvailabilityZone'])}
    for cidr_block, subnet in web_subnet_by_cidrs.items():
        if not subnet:
            available_zones = zones - web_zones
            zone_id, zone_name = available_zones.pop()
            resp = ec2_client.create_subnet(
                AvailabilityZoneId=zone_id,
                CidrBlock=cidr_block,
                VpcId=vpc_id,
                TagSpecifications=[{
                    'ResourceType': 'subnet',
                    'Tags': [
                        {'Key': "Prefix", 'Value': tag_prefix},
                        {'Key': "Name",
                         'Value': "%s %s web" % (tag_prefix, zone_name)}]}],
                DryRun=dry_run)
            subnet = resp['Subnet']
            web_subnet_by_cidrs[cidr_block] = subnet
            web_zones |= set([(zone_id, zone_name)])
            subnet_id = subnet['SubnetId']
            LOGGER.info("%s created subnet %s in zone %s for cidr %s",
                tag_prefix, subnet_id, zone_name, cidr_block)
        if not subnet['MapPublicIpOnLaunch']:
            subnet_id = subnet['SubnetId']
            if not dry_run:
                resp = ec2_client.modify_subnet_attribute(
                    SubnetId=subnet_id,
                    MapPublicIpOnLaunch={'Value': True})
            LOGGER.info("%s modify web subnet %s so instance can receive"\
                " a public IP by default", tag_prefix, subnet_id)

    LOGGER.info("%s provisioning dbs subnets..." % tag_prefix)
    dbs_zones = set([])
    dbs_subnet_by_cidrs = _get_subnet_by_cidrs(
        dbs_subnet_cidrs, tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    for cidr_block, subnet in dbs_subnet_by_cidrs.items():
        if subnet:
            dbs_zones |= {
                (subnet['AvailabilityZoneId'], subnet['AvailabilityZone'])}
    for cidr_block, subnet in dbs_subnet_by_cidrs.items():
        if not subnet:
            available_zones = zones - dbs_zones
            zone_id, zone_name = available_zones.pop()
            resp = ec2_client.create_subnet(
                AvailabilityZoneId=zone_id,
                CidrBlock=cidr_block,
                VpcId=vpc_id,
                TagSpecifications=[{
                    'ResourceType': 'subnet',
                    'Tags': [
                        {'Key': "Prefix", 'Value': tag_prefix},
                        {'Key': "Name",
                         'Value': "%s %s dbs" % (tag_prefix, zone_name)}]}],
                DryRun=dry_run)
            subnet = resp['Subnet']
            dbs_subnet_by_cidrs[cidr_block] = subnet
            dbs_zones |= set([(zone_id, zone_name)])
            subnet_id = subnet['SubnetId']
            LOGGER.info("%s created subnet %s in zone %s for cidr %s",
                tag_prefix, subnet_id, zone_name, cidr_block)
        if subnet['MapPublicIpOnLaunch']:
            subnet_id = subnet['SubnetId']
            if not dry_run:
                resp = ec2_client.modify_subnet_attribute(
                    SubnetId=subnet_id,
                    MapPublicIpOnLaunch={'Value': False})
            LOGGER.info("%s modify dbs subnet %s so instance do not receive"\
                " a public IP by default", tag_prefix, subnet_id)

    LOGGER.info("%s provisioning apps subnets..." % tag_prefix)
    app_zones = set([])
    app_subnet_by_cidrs = _get_subnet_by_cidrs(
        app_subnet_cidrs, tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    for cidr_block, subnet in app_subnet_by_cidrs.items():
        if subnet:
            app_zones |= {
                (subnet['AvailabilityZoneId'], subnet['AvailabilityZone'])}
    for cidr_block, subnet in app_subnet_by_cidrs.items():
        if not subnet:
            available_zones = zones - app_zones
            zone_id, zone_name = available_zones.pop()
            resp = ec2_client.create_subnet(
                AvailabilityZoneId=zone_id,
                CidrBlock=cidr_block,
                VpcId=vpc_id,
                # COMMIT MSG:
                # this requires boto3>=1.14, using `createTag` might fail
                # because the subnet is not fully created yet.
                TagSpecifications=[{
                    'ResourceType': 'subnet',
                    'Tags': [
                        {'Key': "Prefix", 'Value': tag_prefix},
                        {'Key': "Name",
                         'Value': "%s %s app" % (tag_prefix, zone_name)}]}],
                DryRun=dry_run)
            subnet = resp['Subnet']
            app_subnet_by_cidrs[cidr_block] = subnet
            app_zones |= set([(zone_id, zone_name)])
            subnet_id = subnet['SubnetId']
            LOGGER.info("%s created subnet %s in %s for cidr %s",
                tag_prefix, subnet_id, zone_name, cidr_block)
        if subnet['MapPublicIpOnLaunch']:
            subnet_id = subnet['SubnetId']
            if not dry_run:
                resp = ec2_client.modify_subnet_attribute(
                    SubnetId=subnet_id,
                    MapPublicIpOnLaunch={'Value': False})
            LOGGER.info("%s modify app subnet %s so instance do not receive"\
                " a public IP by default", tag_prefix, subnet_id)

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

    # Create the NAT gateway by which private subnets connect to Internet
    # XXX Why do we have a Network interface eni-****?
    nat_elastic_ip = None
    web_elastic_ip = None
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
                        web_elastic_ip = resp_address['AllocationId']
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
    if web_elastic_ip:
        LOGGER.info("%s found Sally public IP %s",
            tag_prefix, web_elastic_ip)
    else:
        resp = ec2_client.allocate_address(
            DryRun=dry_run,
            Domain='vpc')
        web_elastic_ip = resp['AllocationId']
        ec2_client.create_tags(
            DryRun=dry_run,
            Resources=[web_elastic_ip],
            Tags=[{'Key': "Prefix", 'Value': tag_prefix},
                  {'Key': "Name",
                   'Value': "%s Sally public IP" % tag_prefix}])
        LOGGER.info("%s created Sally public IP %s",
            tag_prefix, web_elastic_ip)

    # We have 2 EIP addresses. They need to be connected to machines
    # running in an Internet facing subnet.
    client_token = tag_prefix
    # XXX shouldn't it be the first web subnet instead?
    resp = ec2_client.describe_nat_gateways(Filters=[
        {'Name': "vpc-id", 'Values': [vpc_id]},
        {'Name': "state", 'Values': ['pending', 'available']}])
    if resp['NatGateways']:
        if len(resp['NatGateways']) > 1:
            LOGGER.warning("%s found more than one NAT gateway."\
                " Using first one in the list.", tag_prefix)
        nat_gateway = resp['NatGateways'][0]
        nat_gateway_id = nat_gateway['NatGatewayId']
        nat_gateway_subnet_id = nat_gateway['SubnetId']
        LOGGER.info("%s found NAT gateway %s", tag_prefix, nat_gateway_id)
    else:
        nat_gateway_subnet_id = next(web_subnet_by_cidrs.values())['SubnetId']
        resp = ec2_client.create_nat_gateway(
            AllocationId=nat_elastic_ip,
            ClientToken=client_token,
            SubnetId=nat_gateway_subnet_id)
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

    resp = ec2_client.describe_route_tables(
        DryRun=dry_run,
        RouteTableIds=[public_route_table_id])
    assocs = resp['RouteTables'][0]['Associations']
    if len(assocs) > 1:
        LOGGER.warning("%s found more than one route table association for"\
            " public route table. Using first one in the list." % tag_prefix)
    if not assocs[0]['Main']:
        LOGGER.warning("%s public route table is not the main one for the VPC."
            % tag_prefix)

    for cidr_block, subnet in web_subnet_by_cidrs.items():
        subnet_id = subnet['SubnetId']
        resp = ec2_client.describe_route_tables(
            DryRun=dry_run,
            Filters=[{
                'Name': 'association.subnet-id',
                'Values': [subnet_id]
            }])
        # The Main route table does not show as an explicit association.
        found_association = not bool(resp['RouteTables'])
        if found_association:
            LOGGER.info(
                "%s found public route table %s associated to web subnet %s",
                tag_prefix, public_route_table_id, subnet_id)
        else:
            return
            resp = ec2_client.associate_route_table(
                DryRun=dry_run,
                RouteTableId=public_route_table_id,
                SubnetId=subnet_id)
            LOGGER.info(
                "%s associate public route table %s to web subnet %s",
                tag_prefix, public_route_table_id, subnet_id)

    for cidr_block, subnet in dbs_subnet_by_cidrs.items():
        subnet_id = subnet['SubnetId']
        resp = ec2_client.describe_route_tables(
            DryRun=dry_run,
            Filters=[{
                'Name': 'association.subnet-id',
                'Values': [subnet_id]
            }])
        # The Main route table does not show as an explicit association.
        found_association = False
        if resp['RouteTables']:
            found_association = (
                resp['RouteTables'][0]['Associations'][0]['RouteTableId'] ==
                private_route_table_id
            )
        if found_association:
            LOGGER.info(
                "%s found private route table %s associated to dbs subnet %s",
                tag_prefix, private_route_table_id, subnet_id)
        else:
            resp = ec2_client.associate_route_table(
                DryRun=dry_run,
                RouteTableId=private_route_table_id,
                SubnetId=subnet_id)
            LOGGER.info(
                "%s associate private route table %s to dbs subnet %s",
                tag_prefix, private_route_table_id, subnet_id)

    for cidr_block, subnet in app_subnet_by_cidrs.items():
        subnet_id = subnet['SubnetId']
        resp = ec2_client.describe_route_tables(
            DryRun=dry_run,
            Filters=[{
                'Name': 'association.subnet-id',
                'Values': [subnet_id]
            }])
        # The Main route table does not show as an explicit association.
        found_association = False
        if resp['RouteTables']:
            found_association = (
                resp['RouteTables'][0]['Associations'][0]['RouteTableId'] ==
                private_route_table_id
            )
        if found_association:
            LOGGER.info(
                "%s found private route table %s associated to app subnet %s",
                tag_prefix, private_route_table_id, subnet_id)
        else:
            resp = ec2_client.associate_route_table(
                DryRun=dry_run,
                RouteTableId=private_route_table_id,
                SubnetId=subnet_id)
            LOGGER.info(
                "%s associate private route table %s to app subnet %s",
                tag_prefix, private_route_table_id, subnet_id)

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
            LOGGER.info("%s check ingress rules for %s", tag_prefix, moat_name)
            check_security_group_ingress(security_group, expected_rules=[
                {'port': 80, 'source': '0.0.0.0/0'},
                {'port': 80, 'source': '::/0'},
                {'port': 443, 'source': '0.0.0.0/0'},
                {'port': 443, 'source': '::/0'},
            ],
            tag_prefix=tag_prefix)
        elif security_group['GroupId'] == gate_sg_id:
            # castle-gate rules
            LOGGER.info("%s check ingress rules for %s", tag_prefix, gate_name)
            check_security_group_ingress(security_group, expected_rules=[
                {'port': 80, 'source': moat_sg_id},
                {'port': 443, 'source': moat_sg_id}
            ],
            tag_prefix=tag_prefix)
        elif security_group['GroupId'] == vault_sg_id:
            # vault rules
            LOGGER.info("%s check ingress rules for %s", tag_prefix, vault_name)
            check_security_group_ingress(security_group, expected_rules=[
                {'port': 5432, 'source': gate_sg_id}
            ],
            tag_prefix=tag_prefix)

    # moat allow rules
    if update_moat_rules:
        try:
            resp = ec2_client.authorize_security_group_ingress(
                DryRun=dry_run,
                GroupId=moat_sg_id,
                IpPermissions=[{
                    'FromPort': 80,
                    'IpProtocol': 'tcp',
                    'IpRanges': [{
                        'CidrIp': '0.0.0.0/0'
                    }],
                    'ToPort': 80
                }, {
                    'FromPort': 80,
                    'IpProtocol': 'tcp',
                    'Ipv6Ranges': [{
                        'CidrIpv6': '::/0',
                    }],
                    'ToPort': 80
                }, {
                    'FromPort': 443,
                    'IpProtocol': 'tcp',
                    'IpRanges': [{
                        'CidrIp': '0.0.0.0/0'
                    }],
                    'ToPort': 443
                }, {
                    'FromPort': 443,
                    'IpProtocol': 'tcp',
                    'Ipv6Ranges': [{
                        'CidrIpv6': '::/0',
                    }],
                    'ToPort': 443
                }])
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
    # XXX create the identities bucket?
    # XXX need to force private.
    if not s3_identities_bucket:
        s3_identities_bucket = '%s-identities' % tag_prefix
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
            LOGGER.info("%s created S3 bucket for logs %s",
                tag_prefix, s3_logs_bucket)
        except botocore.exceptions.ClientError as err:
            LOGGER.info("%s found S3 bucket for logs %s",
                tag_prefix, s3_logs_bucket)
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'BucketAlreadyOwnedByYou':
                raise
        # Apply bucket encryption by default
        found_encryption = False
        try:
            resp = s3_client.get_bucket_encryption(
                Bucket=s3_logs_bucket)
            if resp['ServerSideEncryptionConfiguration']['Rules'][0][
                    'ApplyServerSideEncryptionByDefault'][
                        'SSEAlgorithm'] == 'AES256':
                found_encryption = True
                LOGGER.info("%s found encryption AES256 enabled on %s bucket",
                    tag_prefix, s3_logs_bucket)
        except botocore.exceptions.ClientError as err:
            LOGGER.info("%s found S3 bucket for logs %s",
                tag_prefix, s3_logs_bucket)
            if not err.response.get('Error', {}).get('Code', 'Unknown') == \
               'ServerSideEncryptionConfigurationNotFoundError':
                raise
        if not found_encryption:
            s3_client.put_bucket_encryption(
                Bucket=s3_logs_bucket,
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256',
                        }
                    }]
                })
            LOGGER.info("%s enable encryption on %s bucket",
                tag_prefix, s3_logs_bucket)

        # Set versioning and lifecycle policies
        resp = s3_client.get_bucket_versioning(
            Bucket=s3_logs_bucket)
        if 'Status' in resp and resp['Status'] == 'Enabled':
            LOGGER.info("%s found versioning enabled on %s bucket",
                tag_prefix, s3_logs_bucket)
        else:
            s3_client.put_bucket_versioning(
                Bucket=s3_logs_bucket,
                VersioningConfiguration={
                    'MFADelete': 'Disabled',
                    'Status': 'Enabled'
                })
            LOGGER.info("%s enable versioning on %s bucket",
                tag_prefix, s3_logs_bucket)
        found_policy = False
        try:
            resp = s3_client.get_bucket_lifecycle_configuration(
                Bucket=s3_logs_bucket)
            for rule in resp['Rules']:
                if rule['Status'] == 'Enabled':
                    found_rule = True
                    for transition in rule['Transitions']:
                        if transition['StorageClass'] == 'GLACIER':
                            if transition.get('Days', 0) < 90:
                                found_rule = False
                                LOGGER.warning("%s lifecycle for 'GLACIER'"\
                                    " is less than 90 days.", tag_prefix)
                                break
                    if rule['Expiration'].get('Days', 0) < 365:
                        found_rule = False
                        LOGGER.warning(
                            "%s lifecycle expiration is less than 365 days.",
                            tag_prefix)
                    for transition in rule['NoncurrentVersionTransitions']:
                        if transition['StorageClass'] == 'GLACIER':
                            if transition.get('NoncurrentDays', 0) < 90:
                                found_rule = False
                                LOGGER.warning(
                                    "%s version lifecycle for 'GLACIER'"\
                                    " is less than 90 days.", tag_prefix)
                                break
                    if rule['NoncurrentVersionExpiration'].get(
                            'NoncurrentDays', 0) < 365:
                        found_rule = False
                        LOGGER.warning("%s lifecycle version expiration is"\
                            " less than 365 days.", tag_prefix)
                    if found_rule:
                        found_policy = True
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'NoSuchLifecycleConfiguration':
                raise
        if found_policy:
            LOGGER.info("%s found lifecycle policy on %s bucket",
                tag_prefix, s3_logs_bucket)
        else:
            s3_client.put_bucket_lifecycle_configuration(
                Bucket=s3_logs_bucket,
                LifecycleConfiguration={
                    "Rules": [{
                        "Status": "Enabled",
                        "ID": "expire-logs",
                        "Filter": {
                            "Prefix": "", # This is required.
                        },
                        "Transitions": [{
                            "Days": 90,
                            "StorageClass": "GLACIER"
                        }],
                        "Expiration" : {
                            "Days": 365
                        },
                        "NoncurrentVersionTransitions": [{
                            "NoncurrentDays": 90,
                            "StorageClass": "GLACIER"
                        }],
                        'NoncurrentVersionExpiration': {
                            'NoncurrentDays': 365
                        },
                    }]})
            LOGGER.info("%s update lifecycle policy on %s bucket",
                tag_prefix, s3_logs_bucket)

            # https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-access-logs.html#attach-bucket-policy
            elb_account_ids_per_region = {
                'us-east-1': '127311923021',
                'us-east-2': '033677994240',
                'us-west-1': '027434742980',
                'us-west-2': '797873946194',
                'af-south-1': '098369216593',
                'ca-central-1': '985666609251',
                'eu-central-1': '054676820928',
                'eu-west-1': '156460612806',
                'eu-west-2': '652711504416',
                'eu-south-1': '635631232127',
                'eu-west-3': '009996457667',
                'eu-north-1': '897822967062',
                'ap-east-1': '754344448648',
                'ap-northeast-1': '582318560864',
                'ap-northeast-2': '600734575887',
                'ap-northeast-3': '383597477331',
                'ap-southeast-1': '114774131450',
                'ap-southeast-2': '783225319266',
                'ap-south-1': '718504428378',
                'me-south-1': '076674570225',
                'sa-east-1': '507241528517'
            }
            elb_account_id = elb_account_ids_per_region[region_name]
            s3_client.put_bucket_policy(
                Bucket=s3_logs_bucket,
                Policy=json.dumps({
                    "Version": "2008-10-17",
                    "Id": "WriteLogs",
                    "Statement": [{
                        # billing reports
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "billingreports.amazonaws.com"
                        },
                        "Action": [
                            "s3:GetBucketAcl",
                            "s3:GetBucketPolicy"
                        ],
                        "Resource": "arn:aws:s3:::%s" % s3_logs_bucket
                    }, {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "billingreports.amazonaws.com"
                        },
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::%s/*" % s3_logs_bucket
                    }, {
                        # ELB access logs
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::%s:root" % elb_account_id
                        },
                        "Action": "s3:PutObject",
                        "Resource":
                            "arn:aws:s3:::%s/var/log/elb/*" % s3_logs_bucket
                    }, {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "delivery.logs.amazonaws.com"
                        },
                        "Action": "s3:PutObject",
                        "Resource":
                            ("arn:aws:s3:::%s/var/log/elb/*" % s3_logs_bucket),
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-acl": "bucket-owner-full-control"
                            }
                        }
                    }, {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "delivery.logs.amazonaws.com"
                        },
                        "Action": "s3:GetBucketAcl",
                        "Resource": "arn:aws:s3:::%s" % s3_logs_bucket
                    }]
                }))

    if s3_uploads_bucket:
        try:
            resp = s3_client.create_bucket(
                ACL='private',
                Bucket=s3_uploads_bucket,
                CreateBucketConfiguration={
                    'LocationConstraint': region_name
                })
            LOGGER.info("%s created S3 bucket for uploads %s",
                tag_prefix, s3_uploads_bucket)
        except botocore.exceptions.ClientError as err:
            LOGGER.info("%s found S3 bucket for uploads %s",
                tag_prefix, s3_uploads_bucket)
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
                "Statement": [
                    {
                        "Action": [
                            "s3:ListBucket"
                        ],
                        "Effect": "Allow",
                        "Resource": [
                            "arn:aws:s3:::%s" % s3_logs_bucket
                        ],
                        # XXX conditions does not work to restrict listing?
                        "Condition":{
                            "StringEquals":{
                                "s3:prefix":["var/log/"],
                                "s3:delimiter":["/"]
                            }
                        }
                    },
                    {
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
                        "s3:PutObject",
                        # Without `s3:PutObjectAcl` we cannot set profile
                        # pictures and other media `public-read`.
                        "s3:PutObjectAcl"
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
    resp = iam_client.list_role_policies(
        RoleName=gate_role)
    for policy_name in resp['PolicyNames']:
        LOGGER.info(
            "%s found policy %s in role %s",
            tag_prefix, policy_name, gate_role)

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
            PolicyName='DatabasesBackup',
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": [
                        "s3:PutObject"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::%s/var/migrate/*" % s3_logs_bucket
                    ]
                }]
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
                        "arn:aws:s3:::%s/var/log/*" % s3_logs_bucket
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
    resp = iam_client.list_role_policies(
        RoleName=vault_name)
    for policy_name in resp['PolicyNames']:
        LOGGER.info(
            "%s found policy %s in role %s",
            tag_prefix, policy_name, vault_name)

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

    if ssh_key_name and ssh_key_content:
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
                if sally_ip:
                    cidr_block = '%s/32' % sally_ip
                else:
                    LOGGER.warning("no IP range was specified to restrict"\
                        " access to SSH port")
                    cidr_block = '0.0.0.0/0'
                resp = ec2_client.authorize_security_group_ingress(
                    DryRun=dry_run,
                    GroupId=kitchen_door_sg_id,
                    CidrIp=cidr_block,
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
        storage_enckey = _get_or_create_storage_enckey(
            region_name, tag_prefix, dry_run=dry_run)

    # Create an Application ELB
    create_elb(
        tag_prefix, web_subnet_by_cidrs, moat_sg_id,
        s3_logs_bucket=s3_logs_bucket,
        tls_priv_key=tls_priv_key, tls_fullchain_cert=tls_fullchain_cert,
        region_name=region_name)



def create_datastores(region_name, vpc_cidr, tag_prefix,
                      app_name=None,
                      storage_enckey=None,
                      db_host=None,
                      db_master_user=None, db_master_password=None,
                      db_user=None, db_password=None,
                      identities_url=None, s3_identities_bucket=None,
                      image_name=None, ssh_key_name=None,
                      company_domain=None, ldap_host=None,
                      ldap_hashed_password=None,
                      provider=None, dry_run=False):
    """
    This function creates in a specified AWS region the disk storage (S3) and
    databases (SQL) to run a SaaS product. It will:

    - create S3 buckets for media uploads and write-only logs
    - create a SQL database

    `vpc_cidr` is the network mask used for the private IPs.
    `dbs_zone_names` contains the zones in which the SQL databases
    will be hosted.

    Either define `identities_url` or `s3_identities_bucket`.

    `db_master_user` and `db_master_password` are to connect to RDS. When
    postgresql is installed on a bare instance, the master user is "postgres".
    """
    instance_type = 'm3.medium'
    sg_tag_prefix = tag_prefix

    LOGGER.info("Provisions datastores ...")
    if not app_name:
        app_name = '%s-dbs' % tag_prefix if tag_prefix else "dbs"
    if not db_user:
        db_user = tag_prefix
    if not db_host:
        db_host = '%s.%s.internal' % (app_name, region_name)
    if not identities_url:
        if not s3_identities_bucket:
            s3_identities_bucket = '%s-identities' % tag_prefix
        identities_url = "s3://%s/identities/%s/%s" % (
            s3_identities_bucket, region_name, db_host)

    # XXX same vault_name as in `create_network`
    vault_name = _get_security_group_names(
        ['vault'], tag_prefix=sg_tag_prefix)[0]
    ec2_client = boto3.client('ec2', region_name=region_name)

    vpc_id, _ = _get_vpc_id(tag_prefix, ec2_client=ec2_client,
        region_name=region_name)
    _, dbs_subnet_cidrs, _ = _split_cidrs(
        vpc_cidr, ec2_client=ec2_client, region_name=region_name)
    dbs_subnet_by_cidrs = _get_subnet_by_cidrs(dbs_subnet_cidrs,
        tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    # Derive availablility zone from first available subnet.
    dbs_availability_zone = None
    for subnet in dbs_subnet_by_cidrs.values():
        if subnet:
            dbs_availability_zone = subnet['AvailabilityZone']
            break
    db_subnet_group_subnet_ids = [
        subnet['SubnetId'] for subnet in dbs_subnet_by_cidrs.values() if subnet]

    group_ids = _get_security_group_ids(
        [vault_name], tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    vault_sg_id = group_ids[0]

    if not storage_enckey:
        storage_enckey = _get_or_create_storage_enckey(
            region_name, tag_prefix, dry_run=dry_run)

    if provider and provider == 'rds':
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
                AvailabilityZone=dbs_availability_zone,
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
            LOGGER.info("%s created rds db '%s'", tag_prefix, db_name)
        except botocore.exceptions.ClientError as err:
            if not err.response.get('Error', {}).get(
                    'Code', 'Unknown') == 'DBInstanceAlreadyExists':
                raise
            LOGGER.info("%s found rds db '%s'", tag_prefix, db_name)
        return db_name # XXX do we have an aws id?

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
        db_host=db_host,
        db_user=db_user,
        db_password=db_password,
        db_master_password=db_master_password,
        identities_url=identities_url,
        remote_drop_repo="https://github.com/djaodjin/drop.git",
        company_domain=company_domain,
        ldap_host=ldap_host,
        ldap_hashed_password=ldap_hashed_password,
        vpc_cidr=vpc_cidr)

    # Find the ImageId
    instance_profile_arn = _get_instance_profile(
        vault_name, region_name=region_name)
    if instance_profile_arn:
        LOGGER.info("%s found IAM instance profile '%s'",
            tag_prefix, instance_profile_arn)
    else:
        # XXX
        raise NotImplementedError(
            "%s cannot find IAM instance profile for '%s'" % (
                tag_prefix, vault_name))
    image_id = _get_image_id(
        image_name, instance_profile_arn=instance_profile_arn,
        ec2_client=ec2_client, region_name=region_name)

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
        # XXX Haven't been able to use the key we created but the default
        #     aws/ebs is OK...
        for block_device in block_devices:
            block_device['Ebs'].update({
                'KmsKeyId': storage_enckey,
                'Encrypted': True
            })
    LOGGER.debug("""
        ec2_client.run_instances(
        BlockDeviceMappings=%(block_devices)s,
        ImageId='%(image_id)s',
        KeyName='%(ssh_key_name)s',
        InstanceType='%(instance_type)s',
        MinCount=1,
        MaxCount=1,
        SubnetId='%(db_subnet_group_subnet_id)s',
        # Cannot use `SecurityGroups` with `SubnetId` but can
        # use `SecurityGroupIds`.
        SecurityGroupIds=%(group_ids)s,
        IamInstanceProfile={'Arn': '%(instance_profile_arn)s}',
        TagSpecifications=[{
            'ResourceType': "instance",
            'Tags': [{
                'Key': 'Name',
                'Value': '%(app_name)s'
            }]}],
        UserData='''%(user_data)s''')
    """,
        block_devices=block_devices,
        image_id=image_id,
        ssh_key_name=ssh_key_name,
        instance_type=instance_type,
        db_subnet_group_subnet_id=db_subnet_group_subnet_ids[0],
        group_ids=group_ids,
        instance_profile_arn=instance_profile_arn,
        app_name=app_name,
        user_data=user_data)
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

    for instance in resp['Instances']:
        LOGGER.info("%s started ec2 instances %s for '%s' at %s", tag_prefix,
            instance['InstanceId'], app_name, instance['PrivateDnsName'])

    return instance_ids



def create_app_resources(region_name, app_name, image_name,
                         instance_type='t3a.small',
                         storage_enckey=None,
                         ecr_access_role_arn=None,
                         settings_location=None, settings_crypt_key=None,
                         s3_logs_bucket=None, s3_uploads_bucket=None,
                         ssh_key_name=None,
                         app_subnet_id=None, vpc_id=None, vpc_cidr=None,
                         hosted_zone_id=None,
                         app_prefix=None,
                         tag_prefix=None,
                         dry_run=False):
    """
    Create the application servers
    """
    gate_name, kitchen_door_name = _get_security_group_names([
        'castle-gate', 'kitchen-door'], tag_prefix=tag_prefix)
    app_sg_name = _get_security_group_names([
        'courtyard'], tag_prefix=app_prefix)[0]

    ec2_client = boto3.client('ec2', region_name=region_name)
    resp = ec2_client.describe_instances(
        Filters=[
            {'Name': 'tag:Name', 'Values': ["*%s*" % app_name]},
            {'Name': 'instance-state-name',
             'Values': [EC2_RUNNING, EC2_STOPPED, EC2_PENDING]}])

    instances = None
    instance_ids = []
    stopped_instance_ids = []
    for reserv in resp['Reservations']:
        instances = reserv['Instances']
        for instance in reserv['Instances']:
            names = []
            for tag in instance['Tags']:
                if tag['Key'] == 'Name':
                    names = [name.strip() for name in tag['Value'].split(',')]
                    break
            if app_name not in names:
                continue
            instance_ids += [instance['InstanceId']]
            if instance['State']['Name'] == EC2_STOPPED:
                stopped_instance_ids += [instance['InstanceId']]
    if stopped_instance_ids:
        ec2_client.start_instances(
            InstanceIds=stopped_instance_ids,
            DryRun=dry_run)
        LOGGER.info("%s restarted instances %s for '%s'",
            tag_prefix, stopped_instance_ids, app_name)
    if instance_ids:
        LOGGER.info("%s found instances %s for '%s'",
            tag_prefix, instance_ids, app_name)

    # Create a Queue to communicate with the agent on the EC2 instance.
    # Implementation Note:
    #   strange but no exception thrown when queue already exists.
    sqs = boto3.client('sqs', region_name=region_name)
    resp = sqs.create_queue(QueueName=app_name)
    queue_url = resp.get("QueueUrl")

    if instance_ids:
        # If instances are running and there is a message queue,
        # we assume the infrastructure for this app is ready to accept
        # containers.
        return instance_ids

    search_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'templates')
    template_loader = jinja2.FileSystemLoader(searchpath=search_path)
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template("app-cloud-init-script.j2")
    user_data = template.render(
        settings_location=settings_location if settings_location else "",
        settings_crypt_key=settings_crypt_key if settings_crypt_key else "",
        logs_storage_location="s3://%s" % s3_logs_bucket,
        queue_url=queue_url)

    if not vpc_id:
        vpc_id, _ = _get_vpc_id(tag_prefix, ec2_client=ec2_client,
            region_name=region_name)
    if not app_subnet_id:
        #pylint:disable=unused-variable
        _, _, app_subnet_cidrs = _split_cidrs(
            vpc_cidr, ec2_client=ec2_client, region_name=region_name)
        app_subnet_by_cidrs = _get_subnet_by_cidrs(
            app_subnet_cidrs, tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
        # Use first valid subnet that does not require a public IP.
        app_subnet_id = next(iter(app_subnet_by_cidrs.values()))['SubnetId']

    group_ids = _get_security_group_ids(
        [app_sg_name], app_prefix,
        vpc_id=vpc_id, ec2_client=ec2_client)
    app_sg_id = group_ids[0]
    group_ids = _get_security_group_ids(
        [gate_name, kitchen_door_name], tag_prefix,
        vpc_id=vpc_id, ec2_client=ec2_client)
    gate_sg_id = group_ids[0]
    kitchen_door_sg_id = group_ids[1]
    if not app_sg_id:
        if app_prefix and app_prefix.endswith('-'):
            descr = '%s %s' % (app_prefix[:-1], app_name)
        elif app_prefix:
            descr = ('%s %s' % (app_prefix, app_name)).strip()
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
        app_role, iam_client=iam_client, region_name=region_name)
    if instance_profile_arn:
        LOGGER.info("%s found IAM instance profile '%s'",
            tag_prefix, instance_profile_arn)
    else:
        resp = iam_client.create_instance_profile(
            InstanceProfileName=app_role)
        instance_profile_arn = resp['InstanceProfile']['Arn']
        LOGGER.info("%s created IAM instance profile '%s'",
            tag_prefix, instance_profile_arn)
        iam_client.add_role_to_instance_profile(
            InstanceProfileName=app_role,
            RoleName=app_role)
        LOGGER.info("%s added IAM instance profile %s to role %s",
            tag_prefix, instance_profile_arn, app_role)

    # Find the ImageId
    image_id = _get_image_id(
        image_name, instance_profile_arn=instance_profile_arn,
        ec2_client=ec2_client, region_name=region_name)

    block_devices = [
        {
            'DeviceName': '/dev/sda1',
            #'VirtualName': 'string',
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-volume-types.html
            'Ebs': {
                'DeleteOnTermination': False,
                #'Iops': 100, # 'not supported for gp2'
                #'SnapshotId': 'string',
                'VolumeSize': 8,
                'VolumeType': 'gp2'
            },
            #'NoDevice': 'string'
        },
    ]
    if storage_enckey:
        # XXX Haven't been able to use the key we created but the default
        #     aws/ebs is OK...
        for block_device in block_devices:
            block_device['Ebs'].update({
                'KmsKeyId': storage_enckey,
                'Encrypted': True
            })
    if not instances or not instance_ids:
        for _ in range(0, NB_RETRIES):
            # The IAM instance profile take some time to be visible.
            try:
                # XXX adds encrypted volume
                resp = ec2_client.run_instances(
                    BlockDeviceMappings=block_devices,
                    ImageId=image_id,
                    KeyName=ssh_key_name,
                    InstanceType=instance_type,
                    MinCount=1,
                    MaxCount=1,
                    IamInstanceProfile={'Arn': instance_profile_arn},
                    SubnetId=app_subnet_id,
                    # Cannot use `SecurityGroups` with `SubnetId` but can
                    # use `SecurityGroupIds`.
                    SecurityGroupIds=[app_sg_id],
# XXX cannot do that unless we change all routes:
                    # Forces only private IP address even when the VPC subnet
                    # says otherwise.
#                    NetworkInterfaces=[{
#                        'AssociatePublicIpAddress': False,
#                        'DeviceIndex': 0,
#                        'SubnetId': app_subnet_id,
#                        # Cannot use `SecurityGroups` with `SubnetId`
#                        # but can use `SecurityGroupIds`.
#                        'Groups': [app_sg_id]
#                    }],
                    TagSpecifications=[{
                        'ResourceType': "instance",
                        'Tags': [{
                            'Key': 'Name',
                            'Value': app_name
                        }, {
                            'Key': 'Prefix',
                            'Value': app_prefix
                        }]
                    }],
                    UserData=user_data)
                instances = resp['Instances']
                instance_ids = [
                    instance['InstanceId'] for instance in instances]
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
            hosted_zone = route53.get_hosted_zone(
                Id=hosted_zone_id)['HostedZone']
        else:
            hosted_zones_resp = route53.list_hosted_zones()
            hosted_zones = hosted_zones_resp.get('HostedZones')
            for hzone in hosted_zones:
                if hzone.get('Name').startswith(region_name):
                    hosted_zone = hzone
                    hosted_zone_id = hzone.get('Id')
                    break
                if hzone.get('Name') == hosted_zone_name:
                    default_hosted_zone = hzone
        if hosted_zone:
            hosted_zone_name = hosted_zone['Name']
            LOGGER.info("found hosted zone %s", hosted_zone_name)
        else:
            hosted_zone_id = default_hosted_zone.get('Id')
            LOGGER.info(
                "cannot find hosted zone for region %s, defaults to %s",
                region_name, hosted_zone_name)

        host_name = "%(app_name)s.%(hosted_zone_name)s" % {
            'app_name': app_name, 'hosted_zone_name': hosted_zone_name}
        private_ip_addrs = [{'Value': instance['PrivateIpAddress']}
            for instance in instances]
        LOGGER.info("%supdate DNS record for %s to %s ...",
            "(dry_run) " if dry_run else "",
            host_name, [ip_addr['Value'] for ip_addr in private_ip_addrs])
        LOGGER.debug("route53.change_resource_record_sets("\
            "HostedZoneId=%(hosted_zone_id)s, ChangeBatch={'Changes':"\
            " [{'Action': 'UPSERT', 'ResourceRecordSet': {"\
            "'Name': %(host_name)s, 'Type': 'A', 'TTL': 60,"\
            " 'ResourceRecords': %(private_ip_addrs)s}}]})",
            hosted_zone_id=hosted_zone_id, host_name=host_name,
            private_ip_addrs=private_ip_addrs)
        if not dry_run:
            route53.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={'Changes': [{
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': host_name,
                        'Type': 'A',
                        # 'Region': DEFAULT_REGION
                        'TTL': 60,
                        'ResourceRecords': private_ip_addrs
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
    sg_tag_prefix = tag_prefix

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
        vpc_id, _ = _get_vpc_id(tag_prefix, ec2_client=ec2_client,
            region_name=region_name)
    if not dbs_subnet_id:
        #pylint:disable=unused-variable
        web_subnet_cidrs, dbs_subnet_cidrs, _ = _split_cidrs(
            vpc_cidr, ec2_client=ec2_client, region_name=region_name)
        dbs_subnet_by_cidrs = _get_subnet_by_cidrs(
            dbs_subnet_cidrs, tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
        # Use first valid subnet that does not require a public IP.
        dbs_subnet_id = next(dbs_subnet_by_cidrs.values())['SubnetId']

    group_ids = _get_security_group_ids(
        [vault_name], tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    instance_profile_arn = _get_instance_profile(
        vault_name, region_name=region_name)
    if instance_profile_arn:
        LOGGER.info("%s found IAM instance profile '%s'",
            tag_prefix, instance_profile_arn)
    else:
        # XXX
        raise NotImplementedError(
            "%s cannot find IAM instance profile for '%s'" % (
                tag_prefix, vault_name))

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
    instance_type = 't3.micro'
    sg_tag_prefix = tag_prefix

    gate_name = _get_security_group_names(
        ['castle-gate'], tag_prefix=sg_tag_prefix)[0]

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
        vpc_id, _ = _get_vpc_id(tag_prefix, ec2_client=ec2_client,
            region_name=region_name)
    if not web_subnet_id:
        #pylint:disable=unused-variable
        _, _, app_subnet_cidrs = _split_cidrs(
            vpc_cidr, ec2_client=ec2_client, region_name=region_name)
        app_subnet_by_cidrs = _get_subnet_by_cidrs(
            app_subnet_cidrs, tag_prefix,
            vpc_id=vpc_id, ec2_client=ec2_client)
        # Use first valid subnet that does not require a public IP.
        web_subnet_id = next(app_subnet_by_cidrs.values())['SubnetId']

    group_ids = _get_security_group_ids(
        [gate_name], tag_prefix, vpc_id=vpc_id, ec2_client=ec2_client)
    instance_profile_arn = _get_instance_profile(gate_name)
    if instance_profile_arn:
        LOGGER.info("%s found IAM instance profile '%s'",
            tag_prefix, instance_profile_arn)
    else:
        # XXX
        raise NotImplementedError(
            "%s cannot find IAM instance profile for '%s'" % (
                tag_prefix, gate_name))

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
        InstanceType=instance_type,
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
            }, {
                'Key': 'Prefix',
                'Value': tag_prefix
            }]}],
        UserData=user_data)
    instance_ids = [instance['InstanceId'] for instance in resp['Instances']]
    LOGGER.info("%s started ec2 instances %s for '%s'",
                tag_prefix, instance_ids, app_name)
    return instance_ids


def create_domain_forward(region_name, app_name, valid_domains=None,
                          tls_priv_key=None, tls_fullchain_cert=None,
                          listener_arn=None, target_group=None,
                          tag_prefix=None, dry_run=False):
    """
    Create the rules in the load-balancer necessary to forward
    requests for a domain to a specified target group.
    """
    # We attach the certificate to the load balancer listener
    cert_location = None
    if not valid_domains and tls_fullchain_cert and tls_priv_key:
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
    if cert_location and not dry_run:
        resp = elb_client.add_listener_certificates(
            ListenerArn=listener_arn,
            Certificates=[{'CertificateArn': cert_location}])

    if not target_group:
        resp = elb_client.describe_target_groups(
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
        if not dry_run:
            elb_client.modify_rule(
                RuleArn=rule_arn,
                Actions=[
                    {
                        'Type': 'forward',
                        'TargetGroupArn': target_group,
                    }
                ])
        LOGGER.info("%s%s found and modified matching listener rule %s",
            "(dry_run) " if dry_run else "", tag_prefix, rule_arn)
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
        if not dry_run:
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
        LOGGER.info("%s%s created matching listener rule %s",
            "(dry_run) " if dry_run else "", tag_prefix, rule_arn)


def create_target_group(region_name, app_name, instance_ids=None,
                        image_name=None, identities_url=None, ssh_key_name=None,
                        vpc_id=None, vpc_cidr=None, tag_prefix=None):
    """
    Create TargetGroup to forward HTTPS requests to application service.
    """
    if not vpc_id:
        vpc_id, _ = _get_vpc_id(tag_prefix, region_name=region_name)

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
    LOGGER.info("%s found/created target group %s for %s",
        tag_prefix, target_group, app_name)

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
                         region_name=None, sqs_client=None, dry_run=None):
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
    if not dry_run:
        sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(msg))
        LOGGER.info("%s send 'deploy_container' message to %s",
            app_name, queue_url)


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
        help='prefix used to tag the resources created'\
        ' (defaults to config name)')
    parser.add_argument(
        '--config', action='store',
        default=os.path.join(os.getenv('HOME'), '.aws', APP_NAME),
        help='configuration file')

    args = parser.parse_args(input_args[1:])
    config = configparser.ConfigParser()
    config.read(args.config)
    LOGGER.info("read configuration from %s", args.config)
    for section in config.sections():
        LOGGER.info("[%s]", section)
        for key, val in config.items(section):
            if key.endswith('password'):
                LOGGER.info("%s = [REDACTED]", key)
            else:
                LOGGER.info("%s = %s", key, val)

    tag_prefix = args.prefix
    if not tag_prefix:
        tag_prefix = os.path.basename(args.config)

    region_name = config['default'].get('region_name')

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

    storage_enckey = config['default'].get('storage_enckey')

    s3_default_logs_bucket = config['default'].get('s3_logs_bucket')
    if not s3_default_logs_bucket:
        s3_default_logs_bucket = '%s-logs' % tag_prefix

    if not args.skip_create_network:
        create_network(
            region_name,
            config['default']['vpc_cidr'],
            tag_prefix,
            tls_priv_key=tls_priv_key,
            tls_fullchain_cert=tls_fullchain_cert,
            ssh_key_name=ssh_key_name,
            ssh_key_content=ssh_key_content,
            storage_enckey=storage_enckey,
            s3_logs_bucket=s3_default_logs_bucket,
            sally_ip=config['default'].get('sally_ip'),
            dry_run=args.dry_run)

    # Create target groups for the applications.
    for app_name in config:
        if app_name.lower() == 'default':
            continue

        if tag_prefix and app_name.startswith(tag_prefix):
            tls_priv_key_path = config[app_name].get('tls_priv_key_path')
            tls_fullchain_path = config[app_name].get('tls_fullchain_path')
            if not tls_priv_key_path or not tls_fullchain_path:
                tls_priv_key_path = config['default'].get('tls_priv_key_path')
                tls_fullchain_path = config['default'].get('tls_fullchain_path')
            tls_priv_key = None
            tls_fullchain_cert = None
            if tls_priv_key_path and tls_fullchain_path:
                with open(tls_priv_key_path) as priv_key_file:
                    tls_priv_key = priv_key_file.read()
                with open(tls_fullchain_path) as fullchain_file:
                    tls_fullchain_cert = fullchain_file.read()
            instance_ids = config[app_name].get('instance_ids')
            if instance_ids:
                instance_ids = instance_ids.split(',')
            create_target_group(
                region_name,
                app_name,
                instance_ids=instance_ids,
                ssh_key_name=ssh_key_name,
                identities_url=config[app_name].get('identities_url'),
                image_name=config[app_name].get(
                    'image_name', config['default'].get('image_name')),
                vpc_cidr=config['default']['vpc_cidr'],
                tag_prefix=tag_prefix)
            if tls_fullchain_cert and tls_priv_key:
                create_domain_forward(
                    region_name,
                    app_name,
                    tls_priv_key=tls_priv_key,
                    tls_fullchain_cert=tls_fullchain_cert,
                    tag_prefix=tag_prefix)

        elif app_name.startswith('dbs-'):
            create_datastores(
                region_name,
                config['default']['vpc_cidr'],
                tag_prefix,
                app_name=app_name,
                storage_enckey=config[app_name].get(
                    'storage_enckey', storage_enckey),
                db_host=config[app_name].get('db_host'),
                db_master_user=config[app_name].get('db_master_user'),
                db_master_password=config[app_name].get('db_master_password'),
                db_user=config[app_name].get('db_user'),
                db_password=config[app_name].get('db_password'),
                identities_url=config[app_name].get('identities_url'),
                s3_identities_bucket=config[app_name].get(
                    's3_identities_bucket',
                    config['default'].get('s3_identities_bucket')),
                company_domain=config[app_name].get('company_domain'),
                ldap_host=config[app_name].get('ldap_host'),
                ldap_hashed_password=config[app_name].get(
                    'ldap_hashed_password'),
                image_name=config[app_name].get(
                    'image_name', config['default'].get('image_name')),
                ssh_key_name=ssh_key_name,
                provider=config[app_name].get('provider'),
                dry_run=args.dry_run)

        else:
            tls_priv_key_path = config[app_name].get('tls_priv_key_path')
            tls_fullchain_path = config[app_name].get('tls_fullchain_path')
            container_location = config[app_name].get('container_location')
            if container_location and is_aws_ecr(container_location):
                ecr_access_role_arn = config[app_name].get(
                    'ecr_access_role_arn')
                role_name = ecr_access_role_arn
            else:
                ecr_access_role_arn = None
                role_name = config[app_name].get('container_access_token')
            create_app_resources(
                region_name,
                app_name,
                config[app_name].get(
                    'image_name', config['default']['image_name']),
                instance_type=config[app_name].get(
                    'instance_type', 't3a.small'),
                storage_enckey=storage_enckey,
                ecr_access_role_arn=ecr_access_role_arn,
                settings_location=config[app_name].get('settings_location'),
                settings_crypt_key=config[app_name].get('settings_crypt_key'),
                ssh_key_name=ssh_key_name,
                s3_logs_bucket=s3_default_logs_bucket,
                s3_uploads_bucket=config[app_name].get('s3_uploads_bucket'),
                app_subnet_id=config[app_name].get('app_subnet_id',
                    config['default'].get('app_subnet_id')),
                vpc_id=config['default'].get('vpc_id'),
                vpc_cidr=config['default'].get('vpc_cidr'),
                app_prefix=app_name,
                tag_prefix=tag_prefix,
                dry_run=args.dry_run)
            if tls_fullchain_cert and tls_priv_key:
                create_domain_forward(
                    region_name,
                    config[app_name].get('version', '%s-2020-06-08' % APP_NAME),
                    tls_priv_key=tls_priv_key,
                    tls_fullchain_cert=tls_fullchain_cert,
                    tag_prefix=tag_prefix,
                    dry_run=args.dry_run)

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
                    region_name=region_name,
                    dry_run=args.dry_run)


if __name__ == '__main__':
    import sys
    main(sys.argv)

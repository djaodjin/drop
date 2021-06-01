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

import argparse, configparser, datetime, json, logging, os, re, time
from collections import OrderedDict

import boto3
import botocore.exceptions
import pytz, six
#pylint:disable=import-error
from six.moves.urllib.parse import urlparse

from .awscloud import APP_NAME, EC2_RUNNING, get_regions
from ..dparselog import parse_logname


LOGGER = logging.getLogger(__name__)


def datetime_or_now(dtime_at=None):
    if isinstance(dtime_at, six.string_types):
        look = re.match(
            r'(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})$', dtime_at)
        if look:
            kwargs = {key: int(val) for key, val in look.groupdict().items()}
            dtime_at = datetime.datetime(**kwargs)
    if not dtime_at:
        dtime_at = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
    if dtime_at.tzinfo is None:
        dtime_at = dtime_at.replace(tzinfo=pytz.utc)
    return dtime_at


def list_instances(regions=None, ec2_client=None):
    if not regions:
        regions = get_regions(ec2_client)
    runnning_instance_ids = []
    for region_name in regions:
        LOGGER.info('look for instances in region %s...', region_name)
        ec2_client = boto3.client('ec2', region_name=region_name)
        resp = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': [EC2_RUNNING]}])
        for reserv in resp['Reservations']:
            for instance in reserv['Instances']:
                runnning_instance_ids += [instance['InstanceId']]
    return runnning_instance_ids


def list_logs(log_location, domains, lognames=['access', 'error'],
              start_at=None, ends_at=None, s3_client=None):
    """
    log_location is s3://bucketname/prefix

    domains contains the logs we expect to find.
    """
    if start_at:
        start_at = datetime_or_now(start_at)
        if ends_at:
            ends_at = datetime_or_now(ends_at)
        else:
            ends_at = start_at + datetime.timedelta(1)
    else:
        if ends_at:
            ends_at = datetime_or_now(ends_at)
            start_at = ends_at - datetime.timedelta(1)
        else:
            start_at = datetime_or_now(ends_at)
            start_at = datetime.datetime(
                start_at.year, start_at.month, start_at.day)
            ends_at = start_at + datetime.timedelta(1)
    search = {domain: {logname: [] for logname in lognames}
        for domain in domains}
    if not s3_client:
        s3_client = boto3.client('s3')
    _, bucket_name, prefix = urlparse(log_location)[:3]
    if prefix.startswith('/'):
        prefix = prefix[1:]
    resp = s3_client.list_objects_v2(
        Bucket=bucket_name,
        Prefix=prefix)
    continuation = (
        resp['NextContinuationToken'] if resp['IsTruncated'] else None)
    process_log_meta(resp.get('Contents', []), search,
        start_at=start_at, ends_at=ends_at)
    while continuation:
        resp = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=prefix,
            ContinuationToken=continuation)
        continuation = (
            resp['NextContinuationToken'] if resp['IsTruncated'] else None)
        process_log_meta(resp.get('Contents', []), search,
            start_at=start_at, ends_at=ends_at)
    return search


def process_db_meta(logmetas, search, start_at=None, ends_at=None):
    """
    This function will populate the search dictionnary with the instance
    location of each log in the search template.

    example search template:
    {
      'cowork.djaoapp.com': {
        'db': []
      }
    }
    """
    if start_at:
        start_at = datetime_or_now(start_at)
        if ends_at:
            ends_at = datetime_or_now(ends_at)
        else:
            ends_at = start_at + datetime.timedelta(1)
    else:
        if ends_at:
            ends_at = datetime_or_now(ends_at)
            start_at = ends_at - datetime.timedelta(1)
        else:
            start_at = datetime_or_now(ends_at)
            start_at = datetime.datetime(
                start_at.year, start_at.month, start_at.day)
            ends_at = start_at + datetime.timedelta(1)
    backup = 'db'
    for logmeta in logmetas:
        # db backup files have the following name pattern:
        #   db_name.sql.gz
        look = re.match(r'(?P<db_name>\S+)\.sql-(?P<instance_id>[^-]+)\.gz',
            os.path.basename(logmeta['Key']))
        if look:
            db_name = look.group('db_name')
            instance_id = look.group('instance_id')
            at_date = datetime_or_now(logmeta['LastModified'])
            if start_at <= at_date and at_date < ends_at:
                try:
                    search[db_name][backup] += [(at_date, instance_id)]
                    LOGGER.info("add  %s, %s, %s, %s" % (
                        db_name, backup, instance_id, at_date.isoformat()))
                except KeyError:
                    LOGGER.info("skip %s, %s, %s, %s (on db_name or backup)" % (
                        db_name, backup, instance_id, at_date.isoformat()))
            else:
                LOGGER.info("skip %s, %s, %s, %s (on date)" % (
                    db_name, backup, instance_id, at_date.isoformat()))
        else:
            LOGGER.info("err  %s" % logmeta['Key'])


def process_log_meta(logmetas, search, start_at=None, ends_at=None):
    """
    This function will populate the search dictionnary with the instance
    location of each log in the search template.

    example search template:
    {
      'cowork.djaoapp.com': {
        'access': []
        'error': []
      }
    }
    """
    if start_at:
        start_at = datetime_or_now(start_at)
        if ends_at:
            ends_at = datetime_or_now(ends_at)
        else:
            ends_at = start_at + datetime.timedelta(1)
    else:
        if ends_at:
            ends_at = datetime_or_now(ends_at)
            start_at = ends_at - datetime.timedelta(1)
        else:
            start_at = datetime_or_now(ends_at)
            start_at = datetime.datetime(
                start_at.year, start_at.month, start_at.day)
            ends_at = start_at + datetime.timedelta(1)
    for logmeta in logmetas:
        # Log files have the following name pattern:
        #   domain-logname.log-instanceid-yyyymmdd.gz
        domain, logname, instance_id, at_date = parse_logname(
            os.path.basename(logmeta['Key']))
        if at_date:
            if start_at <= at_date and at_date < ends_at:
                try:
                    search[domain][logname] += [(at_date, instance_id)]
                    LOGGER.info("add  %s, %s, %s, %s" % (
                        domain, logname, instance_id, at_date.isoformat()))
                except KeyError:
                    LOGGER.info("skip %s, %s, %s, %s (on domain or logname)" % (
                        domain, logname, instance_id, at_date.isoformat()))
            else:
                LOGGER.info("skip %s, '%s' <= '%s' < '%s' (on date)" % (
                    logmeta['Key'], start_at.isoformat(), at_date.isoformat(),
                    ends_at.isoformat()))
        else:
            LOGGER.info("err  %s" % logmeta['Key'])


def search_db_storage(log_location, domains,
                      start_at=None, ends_at=None, s3_client=None):
    """
    We expect to find a backup for the period [``start_at``, ``ends_at``[
    in the bucket ``log_location`` for all ``domains`` listed.

    ``domains`` is a dictionary formatted as such:

        { domain: [db_name, ...] }
    """
    if start_at:
        start_at = datetime_or_now(start_at)
        if ends_at:
            ends_at = datetime_or_now(ends_at)
        else:
            ends_at = start_at + datetime.timedelta(1)
    else:
        if ends_at:
            ends_at = datetime_or_now(ends_at)
            start_at = ends_at - datetime.timedelta(1)
        else:
            start_at = datetime_or_now(ends_at)
            start_at = datetime.datetime(
                start_at.year, start_at.month, start_at.day)
            ends_at = start_at + datetime.timedelta(1)
    if not log_location.endswith('/'):
        log_location += '/'

    if not s3_client:
        s3_client = boto3.client('s3')
    _, bucket_name, prefix = urlparse(log_location)[:3]
    if prefix.startswith('/'):
        prefix = prefix[1:]

    db_to_domains = {}
    for domain, db_names in six.iteritems(domains):
        for db_name in db_names:
            if db_name in db_to_domains:
                db_to_domains[db_name] += [domain]
            else:
                db_to_domains[db_name] = [domain]

    backup = 'db'
    search = {db_name: {backup: []} for db_name in db_to_domains}
    resp = s3_client.list_objects_v2(
        Bucket=bucket_name,
        Prefix=prefix)
    continuation = (
        resp['NextContinuationToken'] if resp['IsTruncated'] else None)
    process_db_meta(resp.get('Contents', []), search,
        start_at=start_at, ends_at=ends_at)
    while continuation:
        resp = s3_client.list_objects_v2(
            Bucket=bucket_name,
            Prefix=prefix,
            ContinuationToken=continuation)
        continuation = (
            resp['NextContinuationToken'] if resp['IsTruncated'] else None)
        process_db_meta(resp.get('Contents', []), search,
            start_at=start_at, ends_at=ends_at)

    db_results = {}
    for domain, db_names in six.iteritems(domains):
        db_results[domain] = {backup: []}
        for db_name in db_names:
            db_results[domain][backup] += search[db_name][backup]

    return db_results


def search_site_log_storage(log_location, domains,
                            start_at=None, ends_at=None, s3_client=None):
    """
    We expect to find logs for the period [``start_at``, ``ends_at``[
    in the bucket ``log_location`` for all ``domains`` listed.

    ``domains`` is a dictionary formatted as such:

        { domain: [app_name, ...] }
    """
    if start_at:
        start_at = datetime_or_now(start_at)
        if ends_at:
            ends_at = datetime_or_now(ends_at)
        else:
            ends_at = start_at + datetime.timedelta(1)
    else:
        if ends_at:
            ends_at = datetime_or_now(ends_at)
            start_at = ends_at - datetime.timedelta(1)
        else:
            start_at = datetime_or_now(ends_at)
            start_at = datetime.datetime(
                start_at.year, start_at.month, start_at.day)
            ends_at = start_at + datetime.timedelta(1)
    if not log_location.endswith('/'):
        log_location += '/'
    # nginx assets proxys
    log_results = list_logs(log_location + 'var/log/nginx', domains,
        start_at=start_at, ends_at=ends_at, s3_client=s3_client)

    # app containers
    for domain, app_names in six.iteritems(domains):
        for app_name in app_names:
            app_results = list_logs(
                log_location + '%(app_name)s' % {
                    'app_name': app_name}, [app_name], lognames=['app'],
                start_at=start_at, ends_at=ends_at, s3_client=s3_client)
            log_results[domain].update(app_results[app_name])

    return log_results


def search_proxy_log_storage(log_location, domains,
                             start_at=None, ends_at=None, s3_client=None):
    """
    We expect to find logs for the period [``start_at``, ``ends_at``[
    in the bucket ``log_location`` for all ``domains`` listed.

    ``domains`` is a dictionary formatted as such:

        { domain: [app_name, ...] }
    """
    if start_at:
        start_at = datetime_or_now(start_at)
        if ends_at:
            ends_at = datetime_or_now(ends_at)
        else:
            ends_at = start_at + datetime.timedelta(1)
    else:
        if ends_at:
            ends_at = datetime_or_now(ends_at)
            start_at = ends_at - datetime.timedelta(1)
        else:
            start_at = datetime_or_now(ends_at)
            start_at = datetime.datetime(
                start_at.year, start_at.month, start_at.day)
            ends_at = start_at + datetime.timedelta(1)
    if not log_location.endswith('/'):
        log_location += '/'

    # djaoapp session proxys
    log_results = list_logs(log_location + 'var/log/gunicorn', [APP_NAME],
        lognames=['access', 'error', 'app'],
        start_at=start_at, ends_at=ends_at, s3_client=s3_client)

    return log_results


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
        '--log-location', action='store',
        default="s3://%s-logs/" % APP_NAME,
        help='location where logs are stored')
    parser.add_argument(
        '--domain', action='append',
        default=[],
        help='domain to check logs exists for')
    parser.add_argument(
        '--config', action='store',
        default=os.path.join(os.getenv('HOME'), '.aws', APP_NAME),
        help='configuration file')

    args = parser.parse_args(input_args[1:])
    config = configparser.ConfigParser()
    config.read(args.config)
    LOGGER.info("read configuration from %s", args.config)
    for section in config.sections():
        LOGGER.debug("[%s]", section)
        for key, val in config.items(section):
            if key.endswith('password'):
                LOGGER.debug("%s = [REDACTED]", key)
            else:
                LOGGER.debug("%s = %s", key, val)

    log_location = args.log_location
    domains = args.domain
    instances = list_instances()


# Copyright (c) 2025, Djaodjin Inc.
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

import argparse, configparser, datetime, gzip, json, logging, os, re

import boto3
import pytz, six
#pylint:disable=import-error
from six.moves.urllib.parse import urlparse

from ..dparselog import parse_logname


LOGGER = logging.getLogger(__name__)


APP_NAME = 'djaoapp'

EC2_RUNNING = 'running'


def as_datetime(dtime_at=None):
    if isinstance(dtime_at, six.string_types):
        look = re.match(
            r'(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})$', dtime_at)
        if look:
            kwargs = {key: int(val) for key, val in look.groupdict().items()}
            dtime_at = datetime.datetime(**kwargs)
        else:
            dtime_at = None
    if dtime_at and dtime_at.tzinfo is None:
        dtime_at = dtime_at.replace(tzinfo=pytz.utc)
    return dtime_at


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


def extract_os_release(log_content):
    """
    Extract the OS release name from the log content
    """
    os_release = None
    for line in log_content.split('\n'):
        look = re.match(r'PRETTY_NAME="(.+)"', line)
        if look:
            os_release = look.group(1)
            break
    return os_release


def get_regions(ec2_client=None):
    """
    Returns a list of names of regions available
    """
    if not ec2_client:
        ec2_client = boto3.client('ec2')
    resp = ec2_client.describe_regions()
    return [region['RegionName'] for region in resp.get('Regions', [])]


def list_instances(regions=None, ec2_client=None):
    if not regions:
        regions = get_regions(ec2_client)
    runnning_instance_ids = {}
    for region_name in regions:
        LOGGER.info('look for instances in region %s...', region_name)
        ec2_client = boto3.client('ec2', region_name=region_name)
        resp = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': [EC2_RUNNING]}])
        for reserv in resp['Reservations']:
            for instance in reserv['Instances']:
                runnning_instance_ids.update({
                    instance['InstanceId']: {'region': region_name}})
    return runnning_instance_ids


def list_instances_by_subnets(regions=None, ec2_client=None):
    #pylint:disable=too-many-locals
    if not regions:
        regions = get_regions(ec2_client)
    subnets = {}
    instances = {}
    instances_by_subnets = {}
    for region_name in regions:
        LOGGER.info('look for instances in region %s...', region_name)
        ec2_client = boto3.client('ec2', region_name=region_name)
        elb_client = boto3.client('elbv2', region_name=region_name)

        # Load balancers
        resp = elb_client.describe_load_balancers()
        for load_balancer in resp['LoadBalancers']:
            load_balancer_name = load_balancer['LoadBalancerName']
            for zone in load_balancer['AvailabilityZones']:
                subnet_id = zone['SubnetId']
                if subnet_id not in instances_by_subnets:
                    instances_by_subnets.update({
                        subnet_id: [load_balancer_name]})
                else:
                    instances_by_subnets[subnet_id] += [load_balancer_name]

        # EC2 instances
        resp = ec2_client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': [EC2_RUNNING]}])
        for reserv in resp['Reservations']:
            for instance in reserv['Instances']:
                instance_id = instance['InstanceId']
                subnet_id = instance['SubnetId']
                instances.update({instance_id: {}})
                for tag in instance['Tags']:
                    key = tag.get('Key')
                    val = tag.get('Value')
                    if key == 'Name':
                        instances[instance_id].update({'name': val})
                        break
                if subnet_id not in instances_by_subnets:
                    instances_by_subnets.update({subnet_id: [instance_id]})
                else:
                    instances_by_subnets[subnet_id] += [instance_id]

        # route tables
        default_route_table_id = None
        resp = ec2_client.describe_route_tables()
        for route_table in resp['RouteTables']:
            for assoc in route_table['Associations']:
                route_table_id = assoc['RouteTableId']
                subnet_id = assoc.get('SubnetId')
                if subnet_id:
                    if subnet_id not in subnets:
                        subnets.update({subnet_id: {
                            'route_tables': [route_table_id]}})
                    else:
                        subnets[subnet_id]['route_tables'] += [route_table_id]
                elif assoc['Main']:
                    default_route_table_id = route_table_id

        # finish populating subnets
        resp = ec2_client.describe_subnets()
        for subnet in resp['Subnets']:
            subnet_id = subnet['SubnetId']
            if subnet_id not in subnets:
                subnets.update({subnet_id: {
                    'route_tables': [default_route_table_id]}})
            subnets[subnet_id].update({
                'map_public_ip_on_launch': subnet['MapPublicIpOnLaunch'],
            })
            for tag in subnet.get('Tags', []):
                key = tag.get('Key')
                val = tag.get('Value')
                if key == 'Name':
                    subnets[subnet_id].update({'name': val})
                    break
            if subnet_id not in instances_by_subnets:
                instances_by_subnets.update({subnet_id: []})

    for subnet_id, instance_ids in six.iteritems(instances_by_subnets):
        subnet_name = subnets[subnet_id].get('name', "")
        print("%s,%s,%s,%s" % (subnet_id, subnet_name,
            subnets[subnet_id].get('map_public_ip_on_launch'),
            ','.join(subnets[subnet_id].get('route_tables'))))
        for instance_id in instance_ids:
            instance_name = instances.get(instance_id, {}).get('name', "")
            print("\t%s,%s" % (instance_id, instance_name))

    return instances_by_subnets


def list_logs(log_location, domains, lognames=['access', 'error'],
              start_at=None, ends_at=None, s3_client=None):
    """
    log_location is s3://bucketname/prefix

    domains contains the logs we expect to find.
    """
    search = {domain: {logname: [] for logname in lognames}
        for domain in domains}
    if not s3_client:
        s3_client = boto3.client('s3')
    _, bucket_name, prefix = urlparse(log_location)[:3]
    if prefix.startswith('/'):
        prefix = prefix[1:]
    LOGGER.info("list logs at s3://%s/%s", bucket_name, prefix)
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


def list_targetgroups_by_domains(regions=None, default_top_domain=None,
                                 ec2_client=None):
    """
    Returns a dictionnary of target groups indexed by domain name
    for all load balancers in a region.
    """
    #pylint:disable=too-many-locals,too-many-nested-blocks
    targetgroups_by_arns = {}
    targetgroups_by_domains = {}
    if not regions:
        regions = get_regions(ec2_client=ec2_client)
    for region_name in regions:
        if default_top_domain:
            default_domain = "%s.%s" % (region_name, default_top_domain)
        else:
            default_domain = region_name
        elb_client = boto3.client('elbv2', region_name=region_name)
        resp = elb_client.describe_load_balancers()
        for load_balancer in resp['LoadBalancers']:
            resp = elb_client.describe_target_groups(
                LoadBalancerArn=load_balancer['LoadBalancerArn'])
            for targetgroup in resp['TargetGroups']:
                targetgroups_by_arns.update({
                    targetgroup['TargetGroupArn']: targetgroup
                })
            resp = elb_client.describe_listeners(
                LoadBalancerArn=load_balancer['LoadBalancerArn'])
            for listener in resp['Listeners']:
                if listener['Port'] != 443:
                    continue
                resp = elb_client.describe_rules(
                    ListenerArn=listener['ListenerArn'])
                for rule in resp['Rules']:
                    if rule['IsDefault']:
                        action = rule['Actions'][-1]
                        targetgroup = action['TargetGroupArn']
                        targetgroups_by_domains.update({
                            default_domain: targetgroups_by_arns.get(
                                targetgroup, {}).get(
                                    'TargetGroupName', targetgroup)})
                    else:
                        for cond in rule['Conditions']:
                            action = rule['Actions'][-1]
                            if (cond['Field'] in ('host-header',) and
                                action['Type'] in ('forward',)):
                                targetgroup = action['TargetGroupArn']
                                for domain in cond['Values']:
                                    targetgroups_by_domains.update({
                                        domain: targetgroups_by_arns.get(
                                            targetgroup, {}).get(
                                            'TargetGroupName', targetgroup)})
    return targetgroups_by_domains


def list_db_meta(log_location,
                 db_names, start_at=None, ends_at=None, s3_client=None):
    """
    Returns a dictionnary `{db_name: {"db": []}` from a list of db_names.
    """
    if not log_location.endswith('/'):
        log_location += '/'

    if not s3_client:
        s3_client = boto3.client('s3')
    _, bucket_name, prefix = urlparse(log_location)[:3]
    if prefix.startswith('/'):
        prefix = prefix[1:]
    LOGGER.info("list dbs at s3://%s/%s", bucket_name, prefix)
    backup = 'db'
    search = {db_name: {backup: []} for db_name in db_names}
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
    return search


def process_db_meta(logmetas, search, start_at=None, ends_at=None):
    """
    This function will populate the search dictionnary with the instance
    location of each log in the search template.

    example search template:
    {
      'cowork': {
        'db': []
      }
    }
    """
    #pylint:disable=too-many-nested-blocks
    if start_at:
        start_at = as_datetime(start_at)
    if ends_at:
        ends_at = as_datetime(ends_at)
    name = 'db'
    for logmeta in logmetas:
        at_date = None
        # db backup files have the following name pattern:
        #   db_name.sql.gz
        key_path = logmeta['Key']
        look = re.match(r'(?P<db_name>\S+)\.sql-(?P<instance_id>[^-]+)\.gz',
            os.path.basename(key_path))
        if look:
            db_name = look.group('db_name')
            instance_id = look.group('instance_id')
            at_date = datetime_or_now(logmeta['LastModified'])
        if at_date:
            if start_at:
                if start_at <= at_date:
                    if ends_at:
                        if at_date < ends_at:
                            try:
                                search[db_name][name] += [
                                    (at_date, instance_id, key_path)]
                                LOGGER.debug("add  %s, %s, %s, %s",
                                    db_name, name, instance_id,
                                    at_date.isoformat())
                            except KeyError as err:
                                LOGGER.debug("skip %s, %s, %s, %s (on %s)",
                                    db_name, name, instance_id,
                                    at_date.isoformat(),
                                    "db_name=%s" % str(err)
                                    if str(err) == db_name
                                    else "name=%s" % str(err))
                        else:
                            LOGGER.debug(
                                "skip %s, '%s' <= '%s' < '%s' (on date)",
                                logmeta['Key'], start_at.isoformat(),
                                at_date.isoformat(), ends_at.isoformat())
                    else:
                        try:
                            search[db_name][name] += [
                                (at_date, instance_id, key_path)]
                            LOGGER.debug("add  %s, %s, %s, %s",
                                db_name, name, instance_id,
                                at_date.isoformat())
                        except KeyError as err:
                            LOGGER.debug("skip %s, %s, %s, %s (on %s)",
                                db_name, name, instance_id, at_date.isoformat(),
                                "db_name=%s" % str(err)
                                if str(err) == db_name
                                else "name=%s" % str(err))

                else:
                    LOGGER.info("skip %s, '%s' <= '%s' (on date)",
                        logmeta['Key'],
                        start_at.isoformat(), at_date.isoformat())
            elif ends_at:
                if at_date < ends_at:
                    try:
                        search[db_name][name] += [(
                            at_date, instance_id, key_path)]
                        LOGGER.debug("add  %s, %s, %s, %s",
                            db_name, name, instance_id, at_date.isoformat())
                    except KeyError as err:
                        LOGGER.debug("skip %s, %s, %s, %s (on %s)",
                            db_name, name, instance_id, at_date.isoformat(),
                            "db_name=%s" % str(err)
                            if str(err) == db_name
                            else "name=%s" % str(err))
                else:
                    LOGGER.debug("skip %s, '%s' < '%s' (on date)",
                        logmeta['Key'],
                        at_date.isoformat(), ends_at.isoformat())
            else:
                try:
                    search[db_name][name] += [(at_date, instance_id, key_path)]
                    LOGGER.debug("add  %s, %s, %s, %s",
                        db_name, name, instance_id, at_date.isoformat())
                except KeyError as err:
                    LOGGER.debug("skip %s, %s, %s, %s (on %s)",
                        db_name, name, instance_id, at_date.isoformat(),
                        "db_name=%s" % str(err)
                        if str(err) == db_name
                        else "name=%s" % str(err))
        else:
            LOGGER.debug("err  %s", key_path)


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
    #pylint:disable=too-many-nested-blocks
    if start_at:
        start_at = as_datetime(start_at)
    if ends_at:
        ends_at = as_datetime(ends_at)
    for logmeta in logmetas:
        # Log files have the following name pattern:
        #   domain-name.log-instanceid-yyyymmdd.gz
        domain, name, instance_id, at_date = parse_logname(
            os.path.basename(logmeta['Key']))
        instance_name = "i-%s" % instance_id
        search_key = instance_name if instance_name in search else domain
        if at_date:
            if start_at:
                if start_at <= at_date:
                    if ends_at:
                        if at_date < ends_at:
                            try:
                                search[search_key][name] += [
                                    (at_date, instance_id)]
                                LOGGER.debug("add  %s, %s, %s, %s",
                                    domain, name, instance_id,
                                    at_date.isoformat())
                            except KeyError as err:
                                LOGGER.debug("skip %s, %s, %s, %s (on %s)",
                                domain, name, instance_id,
                                at_date.isoformat(), err)
                        else:
                            LOGGER.debug(
                                "skip %s, '%s' <= '%s' < '%s' (on date)",
                                logmeta['Key'], start_at.isoformat(),
                                at_date.isoformat(), ends_at.isoformat())
                    else:
                        try:
                            search[search_key][name] += [
                                (at_date, instance_id)]
                            LOGGER.debug("add  %s, %s, %s, %s",
                                domain, name, instance_id,
                                at_date.isoformat())
                        except KeyError as err:
                            LOGGER.debug(
                            "skip %s, %s, %s, %s (on %s)",
                            domain, name, instance_id,
                            at_date.isoformat(), err)
                else:
                    LOGGER.debug("skip %s, '%s' <= '%s' (on date)",
                        logmeta['Key'],
                        start_at.isoformat(), at_date.isoformat())
            elif ends_at:
                if at_date < ends_at:
                    try:
                        search[search_key][name] += [(at_date, instance_id)]
                        LOGGER.debug("add  %s, %s, %s, %s",
                            domain, name, instance_id, at_date.isoformat())
                    except KeyError as err:
                        LOGGER.debug(
                            "skip %s, %s, %s, %s (on %s)",
                            domain, name, instance_id, at_date.isoformat(),
                            err)
                else:
                    LOGGER.debug("skip %s, '%s' < '%s' (on date)",
                        logmeta['Key'],
                        at_date.isoformat(), ends_at.isoformat())
            else:
                try:
                    search[search_key][name] += [(at_date, instance_id)]
                    LOGGER.debug("add  %s, %s, %s, %s",
                        domain, name, instance_id, at_date.isoformat())
                except KeyError as err:
                    LOGGER.debug("skip %s, %s, %s, %s (on %s)",
                        domain, name, instance_id, at_date.isoformat(), err)
        else:
            LOGGER.debug("err  %s", logmeta['Key'])


def search_db_storage(log_location, domains,
                      start_at=None, ends_at=None, s3_client=None):
    """
    We expect to find a backup for the period [``start_at``, ``ends_at``[
    in the bucket ``log_location`` for all ``domains`` listed.

    ``domains`` is a dictionary formatted as such:

        { domain: [db_name, ...] }
    """
    db_to_domains = {}
    for domain, db_names in six.iteritems(domains):
        for db_name in db_names:
            if db_name in db_to_domains:
                db_to_domains[db_name] += [domain]
            else:
                db_to_domains[db_name] = [domain]

    search = list_db_meta(log_location,
        db_to_domains, start_at=start_at, ends_at=ends_at, s3_client=s3_client)

    backup = 'db'
    db_results = {}
    for domain, db_names in six.iteritems(domains):
        db_results[domain] = {backup: []}
        for db_name in db_names:
            db_results[domain][backup] += search[db_name][backup]

    return db_results


def search_instance_log_storage(log_location, instance_ids,
                                start_at=None, ends_at=None, s3_client=None):
    """
    We expect to find logs for the period [``start_at``, ``ends_at``[
    in the bucket ``log_location`` for all ``instances`` listed.

    ``instances`` is a dictionary formatted as such:

        { instance_id: {} }
    """
    if not s3_client:
        s3_client = boto3.client('s3')
    _, bucket_name, prefix = urlparse(log_location)[:3]

    prefix = (prefix + 'var/log/dintegrity').lstrip('/')
    log_results = list_logs(
        log_location + prefix, instance_ids.keys(),
        start_at=start_at, ends_at=ends_at, lognames=['app'],
        s3_client=s3_client)

    for instance_id, instance_meta in six.iteritems(instance_ids):
        if instance_id in log_results:
            instance_meta.update(log_results[instance_id])
            log_prefix = None
            app_dates = instance_meta.get('app')
            if app_dates:
                at_time = app_dates[0][0].date().strftime("%Y%m%d")
                log_prefix = "%s/dintegrity-app.log-%s-%s" % (
                    prefix, instance_id[2:], at_time)
            if log_prefix:
                resp = s3_client.list_objects_v2(
                    Bucket=bucket_name,
                    Prefix=log_prefix)
                for logmeta in resp.get('Contents', []):
                    logname = logmeta['Key']
                    obj = s3_client.get_object(Bucket=bucket_name, Key=logname)
                    if logname.endswith('.gz'):
                        with gzip.GzipFile(
                                fileobj=obj['Body'], mode='rb') as logfile:
                            content = logfile.read().decode('utf-8')
                    else:
                        content = obj.read().decode('utf-8')
                    os_release = extract_os_release(content)
                    instance_meta.update({'os_release': os_release})
    return instance_ids


def search_proxy_log_storage(log_location, domains,
                             start_at=None, ends_at=None, s3_client=None):
    """
    We expect to find logs for the period [``start_at``, ``ends_at``[
    in the bucket ``log_location`` for all ``domains`` listed.

    ``domains`` is a dictionary formatted as such:

        { domain: [app_name, ...] }
    """
    if not log_location.endswith('/'):
        log_location += '/'

    # djaoapp session proxys
    log_results = list_logs(log_location + 'var/log/gunicorn', [APP_NAME],
        lognames=['access', 'error', 'app'],
        start_at=start_at, ends_at=ends_at, s3_client=s3_client)

    return log_results


def search_site_log_storage(log_location, domains,
                            start_at=None, ends_at=None, s3_client=None):
    """
    We expect to find logs for the period [``start_at``, ``ends_at``[
    in the bucket ``log_location`` for all ``domains`` listed.

    ``domains`` is a dictionary formatted as such:

        { domain: [app_name, ...] }
    """
    if not log_location.endswith('/'):
        log_location += '/'
    # nginx assets proxys
    log_results = list_logs(log_location + 'var/log/nginx', domains,
        start_at=start_at, ends_at=ends_at, s3_client=s3_client)

    # app containers
    for domain, app_names in six.iteritems(domains):
        for app_name in app_names:
            LOGGER.debug("list app logs in %s for %s",
                  log_location + '%(app_name)s' % {'app_name': app_name},
                  app_name)
            app_results = list_logs(
                log_location + '%(app_name)s' % {
                    'app_name': app_name}, [app_name], lognames=['app'],
                start_at=start_at, ends_at=ends_at, s3_client=s3_client)
            log_results[domain].update(app_results[app_name])

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
        '--region', action='append',
        default=[],
        help='Region')
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
    targetgroups_by_domains = list_targetgroups_by_domains(regions=args.region)
    print(json.dumps(targetgroups_by_domains, indent=2))
#    instances_by_subnets = list_instances_by_subnets(regions=args.region)
#    instances = list_instances()

#!/usr/bin/env python
#
# Copyright (c) 2020, DjaoDjin inc.
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

"""
Command-line tool to populate an Elastic Search index.
"""

import argparse, json, gzip, os.path, tempfile, sys, time
from collections import namedtuple
from datetime import datetime
from copy import deepcopy

from ansible.playbook import Playbook
from ansible.template import Templar
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.inventory import Inventory
from ansible.parsing.dataloader import DataLoader
from ansible.vars import VariableManager
import botocorecore, boto3
from elasticsearch import Elasticsearch
import elasticsearch.helpers
from pprint import pprint
import sqlite3
import urllib3, urllib3.util
import tero
import tero.dparselog


def events(fname):
    with gzip.open(fname) as f:
        for line in f:
            yield json.loads(line)

def create_index_templates(es):
    # make sure an index template exists so that new indexes that are
    # created automatically have the correct type mappings.
    # http://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html
    es.indices.put_template(name='logs_template',
                            body={
                                "template": "logs-*",
                                "mappings": {
                                    "log": {
                                        "properties": {
                                            "ip_num": {
                                                "type": "ip"
                                            },
                                            "time_local": {
                                                "type": "date",
                                            },
                                            "s3_key": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "host": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "request": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "http_referer": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "http_path": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "http_request": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                        }
                                    }
                                }
                            })



    es.indices.put_template(name='errors_template',
                            body={
                                "template": "parse-errors*",
                                "mappings": {
                                    "parse-error": {
                                        "properties": {
                                            "log_filename": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "parse_time": {
                                                "type": "date",
                                            },
                                            "log_date": {
                                                "type": "date",
                                            },
                                            "s3_key": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "reason": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "log_folder": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "line": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "exception_message": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                            "exception_type": {
                                                "type": "string",
                                                "index": "not_analyzed",
                                            },
                                        }
                                    }
                                }
                            })


def create_tables(db):
    db.execute('''CREATE TABLE IF NOT EXISTS UPLOAD
             (dt text, key text primary key, line integer, finished integer)''')


def sync_fileobj(fileobj, es, name):
    gzfile = gzip.GzipFile(fileobj=fileobj, mode='rb')
    gzip_stream = enumerate(gzfile)

    events_stream = tero.dparselog.generate_events(gzip_stream, name)

    return elasticsearch.helpers.bulk(
        es, events_stream,
        request_timeout=500,
        raise_on_error=False,
        raise_on_exception=False)


def sync(log_paths, es, location=None, db=None, force=False):
    """
    Insert log records into Elastic Search.
    """
    create_index_templates(es)

    conn = None
    keys = log_paths
    if location:
        log_url = urllib3.util.parse_url(location)
        if log_url.scheme == 's3':
            s3_bucket = log_url.host
            s3_prefix = log_url.path
            if s3_prefix.startswith('/'):
                s3_prefix = s3_prefix[1:]
            s3_resource = boto3.resource('s3')
            if not log_paths:
                keys = s3_resource.Bucket(s3_bucket).objects.filter(
                    Prefix=s3_prefix)
            else:
                keys = [s3_resource.Object(s3_bucket, path)
                    for path in log_paths]

    for key in keys:
        if isinstance(key, s3_resource.Object):
            name = key.key
        else:
            name = key

        if force:
            finished = False
        else:
            db.execute('select finished from UPLOAD where key=?', (name,))
            row = db.fetchone()
            finished = (row and row[0])

        if not finished:
            sys.stderr.write('uploading %s...\n' % name)

            if isinstance(key, s3_resource.Object):
                try:
                    with tempfile.TemporaryFile() as temp_file:
                        key.get_contents_to_file(temp_file)
                        temp_file.seek(0)
                        (successes, errors) = sync_fileobj(temp_file, es, name)
                except botocore.exceptions.ClientError as err:
                    # We might get an InvalidObjectState if the file
                    # has been moved to Glacier already.
                    (successes, errors) = (0, [str(err)])
            else:
                with open(name, 'rb') as fileobj:
                    (successes, errors) = sync_fileobj(fileobj, es, name)

            sys.stdout.write('%s: %d successes, %d errors\n'
                % (name, successes, len(errors)))

            if errors:
                sys.stdout.write('error: %s\n' % str(errors))
            else:
                row_data = (datetime.now().isoformat(), name, True)
                db.execute(
    'INSERT OR REPLACE into UPLOAD (dt,key,finished) VALUES (?,?,?)', row_data)
                sys.stdout.write('%s: cache results\n' % name)
        else:
            sys.stdout.write('%s: cached (skipping)\n' % name)


def normalized_config(full_config):
    status = full_config['DomainStatus']
    necessary_keys = ['DomainName',
                      'ElasticsearchClusterConfig',
                      'EBSOptions',
                      'SnapshotOptions',
                      'AdvancedOptions',
                      'AccessPolicies']
    config = {k: status[k] for k in necessary_keys}

    return config


def set_config_and_wait(es_client, config):
    """
    Change configuration of AWS-hosted ES cluster
    """
    sys.stdout.write('updating Elasticsearch config to:\n')
    pprint(config)
    sys.stdout.write('\n')

    es_client.update_elasticsearch_domain_config(**config)

    while True:
        full_config = es_client.describe_elasticsearch_domain(
            DomainName=config['DomainName'])
        is_processing = full_config['DomainStatus']['Processing']
        is_config_updated = (normalized_config(full_config) == config)
        sys.stdout.write('waiting for config change to complete...\n')

        if not is_processing and is_config_updated:
            break

        time.sleep(15)

    sys.stdout.write('done configuring.\n')


def pub_initcache(db_path='elasticsearch_uploads.sqlite3'):
    """
    Create or re-create a SQLite3 database to store names of log files
    already uploaded into the Elastic Search index.

    --db_path
        Name of the sqlite3 file to store progress.
        Assumes the tables have been created correctly
        defaults to 'elasticsearch_uploads.sqlite3'
    """
    dbconn = sqlite3.connect(db_path)
    # auto commit
    dbconn.isolation_level = None
    db = dbconn.cursor()

    create_tables(db)
    sys.stdout.write('db created at %s\n' % db_path)


def pub_load(log_paths, location=None,
             db_path='elasticsearch_uploads.sqlite3', no_cache=False,
             elasticsearch_domain=None, no_reconfigure=True,
             elasticsearch_host=None,
             force=False):
    """
    Load logs into Elastic Search index.

    log_paths
        List of logs to index into Elastic Search

    --location
        Location of the logs (ex: s3://bucket/logs)

    --db_path
        Name of the sqlite3 file to store progress.
        Assumes the tables have been created correctly
        defaults to 'elasticsearch_uploads.sqlite3'

    --no-cache
        Don't store or read from a db to keep track
        of progress

    --no-reconfigure
        By default, the cluster is reconfigured before
        loading data and restored afterwards

    --elasticsearch-domain
       The elasticsearch domain to use. This overrides
       the default host of localhost:9200, but not
       an explicitly set --elasticsearch-host.
       This is also used to reconfigure the cluster
       before and after loading data.

    --elasticsearch-host
        The elasticsearch host in the form <host>:<port>
        or <host> which assumes port 80.
        If no host is given, then defaults
        to localhost:9200 or uses the information
        derived from --elasticsearch-domain.

    --force
        Upload keys even if we've already uploaded
        them before
    """
    if no_cache:
        # cheat and use an inmemory db
        dbconn = sqlite3.connect(":memory:")
        # auto commit
        dbconn.isolation_level = None
        db = dbconn.cursor()
        create_tables(db)
    elif not os.path.exists(db_path):
        raise Exception(
            "Progress cache not found. Run '%s initcache' first." % sys.argv[0])
    else:
        dbconn = sqlite3.connect(db_path)
        # auto commit
        dbconn.isolation_level = None
        db = dbconn.cursor()

    es_client = None
    beefier_config = None
    smaller_config = None
    es_host = None
    es_port = None
    if elasticsearch_domain:
        es_client = boto3.client('es')

        full_config = es_client.describe_elasticsearch_domain(
            DomainName=elasticsearch_domain)
        es_host = full_config['DomainStatus']['Endpoint']
        es_port = '80'

        if not args.no_reconfigure:
            old_config = normalized_config(full_config)

            beefier_config = deepcopy(old_config)
            beefier_config['ElasticsearchClusterConfig']['InstanceType'] \
                = 'm3.medium.elasticsearch'

            smaller_config = deepcopy(old_config)
            smaller_config['ElasticsearchClusterConfig']['InstanceType'] \
                = 't2.micro.elasticsearch'

    if elasticsearch_host:
        host_parts = elasticsearch_host.split(':')

        es_host = host_parts[0]
        es_port = host_parts[1] if len(host_parts) > 1 else 80

    elif es_host is None and es_port is None:
        es_host = 'localhost'
        es_port = '9200'

    es = Elasticsearch([{'host': es_host, 'port': es_port}])
    # enable gzip compression
    # https://github.com/elastic/elasticsearch-py/issues/252
    connection = es.transport.get_connection()
    connection.headers.update(urllib3.make_headers(accept_encoding=True))

    started = False
    if not es.ping():
        sys.stderr.write("warning: ElasticSearch is not responding,"\
            " will attempt to start instances")
        started = True
        pub_start([])
        time.sleep(300) # wait for instance to finish startup and dns to settle.

    try:
        if beefier_config:
            set_config_and_wait(es_client, beefier_config)

        sync(log_paths, es, location=location, db=db, force=force)
    finally:
        if smaller_config:
            set_config_and_wait(es_client, smaller_config)

    if started:
        # I started the cluster so I will stop it here.
        pub_stop([])


def _execute_playbook(playbook_name):
    """
    Execute a playbook stored in the *share_dir*.
    """
    install_dir = os.path.dirname(os.path.dirname(sys.executable))
    share_dir = os.path.join(install_dir, 'share', 'dws')
    playbook_path = os.path.join(share_dir, 'playbooks', playbook_name)
    if not os.path.exists(playbook_path):
        # When running directly from within src_dir.
        share_dir = os.path.join(install_dir, 'share')
        playbook_path = os.path.join(share_dir, 'playbooks', playbook_name)
    sysconf_dir = os.path.join(install_dir, 'etc')
    Options = namedtuple('Options', ['connection', 'module_path', 'forks',
        'become', 'become_method', 'become_user', 'check'])
    options = Options(connection='local',
        module_path=os.path.dirname(tero.__file__), forks=100, become=None,
        become_method=None, become_user=None, check=False)
    passwords = dict(vault_pass='secret')
    loader = DataLoader()
    variable_manager = VariableManager()
    inventory = Inventory(loader=loader, variable_manager=variable_manager,
        host_list=os.path.join(sysconf_dir, 'ansible', 'hosts'))
    variable_manager.set_inventory(inventory)
    playbook = Playbook.load(playbook_path,
        variable_manager=variable_manager, loader=loader)
    tqm = None
    try:
        tqm = TaskQueueManager(
            inventory=inventory,
            variable_manager=variable_manager,
            loader=loader,
            options=options,
            passwords=passwords)
        for play in playbook.get_plays():
            result = tqm.run(play)
    finally:
        if tqm is not None:
            tqm.cleanup()


def pub_start(args):
    """
    Start the ES cluster if not already running.
    """
    _execute_playbook(playbook_name='aws-start-elasticsearch-instance.yml')


def pub_stop(args):
    """
    Stop the ES cluster if running.
    """
    _execute_playbook(playbook_name='aws-stop-elasticsearch-instance.yml')


def main():
    """
    Main Entry Point
    """
    import __main__

    parser = argparse.ArgumentParser(
        usage='%(prog)s [options] command\n\nVersion\n  %(prog)s version '
        + str(tero.__version__),
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--version', action='version',
        version='%(prog)s ' + str(tero.__version__))
    tero.build_subcommands_parser(parser, __main__)
    args = parser.parse_args()

    # Filter out options with are not part of the function prototype.
    func_args = tero.filter_subcommand_args(args.func, args)
    args.func(**func_args)


if __name__ == '__main__':
    main()

import re
import itertools
from elasticsearch import Elasticsearch
import elasticsearch.helpers
import json
import gzip
import urllib3
import boto
import boto3
import tempfile
import dparselog
from datetime import datetime
import sqlite3
import os.path
import argparse
import sys
from copy import deepcopy
import time
from pprint import pprint

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


completed = set()
def run():
    root = '/var/tmp/djaodjin-logs/tmp'
    fs = os.listdir(root)
    es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
    create_index_templates(es)


    # enable gzip compression
    # https://github.com/elastic/elasticsearch-py/issues/252
    connection = es.transport.get_connection()
    connection.headers.update(urllib3.make_headers(accept_encoding=True))


    for fname in fs:
        fname = '%s/%s' % (root, fname)
        if fname.endswith('.gz'):
            if  fname in completed:
                print 'already done'
                continue
            print 'uploading %s' % fname
            elasticsearch.helpers.bulk(es, events(fname), request_timeout=500)
            
            completed.add(fname)


DB_NAME = 'elastsearch_uploads.sqlite3'

def backfill():
    with open('/var/tmp/djaodjin-logs/loglist.txt') as f:
        finished_keys = list(x[:-1] for x in f)

    conn = sqlite3.connect(DB_NAME)
    conn.isolation_level = None
    c = conn.cursor()
    for k in finished_keys:
        c.execute('INSERT OR REPLACE into UPLOAD (dt,key,finished) VALUES (?,?,?)', (datetime.now().isoformat(),
                                                                          k,
                                                                          True))

def create_tables(db):
    db.execute('''CREATE TABLE IF NOT EXISTS UPLOAD
             (dt text, key text primary key, line integer, finished integer)''')

def sync(db, es,s3_bucket=None, s3_prefix=None,s3_keys=None,force=False):


    create_index_templates(es)
    conn = boto.connect_s3()

    bucket = conn.get_bucket(s3_bucket)
    if s3_keys:
        s3_keys = (bucket.get_key(k) for k in s3_keys)
    else:
        s3_keys = bucket.list(prefix=s3_prefix)



    for key in s3_keys:

        if force:
            finished = False
        else:
            db.execute('select finished from UPLOAD where key=?', (key.key,))
            row = db.fetchone()
            finished = (row and row[0])

        if not finished:
            print 'uploading %s...' % key.key
            with tempfile.TemporaryFile() as f:
                key.get_contents_to_file(f)
                f.seek(0)

                gzfile = gzip.GzipFile(fileobj=f, mode='rb')
                gzip_stream = enumerate(gzfile)

                events_stream = dparselog.generate_events(gzip_stream, key.key)

                (successes, errors) = elasticsearch.helpers.bulk(es, events_stream , request_timeout=500, raise_on_error=False, raise_on_exception=False)

            print 'successes:', successes
            print 'errors:', errors

            if not errors:
                row_data = (datetime.now().isoformat(),
                            key.key,
                            True)
                db.execute('INSERT OR REPLACE into UPLOAD (dt,key,finished) VALUES (?,?,?)', row_data)
                print 'done %s' % key.key
        else:
            print 'skipping %s' % key.key


def normalized_config(full_config):
    status = full_config['DomainStatus']
    necessary_keys = ['DomainName', 'ElasticsearchClusterConfig', 'EBSOptions', 'SnapshotOptions', 'AdvancedOptions', 'AccessPolicies']
    config = { k: status[k] for k in necessary_keys}

    return config


def set_config_and_wait(es_client, config):
    print 'updating Elasticsearch config to:'
    pprint(config)
    print

    es_client.update_elasticsearch_domain_config(**config)

    while True:
        full_config = es_client.describe_elasticsearch_domain(DomainName=config['DomainName'])
        is_processing = full_config['DomainStatus']['Processing']
        is_config_updated = (normalized_config(full_config) == config)
        print 'waiting for config change to complete...'

        if not is_processing and is_config_updated:
            break

        time.sleep(15)

    print 'done configuring.'


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--db',
                        help='Name of the sqlite3 file to store progress. Assumes the tables have been created correctly',
                        default='elasticsearch_uploads.sqlite3')
    parser.add_argument('--create-db', action='store_true',
                        help='Creates a db file with the correct tables and exits.')
    parser.add_argument('--elasticsearch-host',
                        help='''The elasticsearch host in the form <host>:<port> or <host> which assumes port 80.
If no host is given, then defaults to localhost:9200 or uses the information derived from the --elasticsearch-domain''')

    parser.add_argument('--s3-bucket',
                        help='''S3 bucket to use for finding logs.''')
    parser.add_argument('--s3-prefix',
                        help='''S3 prefix to use when searching for logs.''')
    parser.add_argument('s3_keys', nargs='*',
                        help='list of s3 keys to upload')
    parser.add_argument('--force',action='store_true',
                        help="upload keys even if we've already uploaded them before")
    parser.add_argument('--no-db',action='store_true',
                        help="don't store or read from a db to keep track of progress")
    parser.add_argument('--no-reconfigure',action='store_true',
                        help="By default, the cluster is reconfigured before loading data and restored afterwards")
    parser.add_argument('--elasticsearch-domain',
                        help='The elasticsearch domain to use. This overrides the default host of localhost:9200, but not an explicitly set --elasticsearch-host. This is also used to reconfigure the cluster before and after loading data.')

    args = parser.parse_args()

    if not args.create_db and not os.path.exists(args.db):

        raise Exception('Progress database not found. Create first with --create-db')

    if args.no_db:
        # cheat and use an inmemory db
        dbconn = sqlite3.connect(":memory:")
        # auto commit
        dbconn.isolation_level = None
        db = dbconn.cursor()

        create_tables(db)
    else:
        dbconn = sqlite3.connect(args.db)
        # auto commit
        dbconn.isolation_level = None
        db = dbconn.cursor()

        if args.create_db:
            create_tables(db)
            print 'db created at %s' % args.db
            sys.exit(0)

    es_client = None
    beefier_config = None
    smaller_config = None
    es_host = None
    es_port = None
    if args.elasticsearch_domain:
        es_client = boto3.client('es')

        full_config = es_client.describe_elasticsearch_domain(DomainName=args.elasticsearch_domain)
        es_host = full_config['DomainStatus']['Endpoint']
        es_port = 80

        if not args.no_reconfigure:
            old_config = normalized_config(full_config)

            beefier_config = deepcopy(old_config)
            beefier_config['ElasticsearchClusterConfig']['InstanceType'] = 'm3.medium.elasticsearch'

            smaller_config = deepcopy(old_config)
            smaller_config['ElasticsearchClusterConfig']['InstanceType'] = 't2.micro.elasticsearch'

    if args.elasticsearch_host:
        host_parts = args.elasticsearch_host.split(':')

        es_host = host_parts[0]
        es_port = host_parts[1] if len(host_parts) > 1 else 80

    elif es_host is None and es_port is None:
        es_host = 'localhost'
        es_port = '9200'

    es = Elasticsearch([{'host': es_host, 'port': es_port}])

    try:
        if beefier_config:
            set_config_and_wait(es_client, beefier_config)

        sync(db, es, s3_bucket=args.s3_bucket, s3_prefix=args.s3_prefix, s3_keys=args.s3_keys, force=args.force)
    finally:
        if smaller_config:
            set_config_and_wait(es_client, smaller_config)




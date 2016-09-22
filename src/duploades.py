import re
import itertools
from elasticsearch import Elasticsearch
import elasticsearch.helpers
import json
import gzip
import urllib3
import boto
import tempfile
import dparselog
from datetime import datetime
import sqlite3
import os.path
import argparse
import sys

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

def sync(db, es):


    create_index_templates(es)

    s3_bucket='djaodjin'
    prefix='private/'

    conn = boto.connect_s3()
    bucket = conn.get_bucket(s3_bucket)

    for key in bucket.list(prefix=prefix):
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
                elasticsearch.helpers.bulk(es, events_stream , request_timeout=500)

            row_data = (datetime.now().isoformat(),
                        key.key,
                        True)
            db.execute('INSERT OR REPLACE into UPLOAD (dt,key,finished) VALUES (?,?,?)', row_data)
            print 'done %s' % key.key
        else:
            print 'skipping %s' % key.key


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--db',
                        help='Name of the sqlite3 file to store progress. Assumes the tables have been created correctly',
                        default='elasticsearch_uploads.sqlite3')
    parser.add_argument('--create-db', action='store_true',
                        help='Creates a db file with the correct tables and exits.')
    parser.add_argument('--elasticsearch-host', default='localhost:9200',
                        help='''The elasticsearch host in the form <host>:<port> or <host> which assumes port 80.
If no host is given, then defaults to localhost:9200''')

    args = parser.parse_args()

    if not args.create_db and not os.path.exists(args.db):

        raise Exception('Progress database not found. Create first with --create-db')

    dbconn = sqlite3.connect(args.db)
    # auto commit
    dbconn.isolation_level = None
    db = dbconn.cursor()

    if args.create_db:
        create_tables(db)
        print 'db created at %s' % args.db
        sys.exit(0)

    host_parts = args.elasticsearch_host.split(':')

    es_host = host_parts[0]
    es_port = host_parts[1] if len(host_parts) > 1 else 80

    es = Elasticsearch([{'host': es_host, 'port': es_port}])

    sync(db,es)



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

def createdb():
    dbconn = sqlite3.connect(DB_NAME)
    # auto commit
    dbconn.isolation_level = None
    db = dbconn.cursor()

    db.execute('''CREATE TABLE IF NOT EXISTS UPLOAD
             (dt text, key text primary key, line integer, finished integer)''')

def sync():

    dbconn = sqlite3.connect(DB_NAME)
    # auto commit
    dbconn.isolation_level = None
    db = dbconn.cursor()

    es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
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
            print 'uploading %s...' % key.key,
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
            print 'done'
        else:
            print 'skipping %s' % key.key


if __name__ == '__main__':
    if not os.path.exists(DB_NAME):
        raise Exception('no db') 

    sync()



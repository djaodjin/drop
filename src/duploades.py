import re
import itertools
from elasticsearch import Elasticsearch
import elasticsearch.helpers
import json
import gzip

def events(fname):
    with gzip.open(fname) as f:
        for line in f:
            yield json.loads(line)
    
completed = set()
def run():
    root = '/var/tmp/djaodjin-logs/tmp2'
    fs = os.listdir(root)
    es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
    for fname in fs:
        fname = '%s/%s' % (root, fname)
        if fname.endswith('.gz'):
            if  fname in completed:
                print 'already done'
                continue
            print 'uploading %s' % fname
            try:
                event = next(iter(events(fname)))
            except StopIteration:
                print 'no events in this file!'
                completed.add(fname)
                continue


            index = event['_index']
            if not es.indices.exists(index):
                # es.indices.delete(index)
                es.indices.create(index=index,body={
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

            elasticsearch.helpers.bulk(es, events(fname), request_timeout=500)
            
            completed.add(fname)





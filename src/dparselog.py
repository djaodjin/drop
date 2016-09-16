import re
import itertools
from elasticsearch import Elasticsearch
import elasticsearch.helpers
from datetime import tzinfo, timedelta, datetime
import gzip
import os, os.path
import json

# http://stackoverflow.com/questions/1101508/how-to-parse-dates-with-0400-timezone-string-in-python/23122493#23122493
class FixedOffset(tzinfo):
    """Fixed offset in minutes: `time = utc_time + utc_offset`."""
    def __init__(self, offset):
        self.__offset = timedelta(minutes=offset)
        hours, minutes = divmod(offset, 60)
        #NOTE: the last part is to remind about deprecated POSIX GMT+h timezones
        #  that have the opposite sign in the name;
        #  the corresponding numeric value is not used e.g., no minutes
        self.__name = '<%+03d%02d>%+d' % (hours, minutes, -hours)
    def utcoffset(self, dt=None):
        return self.__offset
    def tzname(self, dt=None):
        return self.__name
    def dst(self, dt=None):
        return timedelta(0)
    def __repr__(self):
        return 'FixedOffset(%d)' % (self.utcoffset().total_seconds() / 60)

def parse_date(dt_str):
    naive_date_str, offset_str = dt_str.split(' ')
    naive_dt = datetime.strptime(naive_date_str, '%d/%b/%Y:%H:%M:%S')
    
    offset = int(offset_str[-4:-2])*60 + int(offset_str[-2:])
    if offset_str[0] == "-":
        offset = -offset
    dt = naive_dt.replace(tzinfo=FixedOffset(offset))

    return dt

def convert_bytes_sent(s):
    if s == '-':
        return None
    else:
        return int(s)

def generate_regex(format_string, var_regex, regexps):
    format_vars  =  re.findall(var_regex, format_string)

    var_matches  =  list(re.finditer(var_regex, format_string))

    var_match_positions  =  [(match.start(),match.end()) for match in var_matches]

    non_var_indexes  =  [0] + list(itertools.chain(*var_match_positions)) + [len(format_string)]

    grouped_non_var_indexes = [ (non_var_indexes[i*2],non_var_indexes[i*2+1]) for i in range(len(non_var_indexes)/2)]

    non_var_strings = [format_string[start:end] for start,end in grouped_non_var_indexes]
    escaped_non_var_strings = [re.escape(s) for s in non_var_strings]

    named_regexps = ['(' + regexps[s] + ')' for i,s in enumerate(format_vars)]
    full_regex_pieces = list(itertools.chain(*itertools.izip_longest(escaped_non_var_strings, named_regexps,fillvalue='')))

    full_regex  =  ''.join(full_regex_pieces[:])

    return re.compile(full_regex)


class NginxLogParser(object):

    def __init__(self):
        format_string = '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"'

        var_regex = r'\$[a-z_]+'
        ip_num_regex  =  r'[0-9]{1,3}'
        regexps  =  {
            '$ip_num'               : r'[0-9]{1,3}',
            '$remote_addr'          : '\\.'.join([ip_num_regex] * 4),
            '$remote_user'          : r'-',
            '$time_local'           : r'[^\[\]]+',
            '$request'              : r'[A-Z]+ .* HTTP/1.[01]', # r'(?P<http_method>[A-Z]+) (?P<http_path>.*) HTTP/1.1',
            '$status'               : r'[0-9]{3}',
            '$body_bytes_sent'      : r'[0-9]+',
            '$http_referer'         : r'[^"]+',
            '$http_user_agent'      : r'[^"]+',
            '$http_x_forwarded_for' : r'[^"]+',
        }
        self.format_vars  =  re.findall(var_regex, format_string)
        self.regex = generate_regex(format_string, var_regex, regexps)
        

    def parse(self, to_parse):
        match  =  self.regex.match(to_parse)
        if match:
            parsed = dict(zip(self.format_vars, match.groups()))
        else:
            return None

        parsed = { k[1:]: v for k,v in parsed.items() }

        field_types = {
            'status' : int,
            'body_bytes_sent': int,
            'time_local': parse_date,
        }
        for k, convert in field_types.items():
            parsed[k] = convert(parsed[k])

        request_regex = r'(?P<http_method>[A-Z]+) (?P<http_path>.*) HTTP/1.[01]'
        request_match = re.match(request_regex, parsed['request'])
        if request_match:
            parsed.update(request_match.groupdict())

        return parsed


class GunicornLogParser(object):

    def __init__(self):
        format_string = '''%({X-Forwarded-For}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'''

        var_regex = r'%\([^)]+\)s'
        ip_num_regex  =  r'[0-9]{1,3}'
        regexps = {
            '%({X-Forwarded-For}i)s': '\\.'.join([ip_num_regex] * 4),
            '%(l)s': r'-',
            '%(u)s': r'-',
            '%(t)s': r'\[[^\]]+]',
            '%(r)s': r'[A-Z]+ .* HTTP/1.[01]',
            '%(s)s': r'[0-9]{3}',
            '%(b)s': r'-|[0-9]+',
            '%(f)s': r'[^"]+',
            '%(a)s': r'[^"]+',
        }


        self.format_vars = re.findall(var_regex, format_string)
        self.regex = generate_regex(format_string, var_regex, regexps)
        

    def parse(self, to_parse):
        match  =  self.regex.match(to_parse)
        if match:
            parsed = dict(zip(self.format_vars, match.groups()))
        else:
            return None

        better_names = {
            '%({X-Forwarded-For}i)s': 'http_x_forwarded_for',
            '%(l)s': 'dash',
            '%(u)s': 'username',
            '%(t)s': 'time_local',
            '%(r)s': 'request',
            '%(s)s': 'status',
            '%(b)s': 'body_bytes_sent',
            '%(f)s': 'http_referer',
            '%(a)s': 'http_user_agent',
        }
        parsed = { better_names[k] : v for k,v in parsed.items()}

        request_regex = r'(?P<http_method>[A-Z]+) (?P<http_path>.*) HTTP/1.[01]'
        request_match = re.match(request_regex, parsed['request'])

        if request_match:
            parsed.update(request_match.groupdict())

        field_types = {
            'status' : int,
            'body_bytes_sent': convert_bytes_sent,
            'time_local': lambda s: parse_date(s[1:-1]),
        }
        for k, convert in field_types.items():
            parsed[k] = convert(parsed[k])

        return parsed



def parse_format(to_parse, format_string, var_regex, regexps):

    # format_vars  =  re.findall(var_regex, format_string)

    # var_matches  =  list(re.finditer(var_regex, format_string))

    # var_match_positions  =  [(match.start(),match.end()) for match in var_matches]

    # non_var_indexes  =  [0] + list(itertools.chain(*var_match_positions)) + [len(format_string)]

    # grouped_non_var_indexes = [ (non_var_indexes[i*2],non_var_indexes[i*2+1]) for i in range(len(non_var_indexes)/2)]

    # non_var_strings = [format_string[start:end] for start,end in grouped_non_var_indexes]
    # escaped_non_var_strings = [re.escape(s) for s in non_var_strings]

    # named_regexps = ['(' + regexps[s] + ')' for i,s in enumerate(format_vars)]
    # full_regex_pieces = list(itertools.chain(*itertools.izip_longest(escaped_non_var_strings, named_regexps,fillvalue='')))

    # full_regex  =  ''.join(full_regex_pieces[:])

    regex = generate_regex(format_string, var_regex, regexps)

    match  =  regex.search(full_regex,to_parse)
    if match:
        return dict(zip(format_vars, match.groups()))
    else:
        return None


def parse_gunicorn_log(nginx_log):
    format_string = '''%({X-Forwarded-For}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'''

    var_regex = r'%\([^)]+\)s'
    ip_num_regex  =  r'[0-9]{1,3}'
    regexps = {
        '%({X-Forwarded-For}i)s': ip_num_regex,
        '%(l)s': r'-',
        '%(u)s': r'-',
        '%(t)s': r'\[[^\]]+]',
        '%(r)s': r'[A-Z]+ .* HTTP/1.[01]',
        '%(s)s': r'[0-9]{3}',
        '%(b)s': r'-|[0-9]+',
        '%(f)s': r'[^"]+',
        '%(a)s': r'[^"]+',
    }
    parsed = parse_format(nginx_log, format_string, var_regex, regexps)
    if parsed is None:
        return None

    better_names = {
        '%({X-Forwarded-For}i)s': 'http_x_forwarded_for',
        '%(l)s': 'dash',
        '%(u)s': 'username',
        '%(t)s': 'time_local',
        '%(r)s': 'request',
        '%(s)s': 'status',
        '%(b)s': 'body_bytes_sent',
        '%(f)s': 'http_referer',
        '%(a)s': 'http_user_agent',
    }
    parsed = { better_names[k] : v for k,v in parsed.items()}
    
    request_regex = r'(?P<http_method>[A-Z]+) (?P<http_path>.*) HTTP/1.[01]'
    request_match = re.match(request_regex, parsed['request'])

    if request_match:
        parsed.update(request_match.groupdict())
    
    field_types = {
        'status' : int,
        'body_bytes_sent': convert_bytes_sent,
        'time_local': lambda s: parse_date(s[1:-1]),
    }
    for k, convert in field_types.items():
        parsed[k] = convert(parsed[k])

    return parsed


def parse_nginx_log(nginx_log):
    parsed = parse_format(nginx_log, format_string, var_regex, regexps)
    if parsed is None:
        return None

    parsed = { k[1:]: v for k,v in parsed.items() }

    field_types = {
        'status' : int,
        'body_bytes_sent': int,
        'time_local': parse_date,
    }
    for k, convert in field_types.items():
        parsed[k] = convert(parsed[k])

    request_regex = r'(?P<http_method>[A-Z]+) (?P<http_path>.*) HTTP/1.[01]'
    request_match = re.match(request_regex, parsed['request'])
    if request_match:
        parsed.update(request_match.groupdict())

    return parsed


# with open('/Users/adrian/Downloads/djaoapp.com-access.log-062d8892-20160821') as f:
#     for line in f:
#         print parse_nginx_log(line)

gunicorn_test_string = '''108.252.136.229 - - [09/Aug/2016:10:15:32 -0700] "GET / HTTP/1.0" 500 3840 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"'''
nginx_test_string = '''183.129.160.229 - - [20/Aug/2016:03:34:59 +0000] "GET / HTTP/1.1" 444 0 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:47.0) Gecko/20100101 Firefox/47.0" "-"'''

# parse_nginx_log(nginx_test_string)


# completed = set()

# with open('state.json','w') as f:
#     json.dump( list(completed), f)

def generate_events(root, key):

    fname = os.path.basename(key)
    match = re.match(r'(?P<host>\S+)-(?P<logname>\S+)\.log-(?P<instance_id>[^-]+)-(?P<log_date>[^.]+).*\.gz', fname)
    if not match:
        print 'not a log file? %s' % fname

        return

    full_path = os.path.join( root, key)
    log_folder = os.path.basename(os.path.dirname(key))
    if log_folder == 'nginx':
        log_type = 'webfront'
    elif log_folder == 'gunicorn':
        if fname.startswith('djaodjin-access.log-'):
            log_type = 'djsession'
        else:
            log_type = 'customer'
        
    else:
        log_type = None

    index = 'logs-%s' % (match.group('log_date'))
    doc_type = 'log'

    nginx_parser = NginxLogParser()
    gunicorn_parser = GunicornLogParser()

    error_count = 0
    ok_count = 0
    with gzip.open(full_path) as f:
        for i, line in enumerate(f):
            total_count = ok_count + error_count
            if total_count > 100 and (float(error_count)/total_count) > 0.8:
                print 'too many errors. bailing'
                return

            # remove endline
            line = line[:-1]
            try:
                if log_folder == 'nginx':
                    event = nginx_parser.parse(line)
                elif log_folder == 'gunicorn':
                    event = gunicorn_parser.parse(line)
                else:
                    print 'unknown log folder!', log_folder
                    continue
            except Exception, e:
                print e, line
                continue

            if event is None:
                print 'parse error', log_folder, repr(line)
                error_count += 1
                continue
            else:
                ok_count += 1

            _id = '%s:%d' % (key,i)

            event.update({
                's3_key' : key,
                's3_bucket' : 'djaodjin',
            })
            if log_type is not None:
                event['log_type'] = log_type

            event.update(match.groupdict())

            yield {
                '_id': _id,
                '_index': index,
                '_type': doc_type,
                '_source': event
            }



# def main(root):
#     es = Elasticsearch([{'host': 'localhost', 'port': 1234}])
#     # index = 'logs-test'
#     doc_type = "log"

#     nginx_parser = NginxLogParser()
#     gunicorn_parser = GunicornLogParser()

#     paths = os.walk(root)
#     for dirpath, dirnames, filenames in os.walk(root):
#         for fname in filenames:
#             event = generate_event(root, fname)
#             completed.add(fname)


#             if not es.indices.exists(index):
#                 # es.indices.delete(index)
#                 es.indices.create(index=index,body={
#                     "mappings": {
#                         "log": {
#                             "properties": {
#                                 "ip_num": {
#                                     "type": "ip"
#                                 }
#                             }
#                         }
#                     }
#                 })

#             if batch:
#                 print 'sending batch', len(batch)
#                 elasticsearch.helpers.bulk(es, batch)

#             completed.add(key)
            


if __name__ == '__main__':
    import sys

    root = sys.argv[1]
    key = sys.argv[2]
    import hashlib
    outname = 'tmp/%s.gz' % hashlib.sha1(key).hexdigest()
    if os.path.exists(outname):
        print 'already done'
        sys.exit(0)

    from elasticsearch.serializer import JSONSerializer
    serializer = JSONSerializer()

    try:
        with gzip.open(outname,'wb') as f:
            for event in generate_events(root, key):
                f.write(serializer.dumps(event))
                f.write('\n')

    except Exception as e:
        if os.path.exists(outname):
            os.remove(outname)
        raise e
    # main(root)




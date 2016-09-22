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
        format_string = '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"\n'

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

class JsonEventParser(object):
    def parse(self, to_parse):
        event = json.loads(to_parse)
        return event


class GunicornLogParser(object):

    def __init__(self):
        format_string = '''%({X-Forwarded-For}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"\n'''

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


gunicorn_test_string = '''108.252.136.229 - - [09/Aug/2016:10:15:32 -0700] "GET / HTTP/1.0" 500 3840 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"'''
nginx_test_string = '''183.129.160.229 - - [20/Aug/2016:03:34:59 +0000] "GET / HTTP/1.1" 444 0 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:47.0) Gecko/20100101 Firefox/47.0" "-"'''

def error_event(fname, key, reason, extra=None):
    now = datetime.now()
    body = {
        'reason': reason,
        's3_key': key,
        's3_bucket' : 'djaodjin',
        'parse_time': now,
    }
    if extra:
        body.update(extra)
    return {
        '_index': 'parse-errors-%s' % datetime.strftime(now, '%Y%m%d'),
        '_type': 'parse-error',
        '_source': body,
    }

def generate_events(stream, key):

    fname = os.path.basename(key)
    match = re.match(r'(?P<host>\S+)-(?P<log_name>\S+)\.log-(?P<instance_id>[^-]+)-(?P<log_date>[0-9]{8}).*\.gz', fname)
    if not match:
        print 'not a log file? %s' % fname

        yield error_event(fname, key, 'log filename didnt match regexp')
        return

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

    log_date = datetime.strptime(match.group('log_date'), '%Y%m%d')
    log_name = match.group('log_name')

    index = 'logs-%s' % (match.group('log_date'))
    doc_type = 'log'

    if log_folder == 'nginx':
        parser = NginxLogParser()
    elif log_folder == 'gunicorn':
        if log_name == 'events':
            parser = JsonEventParser()
        else:
            parser = GunicornLogParser()
    else:
        print 'unknown log folder!', log_folder
        yield error_event(fname, key, 'could not find parser for log folder',
                          {'log_folder': log_folder,
                           'log_date': log_date})
        return

    error_count = 0
    ok_count = 0
    for i,line in stream:
        line = line.decode('ascii',errors='replace')

        total_count = ok_count + error_count
        if total_count > 100 and (float(error_count)/total_count) > 0.8:
            print 'too many errors. bailing', key
            yield error_event(fname, key, 'bailing because of too many errors.',
                              {'log_date': log_date,
                               'line': line})
            return

        try:
            event = parser.parse(line)
        except Exception, e:
            print e, line
            yield error_event(fname, key, 'could not parse log line',
                              {'line': line,
                               'exception_message': e.message,
                               'log_date': log_date,
                               'exception_type': type(e).__name__})

            continue

        if event is None:
            print 'parse error', log_folder, repr(line)
            yield error_event(fname, key, 'could not parse log line',
                              {'line': line,
                               'log_date': log_date,})
            error_count += 1
            continue
        else:
            ok_count += 1

        _id = '%s:%d' % (key,i)

        event.update({
            's3_key' : key,
            's3_bucket' : 'djaodjin',
            'log_name': log_name,
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

def sanitize_filename(fname):
    fname  = fname.replace(os.path.sep, '_')
    fname = re.sub(r'[^a-zA-Z_\-.0-9]', '', fname)
    fname = re.sub(r'^[^a-zA-Z0-9]+', '', fname)
    if fname.startswith('.'):
        fname = fname[1:]

    return fname


if __name__ == '__main__':
    import sys
    root = sys.argv[1]
    key = sys.argv[2]

    outname = 'tmp/%s' % sanitize_filename(key)
    if os.path.exists(outname):
        print 'already done'
        sys.exit(0)

    from elasticsearch.serializer import JSONSerializer
    serializer = JSONSerializer()

    try:
        with gzip.open(outname,'wb') as out:
            with open(os.path.join(root,key),mode='rb') as f:
                gzfile = gzip.GzipFile(fileobj=f, mode='rb')
                for event in generate_events(enumerate(gzfile), key):
                    # the elasticsearch serializer does have a
                    # a dumps method, but we don't use it
                    # because it turns off json.dumps' ensure_ascii
                    # we want to enforce ascii because it's
                    # not actually specified what encoding the
                    # log file is in. We were also getting
                    # invalid utf-8 sequences.
                    s = json.dumps(event, default=serializer.default)
                    out.write(s)
                    out.write('\n')

    except Exception as e:
        if os.path.exists(outname):
            os.remove(outname)
        raise e




# Copyright (c) 2019, DjaoDjin inc.
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
from __future__ import unicode_literals

import logging
import gzip, itertools, json, re, os, os.path, sys, time
from datetime import tzinfo, timedelta, datetime

import boto, six
from pytz import utc

LOGGER = logging.getLogger(__name__)
BOTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


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
        return 'FixedOffset(%d)' % (self.utcoffset().total_seconds() // 60)


class JSONEncoder(json.JSONEncoder):

    def default(self, obj):
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        return super(JSONEncoder, self).default(obj)


class LastRunCache(object):
    """
    Cache for last run on a log file.
    """

    def __init__(self, filename):
        self.filename = filename
        self.last_run_logs = {}
        self.load()

    def load(self):
        if os.path.exists(self.filename):
            with open(self.filename) as last_run:
                self.last_run_logs = json.load(
                    last_run, object_hook=datetime_hook)

    def save(self):
        if not os.path.isdir(os.path.dirname(self.filename)):
            os.makedirs(os.path.dirname(self.filename))
        with open(self.filename, 'w') as last_run:
            json.dump(self.last_run_logs, last_run, cls=JSONEncoder, indent=2)

    def more_recent(self, logname, last_modified, update=False):
        result = (not logname in self.last_run_logs
            or self.last_run_logs[logname] < last_modified)
        if result and update:
            self.last_run_logs[logname] = last_modified
        return result


def as_keyname(filename, logsuffix=None, prefix=None, ext='.log'):
    result = filename
    if ext.startswith('.'):
        ext = ext[1:]
    if logsuffix:
        look = re.match(r'^(\S+\.%s)(\S*)$' % ext, filename)
        if look:
            result = look.group(1) + logsuffix + look.group(2)
    if prefix:
        result = prefix + result
    return result


def as_filename(key_name, logsuffix=None, prefix=None, ext='.log'):
    result = key_name
    if ext.startswith('.'):
        ext = ext[1:]
    if logsuffix:
        look = re.match(r'^(\S+\.%s)%s(\S*)$' % (ext, logsuffix), key_name)
        if look:
            result = look.group(1) + look.group(2)
    if prefix is not None:
        #if not prefix.endswith('/'):
        #    prefix = prefix + '/'
        if result.startswith(prefix):
            result = result[len(prefix):]
    return result


def as_logname(key_name, logsuffix=None, prefix=None, ext='.log'):
    if ext.startswith('.'):
        ext = ext[1:]
    result = as_filename(key_name, logsuffix=logsuffix, prefix=prefix)
    look = re.match(r'(\S+\.%s)((-\S+)\.gz)' % ext, result)
    if look:
        result = look.group(1)
    return result


def datetime_hook(json_dict):
    for key, value in list(six.iteritems(json_dict)):
        try:
            json_dict[key] = datetime.strptime(
                value, "%Y-%m-%dT%H:%M:%S.%f+00:00")
            if json_dict[key].tzinfo is None:
                json_dict[key] = json_dict[key].replace(tzinfo=utc)
        except:
            LOGGER.warning("%s: cannot convert '%s' to a datetime object." % (
                key, value))
    return json_dict


def download_updated_logs(lognames, local_prefix=None, logsuffix=None,
                          bucket=None, s3_prefix=None, last_run=None):
    """
    Fetches log files which are on S3 and more recent that specified
    in last_run and returns a list of filenames.
    """
    local_update, _ = list_updates(
        list_local(lognames, prefix=local_prefix, list_all=False),
        list_s3(bucket, lognames, prefix=s3_prefix, time_from_logsuffix=False),
        logsuffix=logsuffix, prefix=s3_prefix)

    for item in local_update:
        keyname = item['Key']
        filename = as_filename(keyname, prefix=s3_prefix)
        if filename.startswith('/'):
            filename = '.' + filename
        logname = as_logname(filename)
        if not last_run or last_run.more_recent(logname, item['LastModified']):
            s3_key = boto.s3.key.Key(bucket, keyname)
            if s3_key.storage_class == 'STANDARD':
                sys.stderr.write("download %s to %s\n" % (
                    keyname, os.path.abspath(filename)))
                if not os.path.isdir(os.path.dirname(filename)):
                    os.makedirs(os.path.dirname(filename))
                with open(filename, 'wb') as file_obj:
                    s3_key.get_contents_to_file(file_obj)
            else:
                sys.stderr.write("skip %s (on %s storage)\n" % (
                    keyname, s3_key.storage_class))

    # It is possible some files were already downloaded as part of a previous
    # run so we construct the list of recent files here.
    downloaded = []
    for item in sorted(list_local(lognames,
                prefix=local_prefix, list_all=False), key=get_last_modified):
        keyname = item['Key']
        filename = as_filename(keyname, prefix=s3_prefix)
        if filename.startswith('/'):
            filename = '.' + filename
        logname = as_logname(filename)
        if not last_run or last_run.more_recent(
                logname, item['LastModified'], update=True):
            downloaded += [filename]
    return downloaded


def get_last_modified(item):
    return item['LastModified']


def list_local(lognames, prefix=None, list_all=False):
    """
    Returns a list of rotated log files with their timestamp.

    Example:
    [{ "Key": "/var/log/nginx/www.example.com.log-20160106.gz",
       "LastModified": "Mon, 06 Jan 2016 00:00:00 UTC"},
     { "Key": "/var/log/nginx/www.example.com.log-20160105.gz",
       "LastModified": "Mon, 05 Jan 2016 00:00:00 UTC"},
    ]
    """
    results = []
    for logname in lognames:
        dirname = os.path.dirname(logname)
        _, ext = os.path.splitext(logname)
        if prefix:
            prefixed_dirname = prefix + dirname
        else:
            prefixed_dirname = dirname
        if os.path.isdir(prefixed_dirname):
            for filename in os.listdir(prefixed_dirname):
                fullpath = os.path.join(dirname, filename)
                prefixed_fullpath = os.path.join(prefixed_dirname, filename)
                if (as_logname(fullpath, ext=ext) == logname
                    and (list_all or not fullpath == logname)):
                    mtime = datetime.fromtimestamp(
                        os.path.getmtime(prefixed_fullpath), tz=utc)
                    results += [{"Key": fullpath, "LastModified": mtime}]
    return results


def list_s3(bucket, lognames, prefix=None, time_from_logsuffix=False):
    """
    Returns a list of rotated log files present in a bucket
    with their timestamp.

    Example:
    [{ "Key": "/var/log/nginx/www.example.com.log-20160106.gz",
       "LastModified": "Mon, 06 Jan 2016 00:00:00 UTC"},
     { "Key": "/var/log/nginx/www.example.com.log-20160105.gz",
       "LastModified": "Mon, 05 Jan 2016 00:00:00 UTC"},
    ]
    """
    results = []
    for logname in lognames:
        dirname = os.path.dirname(logname)
        if prefix:
            dirname = prefix + dirname
        for s3_key in bucket.list(dirname):
            if as_logname(s3_key.name, prefix=prefix) == logname:
                look = re.match(r'\S+-(\d\d\d\d\d\d\d\d)\.gz', s3_key.name)
                if time_from_logsuffix and look:
                    last_modified = datetime.strptime(
                        look.group(1), "%Y%m%d")
                else:
                    last_modified = datetime(*time.strptime(
                        s3_key.last_modified, BOTO_DATETIME_FORMAT)[0:6])
                if last_modified.tzinfo is None:
                    last_modified = last_modified.replace(tzinfo=utc)
                results += [{"Key": s3_key.name, "LastModified": last_modified}]
    return results


def list_updates(local_items, s3_items, logsuffix=None, prefix=None):
    """
    Returns two lists of updated files. The first list is all the files
    in the list *s3_items* which are more recent that files in the list
    *local_items*.
    The second returned list is all the files in the list *local_items*
    which are more recent that files in the list *s3_items*.

    Example:
    [{ "Key": "abc.txt",
       "LastModified": "Mon, 05 Jan 2015 12:00:00 UTC"},
     { "Key": "def.txt",
       "LastModified": "Mon, 05 Jan 2015 12:00:001 UTC"},
    ]
    """
    local_results = []
    local_index = {}
    for local_val in local_items:
        local_index[as_keyname(local_val['Key'],
            logsuffix=logsuffix, prefix=prefix)] = local_val
    for s3_val in s3_items:
        s3_key = s3_val['Key']
        local_val = local_index.get(s3_key, None)
        if local_val:
            local_datetime = local_val['LastModified']
            s3_datetime = s3_val['LastModified']
            if s3_datetime > local_datetime:
                local_results += [s3_val]
        else:
            local_results += [s3_val]

    s3_results = []
    s3_index = {}
    for s3_val in s3_items:
        s3_index[as_filename(s3_val['Key'],
            logsuffix=logsuffix, prefix=prefix)] = s3_val
    for local_val in local_items:
        local_key = local_val['Key']
        s3_val = s3_index.get(local_key, None)
        if s3_val:
            s3_datetime = s3_val['LastModified']
            local_datetime = local_val['LastModified']
            if local_datetime > s3_datetime:
                s3_results += [local_val]
        else:
            s3_results += [local_val]

    return local_results, s3_results


def parse_date(dt_str):
    naive_date_str, offset_str = dt_str.split(' ')
    naive_dt = datetime.strptime(naive_date_str, '%d/%b/%Y:%H:%M:%S')

    offset = int(offset_str[-4:-2])*60 + int(offset_str[-2:])
    if offset_str[0] == "-":
        offset = -offset
    return naive_dt.replace(tzinfo=FixedOffset(offset))


def split_on_comma(http_x_forwarded_for):
    if http_x_forwarded_for == '-':
        return []
    ips = http_x_forwarded_for.split(',')
    return [part.strip() for part in ips]


def convert_bytes_sent(value):
    if value == '-':
        return 0
    return int(value)


def generate_regex(format_string, var_regex, regexps):
    format_vars = re.findall(var_regex, format_string)

    var_matches = list(re.finditer(var_regex, format_string))

    var_match_positions = [(match.start(), match.end())
                           for match in var_matches]

    non_var_indexes = (
        [0] +
        list(itertools.chain(*var_match_positions)) +
        [len(format_string)]
    )

    grouped_non_var_indexes = [(non_var_indexes[i*2], non_var_indexes[i*2+1])
                               for i in range(len(non_var_indexes)//2)]

    non_var_strings = [format_string[start:end]
                       for start, end in grouped_non_var_indexes]
    escaped_non_var_strings = [re.escape(s) for s in non_var_strings]

    named_regexps = ['(' + regexps[s] + ')' for i, s in enumerate(format_vars)]
    full_regex_pieces = list(
        itertools.chain(*six.moves.zip_longest(escaped_non_var_strings,
                                                named_regexps, fillvalue=''))
    )

    full_regex = ''.join(full_regex_pieces[:])

    return re.compile(full_regex)


class NginxLogParser(object):
    """
    We make sure nginx and gunicorn access logs have the same format.
    """

    def __init__(self):
        format_string = '$remote_addr $http_host $remote_user [$time_local]'\
' "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"'\
' "$http_x_forwarded_for"\n'

        var_regex = r'\$[a-z_]+'
        ip_num_regex = r'[0-9]{1,3}'
        regexps = {
            '$ip_num'               : r'[0-9]{1,3}',
            '$remote_addr'          : '\\.'.join([ip_num_regex] * 4),
            '$http_host'            :
                 # We cannot have parentheses in regex here?
                 r'[a-z0-9.-]+|[a-z0-9.-]+:\d+?',
            '$remote_user'          : r'[\w.@+-]+',
            '$time_local'           : r'[^\[\]]+',
            '$request'              : r'[^"]*',
            '$status'               : r'[0-9]{3}',
            '$body_bytes_sent'      : r'[0-9]+|-',
            '$http_referer'         : r'[^"]+',
            '$http_user_agent'      : r'[^"]*',
            '$http_x_forwarded_for' : r'[^"]+',
        }
        self.format_vars = re.findall(var_regex, format_string)
        self.regex = generate_regex(format_string, var_regex, regexps)

    def parse(self, to_parse):
        match = self.regex.match(to_parse)
        if match:
            parsed = dict(zip(self.format_vars, match.groups()))
        else:
            return None

        parsed = {k[1:]: v for k, v in six.iteritems(parsed)}

        field_types = {
            'status' : int,
            'body_bytes_sent': convert_bytes_sent,
            'time_local': parse_date,
            'http_x_forwarded_for': split_on_comma
        }
        for key, convert in six.iteritems(field_types):
            parsed[key] = convert(parsed[key])

        if (parsed['http_x_forwarded_for']
            and parsed['remote_addr'] in ['-', '127.0.0.1']):
            # To simplify processing later on, we replace the direct IP
            # the request is coming from (will be locahost for gunicorn
            # behind nginx anyway) by the IP of the browser client.
            parsed['remote_addr'] = parsed['http_x_forwarded_for'][0]

        request_regex = r'(?P<http_method>[A-Z]+) (?P<http_path>.*) HTTP/1.[01]'
        request_match = re.match(request_regex, parsed['request'])
        if request_match:
            parsed.update(request_match.groupdict())

        return parsed


class JsonEventParser(object):
    """
    Application logs
    """

    @staticmethod
    def parse(to_parse):
        try:
            to_parse = to_parse[to_parse.find('{'):]
            event = json.loads(to_parse)
            field_types = {
                'status' : int,
                'body_bytes_sent': convert_bytes_sent,
                'time_local': parse_date,
                'http_x_forwarded_for': split_on_comma
            }
            for key, convert in six.iteritems(field_types):
                if key in event:
                    event[key] = convert(event[key])
        except ValueError:
            event = None
        return event


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
        sys.stderr.write('warning: "%s" is not a log file?' % fname)
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
        parser = NginxLogParser()
        if log_name == 'access':
            parser = NginxLogParser()
        else:
            parser = JsonEventParser()
    else:
        sys.stderr.write("error: unknown log folder %s\n" % log_folder)
        yield error_event(fname, key, 'could not find parser for log folder',
                          {'log_folder': log_folder,
                           'log_date': log_date})
        return

    error_count = 0
    ok_count = 0
    for i, line in stream:
        line = line.decode('ascii', errors='replace')

        total_count = ok_count + error_count
        if total_count > 100 and (float(error_count)/total_count) > 0.8:
            sys.stderr.write(
                "error: too many errors for key '%s'. bailing" % str(key))
            yield error_event(fname, key, 'bailing because of too many errors.',
                              {'log_date': log_date,
                               'line': line})
            return

        try:
            event = parser.parse(line)
        except Exception as err:
            sys.stderr.write("error: %s in line '%s'\n" % (err, line))
            yield error_event(fname, key, 'could not parse log line',
                              {'line': line,
                               'exception_message': err.message,
                               'log_date': log_date,
                               'exception_type': type(err).__name__})

            continue

        if event is None:
            sys.stderr.write(
                "error: parsing '%s' in '%s'\n" % (repr(line), log_folder))
            yield error_event(fname, key, 'could not parse log line',
                              {'line': line,
                               'log_date': log_date,})
            error_count += 1
            continue
        else:
            ok_count += 1

        _id = '%s:%d' % (key, i)

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
    fname = fname.replace(os.path.sep, '_')
    fname = re.sub(r'[^a-zA-Z_\-.0-9]', '', fname)
    fname = re.sub(r'^[^a-zA-Z0-9]+', '', fname)
    if fname.startswith('.'):
        fname = fname[1:]

    return fname


def main():
    root = sys.argv[1]
    key = sys.argv[2]

    outname = 'tmp/%s' % sanitize_filename(key)
    if os.path.exists(outname):
        sys.stderr.write("'%s' already done\n" % str(outname))
        sys.exit(0)

    from elasticsearch.serializer import JSONSerializer
    serializer = JSONSerializer()

    try:
        with gzip.open(outname, 'wb') as out:
            with open(os.path.join(root, key), mode='rb') as logfile:
                gzfile = gzip.GzipFile(fileobj=logfile, mode='rb')
                for event in generate_events(enumerate(gzfile), key):
                    # the elasticsearch serializer does have a
                    # a dumps method, but we don't use it
                    # because it turns off json.dumps' ensure_ascii
                    # we want to enforce ascii because it's
                    # not actually specified what encoding the
                    # log file is in. We were also getting
                    # invalid utf-8 sequences.
                    out.write(json.dumps(event, default=serializer.default))
                    out.write('\n')

    except Exception as err:
        if os.path.exists(outname):
            os.remove(outname)
        raise err


if __name__ == '__main__':
    main()

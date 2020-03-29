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
from __future__ import absolute_import
from __future__ import unicode_literals

import argparse, datetime, gzip, itertools, json, logging, re, os, os.path, sys

import six

from tero import __version__


LOGGER = logging.getLogger(__name__)


# http://stackoverflow.com/questions/1101508/how-to-parse-dates-with-0400-timezone-string-in-python/23122493#23122493
class FixedOffset(datetime.tzinfo):
    """Fixed offset in minutes: `time = utc_time + utc_offset`."""
    def __init__(self, offset):
        self.__offset = datetime.timedelta(minutes=offset)
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
        return datetime.timedelta(0)
    def __repr__(self):
        return 'FixedOffset(%d)' % (self.utcoffset().total_seconds() // 60)


def get_last_modified(item):
    return item['LastModified']


def parse_date(dt_str):
    naive_date_str, offset_str = dt_str.split(' ')
    naive_dt = datetime.datetime.strptime(naive_date_str, '%d/%b/%Y:%H:%M:%S')

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
        format_string = '$remote_addr$load_balancer_addr $http_host'\
            ' $remote_user [$time_local]'\
            ' "$request" $status $body_bytes_sent'\
            ' "$http_referer" "$http_user_agent"'\
            ' "$http_x_forwarded_for"'

        var_regex = r'\$[a-z_]+'
        ipv6_regex = r'(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}'
        ipv4_regex = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
        ip_num_regex = r'(?:%s)|(?:%s)' % (ipv4_regex, ipv6_regex)

        regexps = {
            '$remote_addr'          : ip_num_regex,
            '$load_balancer_addr'   : r'(?:,\s%s)*' % ip_num_regex,
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
    now = datetime.datetime.now()
    body = {
        'reason': reason,
        's3_key': key,
        's3_bucket' : 'djaodjin',
        'parse_time': now,
    }
    if extra:
        body.update(extra)
    return {
        '_index': 'parse-errors-%s' % datetime.datetime.strftime(now, '%Y%m%d'),
        '_type': 'parse-error',
        '_source': body,
    }


def generate_events(fileobj, key):
    fname = os.path.basename(key)
    match = re.match(r'(?P<host>\S+)-(?P<log_name>\S+)\.log-(?P<instance_id>[^-]+)-(?P<log_date>[0-9]{8})(\.gz)?', fname)
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

    log_date = datetime.datetime.strptime(match.group('log_date'), '%Y%m%d')
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

    LOGGER.debug("using parser %s", parser)
    error_count = 0
    ok_count = 0
    for idx, line in enumerate(fileobj.readlines()):
        if hasattr(line, 'decode'):
            line = line.decode('ascii', errors='replace')
        line = line.strip()

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
                "error: parsing '%s' in '%s'\n" % (line, log_folder))
            yield error_event(fname, key, 'could not parse log line',
                              {'line': line,
                               'log_date': log_date,})
            error_count += 1
            continue

        ok_count += 1
        _id = '%s:%d' % (key, idx)
        event.update({
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


def main(args):
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options] command\n\nVersion\n  %(prog)s version '
        + str(__version__))
    parser.add_argument('--version', action='version',
        version='%(prog)s ' + str(__version__))
    parser.add_argument('lognames', metavar='lognames', nargs='+',
        help="log files to parse")

    options = parser.parse_args(args)
    if len(options.lognames) < 1:
        sys.stderr.write("error: not enough arguments")
        parser.print_help()
        return 1

    serializer = JSONSerializer()
    for logname in options.lognames:
        with open(logname) as logfile:
            for event in generate_events(logfile, logname):
                # the elasticsearch serializer does have a
                # a dumps method, but we don't use it
                # because it turns off json.dumps' ensure_ascii
                # we want to enforce ascii because it's
                # not actually specified what encoding the
                # log file is in. We were also getting
                # invalid utf-8 sequences.
                sys.stdout.write(json.dumps(event, default=serializer.default))
                sys.stdout.write('\n')


if __name__ == '__main__':
    from elasticsearch.serializer import JSONSerializer
    main(sys.argv[1:])

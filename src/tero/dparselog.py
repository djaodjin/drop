# Copyright (c) 2021, DjaoDjin inc.
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

import argparse, datetime, decimal, gzip, itertools, json, logging, re, os
import os.path, sys

import requests, pytz, six

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


class JSONEncoder(json.JSONEncoder):

    def default(self, obj):
        #pylint: disable=method-hidden,arguments-differ
        # `arguments-differ`: parameter is called `o` in json.JSONEncoder.
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        if isinstance(obj, decimal.Decimal):
            return float(obj)
        return super(JSONEncoder, self).default(obj)


def get_last_modified(item):
    return item['LastModified']


def parse_date(dt_str):
    try:
        naive_date_str, offset_str = dt_str.split(' ')
        naive_dt = datetime.datetime.strptime(
            naive_date_str, '%d/%b/%Y:%H:%M:%S')
        offset = int(offset_str[-4:-2])*60 + int(offset_str[-2:])
        if offset_str[0] == "-":
            offset = -offset
        tzinfo = FixedOffset(offset)
    except ValueError:
        space_idx = dt_str.rfind(',')
        if space_idx <= 0:
            raise
        naive_date_str = dt_str[:space_idx]
        offset_str = ""
        naive_dt = datetime.datetime.strptime(
            naive_date_str, '%Y-%m-%d %H:%M:%S')
        tzinfo = datetime.timezone.utc

    return naive_dt.replace(tzinfo=tzinfo)


def parse_time(time_str):
    """
    Returns a timedelta from a string representing elasped time in seconds
    with a milliseconds resolution (ex: nginx $request_time).
    """
    if time_str:
        time_str = time_str.strip()
    if not time_str or time_str == '-':
        return None
    seconds, milliseconds = time_str.split('.')
    milliseconds = milliseconds.split(',')[0]
    return datetime.timedelta(
        seconds=int(seconds), milliseconds=int(milliseconds))


def split_on_comma(http_x_forwarded_for):
    if http_x_forwarded_for == '-':
        return []
    ips = http_x_forwarded_for.split(',')
    return [part.strip() for part in ips]


def parse_pipe(pipe):
    if pipe:
        pipe = pipe.strip()
    return pipe and pipe == 'p'


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


class LogParser(object):

    def parse(self, line, writer=None):
        return None


class MakeLogParser(LogParser):
    """
    Extracts the bare useful information to quickly scan through
    dws log files.
    """

    def run(self, logname, writer=None):
        with open(logname) as log:
            self.buffered_lines = []
            for line in log.readlines():
                self.parse(line, writer=writer)

    def parse(self, line, writer=None):
        # We locally filter log output. Everything that falls before
        # a '^###' marker will be discarded in the error output.
        if not hasattr(self, 'buffered_lines'):
            self.buffered_lines = []
        self.buffered_lines += [line]
        look = re.match(r'^###.*\s+(\S+)\s+.*', line)
        if look:
            self.buffered_lines = [line]
        else:
            look = re.match(
             r'^(make(\[\d+\]:.*not remade because of errors)|(:.*Error \d+))',
                line)
            if look:
                filename = '^make '
            else:
                look = re.match(r'^(.*):\d+:error:', line)
                if look:
                    filename = look.group(1)
                else:
                    look = re.match(r'^error:', line)
                    if look:
                        filename = '^$'
            if look:
                # We will try to finely filter buffered lines to the shell
                # command that triggered the error if possible.
                start = 0
                if len(self.buffered_lines) > 0:
                    start = len(self.buffered_lines) - 1
                while start > 0:
                    look = re.match(filename, self.buffered_lines[start])
                    if look:
                        break
                    start = start - 1
                for prev in self.buffered_lines[start:]:
                    sys.stdout.write(prev)
                self.buffered_lines = []


class NginxLogParser(LogParser):
    """
    We make sure nginx and gunicorn access logs have the same format.
    """

    def __init__(self):
        format_string = '$remote_addr$load_balancer_addr $http_host'\
            ' $remote_user [$time_local]'\
            ' "$request" $status $body_bytes_sent'\
            ' "$http_referer" "$http_user_agent"'\
            ' "$http_x_forwarded_for"'\
            '$request_time$upstream_response_time$pipe'

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
            '$http_referer'         : r'[^"]*',
            '$http_user_agent'      : r'[^"]*',
            '$http_x_forwarded_for' : r'[^"]+',
            '$request_time': r' ?[0-9.,]*',
            '$upstream_response_time': r' ?[0-9.,]*|-?',
            '$pipe': r' ?[p.]?'
        }
        self.format_vars = re.findall(var_regex, format_string)
        self.regex = generate_regex(format_string, var_regex, regexps)

    def parse(self, line, writer=None):
        match = self.regex.match(line)
        if not match:
            raise ValueError("'%s' does not match regex %s" % (
                line.replace("'", "\\'"), self.regex))

        parsed = {k[1:]: v for k, v in six.iteritems(
            dict(zip(self.format_vars, match.groups())))}

        field_types = {
            'status' : int,
            'body_bytes_sent': convert_bytes_sent,
            'time_local': parse_date,
            'http_x_forwarded_for': split_on_comma,
            'request_time': parse_time,
            'upstream_response_time': parse_time,
            'pipe': parse_pipe,
        }
        for key, convert in six.iteritems(field_types):
            if key in parsed:
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


class PythonExceptionLogParser(LogParser):
    """
    Python Exception application logs
    """
    EXCEPTION_START = 0
    TRACEBACK_START = 1
    FIRST_FILE_LINENO = 2
    FILE_LINENO = 3
    STATEMENT = 4
    EXCEPTION_CLASS = 5
    EXCEPTION_END = 6

    def __init__(self):
        self.exception_start_pat = re.compile(r"ERROR (?P<remote_addr>.+) (?P<"\
r"username>.+) \[(?P<asctime>.+)\] Internal Server Error: (?P<http_path>.+) \""\
r"(?P<http_user_agent>.+)\"")
        self.traceback_start_pat = re.compile(
            r"^Traceback \(most recent call last\):")
        self.file_lineno_pat = re.compile(r"\s*File \"(?P<filename>.+)\", line"\
r" (?P<lineno>\d+), in (?P<function>\S+)")
        self.exception_class_pat = re.compile(
            r"^(?P<exception_type>\S+):\s+(?P<exception_descr>.*)")
        self.state = self.EXCEPTION_START
        self.msg = None

    def parse(self, line, writer=None):
        event = None
        if self.state == self.EXCEPTION_START:
            look = self.exception_start_pat.match(line)
            if look:
                self.msg = {
                    'log_level': "ERROR",
                    'asctime': look.group('asctime'),
                    'remote_addr': look.group('remote_addr'),
                    'username': look.group('username'),
                    'http_path': look.group('http_path'),
                    'http_user_agent': look.group('http_user_agent'),
                    'frames': []
                    }
                self.state = self.TRACEBACK_START
        elif self.state == self.TRACEBACK_START:
            look = self.traceback_start_pat.match(line)
            if look:
                self.state = self.FILE_LINENO
        elif self.state == self.FILE_LINENO:
            look = self.file_lineno_pat.match(line)
            if look:
                self.msg['frames'] += [{
                    'filename': look.group('filename'),
                    'lineno': int(look.group('lineno')),
                    'function': look.group('function')
                }]
                self.state = self.STATEMENT
            else:
                look = self.exception_class_pat.match(line)
                if look:
                    self.msg.update({
                        'exception_type': look.group('exception_type'),
                        'exception_descr': look.group('exception_descr')
                    })
                    self.state = self.EXCEPTION_END
        elif self.state == self.STATEMENT:
            self.msg['frames'][-1].update({
                'context_line': line.strip()
            })
            self.state = self.FILE_LINENO

        if self.state == self.EXCEPTION_END:
            event = self.msg
            if writer:
                writer.write(json.dumps(event))
            self.msg = None
            self.state = self.EXCEPTION_START

        return event


class JsonEventParser(PythonExceptionLogParser):
    """
    JSON-formatted (deployutils.apps.django.logging.JSONFormatter) application
    logs
    """

    def parse(self, line, writer=None):
        event = None
        if self.state == self.EXCEPTION_START:
            candidate_event_start = line.find('{')
            if candidate_event_start >= 0:
                line = line[candidate_event_start:]
                event = json.loads(line)
                field_types = {
                    'status' : int,
                    'body_bytes_sent': convert_bytes_sent,
                    'time_local': parse_date,
                    'http_x_forwarded_for': split_on_comma
                }
                for key, convert in six.iteritems(field_types):
                    if key in event:
                        event[key] = convert(event[key])
                return event
        # We can't find an event, so let's try to parse an Exception.
        return super(JsonEventParser, self).parse(line, writer=writer)


class EventWriter(object):

    def __init__(self, url_patterns=None):
        self.url_patterns = [] if not url_patterns else url_patterns

    def as_url_pattern(self, path):
        for pat in self.url_patterns:
            LOGGER.debug("Compare %s with %s" % (path, pat))
            parts = pat.split('/')
            parts_re = []
            for part in parts:
                if part.startswith('{'):
                    parts_re += [r'\w+']
                else:
                    parts_re += [part]
            pat_re = '/'.join(parts_re)
            look = re.match(pat_re, path)
            if look:
                return pat
        return path

    def write(self, event):
        sys.stdout.write(json.dumps(event, indent=2, cls=JSONEncoder))
        sys.stdout.write('\n')


class DuplicateEventWriter(EventWriter):

    def __init__(self, *writers):
        self.writers = writers

    def write(self, event):
        for writer in self.writers:
            writer.write(event)


class GitLabEventWriter(EventWriter):

    def __init__(self, api_endpoint, token,
                 default_project_name=None, url_patterns=None):
        super(GitLabEventWriter, self).__init__(url_patterns=url_patterns)
        self.filter_processed_events = False
        self.api_endpoint = api_endpoint
        self.token = token
        self.default_project_name = default_project_name

    def write(self, event):
        source_event = event.get('_source', {})
        if source_event.get('exception_type'):
            auth_headers = {'PRIVATE-TOKEN': self.token}
            project_name = source_event.get('host', self.default_project_name)
            project_search_api_endpoint = "%s/projects" % self.api_endpoint
            if project_name:
                project_search_api_endpoint += '?search=%s' % project_name
            resp = requests.get(project_search_api_endpoint,
                headers=auth_headers)
            resp_data = resp.json()
            project_id = resp_data[0].get('id')
            issue_api_endpoint = "%s/projects/%d/issues" % (
                self.api_endpoint, project_id)
            http_method = source_event.get('http_method', 'GET')
            http_path = source_event.get('http_path')
            title = "%s %s" % (http_method, self.as_url_pattern(http_path))
            resp = requests.get(
                issue_api_endpoint + '?search=%s' % title.replace(' ', '+'),
                headers=auth_headers)
            resp_data = resp.json()
            if resp_data:
                issue_data = resp_data[0]
            else:
                issue_data = {}
            issue_iid = issue_data.get('iid')
            if not issue_iid:
                resp = requests.post(issue_api_endpoint,
                    data={
                        "issue_type": "incident",
                        "title": title
                    },
                    headers=auth_headers)
                issue_data = resp.json()
                issue_iid = issue_data.get('iid')
                LOGGER.info("create issue %s/%d", issue_api_endpoint, issue_iid)
            else:
                requests.put(issue_api_endpoint + str(issue_iid),
                    data={'state_event': 'reopen'},
                    headers=auth_headers)
            note = "**Exception**: %s: %s\n" % (
                source_event.get('exception_type'),
                source_event.get('exception_descr'))
            affected = source_event.get('username')
            if affected:
                note += "**Affected user**: %s\n" % affected
            note += "**Traceback**:\n```\n"
            for frame in source_event.get('frames'):
                note += "  File \"%s\", line %d, in %s\n" % (
                    frame.get('filename'), int(frame.get('lineno')),
                    frame.get('function'))
                note += "    %s\n" % frame.get('context_line')
            note += "```\n"
            LOGGER.info("update issue %s/%d", issue_api_endpoint, issue_iid)
            resp = requests.post(issue_api_endpoint + "/%d/notes" % issue_iid,
                data={'body': note},
                headers=auth_headers)
        if not (self.filter_processed_events and
            source_event.get('exception_type')):
            super(GitLabEventWriter, self).write(event)


def error_event(key, reason, extra=None):
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


def parse_logname(filename):
    host = None
    log_name = None
    instance_id = None
    log_date = None
    look = re.match(
        r'(?P<host>\S+)-(?P<log_name>\S+)\.log(-(?P<instance_id>[^-"\
        "]+))?-(?P<log_date>[0-9]{8})(-[0-9]{1,10})?(\.gz)?',
        os.path.basename(filename))
    if look:
        host = look.group('host')
        log_name = look.group('log_name')
        instance_id = look.group('instance_id')
        log_date = datetime.datetime.strptime(look.group('log_date'), '%Y%m%d')
        if log_date.tzinfo is None:
            log_date = log_date.replace(tzinfo=pytz.utc)
    return host, log_name, instance_id, log_date


def generate_events(fileobj, key):
    #pylint:disable=too-many-locals
    host, log_name, instance_id, log_date = parse_logname(key)
    if not instance_id:
        sys.stderr.write('warning: "%s" cannot extract instance_id\n' % key)
    if not log_name:
        sys.stderr.write('warning: "%s" does not match log file regex\n' % key)
        yield error_event(key, 'log filename didnt match regexp')
        return

    log_parser = NginxLogParser()
    log_type = 'webfront'
    if host == 'djaoapp':
        # Dealing with the RBAC proxy access log.
        log_type = 'djsession'
    elif '.' not in host:
        log_type = 'customer'
    if log_name not in ('access',):
        log_parser = JsonEventParser()
        log_type = None
        if log_name not in ('app',):
            sys.stderr.write(
                "(skip) cannot derive Site from '%s'" % key)
            yield error_event(key,
                'could not find parser based on log filename')
            return

    LOGGER.debug("log %s using parser %s", key, log_parser)
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
            yield error_event(key, 'bailing because of too many errors.',
                              {'log_date': log_date,
                               'line': line})
            return

        try:
            event = log_parser.parse(line)
        except Exception as err:
            LOGGER.info("warning: '%s' cannot be interpreted by %s (%s)",
                line.replace("'", "\\'"), log_parser.__class__.__name__, err)
            yield error_event(key, 'could not parse log line',
                              {'line': line,
                               'exception_message': str(err),
                               'log_date': log_date,
                               'exception_type': type(err).__name__})
            error_count += 1
            continue

        if event:
            ok_count += 1
            _id = '%s:%d' % (key, idx)
            event.update({
                'log_name': log_name,
            })
            if log_type is not None:
                event['log_type'] = log_type

            event.update({
                'host': host,
                'log_name': log_name,
                'instance_id': instance_id,
                'log_date': log_date.strftime('%Y%m%d')
            })

            index = 'logs-%s' % log_date.strftime('%Y%m%d')
            doc_type = 'log'
            yield {
                '_id': _id,
                '_index': index,
                '_type': doc_type,
                '_source': event
            }


def parse_logfile(logname, writer=None):
    if not writer:
        writer = EventWriter()

    # hook for what used to be in `dlogfilt.py`.
    look = re.match(r'dws\S+\.log', os.path.basename(logname))
    if look:
        parser = MakeLogParser()
        parser.run(logname, writer=writer)

    if logname.endswith('.gz'):
        with gzip.open(logname, 'rt') as logfile:
            for event in generate_events(logfile, logname):
                writer.write(event)
    else:
        with open(logname, 'rt') as logfile:
            for event in generate_events(logfile, logname):
                writer.write(event)


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
    parser.add_argument('--gitlab-api-base', action='store')
    parser.add_argument('--token', action='store')
    parser.add_argument('--default-project-name', action='store', default=None)
    parser.add_argument('--url-patterns', dest='url_patterns', action='store',
        help='File containing URL patterns to aggregate exceptions')
    parser.add_argument('lognames', metavar='lognames', nargs='+',
        help="log files to parse")

    options = parser.parse_args(args)
    if len(options.lognames) < 1:
        sys.stderr.write("error: not enough arguments")
        parser.print_help()
        return -1

    url_patterns = []
    url_patterns_filename = options.url_patterns
    if url_patterns_filename:
        with open(url_patterns_filename) as url_patterns_file:
            for pat in url_patterns_file.readlines():
                url_patterns += [pat.strip()]

    writer = None
    if options.gitlab_api_base:
        writer = GitLabEventWriter(options.gitlab_api_base, options.token,
            default_project_name=options.default_project_name,
            url_patterns=url_patterns)

    for logname in options.lognames:
        parse_logfile(logname, writer=writer)

    return 0

if __name__ == '__main__':
    main(sys.argv[1:])

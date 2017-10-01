#!/usr/bin/env python
#
# Copyright (c) 2016, Djaodjin Inc.
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

import argparse, datetime, json, logging, os, re, sys, time

import boto, six
from pytz import utc

__version__ = None

LOGGER = logging.getLogger(__name__)

BOTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


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
            json_dict[key] = datetime.datetime.strptime(
                value, "%Y-%m-%dT%H:%M:%S.%f+00:00")
            if json_dict[key].tzinfo is None:
                json_dict[key] = json_dict[key].replace(tzinfo=utc)
        except:
            pass
    return json_dict


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
                    mtime = datetime.datetime.fromtimestamp(
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
                    last_modified = datetime.datetime.strptime(
                        look.group(1), "%Y%m%d")
                else:
                    last_modified = datetime.datetime(*time.strptime(
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


def download_updated_logs(local_update,
                          bucket=None, s3_prefix=None, last_run=None):
    """
    Fetches log files which are on S3 and more recent that specified
    in last_run.
    """
    downloaded = []
    for item in sorted(local_update, key=get_last_modified):
        keyname = item['Key']
        filename = as_filename(keyname, prefix=s3_prefix)
        if filename.startswith('/'):
            filename = '.' + filename
        logname = as_logname(filename)
        if not last_run or last_run.more_recent(
                logname, item['LastModified'], update=True):
            s3_key = boto.s3.key.Key(bucket, keyname)
            if s3_key.storage_class == 'STANDARD':
                sys.stderr.write("download %s to %s\n" % (
                    keyname, os.path.abspath(filename)))
                if not os.path.isdir(os.path.dirname(filename)):
                    os.makedirs(os.path.dirname(filename))
                with open(filename, 'wb') as file_obj:
                    s3_key.get_contents_to_file(file_obj)
                    downloaded += [filename]
            else:
                sys.stderr.write("skip %s (on %s storage)\n" % (
                    keyname, s3_key.storage_class))
    return downloaded


def main(args):
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options] command\n\nVersion\n  %(prog)s version '
        + str(__version__))
    parser.add_argument('--version', action='version',
        version='%(prog)s ' + str(__version__))
    parser.add_argument('--last-run', action='store',
        dest='last_run', default=None,
        help='Store a map of {logname: last_date} to use when deciding'\
            ' to download a log or not')
    parser.add_argument('--location', action='store',
        dest='location', default=None,
        help='Location where log files are stored')
    parser.add_argument('--list-all', action='store_true',
        dest='list_all', default=False,
        help='List all files (by default it will exclude the current log)')
    parser.add_argument('--download', action='store_true',
        dest='download', default=False,
        help='Download the rotated log files (by default upload)')
    parser.add_argument('--logsuffix', action='store',
        dest='logsuffix', default=None,
        help='Suffix inserted in log filenames on upload')
    parser.add_argument('lognames', metavar='lognames', nargs='+',
        help="rotated log files to upload/download")

    options = parser.parse_args(args[1:])
    if len(options.lognames) < 1:
        sys.stderr.write("error: not enough arguments")
        parser.print_help()
        return 1

    lognames = options.lognames
    logsuffix = options.logsuffix
    parts = options.location[5:].split('/')
    s3_bucket = parts[0]
    s3_location = 's3://' + s3_bucket
    s3_prefix = '/'.join(parts[1:])
    to_s3 = not options.download
    if to_s3:
        sys.stderr.write("Upload rotated logs for %s to %s under prefix '%s'\n"
            % (' '.join(lognames), s3_location, s3_prefix))
    else:
        sys.stderr.write(
            "Download rotated logs for %s from %s under prefix '%s'\n"
            % (' '.join(lognames), s3_location, s3_prefix))

    conn = boto.connect_s3()
    bucket = conn.get_bucket(s3_bucket)
    local_prefix = '.' if not to_s3 else None
    local_update, s3_update = list_updates(
        list_local(lognames, prefix=local_prefix, list_all=options.list_all),
        list_s3(bucket, lognames, prefix=s3_prefix,
                time_from_logsuffix=(not to_s3)),
        logsuffix=logsuffix, prefix=s3_prefix)

    if to_s3:
        # Upload
        headers = {
            'Content-Type': 'text/plain',
            'Content-Encoding': 'gzip'}
        for item in s3_update:
            filename = item['Key']
            s3_key = boto.s3.key.Key(bucket)
            s3_key.name = as_keyname(
                filename, logsuffix=logsuffix, prefix=s3_prefix)
            sys.stderr.write("Upload %s ... to %s/%s\n"
                % (filename, s3_location, s3_key.name))
            with open(filename, 'rb') as file_obj:
                s3_key.set_contents_from_file(file_obj, headers)
    else:
        # Download
        if options.last_run and os.path.exists(options.last_run):
            last_run = LastRunCache(options.last_run)
        else:
            last_run = None
        download_updated_logs(
            local_update, bucket=bucket, s3_prefix=s3_prefix, last_run=last_run)
        if last_run:
            last_run.save()

if __name__ == '__main__':
    sys.exit(main(sys.argv))

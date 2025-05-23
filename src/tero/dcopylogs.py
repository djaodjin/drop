#!/usr/bin/env python
#
# Copyright (c) 2025, Djaodjin Inc.
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

import argparse, datetime, decimal, json, logging, os, re, sys

import boto3, requests, six
from pytz import utc

from . import __version__
from .dparselog import parse_logname


LOGGER = logging.getLogger(__name__)


class JSONEncoder(json.JSONEncoder):

    def default(self, obj): #pylint: disable=method-hidden,arguments-renamed
        # parameter is called `o` in json.JSONEncoder.
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        if isinstance(obj, decimal.Decimal):
            return float(obj)
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


def as_keyname(filename, logsuffix=None, prefix=None, logext=None):
    """
    The keyname returned is in a format as expected by AWS S3
    (i.e. no leading '/') whether `filename` is an absolute path or
    a subdirectory of the current path.
    """
    filename = filename.lstrip(os.sep)
    result = filename
    if logext and logext.startswith('.'):
        logext = logext[1:]
    if logsuffix:
        if logext:
            look = re.match(r'^(\S+\.%s)(\S*)$' % logext, filename)
            if look:
                result = look.group(1) + logsuffix + look.group(2)
        else:
            base, ext = os.path.splitext(filename)
            result = base + logsuffix + ext
    if prefix:
        result = "%s/%s" % (prefix.strip('/'), result)
    return result


def as_filename(key_name, logsuffix=None, prefix=None, logext=None):
    result = key_name
    if logext and logext.startswith('.'):
        logext = logext[1:]
    if logsuffix:
        if logext:
            look = re.match(r'^(\S+\.%s)%s(\S*)$' % (
                logext, logsuffix), key_name)
            if look:
                result = look.group(1) + look.group(2)
        else:
            look = re.match(r'^(\S+)%s(\S*)$' % logsuffix, key_name)
            if look:
                result = look.group(1) + look.group(2)
    if prefix is not None:
        if result.startswith(prefix):
            result = result[len(prefix):]
        result = result.lstrip('/')
    return result


def as_logname(key_name, logsuffix=None, prefix=None, ext='.log'):
    if ext in ['.gz', '.zip']:
        # We don't really have a log extension. File is already compressed.
        ext = None
    result = as_filename(key_name, logsuffix=logsuffix, prefix=prefix,
        logext=ext)
    if ext:
        if ext.startswith('.'):
            ext = ext[1:]
        look = re.match(r'(\S+\.%s)((-[0-9a-z\-]+)(\.gz)?)' % ext, result)
        if look:
            result = look.group(1)
    return result


def datetime_hook(json_dict):
    for key, value in list(six.iteritems(json_dict)):
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f+00:00", "%Y-%m-%dT%H:%M:%S+00:00"):
            try:
                json_dict[key] = datetime.datetime.strptime(value, fmt)
                if json_dict[key].tzinfo is None:
                    json_dict[key] = json_dict[key].replace(tzinfo=utc)
                break
            except ValueError:
                pass
        if not isinstance(json_dict[key], datetime.datetime):
            LOGGER.warning("%s: cannot convert '%s' to a datetime object.",
                key, value)
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
                if as_logname(fullpath, ext=ext) != logname:
                    # We are only uploading logs matching
                    # a specific name pattern.
                    continue

                if not (list_all or fullpath.endswith('.gz')):
                    # We are only uploading compressed logs.
                    continue

                parsed_host, _, _, _ = parse_logname(fullpath)
                if not (list_all or parsed_host is not None):
                    # If we cannot parse a host, we won't upload the file,
                    # i.e. we are filtering out /var/log/nginx/access.log
                    # and /var/log/nginx/error.log files.
                    continue

                prefixed_fullpath = os.path.join(prefixed_dirname, filename)
                mtime = datetime.datetime.fromtimestamp(
                    os.path.getmtime(prefixed_fullpath), tz=utc)
                results += [{"Key": fullpath, "LastModified": mtime}]
    return results


def list_s3(bucket, lognames, prefix=None, logsuffix=None,
            time_from_logsuffix=False):
    """
    Returns a list of rotated log files present in a bucket
    with their timestamp.

    Example:

    .. code-block:: json

        list_s3(bucket, lognames=['www.example.com.log'])

    returns

    .. code-block:: json

        [{
            "Key": "var/log/www.example.com.log-0ce5c29636da94d4c-20160106.gz",
            "LastModified": "Mon, 06 Jan 2016 00:00:00 UTC"
         }, {
            "Key": "var/log/www.example.com.log-0ce5c29636da94d4c-20160105.gz",
            "LastModified": "Mon, 05 Jan 2016 00:00:00 UTC"
         }]
    """
    results = []
    s3_resource = boto3.resource('s3')
    for logname in lognames:
        logprefix, ext = os.path.splitext(logname)
        logprefix = logprefix.lstrip('/')
        if prefix:
            logprefix = "%s/%s" % (prefix.strip('/'), logprefix)
        for s3_key in s3_resource.Bucket(bucket).objects.filter(
                Prefix=logprefix):
            logkey = as_logname(s3_key.key, logsuffix=logsuffix,
                prefix=prefix, ext=ext)
            if logname.startswith('/'):
                logkey = '/' + logkey
            if logkey == logname:
                look = re.match(r'\S+-(\d\d\d\d\d\d\d\d)\.gz', s3_key.key)
                if time_from_logsuffix and look:
                    last_modified = datetime.datetime.strptime(
                        look.group(1), "%Y%m%d")
                else:
                    last_modified = s3_key.last_modified
                if last_modified.tzinfo is None:
                    last_modified = last_modified.replace(tzinfo=utc)
                results += [{"Key": s3_key.key, "LastModified": last_modified}]
    return results


def list_updates(local_items, s3_items, prefix=None,
                 logsuffix=None, logext='.log'):
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
            logsuffix=logsuffix, prefix=prefix, logext=logext)] = local_val
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
            logsuffix=logsuffix, prefix=prefix, logext=logext)] = s3_val
    for local_val in local_items:
        local_key = local_val['Key'].lstrip('/')
        s3_val = s3_index.get(local_key, None)
        if s3_val:
            s3_datetime = s3_val['LastModified']
            local_datetime = local_val['LastModified']
            if local_datetime > s3_datetime:
                s3_results += [local_val]
        else:
            s3_results += [local_val]

    return local_results, s3_results


def download_updated_logs(lognames,
                          local_prefix=None, logsuffix=None,
                          bucket=None, s3_prefix=None,
                          last_run=None, list_all=False,
                          time_from_logsuffix=False, dry_run=False):
    """
    Fetches log files which are on S3 and more recent that specified
    in last_run and returns a list of filenames.
    """
    #pylint:disable=too-many-arguments,too-many-locals
    local_update, _ = list_updates(
        list_local(lognames, prefix=local_prefix, list_all=list_all),
        list_s3(bucket, lognames, prefix=s3_prefix,
            time_from_logsuffix=time_from_logsuffix),
        logsuffix=logsuffix, prefix=s3_prefix)

    downloaded = []
    s3_resource = boto3.resource('s3')
    for item in sorted(local_update, key=get_last_modified):
        keyname = item['Key']
        keydatetime = item['LastModified']
        logname = as_logname(keyname)
        filename = as_filename(keyname, prefix=s3_prefix)
        filename = filename.lstrip(os.sep)
        if local_prefix:
            filename = os.path.join('.', local_prefix, filename)
        else:
            filename = os.path.join('.', filename)
        if not last_run or last_run.more_recent(
                logname, item['LastModified'], update=True):
            s3_key = s3_resource.Object(bucket, keyname)
            if not s3_key.storage_class or s3_key.storage_class == 'STANDARD':
                LOGGER.info("%sdownload %s (%s) to %s\n",
                    "(dryrun) " if dry_run else "",
                    keyname, keydatetime.isoformat(), os.path.abspath(filename))
                if not dry_run:
                    if not os.path.isdir(os.path.dirname(filename)):
                        os.makedirs(os.path.dirname(filename))
                    s3_key.download_file(filename)
                downloaded += [filename]
            else:
                LOGGER.info("skip %s (%s, on %s storage)\n",
                    keyname, keydatetime.isoformat(), s3_key.storage_class)

    # It is possible some files were already downloaded as part of a previous
    # run so we construct the list of recent files here.
    downloaded = []
    for item in sorted(list_local(lognames,
                prefix=local_prefix, list_all=False), key=get_last_modified):
        keyname = item['Key']
        logname = as_logname(keyname)
        filename = as_filename(keyname, prefix=s3_prefix)
        filename = filename.lstrip(os.sep)
        if local_prefix:
            filename = os.path.join('.', local_prefix, filename)
        else:
            filename = os.path.join('.', filename)
        if not last_run or last_run.more_recent(
                logname, item['LastModified'], update=True):
            downloaded += [filename]
    return downloaded


def upload_log(s3_location, filename, logsuffix=None,
               logext='.log', dry_run=False):
    """
    Upload a local log file to an S3 bucket. If logsuffix is ``None``,
    the instance-id will be automatically added as a suffix in the log filename.
    """
    headers = {'ContentType': 'text/plain'}
    if filename.endswith('.gz'):
        headers.update({'ContentEncoding': 'gzip'})
    if filename.endswith('.zip'):
        headers.update({'ContentType': 'application/zip'})
    parts = s3_location[5:].split('/')
    s3_bucket = parts[0]
    s3_prefix = '/'.join(parts[1:])
    if not logsuffix:
        # https://github.com/boto/boto3/issues/313
        resp = requests.get('http://instance-data/latest/meta-data/instance-id')
        logsuffix = resp.text
        if logsuffix.startswith('i-'):
            logsuffix = logsuffix[1:]
    keyname = as_keyname(
        filename, logsuffix=logsuffix, prefix=s3_prefix, logext=logext)
    LOGGER.info("%supload %s ... to s3://%s/%s\n",
        "(dryrun) " if dry_run else "", filename, s3_bucket, keyname)
    if not dry_run:
        s3_client = boto3.client('s3')
        s3_client.upload_file(filename, s3_bucket, keyname, ExtraArgs=headers)


def main(args):
    #pylint:disable=too-many-locals
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options] command\n\nVersion\n  %(prog)s version '
        + str(__version__))
    parser.add_argument('--version', action='version',
        version='%(prog)s ' + str(__version__))
    parser.add_argument('--dry-run', action='store_true',
        dest='dry_run', default=False,
        help='Only show commands. Do not actually copy files')
    parser.add_argument('--quiet', action='store_true',
        dest='quiet', default=False,
        help='Quiet mode. Only write on stderr when there is an error')
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
    parser.add_argument('--logext', action='store',
        dest='logext', default='.log',
        help='File extension after which logsuffix is inserted '
            '(defaults to ".log")')
    parser.add_argument('lognames', metavar='lognames', nargs='+',
        help="rotated log files to upload/download")

    options = parser.parse_args(args[1:])
    if len(options.lognames) < 1:
        sys.stderr.write("error: not enough arguments")
        parser.print_help()
        return 1

    if options.quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(format='%(message)s', level=logging.INFO)

    lognames = options.lognames
    logsuffix = options.logsuffix
    logext = options.logext
    s3_location = options.location
    parts = s3_location[5:].split('/')
    s3_bucket = parts[0]
    s3_prefix = '/'.join(parts[1:])
    to_s3 = not options.download
    if to_s3:
        LOGGER.info(
            "Upload rotated logs for %s to bucket '%s' under prefix '%s'\n",
            ' '.join(lognames), s3_bucket, s3_prefix)
    else:
        LOGGER.info(
            "Download rotated logs for %s from bucket '%s' under prefix '%s'\n",
            ' '.join(lognames), s3_bucket, s3_prefix)

    local_prefix = '.' if not to_s3 else None
    if to_s3:
        # Upload
        _, s3_update = list_updates(
            list_local(lognames, prefix=local_prefix,
                list_all=options.list_all),
            list_s3(s3_bucket, lognames, prefix=s3_prefix,
                logsuffix=logsuffix),
            prefix=s3_prefix, logsuffix=logsuffix, logext=logext)
        for item in s3_update:
            filename = item['Key']
            upload_log(s3_location, filename,
                logsuffix=logsuffix, logext=logext,
                dry_run=options.dry_run)
    else:
        # Download
        if options.last_run and os.path.exists(options.last_run):
            last_run = LastRunCache(options.last_run)
        else:
            last_run = None
        download_updated_logs(lognames,
            local_prefix=local_prefix, logsuffix=logsuffix,
            bucket=s3_bucket, s3_prefix=s3_prefix,
            last_run=last_run, list_all=options.list_all,
            time_from_logsuffix=True, dry_run=options.dry_run)
        if not options.dry_run and last_run:
            last_run.save()
    return 0


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main(sys.argv[1:])

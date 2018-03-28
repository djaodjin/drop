#!/usr/bin/env python
#
# Copyright (c) 2018, Djaodjin Inc.
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

import argparse, logging, os, sys

import boto


__version__ = None

LOGGER = logging.getLogger(__name__)

BOTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

def main(args):
    #pylint:disable=too-many-locals
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
    #pylint:disable=invalid-name
    bin_path = os.path.realpath(os.path.abspath(sys.argv[0]))
    if bin_path.endswith('bin/dcopylogs'):
        sys.path += [os.path.join(
            os.path.dirname(os.path.dirname(bin_path)), 'lib',
            'python%d.%d' % (sys.version_info[0], sys.version_info[1]),
            'site-packages')]
    from tero.dcopylogs import (LastRunCache, list_updates, list_local,
        list_s3, as_keyname, download_updated_logs)

    sys.exit(main(sys.argv))

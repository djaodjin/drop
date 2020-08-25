#!/usr/bin/env python
#
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

import argparse, hashlib, json, logging, re, select, sys

import six, boto3
from six.moves.urllib.parse import urlparse
from systemd import journal

__version__ = None

LOGGER = logging.getLogger(__name__)

APP_NAME = 'djaoapp'
S3_LOGS_BUCKET = 'djaoapp-logs'

PAT = None
exception_start_pat = re.compile(r"ERROR (?P<remote_addr>.+) (?P<username>.+) \[(?P<asctime>.+)\] Internal Server Error: (?P<http_path>.+) \"(?P<http_user_agent>.+)\"")
traceback_start_pat = re.compile(r"^Traceback \(most recent call last\):")
file_lineno_pat = re.compile(r"\s+File \"(?P<filename>.+)\", line (?P<lineno>\d+), in (?P<function>\S+)")
exception_class_pat = re.compile(r"^(?P<exception_type>\S+):\s+\S+")

EXCEPTION_START = 0
TRACEBACK_START = 1
FIRST_FILE_LINENO = 2
FILE_LINENO = 3
STATEMENT = 4
EXCEPTION_CLASS = 5
EXCEPTION_END = 6

msg = None
state = EXCEPTION_START


class EventWriter(object):

    def __init__(self, location):
        _, self.bucket, prefix = urlparse(location)[:3]
        self.prefix = prefix.strip('/')
        self.s3_client = boto3.resource('s3')

    def write(self, msg):
        mod = hashlib.sha256()
        mod.update(msg.encode("utf-8"))
        key = "%s/%s.json" % (self.prefix, mod.hexdigest())
#        print("XXX isolate msg:\n%s***" % str(msg))
        LOGGER.info("upload event to s3://%s/%s" % (self.bucket, key))
        self.s3_client.Object(self.bucket, key).put(Body=msg)


def append_content(content, writer=None):
    global state, msg

    if state == EXCEPTION_START:
        look = exception_start_pat.match(content)
#        print("XXX [EXCEPTION_START] look:%s" % str(look))
        if look:
            msg = {
                'log_level': "ERROR",
                'asctime': look.group('asctime'),
                'remote_addr': look.group('remote_addr'),
                'username': look.group('username'),
                'http_path': look.group('http_path'),
                'http_user_agent': look.group('http_user_agent'),
                'frames': []
                }
            state = TRACEBACK_START
    elif state == TRACEBACK_START:
        look = traceback_start_pat.match(content)
        if look:
            state = FILE_LINENO
    elif state == FILE_LINENO:
        look = file_lineno_pat.match(content)
        if look:
            msg['frames'] += [{
                'filename': look.group('filename'),
                'lineno': look.group('lineno'),
                'function': look.group('function')
            }]
            state = STATEMENT
        else:
            look = exception_class_pat.match(content)
            if look:
                msg.update({
                    'exception_type': look.group('exception_type')
                })
                msg = json.dumps(msg)
                state = EXCEPTION_END
    elif state == STATEMENT:
        msg['frames'][-1].update({
            'context_line': content.strip()
        })
        state = FILE_LINENO

    if state == EXCEPTION_END:
        if writer:
            writer.write(msg)
        msg = None
        state = EXCEPTION_START


def parse_output(filename, writer):
    with open(filename) as filed:
        for line in filed.readlines():
            append_content(line, writer)


def main(args):
    parser = argparse.ArgumentParser(\
            usage='%(prog)s [options] command\n\nVersion\n  %(prog)s version ' \
                + str(__version__))
    parser.add_argument('--version', action='version',
                        version='%(prog)s ' + str(__version__))
    parser.add_argument('-c', '--unit', dest='unit', default=APP_NAME)
    parser.add_argument('--location', dest='location',
        default='s3://%s/50x/' % S3_LOGS_BUCKET)
    parser.add_argument('filenames', nargs='*')

    options = parser.parse_args(args[1:])

    unit = options.unit
    writer = EventWriter(options.location)

    if options.filenames:
        for filename in options.filenames:
            parse_output(filename, writer)
        return

    global PAT
    PAT = re.compile(r'^gunicorn.%(unit)s.app: \[\d+\] ERROR.+\[.+\] ({.+)' % {
        'unit': unit})
    jctl = journal.Reader()
    jctl.add_match(_SYSTEMD_UNIT='%s.service' % unit)
    jctl.seek_tail()
    jctl.get_previous()  # Important! - Discard old journal entries
    pctl = select.poll()
    pctl.register(jctl, jctl.get_events())
    msg = None
    while True:
        resp = pctl.poll()
        if resp and jctl.process() == journal.APPEND:
            # If we don't call `jctl.process()`, flags are not reset properly
            # and poll does not wait.
            # See https://www.freedesktop.org/software/systemd/man/sd_journal_get_events.html
            for evt in jctl:
                content = evt.get('MESSAGE')
                look = pat.match(content)
                if look:
                    msg = look.group(1)
                elif isinstance(msg, six.string_types):
                    msg += content
                else:
                    msg = None
                if msg:
                    try:
                        val = json.loads(msg)
                        if writer:
                            writer.write(msg)
                    except (TypeError, ValueError) as err:
                        pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main(sys.argv)

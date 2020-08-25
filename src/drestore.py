#!/usr/bin/env python
#
# Copyright (c) 2017, DjaoDjin inc.
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

"""
Restore databases from file dumps
"""
from __future__ import unicode_literals

import argparse, re, os, subprocess, sys, tempfile

__version__ = '0.1dev'


def restore_ldap(filename, domain=None):
    """
    Restore a LDAP database from file.
    """
    with tempfile.NamedTemporaryFile(dir=os.path.dirname(filename)) as tmpfile:
        tmpfilename = tmpfile.name
        with open(filename) as backup:
            for line in backup.readlines():
                look = re.match('^(\S+): (.*)', line)
                if look:
                    key = look.group(1)
                    value = look.group(2)
                    if not key in ('structuralObjectClass', 'entryUUID',
                        'creatorsName', 'createTimestamp', 'entryCSN',
                        'modifiersName', 'modifyTimestamp'):
                        config_line = "%s: %s\n" % (key, value)
                        if hasattr(config_line, 'encode'):
                            config_line = config_line.encode('utf-8')
                        tmpfile.write(config_line)
                else:
                    if hasattr(line, 'encode'):
                        line = line.encode('utf-8')
                    tmpfile.write(line)
        domain_dn = ',dc='.join(domain.split('.'))
        cmd = ['ldapadd', '-Y', 'EXTERNAL', '-H', 'ldapi:///',
               '-f', tmpfilename, '-D', 'cn=Manager,dc=%s' % domain_dn]
        sys.stdout.write("%s\n" % ' '.join(cmd))
        subprocess.check_call(cmd)


def restore_postgresql(filename, drop_if_exists=True):
    """
    Restore a PostgresQL database from file.
    """
    if drop_if_exists:
        db_name = os.path.basename(filename).split('.')[0]
        cmd = ['sudo', '-u', 'postgres', 'psql', '-c',
            'DROP DATABASE IF EXISTS %s;' % db_name]
        sys.stdout.write("%s\n" % ' '.join(cmd))
        subprocess.check_call(cmd)
    if filename.endswith('.gz'):
        cmd = ['sh', '-c',
            "sudo -u postgres gunzip -c %s | sudo -u postgres psql" % filename]
    else:
        cmd = ['sudo', '-u', 'postgres', 'psql', '-f', filename]
    sys.stdout.write("%s\n" % ' '.join(cmd))
    subprocess.check_call(cmd)


def main(args):
    """
    Main Entry Point
    """
    exit_code = 0
    parser = argparse.ArgumentParser(
        usage='%(prog)s [options] command\n\nVersion\n  %(prog)s version '
        + str(__version__))
    parser.add_argument('--version', action='version',
        version='%(prog)s ' + str(__version__))
    parser.add_argument('--domainName', dest='domain',
        action='store', default=None,
        help="domain managed by LDAP server")
    parser.add_argument('filenames', nargs='+',
        help='List of files to restore')

    if len(args) <= 1:
        parser.print_help()
        return 1

    options = parser.parse_args(args[1:])

    for filename in options.filenames:
        if filename.endswith('.ldif'):
            restore_ldap(filename, domain=options.domain)
        elif filename.endswith('.sql') or filename.endswith('.sql.gz'):
            restore_postgresql(filename)
        else:
            sys.stderr.write(
                "error: cannot decide how to restore '%s'\n" % filename)
            exit_code = 1
    return exit_code


if __name__ == '__main__':
    sys.exit(main(sys.argv))

#!/usr/bin/env python
#
# Copyright (c) 2016, DjaoDjin inc.
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

import argparse, re, os, subprocess, sys, tempfile

__version__ = '0.1dev'


def restore_ldap(filename, domain=None):
    """
    Restore a LDAP database from file.
    """
    handle, tmpfilename = tempfile.mkstemp(dir=os.path.dirname(filename))
    try:
        with open(filename) as backup:
            for line in backup.readlines():
                look = re.match('^(\S+): (.*)', line)
                if look:
                    key = look.group(1)
                    value = look.group(2)
                    if not key in ('structuralObjectClass', 'entryUUID',
                        'creatorsName', 'createTimestamp', 'entryCSN',
                        'modifiersName', 'modifyTimestamp'):
                        os.write(handle, "%s: %s\n" % (key, value))
                else:
                    os.write(handle, line)
        os.close(handle)
        domain_dn = ',dc='.join(domain.split('.'))
        cmd = ['ldapadd', '-x', '-H', 'ldap:///', '-f', tmpfilename,
            '-D', 'cn=Manager,dc=%s' % domain_dn, '-W']
        sys.stdout.write("%s\n" % ' '.join(cmd))
        subprocess.check_call(cmd)
    finally:
        os.remove(tmpfilename)


def restore_postgresql(filename):
    """
    Restore a PostgresQL database from file.
    """
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
        elif filename.endswith('.sql'):
            restore_postgresql(filename)
        else:
            sys.stderr.write(
                "error: cannot decide how to restore '%s'\n" % filename)
            exit_code = 1
    return exit_code


if __name__ == '__main__':
    sys.exit(main(sys.argv))

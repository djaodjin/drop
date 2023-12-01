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

"""
This script has two purposes. First, it generates filenames stamped with
date and time according to the following pattern filename-yyyy_mm_dd_hh.
Second, this script will remove files in the current directory based
on a specified aging policy.

Primary Author(s): Sebastien Mirolo <smirolo@fortylines.com>
"""
from __future__ import unicode_literals

import datetime, optparse, os, re, shutil, sys

import tero as dws

DO_NOT_EXECUTE = True
VERBOSE = False


def keep_dates(dates, keep_count):
    """
    returns a list of keep_count dates that have been preserved.

    dates         list dates
    keep_count     integer number of dates to keep out of dates
    """
    if len(dates) <= keep_count:
        return dates

    keep = []
    step = 0
    dates.sort()
    cutoff = int(len(dates) / keep_count)
    if len(dates) % keep_count > 0:
        # We round up such that less than
        # or equal to keep_count dates are preserved.
        cutoff = cutoff + 1
    for date in dates:
        if step == 0:
            keep += [date]
        step = (step + 1) % cutoff
    return keep

# Clean a list of dates
# return a list of dates that have been preserved accoring to a policy
# of keep_per_year,keep_per_month,keep_per_week.
def cleanup_aged_stamps(dates, keep_per_year, keep_per_month, keep_per_week):
    keep = []
    years = {}
    months = {}
    weeks = {}
    dates.sort()
    now = datetime.datetime.now()
    for date in dates:
        delta = now - date
        if delta.days > 365:
            if not date.year in years:
                years[date.year] = []
            years[date.year] += [date]
        elif delta.days > 30:
            if not date.month in months:
                months[date.month] = []
            months[date.month] += [date]
        elif delta.days > 7:
            week = delta.days / 7
            if not week in weeks:
                weeks[week] = []
            weeks[week] += [date]
        else:
            # Less than a week old
            keep += [date]
    for year in years.values():
        keep += keep_dates(year, keep_per_year)
    for month in months.values():
        keep += keep_dates(month, keep_per_month)
    for week in weeks.values():
        keep += keep_dates(week, keep_per_week)
    return keep

# Removes files through an aging process such as to only keep
# a maximum amount of temporaries.
def cleanup_aged_files(dirname,
                       keep_per_year=1, keep_per_month=1, keep_per_week=1):
    files = {}
    if not os.path.isdir(dirname):
        raise dws.Error(dirname + ' is not a directory.')
    for logname in os.listdir(dirname):
        look = re.match(
            r"(.*)-(\d\d\d\d)_(\d\d)_(\d\d)(-\d\d)?(\..*)", logname)
        if look:
            filename = look.group(1) + look.group(6)
            if not filename in files:
                files[filename] = []
            hour = 0
            if look.group(5) and look.group(5).startswith('-'):
                hour = int(look.group(5)[1:])
            files[filename] += [datetime.datetime(int(look.group(2)),
                                                  int(look.group(3)),
                                                  int(look.group(4)),
                                                  hour)]
    for filename in files:
        keep = cleanup_aged_stamps(
            files[filename], keep_per_year, keep_per_month, keep_per_week)
        for date in files[filename]:
            pathname = os.path.join(
                dirname, dws.mark(filename, dws.stamp(date)))
            if not date in keep:
                if not DO_NOT_EXECUTE:
                    sys.stdout.write('clean ' + pathname)
                    tmp_dir = os.sep + 'tmp'
                    if 'TMPDIR' in os.environ:
                        tmp_dir = os.environ['TMPDIR']
                    shutil.move(pathname, os.path.join(
                        tmp_dir, os.path.basename(pathname)))
                else:
                    if VERBOSE:
                        sys.stdout.write('clean* ' + pathname)
            else:
                if VERBOSE:
                    sys.stdout.write('keep  ' + pathname)


def pub_clean(args):
    '''clean         targetDir
                  Delete files which have aged according to a policy.
                  The policy is defined by the number of stamped files
                  that are kept per year, month and week. All stamps
                  less than a week old are always kept.'''
    if len(args) < 1:
        raise dws.Error('missing *targetDir*')
    cleanup_aged_files(
        args[0], keep_per_year=1, keep_per_month=1, keep_per_week=1)

def pub_install(args):
    '''install      sourceFile [sourceFile ...] targetDir
                  Install source file into target directory
                  with a stamp suffix.'''
    install_dir = args.pop()
    for filename in args:
        shutil.copy(
            filename, os.path.join(install_dir, dws.stampfile(filename)))

# Main Entry Point
def main(args):
    try:
        epilog = '\nCommands:\n'
        import __main__
        keys = __main__.__dict__.keys()
        keys.sort()
        for command in keys:
            if command.startswith('pub'):
                epilog += __main__.__dict__[command].__doc__ + '\n'

        parser = optparse.OptionParser(\
            usage='%prog [options] command\n\nVersion\n  %prog version ' \
                + str(dws.__version__),
            formatter=dws.CommandsFormatter(),
            epilog=epilog)
        parser.add_option('--help-book', dest='helpBook', action='store_true',
                          help='Print help in docbook format')
        parser.add_option('--version', dest='version', action='store_true',
                          help='Print version information')
        parser.add_option('-n', dest='noexecute', action='store_true',
                          help='Do not execute, run informative only.')
        parser.add_option('-v', dest='verbose', action='store_true',
                          help='Verbose mode')

        options, args = parser.parse_args()
        if options.version:
            sys.stdout.write(args[0] + ' version ' + str(dws.__version__) \
                                 + '\n')
            sys.exit(0)

        if options.helpBook:
            help_text = dws.StringIO()
            parser.print_help(help_text)
            dws.help_book(help_text)
            sys.exit(0)
        if options.noexecute:
            global DO_NOT_EXECUTE
            DO_NOT_EXECUTE = True
        if options.verbose:
            global VERBOSE
            VERBOSE = True

        arg = args.pop(0)
        command = 'pub' + arg.capitalize()
        if command in __main__.__dict__:
            __main__.__dict__[command](args)
        else:
            raise dws.Error(args[0] + ' ' + arg + ' does not exist.\n')

    except dws.Error as err:
        sys.stderr.write(str(err))
        sys.exit(err.code)

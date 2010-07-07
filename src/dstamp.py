#!/usr/bin/env python
#
# Copyright (c) 2009, Sebastien Mirolo
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of fortylines nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY Sebastien Mirolo ''AS IS'' AND ANY
#   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL Sebastien Mirolo BE LIABLE FOR ANY
#   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# This script has two purposes. First, it generates filenames stamped with
# date and time according to the following pattern filename-yyyy_mm_dd_hh.
# Second, this script will remove files in the current directory based
# on a specified aging policy.

__version__ = None

import datetime, optparse, os, shutil, sys

# We donot want to install dws.py alongside dws in *binDir* and rely
# on the search path to find it. Thus dws is imported directly through 
# a load_source() command here.
import imp
dws = imp.load_source('dws',
   os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])),'dws'))

doNotExecute = True

# \brief return a list of keepCount dates that have been preserved.
#
# dates         list dates
# keepCount     integer number of dates to keep out of dates
def keepDates(dates,keepCount):
    if len(dates) <= keepCount:
        return dates
    else:
        keep = []        
        step = 0
        dates.sort()
        cutoff = int(len(dates) / keepCount)
        if len(dates) % keepCount > 0:
            # We round up such that less than
            # or equal to keepCount dates are preserved.
            cutoff = cutoff + 1
        for d in dates:
            if step == 0:
                keep += [ d ]
            step = (step + 1) % cutoff
        return keep

# Clean a list of dates
# return a list of dates that have been preserved accoring to a policy
# of keepPerYear,keepPerMonth,keepPerWeek.
def cleanUpAgedStamps(dates,keepPerYear,keepPerMonth,keepPerWeek):
    keep = []
    years = {}
    months = {}
    weeks = {}
    lessThanWeek = []
    dates.sort()
    now = datetime.datetime.now()
    for d in dates:
        delta = now - d
        if delta.days > 365:
            if not d.year in years:
                years[d.year] = []
            years[d.year] += [ d ]
        elif delta.days > 30:
            if not d.month in months:
                months[d.month] = []
            months[d.month] += [ d ]
        elif delta.days > 7:
            week = delta.days / 7
            if not week in weeks:
                weeks[week] = []
            weeks[week] += [ d ]
        else:
            # Less than a week old
            keep += [ d ]
    for y in years.values():
        keep += keepDates(y,keepPerYear)
    for m in months.values():
        keep += keepDates(m,keepPerMonth)
    for w in weeks.values():
        keep += keepDates(w,keepPerWeek)
    return keep
        
# Removes files through an aging process such as to only keep
# a maximum amount of temporaries.
def cleanUpAgedFiles(dirname,keepPerYear=1,keepPerMonth=1,keepPerWeek=1):
    files = {}
    for p in os.listdir(dirname):
        look = re.match("(.*)-(\d\d\d\d)_(\d\d)_(\d\d)_(\d\d)(\..*)",p)
        if look != None:
            filename = look.group(1) + look.group(6)
            if files[filename] == None:
                files[filename] = []
            files[filename] += [ datetime.datetime(int(look.group(2)),
                                                   int(look.group(3)),
                                                   int(look.group(4)),
                                                   int(look.group(5))) ]
    for filename in files.keys():
        keep = cleanUpAgedStamps(files[filename],keepPerYear,keepPerMonth,keepPerWeek)
        for d in files[filename]:
            if not d in keep:
                pathname = os.path.join(dirname,stamp(filename,d))
                if not doNotExecute:
                    os.remove(pathname)

def pubClean(args):
    '''clean         targetDir
                  Delete files which have aged according to a policy.
                  The policy is defined by the number of stamped files
                  that are kept per year, month and week. All stamps
                  less than a week old are always kept.'''
    cleanUpAgedFiles('.',keepPerYear=1,keepPerMonth=1,keepPerWeek=1)

def pubInstall(args):
    '''install      sourceFile [sourceFile ...] targetDir
                  Install source file into target directory
                  with a stamp suffix.'''
    installDir = args.pop()
    for f in args:
        shutil.copy(f,os.path.join(installDir,dws.stampfile(f)))

# Main Entry Point
if __name__ == '__main__':
    try:
        epilog= '\nCommands:\n'
        import __main__
        keys = __main__.__dict__.keys()
        keys.sort()
        for command in keys:
            if command.startswith('pub'):
                epilog += __main__.__dict__[command].__doc__ + '\n'

        parser = optparse.OptionParser(\
            usage='%prog [options] command\n\nVersion\n  %prog version ' \
                + str(__version__),
            formatter=dws.CommandsFormatter(),
            epilog=epilog)
        parser.add_option('--version', dest='version', action='store_true',
                          help='Print version information')

        options, args = parser.parse_args()
        if options.version:
            sys.stdout.write(sys.argv[0] + ' version ' + str(__version__) \
                                 + '\n')
            sys.exit(0)

        arg = args.pop(0)
        command = 'pub' + arg.capitalize()
        if command in __main__.__dict__:
            __main__.__dict__[command](args)
        else:
            raise dws.Error(sys.argv[0] + ' ' + arg + ' does not exist.\n')

    except dws.Error, err:
        sys.stderr.write(str(err))
        sys.exit(err.code)

 

        

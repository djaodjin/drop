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

import datetime, dws, os, sys

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

# Main Entry Point
if __name__ == '__main__':
    keepPerYear = 1
    keepPerMonth = 1
    keepPerWeek = 1
    arguments = sys.argv[1:]
    if len(arguments) == 0:
        sys.stdout.write('''
usage: ''' + sys.argv[0] + ''' [command] pathname
where command is one of the following:
clean             delete files which have aged according to a policy.
                  The policy is defined by the number of stamped files
                  that are kept per year, month and week. All stamps
                  less than a week old are always kept.

selftest          Run the selftest that checks the algorithm is implemented
                  correctly.
''')        
    if arguments[0] == 'clean':
        cleanUpAgedFiles('.',keepPerYear,keepPerMonth,keepPerWeek)
    elif arguments[0] == 'selftest':
        # Generate test cases
        now = datetime.datetime.now()
        # more than one year old
        dates = [ now - datetime.timedelta(days=366) ]
        dates += [ now - datetime.timedelta(days=365+79) ]
        dates += [ now - datetime.timedelta(days=365+82) ]
        dates += [ now - datetime.timedelta(days=365+85) ]
        dates += [ now - datetime.timedelta(days=365*2+1) ]
        dates += [ now - datetime.timedelta(days=365*2+120) ]
        dates += [ now - datetime.timedelta(days=365*2+122) ]
        dates += [ now - datetime.timedelta(days=365*3+1) ]
        dates += [ now - datetime.timedelta(days=365*3+63) ]
        # more than one month but less than one year old
        dates += [ now - datetime.timedelta(days=32) ]
        dates += [ now - datetime.timedelta(days=36) ]
        dates += [ now - datetime.timedelta(days=39) ]
        dates += [ now - datetime.timedelta(days=65) ]
        dates += [ now - datetime.timedelta(days=67) ]
        dates += [ now - datetime.timedelta(days=69) ]
        # more than one week but less than one month old
        dates += [ now - datetime.timedelta(days=7) ]
        dates += [ now - datetime.timedelta(days=8) ]
        dates += [ now - datetime.timedelta(days=12) ]
        dates += [ now - datetime.timedelta(days=23) ]
        # less than one week old
        dates += [ now - datetime.timedelta(days=1) ]
        dates += [ now - datetime.timedelta(days=2) ]
        dates += [ now - datetime.timedelta(days=3) ]
        dates += [ now - datetime.timedelta(days=4) ]
        keep = cleanUpAgedStamps(dates,1,1,1)
        for d in dates:
            delta = now - d
            if d in keep:
                sys.stdout.write('* ')
            else:
                sys.stdout.write('  ')
            sys.stdout.write(dws.stamp("dummy.log",d) + ' >' + str(delta.days) + ' days\n')
    else:
        # stamp file with current date
        print dws.stamp(sys.argv[1])
        

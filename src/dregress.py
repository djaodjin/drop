#!/usr/bin/env python
#
# Generate regression between two log files.

import re, os, sys

def diffAdvance(diff):
    diffLineNum = sys.maxint
    look = None
    while look == None:
        diffLine = diff.readline()
        if diffLine == '':
            break
        # print "advance diff: " + diffLine
        look = re.match('@@ -(\d)+,',diffLine)
    if look != None:
        diffLineNum = int(look.group(1))
    return diffLineNum


def logAdvance(log):
    logTestName = None
    logLineNum = sys.maxint
    logLine = log.readline()
    # print "advance log: " + logLine
    look = re.match('(\d+):.*name="(\S+)"',logLine)
    if look != None:
        logLineNum = int(look.group(1))
        logTestName = look.group(2)
    return logLineNum, logTestName

# Main Entry point
if len(sys.argv) < 3:
    sys.stderr.write('usage: logfile referenceLogfile')
    sys.exit(1)

logfile = sys.argv[1]
reffile = sys.argv[2]

logCmdLine = "grep -n '<test ' " + logfile
# Use one line of context such that a "first line" diff does
# not include "previous test" output in the context because
# that would change value of diffLineNum and mess the following
# algorithm.
diffCmdLine = 'diff -U 1 ' + logfile + ' ' + reffile
print "log cmd line: " + logCmdLine
print "diff cmd line: " + diffCmdLine
log = os.popen(logCmdLine)
diff = os.popen(diffCmdLine)
logLineNum, logTestName = logAdvance(log)
diffLineNum = diffAdvance(diff)
final = False
# end-of-file is detected by checking the uninitialized value 
# of logLineNum and diffLineNum as set by logAdvance() and diffAdvance().
while logLineNum != sys.maxint or diffLineNum != sys.maxint:
    if diffLineNum < logLineNum:
        # last log failed
        print "   !!! swtich on (" + str(logLineNum) + ',' + str(diffLineNum) + ')'
        if logTestName != None:
            print logTestName + " fail"
            logTestName = None
        diffLineNum = diffAdvance(diff)
    elif diffLineNum > logLineNum:
        # last log passed
        print "   !!! swtich on (" + str(logLineNum) + ',' + str(diffLineNum) + ')'
        if logTestName != None:
            print logTestName + " pass"
        logLineNum, logTestName = logAdvance(log)
    else:
        print "   !!! else swtich on (" + str(logLineNum) + ',' + str(diffLineNum) + ')'
        diffLineNum = diffAdvance(diff)
        logLineNum, logTestName = logAdvance(log)
 
diff.close()
log.close()

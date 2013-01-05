#!/usr/bin/env python
#
# Copyright (c) 2012-2013, Fortylines LLC
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
#   THIS SOFTWARE IS PROVIDED BY Fortylines LLC ''AS IS'' AND ANY
#   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL Fortylines LLC BE LIABLE FOR ANY
#   DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# This script extracts the bare useful information to quickly scan through
# log files.
#
# Primary Author: Sebastien Mirolo

import re, sys

if __name__ == '__main__':
    '''Main Entry Point'''
    for arg in sys.argv[1:]:
        log = open(arg,'r')
        line = log.readline()
        bufferedLines = [ line ]
        while line != '':
            # We locally filter log output. Everything that falls before
            # a '^###' marker will be discarded in the error output.
            look = re.match('^###.*\s+(\S+)\s+.*',line)
            if look:
                bufferedLines = [ line ]
            else:
                look = re.match('^(make(\[\d+\]:.*not remade because of errors)|(:.*Error \d+))',line)
                if look:
                    filename = '^make '
                else:
                    look = re.match('^(.*):\d+:error:',line)
                    if look:
                        filename = look.group(1)
                    else:
                        look = re.match('^error:',line)
                        if look:
                            filename = '^$'
                if look:
                    # We will try to finely filter buffered lines to the shell
                    # command that triggered the error if possible.
                    start = 0
                    if len(bufferedLines) > 0:
                        start = len(bufferedLines) - 1
                    while start > 0:
                        look = re.match(filename,bufferedLines[start])
                        if look:
                            break
                        start = start - 1
                    for prev in bufferedLines[start:]:
                        sys.stdout.write(prev)
                    bufferedLines = []
            line = log.readline()
            bufferedLines += [ line ]


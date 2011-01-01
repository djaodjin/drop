#!/usr/bin/env python
#
# Copyright (c) 2009-2010, Fortylines LLC
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

import subprocess, datetime, os, time, signal

__version__ = None


def timeoutCommand(cmdline, timeout):
    '''Executes a shell command and kill it if it did not complete
    in *timeout* seconds. returns the error code returned by the process.'''
    start = datetime.datetime.now()
    cmd = subprocess.Popen(' '.join(cmdline),shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    line = cmd.stdout.readline()
    while process.poll() is None:
    #while line != '':
       writetext(line)
       line = cmd.stdout.readline()
       time.sleep(0.1)
       now = datetime.datetime.now()
       if (now - start).seconds > timeout:
           os.kill(cmd.pid, signal.SIGKILL)
           os.waitpid(-1, os.WNOHANG)
    cmd.wait()
    return cmd.returncode

# Main Entry Point
if __name__ == '__main__':

    import optparse

    parser = optparse.OptionParser(\
        usage='%prog [options] command\n\nVersion\n  %prog version ' \
            + str(__version__))
    parser.add_option('--timeout', dest='timeout', action='int',
        default=10,
        help='sets the time out in seconds')
    parser.add_option('--version', dest='version', action='store_true',
        help='Print version information')

    options, args = parser.parse_args()
    if options.version:
        sys.stdout.write(sys.argv[0] + ' version ' + str(__version__) \
                             + '\n')
        sys.exit(0)

    if len(args) < 1:
        parser.print_help()
        sys.exit(1)

    timeout = 10
    if options.timeout:
        timeout = options.timeout

    return timeoutCommand(args, timeout)
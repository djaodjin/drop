# Copyright (c) 2021, DjaoDjin inc.
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
Download open issues from GitHub repositories
"""
import argparse, configparser, logging, os, sys

import requests


def download(repos, user=None, password=None):
    kwargs = {}
    if user and password:
        kwargs = {'auth': requests.auth.HTTPBasicAuth(user, password)}
    headers = ['owner', 'repo', 'number', 'title', 'milestone', 'url']
    print("%s" % ','.join(headers))
    for repo in repos:
        owner, repo = repo.split('/')
        resp = requests.get("https://api.github.com/repos/"\
            "%(owner)s/%(repo)s/issues?state=open" % {
                'owner': owner, 'repo': repo}, **kwargs)
        if resp.status_code != 200:
            sys.stderr.write("error: %s" % str(resp.json()))
            return
        for issue in resp.json():
            number = issue['number']
            milestone = ""
            milestone_data = issue.get('milestone')
            if milestone_data:
                milestone = milestone_data.get('title', "")
            title = issue.get('title', "")
            url = issue.get('url', "")
            print("%s,%s,%s,%s,%s,%s" % (
                owner, repo, number, title, milestone, url))


def main(input_args):
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--config', action='store',
        default=os.path.join(os.getenv('HOME'), '.dws', 'dissues'),
        help='configuration file')
    parser.add_argument(
        '--user', action='store',
        default=None,
        help='user to authenticate with')
    parser.add_argument(
        '--password', action='store',
        default=None,
        help='password to authenticate with')
    parser.add_argument(
        'repo_names', nargs='*',
        help='repo_name')
    args = parser.parse_args(input_args[1:])
    config = configparser.ConfigParser()
    params = config.read(args.config)
    user = None
    password = None
    repos = []
    logging.info("read configuration from %s", args.config)
    for section in config.sections():
        logging.debug("[%s]", section)
        for key, val in config.items(section):
            logging.debug("%s = %s", key, val)
            if key == 'repos':
                repos = val.split()
            elif key == 'user':
                user = val
            elif key == 'password':
                password = val
    if args.user and args.password:
        user = args.user
        password = args.password
    if args.repo_names:
        repos = args.repo_names
    download(repos, user=user, password=password)

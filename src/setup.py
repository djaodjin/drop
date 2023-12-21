# Copyright (c) 2023, DjaoDjin inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from distutils.core import setup

import tero

setup(name='drop',
    version=tero.__version__,
    author='DjaoDjin inc.',
    author_email='support@djaodjin.com',
    packages=[
        'tero',
        'tero.setup',
        'tero.clouds'
    ],
    package_data={
        'tero.setup': [
            '*.tpl'
        ],
        'tero.clouds': [
            'templates/*.j2'
        ]
    },
    scripts=[
        # Scripts on developper machine build packages and run tests
        'scripts/dbldpkg',
        'scripts/dstamp',
        'scripts/dtimeout',
        # Scripts installed on machines to manage operations
        'scripts/dauthcmd',
        'scripts/dcopylogs',
        'scripts/dlogwatch',
        # Scripts to configure cloud infrastructure and OS distributions
        'scripts/dcloud',
        'scripts/dservices',
        'scripts/dsettings',
        # Scripts to monitor development work and operations
        'scripts/dintegrity',
        'scripts/dmonitor',
        'scripts/dregress',
        'scripts/dissues'
    ],
    url='https://github.com/djaodjin/drop/',
    download_url='https://github.com/djaodjin/drop/tarball/%s' \
        % tero.__version__,
    license='BSD',
    description='DjaoDjin workspace management',
    long_description=open('../README.md').read(),
)

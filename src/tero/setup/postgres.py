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

from tero.setup import after_daemon_start, postinst, SetupTemplate
from tero.setup.cron import add_entry as cron_add_entry


class postgresql_serverSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(postgresql_serverSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['postgresql']

    def run(self, context):
        complete = super(postgresql_serverSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        postinst.shellCommand(['[ -d /var/lib/pgsql/data/base ] ||',
            '/usr/bin/postgresql-setup', 'initdb'])

        return complete


class postgresqlSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(postgresqlSetup, self).__init__(name, files, **kwargs)

    def create_database(self, db_name, db_user, db_password, context):
        after_daemon_start('postgresql',
          'psql -e "CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8;"'
                           % db_name)
        after_daemon_start('postgresql',
    'psql -e "GRANT ALL ON %s.* TO \'%s\'@\'localhost\' IDENTIFIED BY \'%s\'"'
             % (db_name, db_user, db_password))
        cron_add_entry('pg_backup_%(db_name)s' % {'db_name': db_name},
'pg_dump -U postgres -C -f /var/db/pgsql/backups/%(db_name)s.sql %(db_name)s'\
' && chmod 600 /var/db/pgsql/backups/%(db_name)s.sql' % {'db_name': db_name},
        context=context)

    def run(self, context):
        complete = super(postgresqlSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete
        files = self.managed.get('postgresql', {}).get('files', {})
        for name, vals in files.iteritems():
            if name == 'databases':
                db_name = None
                for elem in vals:
                    settings = elem[0]
                    if 'db_name' in settings:
                        db_name = settings['db_name']
                self.create_database(
                    db_name, context.DB_USER, context.DB_PASSWORD, context)
        return complete

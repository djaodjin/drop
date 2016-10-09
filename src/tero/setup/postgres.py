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

import argparse, getpass, re, os, socket, sys

from tero import Context, Variable
from tero.setup import (after_daemon_start, modify_config, postinst, stageFile,
    SetupTemplate)
from tero.setup.local import add_context_variables
from tero.setup.cron import add_entry as cron_add_entry


class postgresql_serverSetup(SetupTemplate):

    backup_script = [
        "sudo -u postgres psql -U postgres -qAt -c 'select datname from"\
        " pg_database where datallowconn' | xargs -r -I X sudo -u postgres"\
        " pg_dump -U postgres -C -f /var/backups/X.sql X",
        "chmod 600 /var/backups/*.sql"]

    def __init__(self, name, files, **kwargs):
        super(postgresql_serverSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['postgresql']

    def create_cron_conf(self, context):
        """
        Create a cron job to backup the database to a flat text file.
        """
        _, new_conf_path = stageFile(os.path.join(
            context.value('etcDir'), 'cron.daily', 'pg_backup'), context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write("""#!/bin/sh

%(backup_script)s
""" % {'backup_script': '\n'.join(self.backup_script)})

    def create_logrotate_conf(self, context):
        """
        Rotate flat file backups.
        """
        _, new_conf_path = stageFile(os.path.join(
            context.value('etcDir'), 'logrotate.d', 'pg_backup'), context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write("""/var/backups/*.sql
{
    create 0600 root root
    daily
    rotate 7
    missingok
    notifempty
    compress
    sharedscripts
    postrotate
        %(backup_script)s
    endscript
}
""" % {'backup_script': '\n        '.join(self.backup_script)})

    def run(self, context):
        complete = super(postgresql_serverSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        pg_user = context.value('dbUser')
        vpc_cidr = context.value('vpc_cidr')
        postgresql_conf = '/var/lib/pgsql/data/postgresql.conf'
        pg_ident_conf = '/var/lib/pgsql/data/pg_ident.conf'
        pg_ident_conf = '/var/lib/pgsql/data/pg_ident.conf'
        pg_hba_conf = '/var/lib/pgsql/data/pg_hba.conf'

        listen_addresses = "'localhost'"
        for key, val in self.managed['postgresql-server']['files'].iteritems():
            if key == 'listen_addresses':
                listen_addresses = "'%s'" % val

        modify_config(postgresql_conf,
            settings={'listen_addresses': listen_addresses},
            sep=' = ', context=context)

        # pg_ident
        system_to_pg_mapping = {
            'postgres': 'postgres',
            '/^(.*)$': pg_user
        }
        old_conf_path, new_conf_path = stageFile(pg_ident_conf, context)
        with open(new_conf_path, 'w') as new_conf:
            with open(old_conf_path) as old_conf:
                for line in old_conf.readlines():
                    look = re.match(r'^mymap\s+(\S+)\s+(\S+)', line.strip())
                    if look:
                        system_user = look.group(1)
                        if system_user in system_to_pg_mapping:
                            new_conf.write(
                                '%(map)s%(system_user)s%(pg_user)s\n' % {
                                    'map': 'mymap'.ljust(16),
                                    'system_user': system_user.ljust(24),
                        'pg_user': system_to_pg_mapping[system_user].ljust(16)})
                    else:
                        new_conf.write(line)

        # pg_hba
        connections = [['postgres', 'postgres', vpc_cidr],
                       ['all', pg_user, vpc_cidr]]
        old_conf_path, new_conf_path = stageFile(pg_hba_conf, context)
        with open(new_conf_path, 'w') as new_conf:
            with open(old_conf_path) as old_conf:
                for line in old_conf.readlines():
                    look = re.match(r'^local.*peer$', line.strip())
                    if look:
                        new_conf.write(line.strip() + ' map=mymap\n')
                    else:
                        look = re.match(
r'^host\s+(?P<db>\S+)\s+(?P<pg_user>\S+)\s+(?P<cidr>\S+)\s+(?P<method>\S+)',
                            line.strip())
                        if look:
                            found = None
                            remains = []
                            for conn in connections:
                                if (conn[0] == look.group('db')
                                    and conn[1] == look.group('pg_user')):
                                    found = conn
                                else:
                                    remains += [conn]
                            connections = remains
                            if found:
                                new_conf.write(
                                'host    %(db)s%(pg_user)s%(cidr)smd5\n' % {
                                    'db': found[0].ljust(16),
                                    'pg_user': found[1].ljust(16),
                                    'cidr': found[2].ljust(16)})
                            else:
                                new_conf.write(line)
                        else:
                            new_conf.write(line)
                if len(connections) > 0:
                    new_conf.write("# Remote connections\n")
                    for conn in connections:
                        new_conf.write(
                        'host    %(db)s%(pg_user)s%(cidr)smd5\n' % {
                            'db': conn[0].ljust(16),
                            'pg_user': conn[1].ljust(16),
                            'cidr': conn[2].ljust(16)})

        self.create_cron_conf(context)
        postinst.shellCommand(['[ -d /var/lib/pgsql/data/base ] ||',
            '/usr/bin/postgresql-setup', 'initdb'])

        return complete


class postgresqlSetup(SetupTemplate):

    def __init__(self, name, files, **kwargs):
        super(postgresqlSetup, self).__init__(name, files, **kwargs)

    @staticmethod
    def create_database(db_name, db_user, db_password, context):
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
                self.create_database(db_name,
                    context.value('dbUser'), context.value('dbPassword'),
                    context)
        return complete


def main(args):
    import tero
    parser = argparse.ArgumentParser(usage='%(prog)s [options]')
    parser.add_argument('-D', dest='defines', action='append', default=[],
                      help='Add a (key,value) definition to use in templates.')
    options = parser.parse_args(args[1:])
    defines = dict([item.split('=') for item in options.defines])

    tero.CONTEXT = Context()
    add_context_variables(tero.CONTEXT)
    tero.CONTEXT.environ['vpc_cidr'] = Variable('vpc_cidr',
             {'description': 'CIDR allowed to create remote connections',
              'default': defines.get('vpc_cidr', '192.168.144.0/24')})
    for define in options.defines:
        key, value = define.split('=')
        tero.CONTEXT.environ[key] = value

    tero.CONTEXT.locate()

    setup = postgresql_serverSetup('postgresql-server', {})
    setup.run(tero.CONTEXT)


if __name__ == '__main__':
    sys.exit(main(sys.argv))

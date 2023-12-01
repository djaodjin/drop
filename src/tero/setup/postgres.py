# Copyright (c) 2023, DjaoDjin inc.
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
from __future__ import unicode_literals

import argparse, logging, re, os, subprocess, sys

import six

import tero
from .. import Variable, shell_command
from . import (after_daemon_start, modify_config, postinst, stage_file,
    SetupTemplate)
from .cron import add_entry as cron_add_entry


class postgresql_serverSetup(SetupTemplate):

    pgdata = '/var/lib/pgsql/data'
    postgresql_setup = '/usr/bin/postgresql-setup'
    pg_dump = '/usr/bin/pg_dump'
    daemons = ['postgresql']

    def __init__(self, name, files, **kwargs):
        super(postgresql_serverSetup, self).__init__(name, files, **kwargs)

    def backup_script(self, context):
        return [
        "#!/bin/sh",
        "",
        "LOG_SUFFIX=`curl -s "\
        " http://instance-data/latest/meta-data/instance-id | sed -e s/i-/-/`",

        "sudo -u postgres sh -c 'rm /var/migrate/pgsql/dumps/*.gz'",

        "sudo -u postgres psql -U postgres -qAt -c 'select datname from"\
        " pg_database where datallowconn' | xargs -r -I X sudo -u postgres"\
        " %(pg_dump)s -U postgres -C -f /var/backups/pgsql/X.sql$LOG_SUFFIX X" %
            {'pg_dump': self.pg_dump},

        "chmod 600 /var/backups/pgsql/*.sql",

    'sudo -u postgres sh -c "gzip /var/migrate/pgsql/dumps/*.sql$LOG_SUFFIX"',

        "sudo -u postgres /usr/bin/aws s3 cp --quiet --recursive --sse AES256"\
        " /var/migrate/pgsql/dumps/"\
        " s3://%(s3_logs_bucket)s/var/migrate/pgsql/dumps/" % {
        's3_logs_bucket': context.value('logsBucket')
    }]

    def create_cron_conf(self, context):
        """
        Create a cron job to backup the database to a flat text file.
        """
        _, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'cron.daily', 'pg_backup'), context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write("\n".join(self.backup_script(context)))

    def create_logrotate_conf(self, context):
        """
        Rotate flat file backups.
        """
        _, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'logrotate.d', 'pg_backup'), context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write("""/var/backups/pgsql/*.sql
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

    @staticmethod
    def write_ident_line(fileobj, system_user, pg_user):
        fileobj.write('%(map)s%(system_user)s%(pg_user)s\n' % {
            'map': 'mymap'.ljust(16),
            'system_user': system_user.ljust(24),
            'pg_user': pg_user.ljust(16)})

    @staticmethod
    def restore(filename, drop_if_exists=True):
        """
        Restore a PostgresQL database from file.
        """
        if drop_if_exists:
            db_name = os.path.basename(filename).split('.')[0]
            cmd = ['sudo', '-u', 'postgres', 'psql', '-c',
                'DROP DATABASE IF EXISTS %s;' % db_name]
            sys.stdout.write("%s\n" % ' '.join(cmd))
            subprocess.check_call(cmd)
        if filename.endswith('.gz'):
            cmd = ['sh', '-c',
            "sudo -u postgres gunzip -c %s | sudo -u postgres psql" % filename]
        else:
            cmd = ['sudo', '-u', 'postgres', 'psql', '-f', filename]
        sys.stdout.write("%s\n" % ' '.join(cmd))
        subprocess.check_call(cmd)

    def run(self, context):
        complete = super(postgresql_serverSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        db_host = context.value('dbHost')
        vpc_cidr = context.value('vpc_cidr')
        pg_user = context.value('dbUser')
        postgresql_conf = os.path.join(self.pgdata, 'postgresql.conf')
        pg_ident_conf = os.path.join(self.pgdata, 'pg_ident.conf')
        pg_hba_conf = os.path.join(self.pgdata, 'pg_hba.conf')

        if not os.path.exists(postgresql_conf):
            # /var/lib/pgsql/data will be empty unless we run initdb once.
            shell_command([self.postgresql_setup, 'initdb'])

        listen_addresses = "'localhost'"
        for key, val in six.iteritems(self.managed[
                '%s-server' % self.daemons[0].replace('-', '')]['files']):
            if key == 'listen_addresses':
                listen_addresses = ', '.join(
                    ["'%s'" % address[0] for address in val])

        postgresql_conf_settings = {'listen_addresses': listen_addresses}
        if db_host:
            db_ssl_key_file = "/etc/pki/tls/private/%s.key" % db_host
            db_ssl_cert_file = "/etc/pki/tls/certs/%s.crt" % db_host
            dh_params = "/etc/ssl/certs/dhparam.pem"
            if (os.path.exists(db_ssl_key_file) and
                os.path.exists(db_ssl_cert_file)):
                postgresql_conf_settings.update({
                    'ssl': "on",
                    'ssl_cert_file': "'%s'" % db_ssl_cert_file,
                    'ssl_key_file': "'%s'" % db_ssl_key_file,
                    'ssl_prefer_server_ciphers': "on",
                #ssl_ca_file = ''
                #ssl_crl_file = ''
                #ssl_ecdh_curve = 'prime256v1'
                #ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL' # allowed SSL ciphers
                })
                if os.path.exists(dh_params):
                    postgresql_conf_settings.update({
                        'ssl_dh_params_file': "'%s'" % dh_params,
                    })
                postinst.shell_command([
                    'chown', 'root:postgres', db_ssl_key_file])
                postinst.shell_command([
                    'chmod', '640', db_ssl_key_file])
                postinst.shell_command([
                    'chmod', '755', os.path.dirname(db_ssl_key_file)])
        modify_config(postgresql_conf,
            settings=postgresql_conf_settings,
            sep=' = ', context=context)

        # pg_ident
        system_to_pg_mapping = {'postgres': 'postgres'}
        if pg_user:
            system_to_pg_mapping.update({'/^(.*)$': pg_user})
        else:
            logging.warning("dbUser is '%s'. No regular user will be created"\
                " to access the database remotely.")
        old_conf_path, new_conf_path = stage_file(pg_ident_conf, context)
        with open(new_conf_path, 'w') as new_conf:
            with open(old_conf_path) as old_conf:
                for line in old_conf.readlines():
                    look = re.match(r'^mymap\s+(\S+)\s+(\S+)', line.strip())
                    if look:
                        system_user = look.group(1)
                        if system_user in system_to_pg_mapping:
                            self.write_ident_line(new_conf, system_user,
                                system_to_pg_mapping[system_user])
                            del system_to_pg_mapping[system_user]
                    else:
                        new_conf.write(line)
                for system_user, pgident_user in six.iteritems(
                        system_to_pg_mapping):
                    self.write_ident_line(new_conf, system_user, pgident_user)

        # pg_hba
        connections = [['all', 'postgres', vpc_cidr],
                       # 'all' because we need to add a constraint on auth_user
                       ['all', pg_user, vpc_cidr]]
        old_conf_path, new_conf_path = stage_file(pg_hba_conf, context)
        with open(new_conf_path, 'w') as new_conf:
            with open(old_conf_path) as old_conf:
                source_host = 'host'
                if (postgresql_conf_settings.get('ssl') and
                    postgresql_conf_settings.get('ssl') == "on"):
                    source_host = 'hostssl'
                for line in old_conf.readlines():
                    look = re.match(r'^local.*peer$', line.strip())
                    if look:
                        new_conf.write(line.strip() + ' map=mymap\n')
                    else:
                        look = re.match(r'^(host|hostssl|hostnossl)\s+'\
r'(?P<db>\S+)\s+(?P<pg_user>\S+)\s+(?P<cidr>\S+)\s+(?P<method>\S+)',
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
                                '%(host)s    %(db)s%(pg_user)s%(cidr)smd5\n' % {
                                    'host': source_host.ljust(10),
                                    'db': found[0].ljust(16),
                                    'pg_user': found[1].ljust(16),
                                    'cidr': found[2].ljust(24)})
                            else:
                                new_conf.write(line)
                        else:
                            new_conf.write(line)
                if connections:
                    new_conf.write("# Remote connections\n")
                    for conn in connections:
                        new_conf.write(
                        '%(host)s    %(db)s%(pg_user)s%(cidr)smd5\n' % {
                            'host': source_host.ljust(10),
                            'db': conn[0].ljust(16),
                            'pg_user': conn[1].ljust(16),
                            'cidr': conn[2].ljust(24)})

        self.create_cron_conf(context)
        #XXX optimizations?
        #https://people.planetpostgresql.org/devrim/index.php?/archives/\
        #83-Using-huge-pages-on-RHEL-7-and-PostgreSQL-9.4.html
        postinst.shell_command(['[ -d %(pgdata)s/base ] ||' % {
            'pgdata': self.pgdata }, self.postgresql_setup, 'initdb'])

        return complete


class postgresql14_serverSetup(postgresql_serverSetup):

    pgdata = '/var/lib/pgsql/14/data'
    postgresql_setup = '/usr/pgsql-14/bin/postgresql-14-setup'
    pg_dump = '/usr/pgsql-14/bin/pg_dump'
    daemons = ['postgresql-14']


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
'pg_dump -U postgres -C -f /var/backups/pgsql/%(db_name)s.sql %(db_name)s'\
' && chmod 600 /var/backups/pgsql/%(db_name)s.sql' % {'db_name': db_name},
        context=context)

    def run(self, context):
        complete = super(postgresqlSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete
        files = self.managed.get('postgresql', {}).get('files', {})
        for name, vals in six.iteritems(files):
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
    parser = argparse.ArgumentParser(usage='%(prog)s [options]')
    parser.add_argument('-D', dest='defines', action='append', default=[],
                      help='Add a (key,value) definition to use in templates.')
    options = parser.parse_args(args[1:])
    defines = dict([item.split('=') for item in options.defines])

    tero.CONTEXT = tero.Context()
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

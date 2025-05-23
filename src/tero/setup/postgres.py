# Copyright (c) 2024, DjaoDjin inc.
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
from tero.setup import (after_daemon_start, modify_config, postinst, stage_file,
    SetupTemplate)
from tero.setup.cron import add_entry as cron_add_entry


class postgresql_serverSetup(SetupTemplate):

    pgdata_candidates = ['/var/lib/pgsql/data']
    postgresql_setup_candidates = ['/usr/bin/postgresql-setup']
    pg_dump_candidates = ['/usr/bin/pg_dump']
    service_candidates = ['/usr/lib/systemd/system/postgresql.service']

    def __init__(self, name, files, **kwargs):
        super(postgresql_serverSetup, self).__init__(name, files, **kwargs)

    @property
    def daemons(self):
        if not hasattr(self, '_daemons'):
            service = self.locate_config('service', self.service_candidates)
            self._daemons = [os.path.splitext(os.path.basename(service))[0]]
        return self._daemons

    def backup_script(self, context):
        pg_dump = self.locate_config('pg_dump', self.pg_dump_candidates)
        return [
        "#!/bin/sh",
        "",
        "cd /var/migrate/pgsql",
        "# IMDSv2",
        'TOKEN=`curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`',
        'LOG_SUFFIX=`curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id | sed -e s/i-/-/`',

        "sudo -u postgres sh -c 'rm /var/migrate/pgsql/dumps/*.gz'",

        "sudo -u postgres psql -U postgres -qAt -c 'select datname from"\
        " pg_database where datallowconn' | xargs -r -I X sudo -u postgres"\
        " %(pg_dump)s -U postgres -C -f /var/migrate/pgsql/dumps/X.sql$LOG_SUFFIX X" %
            {'pg_dump': pg_dump},

        "chmod 600 /var/migrate/pgsql/dumps/*.sql$LOG_SUFFIX",

    'sudo -u postgres sh -c "gzip /var/migrate/pgsql/dumps/*.sql$LOG_SUFFIX"',

        "sudo -u postgres /usr/bin/aws s3 cp --quiet --recursive --sse AES256"\
        " /var/migrate/pgsql/dumps/"\
        " s3://%(s3_logs_bucket)s/var/migrate/pgsql/dumps/" % {
        's3_logs_bucket': context.value('logsBucket')},
        ""]

    @staticmethod
    def locate_config(name, candidates):
        found = None
        for candidate in candidates:
            if os.path.exists(candidate):
                found = candidate
                break
        if not found:
            raise RuntimeError("couldn't locate %s in %s!" % (name, candidates))
        return found


    def create_cron_conf(self, context):
        """
        Create a cron job to backup the database to a flat text file.
        """
        _, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'cron.daily', 'pg_backup'), context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write("\n".join(self.backup_script(context)))
        postinst.shell_command(['chmod', '755', new_conf_path])


    def create_logrotate_conf(self, context):
        """
        Rotate flat file backups.
        """
        _, new_conf_path = stage_file(os.path.join(
            context.value('etcDir'), 'logrotate.d', 'pg_backup'), context)
        with open(new_conf_path, 'w') as new_conf:
            new_conf.write("""/var/migrate/pgsql/dumps/*.sql
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
        pgdata = self.locate_config('pgdata', self.pgdata_candidates)
        postgresql_conf = os.path.join(pgdata, 'postgresql.conf')
        pg_ident_conf = os.path.join(pgdata, 'pg_ident.conf')
        pg_hba_conf = os.path.join(pgdata, 'pg_hba.conf')

        postgresql_setup = self.locate_config(
            'postgresql_setup', self.postgresql_setup_candidates)
        if not os.path.exists(postgresql_conf):
            # /var/lib/pgsql/data will be empty unless we run initdb once.
            tero.shell_command(
                [postgresql_setup, '--initdb', '--unit', 'postgresql'])

        listen_addresses = "'localhost'"
        name = self.__class__.__name__[:-len('Setup')].replace('_', '-')
        for key, val in six.iteritems(self.managed[name]['files']):
            if key == 'listen_addresses':
                listen_addresses = ', '.join(
                    ["'%s'" % address[0] for address in val])

        postgresql_conf_settings = {'listen_addresses': listen_addresses}
        if db_host:
            db_ssl_key_file = "/etc/pki/tls/private/%s.key" % db_host
            db_ssl_cert_file = "/etc/pki/tls/certs/%s.crt" % db_host
            dh_params = "/etc/ssl/certs/dhparam.pem"
            # (15.12) The psql client cannot connect to the server
            # if we use a ecdsa certificate.
            postinst.create_certificate(db_host,
                company_domain=context.value('companyDomain'), prev_rsa=True)
            postgresql_conf_settings.update({
                'ssl': "on",
                'ssl_cert_file': "'%s'" % db_ssl_cert_file,
                'ssl_key_file': "'%s'" % db_ssl_key_file,
                'ssl_prefer_server_ciphers': "on",
                #ssl_ca_file = ''
                #ssl_crl_file = ''
                #ssl_ecdh_curve = 'prime256v1'
                #ssl_ciphers = 'HIGH:MEDIUM:+3DES:!aNULL' # allowed SSL ciphers
                # performance monitoring
                'compute_query_id': "auto",
                'pg_stat_statements.track': "all",
                'pg_stat_statements.max': "10000",
                'track_activity_query_size': "2048",
                'shared_preload_libraries': "'pg_stat_statements'"
            })
            if os.path.exists(dh_params):
                postgresql_conf_settings.update({
                    'ssl_dh_params_file': "'%s'" % dh_params,
                })
            postinst.shell_command(['chown', 'root:postgres', db_ssl_key_file])
            postinst.shell_command(['chmod', '640', db_ssl_key_file])
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
                                '%(host)s %(db)s%(pg_user)s%(cidr)smd5\n' % {
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
            'pgdata': pgdata}, postgresql_setup, 'initdb'])

        return complete


class postgresql14_serverSetup(postgresql_serverSetup):

    pgdata_candidates = ['/var/lib/pgsql/14/data', '/var/lib/pgsql/data']
    postgresql_setup_candidates = [
        '/usr/pgsql-14/bin/postgresql-14-setup', '/usr/bin/postgresql-setup']
    pg_dump_candidates = ['/usr/pgsql-14/bin/pg_dump', ]
    service_candidates = ['/usr/lib/systemd/system/postgresql-14.service',
        '/usr/lib/systemd/system/postgresql.service']


class postgresql15_serverSetup(postgresql_serverSetup):

    pgdata_candidates = ['/var/lib/pgsql/15/data', '/var/lib/pgsql/data']
    postgresql_setup_candidates = [
        '/usr/pgsql-15/bin/postgresql-15-setup', '/usr/bin/postgresql-setup']
    pg_dump_candidates = ['/usr/pgsql-15/bin/pg_dump', '/usr/bin/pg_dump']
    service_candidates = ['/usr/lib/systemd/system/postgresql-15.service',
        '/usr/lib/systemd/system/postgresql.service']


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
'pg_dump -U postgres -C -f /var/migrate/pgsql/dumps/%(db_name)s.sql %(db_name)s'\
' && chmod 600 /var/migrate/pgsql/dumps/%(db_name)s.sql' % {'db_name': db_name},
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
    tero.CONTEXT.environ['vpc_cidr'] = tero.Variable('vpc_cidr',
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

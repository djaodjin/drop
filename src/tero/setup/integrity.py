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

import getpass, json, logging, os, pwd, re, socket, subprocess, sys

import sqlparse
from sqlparse import sql, tokens

import tero, tero.dstamp


def _load_sqlschema(schema_text):
    tables = {}
    statements = sqlparse.parse(schema_text)
    for statement in statements:
        statement_tokens = statement.tokens # XXX list(statement.flatten())
        # CREATE
        token = statement_tokens.pop(0) if statement_tokens else None
        while token and not token.match(tokens.Keyword.DDL, values=('CREATE',)):
            token = statement_tokens.pop(0) if statement_tokens else None
        if not token:
            continue

        # TABLE
        token = statement_tokens.pop(0) if statement_tokens else None
        while token and not token.match(tokens.Keyword, values=('TABLE',)):
            token = statement_tokens.pop(0) if statement_tokens else None
        if not token:
            continue

        # identifier
        token = statement_tokens.pop(0) if statement_tokens else None
        while token and not isinstance(token, sql.Identifier):
            token = statement_tokens.pop(0) if statement_tokens else None
        if not token:
            continue
        table_identifier = token.value

        # fields
        tables[table_identifier] = {}
        logging.warning("CREATE TABLE %s", table_identifier)
        token = statement_tokens.pop(0) if statement_tokens else None
        while token and not isinstance(token, sql.Parenthesis):
            token = statement_tokens.pop(0) if statement_tokens else None
        if not token:
            continue
        field_tokens = list(token.flatten()) # XXX token.tokens
        while field_tokens:
            field_name = None
            field_type = None
            field_modifier = False
            field_length = None
            field_not_null = False
            # field identifier
            field_token = field_tokens.pop(0) if field_tokens else None
            while field_token and not (
                    field_token.match(tokens.Name, values=None) or
                    field_token.match(tokens.Name.Builtin, values=None) or
                    field_token.match(tokens.String.Symbol, values=None) or
                    field_token.match(tokens.Keyword, values=None)):
                field_token = field_tokens.pop(0) if field_tokens else None
            if field_token.match(tokens.Keyword, values=('CONSTRAINT',)):
                indent = 0
                while field_token:
                    if field_token.match(tokens.Punctuation, values=('(',)):
                        indent += 1
                    elif field_token.match(tokens.Punctuation, values=(')',)):
                        indent -= 1
                    elif (field_token.match(tokens.Punctuation, values=(',',))
                          and not indent):
                        break
                    field_token = field_tokens.pop(0) if field_tokens else None
                if field_token:
                    continue
            if not field_token:
                continue
            field_name = field_token.value.strip('"')
            # field type
            field_token = field_tokens.pop(0) if field_tokens else None
            while field_token and not (
                    field_token.match(tokens.Name.Builtin, values=None) or
                    field_token.match(tokens.Keyword, values=None)):
                field_token = field_tokens.pop(0) if field_tokens else None
            if not field_token:
                continue
            field_type = field_token
            # `character` is followed by `varying`
            field_token = field_tokens.pop(0) if field_tokens else None
            while field_token:
                if field_token.match(tokens.Name, values=('varying',)):
                    while field_token and not (field_token.match(
                        tokens.Token.Literal.Number.Integer, values=None)):
                        field_token = (
                            field_tokens.pop(0) if field_tokens else None)
                    field_length = int(field_token.value)
                    field_token = field_tokens.pop(0) if field_tokens else None
                elif field_token.match(tokens.Keyword.CTE, values=('WITH',)):
                    field_modifier = True
                    field_token = field_tokens.pop(0) if field_tokens else None
                elif field_token.match(tokens.Keyword, values=('NOT NULL',)):
                    field_not_null = True
                    field_token = field_tokens.pop(0) if field_tokens else None
                elif field_token.match(tokens.Punctuation, values=(',',)):
                    break
                else:
                    field_token = field_tokens.pop(0) if field_tokens else None

            tables[table_identifier][field_name] = {
                'type': field_type.value,
                'required': field_not_null
            }
            if field_modifier:
                tables[table_identifier][field_name].update({
                    'timezone': True
                })
            if field_length:
                tables[table_identifier][field_name].update({
                    'length': field_length
                })
            logging.warning('- "%s" %s%s%s%s',
                field_name,
                field_type,
                " WITH XXX" if field_modifier else "",
                " varying(%d)" % field_length if field_length else "",
                " NOT NULL" if field_not_null else "")
    return tables


def check_apps(reference_prerequisites=None, root_dir='/var/www',
               write_to_file=False):
    """
    Check versions of apps currently running on the machine.
    """
    apps = find_apps(root_dir)

    checked = True
    for app_name, app_snap in apps.items():
        app_prerequisites = app_snap['dependencies']
        if write_to_file:
            app_schema_path = '%s-prerequisites.json' % app_name
            logging.warning("saving prerequisites for %s to %s ...",
                app_name, app_schema_path)
            with open(app_schema_path, 'w') as schema_file:
                schema_file.write(json.dumps(app_prerequisites, indent=2))
        print("App %s:" % str(app_name))
        if not reference_prerequisites:
            continue
        added_prerequisites = (
            set(app_prerequisites) - set(reference_prerequisites))
        removed_prerequisites = (
            set(reference_prerequisites) - set(app_prerequisites))
        if added_prerequisites:
            checked = False
            print("The following prerequisites were added to the reference:")
            for prerequisite in sorted(added_prerequisites):
                print("- %s==%s" % (
                    prerequisite, app_prerequisites[prerequisite]))
        if removed_prerequisites:
            checked = False
            print(
                "The following prerequisites were removed from the reference:")
            for prerequisite in sorted(removed_prerequisites):
                print("- %s==%s" % (
                    prerequisite, reference_prerequisites[prerequisite]))
        first_time = True
        for prerequisite in sorted(
                set(app_prerequisites) & set(reference_prerequisites)):
            if (app_prerequisites[prerequisite] !=
                reference_prerequisites[prerequisite]):
                checked = False
                if first_time:
                    print("The following prerequisites were changed:")
                    first_time = False
                print("- %s version %s, expected version %s" % (
                    prerequisite, app_prerequisites[prerequisite],
                    reference_prerequisites[prerequisite]))
    return checked


def check_permissions(paths, owner, group, mode):
    for path in paths:
        stat = os.stat(path)
        if stat.st_uid != owner:
            sys.stderr.write('onwer mismatch: ' + path + '\n')
        if stat.st_gid != group:
            sys.stderr.write('group mismatch: ' + path + '\n')
        if stat.st_mode != mode:
            sys.stderr.write('mode mismatch: ' + path + '\n')


def check_systemd_services():
    services = []
    output_lines = tero.shell_command(
        '/usr/bin/systemctl list-unit-files', pat=r'.*')
    for line in output_lines:
        look = re.match(r'(.*)\.service\S+enabled', line)
        if look:
            services += [look.group(1)]
    return services


def check_sqlschema(schema_text, reference_schema=None):
    """
    Analyze a SQL schema that was dumped with `pg_dump --schema-only`
    """
    schema = _load_sqlschema(schema_text)
    if not reference_schema:
        logging.warning("There are no reference schema to compare against.")
        reference_schema = schema
    added_tables = (set(schema) - set(reference_schema))
    removed_tables = (set(reference_schema) - set(schema))
    if added_tables:
        print("The following tables were added to the reference schema:")
        for table in sorted(added_tables):
            print("- %s" % table)
        print("")
    if removed_tables:
        print("The following tables were removed from the reference schema:")
        for table in sorted(removed_tables):
            print("- %s" % table)
        print("")
    for table in sorted(set(schema) & set(reference_schema)):
        added_fields = (set(schema[table]) - set(reference_schema[table]))
        removed_fields = (set(reference_schema[table]) - set(schema[table]))
        altered = []
        for field in sorted(set(schema[table]) & set(reference_schema[table])):
            if (schema[table][field]['type'] !=
                reference_schema[table][field]['type']):
                if (schema[table][field]['type'] in ('integer', 'bigint') and
                    reference_schema[table][field]['type'] == 'serial'):
                    # pg_dump14 will mark as 'id' as integer and
                    # add a `CREATE SEQUENCE` statement.
                    pass
                else:
                    altered += ['"%s" type was altered from %s to %s' % (
                        field,
                        reference_schema[table][field]['type'],
                        schema[table][field]['type'])]
            elif (schema[table][field].get('length', 0) !=
                  reference_schema[table][field].get('length', 0)):
                altered += ['"%s" length was altered from %d to %d' % (
                    field,
                    reference_schema[table][field].get('length', 0),
                    schema[table][field].get('length', 0))]
            if (schema[table][field]['required'] !=
                reference_schema[table][field]['required']):
                altered += ['"%s" was altered from %s to %s' % (
                    field, ("NOT NULL"\
                    if reference_schema[table][field]['required'] else "NULL"),
                    "NOT NULL" if schema[table][field]['required'] else "NULL")]
        if added_fields or removed_fields or altered:
            print('Table "%s" was altered:' % table)
            if added_fields:
                print('\tThe following fields were added:')
                for field in sorted(added_fields):
                    print("\t- %s%s" % (field, ("  NOT NULL"\
                        if schema[table][field]['required'] else "")))
            if removed_fields:
                print('\tThe following fields were removed:')
                for field in sorted(removed_fields):
                    print("\t- %s" % field)
            if altered:
                print('\tThe following fields were altered:')
                for field in altered:
                    print("\t- %s" % field)
            print('')


def create_archives(backup_dir, backup_tops):
    '''Create an archive out of each backup_top.'''
    os.chdir(backup_dir)
    for backup_top in backup_tops:
        basename = os.path.basename(backup_top)
        archive = tero.stampfile(basename)
        tero.shell_command(['tar', '--bzip2', '-cf', archive,
                          '-C', os.path.dirname(backup_top),
                          '--exclude', 'build/',
                          basename])
    tero.dstamp.cleanup_aged_files(backup_dir)


def fingerprint_fs(context, log_path_prefix, exclude_tops=None):
    '''Uses mtree to take a fingerprint of the filesystem and output
       the specification file in "*log_path_prefix*.mtree".
       If an *exclude_tops* file exists, it contains patterns used to skip
       over parts of the filesystem to fingerprint.'''

    if not exclude_tops and os.path.exists(exclude_tops):
        exclude_tops_flags = " -X " + exclude_tops
    else:
        exclude_tops_flags = ""
        tero.shell_command([os.path.join(context.value('binDir'), 'mtree'),
                          ' -c -K sha1digest -p /',
                          exclude_tops_flags,
                          ' > ' + os.path.abspath(log_path_prefix + '.mtree')])

def find_apps(root_dir):
    """
    Find apps installed in *root_dir*
    """
    apps = {}
    for app_name in os.listdir(root_dir):
        python_version = None
        python = os.path.join(root_dir, app_name, 'bin', 'python')
        # find python version
        if os.path.exists(python):
            cmdline = [python, '--version']
            freeze_output = subprocess.check_output(cmdline)
            look = re.match(r'Python ([0-9]+(\.[0-9]+)*)',
                freeze_output.decode('utf-8'))
            if look:
                python_version = look.group(1)
        apps.update({app_name: {
            'owner': pwd.getpwuid(os.stat(
                os.path.join(root_dir, app_name)).st_uid).pw_name,
            'dependencies': {
                'python': python_version,
            }}})
        # find python prerequisites
        pip = os.path.join(root_dir, app_name, 'bin', 'pip')
        if os.path.exists(pip):
            cmdline = [pip, 'freeze']
            output_lines = tero.shell_command(cmdline, pat=r'.*')
            for line in output_lines:
                look = re.match(r'(\S+)==(\S+)', line)
                if look:
                    prerequisite = look.group(1)
                    version = look.group(2)
                    apps[app_name]['dependencies'].update({
                        prerequisite: version})
        # find process PID
        pid_path = os.path.join(
            root_dir, app_name, 'var', 'run', '%s.pid' % app_name)
        if os.path.exists(pid_path):
            with open(pid_path) as pid_file:
                pid = int(pid_file.read())
            apps[app_name].update({'pid': pid})

    return apps


def find_disk_usage(dist_host):
    """
    List information about disk usage
    """
    tero.shell_command(['/usr/bin/df', '-lh', '--total'])


def find_privileged_executables(log_path_prefix):
    '''Look through the filesystem for executables that have the suid bit
       turned on and executables that can be executed as remote commands.'''
    # find suid privileged executables
    suid_results = log_path_prefix + '.suid'
    try:
        tero.shell_command(['/usr/bin/find', '/', '-type f',
                          '\\( -perm -04000 -or -perm -02000 \\) -ls',
                          ' > ' + suid_results])
    except RuntimeError:
        # It is ok to get an exception here. We cannot exclude /dev, etc.
        # when searching from root.
        pass
    # find rcmd executables
    rcmd_results = log_path_prefix + getpass.getuser() + '.rcmd'
    try:
        tero.shell_command(['/usr/bin/find', '/',
                          '| grep -e ".rhosts" -e "hosts.equiv"',
                          ' > ' + rcmd_results])
    except RuntimeError:
        # It is ok to get an exception here. We cannot exclude /dev, etc.
        # when searching from root.
        pass


def find_running_processes(log_path_prefix, dist_host, apps=None):
    """
    List running processes
    """
    app_by_pids = {}
    ps_cmd = ['/bin/ps', '-e', 'u']
    if dist_host.endswith('Darwin'):
        ps_cmd += ['HF']
    output = tero.shell_command(ps_cmd, pat=r'.*', admin=True)
    for line in output:
        #USER      PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
        # START could be a time (hh:mm) or a date (ex:Jun09)
        #pylint:disable=line-too-long
        look = re.match(r'(?P<user>\S+)\s+(?P<pid>\d+)\s+(?P<cpu>\d+\.\d+)\s+(?P<mem>\d+\.\d+)\s+(?P<vsz>\d+)\s+(?P<rss>\d+)\s+(?P<tty>\S+)\s+(?P<stat>\S+)\s+(?P<start>\S+)\s+(?P<time>\d+:\d+)\s+(?P<command>.+)$', line)
        if look:
            user = look.group('user')
            pid = int(look.group('pid'))
            command = look.group('command')
            app_by_pids.update(
                {pid: {'user': user, 'command': command}})

    if apps is None:
        apps = {}

    if apps:
        for app_name, app_snap in apps.items():
            pid = app_snap.get('pid')
            if not pid:
                continue
            app_snap.update(app_by_pids[pid])
            del app_by_pids[pid]

    apps.update(app_by_pids)
    return apps


def find_meminfo(dist_host):
    """
    List information about memory usage
    """
    tero.log_info("cat /proc/meminfo")
    with open('/proc/meminfo') as meminfo_file:
        for line in meminfo_file.readlines():
            sys.stdout.write(line)


def find_open_ports(log_path_prefix, dist_host, apps=None):
    """
    List processes listening on open ports
    """
    app_by_pids = {}
    if dist_host.endswith('Darwin'):
        tero.shell_command(
            ['/usr/sbin/lsof', '-i', '-P'], pat=r'.*', admin=True)
    else:
        output = tero.shell_command(
            ['/bin/netstat', '-n', '-atp'], pat=r'.*', admin=True)
        for line in output:
            # Proto Recv-Q Send-Q LocalAddress ForeignAddress State PID/Program
            #pylint:disable=line-too-long
            look = re.match(r'(?P<proto>\S+)\s+(?P<recvq>\d+)\s+(?P<sendq>\d+)\s+(?P<local_address>((\d+\.\d+\.\d+\.\d+)|([0-9a-f]*:[0-9a-f]*:[0-9a-f]*)):\d+)\s+(?P<foreign_address>((\d+\.\d+\.\d+\.\d+)|([0-9a-f]*:[0-9a-f]*:[0-9a-f]*)):[0-9\*]+)\s+(?P<state>\S+)\s+(?P<pid>\d+)/(?P<program_name>.+)$', line)
            if look:
                pid = int(look.group('pid'))
                local_address = look.group('local_address')
                foreign_address = look.group('foreign_address')
                port = local_address.split(':')[-1]
                app_by_pids.update({pid: {
                    'port': port,
                    'local_address': local_address,
                    'foreign_address': foreign_address
                }})

    # Open ports as listed by nmap
    #XXX tero.shell_command(['nmap', 'localhost'], admin=True)

    if apps is None:
        apps = {}

    if apps:
        for app_name, app_snap in apps.items():
            pid = app_snap.get('pid')
            if not pid:
                continue
            app_snap.update(app_by_pids[pid])
            del app_by_pids[pid]

    apps.update(app_by_pids)

    return apps


def fingerprint(context, log_path_prefix, skip_usage=False,
                skip_filesystem=False, skip_privileged_executables=False,
                skip_apps=False, skip_processes=False, skip_ports=False):
    """
    Record a fingerprint of the running system.
    """
    dist_host = context.value('distHost')
    if not skip_usage:
        find_meminfo(dist_host)
        find_disk_usage(dist_host)
    if not skip_filesystem:
        fingerprint_fs(context, log_path_prefix,
            os.path.join(context.value('etcDir'),
                'excludes-' + socket.gethostname()))
    if not skip_privileged_executables:
        find_privileged_executables(log_path_prefix)
    if not skip_apps:
        apps = find_apps(root_dir='/var/www')
        if not skip_processes:
            apps = find_running_processes(log_path_prefix, dist_host, apps=apps)
        if not skip_ports:
            apps = find_open_ports(log_path_prefix, dist_host, apps=apps)
        print("\napp_name, port, user, owner, python_version, django_version")
        for app_name, app_snap in apps.items():
            try:
                pid = int(app_name)
            except ValueError:
                print("%(app_name)s,%(port)s, %(user)s, %(owner)s,"\
                    " %(python_version)s, %(django_version)s" % {
                    'app_name': app_name,
                    'port': app_snap.get('port'),
                    'user': app_snap.get('user'),
                    'owner': app_snap.get('owner'),
                    'python_version': app_snap.get(
                        'dependencies', {}).get('python'),
                    'django_version': app_snap.get(
                        'dependencies', {}).get('Django'),
                })
#        print("apps=%s" % str(apps))


def pub_check(names, reference=None):
    """
    Run specified checks
    """
    if not names:
        sys.stdout.write("Please choose one of the 'schema' or 'apps' command.")
        return

    reference_schema = None
    command = names.pop(0)
    if command == 'apps':
        if reference:
            logging.warning("loading reference %s ...", reference)
            with open(reference) as schema_file:
                reference_schema = json.loads(schema_file.read())
        check_apps(reference_prerequisites=reference_schema)

    elif command == 'schema':
        if not names:
            names = tero.shell_command(
                ['psql', '-qAt', '-c',
                 "select datname from pg_database where datallowconn"],
                pat=r'.*', admin='postgres')
        if reference:
            logging.warning("loading reference %s ...", reference)
            with open(reference) as schema_file:
                reference_schema = _load_sqlschema(schema_file.read())
        for name in names:
            schema_text = None
            if name and name.endswith('.sql'):
                schema_path = name
                logging.warning("loading %s ...", schema_path)
                with open(schema_path) as schema_file:
                    schema_text = schema_file.read()
            else:
                cmdline = [
                    'sudo', '-u', 'postgres', 'pg_dump', '--schema-only', name]
                logging.warning("loading %s ...", ' '.join(cmdline))
                schema_text = subprocess.check_output(cmdline)
            check_sqlschema(schema_text, reference_schema=reference_schema)


def pub_snap(names):
    """
    Takes a snapshot of running machine
    """
    tero.CONTEXT = tero.Context()
    tero.CONTEXT.locate()
    log_path_prefix = tero.stampfile(tero.CONTEXT.log_path(
            os.path.join(tero.CONTEXT.host(), socket.gethostname())))
    fingerprint(tero.CONTEXT, log_path_prefix, skip_filesystem=True,
                skip_privileged_executables=True,  skip_apps=False)

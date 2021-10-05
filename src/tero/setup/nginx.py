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

import os, re, six

from tero import APT_DISTRIBS, REDHAT_DISTRIBS, setup


class nginxSetup(setup.SetupTemplate):

    proxy_params_template = """
            proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
            proxy_set_header Host               $host;
            proxy_set_header X-Real-IP          $remote_addr;
            proxy_set_header X-Forwarded-Proto  $scheme;

            # proxy_redirect default;
            proxy_redirect off;
"""

    def __init__(self, name, files, **kwargs):
        super(nginxSetup, self).__init__(name, files, **kwargs)
        self.daemons = ['nginx']
        self.configfiles = []

    @staticmethod
    def conf_path(domain, dist_host, sysconfdir='/etc'):
        if dist_host in APT_DISTRIBS:
            return os.path.join(
                sysconfdir, 'nginx', 'sites-available', domain)
        elif dist_host in REDHAT_DISTRIBS:
            return os.path.join(
                sysconfdir, 'nginx', 'conf.d', domain + '.conf')

    def run(self, context):
        complete = super(nginxSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete

        last_webapps = ""
        remove_default_server = False
        _, new_proxy_params = setup.stageFile(os.path.join(
            context.value('etcDir'), 'nginx', 'proxy_params'), context=context)
        with open(new_proxy_params, 'w') as proxy_params_file:
            proxy_params_file.write(self.proxy_params_template)
        for name, vals in six.iteritems(self.managed['nginx']['files']):
            webapps = ""
            if name.startswith('site-config'):
                templates_dir = os.path.dirname(os.path.abspath(__file__))
                domain = None
                for elem in vals:
                    settings = elem[0]
                    if 'domainName' in settings:
                        domain = settings['domainName']
                    webapp_settings = settings.get('webapp', None)
                    if webapp_settings:
                        if not isinstance(webapp_settings, list):
                            webapp_settings = [webapp_settings]
                        with open(os.path.join(templates_dir,
                            'proxy.tpl')) as proxy_template_file:
                            webapp_template = proxy_template_file.read()
                        for webapp in webapp_settings:
                            if 'app_name' not in webapp:
                                webapp.update({
                                    'app_name': domain.split('.')[0]})
                            webapps += webapp_template % webapp
                    port = settings.get('port', '80')
                if port == '443':
                    with open(os.path.join(templates_dir,
                        'https.tpl')) as https_template_file:
                        conf_template = https_template_file.read()
                else:
                    with open(os.path.join(templates_dir,
                        'http.tpl')) as http_template_file:
                        conf_template = http_template_file.read()
                    remove_default_server = True
                self.site_conf(domain, context, conf_template,
                        webapps=webapps)
                if webapps:
                    last_webapps = webapps

        # Remove default server otherwise our config for intermediate nodes
        # with no domain names will be overridden.
        if remove_default_server:
            org_nginx_conf, new_nginx_conf = setup.stageFile(os.path.join(
                context.value('etcDir'), 'nginx', 'nginx.conf'),
                context=context)
            with open(org_nginx_conf) as org_nginx_conf_file:
                with open(new_nginx_conf, 'w') as new_nginx_conf_file:
                    remove = 0
                    for line in org_nginx_conf_file.readlines():
                        look = re.match(r'.*server\s+{', line)
                        if look:
                            remove = 1
                        elif remove > 0:
                            look = re.match('{', line)
                            if look:
                                remove += 1
                            look = re.match('}', line)
                            if look:
                                remove -= 1
                        if remove == 0:
                            new_nginx_conf_file.write(line)

        certs_top = os.path.join(context.value('etcDir'), 'pki', 'tls', 'certs')
        dhparam_path = os.path.join(certs_top, 'dhparam.pem')
        setup.postinst.shellCommand([
            '[', '-f', dhparam_path, ']', '||', '/usr/bin/openssl',
            'dhparam', '-out', dhparam_path, '4096'])
        setup.postinst.shellCommand([
            'setsebool', '-P', 'httpd_can_network_connect', '1'])
        return complete


    def site_conf(self, domain, context, config_template,
                  webapps="", conf_name=None):
        """
        Generate a configuration file for the site.
        """
        app_name = domain.split('.')[0]
        if conf_name is None:
            conf_name = app_name
        document_root = os.path.join(
            os.sep, 'var', 'www', app_name, 'reps', app_name, 'htdocs')

        certs_top = os.path.join(context.value('etcDir'),
            'pki', 'tls', 'certs', 'live')
        key_top = os.path.join(context.value('etcDir'),
            'pki', 'tls', 'private', 'live')
        key_path = os.path.join(key_top, domain, 'privkey.pem')
        cert_path = os.path.join(certs_top, domain, 'fullchain.pem')
        wildcard_key_path = os.path.join(
            key_top, domain, 'wildcard-privkey.pem') # XXX change for subdomain?
        wildcard_cert_path = os.path.join(
            certs_top, domain, 'wildcard-fullchain.pem')

        # If no TLS certificate is present, we will create a self-signed one,
        # this in order to start nginx correctly.
        wildcard_csr_path = wildcard_cert_path.replace('.crt', '.csr')
        domain_info = os.path.join(
            os.path.dirname(setup.postinst.postinst_run_path),
            '%s.info' % domain)
        _, domain_info_path = setup.stageFile(domain_info, context)
        with open(domain_info_path, 'w') as domain_info_file:
            domain_info_file.write("US\nCalifornia\nSan Francisco\n"\
                "Dummy Corp\n\n*.%(domain)s\nsupport@%(email)s\n\n\n" %
            {'domain': domain, 'email': 'root@localhost.localdomain'})
        setup.postinst.shellCommand([
            '[', '-f', wildcard_key_path, ']', '||', '/usr/bin/openssl',
            'req', '-new', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', wildcard_key_path, '-out', wildcard_csr_path,
            '<', domain_info_path])
        setup.postinst.shellCommand([
            '[', '-f', wildcard_cert_path, ']', '||', '/usr/bin/openssl',
            'x509', '-req', '-days', '15',
            '-in', wildcard_csr_path,
            '-signkey', wildcard_key_path,
            '-out', wildcard_cert_path])
        setup.postinst.shellCommand([
            '[', '-f', key_path, ']', '||', '/usr/bin/ln', '-s',
            wildcard_key_path, key_path])
        setup.postinst.shellCommand([
            '[', '-f', cert_path, ']', '||', '/usr/bin/ln', '-s',
            wildcard_cert_path, cert_path])
        dhparam_path = os.path.join(certs_top, 'dhparam.pem')
        _, new_site_conf = setup.stageFile(self.conf_path(
            domain, context.host(), context.value('etcDir')),
            context=context)
        # XXX increase server name hash with amazon host names.
        # server_names_hash_bucket_size 64;
        # XXX also to fix warn:     ``types_hash_bucket_size 256;``
        with open(new_site_conf, 'w') as site_conf_file:
            site_conf_file.write(config_template % {
                'app_name': app_name,
                'domain': domain,
                'domain_re': domain.replace('.', '\\.'),
                'document_root': document_root,
                'key_path': key_path,
                'cert_path': cert_path,
                'dhparam_path': dhparam_path,
                'webapps': webapps,
                'wildcard_key_path': wildcard_key_path,
                'wildcard_cert_path': wildcard_cert_path})

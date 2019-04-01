# Copyright (c) 2019, DjaoDjin inc.
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

import os, six, stat

from tero import APT_DISTRIBS, REDHAT_DISTRIBS, setup


class iptablesSetup(setup.SetupTemplate):

    IPV4 = 'ip'
    IPV6 = 'ip6'

    def __init__(self, name, files, **kwargs):
        super(iptablesSetup, self).__init__(name, files, **kwargs)

    @classmethod
    def conf_path(cls, dist_host, ip_type=IPV4, sysconfdir=None):
        if dist_host in APT_DISTRIBS:
            return os.path.join(sysconfdir, '%stables.conf' % ip_type)
        elif dist_host in REDHAT_DISTRIBS:
            return os.path.join(sysconfdir, 'sysconfig', '%stables' % ip_type)

    def run(self, context):
        complete = super(iptablesSetup, self).run(context)
        if not complete:
            # As long as the default setup cannot find all prerequisite
            # executable, libraries, etc. we cannot update configuration
            # files here.
            return complete
        ports = []
        forwards = []
        for key, val in six.iteritems(self.managed['iptables']['files']):
            if key == 'port':
                for port, _ in val:
                    ports += [int(port)]
            elif key == 'forward':
                for forward, _ in val:
                    orig, dest = forward.split(':')
                    forwards += [(int(orig), int(dest))]

        # We completely overwrite the iptables configuration for both
        # ipv4 and ipv6. We own it.
        _, new_conf_path = setup.stageFile(
            self.conf_path(context.host(), sysconfdir=context.value('etcDir')),
            context=context)
        with open(new_conf_path, 'w') as conf:
            if forwards:
                conf.write("""*nat
%s
COMMIT""" % '\n'.join([
            "-I PREROUTING -i eth0 -p tcp --dport %d -j REDIRECT --to-port %d"
                % forward for forward in forwards]))
            local_filter_rules = '\n'.join([
            '-A INPUT -m state --state NEW -m tcp -p tcp --dport %d -j ACCEPT'
                % port for port in ports])
            conf.write("""*filter
:INPUT DROP [1000:900000]
:FORWARD DROP [0:0]
:LOGNDROP - [0:0]
:OUTPUT DROP [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -s 127.0.0.1 -j ACCEPT
%(local_filter_rules)s
-A INPUT -p icmp -m icmp --icmp-type 8 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 13 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT 
-A INPUT -p icmp -m icmp --icmp-type 30 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT 
-A FORWARD -j REJECT --reject-with icmp-port-unreachable
-A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
-A INPUT -j LOGNDROP
-A LOGNDROP -m limit --limit 5/min -j LOG --log-prefix "Denied: " --log-level 7
-A LOGNDROP -j DROP
COMMIT
""" % {'local_filter_rules': local_filter_rules})

        local6_filter_rules = '\n'.join([
            '-A INPUT -m state --state NEW -m tcp -p tcp --dport %d -j ACCEPT'
            % port for port in ports])
        _, new_conf_path = setup.stageFile(
            self.conf_path(context.host(),
                ip_type=self.IPV6, sysconfdir=context.value('etcDir')),
            context=context)
        with open(new_conf_path, 'w') as conf:
            conf.write("""
*filter
:INPUT DROP [1000:900000]
:FORWARD DROP [0:0]
:LOGNDROP - [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -s ::1 -j ACCEPT
-A INPUT -m state --state NEW -m udp -p udp --dport 546 -d fe80::/64 -j ACCEPT
%(local6_filter_rules)s
-A INPUT -j LOGNDROP
-A FORWARD -j REJECT --reject-with icmp6-adm-prohibited
-A LOGNDROP -m limit --limit 5/min -j LOG --log-prefix "Denied: " --log-level 7
-A LOGNDROP -j DROP
COMMIT
""" % {'local6_filter_rules': local6_filter_rules})

        # Make sure we disable firewalld, we are using static rules here.
        setup.postinst.shellCommand(['systemctl', 'stop', 'firewalld.service'])
        setup.postinst.shellCommand(
            ['systemctl', 'disable', 'firewalld.service'])

        # Create ifup-local script to load iptables rules
        _, new_ifup_local = setup.stageFile(
            '/usr/sbin/ifup-local', context=context)
        with open(new_ifup_local, 'w') as conf:
            conf.write("""#!/bin/bash

/sbin/iptables-restore < /etc/sysconfig/iptables
/sbin/ip6tables-restore < /etc/sysconfig/ip6tables

IPADDR=`hostname -I`
sed -i "/^.*  *%(domain)s/{h;s/.* /${IPADDR}/};\${x;/^\$/{s//${IPADDR} %(domain)s/;H};x}" /etc/hosts
""" % {'domain': 'private-ip.local'})
        os.chmod(new_ifup_local, stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR
            |stat.S_IRGRP|stat.S_IXGRP|stat.S_IROTH|stat.S_IXOTH)
        setup.postinst.shellCommand(['/usr/sbin/ifup-local'])

        return complete

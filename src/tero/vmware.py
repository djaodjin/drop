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
from __future__ import unicode_literals

import logging, os, re, shutil, subprocess, sys

import fabric.api as fab

import tero


LOGGER = logging.getLogger(__name__)

VM_LIST = None
VM_APPLIB_DIR = "/Applications/VMware Fusion.app/Contents/Library"
VM_DHCP_LEASES = "/var/db/vmware/vmnet-dhcpd-vmnet8.leases"
VM_RUN = os.path.join(VM_APPLIB_DIR, "vmrun")
OVFTOOL = os.path.join(VM_APPLIB_DIR, "VMware OVF Tool/ovftool")
VM_SEARCH_PATH = ['.',
                  os.path.join('/Library', 'Virtual Machines'),
                  os.path.join('/Users', os.environ['LOGNAME'],
                               'Documents', 'Virtual Machines.localized'),
                  os.path.join('/Users', os.environ['LOGNAME'],
                               'Documents', 'Virtual Machines.localized',
                               'Templates')]

class Backend(object):

    def boot(self, vm_name, image=None, macaddr=None, key_name=None):
        """
        Create and starts a VMware virtual machine.
        """
        guest = None
        if not find_vm(vm_name):
            guest = duplicate(image, vm_name, macaddr)
        self.start(vm_name)
        if guest and key_name:
            install_keyfile(guest)
        return guest

    def network_ip(self, hostnames):
        """
        Returns the ip address of a VMware virtual machine if we can figure
        it out.
        """
        results = {}
        vms = list_vms()
        for vm_base in hostnames:
            if re.match(r'\d+\.\d+\.\d+\.\d+', vm_base):
                ipaddr = vm_base
            else:
                ipaddr = None
                vm_name = get_vm_name(vm_base)
                for name, curip, _ in vms:
                    if name == vm_name:
                        ipaddr = curip
                        break
            results.update({vm_base: ipaddr})
        return results

    @staticmethod
    def start(vm_name):
        """
        Starts a VMware virtual machine (It must have been previously created).
        """
        vm_path = None
        proc = subprocess.Popen([VM_RUN, 'list'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             close_fds=True)
        line = proc.stdout.readline().decode('utf-8')
        while line != '':
            look = re.match(r'.*%s\.vmwarevm' % vm_name, line)
            if look != None:
                vm_path = line
                break
            line = proc.stdout.readline().decode('utf-8')
        proc.wait()
        if proc.returncode is not None and proc.returncode != 0:
            raise RuntimeError(
                'vmrun exited with error code ' + str(proc.returncode))
        if not vm_path:
            logging.info("starting %s ...", vm_name)
            vm_path = find_vm(vm_name)
            cmdline = VM_RUN.replace(' ', '\ ') + ' start "' + str(vm_path) \
                + '" nogui > /dev/null 2>&1'
            logging.info(cmdline)
            subprocess.check_call(cmdline,
                                 shell=True,
                                 stdout=None,
                                 stderr=subprocess.STDOUT,
                                 close_fds=True)
        else:
            logging.info("found %s at %s", vm_name, vm_path)


    @staticmethod
    def stop(vm_name):
        """
        Stops a VMware virtual machine.
        """
        # Look for the absolute path to the virtual machine.
        vm_path = None
        cmdline = [VM_RUN, 'list']
        cmd = subprocess.Popen(cmdline,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             close_fds=True)
        line = cmd.stdout.readline().decode('utf-8')
        while line != '':
            look = re.match(r'.*%s\.vmwarevm' % vm_name, line)
            if look != None:
                vm_path = line.strip()
                break
            line = cmd.stdout.readline().decode('utf-8')
        cmd.wait()
        if cmd.returncode != 0:
            raise subprocess.CalledProcessError(cmd.returncode, cmdline)
        # Stop the virtual machine.
        cmdline = [VM_RUN, 'stop', vm_path]
        cmd = subprocess.Popen(cmdline,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               close_fds=True)
        cmd.wait()
        if cmd.returncode != 0:
            raise subprocess.CalledProcessError(cmd.returncode, cmdline)



def find_vm(vm_name):
    '''Returns the absolute to a VM named *vm_name* or None if no VM with
    that name could be found.'''
    src = None
    if vm_name.endswith('.vmwarevm'):
        vm_name = os.path.splitext(vm_name)[0]
    for vm_dir in VM_SEARCH_PATH:
        localname = os.path.join(vm_dir, vm_name, vm_name + '.ovf')
        if os.path.exists(localname):
            src = localname
            break
        localname = os.path.join(
            vm_dir, vm_name + '.vmwarevm', vm_name + '.vmx')
        if os.path.exists(localname):
            src = localname
            break
    return src


def duplicate(src_name, dest, vm_mac=None):
    '''This function will make a copy of a VMware startup image (*src_name*)
    for which it will search for in VM_SEARCH_PATH.'''
    src = find_vm(src_name)
    dest_name = os.path.splitext(os.path.basename(dest))[0]
    if src.endswith('.ovf'):
        # This is an OVF virtual machine, let's use the ovftool.
        cmdline = [OVFTOOL, src, os.path.join(dest, dest_name + '.vmx')]
        subprocess.check_call(cmdline)
        if not dest.endswith('.vmwarevm'):
            dest = dest + '.vmwarevm'
    else:
        # Copy the virtual machine the hard way ...
        if not dest.endswith('.vmwarevm'):
            dest = dest + '.vmwarevm'
        src = os.path.dirname(src)
        subprocess.check_call('rsync -rav "%s/" "%s"' % (src, dest), shell=True)
        prev_cwd = os.getcwd()
        os.chmod(dest, 0o755)
        os.chdir(dest)
        # Base and target have different names, we need to do some magic here.
        for pathname in os.listdir('.'):
            if pathname.endswith('.log'):
                # Otherwise the IP address from the base image is cached.
                os.remove(pathname)
                continue
            elif pathname.endswith('.vmx'):
                os.chmod(pathname, 0o755)
            elif (pathname.startswith(src_name + '-s')
                  or pathname.endswith('.nvram')
                  or pathname.endswith('.vmdk')):
                os.chmod(pathname, 0o600)
            elif (pathname.endswith('.vmsd')
                  or pathname.endswith('.vmxf')
                  or pathname.endswith('.plist')):
                os.chmod(pathname, 0o644)
            if  src_name != dest_name:
                if (pathname == src_name + '.vmdk'
                    or pathname.endswith('.vmx')
                    or pathname.endswith('.vmxf')):
                    new_file = pathname.replace(src_name, dest_name)
                    cmdline = 'sed -e "s,%(src)s,%(dest)s,g" -e "s,%(src_name)s,%(dest_name)s,g" %(org_file)s > %(new_file)s' % {
                        'src': src,
                        'dest': dest,
                        'src_name': src_name,
                        'dest_name': dest_name,
                        'org_file': pathname,
                        'new_file': new_file}
                    sys.stderr.write(cmdline + '\n')
                    os.system(cmdline)
                    os.remove(pathname)
                else:
                    shutil.move(pathname, pathname.replace(src_name, dest_name))
        os.chdir(prev_cwd)

    if vm_mac:
        macaddr = vm_mac
    else:
        _, macaddr = read_addr_from_dhcp_conf(dest_name)

    if macaddr:
        # Change the MAC address
        org_path = os.path.join(dest, dest_name + '.vmx~')
        new_path = os.path.join(dest, dest_name + '.vmx')
        shutil.copy(new_path, org_path)
        with open(org_path) as org_file:
            with open(new_path, 'w') as new_file:
                for line in org_file.readlines():
                    look = re.match('ethernet0.addressType = (.*)', line)
                    if look:
                        new_file.write('ethernet0.addressType = "static"\n')
                        new_file.write('ethernet0.address = "%s"\n'
                                       % macaddr)
                    elif line.startswith('ethernet0.generatedAddress'):
                        continue
                    else:
                        new_file.write(line)
        os.remove(org_path)
        org_file = os.path.join(dest, dest_name + '.plist~')
        new_file = os.path.join(dest, dest_name + '.plist')
        if os.path.exists(new_file):
            shutil.copy(new_file, org_file)
            cmdline = 'sed -e "s,<string>.*</string>,<string>%(dest_name)s</string>," %(org_file)s > %(new_file)s' % {
                'org_file': org_file,
                'new_file': new_file,
                'dest_name': dest_name}
            sys.stderr.write(cmdline + '\n')
            os.system(cmdline)
            os.remove(org_file)
    return dest


def ping_live_ip():
    # Without a ping beforehand, arp does not find a match
    # between ip and mac addresses.
    ips = []
    cmdline = ['/opt/local/bin/nmap', '-sP', '192.168.144.1/24']
    LOGGER.info(' '.join(cmdline))
    cmd = subprocess.Popen(cmdline,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT,
                           close_fds=True)
    line = cmd.stdout.readline().decode('utf-8')
    while line != '':
        look = re.match(r'Nmap scan report for (\d+\.\d+\.\d+\.\d+)', line)
        if look != None:
            ips += [look.group(1)]
        line = cmd.stdout.readline().decode('utf-8')
    return ips


def get_ip_by_mac(probing=False):
    """
    Tries to infer all live IP addresses on the VM sub-network
    and returns a dictionary of IPs keyed by MAC addresses.
    """
    ip_by_mac = {}
    # By reading the DHCP leases file.
    with open(VM_DHCP_LEASES) as leases:
        ipaddr = None
        macaddr = None
        line = leases.readline()
        while line:
            look = re.match('lease (.*) {', line)
            if look:
                ipaddr = look.group(1)
            look = re.match(r'\s+hardware ethernet (.*);', line)
            if look:
                macaddr = look.group(1)
            look = re.match(r'\s+abandoned;', line)
            if look:
                ipaddr = None
                macaddr = None
            look = re.match('}', line)
            if look and ipaddr and macaddr:
                ip_by_mac[macaddr] = ipaddr
                ipaddr = None
                macaddr = None
            line = leases.readline()

    # By doing network probing.
    if probing:
        candidate_ips = ping_live_ip()
        for ipaddr in candidate_ips:
            # XXX ipaddr = '192.168.144.%d' % num
            cmdline = ['/usr/sbin/arp', ipaddr]
            cmd = subprocess.Popen(cmdline,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,
                                 close_fds=True)
            line = cmd.stdout.readline().decode('utf-8')
            while line != '':
                matched = \
                r'.*\(%s\) at (\S+):(\S+):(\S+):(\S+):(\S+):(\S+) on vmnet8' \
                    % ipaddr
                look = re.match(matched, line)
                if look != None:
                    mac0 = int(look.group(1), 16)
                    mac1 = int(look.group(2), 16)
                    mac2 = int(look.group(3), 16)
                    mac3 = int(look.group(4), 16)
                    mac4 = int(look.group(5), 16)
                    mac5 = int(look.group(6), 16)
                    mac = '%02x:%02x:%02x:%02x:%02x:%02x' % (mac0,
                        mac1, mac2, mac3, mac4, mac5)
                    ip_by_mac[mac] = ipaddr
                    break
                line = cmd.stdout.readline().decode('utf-8')
            cmd.wait()
            # We don't check the return code here because if the ip address
            # is not in use, arp would return a positive exit code.
    return ip_by_mac


def install_keyfile(guest):
    if fab.env.keyfile:
        cmdline = [VM_RUN, '-gu', fab.env.user, '-gp', fab.env.password,
                   'createDirectoryInGuest', guest,
                   '/home/%s/.ssh' % fab.env.user]
        cmd = subprocess.check_call(cmdline)
        cmdline = [VM_RUN, '-gu', fab.env.user, '-gp', fab.env.password,
                   'CopyFileFromHostToGuest', guest,
                   fab.env.keyfile + '.pub',
                   '/home/%s/.ssh/authorized_keys' % fab.env.user]
        cmd = subprocess.check_call(cmdline)


def get_vm_name(vm_path):
    return os.path.splitext(os.path.basename(vm_path))[0]


def list_vms():
    """Returns a list of up and running virtual machines
    as tuples (vm, ip, mac)."""
    global VM_LIST
    if VM_LIST is not None:
        return VM_LIST

    # Get the MAC address for all matching IPs
    VM_LIST = []
    pinged = False
    ip_by_mac = get_ip_by_mac()

    # Get list of virtual machines up and running
    cmdline = [VM_RUN, 'list']
    cmd = subprocess.Popen(cmdline,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    line = cmd.stdout.readline().decode('utf-8')
    while line != '':
        look = re.match(r'(.*)\.vmx', line)
        if look != None:
            mac = 'unknown'
            vm_path = line.strip()
            vm_name = get_vm_name(vm_path)
            with open(vm_path) as vm_conf:
                for conf_line in vm_conf.readlines():
                    look = re.match(
                        r'ethernet0.address = "(\S+:\S+:\S+:\S+:\S+:\S+)"',
                        conf_line)
                    if look != None:
                        mac = look.group(1)
                    look = re.match(
                    r'ethernet0.generatedAddress = "(\S+:\S+:\S+:\S+:\S+:\S+)"',
                        conf_line)
                    if look != None:
                        mac = look.group(1)
            ipaddr, macaddr = read_addr_from_dhcp_conf(vm_name)
            if macaddr:
                ip_by_mac.update({macaddr : ipaddr})
            if mac in ip_by_mac:
                VM_LIST += [(vm_name, ip_by_mac[mac], mac)]
            else:
                VM_LIST += [(vm_name, 'unknown', mac)]
        line = cmd.stdout.readline().decode('utf-8')
    cmd.wait()
    if cmd.returncode != 0:
        raise subprocess.CalledProcessError(cmd.returncode, cmdline)
    return VM_LIST


def read_addr_from_dhcp_conf(vm_name):
    ipaddr = None
    macaddr = None
    # Let's try to find out the ip that will be allocated
    # by the DHCP daemon.
    with open("/Library/Preferences/VMware Fusion/vmnet8/dhcpd.conf") as dnsf:
        name = None
        line = dnsf.readline()
        while line != '':
            look = re.match(r'host (\S+)\s+{', line)
            if look:
                name = look.group(1)
            if name and name == vm_name:
                look = re.match(r'\s*fixed-address (\S+);', line)
                if look:
                    ipaddr = look.group(1)
                else:
                    look = re.match(r'\s*hardware ethernet (\S+);', line)
                    if look:
                        macaddr = look.group(1)
                if ipaddr and macaddr:
                    break
            line = dnsf.readline()
    return ipaddr, macaddr

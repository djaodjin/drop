#!/usr/bin/env python
#
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

"""
Command-line tool to run docker images in ecs with their own resources.
"""

import argparse
import boto3
import os
import os.path
import paramiko
from Crypto.PublicKey import RSA
from StringIO import StringIO
import re
import time
import subprocess
import sys
import botocore.exceptions
# import django.core.management

from random import choice

SUFFIX = "".join([choice("abcdefghijklmnopqrstuvwxyz0123456789") for i in range(10)])
PREFIX = 'rundocker'
def make_name(s=None):
    if s is None:
        return '%s-%s' % (PREFIX, SUFFIX)
    else:
        return '%s-%s-%s' % (PREFIX, s, SUFFIX)

def pubkey(keypair):
    key = RSA.importKey(keypair['KeyMaterial'])
    return key.publickey().exportKey('OpenSSH')

def privatekey(keypair):
    key = RSA.importKey(keypair['KeyMaterial'])
    return key.exportKey('PEM')

def mkdirp_remote(sftp, path):
    (head, tail) = os.path.split(path)
    if head != '' and head != '/':
        mkdirp(sftp, head)

    if path != '.':
        try:
            sftp.stat(path)
        except IOError:
            # file doesn't exist
            print 'mkdir', path
            sftp.mkdir(path)


def copy_dir(sftp, local, remote):

    for path,dirnames, fnames in os.walk(local):
        for fname in fnames:
            localpath = os.path.join(path,fname)
            relpath = os.path.relpath(localpath, local)
            remotepath = os.path.join(remote, relpath)

            dirname = os.path.dirname(remotepath)

            mkdirp_remote(sftp, dirname)
            print 'copy %s -> %s' % (localpath, remotepath)
            sftp.put(localpath, remotepath)

def rsync(pem_path, from_dir, to_dir):
    absolute_pem_path = os.path.abspath(pem_path)
    rsync_cmd = [
        '/usr/bin/rsync',
        '-ravz',  '--progress',
        '--delete',
        '-e', 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i %s' % absolute_pem_path,
        from_dir,
        to_dir,
    ]
    print ' '.join(rsync_cmd)

    process = subprocess.Popen(rsync_cmd, stdout=sys.stdout, stderr=sys.stderr)

    exit_code = process.wait()
    if exit_code != 0:
        raise Exception('Rsync failed!')


def sanitize_filename(fname):
    fname = fname.replace(os.path.sep, '-')
    fname = re.sub(r'[^a-zA-Z_\-.0-9]', '', fname)
    fname = re.sub(r'^[^a-zA-Z0-9]+', '', fname)
    if fname.startswith('.'):
        fname = fname[1:]

    return fname

def make_task_definition_json(image, mounts, env=[]):

    volumes = []
    mount_points = []
    for i, mount in enumerate(mounts.items()):
        from_path, to_path = mount

        source_path = os.path.join('/home/ec2-user', sanitize_filename(from_path))
        volume = {
            'name': 'm%d' % i,
            'host': {
                'sourcePath': source_path
            }
        }
        mount_point = {
            'sourceVolume': volume['name'],
            'containerPath': to_path,
        }
        mount_points.append(mount_point)
        volumes.append(volume)

    definition = {
        'containerDefinitions': [
            {
                "name": make_name('rundocker'),
                "image": image,
                "essential": True,
                "portMappings": [
                    {
                        "containerPort": 8000,
                        "hostPort": 8020
                    }
                ],
                "environment": env,
                "memoryReservation": 512,
                'mountPoints': mount_points
            },

        ],
        'volumes': volumes,
        'family': make_name('rundocker')
    }

    return definition

def run_docker(image, mounts, env, instance_profile, security_group):
    try:

        ecs = boto3.client('ecs', region_name='us-west-2')
        ec2 = boto3.client('ec2', region_name='us-west-2')

        keyName = make_name('ecs')

        keypair = ec2.create_key_pair(KeyName=keyName)
        with open('ecs.pem','w') as f:
            f.write(privatekey(keypair))

        os.chmod('ecs.pem', 0600)

        task_family = make_name('task')
        task_definition_json = make_task_definition_json(image, mounts)
        print task_definition_json
        task_definition = ecs.register_task_definition(**task_definition_json)

        cluster = ecs.create_cluster(clusterName=make_name('cluster'))

        instance_json = {
            # Use the official ECS image for us-west2
            # http://docs.aws.amazon.com/AmazonECS/latest/developerguide/launch_container_instance.html
            'ImageId':"ami-56ed4936",
            'SecurityGroups':[
                security_group,
            ],
            'KeyName':keypair['KeyName'],
            'MinCount':1,
            'MaxCount':1,
            'InstanceType':"t2.micro",
            'IamInstanceProfile':{
                "Name": instance_profile
            },
            'UserData':"#!/bin/bash \n echo ECS_CLUSTER=" + cluster['cluster']['clusterName'] + " >> /etc/ecs/ecs.config"
        }
        run_instances_response = ec2.run_instances(**instance_json)


        ec2_waiter = ec2.get_waiter('instance_running')
        instance_ids = [instance['InstanceId'] for instance in run_instances_response['Instances']]
        print 'waiting for ec2 instance'
        ec2_waiter.wait(InstanceIds=instance_ids)


        ec2_resource = boto3.resource('ec2', region_name='us-west-2')
        instance = ec2_resource.Instance(instance_ids[0])
        instance_name = make_name('ecs')
        print 'instance running: (%s) %s' % (instance_name, instance.private_ip_address)
        print 'ssh -i ecs.pem ec2-user@%s' % instance.private_ip_address

        instance.create_tags(Tags=[{
            'Key': 'Name',
            'Value': instance_name
        }])

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        key = paramiko.RSAKey.from_private_key(StringIO(keypair['KeyMaterial']))

        connected = False
        while True:
            try:
                ssh.connect(instance.private_ip_address, username='ec2-user',pkey=key)
                break
            except paramiko.ssh_exception.NoValidConnectionsError:
                print 'waiting to connect to ec2 instance...'
                time.sleep(15)

        stdin, stdout, sterr = ssh.exec_command('sudo yum -y install rsync')
        stdout.channel.recv_exit_status()
        sftp = ssh.open_sftp()

        for from_path,_ in mounts.items():
            source_path = os.path.join('/home/ec2-user', sanitize_filename(from_path))
            remote_path = 'ec2-user@%s:%s' % (instance.private_ip_address, source_path)
            if os.path.isdir(from_path) and from_path[-1] != '/':
                from_path = '%s/' % from_path
            rsync('ecs.pem', from_path, remote_path)
            # copy_dir_to_remote(sftp, from_path, source_path)


        while True:
            container_instances = ecs.list_container_instances(
                cluster=cluster['cluster']['clusterName'],
            )

            if len(container_instances['containerInstanceArns']) > 0:
                break

            print 'waiting for ec2 instances to join cluster...'
            time.sleep(15)

        run_task =  ecs.run_task(
            cluster=cluster['cluster']['clusterName'],
            taskDefinition=task_definition['taskDefinition']['taskDefinitionArn'],
            count=1,
        )

        task_arn = run_task['tasks'][0]['taskArn']

        print ecs.describe_tasks(
            cluster=cluster['cluster']['clusterName'],
            tasks=[task_arn]
        )

        while True:
            task_status = ecs.describe_tasks(
                cluster=cluster['cluster']['clusterName'],
                tasks=[task_arn]
            )
            print task_status
            if task_status['tasks'][0]['lastStatus'] == 'STOPPED':
                break

            time.sleep(15)

        tasks_stopped_waiter = ecs.get_waiter('tasks_stopped')
        tasks_stopped_waiter.wait(
            cluster=cluster['cluster']['clusterName'],
            tasks=[task_arn]
        )

    finally:


        try:
            sftp.close()
        except Exception, e:
            print e

        try:
            ssh.close()
        except Exception, e:
            print e

        try:
            instance.terminate()
        except Exception, e:
            print e

        try:
            ec2.delete_key_pair(KeyName=keypair['KeyName'])
        except Exception, e:
            print e

        try:
            arn = task_definition['taskDefinition']['taskDefinitionArn']
            ecs.deregister_task_definition(taskDefinition=arn)
        except Exception, e:
            print e

        try:
            ecs.delete_cluster(cluster=cluster['cluster']['clusterName'])
        except Exception, e:
            print e



def main():
    """
    Main Entry Point
    """
    import __main__

    parser = argparse.ArgumentParser()
    parser.add_argument('--instance-profile')
    parser.add_argument('--security-group')
    parser.add_argument('-v', '--volume', action='append', default=[])
    parser.add_argument('image')
    parser.add_argument('-e', '--env', action='append', default=[])


    args = parser.parse_args()

    mounts = dict( mount.split(':') for mount in args.volume)
    env = []
    for name_value_pair in args.env:
        name,value = name_value_pair.split('=', 1)
        env.append({
            'name': name,
            'value': value
        })

    run_docker(args.image, mounts, env, args.instance_profile, args.security_group)


if __name__ == '__main__':
    main()

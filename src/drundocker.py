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


def pubkey(keypair):
    key = RSA.importKey(keypair['KeyMaterial'])
    return key.publickey().exportKey('OpenSSH')


def privatekey(keypair):
    key = RSA.importKey(keypair['KeyMaterial'])
    return key.exportKey('PEM')


def mkdirp_remote(sftp, path):
    (head, tail) = os.path.split(path)
    if head != '' and head != '/':
        mkdirp_remote(sftp, head)

    if path != '.':
        try:
            sftp.stat(path)
        except IOError:
            # file doesn't exist
            print 'mkdir', path
            sftp.mkdir(path)


def copy_dir(sftp, local, remote):

    for path, dirnames, fnames in os.walk(local):
        for fname in fnames:
            localpath = os.path.join(path, fname)
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
        '-ravz',
        '--progress',
        '--delete',
        '-e',
        'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i %s' %
        absolute_pem_path,
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


def make_task_definition_json(family, image, mounts, env=None):
    if env is None:
        env = []

    volumes = []
    mount_points = []
    for i, mount in enumerate(mounts.items()):
        from_path, to_path = mount

        source_path = os.path.join(
            '/home/ec2-user',
            sanitize_filename(from_path))
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
                "name": '%s-container' % family,
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
        'family': family
    }

    return definition


def run_docker(
        cluster_name,
        image,
        mounts,
        env,
        instance_profile,
        security_group,
        hosted_zone_id,
        host_name,
        key_path):
    try:

        ecs = boto3.client('ecs', region_name='us-west-2')
        ec2 = boto3.client('ec2', region_name='us-west-2')
        route53 = boto3.client('route53')

        key_name = '%s-key' % cluster_name

        keypair = ec2.create_key_pair(KeyName=key_name)
        with open(key_path, 'w') as key_file:
            key_file.write(privatekey(keypair))

        os.chmod(key_path, 0o600)

        task_family = '%s-task-family' % cluster_name
        task_definition_json = make_task_definition_json(
            task_family, image, mounts, env)
        print task_definition_json
        task_definition = ecs.register_task_definition(**task_definition_json)

        cluster = ecs.create_cluster(clusterName=cluster_name)

        instance_json = {
            # Use the official ECS image for us-west2
            # http://docs.aws.amazon.com/AmazonECS/latest/developerguide/launch_container_instance.html
            'ImageId': "ami-56ed4936",
            'SecurityGroups': [
                security_group,
            ],
            'KeyName': keypair['KeyName'],
            'MinCount': 1,
            'MaxCount': 1,
            'InstanceType': "t2.micro",
            'IamInstanceProfile': {
                "Name": instance_profile
            },
            'UserData': "#!/bin/bash \n echo ECS_CLUSTER=" + cluster['cluster']['clusterName'] + " >> /etc/ecs/ecs.config"
        }
        run_instances_response = ec2.run_instances(**instance_json)

        ec2_waiter = ec2.get_waiter('instance_running')
        instance_ids = [instance['InstanceId']
                        for instance in run_instances_response['Instances']]
        print 'waiting for ec2 instance'
        ec2_waiter.wait(InstanceIds=instance_ids)

        ec2_resource = boto3.resource('ec2', region_name='us-west-2')
        instance = ec2_resource.Instance(instance_ids[0])
        instance_name = '%s-ecs' % cluster_name
        print 'instance running: (%s) %s' % (instance_name, instance.private_ip_address)
        print 'ssh -i %s ec2-user@%s' % (key_path, instance.private_ip_address)

        instance.create_tags(Tags=[{
            'Key': 'Name',
            'Value': instance_name
        }])

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        key = paramiko.RSAKey.from_private_key(
            StringIO(keypair['KeyMaterial']))

        while True:
            try:
                ssh.connect(
                    instance.private_ip_address,
                    username='ec2-user',
                    pkey=key)
                break
            except paramiko.ssh_exception.NoValidConnectionsError:
                print 'waiting to connect to ec2 instance...'
                time.sleep(15)

        stdin, stdout, sterr = ssh.exec_command('sudo yum -y install rsync')
        stdout.channel.recv_exit_status()
        sftp = ssh.open_sftp()

        for from_path, _ in mounts.items():
            source_path = os.path.join(
                '/home/ec2-user', sanitize_filename(from_path))
            remote_path = 'ec2-user@%s:%s' % (
                instance.private_ip_address, source_path)
            if os.path.isdir(from_path) and from_path[-1] != '/':
                from_path = '%s/' % from_path
            rsync(key_path, from_path, remote_path)
            # copy_dir_to_remote(sftp, from_path, source_path)

        while True:
            container_instances = ecs.list_container_instances(
                cluster=cluster['cluster']['clusterName'],
            )

            if len(container_instances['containerInstanceArns']) > 0:
                break

            print 'waiting for ec2 instances to join cluster...'
            time.sleep(15)

        run_task = ecs.run_task(
            cluster=cluster['cluster']['clusterName'],
            taskDefinition=task_definition['taskDefinition']['taskDefinitionArn'],
            count=1,
        )

        task_arn = run_task['tasks'][0]['taskArn']

        print ecs.describe_tasks(
            cluster=cluster['cluster']['clusterName'],
            tasks=[task_arn]
        )

        route53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': host_name,
                            'Type': 'A',
                            # 'Region': 'us-west-2'
                            'TTL': 3600,
                            'ResourceRecords': [
                                {
                                    'Value': instance.private_ip_address
                                },
                            ],
                        }
                    },
                ]
            }
        )

    finally:

        try:
            sftp.close()
        except Exception as e:
            print e

        try:
            ssh.close()
        except Exception as e:
            print e



def shutdown_cluster(cluster_name, mounts, key_path):

    ecs = boto3.client('ecs', region_name='us-west-2')
    ec2 = boto3.client('ec2', region_name='us-west-2')
    ec2_resource = boto3.resource('ec2', region_name='us-west-2')

    running_task_arns = ecs.list_tasks(
        cluster=cluster_name,
        desiredStatus='RUNNING')['taskArns']
    stopped_task_arns = ecs.list_tasks(
        cluster=cluster_name,
        desiredStatus='STOPPED')['taskArns']
    all_task_arns = running_task_arns + stopped_task_arns
    if all_task_arns:
        tasks = ecs.describe_tasks(cluster=cluster_name,
                                   tasks=all_task_arns)
    else:
        tasks = None

    container_instance_arns = set(
        [task['containerInstanceArn'] for task in tasks['tasks']])

    container_instances = ecs.describe_container_instances(
        cluster=cluster_name, containerInstances=list(container_instance_arns))

    instance_ids = [info['ec2InstanceId']
                    for info in container_instances['containerInstances']]
    instances = [ec2_resource.Instance(iid) for iid in instance_ids]
    instances = [instance for instance in instances
                 if instance.state.get('Name') == 'running']

    keypair_names = [instance.key_name for instance in instances
                     if instance.key_name.startswith(cluster_name)]

    for task_arn in running_task_arns:
        print 'stopping task', cluster_name, task_arn
        ecs.stop_task(cluster=cluster_name,
                      task=task_arn)

    if running_task_arns:
        tasks_stopped_waiter = ecs.get_waiter('tasks_stopped')
        print 'waiting for tasks to stop'
        tasks_stopped_waiter.wait(
            cluster=cluster_name,
            tasks=running_task_arns
        )

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    with open(key_path) as key_file:
        key = paramiko.RSAKey.from_private_key(key_file)

    if instances:
        ssh.connect(
            instances[0].private_ip_address,
            username='ec2-user',
            pkey=key)

        for from_path, _ in mounts.items():
            source_path = os.path.join(
                '/home/ec2-user', '%s/' %
                sanitize_filename(from_path))
            remote_path = 'ec2-user@%s:%s' % (
                instance.private_ip_address, source_path)

            # docker sets file permissions as the user used inside the docker container
            # which tends to be root.
            stdin, stdout, sterr = ssh.exec_command(
                'sudo chown ec2-user:ec2-user -R %s' %
                source_path)
            stdout.channel.recv_exit_status()

            if os.path.isdir(from_path) and from_path[-1] != '/':
                from_path = '%s/' % from_path
            rsync(key_path, remote_path, from_path)

        ssh.close()

    for keyname in keypair_names:
        print 'deleting key pair', keyname
        ec2.delete_key_pair(KeyName=keyname)

    for instance in instances:
        instance.terminate()

    if instances:
        print 'waiting for instances to shut down'
        instances_terminated_waiter = ec2.get_waiter('instance_terminated')
        instances_terminated_waiter.wait(
            InstanceIds=[instance.id for instance in instances])

    if tasks:
        for task in tasks['tasks']:
            print 'deregistering task', task['taskDefinitionArn']
            ecs.deregister_task_definition(
                taskDefinition=task['taskDefinitionArn'])

    print 'deleting cluster', cluster_name
    ecs.delete_cluster(cluster=cluster_name)


def run(input_args):
    """
    Main Entry Point
    """
    import __main__

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--instance-profile',
        help='instance profile to use for cluster instance')
    parser.add_argument(
        '--security-group',
        help='security groupto run the ec2 instance in')
    parser.add_argument(
        '-v',
        '--volume',
        action='append',
        default=[],
        help='Adds a volume to run the docker instance with. The folder will be automatically transferred to the cluster instance. Conceptually similar to the docker run --volume args.')
    parser.add_argument(
        '-e',
        '--env',
        action='append',
        default=[],
        help='Environment variables to run the docker container with. Conceptually similar to the docker --env flag.')
    parser.add_argument(
        '--cluster-name',
        required=True,
        help='Name to use for the cluster. This can be used for stopping the cluster.')
    parser.add_argument(
        '--hostname',
        required=True,
        help='A dns entry with this hostname is created.')
    parser.add_argument(
        '--hosted-zone-id',
        required=True,
        help='The hosted zone id to creat the dns entry in.')
    parser.add_argument(
        '--key',
        required=True,
        help='A security key is created and *written* to this file path.')
    parser.add_argument(
        'image',
        help='The name of docker image to run.')

    args = parser.parse_args(input_args)

    mounts = dict(mount.split(':') for mount in args.volume)
    env = []
    for name_value_pair in args.env:
        name, value = name_value_pair.split('=', 1)
        env.append({
            'name': name,
            'value': value
        })

    run_docker(
        args.cluster_name,
        args.image,
        mounts,
        env,
        args.instance_profile,
        args.security_group,
        args.hosted_zone_id,
        args.hostname,
        args.key)

def stop(input_args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-v',
        '--volume',
        action='append',
        default=[],
        help='if provided, the files from the provided volume will be transferred back from the cluster instance after the task has been stopped.')
    parser.add_argument(
        '--cluster-name',
        required=True,
        help='name of the cluster instance to stop.')
    parser.add_argument(
        '--key',
        required=True,
        help='private key that can be used to connect to the cluster instance.')

    args = parser.parse_args(input_args)

    mounts = dict(mount.split(':') for mount in args.volume)

    shutdown_cluster(args.cluster_name, mounts, args.key)


if __name__ == '__main__':
    if sys.argv[1] == 'run':
        run(sys.argv[2:])
    elif sys.argv[1] == 'stop':
        stop(sys.argv[2:])
    else:
        print 'usage: python drundocker.py cmd args..'
        sys.exit(1)
    # main()

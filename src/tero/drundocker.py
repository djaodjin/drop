#!/usr/bin/env python
#
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

"""
Command-line tool to run docker images in ecs with their own resources.
"""

import argparse, logging, os, re, time

import boto3, paramiko, six
from botocore.exceptions import ClientError

from . import shell_command

LOGGER = logging.getLogger()
DEFAULT_REGION = 'us-west-2'


def mkdirp_remote(sftp, path):
    head, _ = os.path.split(path)
    if head != '' and head != '/':
        mkdirp_remote(sftp, head)
    if path != '.':
        try:
            sftp.stat(path)
        except IOError:
            # file doesn't exist
            LOGGER.debug('mkdir %s', path)
            sftp.mkdir(path)


def copy_dir(sftp, local, remote):
    for path, _, fnames in os.walk(local):
        for fname in fnames:
            localpath = os.path.join(path, fname)
            relpath = os.path.relpath(localpath, local)
            remotepath = os.path.join(remote, relpath)
            dirname = os.path.dirname(remotepath)
            mkdirp_remote(sftp, dirname)
            LOGGER.info('copy %s -> %s', localpath, remotepath)
            sftp.put(localpath, remotepath)


def rsync(pem_path, from_dir, to_dir):
    absolute_pem_path = os.path.abspath(pem_path)
    rsync_cmd = [
        '/usr/bin/rsync',
        '-ravz',
        '-e',
        '/usr/bin/ssh -o UserKnownHostsFile=/dev/null'\
            ' -o StrictHostKeyChecking=no -i %s' % absolute_pem_path,
        from_dir,
        to_dir,
    ]
    shell_command(rsync_cmd, nolog=True)


def sanitize_filename(fname):
    fname = fname.replace(os.path.sep, '-')
    fname = re.sub(r'[^a-zA-Z_\-.0-9]', '', fname)
    fname = re.sub(r'^[^a-zA-Z0-9]+', '', fname)
    if fname.startswith('.'):
        fname = fname[1:]

    return fname


def make_task_definition_json(family, image, mounts, container_port, env=None):
    if env is None:
        env = []

    volumes = []
    mount_points = []
    for idx, mount in enumerate(six.iteritems(mounts)):
        from_path, to_path = mount

        source_path = os.path.join(
            '/home/ec2-user',
            sanitize_filename(from_path))
        volume = {
            'name': 'm%d' % idx,
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
                        "containerPort": container_port,
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
        image,
        container_port=8020,
        mounts=None,
        env=None,
        host_name=None,
        cluster_name=None,
        instance_profile=None,
        security_group=None,
        hosted_zone_id=None,
        key_name=None,
        key_path=None,
        region_name=DEFAULT_REGION):
    """
    Create an ECS cluster named *cluster_name*, create an EC2 instance
    based of us-west2 ECS-ready image (ami-56ed4936), copy the directories
    specified in mounts from the local machine to the EC2 instance,
    launch the docker image (*image*) in the ECS cluster and associate
    a *host_name* in the route53 DNS to access it.
    """
    try:
        ecs = boto3.client('ecs', region_name=region_name)
        ec2 = boto3.client('ec2', region_name=region_name)
        route53 = boto3.client('route53')

        if not key_path:
            key_path = os.path.join(
                os.path.expanduser('~'), '.ssh', '%s_rsa' % cluster_name)
        if not os.path.exists(key_path):
            shell_command(['/usr/bin/ssh-keygen', '-q', '-b', '2048',
                '-N', '""', '-t', 'rsa', '-f', key_path], nolog=True)
        if not key_name:
            key_name = '%s-key' % cluster_name
        try:
            keypairs = ec2.describe_key_pairs(KeyNames=[key_name])
            ec2_key_fingerprint = keypairs['KeyPairs'][0]['KeyFingerprint']
            LOGGER.debug("Fingerprint of key '%s' on ec2: %s",
                key_name, ec2_key_fingerprint)
        except ClientError as err:
            ec2_key_fingerprint = None
        if not ec2_key_fingerprint:
            with open("%s.pub" % key_path, 'rb') as key_file:
                public_key_material = key_file.read()
                ec2.import_key_pair(
                    KeyName=key_name, PublicKeyMaterial=public_key_material)

        task_family = '%s-task-family' % cluster_name
        task_definition_json = make_task_definition_json(
            task_family, image, mounts, container_port, env=env)
        LOGGER.debug("task_definition=%s", task_definition_json)
        task_definition = ecs.register_task_definition(**task_definition_json)

        cluster = ecs.create_cluster(clusterName=cluster_name)

        instance_json = {
            # Use the official ECS image for us-west2
            # http://docs.aws.amazon.com/AmazonECS/latest/developerguide/launch_container_instance.html
            'ImageId': "ami-56ed4936",
            'SecurityGroups': [
                security_group,
            ],
            'KeyName': key_name,
            'MinCount': 1,
            'MaxCount': 1,
            'InstanceType': "t2.micro",
            'IamInstanceProfile': {
                "Name": instance_profile
            },
            'UserData':
              "#!/bin/bash \n echo ECS_CLUSTER=%s >> /etc/ecs/ecs.config" % str(
                  cluster['cluster']['clusterName'])
        }
        run_instances_response = ec2.run_instances(**instance_json)

        ec2_waiter = ec2.get_waiter('instance_running')
        instance_ids = [instance['InstanceId']
                        for instance in run_instances_response['Instances']]
        LOGGER.info('waiting for ec2 instance')
        ec2_waiter.wait(InstanceIds=instance_ids)

        ec2_resource = boto3.resource('ec2', region_name=DEFAULT_REGION)
        instance = ec2_resource.Instance(instance_ids[0])
        instance_name = '%s-ecs' % cluster_name
        LOGGER.info('instance running: (%s) %s',
            instance_name, instance.private_ip_address)
        LOGGER.info('ssh -i %s ec2-user@%s',
            key_path, instance.private_ip_address)

        instance.create_tags(Tags=[{
            'Key': 'Name',
            'Value': instance_name
        }])

        LOGGER.info("copying fixtures files to %s ...",
            instance.private_ip_address)
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            while True:
                try:
                    ssh.connect(
                        instance.private_ip_address,
                        username='ec2-user',
                        pkey=paramiko.RSAKey.from_private_key_file(
                            filename=key_path))
                    break
                except paramiko.ssh_exception.NoValidConnectionsError:
                    LOGGER.info('waiting to connect to ec2 instance...')
                    time.sleep(15)
            _, stdout, _ = ssh.exec_command('sudo yum -y install rsync')
            stdout.channel.recv_exit_status()
            for from_path, _ in six.iteritems(mounts):
                source_path = os.path.join(
                    '/home/ec2-user', sanitize_filename(from_path))
                remote_path = 'ec2-user@%s:%s' % (
                    instance.private_ip_address, source_path)
                if os.path.isdir(from_path) and from_path[-1] != '/':
                    from_path = '%s/' % from_path
                rsync(key_path, from_path, remote_path)

        LOGGER.info("waiting for ec2 instances to join cluster...")
        while True:
            container_instances = ecs.list_container_instances(
                cluster=cluster['cluster']['clusterName'],
            )
            if len(container_instances['containerInstanceArns']) > 0:
                break
            time.sleep(15)

        run_task = ecs.run_task(
            cluster=cluster['cluster']['clusterName'],
        taskDefinition=task_definition['taskDefinition']['taskDefinitionArn'],
            count=1,
        )
        task_arn = run_task['tasks'][0]['taskArn']
        LOGGER.info(ecs.describe_tasks(
            cluster=cluster['cluster']['clusterName'],
            tasks=[task_arn]
        ))

        LOGGER.info("update DNS record for %s ...", host_name)
        route53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': host_name,
                            'Type': 'A',
                            # 'Region': DEFAULT_REGION
                            'TTL': 60,
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
    except Exception as err:
        LOGGER.exception("%s", err)
        raise


def shutdown_cluster(cluster_name, mounts,
            key_path=None, delete_keypair=False):
    """
    Copy the localstate_dir data files (i.e. *mounts*) and shuts down
    the cluster *cluster_name*.
    """
    if not key_path:
        key_path = os.path.join(
            os.path.expanduser('~'), '.ssh', '%s_rsa' % cluster_name)

    ecs = boto3.client('ecs', region_name=DEFAULT_REGION)
    ec2 = boto3.client('ec2', region_name=DEFAULT_REGION)
    ec2_resource = boto3.resource('ec2', region_name=DEFAULT_REGION)

    running_task_arns = ecs.list_tasks(
        cluster=cluster_name,
        desiredStatus='RUNNING')['taskArns']
    stopped_task_arns = ecs.list_tasks(
        cluster=cluster_name,
        desiredStatus='STOPPED')['taskArns']
    all_task_arns = running_task_arns + stopped_task_arns
    if all_task_arns:
        tasks = ecs.describe_tasks(cluster=cluster_name, tasks=all_task_arns)
    else:
        tasks = None

    container_instance_arns = ecs.list_container_instances(cluster=cluster_name)
    container_instances = ecs.describe_container_instances(
        cluster=cluster_name,
        containerInstances=container_instance_arns['containerInstanceArns'])

    instance_ids = [info['ec2InstanceId']
                    for info in container_instances['containerInstances']]
    instances = [ec2_resource.Instance(iid) for iid in instance_ids]

    for instance in instances:
        instance.load()
    instances = [instance for instance in instances
                 if instance.meta.data
                 if instance.state.get('Name') == 'running']

    for task_arn in running_task_arns:
        LOGGER.info('stopping task %s on cluster %s', task_arn, cluster_name)
        ecs.stop_task(cluster=cluster_name,
                      task=task_arn)

    if running_task_arns:
        tasks_stopped_waiter = ecs.get_waiter('tasks_stopped')
        LOGGER.info('waiting for tasks to stop')
        tasks_stopped_waiter.wait(
            cluster=cluster_name,
            tasks=running_task_arns
        )

    if instances and tasks:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        with open(key_path) as key_file:
            key = paramiko.RSAKey.from_private_key(key_file)
        ssh.connect(
            instances[0].private_ip_address,
            username='ec2-user',
            pkey=key)

        task_definition = ecs.describe_task_definition(
            taskDefinition=tasks['tasks'][0]['taskDefinitionArn'])

        for from_path, to_path in six.iteritems(mounts):
            mount_points = task_definition['taskDefinition']['containerDefinitions'][0]['mountPoints']
            source_path = None
            for mount_point in mount_points:
                if to_path == mount_point['containerPath']:
                    volume_name = mount_point['sourceVolume']
                    break
            else:
                LOGGER.info('Could not find volume source for %s!', to_path)
                continue

            volumes = task_definition['taskDefinition']['volumes']
            for volume in volumes:
                if volume['name'] == volume_name:
                    source_path = volume['host']['sourcePath']
                    break

            remote_path = 'ec2-user@%s:%s/' % (
                instance.private_ip_address, source_path)

            # docker sets file permissions as the user used inside the docker
            # container which tends to be root.
            _, stdout, _ = ssh.exec_command(
                'sudo chown ec2-user:ec2-user -R %s' %
                source_path)
            stdout.channel.recv_exit_status()

            rsync(key_path, remote_path, from_path)

        ssh.close()

    if delete_keypair:
        keypair_names = [instance.key_name for instance in instances
            if instance.key_name.startswith(cluster_name)]
        for keyname in keypair_names:
            LOGGER.info('deleting key pair %s', keyname)
            ec2.delete_key_pair(KeyName=keyname)

    for instance in instances:
        instance.terminate()

    if instances:
        LOGGER.info('waiting for instances to shut down')
        instances_terminated_waiter = ec2.get_waiter('instance_terminated')
        instances_terminated_waiter.wait(
            InstanceIds=[instance.id for instance in instances])

    if tasks:
        for task in tasks['tasks']:
            LOGGER.info('deregistering task %s', task['taskDefinitionArn'])
            ecs.deregister_task_definition(
                taskDefinition=task['taskDefinitionArn'])

    LOGGER.info('deleting cluster %s', cluster_name)
    ecs.delete_cluster(cluster=cluster_name)


def run(input_args):
    """
    Provision and boots a docker image into a container.
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
        help='Adds a volume to run the docker instance with. The folder will"\
        " be automatically transferred to the cluster instance. Conceptually"\
        " similar to the docker run --volume args.')
    parser.add_argument(
        '-e',
        '--env',
        action='append',
        default=[],
        help='Environment variables to run the docker container with."\
        " Conceptually similar to the docker --env flag.')
    parser.add_argument(
        '--cluster-name',
        required=True,
        help='Name to use for the cluster. This can be used for stopping"\
        " the cluster.')
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
        args.image,
        mounts=mounts,
        env=env,
        host_name=args.hostname,
        cluster_name=args.cluster_name,
        instance_profile=args.instance_profile,
        security_group=args.security_group,
        hosted_zone_id=args.hosted_zone_id,
        key_path=args.key)


def stop(input_args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-v',
        '--volume',
        action='append',
        default=[],
        help='if provided, the files from the provided volume will be'\
        ' transferred back from the cluster instance after the task'\
        ' has been stopped.')
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

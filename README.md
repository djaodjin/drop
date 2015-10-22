Drop is an inter-project dependencies tool that binds functionality of
source control systems, autoconf scripts, make and package managers.

There are a lot of tools orchestration and deployment to production
but very few tools to help someone configure a machine for development.
dws is just a tool.

At its core, drop helps to run multiple sequences of _dev_ commands in
topological order. ex:

    git clone _repo-1_
    ./configure
    make
    make install
    git clone _repo-2_
    ./configure
    make
    make install

is replaced by a single command:

    dws build _myproject-and-prerequisites_.xml

#############################################
###### ANSIBLE SCRIPT LAUNCH ################
#############################################

For launch Ansible scripts, you must create some resources on 
Amazon console before: 

1 - If you don't want use vpc-default in zone, create a new and update group_vars/all file,
    "vpc_id: new_vpc_id|vpc_default" 
    For this moment use, default VPC
2 - Create new private hosted Zone in route 53 console and update group_vars/all file : 
    "hosted_zone_name: hosted_zone". for example djaodjin.internal.
3 - Add hosted_zone_id in group_vars/all: 
    "hosted_zone_id: hosted_zone_id" look at the group_vars/all file for example

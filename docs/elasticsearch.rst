Assuming that you've already gone through tutorials.rst to setup
your elasticsearch instances and are uploading your logs to s3, you can setup
a cron to regularly have your logs ingested into elasticsearch.

First, you must setup permissions correctly.

1. Make sure that when you created your elasticsearch instance, you properly
   set the ansible variable es.access_policies to give access to the
   ip address of the server that will run the ingestion cron.

2. Make sure you have an IAM policy that gives your cron server s3 read access
   to your logs as well as an permisison to read and update the elasticsearch
   configuration.

   An example s3 IAM policy:
   {
    "Statement": [
        {
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Effect": "Allow",
            "Resource": [
               "* s3 arns *"
            ]
        }
    ],
    "Version": "2012-10-17"
   }

   An example elasticsearch policy:

   {
    "Statement": [
        {
            "Action": [
                "es:DescribeElasticsearchDomain",
                "es:UpdateElasticsearchDomainConfig"
            ],
            "Effect": "Allow",
            "Resource": [
               "* elasticsearch domain arn *"
            ],
            "Sid": "Stmt1475258218000"
        }
    ],
    "Version": "2012-10-17"
   }

Once the permissions are setup, we are ready to upload the logs to the Elastic
Search index but first, we need to create a persistent cache (SQLite3 database)
that will keep track of which logs have been uploaded to the index.

    $ duploades initcache


Now you can run the upload progress to start ingesting logs.

    # Upload a local log file (gzip compressed)
    $ duploades load --elasticsearch-host *elasticsearch-host* *log_path*

    # Upload a log file in a S3 bucket (through a local temporary file)
    $ duploades load --elasticsearch-host *elasticsearch-host* *log_path* \
        --location s3://*bucket*


The command is idempotent and can be run/rerun as frequently as you want logs
to be ingested.

If everything is working correctly, your logs should now be ingested
into the elasticsearch domain. You can now setup a cron to have this done
regularly and automatically.

An example cron that runs daily. Place in a file in /etc/cron.d

     SHELL=/bin/bash
     1 1 * * * <your linux user> AWS_DEFAULT_REGION='*elasticsearch aws region *' duploades load --elasticsearch-host *elasticsearch-host* --location s3://*bucket*


To download the logs from a s3 bucket to the local machine:

    $ dcopylogs --download --location s3://*bucket*/*root_dir* /var/log/gunicorn/*log_name*.log

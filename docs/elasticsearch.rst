Assuming that you've already gone through tutorials.rst to setup your elasticsearch instances
and are uploading your logs to s3, you can setup a cron to regularly have your logs ingested into elasticsearch.

First, you must setup permissions correctly.

1. Make sure that when you created your elasticsearch instance, you properly
   set the ansible variable es.access_policies to give access to the
   ip address of the server that will run the ingestion cron.

2. Make sure you have an IAM policy that gives your cron server s3 read access to your logs
   as well as an permisison to read and update the elasticsearch configuration.

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

Once you the permissions are setup, create a sqlite database to keep track
of which s3 logs you've already uploaded

    $ *VIRTUAL_ENV*/bin/python *drop*/src/duploades.py --create-db *db-path*

Now you can run the upload progress to start ingesting logs.

    $ *VIRTUAL_ENV*/bin/python *drop*/src/duploades.py --db *db-path* --s3-bucket *bucket* --s3-prefix *prefix* --elasticsearch-domain *elasticsearch domain*

The command is idempotent and can be run/rerun as frequently as you want logs to be ingested.

If everything is working correctly, your logs should now be ingested into your elasticsearch domain.
You can now setup a cron to have this done regularly and automatically.

An example cron that runs daily. Place in a file in /etc/cron.d

     SHELL=/bin/bash
     1 1 * * * <your linux user> AWS_DEFAULT_REGION='*elasticsearch aws region *' *VIRTUAL_ENV*/bin/python *drop*/src/duploades.py --db *db-path* --s3-bucket *bucket* --s3-prefix *prefix* --elasticsearch-domain *elasticsearch domain*

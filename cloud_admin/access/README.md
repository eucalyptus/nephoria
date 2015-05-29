



#### AutoCreds:

AutoCreds is a convenience class which attempt to provide utilities for reading in
credentials data from multiple sources.

The auto_create flag (set to True by default) attempts  to automatically produce credentials
based upon the information provided to this AutoCreds obj.

- If any ssh connect arguments (outside of hostname) are provided then only the remote
  machine tried for existing creds at 'self._credpath'.
- If credpath was provided the local file system will first be tried for existing
  credentials
- If aws access and secret keys were provided allong with hostname, will attempt to
  derivce service credpaths from the Eucalyptus Admin api.
- Finally if a hostname was provided an ssh attempt will be made (with any other
  connection kwargs provided)to fetch from the remote system as well.
  If password or keypath was not provided, this assumes keys have been sync'd between the
  localhost and the remote machine.

Upon the first successful discovery of credentials, the local obj is populated with
eucarc attributes and returns.

Some example usage through ipython session:

```
Import AutoCreds...
In [7]: from cloud_admin.access.autocreds import AutoCreds
```

From a remote machine..
```
In [8]: creds = AutoCreds(credpath='', hostname='10.111.5.156', password='foobar')
In [9]: creds.ec2_url
Out[9]: 'http://10.111.5.156:8773/services/compute'
```

From a local filepath:
```

In [11]: creds = AutoCreds(credpath='eucarc-10.111.5.156-eucalyptus-admin/eucarc')
In [12]: creds.s3_url
Out[12]: 'http://10.111.5.156:8773/services/objectstorage'

```

From the Eucalyptus Admin Api, access the credential values as attributes of the
AutoCreds obj such as:

```

In [21]: admin_connection = ServiceConnection(host='10.111.5.156',
                                     aws_access_key_id=creds.aws_access_key,
                                     aws_secret_key=creds.aws_secret_key)

In [22]: creds = AutoCreds(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                  hostname='10.111.5.156')

```

From root local/remote access....
```

In [23]: creds = AutoCreds(hostname='10.111.5.156', password=foobar)


```




All creds can be fetched in a dict or as attributes of the AutoCreds object:
```
In [24]: creds.get_eucarc_attrs()
Out[24]:
{'aws_access_key': 'AKIAAAI765C6PIO7QMS7',
 'aws_auto_scaling_url': 'http://10.111.5.156:8773/services/AutoScaling',
 'aws_cloudformation_url': 'http://10.111.5.156:8773/services/CloudFormation',
 'aws_cloudwatch_url': 'http://10.111.5.156:8773/services/CloudWatch',
 'aws_credential_file': None,
 'aws_elb_url': 'http://10.111.5.156:8773/services/LoadBalancing',
 'aws_iam_url': 'http://10.111.5.156:8773/services/Euare',
 'aws_secret_key': 'lqi6Bp6hHAIwkXwicRyDKxHDckr2vrnDd7I1xu6d',
 'aws_simpleworkflow_url': 'http://10.111.5.156:8773/services/SimpleWorkflow',
 'ec2_access_key': 'AKIAAAI765C6PIO7QMS7',
 'ec2_account_number': None,
 'ec2_cert': None,
 'ec2_jvm_args': None,
 'ec2_private_key': None,
 'ec2_secret_key': 'lqi6Bp6hHAIwkXwicRyDKxHDckr2vrnDd7I1xu6d',
 'ec2_url': 'http://10.111.5.156:8773/services/compute',
 'ec2_user_id': None,
 'euare_url': 'http://10.111.5.156:8773/services/Euare',
 'eucalyptus_cert': None,
 'eustore_url': 'http://emis.eucalyptus.com/',
 's3_url': 'http://10.111.5.156:8773/services/objectstorage',
 'token_url': 'http://10.111.5.156:8773/services/Tokens'}

# Credentials attributes are accessible as local attributes of the AutoCreds object:
In [24]: print creds.aws_access_key
AKIAAAI765C6PIO7QMS7

In [25]: creds.__dict__.get('ec2_user_id')
Out[25]: '000245264304'
```


 # For easy viewing, they can be shown in table format as well:
```
In [26]: creds.show()
[2015-05-18 15:47:12,249] [AutoCreds] [DEBUG]:
+------------------------+--------------------------------------------------+
| ec2_account_number     | None                                             |
+------------------------+--------------------------------------------------+
| euare_url              | http://10.111.5.156:8773/services/Euare          |
+------------------------+--------------------------------------------------+
| ec2_user_id            | None                                             |
+------------------------+--------------------------------------------------+
| token_url              | http://10.111.5.156:8773/services/Tokens         |
+------------------------+--------------------------------------------------+
| ec2_url                | http://10.111.5.156:8773/services/compute        |
+------------------------+--------------------------------------------------+
| aws_elb_url            | http://10.111.5.156:8773/services/LoadBalancing  |
+------------------------+--------------------------------------------------+
| aws_cloudformation_url | http://10.111.5.156:8773/services/CloudFormation |
+------------------------+--------------------------------------------------+
| aws_secret_key         | lqi6Bp6hHAIwkXwicRyDKxHDckr2vrnDd7I1xu6d         |
+------------------------+--------------------------------------------------+
| aws_cloudwatch_url     | http://10.111.5.156:8773/services/CloudWatch     |
+------------------------+--------------------------------------------------+
| eucalyptus_cert        | None                                             |
+------------------------+--------------------------------------------------+
| s3_url                 | http://10.111.5.156:8773/services/objectstorage  |
+------------------------+--------------------------------------------------+
| aws_iam_url            | http://10.111.5.156:8773/services/Euare          |
+------------------------+--------------------------------------------------+
| aws_simpleworkflow_url | http://10.111.5.156:8773/services/SimpleWorkflow |
+------------------------+--------------------------------------------------+
| ec2_jvm_args           | None                                             |
+------------------------+--------------------------------------------------+
| ec2_private_key        | None                                             |
+------------------------+--------------------------------------------------+
| ec2_access_key         | AKIAAAI765C6PIO7QMS7                             |
+------------------------+--------------------------------------------------+
| ec2_secret_key         | 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         |
+------------------------+--------------------------------------------------+
| aws_access_key         | AKIAAAI765C6PIO7QMS7                             |
+------------------------+--------------------------------------------------+
| eustore_url            | http://emis.eucalyptus.com/                      |
+------------------------+--------------------------------------------------+
| aws_credential_file    | None                                             |
+------------------------+--------------------------------------------------+
| ec2_cert               | None                                             |
+------------------------+--------------------------------------------------+
| aws_auto_scaling_url   | http://10.111.5.156:8773/services/AutoScaling    |
+------------------------+--------------------------------------------------+
| UNPARSED LINES         | None                                             |
+------------------------+--------------------------------------------------+)
```
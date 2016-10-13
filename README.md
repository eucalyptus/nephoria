# Nephoria
Cloud Utilities and Automated Test Framework for Eucalyptus
=======
Nephoria
======================

Nephoria is an attempt to leverage existing test code to make navigating clouds, the systems they
run on, and the services they provide easier for the purpose of testing and validating cloud
related operations.

Nephoria attempts to provide the following utlities through a set of simple interfaces:
 - Linux System Administrative Utilities
 - Eucalyptus Cloud Administrative Utilities
 - User Interfaces For Common AWS and Eucalyptus Cloud Services
 - CLI Driven Testcases, Frameworks, Harness, etc..

Installation
------
Use your package manager to install package dependencies first...
    
    yum install python-setuptools gcc python-devel git libffi-devel openssl-devel readline-devel patch
    apt-get install python-setuptools gcc python-dev git libffi-devel openssl-devel readline-devel patch


Installing nephoria using pip: 

    yum install python-pip
    pip install nephoria



Installing or developing from source. Clone the code from github, make changes,  and then install or re-install  with your changes:

    git clone https://github.com/eucalyptus/nephoria.git
    cd nephoria
    [CHANGE CODE]
    python setup.py install

**See nephoria/toolkit helper scripts for more install options


Main Classes
------
The primary interface for creating tests is the TestController:

"nephoria/testcontroller" This interface provides the following:
 - Some ulitiy methods for gaining access/credentials to a specific Eucalyptus Cloud
 - sysadmin interface:
    - interacting with the Eucalyptus Empyrean interface(cloud services and properties administration)
    - interacting with the systems hosting the cloud services (linux, and/or specific backend storage, network, etc).
 - admin: The eucalyptus/admin (account/user).
 - user: a default test user (this may be removed shortly)

 "nephoria/usercontext". Objects of this class represent a cloud user. A collection of
 account/user credentials and related attributes, and cloud service endpoints. A user context will
 has cloud interfaces such as user.ec2, user.s3, which contain boto or boto3 based methods wrapped
 to provide test-check utilities often beyond the cloud api itself.


Example test cases written with this library can be found in the testcases/unstable directory of the source tree

Design
------

nephoria is designed to allow a user to quickly generate automated tests for testing a Eucalyptus or Amazon cloud.
In the case of testing a private cloud, root(like) access to a 'cloud controller' is required to validate artifacts
both in the cloud as well as in the underlying system itself. For non-system related tests cloud credentials
can be provided.


Constructor
------
```
from nephoria.testcontroller import TestController
clc_ip = '1.2.3.4'
# Create the test controller
tc = TestController(hostname=clc_ip, log_level='DEBUG')

# Test controller has some baked in utilities and
# two primary types of user interfaces; sysadmin and admin...

# sysadmin is for cloud host and cloud system administrative operations.
# sysadmin is systemconnection interface which combines the eucalyptus admin only rest interface
# with a set of connections and utlities to interact with the underlying linux hosts and backends
# which make up a Eucalyptus cloud.
tc.sysadmin.show_hosts()
tc.sysadmin.show_services()

# admin is a UserContext interface representing the 'eucalyptus/admin' account/user.
A UserContext obj is basically a key value store of credentials + cloud service
# endpoint information, combined with cloud service interfaces/connections such as user.ec2,
# user.s3, user.iam, etc. for interacting with the cloud service APIs.
tc.admin.iam.show_all_accounts()
tc.admin.ec2.show_images()
tc.admin.s3.get_bucket()

# Create a UserContext object from either a existing user on the cloud...
user = tc.get_user_by_name('testrunner', 'admin')
user.ec2.show_images()
```
=======
# Basic User interface to connect to EUCA or AWS clouds...
```
# Create a UserContext with existing; Access Key, Secret Key and the region information...
#Connect to an AWS cloud and region...
user_aws = UserContext(aws_access_key='****myaccesskey****', aws_secret_key='************mysecretkey*********',  region='us-west-1', domain='amazonaws.com')
#Connect to a Eucalyptus Cloud...
user_euca = UserContext(aws_access_key='****myaccesskey****', aws_secret_key='************mysecretkey*********',  region='', domain='myeucacloud.com')

# User has 3 interfaces to the cloud;  1)ops, 2)boto2, 3)boto3. 
# The 'ops' interfaces are intended to provide test or convienence wrappers over an underlying boto interfaces. 
# This is intended to allow specific tests or checks to be shared and repeated easilly throughout the library. 

user.ec2.*
user.ec2.boto2.*
user.ec2.boto3.*

user.iam.*
user.iam.boto2.*
user.iam.boto3.*

user.s3.*
user.s3.boto2.*
user.s3.boto3.*

...and so on...


#Examples:
Ops:
In : user_aws.ec2.get_instances()
Out: 
[Instance:i-2bf2xxxx,
 Instance:i-bbe3xxxx,
 Instance:i-0cb9xxxx]
Boto2:
In : user.ec2.boto2.get_all_instances()
Out: 
[Reservation:r-4fbfxxxx,
 Reservation:r-2fcaxxxx,
 Reservation:r-43b3xxxx,

Boto3:
In : tc.admin.ec2.boto3.client.describe_instances()
Out: 
{u'Reservations': []}
)
```


=======

# ...or easilly create a new account and/or user on the cloud...
------
```
user = tc.create_user_using_cloudadmin('newaccount', 'admin')
user.iam.show_user_summary()
instance = user.ec2.run_image()

```

Creating and Running TestCases
------
```
The primary test case class is CliTestRunner(). This class intends to provide consistent cli
driven testcases, testcase arguements, and results.
The tests typically require 1 or more of the following:

 - CLC IP
 - Calyptos Cloud Topology yml
 - Cloud user access key and secret key
 - Specific Cloud service endpoints


See the README under the testcase_utils as well
as the existing testcases in the testcases\ directory for more info.
```
Example TestCase run:
```
python load_hvm_image.py --clc 192.168.0.199 --image-url http://images.qa1/disk.img --test-list test1_check_args
...
...
...
---------------------------------------------------------------------------------------------------------------------
 -------------------------------------------------------------------------------------------------------------------
   TEST RESULTS FOR "LoadHvmImage"
 -------------------------------------------------------------------------------------------------------------------
   | RESULT:    | PASSED                                                                                         |
   | TEST NAME  | test1_check_args                                                                               |
   | TIME:      | 0                                                                                              |
   | TEST ARGS: | test1_check_args()                                                                             |
   | OUTPUT:    | None                                                                                           |
 -------------------------------------------------------------------------------------------------------------------
   | RESULT:    | NOT_RUN                                                                                        |
   | TEST NAME  | test2_create_emi                                                                               |
   | TIME:      | 1                                                                                              |
   | TEST ARGS: | test2_create_emi()                                                                             |
   | OUTPUT:    | NOT_RUN (test2_create_emi:)                                                                    |
 -------------------------------------------------------------------------------------------------------------------
   | RESULT:    | NOT_RUN                                                                                        |
   | TEST NAME  | test3_make_image_public                                                                        |
   | TIME:      | 0                                                                                              |
   | TEST ARGS: | test3_make_image_public()                                                                      |
   | OUTPUT:    | NOT_RUN (test3_make_image_public:)                                                             |
 -------------------------------------------------------------------------------------------------------------------
   | RESULT:    | NOT_RUN                                                                                        |
   | TEST NAME  | test4_tag_image                                                                                |
   | TIME:      | 0                                                                                              |
   | TEST ARGS: | test4_tag_image()                                                                              |
   | OUTPUT:    | NOT_RUN (test4_tag_image:)                                                                     |
 -------------------------------------------------------------------------------------------------------------------
   | RESULT:    | PASSED                                                                                         |
   | TEST NAME  | clean_method                                                                                   |
   | TIME:      | 0                                                                                              |
   | TEST ARGS: | clean_method()                                                                                 |
   | OUTPUT:    | None                                                                                           |
 -------------------------------------------------------------------------------------------------------------------


   LATEST RESULTS:
   -----------------------------------------------
     TOTAL   FAILED   PASSED   NOT_RUN   ELAPSED
   -----------------------------------------------
       5       0        2         3         1
   -----------------------------------------------

   ```


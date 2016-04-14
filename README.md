# Nephoria
Cloud Utilties and Automated Test Framework for Eucalyptus
=======
Nephoria (previously known as nephoria)
======================

nephoria is an attempt to leverage existing test code to make test writing faster and standardized.  

Installation
------
If easy_install is not available in your environment use your package manager to install python-setuptools
    
    yum install python-setuptools gcc python-devel git
    apt-get install python-setuptools gcc python-dev git

Installing nephoria and its dependencies is as easy as:

    easy_install nephoria

For development purposes you can then clone the code from github and then reinstall with your changes

    git clone https://github.com/eucalyptus/nephoria.git
    cd nephoria
    [CHANGE CODE]
    python setup.py install


### Branches


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

from nephoria.testcontroller import TestController
clc_ip = '1.2.3.4'
tc = TestController(hostname=clc_ip, log_level='DEBUG')
user = tc.get_user_by_name('testrunner', 'admin')
user.ec2.show_images()
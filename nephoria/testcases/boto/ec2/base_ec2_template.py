#!/usr/bin/env python
from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcontroller import TestController
import copy
import time


"""
This is intended to demonstrate some ways to write a basic test suite.

To run this test from the command line:

## First see what CLI args are provided. Note the --sample-arg added in the test vs the default
## arguments provided by the CliTestRunner Class
prompt# python run_instances.py -h

## Run the tests
prompt# python run_instances.py --clc a.b.c.d --password mypass

## Run a subset of the tests
prompt# python run_instances.py --clc a.b.c.d --test-list 'test1, test12_skip_me'


To run this test from a python shell:
prompt# ipython
In [1]: from nephoria.cloudtests.instances.run_instances import BaseEc2Template
In [2]: test = BaseEc2Template(clc='a.b.c.d', password='mypass')
In [3]: test.run()

# Or call the method directly...
In [4]: test.test1()
"""


class BaseEc2Template(CliTestRunner):

    #####################################################################################
    # Example of how to edit, add, remove the pre-baked cli arguments provided in the base
    # CliTestRunner class...
    #####################################################################################

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['vm_count'] = {'args': ['--vm-count'],
                                     'kwargs': {'help': 'Number of VMs to run',
                                                'default': 1,
                                                'type': int}}
    _DEFAULT_CLI_ARGS['instance_timeout'] = {
        'args': ['--instance-timeout'],
        'kwargs': {'help': 'Time to wait for an instance to run',
                   'default': 300,
                   'type': int}}

    #####################################################################################
    # Populate the most commonly needed test artifacts by using dynamic properties, rather
    # than in self.__init__()...
    #####################################################################################

    # Test controller is the primary interface for system, and cloud administration.
    @property
    def tc(self):
        tc = getattr(self, '__tc', None)
        if not tc:
            tc = TestController(self.args.clc,
                                password=self.args.password,
                                clouduser_name=self.args.test_user,
                                clouduser_account=self.args.test_account,
                                log_level=self.args.log_level)
            setattr(self, '__tc', tc)
        return tc

    # Tests should be explicit about creating and managing accounts/users in the test.
    # This is for both read-ability, as well as to avoid over using 'admin' and
    # 'eucalyptus/admin' accounts.
    @property
    def user(self):
        user = getattr(self, '__user', None)
        if not user:
            try:
                user = self.tc.get_user_by_name(aws_account_name=self.args.test_account,
                                                aws_user_name=self.args.test_user)
            except:
                user = self.tc.create_user_using_cloudadmin(aws_account_name=self.args.test_account,
                                                            aws_user_name=self.args.test_user)
            setattr(self, '__user', user)
        return user

    # Most tests need some sort of emi. get_emi() applies some standard filters, but many tests
    # will want to apply more filters per customer cli arguments to fetch an EMI of proper type
    @property
    def emi(self):
        emi = getattr(self, '__emi', None)
        if not emi:
            if self.args.emi:
                emi = self.user.ec2.get_emi(emi=self.args.emi)
            else:
                try:
                    emi = self.user.ec2.get_emi(location='cirros')
                except:
                    pass
                if not emi:
                    emi = self.user.ec2.get_emi()
            setattr(self, '__emi', emi)
        return emi

    @emi.setter
    def emi(self, value):
        setattr(self, '__emi', value)

    @property
    def keypair_name(self):
        keyname = getattr(self, '__keypairname', None)
        if not keyname:
            keyname = "{0}_{1}".format(self.__class__.__name__, int(time.time()))
        return keyname

    @property
    def keypair(self):
        key = getattr(self, '__keypair', None)
        if not key:
            key = self.user.ec2.get_keypair(key_name=self.keypair_name)
            setattr(self, '__keypair', key)
        return key

    @property
    def group(self):
        group = getattr(self, '__group', None)
        if not group:
            group = self.user.ec2.add_group("{0}_group".format(self.__class__.__name__))
            self.user.ec2.authorize_group(group, port=22, protocol='tcp')
            self.user.ec2.authorize_group(group,  protocol='icmp', port=-1)
            self.user.ec2.show_security_group(group)
            setattr(self, '__group', group)
        return group

    @group.setter
    def group(self, value):
        setattr(self, '__group', value)

    #####################################################################################
    # Create the test methods...
    #####################################################################################

    """
    def test1_<put your descriptive method name here>(self):
        '''
        <Your test description, test objective and keywords needed for categorizing this test>
        '''
        <put your test here...>
    """

    def clean_method(self):
        instances = getattr(self, 'instances', [])
        keypair = getattr(self, '__keypair', None)
        self.user.ec2.terminate_instances(instances)
        if keypair:
            self.user.ec2.delete_keypair(self.keypair)



if __name__ == "__main__":

    test = BaseEc2Template()
    result = test.run()
    exit(result)



#!/usr/bin/env python
from cloud_utils.log_utils import get_traceback
from cloud_admin.backends.network.eucanetd_get import EucanetdGet
from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcontroller import TestController
from boto.ec2.group import Group
from prettytable import PrettyTable
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
In [1]: from nephoria.cloudtests.instances.run_instances import RunInstances
In [2]: test = RunInstances(clc='a.b.c.d', password='mypass')
In [3]: test.run()

# Or call the method directly...
In [4]: test.test1()
"""


class XMLTimerVPC(CliTestRunner):

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


    @property
    def eucnetd(self):
        ed = getattr(self, '__ed', None)
        if not ed:
            ed = EucanetdGet(machine=self.tc.sysadmin.clc_machine)
            setattr(self, '__ed', ed)
        return ed

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

    @property
    def emi(self):
        emi = getattr(self, '__emi', None)
        if not emi:
            try:
                if self.args.emi:
                    emi = self.user.ec2.get_emi(emi=self.args.emi)
                else:
                    emi = self.user.ec2.get_emi()
                setattr(self, '__emi', emi)
            except Exception as E:
                self.log.error("{0}\nFailed to fetch EMI:{1}".format(get_traceback(), E))
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
        if value is None or isinstance(value, Group):
            setattr(self, '__group', value)
        else:
            raise ValueError('Can not set security group to type:"{0/{1}"'
                             .format(value, type(value)))


    def global_xml_check(self, ins, timeout=300, present=True):
        res_dict = {}
        for i in ins:
            i.auto_connect = True
            res_dict[i.id] = 'FAILED'

        setattr(self, 'instances', ins)

        pt = PrettyTable(['INSTANCE', 'XML TIME'])
        ed = self.eucnetd
        start = time.time()
        elapsed = 0
        while elapsed < timeout and 'FAILED' in res_dict.values():
            elapsed = int(time.time() - start)
            ed.global_xml.update()
            for instance in ins:
                self.log.debug('Looking for instance: {0} in globalxml, elapsed:{1}'
                               .format(instance.id, elapsed))
                i_xml = ed.global_xml.instances.get_by_name(instance.id)
                if present:
                    if i_xml:
                        self.log.debug('Instance: {0} present in global xml after '
                                       'elapsed:{1}'.format(instance.id, elapsed))
                        i_xml.show()
                        res_dict[instance.id] = elapsed
                    else:
                        self.log.debug('Instance: {0} not present in global xml after '
                                       'elapsed:{1}'.format(instance.id, elapsed))
                        res_dict[instance.id] = 'FAILED'
                else:
                    if i_xml:
                        self.log.debug('Instance: {0} still present in global xml after '
                                       'elapsed:{1}'.format(instance.id, elapsed))
                        res_dict[instance.id] = 'FAILED'
                        i_xml.show()

                    else:
                        self.log.debug('Instance: {0} no longer present in global xml after '
                                       'elapsed:{1}'.format(instance.id, elapsed))
                        res_dict[instance.id] = elapsed

            if 'FAILED' in res_dict.values():
                time.sleep(2)
            else:
                break
        for i, value in res_dict.iteritems():
            pt.add_row([i, value])
        self.log.info("\n{0}\n".format(pt))
        return res_dict

    #####################################################################################
    # Create the test methods...
    #####################################################################################

    def test1_run_instances_wait_for_eucanetd(self, timeout=300):
        """
        Attempts to run the number of instances provided by the vm_count param
        """
        ins = []
        if self.args.zone:
            zones = [self.args.zone]
        else:
            zones = self.user.ec2.get_zone_names()
        for x in xrange(0, self.args.vm_count):
            for zone in zones:
                i = self.user.ec2.run_image(image=self.emi, keypair=self.keypair,
                                              min=1, max=1,
                                              zone=zone, vmtype=self.args.vmtype,
                                              group=self.group,
                                              timeout=self.args.instance_timeout,
                                              monitor_to_running=False,
                                              )[0]

                ins.append(i)
        setattr(self, 'instances', ins)
        res_dict = {}
        for i in ins:
            i.auto_connect = True
            res_dict[i.id] = 'FAILED'

        setattr(self, 'instances', ins)

        res_dict = self.global_xml_check(ins, timeout=timeout, present=True)

        if 'FAILED' in res_dict.values():
            raise RuntimeError('Test Failed. XML was not found for all instances within '
                               'Timeout:{0}. See table in test output'.format(timeout))



    def test2_monitor_instances_to_running_and_connect(self, instances=None, timeout=300):
        ins = instances or getattr(self, 'instances', None)
        if ins is None:
            raise ValueError('Instances were not found to monitor or connect. '
                             'Run test1 first or provide a list of euinstances to this test')
        try:
            self.user.ec2.monitor_euinstances_to_running(ins, timeout=timeout)
        except Exception as E:
            self.log.error("{0}\nError(s) during monitor_instances_to_running: {1}"
                           .format(get_traceback(), E))


    def clean_method(self):
        timeout = 300
        instances = getattr(self, 'instances', [])
        keypair = getattr(self, '__keypair', None)
        errors =[]
        try:
            if instances:
                ins_ids = [str(x.id) for x in instances]
                self.user.ec2.connection.terminate_instances(ins_ids)
            self.user.ec2.terminate_instances(instances)
        except Exception as E:
            errors.append(E)
            self.log.error('{0}\n{1}'.format(get_traceback(), E))
        try:
            if keypair:
                self.user.ec2.delete_keypair(self.keypair)
        except Exception as E:
            errors.append(E)
            self.log.error('{0}\n{1}'.format(get_traceback(), E))
        try:
            res_dict = self.global_xml_check(instances, timeout=timeout, present=False)
            if 'FAILED' in res_dict.values():
                raise RuntimeError('Test Failed. XML was still found for terminated instances using'
                                   'Timeout:{0}. See table in test output'.format(timeout))
        except Exception as E:
            errors.append(E)
            self.log.error('{0}\n{1}'.format(get_traceback(), E))
        if errors:
            ebuf = 'Errors during cleanup...\n'
            for E in errors:
                ebuf += "{0}\n".format(E)
            raise RuntimeError(ebuf)




if __name__ == "__main__":

    test = XMLTimerVPC()
    result = test.run()
    exit(result)
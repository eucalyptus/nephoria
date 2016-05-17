#!/usr/bin/env python
#
#
# Description:  This script encompasses test cases/modules concerning instance specific behavior and
#               features for Eucalyptus.  The test cases/modules that are executed can be
#               found in the script under the "tests" list.

import copy
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from cloud_utils.net_utils.sshconnection import CommandExitCodeException
from cloud_utils.net_utils import ping
from cloud_utils.log_utils import red, get_traceback
from nephoria.testcase_utils import WaitForResultException, wait_for_result
from nephoria.aws.ec2.euinstance import EuInstance
from nephoria.testcase_utils.cli_test_runner import CliTestRunner
from nephoria.usercontext import UserContext
from nephoria.testcontroller import TestController
from nephoria.exceptions import EucaAdminRequired

from boto.ec2.group import Group
from boto.ec2.image import Image

class LegacyInstanceTestSuite(CliTestRunner):

    _CLI_DESCRIPTION = "Test the Eucalyptus EC2 instance store image functionality."

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['instance_timeout'] = {
        'args': ['--instance-timeout'],
        'kwargs': {'help': 'Time to wait for an instance to run',
                   'default': 600,
                   'type': int}}
    _DEFAULT_CLI_ARGS['user_data'] = {
        'args': ['--user-data'],
        'kwargs': {'help': 'User Data to provide to instances run in this test',
                   'default': None}}
    _DEFAULT_CLI_ARGS['instance_user'] = {
        'args': ['--instance-user'],
        'kwargs': {'help': 'Login user to use for instances in this test',
                   'default': 'root'}}
    _DEFAULT_CLI_ARGS['root_device_type'] = {
        'args': ['--root-device-type'],
        'kwargs': {'help': 'root device type to filter for when fetching an EMI. '
                           '(ie: ebs or instance-store)',
                   'default': 'instance-store'}}


    def post_init(self, *args, **kwargs):
        self._is_multicluster = None
        self._zonelist = []
        self._group = None
        self._keypair = None
        self._keypair_name = None
        self.instances = []
        self._user = None
        self._tc = None

        self.address = None
        self.volumes = []
        self.private_addressing = False
        self.current_instances = None
        self.instances_lock = threading.Lock()
        self._managed_network = None
        self._run_instance_params = None

    @property
    def run_instance_params(self):
        # Move params to property since items here may generate unnecessary
        # requests to the cloud depending on the tests to be run.
        if self._run_instance_params is None:
            self._run_instance_params={'image': self.emi,
                                       'user_data': self.args.user_data,
                                       'username': self.args.instance_user,
                                       'keypair': self.keypair.name,
                                       'group': self.group.name,
                                       'timeout': self.args.instance_timeout,
                                       'type': self.args.vmtype}
        return  self._run_instance_params

    @run_instance_params.setter
    def run_instance_params(self, params):
        params = params or {}
        if not isinstance(params, dict):
            raise ValueError('run_instance_params must be of type dict, got:"{0}/{1}"'
                             .format(params, type(params)))
        self._run_instance_params = params

    @property
    def managed_network(self):
        # Check for legacy network modes; system, static. Default to managed, edge, vpc types
        if self._managed_network is None:
            try:
                if self.tc:
                    mode_props = self.tc.sysadmin.get_properties('cluster.networkmode')
                    if mode_props:
                        mode_prop = mode_props[0]
                        if re.search("(SYSTEM|STATIC)", mode_prop.value()):
                            self._managed_network = False
                    else:
                        self.log.error('No network mode properties found for any clusters?')
            except Exception as E:
                self.log.error('{0}\nError while attempting to fetch network mode:"{1}"'
                               .format(get_traceback(), E))
            if self._managed_network is None:
                self._managed_network = True
        return self._managed_network

    @property
    def tc(self):
        tc = getattr(self, '_tc', None)
        if not tc and self.args.clc or self.args.environment_file:
            tc = TestController(hostname=self.args.clc,
                                environment_file=self.args.environment_file,
                                password=self.args.password,
                                clouduser_name=self.args.test_user,
                                clouduser_account=self.args.test_account,
                                log_level=self.args.log_level)
            setattr(self, '_tc', tc)
        return tc

    @property
    def keypair_name(self):
        keyname = getattr(self, '_keypair_name', None)
        if not keyname:
            keyname = "{0}_{1}".format(self.__class__.__name__, int(time.time()))
        return keyname

    @property
    def keypair(self):
        key = getattr(self, '_keypair', None)
        if not key:
            key = self.user.ec2.get_keypair(key_name=self.keypair_name)
            setattr(self, '_keypair', key)
        return key

    @property
    def group(self):
        group = getattr(self, '_group', None)
        if not group:
            group_name = "{0}_group".format(self.__class__.__name__)
            group = self.user.ec2.add_group(group_name)
            self.user.ec2.authorize_group(group, port=22, protocol='tcp')
            self.user.ec2.authorize_group(group,  protocol='icmp', port=-1)
            self.user.ec2.show_security_group(group)
            setattr(self, '_group', group)
        return group

    @group.setter
    def group(self, value):
        if value is None or isinstance(value, Group):
            setattr(self, '__group', value)
        else:
            raise ValueError('Can not set security group to type:"{0/{1}"'
                             .format(value, type(value)))

    @property
    def emi(self):
        emi = getattr(self, '_emi', None)
        if not emi:
            if self.args.emi:
                emi = self.user.ec2.get_emi(emi=self.args.emi)
            else:
                try:
                    self.user.ec2.get_emi(root_device_type=self.args.root_device_type,
                                          basic_image=True)
                except:
                    pass
                if not emi:
                    emi = self.user.ec2.get_emi()
            setattr(self, '_emi', emi)
        return emi

    @emi.setter
    def emi(self, value):
        if isinstance(value, basestring):
            value = self.user.ec2.get_emi(emi=value)
        if value is None or isinstance(value, Image):
            setattr(self, '_emi', value)
        else:
            raise ValueError('Could not set emi to value:"{0}/{1}"'.format(value, type(value)))

    @property
    def user(self):
        if not self._user:
            if self.args.access_key and self.args.secret_key and self.args.region:
                self._user = UserContext(aws_access_key=self.args.access_key,
                                         aws_secret_key=self.args.secret_key,
                                         region=self.args.region)
            if (self.args.clc or self.args.environment_file) and self.tc:
                self._user = self.tc.user
        return self._user

    @property
    def zonelist(self):
        if not self._zonelist:
            # create some zone objects and append them to the zonelist
            if self.args.zone:
                self._zonelist.append(self.args.zone)
                self.multicluster = False
            else:
                for zone in self.user.ec2.get_zone_names():
                    self._zonelist.append(zone)
            if not self._zonelist:
                raise RuntimeError("Could not discover an availability zone to "
                                   "perform tests in. Please specify zone")
        return self._zonelist

    @property
    def is_multicluster(self):
        if self._is_multicluster is None:
            if len(self.zonelist) > 1:
                self._multicluster = True
            else:
                self._multicluster = False
        return self._multicluster

    def set_instances(self, instances):
        self.instances_lock.acquire()
        self.current_instances = instances
        self.instances_lock.release()

    def assertTrue(self, expr, msg=None):
        """Check that the expression is true."""
        if not expr:
            msg = msg or (str(expr) + " is not true")
            raise ValueError(msg)

    def assertFalse(self, expr, msg):
        if expr:
            msg = msg or (str(expr) + " is not false")
            raise ValueError(msg)

    def clean_method(self):
        errors = []
        try:
            if self.instances:
                self.user.ec2.terminate_instances(self.instances)
        except Exception as E:
            self.log.error(red(get_traceback()))
            errors.append(E)
        try:
            if self.volumes:
                delete = []
                for volume in self.volumes:
                    volume.update()
                    if volume.status != 'deleted':
                        delete.append(volume)
                if delete:
                    self.user.ec2.delete_volumes(delete)
        except Exception as E:
            self.log.error(red(get_traceback()))
            errors.append(E)
        try:
            if self._keypair:
                self.user.ec2.delete_keypair(self.keypair)
        except Exception as E:
            self.log.error(red(get_traceback()))
            errors.append(E)
        try:
            if self._group:
                self.user.ec2.delete_group(self.group)
        except Exception as E:
            self.log.error(red(get_traceback()))
            errors.append(E)
        if errors:
            buf = "The following errors occurred during test cleanup:"
            for error in errors:
                buf += "\n{0}".format(error)
            raise RuntimeError(buf)


    def merge_dicts(self, d1, d2):
        new_d = d1.copy()
        new_d.update(d2)
        return new_d

    def run_image(self, zones=None, **additional_kwargs):
        instances = []
        instance_params = self.merge_dicts(self.run_instance_params, additional_kwargs)
        zones = zones or self.zonelist
        if not isinstance(zones, list):
            zones = [zones]
        for zone in zones:
            instance_params['zone'] = zone
            instances += self.user.ec2.run_image(**instance_params)
            with self.instances_lock:
                self.instances += instances
        return instances

    def test1_BasicInstanceChecks(self, zone=None):
        """
        This case was developed to run through a series of basic instance tests.
             The tests are as follows:
                   - execute run_instances command
                   - make sure that public DNS name and private IP aren't the same
                       (This is for Managed/Managed-NOVLAN networking modes)
                   - test to see if instance is ping-able
                   - test to make sure that instance is accessible via ssh
                       (ssh into instance and run basic ls command)
             If any of these tests fail, the test case will error out, logging the results.
        """
        instances = self.run_image(zone=zone, **self.run_instance_params)
        self.instances += instances
        for instance in instances:
            if instance.virtualization_type == "paravirtual":
                paravirtual_ephemeral = "/dev/" + instance.rootfs_device + "2"
                try:
                    instance.sys("ls -1 " + paravirtual_ephemeral, code=0)
                    self.log.debug('Found ephemeral storage at: "{0}"'
                                   .format(paravirtual_ephemeral))
                except CommandExitCodeException as CE:
                    self.log.error(red("Did not find ephemeral storage at " +
                                       paravirtual_ephemeral))
            elif instance.virtualization_type == "hvm" and instance.ins1.root_device_type != 'ebs':
                hvm_ephemeral = "/dev/" + instance.block_device_prefix + "b"
                try:
                    instance.sys("ls -1 " + hvm_ephemeral, code=0)
                except CommandExitCodeException as CE:
                    self.log.error(red("Did not find ephemeral storage at " + hvm_ephemeral))
                    raise CE
            self.log.debug("Pinging instance public IP from inside instance")
            instance.sys('ping -c 1 ' + instance.ip_address, code=0)
            self.log.debug("Pinging instance private IP from inside instance")
            instance.sys('ping -c 1 ' + instance.private_ip_address, code=0)
        self.set_instances(instances)
        return instances

    def test2_DNSResolveCheck(self):
        """
        This case was developed to test DNS resolution information for public/private DNS
        names and IP addresses.  The tested DNS resolution behavior is expected to follow

        AWS EC2.  The following tests are ran using the associated meta-data attributes:
           - check to see if Eucalyptus Dynamic DNS is configured
           - nslookup on hostname; checks to see if it matches local-ipv4
           - nslookup on local-hostname; check to see if it matches local-ipv4
           - nslookup on local-ipv4; check to see if it matches local-hostname
           - nslookup on public-hostname; check to see if it matches local-ipv4
           - nslookup on public-ipv4; check to see if it matches public-host
        If any of these tests fail, the test case will error out; logging the results.
        """
        if not self.current_instances:
            instances = self.run_image()
        else:
            instances = self.current_instances

        def install_bind_utils_on_instance(instance):
            try:
                instance.sys('which nslookup', code=0)
                return
            except CommandExitCodeException:
                pass
            instance.package_manager.install('bind-utils')

        def validate_instance_dns(self=self):
            try:
                for instance in instances:
                    if not re.search("internal", instance.private_dns_name):
                        self.user.ec2.debug("Did not find instance DNS enabled, skipping test")
                        self.set_instances(instances)
                        return instances
                    self.log.debug('\n'
                               '# Test to see if Dynamic DNS has been configured \n'
                               '# Per AWS standard, resolution should have private hostname or '
                               'private IP as a valid response\n'
                               '# Perform DNS resolution against public IP and public DNS name\n'
                               '# Perform DNS resolution against private IP and private DNS name\n'
                               '# Check to see if nslookup was able to resolve\n')
                    assert isinstance(instance, EuInstance)
                    install_bind_utils_on_instance(instance)
                    self.log.debug('Check nslookup to resolve public DNS Name to local-ipv4 address')
                    self.assertTrue(
                        instance.found("nslookup " + instance.public_dns_name,
                                       instance.private_ip_address),
                        "Incorrect DNS resolution for hostname.")
                    self.log.debug('Check nslookup to resolve public-ipv4 '
                                   'address to public DNS name')
                    if self.managed_network:
                        self.assertTrue(instance.found("nslookup " + instance.ip_address,
                                                       instance.public_dns_name),
                                        "Incorrect DNS resolution for public IP address")
                    self.log.debug('Check nslookup to resolve private DNS Name to local-ipv4 address')
                    if self.managed_network:
                        self.assertTrue(instance.found("nslookup " + instance.private_dns_name,
                                                       instance.private_ip_address),
                                        "Incorrect DNS resolution for private hostname.")
                    self.log.debug('Check nslookup to resolve local-ipv4 address to private DNS name')
                    self.assertTrue(instance.found("nslookup " + instance.private_ip_address,
                                                   instance.private_dns_name),
                                    "Incorrect DNS resolution for private IP address")
                    self.log.debug('Attempt to ping instance public_dns_name')
                    self.assertTrue(ping(instance.public_dns_name))
                    return True
            except Exception, e:
                self.log.error('{0}\nValidate_instance_dns error:"{1}"'.format(get_traceback(), e))
                return False
        wait_for_result(validate_instance_dns, True, timeout=120, )
        self.set_instances(instances)
        return instances

    def test3_Reboot(self):
        """
        This case was developed to test IP connectivity and volume attachment after
        instance reboot.  The following tests are done for this test case:
                   - creates a 1 gig EBS volume, then attach volume
                   - reboot instance
                   - attempts to connect to instance via ssh
                   - checks to see if EBS volume is attached
                   - detaches volume
                   - deletes volume
        If any of these tests fail, the test case will error out; logging the results.
        """
        if not self.current_instances:
            instances = self.run_image()
        else:
            instances = self.current_instances
        for instance in instances:
            ### Create 1GB volume in first AZ
            volume = self.user.ec2.create_volume(instance.placement, size=1, timepergig=180)
            self.volumes.append(volume)
            instance.attach_volume(volume)
            ### Reboot instance
            instance.reboot_instance_and_verify(waitconnect=20)
            instance.detach_euvolume(volume)
            self.user.ec2.delete_volume(volume)
        self.set_instances(instances)
        return instances

    def test4_MetaData(self):
        """
        This case was developed to test the metadata service of an instance for consistency.
        The following meta-data attributes are tested:
           - public-keys/0/openssh-key
           - security-groups
           - instance-id
           - local-ipv4
           - public-ipv4
           - ami-id
           - ami-launch-index
           - instances-id
           - placement/availability-zone
           - kernel-id
           - public-hostname
           - local-hostname
           - hostname
           - ramdisk-id
           - instance-type
           - any bad metadata that shouldn't be present.
        Missing nodes
         ['block-device-mapping/',  'ami-manifest-path']
        If any of these tests fail, the test case will error out; logging the results.
        """
        if not self.current_instances:
            instances = self.run_image(**self.run_instance_params)
        else:
            instances = self.current_instances
        for instance in instances:
            ## Need to verify  the public key (could just be checking for a string of a certain length)
            self.assertTrue(re.match(instance.get_metadata(
                "public-keys/0/openssh-key")[0].split('eucalyptus.')[-1],
                                     self.keypair.name),
                            'Incorrect public key in metadata')
            self.assertTrue(re.match(instance.get_metadata("security-groups")[0], self.group.name),
                            'Incorrect security group in metadata')
            # Need to validate block device mapping
            #self.assertTrue(re.search(instance_ssh.get_metadata("block-device-mapping/")[0], ""))
            self.assertTrue(re.match(instance.get_metadata("instance-id")[0], instance.id),
                            'Incorrect instance id in metadata')
            self.assertTrue(re.match(instance.get_metadata("local-ipv4")[0],
                                     instance.private_ip_address),
                            'Incorrect private ip in metadata')
            self.assertTrue(re.match(instance.get_metadata("public-ipv4")[0], instance.ip_address),
                            'Incorrect public ip in metadata')
            self.assertTrue(re.match(instance.get_metadata("ami-id")[0], instance.image_id),
                            'Incorrect ami id in metadata')
            self.assertTrue(re.match(instance.get_metadata("ami-launch-index")[0],
                                     instance.ami_launch_index),
                            'Incorrect launch index in metadata')
            self.assertTrue(re.match(instance.get_metadata("reservation-id")[0],
                                     instance.reservation.id),
                            'Incorrect reservation-id in metadata')
            self.assertTrue(re.match(
                instance.get_metadata("placement/availability-zone")[0],  instance.placement),
                'Incorrect availability-zone in metadata')
            if self.emi.virtualization_type == "paravirtual":
                self.assertTrue(re.match(instance.get_metadata("kernel-id")[0], instance.kernel),
                                'Incorrect kernel id in metadata')
                self.assertTrue(re.match(instance.get_metadata("ramdisk-id")[0], instance.ramdisk),
                                'Incorrect ramdisk in metadata')
            self.assertTrue(re.match(instance.get_metadata("public-hostname")[0],
                                     instance.public_dns_name),
                            'Incorrect public host name in metadata')
            self.assertTrue(re.match(instance.get_metadata("local-hostname")[0],
                                     instance.private_dns_name),
                            'Incorrect private host name in metadata')
            self.assertTrue(re.match(instance.get_metadata("hostname")[0],
                                     instance.private_dns_name),
                            'Incorrect host name in metadata')
            self.assertTrue(re.match(instance.get_metadata("instance-type")[0],
                                     instance.instance_type),
                            'Incorrect instance type in metadata')
            bad_meta_data_keys = ['foobar']
            for key in bad_meta_data_keys:
                self.assertTrue(re.search("Not Found", "".join(instance.get_metadata(key))),
                                'No fail message on invalid meta-data node')
        self.set_instances(instances)
        return instances

    def test5_ElasticIps(self):
        """
       This case was developed to test elastic IPs in Eucalyptus. This test case does
       not test instances that are launched using private-addressing option.
       The test case executes the following tests:
           - allocates an IP, associates the IP to the instance, then pings the instance.
           - disassociates the allocated IP, then pings the instance.
           - releases the allocated IP address
       If any of the tests fail, the test case will error out, logging the results.
        """
        if not self.current_instances:
            instances = self.run_image(**self.run_instance_params)
        else:
            instances = self.current_instances

        for instance in instances:
            if instance.ip_address == instance.private_ip_address:
                self.log.warning("WARNING: System or Static mode detected, skipping ElasticIps")
                return instances
            domain = None
            if instance.vpc_id:
                domain = 'vpc' # Set domain to 'vpc' for use with instance in a VPC
            self.address = self.user.ec2.allocate_address(domain=domain)
            self.assertTrue(self.address, 'Unable to allocate address')
            self.user.ec2.associate_address(instance, self.address)
            instance.update()
            self.assertTrue(ping(instance.ip_address),"Could not ping instance with new IP")
            self.user.ec2.disassociate_address_from_instance(instance)
            self.user.ec2.release_address(self.address)
            self.address = None
            assert isinstance(instance, EuInstance)
            time.sleep(5)
            instance.update()
            self.assertTrue(ping(instance.ip_address),
                            "Could not ping after dissassociate")
        self.set_instances(instances)
        return instances

    def test6_MultipleInstances(self):
        """
        This case was developed to test the maximum number of m1.small vm types a configured
        cloud can run.  The test runs the maximum number of m1.small vm types allowed, then
        tests to see if all the instances reached a running state.  If there is a failure,
        the test case errors out; logging the results.
        """
        if self.current_instances:
            self.user.ec2.terminate_instances(self.current_instances)
            self.set_instances(None)

        instances = self.run_image(min=2, max=2, **self.run_instance_params)
        self.set_instances(instances)
        return instances


    def test7_LargestInstance(self):
        """
        This case was developed to test the maximum number of c1.xlarge vm types a configured
        cloud can run.  The test runs the maximum number of c1.xlarge vm types allowed, then
        tests to see if all the instances reached a running state.  If there is a failure,
        the test case errors out; logging the results.
        """
        if self.current_instances:
            self.user.ec2.terminate_instances(self.current_instances)
            self.set_instances(None)
        params = copy.copy(self.run_instance_params)
        params['type'] = 'c1.xlarge'
        instances = self.run_image(**params)
        self.set_instances(instances)
        return instances

    def test8_PrivateIPAddressing(self):
        """
        This case was developed to test instances that are launched with private-addressing
        set to True.  The tests executed are as follows:
            - run an instance with private-addressing set to True
            - allocate/associate/disassociate/release an Elastic IP to that instance
            - check to see if the instance went back to private addressing
        If any of these tests fail, the test case will error out; logging the results.
        """
        if self.current_instances:
            for instance in self.current_instances:
                if instance.ip_address == instance.private_ip_address:
                    self.user.ec2.debug("WARNING: System or Static mode detected, skipping "
                                      "PrivateIPAddressing")
                    return self.current_instances
            self.user.ec2.terminate_instances(self.current_instances)
            self.set_instances(None)
        instances = self.run_image(private_addressing=True,
                                            auto_connect=False,
                                            **self.run_instance_params)
        for instance in instances:
            address = self.user.ec2.allocate_address()
            self.assertTrue(address, 'Unable to allocate address')
            self.user.ec2.associate_address(instance, address)
            self.log.info('Sleeping for 30 seconds to allow for association')
            time.sleep(30)
            instance.update()
            self.log.debug('Attempting to ping associated IP:"{0}"'.format(address.public_ip))
            self.assertTrue(ping(instance.ip_address),
                            "Could not ping instance with new IP")
            self.log.debug('Disassociating address:{0} from instance:{1}'.format(address.public_ip,
                                                                             instance.id))
            address.disassociate()
            self.log.info('Sleeping for 30 seconds to allow for disassociation')
            time.sleep(30)
            instance.update()
            self.log.debug('Confirming disassociated IP:"{0}" is no longer in use'
                       .format(address.public_ip))
            def wait_for_ping():
                return ping(address.public_ip, poll_count=1)
            try:
                wait_for_result(callback=wait_for_ping, result=False)
            except WaitForResultException as WE:
                self.log.error("Was able to ping address:'{0}' that should no long be associated "
                               "with an instance".format(address.public_ip))
                raise WE
            address.release()
            if instance.ip_address:
                if (instance.ip_address != "0.0.0.0" and
                            instance.ip_address != instance.private_ip_address):
                    raise RuntimeError("Instance:'{0}' received a new public IP:'{0}' "
                                       "after disassociate"
                                       .format(instance.id, instance.ip_address))
        self.user.ec2.terminate_instances(instances)
        self.set_instances(instances)
        return instances

    def test9_Churn(self):
        """
        This case was developed to test robustness of Eucalyptus by starting instances,
        stopping them before they are running, and increase the time to terminate on each
        iteration.  This test case leverages the BasicInstanceChecks test case. The
        following steps are ran:
            - runs BasicInstanceChecks test case 5 times, 10 second apart.
            - While each test is running, run and terminate instances with a 10sec sleep in between.
            - When a test finishes, rerun BasicInstanceChecks test case.
        If any of these tests fail, the test case will error out; logging the results.
        """
        if self.current_instances:
            self.user.ec2.terminate_instances(self.current_instances)
            self.set_instances(None)
        try:
            most = {'zone': "", 'count': 0}
            for zone in self.zonelist:
                user = self.user
                if self.tc:
                    user = self.tc.admin
                zone_availability = user.ec2.get_available_vm_slots(vmtype=self.args.vmtype,
                                                                    zone_name=zone)
                if zone_availability > most.get('count'):
                    most['zone'] = zone
                    most['count'] = zone_availability
            zone = most.get('zone')
            available_instances_before = most.get('count')
            # Limit this test...
            if available_instances_before > 4:
                count = 4
            else:
                count = available_instances_before
        except EucaAdminRequired:
            self.log.warning("Running as non-admin, defaulting to 4 VMs")
            available_instances_before = count = 4

        future_instances = []

        with ThreadPoolExecutor(max_workers=count) as executor:
            ## Start asynchronous activity
            ## Run 5 basic instance check instances 10s apart
            for i in xrange(count):
                future_instances.append(executor.submit(self.test1_BasicInstanceChecks, zone=zone))
                time.sleep(10)

        with ThreadPoolExecutor(max_workers=count) as executor:
            ## Start asynchronous activity
            ## Terminate all instances
            for future in future_instances:
                executor.submit(self.user.ec2.terminate_instances, future.result())

        def available_after_greater():
            try:
                if self.tc:
                    user = self.tc.admin
                else:
                    user = self.user
                return user.ec2.get_available_vm_slots(
                    vmtype=self.args.vmtype, zone_name=zone) >= available_instances_before
            except EucaAdminRequired:
                self.log.warning("Running as non-admin, skipping validation of available VMs.")
                return True
        wait_for_result(available_after_greater, result=True, timeout=360)

    def ReuseAddresses(self):
        """
        This case was developed to test when you run instances in a series, and make sure
        they get the same address.  The test launches an instance, checks the IP information,
        then terminates the instance. This test is launched 5 times in a row.  If there
        is an error, the test case will error out; logging the results.
        """
        prev_address = None
        if self.current_instances:
            self.user.ec2.terminate_instances(self.current_instances)
            self.set_instances(None)
        for i in xrange(5):
            instances = self.run_image()
            for instance in instances:
                if prev_address is not None:
                    self.assertTrue(re.search(str(prev_address), str(instance.ip_address)),
                                    str(prev_address) +
                                        " Address did not get reused but rather  " +
                                        str(instance.public_dns_name))
                prev_address = instance.ip_address
            self.user.ec2.terminate_instances(instances)

    def BundleInstance(self):
        """
        Bundle a running instance(s).
        Register new image, run the image and verify.

        """
        if not self.current_instances:
            self.current_instances = self.run_image()
        original_image = self.run_instance_params['image']
        for instance in self.current_instances:
            current_time = str(int(time.time()))
            temp_file = "/root/my-new-file-" + current_time
            instance.sys("touch " + temp_file)
            self.log.info('Sleeping for 60 seconds to allow for bundle operation')
            time.sleep(60)
            starting_uptime = instance.get_uptime()
            self.run_instance_params['image'] = \
                self.user.ec2.bundle_instance_monitor_and_register(instance)
            instance.connect_to_instance()
            ending_uptime = instance.get_uptime()
            if ending_uptime > starting_uptime:
                raise RuntimeError("Instance did not get stopped then started")
            bundled_image_instances = self.run_image()
            for new_instance in bundled_image_instances:
                new_instance.sys("ls " + temp_file, code=0)
            self.user.ec2.terminate_instances(bundled_image_instances)
        self.run_instance_params['image'] = original_image

if __name__ == "__main__":
    test = LegacyInstanceTestSuite()
    result = test.run()
    exit(result)
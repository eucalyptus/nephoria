



# todo This test is in development and may not be working as of 4/27/16

"""
Original approach was to do a test matrix generator. The current method has the intention of
supporting the following parameters in a test. Each parameter has a dictionary which defines the
set of possible values for that parameter. The most basic subset of values will end up being
several hundred test points.

def packet_test_scenario(self, zone1, zone2, sec_group1, sec_group_2, vpc1, vpc2, subnet1,
subnet2, use_private, protocol, pkt_count=5, retries=2, verbose=None):

Some examples of defined parameter ranges to be iterator over so all combinations
can be fed to the test generator. (This is just a small subnet):

addressing = {'public': True, 'private': True, 'eip': True}
vpc1 = self.default_vpc
vpc2 = self.get_test_vpcs(count=1)[0]
protocols = {'ICMP': {'protocol': ICMP, 'count': pkt_count},
             'TCP': {'protocol': TCP, 'count': pkt_count, 'bind': True},
             'UDP': {'protocol': UDP, 'count': pkt_count},
             'SCTP': {'protocol': SCTP, 'count': pkt_count, 'bind': True}}
vpc1_sec_group1, vpc1_sec_group2 = self.get_test_security_groups(vpc=vpc1, count=2, rules=[])
vpc2_sec_group1, vpc2_sec_group2 = self.get_test_security_groups(vpc=vpc2, count=2, rules=[]
Zones = self.user.ec2.get_zone_names()
Vmtypes = ['c1.medium']
subnet1 = self.default_subnet
subnet2 = get_test_subnets(count=1)[0]
eni_count =??
eni_network = ??
ingress/egress options for protocols = ['allow_per_protocol', 'allow_per_group', 'deny_per_proto',
                                        'deny_per_port', 'deny_per_group']

"""

from nephoria.testcontroller import TestController
from nephoria.usercontext import UserContext
from nephoria.testcase_utils.cli_test_runner import CliTestRunner, TestResult, SkipTestException
from nephoria.aws.ec2.euinstance import EuInstance
from cloud_utils.net_utils import packet_test, is_address_in_network, test_port_status
from cloud_utils.net_utils.sshconnection import CommandExitCodeException
from cloud_utils.log_utils import markup, printinfo, get_traceback, red, ForegroundColor, \
    BackGroundColor
from boto.exception import BotoServerError, EC2ResponseError
from boto.vpc.subnet import Subnet
from boto.vpc.vpc import VPC
from boto.ec2.image import Image
from boto.ec2.group import Group
from boto.ec2.securitygroup import SecurityGroup
from random import randint
import socket
from prettytable import PrettyTable
import copy
import re
import time
from os.path import basename

ICMP = 1
TCP = 6
UDP = 17
SCTP = 132


import __builtin__
openfiles = set()
oldfile = __builtin__.file

def printOpenFiles():
    print red("\n\n### %d OPEN FILES: [%s]\n\n" % (len(openfiles), ", ".join(f.x for f in openfiles)))

class newfile(oldfile):
    def __init__(self, *args):
        self.x = args[0]
        print red("### OPENING %s ###" % str(self.x))
        oldfile.__init__(self, *args)
        openfiles.add(self)
        printOpenFiles()

    def close(self):
        print red("### CLOSING %s ###" % str(self.x))
        oldfile.close(self)
        openfiles.remove(self)
        printOpenFiles()

oldopen = __builtin__.open
def newopen(*args):
    return newfile(*args)
__builtin__.file = newfile
__builtin__.open = newopen

class VpcBasics(CliTestRunner):

    _CLI_DESCRIPTION = "Test the Eucalyptus EC2 instance store image functionality."

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    DEFAULT_SG_RULES =  [('tcp', 22, 22, '0.0.0.0/0'), ('icmp', -1, -1, '0.0.0.0/0')]
    _DEFAULT_CLI_ARGS['vpc_cidr'] = {
        'args': ['--vpc-cidr'],
        'kwargs': {'help': 'Cidr network range for VPC(s) created in this test',
                   'default': "172.{0}.0.0/16"}}

    _DEFAULT_CLI_ARGS['proxy_vmtype'] = {
        'args': ['--proxy-vmtype'],
        'kwargs': {'help': 'Vm type to use for proxy test instance',
                   'default': 'm1.large'}}

    SUBNET_TEST_TAG = "SUBNET_TEST_TAG"
    SECURITY_GROUP_TEST_TAG = "SECURITY_GROUP_TEST_TAG"
    ENI_TEST_TAG = 'ENI_TEST_TAG'
    ROUTE_TABLE_TEST_TAG = 'ROUTE_TABLE_TEST_TAG'

    def post_init(self):
        self.test_id = "{0}{1}".format(int(time.time()), randint(0, 50))
        self.id = str(int(time.time()))
        self.test_name = self.__class__.__name__
        self._tc = None
        self._group = None
        self._zonelist = []
        self._keypair = None
        self._keypair_name = None
        self._emi = None
        self._user = None
        self._addresses = []
        self._test_vpcs = []
        self._proxy_instances = {}
        self._security_groups = {}
        self._test_enis = {}


    @property
    def tc(self):
        tc = getattr(self, '_tc', None)
        if not tc and self.args.clc or self.args.environment_file:
            tc = TestController(hostname=self.args.clc,
                                environment_file=self.args.environment_file,
                                password=self.args.password,
                                log_level=self.args.log_level)
            setattr(self, '_tc', tc)
        return tc

    @property
    def my_tag_name(self):
        return '{0}_CREATED_TESTID'.format(self.__class__.__name__)

    def get_proxy_instance(self, zone, user=None):
        user = user or self.user
        if not zone:
            raise ValueError('Must provide zone for get_proxy_instance. Got:"{0}"'.format(zone))
        proxy_instances = getattr(self, '_proxy_instances', {})
        pi =  proxy_instances.get(zone, None)
        if pi:
            try:
                pi.update()
                if pi.status != "running":
                    try:
                        pi.terminate()
                    except:
                        pass
                    pi = None
            except Exception as E:
                self.log.debug('{0}\nIgnoring error caught while fetching proxy instance '
                               'status:"{1}'.format(get_traceback(), E))
                pi = None
        if not pi:
            subnet = user.ec2.get_default_subnets(zone=zone)
            if not subnet:
                raise ValueError('No default subnet for zone:{0} to create proxy instance in'
                                 .format(zone))
            subnet = subnet[0]
            pi = user.ec2.run_image(image=self.emi, keypair=self.get_keypair(user),
                                         group=self.group,
                                         subnet_id = subnet.id, zone=zone,
                                         type=self.args.proxy_vmtype,
                                         systemconnection=self.tc.sysadmin)[0]
            proxy_instances[zone] = pi
            self._proxy_instances = proxy_instances
        return pi

    def get_test_enis_for_subnet(self, subnet, status='available', count=0, user=None):
        """
        Attempts to fetch enis for a given subnet which are tagged with self.test_tag_name and
        self.id.
        If a count is provided and the status filter value is 'available', then an existing
        number of enis tagged with this test's tag in the available state will be returned.
        If less than count are found, new enis will be created until 'count' number
        of enis can be returned.

        Args:
            subnet: boto subnet obj or string subnet id
            status: 'available', 'in-use', or None
            count: Int, number of test ENIs to fetch
            returns list of ENIs
        """
        user = user or self.user
        if count and status != 'available':
            raise ValueError('Count argument can only be used with status "available" got: '
                             'count:{0}, status:{1}'.format(count, status))
        if isinstance(subnet, basestring):
            orig_sub = subnet
            subnet = user.ec2.get_subnet(subnet)
            if not subnet:
                raise ValueError('get_eni_for_subnet: Could not find subnet for "{0}"'
                                 .format(orig_sub))
        if not isinstance(subnet, Subnet):
            raise ValueError('Must provide type Subnet() or subnet id for get_eni_subnet. '
                             'Got:"{0}"'.format(subnet))
        filters = {'subnet-id': subnet.id, 'tag-key': self.my_tag_name, 'tag-value': self.id}
        if status:
            filters['status'] = status
        enis = user.ec2.connection.get_all_network_interfaces(filters=filters) or []
        if count and len(enis) < count:
            for x in xrange(0, (count-len(enis))):
                eni = user.ec2.connection.create_network_interface(
                    subnet_id=subnet.id, description='This was created by: {0}'.format(self.id))
                user.ec2.create_tags(eni.id, {self.my_tag_name: self.id})
                eni.update()
                enis.append(eni)
        return enis

    def add_subnet_interface_to_proxy_vm(self, subnet):
        pass

    @property
    def keypair_name(self):
        keyname = getattr(self, '_keypair_name', None)
        if not keyname:
            keyname = "{0}_{1}".format(self.__class__.__name__, int(time.time()))
        return keyname

    def get_keypair(self, user=None):
        user = user or self.user
        keys = getattr(self, '_keypairs', None)
        if not keys:
            key = user.ec2.get_keypair(key_name=self.keypair_name)
            keys = {user: key}
            setattr(self, '_keypairs', keys)
        return keys[user]

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
                emi = self.user.ec2.get_images(emi=self.args.emi)
                if emi and isinstance(emi, list):
                    emi = emi[0]
            else:
                try:
                    emi = self.user.ec2.get_emi(basic_image=True)
                except:
                    pass
                if not emi:
                    emi = self.user.ec2.get_emi(basic_image=False)
            emi = emi or None
            setattr(self, '_emi', emi)
        return emi

    @emi.setter
    def emi(self, value):
        if isinstance(value, basestring):
            value = self.user.ec2.get_images(emi=self.args.emi)
            if value and isinstance(value, list):
                value = value[0]
        if value is None or isinstance(value, Image):
            setattr(self, '_emi', value)
        else:
            raise ValueError('Could not set emi to value:"{0}/{1}"'.format(value, type(value)))

    @property
    def new_ephemeral_user(self):
        account_prefix = 'vpcnewuser'
        attr_name = '_new_ephemeral_user'
        user = getattr(self, attr_name, None)
        if not user:
            accounts = [x.get('account_name') for x in self.tc.admin.iam.get_all_accounts()]
            for x in xrange(0, 1000):
                account_name = "{0}{1}".format(account_prefix, x)
                user_name = 'admin'
                if not account_name in accounts:
                    self.log.debug('Creating a new account for this test: {0}'
                                   .format(account_name))
                    user = self.tc.create_user_using_cloudadmin(aws_account_name=account_name,
                                                                aws_user_name=user_name)
                    setattr(self, attr_name, user)
                    break
        return user

    @new_ephemeral_user.setter
    def new_ephemeral_user(self, user):
        attr_name = '_new_ephemeral_user'
        if user is None or isinstance(user, UserContext):
            setattr(self, attr_name, user)

    @property
    def user(self):
        if not self._user:
            if self.args.access_key and self.args.secret_key and self.args.region:
                self._user = UserContext(aws_access_key=self.args.access_key,
                                         aws_secret_key=self.args.secret_key,
                                         region=self.args.region)
            if (self.args.clc or self.args.environment_file) and self.tc:
                users = self.tc.admin.iam.get_all_users()
                for user in users:
                    if user.get('account_name') == self.args.test_account and \
                        user.get('user_name') == self.args.test_user:
                        self._user = self.tc.get_user_by_name(
                            aws_user_name=self.args.test_user,
                            aws_account_name=self.args.test_account)
                        self.new_ephemeral_user = self._user
                        return self._user
                self._user = self.tc.create_user_using_cloudadmin(
                    aws_user_name=self.args.test_user, aws_account_name=self.args.test_account)
        return self._user

    @property
    def zones(self):
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
    def default_vpc(self):
        if self.user.ec2.vpc_supported:
            vpcs = self.user.ec2.get_default_vpcs()
            if not vpcs:
                raise RuntimeError('No default VPC found for user:"{0}"'.format(self.user))
            return vpcs[0]

    def create_test_vpcs(self, count=1, create_igw_per_vpc=True, starting_octet=172,
                         add_default_igw_route=True, user=None):
        user = user or self.user
        test_vpcs = []
        if not create_igw_per_vpc and add_default_igw_route:
            raise ValueError('Can not use add_default_igw_route if create_igw_per_vpc is not set')
        for vpc_count in xrange(0, count):
            # Make the new vpc cidr net in the private range based upon the number of existing VPCs
            net_octet = 1 + (250 % len(user.ec2.get_all_vpcs()))
            new_vpc = user.ec2.connection.create_vpc(cidr_block='{0}.{1}.0.0/16'
                                                     .format(starting_octet, net_octet))
            user.ec2.create_tags(new_vpc.id, {self.my_tag_name: count})
            test_vpcs.append(new_vpc)
            if create_igw_per_vpc:
                gw = user.ec2.connection.create_internet_gateway()
                user.ec2.connection.attach_internet_gateway(internet_gateway_id=gw.id,
                                                            vpc_id=new_vpc.id)
            if add_default_igw_route:
                default_rt = user.ec2.connection.get_all_route_tables(
                    filters={'association.main': 'true', 'vpc-id': new_vpc.id})[0]
                user.ec2.connection.create_route(default_rt.id, '0.0.0.0/0', gw.id)
            user.log.info('Created the following VPC: {0}'.format(new_vpc.id))
            user.ec2.show_vpc(new_vpc)
        return test_vpcs

    def create_test_subnets(self, vpc, zones=None, count_per_zone=1, user=None):
        """
        This method is intended to provided the convenience of returning a number of subnets per
        zone equal to the provided 'count_per_zone'. The intention is this method will
        take care of first attempting to re-use existing subnets, and creating new ones if needed
        to meet the count requested.

        :param vpc: boto VPC object
        :param count_per_zone: int, number of subnets needed per zone
        :return: list of subnets
        """
        user = user or self.user
        test_subnets = []
        zones = zones or self.zones
        if not isinstance(zones, list):
            zones = [zones]
        for x in xrange(0, count_per_zone):
            for zone in self.zones:
                # Use a /24 of the vpc's larger /16
                subnets = user.ec2.get_all_subnets(filters={'vpc-id': vpc.id})

                subnet_cidr = None
                attempts = 0
                while subnet_cidr is None and attempts < 253:
                    attempts += 1
                    subnet_cidr =  re.sub("(\d+.\d+).\d+.\d+.\d\d",
                                          r"\1.{0}.0/24".format(attempts), vpc.cidr_block)
                    if not subnet_cidr:
                        raise ValueError('Failed to parse subnet_cidr from vpc cidr block:{0}'
                                         .format(vpc.cidr_block))
                    for sub in subnets:
                        if sub.cidr_block == subnet_cidr or \
                                is_address_in_network(subnet_cidr.strip('/24'), sub.cidr_block):
                            self.log.info('Subnet: {0} conflicts with existing:{1}'
                                          .format(subnet_cidr, sub.cidr_block))
                            subnet_cidr = None
                            break
                try:
                    subnet = user.ec2.connection.create_subnet(vpc_id=vpc.id,
                                                               cidr_block=subnet_cidr,
                                                               availability_zone=zone)
                except:
                    try:
                        self.log.error('Existing subnets during create request:')
                        user.ec2.show_subnets(subnets, printmethod=self.log.error)
                    except:
                        pass
                    self.log.error('Failed to create subnet for vpc:{0}, cidr:{1} zone:{2}'
                                   .format(vpc.id, subnet_cidr, zone))
                    raise
                user.ec2.create_tags(subnet.id, {self.my_tag_name: x})
                test_subnets.append(subnet)
                user.log.info('Created the following SUBNET: {0}'.format(subnet.id))
                user.ec2.show_subnet(subnet)
        return test_subnets

    def get_test_vpcs(self, count=1, user=None):
        """
        This method is intended to provided the convenience of returning a number of VPCs equal
        to 'count'. The intention is this method will take care of first attempting to
        re-use existing VPCs, and creating new ones if needed to meet the count requested.

        :param count: number of VPCs requested
        :return: list of VPC boto objects
        """
        user = user or self.user
        existing = user.ec2.get_all_vpcs(filters={'tag-key': self.my_tag_name})
        if len(existing) >= count:
            return existing[0:count]
        needed = count - len(existing)
        new_vpcs = self.create_test_vpcs(count=needed, create_igw_per_vpc=1, user=user)
        ret_list = existing + new_vpcs
        return ret_list

    def get_non_default_test_subnets_for_vpc(self, vpc, zone=None, count=1, user=None):
        """
        Fetch a given number of subnets within the provided VPC by either finding existing
        or creating new subnets to meet the count requested.
        :param vpc: boto vpc object
        :param count: number of subnets requested
        :return: list of subnets
        """
        user = user or self.user
        filters = {'vpc-id': vpc.id}

        filters['defaultForAz'] = 'false'
        filters['tag-key'] = self.my_tag_name
        if zone:
            filters['availabilityZone'] = zone
            zones = [zone]
        else:
            zones = None
        existing = user.ec2.get_all_subnets(filters=filters)
        if len(existing) >= count:
            return  existing[0:count]
        needed = count - len(existing)
        new_subnets = self.create_test_subnets(vpc=vpc, zones=zones,
                                               count_per_zone=needed, user=user)
        ret_subnets = existing + new_subnets
        return ret_subnets

    def get_test_security_groups(self, vpc=None, count=1, rules=None, user=None):
        """
        Fetch a given number of security groups by either finding existing or creating new groups
        to meet the count requested. If VPC is not provided, self.default_vpc value will be used.
        Any existing rules within the group will be removed and then replaced with the rules
        provided to this method. If 'rules' is None, the 'self.DEFAULT_SG_RULES' value will be
        used instead.
        rules can be a list of rule sets. A rule set should be in the following format:
        (protocol, start port, end port, cidr)
        example: [('tcp', 22, 22, '0.0.0.0/0'), ('icmp', -1, -1, '0.0.0.0/0')]

        :param vpc: boto vpc obj
        :param count: int, number of security groups requested
        :param rules: list of rule sets
        :return:
        """
        user = user or self.user
        if rules is None:
            rules = self.DEFAULT_SG_RULES
        sec_groups = []
        ret_groups = []
        vpc = vpc or self.check_user_default_vpcs(user)
        if vpc and not isinstance(vpc, basestring):
            vpc = vpc.id
        existing = self._security_groups.get(vpc, None)
        if existing is None:
            existing = []
            self._security_groups[vpc] = existing
        if len(existing) >= count:
            sec_groups =  existing[0:count]
        else:
            for x in xrange(0, count-len(existing)):
                name = "{0}_{1}_{2}".format(self.test_name,
                                            len(self._security_groups[vpc]) + 1,
                                            self.test_id)
                self._security_groups[vpc].append(
                    user.ec2.connection.create_security_group(name=name, description=name,
                                                              vpc_id=vpc))
            sec_groups = self._security_groups[vpc]
        for group in sec_groups:
            user.ec2.revoke_all_rules(group)
            for rule in rules:
                protocol, port, end_port, cidr_ip = rule
                user.ec2.authorize_group(group=group, port=port, end_port=end_port,
                                         protocol=protocol)
            group = user.ec2.get_security_group(group.id)
            if not group:
                raise ValueError('Was not able to retrieve sec group: {0}/{1}'
                                 .format(group.name, group.id))
            ret_groups.append(group)
        user.ec2.show_security_groups(ret_groups)
        return ret_groups

    def get_test_addresses(self, count=1):
        raise NotImplementedError('do this')
        """
        existing = self._addresses
        if existing:
            addrs = []
            for addr in existing:
                addrs.append(addr.public_ip)
            existing = self.user.ec2.get_all_addresses(addresses=addrs)
        for addr in existing:
            if addr
        """


    @printinfo
    def get_test_instances(self, zone, group_id,  vpc_id=None, subnet_id=None,
                           state='running', count=None, monitor_to_running=True,
                           auto_connect=True, timeout=480, user=None, exclude=None):
        """
        Finds existing instances created by this test which match the criteria provided,
        or creates new ones to meet the count requested.
        returns list of instances.

        Args:
            zone:  String, zone name
            group_id: String, security group id
            vpc_id: String, vpc id
            subnet_id: String subnet id
            state: String, state of instances to
            count: int, number of instances to fetch, will find existing and attempt to run new
                   to fulfill this requested count.
            monitor_to_running: monitor instances to a running state before returning them.
                                error out if they do not go to running within timeout
            timeout: int, number of seconds to monitor instances to running before erroring.
            user: user context object to use, defaults to self.user
            exclude: instance id or list of instance ids to exclude when fetching
            returns: list of instances which meet the provided criteria.
        """
        instances = []
        user = user or self.user
        if zone is None or group_id is None:
            raise ValueError('Must provide both zone:"{0}" and group_id:"{1}"'
                             .format(zone, group_id))
        existing_instances = []
        exclude_instances = []
        if exclude:
            if not isinstance(exclude, list):
                exclude = [exclude]
            for i in exclude:
                if isinstance(i, basestring):
                    exclude_instances.append(i)
                else:
                    exclude_instances.append(i.id)
        count = int(count or 0)
        filters = {'tag-key': self.test_name, 'tag-value': self.test_id}
        filters['availability-zone'] = zone
        if not isinstance(group_id, basestring) and group_id is not None:
            group_id = group_id.id
        if group_id:
            filters['group-id'] = group_id
        if subnet_id:
            if not isinstance(subnet_id, basestring):
                subnet_id = subnet_id.id
            filters['subnet-id'] = subnet_id
        if vpc_id:
            if not isinstance(vpc_id, basestring):
                vpc_id = vpc_id.id
            filters['vpc-id'] = vpc_id
        if state:
            filters['instance-state-name'] = state
        queried_instances = user.ec2.get_instances(filters=filters)
        self.log.debug('queried_instances:{0}'.format(queried_instances))
        for q_instance in queried_instances:
            if (q_instance.state in ['pending', 'running'] and
                        q_instance.id not in exclude_instances):
                for instance in user.ec2.test_resources.get('instances'):
                    if instance.id == q_instance.id:
                        existing_instances.append(instance)
        for instance in existing_instances:
            euinstance = user.ec2.convert_instance_to_euinstance(instance,
                                                                 keypair=self.get_keypair(user),
                                                                 auto_connect=False)
            euinstance.log.set_stdout_loglevel(self.args.log_level)
            euinstance.auto_connect = auto_connect
            instances.append(euinstance)
        self.log.debug('existing_instances:{0}'.format(existing_instances))
        if not count:
            if monitor_to_running:
                return user.ec2.monitor_euinstances_to_running(instances, timeout=timeout)
            return instances
        if len(instances) >= count:
            instances = instances[0:count]
            if monitor_to_running:
                return user.ec2.monitor_euinstances_to_running(instances, timeout=timeout)
            return instances
        else:
            needed = count - len(instances)
            if vpc_id and not subnet_id:
                vpc_filters = {'vpc-id':vpc_id}
                if zone:
                    vpc_filters['availability-zone'] = zone
                subnets = user.ec2.get_all_subnets(filters=vpc_filters)
                if not subnets:
                    raise ValueError('No subnet found for vpc: {0}'.format(vpc_id))
                subnet = subnets[0]
                subnet_id = subnet.id
            new_ins = self.create_test_instances(zone=zone, group=group_id,
                                                 subnet=subnet_id, count=needed,
                                                 monitor_to_running=monitor_to_running,
                                                 user=user)
            instances.extend(new_ins)
            if len(instances) != count:
                raise RuntimeError('Less than the desired:{0} number of instances returned?'
                                   .format(count))
            return instances

    @printinfo
    def create_test_instances(self, emi=None, key=None, group=None, zone=None, subnet=None,
                              count=1, monitor_to_running=True, auto_connect=True, tag=True,
                              user=None):
        """
        Creates test instances using the criteria provided. This method is intended to be
        called from 'get_test_instances()'.

        :param emi: emi id
        :param key: key obj or id
        :param group: group obj or id
        :param zone: zone name
        :param subnet: subnet obj or id
        :param count: numer of VMs to run
        :param monitor_to_running: bool, if True will monitor instances and verify they are in a
                                  correct working and accessible state.
        "param auto_connect: bool, if True will attempt to automatically setup ssh connections
                            to the instances upon running state.
        :param tag:
        :return:
        """
        user = user or self.user
        vpc_id = None
        subnet_id = None
        if subnet:
            if isinstance(subnet, basestring):
                subnet = user.ec2.get_subnet(subnet)
            if not isinstance(subnet, Subnet):
                raise ValueError('Failed to retrieve subnet with id "{0}" from cloud'
                                 .format(subnet))
        else:
            self.log.debug('No VPC provided using default VPC and default subnet')
            default_vpc = self.check_user_default_vpcs(user)
            subnets = user.ec2.get_default_subnets(vpc=default_vpc, zone=zone)
            if not subnets:
                raise ValueError('{0}: Failed to find subnet for default vpc:"{1}"'
                                 .format(user, default_vpc.id))
            subnet = subnets[0]
        vpc_id = subnet.vpc_id
        subnet_id = subnet.id

        if group:
            if not isinstance(group, SecurityGroup):
                group = user.ec2.get_security_group(group)
        else:
            group = self.get_test_security_groups(vpc=vpc_id, count=1, user=user)[0]
        emi = emi or self.emi
        key = key or self.get_keypair(user)
        instances = user.ec2.run_image(image=emi,
                                       keypair=key,
                                       group=group,
                                       zone=zone,
                                       subnet_id=subnet_id,
                                       max=count,
                                       auto_connect=auto_connect,
                                       monitor_to_running=False,
                                       systemconnection=self.tc.sysadmin)
        for instance in instances:
            assert isinstance(instance, EuInstance)
            if instance.subnet_id != subnet_id:
                raise ValueError('Instance:{0} subnet.id:{1} does not match requested:{2}'
                                 .format(instance, instance.subnet_id, subnet_id))
            instance.add_tag(key=self.test_name, value=self.test_id)
        if monitor_to_running:
            return user.ec2.monitor_euinstances_to_running(instances=instances)
        return instances

    def check_user_supported_platforms(self, user=user):
        user = user or self.user
        supported_platforms = self.new_ephemeral_user.ec2.get_supported_platforms() or []
        self.log.info('Found supported platforms: "{0}"'.format(", ".join(supported_platforms)))
        if 'VPC' not in supported_platforms:
            raise ValueError('User does not have VPC in the supported platforms:{0}'
                             .format(supported_platforms))
        return supported_platforms

    def check_user_default_vpcs(self, user=None):
        user = user or self.user
        default_vpcs = user.ec2.get_default_vpcs()
        if not default_vpcs:
            raise ValueError('No default VPCs found for user:{0}'.format(user))
        try:
            user.ec2.show_vpcs(default_vpcs)
        except Exception as E:
            self.log.warning('{0}. Warning, could not show VPC debug. Ignoring err: '
                             '"{1}"'.format(get_traceback(), E))
        if len(default_vpcs) > 1:
            raise ValueError('Multiple default VPCs found for user:{0}, vpcs:"{1}"'
                             .format(user, default_vpcs))
        return default_vpcs[0]

    def check_user_default_igw(self, user=None):
        user = user or self.user
        default_vpc = self.check_user_default_vpcs(user=user)
        igw = user.ec2.connection.get_all_internet_gateways(
            filters={'attachment.vpc-id': default_vpc.id})
        if not igw:
            raise ValueError('{0}: Default Internet Gateway not found vpc:{1}'
                             .format(user, default_vpc))
        try:
            user.ec2.show_internet_gateways(igw)
        except Exception as E:
            self.log.warning('{0}. Warning, could not show IGW debug. Ignoring err: '
                             '"{1}"'.format(get_traceback(), E))
        if len(igw) > 1:
            raise ValueError('{0}: More than 1 IGW returned for default VPC:{1}, IGWS:{2}'
                             .format(user, default_vpc, igw))
        return igw[0]

    def check_user_default_subnets(self, user=None):
        user = user or self.user
        subs = user.ec2.get_default_subnets()
        if not subs:
            raise ValueError('{0}: No default subnets found'.format(user))
        zone_names = user.ec2.get_zone_names().sort()
        sub_zones = [x.availability_zone for x in subs].sort()
        try:
            user.ec2.show_subnets(subs)
        except Exception as E:
            self.log.warning('{0}. Warning, could not show subnet debug. Ignoring err: '
                             '"{1}"'.format(get_traceback(), E))
        if zone_names != sub_zones:
            raise ValueError('Error default subnets zones: "{0}" do not match '
                             'Availability zones found:"{1}"'.format(zone_names, sub_zones))
        return subs


    def check_user_default_route_table_present(self, user=None):
        user = user or self.user
        default_vpc = self.check_user_default_vpcs(user=user)
        rt = user.ec2.connection.get_all_route_tables(
            filters={'association.main': 'true', 'vpc-id': default_vpc.id})
        if not rt:
            raise ValueError('{0}: No route table associated with default vpc:{1}'
                             .format(user, default_vpc))
        try:
            user.ec2.show_route_tables(rt)
        except Exception as E:
            self.log.warning('{0}. Warning, could not show route table debug. Ignoring err: '
                             '"{1}"'.format(get_traceback(), E))
        if len(rt) > 1:
            raise ValueError('More than one route table returned as main assoc with default '
                             'vpc:{0}, RTs:{1}'.format(default_vpc, rt))
        return rt[0]


    def check_user_default_routes_present(self, user=None, vpc=None, check_igw=True):
        user = user or self.user
        vpc = vpc or self.check_user_default_vpcs(user=user)
        rt = self.check_user_default_route_table_present(user=user)
        routes = rt.routes
        default_cidr_route = False
        default_igw_route = False
        if not check_igw:
            default_igw_route = True
            igw = None
        else:
            igw = self.check_user_default_igw(user=user)
        for route in routes:
            if route.destination_cidr_block == vpc.cidr_block and \
                            route.gateway_id == 'local':
                default_cidr_route = True
            if check_igw:
                if route.gateway_id == igw.id and route.destination_cidr_block == '0.0.0.0/0':
                    default_igw_route = True
            if default_igw_route and default_cidr_route:
                break
        if not default_cidr_route:
            raise ValueError('{0}: Default route for VPC network:{1} not found'
                             .format(vpc.id, vpc.cidr_block))
        if not default_igw_route:
            raise ValueError('{0}: Default route for IGW:{1} not found'
                             .format(vpc.id, igw.id))

    def check_user_default_security_group_rules(self, user=None):
        """
        A users VPC includes a default security group whose initial rules are to deny all
        inbound traffic, allow all outbound traffic, and allow all traffic between
        instances in the group. You can't delete this group; however, you can change
        the group's rules.
        Args:
            user: user context to test against

        Returns:

        """
        user = user or self.user
        default_group = user.ec2.get_security_group('default')
        user.ec2.show_security_group(default_group)


    def basic_instance_ssh_default_vpc(self, user=None, instances_per_zone=2):
        user = user or self.user
        instances = []
        vpc = self.check_user_default_vpcs(user)
        instance_count = instances_per_zone
        for zone in self.zones:
            subnet = user.ec2.get_default_subnets(zone=zone) or None
            sec_group = self.get_test_security_groups(vpc=vpc, count=1, rules=self.DEFAULT_SG_RULES,
                                                      user=user)[0]
            if subnet:
                subnet = subnet[0]
            instances.extend(self.get_test_instances(zone=zone,
                                                     subnet_id=subnet.id,
                                                     group_id=sec_group.id,
                                                     vpc_id=vpc.id,
                                                     count=instance_count,
                                                     monitor_to_running=False,
                                                     user=user))
        user.ec2.monitor_euinstances_to_running(instances=instances)
        self.log.info('basic_instance_ssh_default_vpc passed')
        return instances

    @printinfo
    def packet_test_scenario(self, zone_tx, zone_rx, sec_group_tx, sec_group_rx, subnet_tx,
                             subnet_rx, use_private, protocol, port, count, bind, retries=2,
                             expected_packets=None, set_security_group=True,
                             verbose=None, ssh_tx=None, ssh_rx=None):
        """
        This method is intended to be used as the core test method. It can be fed different
        sets of params each representing a different test scenario. This should allow for
        dictionaries of params to be autogenerated and fed to this test method forming a
        auto-generated test matrix. Used with cli_runner each param set can be ran as a testunit
        providing formatted results. This method should also provide a dict of results for
        additional usage.
        :param zone_tx: zone name
        :param zone_rx: zone name
        :param sec_group_tx: group obj or id
        :param sec_group_rx: group obj or id
        :param subnet_tx: subnet obj or id
        :param subnet_rx: subnet obj or id
        :param use_private: bool, to use private addressing or not
        :param protocol: protocol number for packets ie: 1=icmp, 6=tcp, 17=udp, 132=sctp, etc..
        :param count: number of packets to send in test
        :param retries: number of retries
        :param expected_packets: number of packets to expect, defaults to 'count' sent.
        :param verbose: bool, for verbose output
        :param ssh_tx: adminapi SshConnection obj, used for tx pkts, if provided an instance will
                       not be fetched
        :param ssh_rx: adminapi SshConnection obj, used for rx pkts, if provided an instance will
                       not be fetched
        param set_security_group: boolean. If true all ingress rules from sec_groups will be
                                  removed. New rules specific to this test will be added back.
                                  If false the group will remain untouched.
        matching
        :return dict of results (tbd)
        """
        ins1 = self.get_test_instances(zone=zone_tx, group_id=sec_group_tx, subnet_id=subnet_tx, count=1)
        if not ins1:
            raise RuntimeError('Could not fetch or create test instance #1 with the following '
                               'criteria; zone:{0}, sec_group:{1}, subnet:{2}, count:{3}'
                               .format(zone_tx, sec_group_tx, subnet_tx, 1))
        ins1 = ins1[0]
        ins2 = self.get_test_instances(zone=zone_rx, group_id=sec_group_rx, subnet_id=subnet_rx, count=1,
                                       exclude=[ins1.id])
        if not ins2:
            raise RuntimeError('Could not fetch or create test instance #2 with the following '
                               'criteria; zone:{0}, sec_group:{1}, subnet:{2}, count:{3}'
                               .format(zone_rx, sec_group_rx, subnet_rx, 1))
        ins2 = ins2[0]
        if expected_packets is None:
            expected_packets = count
        def same(x, y):
            if str(x) == str(y):
                return 'SAME'
            else:
                return 'DIFF'
        header_pt = PrettyTable(['ROLE', 'INS ID', 'ZONE', 'VPC', 'SEC GRP', 'SUBNET',
                                 'PRIV', 'PROTO', 'PORT', 'COUNT'])
        header_pt.align = 'l'
        header_pt.add_row(['TX', "{0}\n{1}\n{2}".format(ins1.id, ins1.ip_address,
                                                        ins1.private_ip_address),
                           ins1.placement, ins1.vpc_id, ins1.groups[0].name,
                           ins1.subnet_id, use_private, self.proto_to_name(protocol), port, count])
        header_pt.add_row(['RX', "{0}\n{1}\n{2}".format(ins2.id, ins2.ip_address,
                                                        ins2.private_ip_address),
                           ins2.placement, ins2.vpc_id, ins2.groups[0].name,
                           ins2.subnet_id, use_private, self.proto_to_name(protocol), port, count])
        header_pt.add_row(['--', '---', same(ins1.placement, ins2.placement),
                           same(ins1.vpc_id, ins2.vpc_id),
                           same(ins1.groups[0].name, ins2.groups[0].name),
                           same(ins1.subnet_id, ins2.subnet_id),
                           use_private, self.proto_to_name(protocol), port, count])
        src_ip = ins1.ip_address
        if use_private:
            src_ip = ins1.private_ip_address

        def apply_rule(rule, groups):
            protocol, port, end_port, cidr_ip = rule
            for group in groups:
                self.user.ec2.authorize_group(group=group, port=port, end_port=end_port,
                                              protocol=protocol)
        if set_security_group:
            self.user.ec2.revoke_all_rules(sec_group_tx)
            self.user.ec2.revoke_all_rules(sec_group_rx)
            base_rule = ('tcp', 22, 22, '0.0.0.0/0')
            test_rule = (protocol, port or -1, port or -1, src_ip)
            apply_rule(base_rule, [sec_group_tx, sec_group_rx])
            apply_rule(test_rule, [sec_group_rx])

        self.log.debug('{0}{1}\n'.format(markup('\nAttempting packet test with instances:\n',
                                                [ForegroundColor.BLUE, BackGroundColor.BG_WHITE]),
                        self.tc.admin.ec2.show_instances([ins1, ins2], printme=False)))
        self.user.ec2.show_security_groups([sec_group_tx, sec_group_rx])
        if use_private:
            src_ip = ins1.private_ip_address
            dest_ip = ins2.private_ip_address
        else:
            dest_ip = ins2.ip_address
        retries = retries or 1
        results = None
        for retry in xrange(0, retries):
            try:
                results = packet_test(sender_ssh=ins1.ssh, receiver_ssh=ins2.ssh, dest_ip=dest_ip,
                                      protocol=protocol, port=port, bind=bind, count=count,
                                      verbose=verbose)
                results['header'] = header_pt.get_string()
                if results['count'] != expected_packets and not results['error']:
                    raise RuntimeError('Packet count does not equal expected count provided. '
                                       'No error in output found')
                self.log.debug(markup('Got results:{0}'.format(results),
                                      [BackGroundColor.BG_BLACK,ForegroundColor.WHITE]))
            except Exception as E:
                self.log.warning(markup('{0}\nError in packet test on attempt: {1}/{2}, err:{3}'
                                 .format(get_traceback(), retry, retries, E),
                                        [ForegroundColor.WHITE, BackGroundColor.BG_RED]))
                results = {'error': E}
                results['header'] = header_pt.get_string()
        for ins in [ins1, ins2]:
            try:
                ins.ssh.close()
            except Exception as E:
                self.log.warning("{0}\nError while closing ssh for instance:{1}, err:{2}".
                                 format(get_traceback(), ins, E))
        return results

    def basic_net_test(self, matrix=None, dry_run=False):
        matrix = matrix or self.generate_basic_net_test_matrix()
        zones = matrix.get('zones')
        zone_names = zones.keys()
        setattr(self, '_results', [])
        for zone1_name in zone_names:
            zone1_dict = zones[zone1_name]
            for zone2_name in zone_names:
                zone2_dict = zones[zone2_name]
                for vpc1_dict in [zone1_dict.get('default_vpc'), zone1_dict.get('vpc2'),
                                  zone2_dict.get('default_vpc'), zone2_dict.get('vpc2')]:
                    vpc1 = vpc1_dict.get('vpc')
                    for vpc2_dict in [zone1_dict.get('default_vpc'), zone1_dict.get('vpc2'),
                                      zone2_dict.get('default_vpc'), zone2_dict.get('vpc2')]:
                        vpc2 = vpc2_dict.get('vpc')
                        for vpc1_group in vpc1_dict.get('security_groups'):
                            for vpc2_group in vpc2_dict.get('security_groups'):
                                for vpc1_subnet in vpc1_dict.get('subnets'):
                                    for vpc2_subnet in vpc2_dict.get('subnets'):
                                        for use_private in [True, False]:

                                            for test_dict in matrix.get('packet_tests'):
                                                protocol = test_dict['protocol']
                                                port = test_dict['port']
                                                count = test_dict['count']
                                                expected_count = count
                                                bind = test_dict['bind']
                                                if use_private and vpc1_group == vpc2_group:
                                                    expected_count = 0
                                                if dry_run:
                                                    self.show_packet_test_scenario(
                                                        vpc1, vpc2,
                                                        zone1_name, zone2_name,
                                                        vpc1_group, vpc2_group,
                                                        vpc1_subnet, vpc2_subnet,
                                                        use_private, protocol, port, count)
                                                else:
                                                    result = self.packet_test_scenario(
                                                        zone_tx=zone1_name, zone_rx=zone2_name,
                                                        sec_group_tx=vpc1_group,
                                                        sec_group_rx=vpc2_group,
                                                        subnet_tx=vpc1_subnet,
                                                        subnet_rx=vpc2_subnet,
                                                        use_private=use_private, protocol=protocol,
                                                        port=port, count=count, bind=bind)

                                                    self._results.append(result)
                                                    try:
                                                        test = 0
                                                        for res in self._results:
                                                            test += 1
                                                            self.log.info('TEST NUMBER:{0}'
                                                                          .format(test))
                                                            self.show_packet_test_results(
                                                                results_dict=res)
                                                    except Exception as E:
                                                        self.log.warning('{0}\nError while trying'
                                                                         'to show test results: {1}'
                                                                         .format(get_traceback(), E))
        return self._results

    def show_packet_test_scenario(self, vpc1, vpc2, zone1, zone2, sec1, sec2, sub1, sub2,
                                  private_addr, protocol, port, count):
        def same(x, y):
            if x == y:
                return 'SAME'
            return 'DIFF'
        pt = PrettyTable(['ROLE','VPC', 'ZONE', 'SECGRP', 'SUBNET', 'PRIVADDR', 'PROTO',
                         'PORT', 'COUNT'])
        pt.align = 'l'
        pt.add_row(['SENDER', str(vpc1), str(zone1), str(sec1), str(sub1), str(private_addr),
                    str(self.proto_to_name(protocol)), str(port), str(count)])
        pt.add_row(['RECEIVER', str(vpc2), str(zone2), str(sec2), str(sub2), str(private_addr),
                    str(self.proto_to_name(protocol)), str(port), str(count)])
        pt.add_row('', same(vpc1, vpc2), same(zone1, zone2), same(sec1, sec2), same(sub1, sub2),
                   '', '', '', '')
        self.log.info('\n{0}\n'.format(pt))


    def generate_basic_net_test_matrix(self):
        """
        Sample method to show how a set of test parameters might be defined for feeding to
        self.packet_test_scenario(). The set of parameters defines the test matrix to be run.
        :return: test matrix dict
        """
        pkt_count = 5
        start_port = 101
        end_port = 101
        matrix = {}
        private_addressing = [True, False]
        vpc1 = self.default_vpc
        vpc2 = self.get_test_vpcs(count=1)[0]
        packet_tests = []

        #for port in xrange(start_port, end_port):
        #    packet_tests.append({'name': 'UDP', 'protocol': UDP, 'count': pkt_count,
        #                         'port': port, 'bind': False})
        #for port in xrange(start_port, end_port):
        #    packet_tests.append({'name': 'TCP', 'protocol': TCP, 'count': pkt_count,
        #                         'bind': True, 'port':port})
        #for port in xrange(start_port, end_port):
        #    packet_tests.append({'name': 'SCTP', 'protocol': SCTP, 'count': pkt_count,
        #                         'bind': True, 'port': port})
        packet_tests.append({'name': 'ICMP', 'protocol': ICMP, 'count': pkt_count, 'port': None,
                          'bind': False})
        vpc1_sec_group1, vpc1_sec_group2 = self.get_test_security_groups(
            vpc=vpc1, count=2, rules=self.DEFAULT_SG_RULES)
        vpc2_sec_group1, vpc2_sec_group2 = self.get_test_security_groups(
            vpc=vpc2, count=2, rules=self.DEFAULT_SG_RULES)
        matrix['packet_tests'] = packet_tests
        # Create the available test params per zone...
        matrix['zones'] = {}
        for zone in self.zones:
            new_def = {}
            new_def['private_addressing'] = private_addressing
            new_def['start_port'] = start_port
            new_def['end_port'] = end_port
            default_vpc = {'vpc': vpc1}
            second_vpc = {'vpc': vpc2}

            default_vpc['security_groups'] = [vpc1_sec_group1, vpc1_sec_group2]
            second_vpc['security_groups'] = [vpc2_sec_group1, vpc2_sec_group2]

            # VPC1 'should' be the default vpc, and the first subnet tested should be the
            # default subnet for the zone to cover 'default vpc+subnet' the rest will be
            # created by this test suite...
            default_vpc['subnets'] = self.user.ec2.get_default_subnets(vpc=vpc1, zone=zone) + \
                                      self.get_non_default_test_subnets_for_vpc(vpc1,
                                                                                zone=zone,
                                                                                count=1)
            second_vpc['subnets'] = self.user.ec2.get_default_subnets(vpc=vpc2, zone=zone) + \
                                      self.get_non_default_test_subnets_for_vpc(vpc2,
                                                                                zone=zone,
                                                                                count=1)
            new_def['default_vpc'] = default_vpc
            new_def['vpc2'] =  second_vpc
            matrix['zones'][zone] = new_def
        return matrix


    def basic_eni_test(self, zone1, zone2, sec_group1, sec_group_2, vpc1, vpc2, subnet1, subnet2,
                       use_private, protocol, pkt_count=5, retries=2, verbose=None):
        raise NotImplementedError()

    def build_test_kwargs_from_testdefs(self, matrix):
        test_case_kwargs = []
        for zone, testdef in matrix.iteritems():
            protocol_dict = testdef.get('protocols')
            for protocol, proto_kwargs in protocol_dict.iteritems():
                addressing_dict = testdef.get('addressing' or {})
                for addressing, value in addressing_dict.iteritems():
                    for vm1_vpc in [testdef.get('vpc1'), testdef.get('vpc2')]:
                        pass

    def proto_to_name(self, proto):
        for varname, value in vars(socket).items():
            if varname.startswith('IPPROTO') and value == proto:
                return varname.lstrip('IPPROTO')
        return proto

    def show_packet_test_results(self, results_dict, header=None, printmethod=None, printme=True):
        if not results_dict:
            self.log.warning('Empty results dict passed to show_packet_test_results')
            return

        protocol = results_dict.get('protocol', "???")
        header = header or results_dict.get('header', None) or 'PACKET_TEST_RESULTS'
        main_pt = PrettyTable([header])
        main_pt.align = 'l'
        main_pt.padding_width = 0
        main_pt.add_row(["{0}".format(results_dict.get('name', "???"))])
        main_pt.add_row(["Elapsed:{0}, Packet Count:{1}".format(results_dict.get('elapsed', "???"),
                                                        results_dict.get('count', "???"))])
        if results_dict.get('error', None):
            main_pt.add_row(["ERROR: {0}".format(markup(results_dict.get('error'), [1, 91]))])
        pt = PrettyTable(['pkt_src_addr', 'pkt_dst_addr', 'protocol', 'port', 'pkt_count'])
        for src_addr, s_dict in results_dict.get('packets', {}).iteritems():
            for dst_addr, d_dict in s_dict.iteritems():
                for port, count in d_dict.iteritems():
                    pt.add_row([src_addr, dst_addr, self.proto_to_name(protocol), port, count])
        main_pt.add_row(["{0}".format(pt)])
        if not printme:
            return main_pt
        printmethod = printmethod or self.log.info
        printmethod(markup("\n{0}\n".format(main_pt),
                           [ForegroundColor.BLUE, BackGroundColor.BG_WHITE]))

    ###############################################################################################
    #  Newly created user tests for default VPC artifacts and attributes
    ###############################################################################################
    def test1a_new_user_supported_platforms(self):
        """
        Definition:
        Attempts to check that a newly created user has VPC in it's supported platforms
        """
        return self.check_user_supported_platforms(user=self.new_ephemeral_user)

    def test1b_new_user_default_vpc(self):
        """
        Definition:
        Attempts to check that a newly created user has a default VPC
        """
        return self.check_user_default_vpcs(user=self.new_ephemeral_user)

    def test1c_new_user_default_igw(self):
        """
        Definition:
        Attempts to check that a newly created user has a default igw associated with the
        default vpc
        """
        return self.check_user_default_igw(user=self.new_ephemeral_user)

    def test1d_new_user_default_subnets(self):
        """
        Definition:
        Attempts to verify that a newly created user has default subnets in each availability
        zone
        """
        return self.check_user_default_subnets(user=self.new_ephemeral_user)

    def test1e_new_user_default_route_table(self):
        """
        Definition:
        Attempts to verify that a newly created user has a default route table associated
        with its default vpc
        """
        return self.check_user_default_route_table_present(user=self.new_ephemeral_user)

    def test1f_new_user_default_routes(self):
        """
        Definition:
        Attempts to verify that a newly created user has a default routes present for the vpc
        cidr block and default igw in it's route table
        """
        return self.check_user_default_routes_present(user=self.new_ephemeral_user)

    def test1z_new_user_default_security_group_rules(self):
        """
        Test attributes specific to the 'default' security group
        By default, no inbound traffic is allowed until you add inbound rules
         to the security group.
        By default, an outbound rule allows all outbound traffic.
        You can remove the rule and add outbound rules that allow specific outbound traffic only.
        Instances associated with a security group can't talk to each other unless you
        add rules allowing it (exception: the default security group has these rules by default).

        """
        return self.check_user_default_security_group_rules(user=self.new_ephemeral_user)

    def test1z_new_user_basic_instance_ssh_defaults(self):
        """
            Definition:
            Attempts to run an instance in the default vpc and subnet and verify basic ssh
            connectivity.
            This test should use a newly created account/user.
            """
        user = self.new_ephemeral_user
        ins = self.basic_instance_ssh_default_vpc(user=user, instances_per_zone=1)
        if ins:
            self.log.debug('Terminated successful test instances')
            user.ec2.terminate_instances(ins)

    ###############################################################################################
    #  Primary test user tests for default VPC artifacts and attributes, this user may be existing
    #  If this user is the same as the 'newly created user, and the previous tests were run against
    #  that user, then these tests will be skipped.
    ###############################################################################################

    def test2a_test_user_supported_platforms(self):
        """
        Definition:
        Attempts to check that the current test user has VPC in it's supported platforms
        """
        if self.user == self.new_ephemeral_user:
           test = self.get_testunit_by_method(self.test1a_new_user_supported_platforms)
           if test and test.result != TestResult.not_run:
               raise SkipTestException('Test already run for the test user')
        return self.check_user_supported_platforms(user=self.user)

    def test2b_test_user_default_vpc(self):
        """
        Definition:
        Attempts to check that the current test user has a default VPC
        """
        if self.user == self.new_ephemeral_user:
            test = self.get_testunit_by_method(self.test1b_new_user_default_vpc)
            if test and test.result != TestResult.not_run:
                raise SkipTestException('Test already run for the test user')
        return self.check_user_default_vpcs(user=self.user)

    def test2c_test_user_default_igw(self):
        """
        Definition:
        Attempts to check that the current test user has a default igw associated with the
        default vpc
        """
        if self.user == self.new_ephemeral_user:
            test = self.get_testunit_by_method(self.test1c_new_user_default_igw)
            if test and test.result != TestResult.not_run:
                raise SkipTestException('Test already run for the test user')
        return self.check_user_default_igw(user=self.user)

    def test2d_test_user_default_subnets(self):
        """
        Definition:
        Attempts to verify that the current test user has default subnets in each availability
        zone
        """
        if self.user == self.new_ephemeral_user:
            test = self.get_testunit_by_method(self.test1d_new_user_default_subnets)
            if test and test.result != TestResult.not_run:
                raise SkipTestException('Test already run for the test user')
        return self.check_user_default_subnets(user=self.user)

    def test2e_test_user_default_route_table(self):
        """
        Definition:
        Attempts to verify that the current test user has a default route table associated
        with its default vpc
        """
        if self.user == self.new_ephemeral_user:
            test = self.get_testunit_by_method(self.test1e_test_user_default_route_table)
            if test and test.result != TestResult.not_run:
                raise SkipTestException('Test already run for the test user')
        return self.check_user_default_route_table_present(user=self.user)

    def test2f_test_user_default_security_group_rules(self):
        """
        Test attributes specific to the 'default' security group
        By default, no inbound traffic is allowed until you add inbound rules
         to the security group.
        By default, an outbound rule allows all outbound traffic.
        You can remove the rule and add outbound rules that allow specific outbound traffic only.
        Instances associated with a security group can't talk to each other unless you
        add rules allowing it (exception: the default security group has these rules by default).

        """
        if self.user == self.new_ephemeral_user:
            test = self.get_testunit_by_method(self.test1z_new_user_default_security_group_rules)
            if test and test.result != TestResult.not_run:
                raise SkipTestException('Test already run for the test user')
        return self.check_user_default_security_group_rules(user=self.user)

    def test1g_test_user_default_routes(self):
        """
        Definition:
        Attempts to verify that a test user has a default routes present for the vpc
        cidr block and default igw in it's route table
        """
        return self.check_user_default_routes_present(user=self.user)

    def test2z_test_user_basic_instance_ssh_defaults(self):
        """
        Definition:
        Attempts to run an instance in the default vpc and subnet and verify basic ssh
        connectivity.
        This test should use the primary test user.
        """
        if self.user == self.new_ephemeral_user:
            test = self.get_testunit_by_method(self.test1z_new_user_basic_instance_ssh_defaults)
            if test and test.result != TestResult.not_run:
                raise SkipTestException('Test already run for the test user')
        user = self.user
        ins = self.basic_instance_ssh_default_vpc(user=user, instances_per_zone=1)
        if ins:
            self.log.debug('Terminated successful test instances')
            user.ec2.terminate_instances(ins)


    ###############################################################################################
    # Test security groups basics
    # - Legacy 'net test' covers most of the basic security group auth and revoke packet tests
    # - This should cover attributes specific to VPC
    ###############################################################################################
    def test3b0_get_vpc_for_security_group_tests(self):
        test_vpc = self.user.ec2.get_all_vpcs(filters={'tag-key': self.SUBNET_TEST_TAG,
                                                       'tag-value': self.test_id})
        if not test_vpc:
            test_vpc = self.create_test_vpcs()
            if not test_vpc:
                raise RuntimeError('Failed to create test VPC for subnet tests?')
            test_vpc = test_vpc[0]
            self.user.ec2.create_tags([test_vpc.id], {self.SECURITY_GROUP_TEST_TAG: self.test_id})
        else:
            test_vpc = test_vpc[0]
        return test_vpc

    def test3b1_default_security_group_initial_ingress_rules(self):
        """
        A users VPC includes a default security group whose initial rules are to deny all
        inbound traffic, allow all outbound traffic, and allow all traffic between
        instances in the group. You can't delete this group; however, you can change
        the group's rules.

        By default, no inbound traffic is allowed until you add inbound rules
         to the security group.
        By default, an outbound rule allows all outbound traffic.
        You can remove the rule and add outbound rules that allow specific outbound traffic only.
        """
        user = self.user
        vpc = self.test3b0_get_vpc_for_security_group_tests()
        def_sg = user.ec2.get_security_group(name='default', vpc_id=vpc.id)
        user.ec2.show_security_group(def_sg)
        ingress_rules = def_sg.rules
        # Deny all ingress traffic except for it's own group
        self.status('Checking group {0} for user:{1}. Default Group should posses 1 '
                    'ingress rule permitting traffic from VMs in its own group'
                    .format(def_sg, user))
        if len(ingress_rules) != 1:
            raise ValueError('Expected default security group to posses 1 ingress rule, '
                             'found {0} for users:{1} sec group: {2}'.format(len(ingress_rules),
                                                                             user, def_sg.id))
        ig = ingress_rules[0]
        if (ig.from_port or ig.groups or ig.ipRanges or ig.ip_protocol or ig.to_port):
            raise ValueError('Expected the following to be unset. Got: from_port{0}, groups:{1}, '
                             'ipRanges:{2}, ip_protocol:{3}, to_port:{4}'
                             .format(ig.from_port, ig.groups, ig.ipRanges,
                                     ig.ip_protocol, ig.to_port))
        grant = ingress_rules.grants[0]
        expected_ingress_grant = {'cidr_ip': None,
                                  'groupId': def_sg.id,
                                  'groupName': 'default',
                                  'group_id': def_sg.id,
                                  'item': '',
                                  'name': 'default',
                                  'owner_id': self.user.aws_account_id,
                                  'userId': self.user.aws_account_id}
        for key, value in expected_ingress_grant:
            if grant[key] != value:
                raise ValueError('Default grant attribute: "{0}" value:"{1}", does not'
                                 ' match expected attribute value:{2}'.format(key, grant[key],
                                                                              value))

    def test3b2_default_security_group_initial_egress_rules(self):
        """
        A users VPC includes a default security group whose initial rules are to deny all
        inbound traffic, allow all outbound traffic, and allow all traffic between
        instances in the group. You can't delete this group; however, you can change
        the group's rules.

        By default, no inbound traffic is allowed until you add inbound rules
         to the security group.
        By default, an outbound rule allows all outbound traffic.
        You can remove the rule and add outbound rules that allow specific outbound traffic only.
        """
        user = self.user
        vpc = self.test3b0_get_vpc_for_security_group_tests()
        def_sg = user.ec2.get_security_group(name='default', vpc_id=vpc.id)
        user.ec2.show_security_group(def_sg)
        egress_rules = def_sg.rules_egress
        self.status('Checking group {0} for user:{1}. Default Group should posses 1 '
                    'egress rule permitting all egress traffic'
                    .format(def_sg, user))
        if len(egress_rules) != 1:
            raise ValueError('Expected default security group to posses 1 egress rule, '
                             'found {0} for users:{1} sec group: {2}'.format(len(egress_rules),
                                                                             user, def_sg.id))
        ig = egress_rules[0]
        if (ig.from_port or ig.groups or ig.ipRanges or ig.ip_protocol or ig.to_port):
            raise ValueError('Expected the following to be unset. Got: from_port{0}, groups:{1}, '
                             'ipRanges:{2}, ip_protocol:{3}, to_port:{4}'
                             .format(ig.from_port, ig.groups, ig.ipRanges,
                                     ig.ip_protocol, ig.to_port))
        grant = egress_rules.grants[0]
        expected_egress_grant = {'cidr_ip': '0.0.0.0/0',
                                 'group_id': None,
                                 'item': '',
                                 'name': None,
                                 'owner_id': None}
        for key, value in expected_egress_grant:
            if grant[key] != value:
                raise ValueError('Default grant attribute: "{0}" value:"{1}", does not'
                                 ' match expected attribute value:{2}'.format(key, grant[key],
                                                                              value))

    def test3b3_basic_default_security_group_packet_test(self, egress_test_ip=None):
        """
        Your VPC includes a default security group whose initial rules are to deny all
        inbound traffic, allow all outbound traffic, and allow all traffic between
        instances in the group.
        Defaults:
        This test will verify the default rules by attempting to reach a VM in the default group.
        This should fail.
        Modify/Authorize the group:
        Modify the default rules to allow ssh (tcp/22), verify ssh access and verify egress rules
        using ICMP to the egress test ip (defaults to a UFS).
        """
        user = self.user
        vpc = self.test3b0_get_vpc_for_security_group_tests()
        def_sg = user.ec2.get_security_group(name='default', vpc_id=vpc.id)
        user.ec2.show_security_group(def_sg)
        vms = self.create_test_instances(group=def_sg, auto_connect=False, count=2)[0]
        self.status('Attempting to reach vm on tcp/22 this should not be allowed...')
        try:
            for vm in vms:
                test_port_status(vms.ip_address, 22)
        except socket.error as SE:
            self.status('Could not reach vm in default sg, passed:{0}'.format(SE))
        user.ec2.authorize_group(def_sg, protocol='tcp', port=22, cidr_ip='0.0.0.0/0')
        self.status('Attempting to connect to test VMs after authorizing ssh...')
        for vm in vms:
            vm.connect_to_instance()
        self.status('Attempting VM to VM packet test in default group. All traffic should be '
                    'allowed for this test')
        vm1, vm2 = vms
        results = []
        results.append(self.packet_test_scenario(zone_tx=vm2.placement, zone_rx=vm1.placement,
                                  sec_group_tx=def_sg.id, sec_group_rx=def_sg.id,
                                  subnet_tx=vm2.subnet_id, subnet_rx=vm1.subnet_id,
                                  use_private=False, protocol=1, port=None, count=5,
                                  bind=False, set_security_group=False,
                                  ssh_tx=vm1.ssh, ssh_rx=vm2.ssh))
        results.append(self.packet_test_scenario(zone_tx=vm2.placement, zone_rx=vm1.placement,
                                  sec_group_tx=def_sg.id, sec_group_rx=def_sg.id,
                                  subnet_tx=vm2.subnet_id, subnet_rx=vm1.subnet_id,
                                  use_private=False, protocol=6, port=100, count=5,
                                  bind=True, set_security_group=False,
                                  ssh_tx=vm1.ssh, ssh_rx=vm2.ssh))
        results.append(self.packet_test_scenario(zone_tx=vm2.placement, zone_rx=vm1.placement,
                                  sec_group_tx=def_sg.id, sec_group_rx=def_sg.id,
                                  subnet_tx=vm2.subnet_id, subnet_rx=vm1.subnet_id,
                                  use_private=False, protocol=17, port=101, count=5,
                                  bind=False, set_security_group=False,
                                  ssh_tx=vm1.ssh, ssh_rx=vm2.ssh))
        results.append(self.packet_test_scenario(zone_tx=vm2.placement, zone_rx=vm1.placement,
                                  sec_group_tx=def_sg.id, sec_group_rx=def_sg.id,
                                  subnet_tx=vm2.subnet_id, subnet_rx=vm1.subnet_id,
                                  use_private=False, protocol=132, port=101, count=5,
                                  bind=True, set_security_group=False,
                                  ssh_tx=vm1.ssh, ssh_rx=vm2.ssh))
        for result in results:
            self.show_packet_test_results(results_dict=result)
        errors = []
        for result in results:
            error = result.get('error', None)
            if error:
                errors.append(error)
        if errors:
            self.log.error('Errors detected during default sec group packet test:{0}'
                           .format("\n".join(str(x) for x in errors)))
            raise RuntimeError('Errors detected during default sec group packet test. See results')
        self.status('VM to VM to default security group packet test passed.')
        self.status('Testing VM to egress now...')
        ufs = self.tc.sysadmin.get_hosts_for_ufs()[0]
        for vm in vms:
            vm.sys('ping -c1 ' + ufs.hostname, code=0)


    def test3b4_test_security_group_count_limit(self):
        """
        AWS: You can create up to 500 security groups per VPC.
        EUCA: Verify cloud property 'cloud.vpc.securitygroupspervpc'.
        """
        user = self.user
        vpc = self.test3b0_get_vpc_for_security_group_tests()
        prop = self.tc.sysadmin.get_property('cloud.vpc.securitygroupspervpc')
        limit = int(prop.value)
        self.status('Attempting to verify security group counts up to '
                    'cloud.vpc.securitygroupspervpc:{0}'.format(limit))
        try:
            # Create Security groups to limit
            self.get_test_security_groups(vpc=vpc, user=user, count=limit)
        except Exception as SE:
            groups = user.ec2.connection.get_all_security_groups(filters={'vpc-id': vpc.id})
            if len(groups) != limit:
                self.log.error('Could not create security group count:{0} == limit:{1}'
                               .format(len(groups), limit))
            else:
                self.status('Group count: {0} == cloud.vpc.securitygroupspervpc:{1}'
                            .format(len(groups), limit))


    def test3b5_test_security_group_rule_limits(self):
        """
        AWS: You can add up to 50 rules to a security group
        EUCA: you can add up to cloud.vpc.rulespersecuritygroup to a security group
        """
        user = self.user
        vpc = self.test3b0_get_vpc_for_security_group_tests()
        prop = self.tc.sysadmin.get_property('cloud.vpc.rulespersecuritygroup')
        limit = int(prop.value)
        group = self.get_test_security_groups(vpc=vpc, user=user, rules={}, count=1)[0]
        egress_count = len(group.rules_egress)
        if len(group.rules) != 0:
            user.ec2.revoke_all_rules(group)
        self.log.debug('Attempt to create limit number:{0} of rules per group'.format(limit))
        for x in xrange(0, limit-egress_count):
            user.ec2.authorize_group(group, port=x, protocol='tcp', cidr_ip='0.0.0.0/32')
        group = user.ec2.get_security_group(group.id)
        user.ec2.show_security_group(group)
        try:
            self.log.debug('Attempt to exceed the rules per group limit...')
            user.ec2.authorize_group(group, port=(x + 1), protocol='tcp', cidr_ip='0.0.0.0/32')
        except EC2ResponseError as EE:
            if EE.status == '400' and EE.reason == 'RulesPerSecurityGroupLimitExceeded':
                self.log.debug('Negative test caught with correct exception: {0}'.format(EE))
            else:
                raise EE
        else:
            raise ValueError('Was able to exceed rules per group limit of:{0}'.format(limit))

    def test3b6_test_security_group_per_eni_limits(self):
        """
        You can assign up to 5 security groups to a network interface.
        EUCA: cloud.vpc.securitygroupspernetworkinterface
        """
        user = self.user
        vpc = self.test3b0_get_vpc_for_security_group_tests()
        prop = self.tc.sysadmin.get_property('cloud.vpc.securitygroupspernetworkinterface')
        limit = int(prop.value)
        subnet = self.get_non_default_test_subnets_for_vpc(vpc=vpc, count=1, user=user)[0]
        eni = self.get_test_enis_for_subnet(subnet, count=1, user=user)[0]
        self.status('Attempt to set eni groups to maximum count per limit:{0}'.format(limit))
        groups = self.get_test_security_groups(vpc=vpc, rules={}, count=limit)
        user.ec2.connection.modify_network_interface_attribute(eni.id,
                                                               attr='groupSet',
                                                               value=groups)
        eni.update()
        if len(eni.groups) != limit:
            raise ValueError('Was not able to set eni max groups to limit:{0}, got:{1}'
                             .format(limit, len(eni.groups)))
        self.status('Succeeded in setting group limit, now try to exceed it')
        try:
            groups = self.get_test_security_groups(vpc=vpc, rules={}, count=(limit + 1))
            user.ec2.connection.modify_network_interface_attribute(eni.id,
                                                                   attr='groupSet',
                                                                   value=groups)
        except EC2ResponseError as EE:
            if EE.status == '400' and EE.reason == 'SecurityGroupsPerInterfaceLimitExceeded':
                self.log.debug('Negative test caught with correct exception: {0}'.format(EE))
            else:
                raise EE
        else:
            raise ValueError('Was able to exceed groups per eni limit of:{0}'.format(limit))
        eni.delete()

    def test3z0_test_clean_up_security_group_vpc_dependencies(self):
        """
        Delete the VPC and dependency artifacts created for the security group testing.
        """
        if not self.args.no_clean:
            user = self.user
            vpc = self.test3b0_get_vpc_for_security_group_tests()
            if vpc:
                user.ec2.delete_vpc_and_dependency_artifacts(vpc)

    ###############################################################################################
    #  ROUTE TABLE tests
    ###############################################################################################
    def test4b0_get_vpc_for_route_table_tests(self):
        test_vpc = self.user.ec2.get_all_vpcs(filters={'tag-key': self.ROUTE_TABLE_TEST_TAG,
                                                       'tag-value': self.test_id})
        if not test_vpc:
            test_vpc = self.create_test_vpcs()
            if not test_vpc:
                raise RuntimeError('Failed to create test VPC for route table tests?')
            test_vpc = test_vpc[0]
            self.user.ec2.create_tags([test_vpc.id], {self.ROUTE_TABLE_TEST_TAG: self.test_id})
        else:
            test_vpc = test_vpc[0]
        return test_vpc


    def test4b1_get_subnets_for_route_table_tests(self, vpc=None, count=1):
        vpc = vpc or self.test4b0_get_vpc_for_route_table_tests()
        subnets = self.user.ec2.get_all_subnets(filters={'vpc_id': vpc.id,
                                                         'tag-key': self.ROUTE_TABLE_TEST_TAG,
                                                         'tag-value': self.test_id}) or []
        subnets = subnets[:count]
        if len(subnets) > count:
            new_subnets = self.create_test_subnets(vpc=vpc, count_per_zone=count)
            sub_ids = [str(x.id) for x in new_subnets]
            self.user.ec2.create_tags(sub_ids, {self.ROUTE_TABLE_TEST_TAG: self.test_id})
            subnets += new_subnets
        if len(subnets) != count:
            raise ValueError('Did not retrieve {0} number of subnets for route table tests?'
                             .format(count))
        return subnets

    def test4b2_route_table_verify_internet_gateway_route(self, subnet=None, user=None,
                                                           force_main_rt=False):
        """
        Launch a VM(s) in a subnet referencing the route table to be tested.
        Add use an exiting route referencing an internet gateway. Verify traffic is routed
        correctly with regards to this IGW route

        """
        user = user or self.user
        if subnet:
            if isinstance(subnet, basestring):
                subnetobj = user.ec2.get_subnet(subnet)
            if not subnetobj:
                raise ValueError('user:{0}, could not fetch subnet:{1}'.format(user, subnet))
            subnet = subnetobj
            vpc = user.ec2.get_vpc(subnet.vpc_id)
        vpc = vpc or self.test4b0_get_vpc_for_route_table_tests()
        subnet = subnet or self.test4b1_get_subnets_for_route_table_tests(vpc, count=1)[0]

        rts = user.ec2.connection.get_all_route_tables(
            filters={'association.subnet_id': subnet.id}) or []

        if force_main_rt:
            # if force main is setup, disassociate all other router so the test is forced
            # to use the main table
            for rt in rts:
                for ass in rt.associtations:
                    if ass.subnet_id == subnet.id:
                        user.ec2.connection.disassociate_route_table(ass.id)
            rts = []
        if not rts:
            rts = user.ec2.connection.get_all_route_tables(filters={'association.main': 'true',
                                                                   'vpc-id': vpc.id})
            if not rts:
                raise ValueError('Main route table not found for vpc:{0}, and no'
                                 'route table associated with subnet:{1}'.format(vpc.id,
                                                                                 subnet.id))
        rt = rts[0]
        igw = user.ec2.connection.get_all_internet_gateways(filters={'attachment.vpc-id': vpc.id})
        if not igw:
            raise ValueError('No internet gateway found for VPC: {0}'.format(vpc.id))
        igw = igw[0]

        original_igw_route = None
        new_route = None
        current_route = None
        for route in rt.routes:
            if route.gateway_id == igw.id:
                original_igw_route = route
                current_route = route

        if not original_igw_route or original_igw_route.destination_cidr_block != '0.0.0.0/0':
            user.ec2.connection.delete_route(
                route_table_id=rt.id,
                destination_cidr_block=original_igw_route.desination_cidr_block)
            new_route = user.ec2.connection.create_route(rt.id, '0.0.0.0/0', igw.id)
            current_route = new_route
        group = self.get_test_security_groups(vpc=vpc, rules = [('tcp', 22, 22, '0.0.0.0/0'),
                                                                ('icmp', -1, -1, '0.0.0.0/0')])[0]
        vm = self.get_test_instances(zone=subnet.availability_zone, subnet_id=subnet.id,
                                               group_id=group.id, user=user, count=1)[0]
        self.status('Attempting to ping the VM from the UFS using the default IGW route...')
        ufs = self.tc.sysadmin.get_hosts_for_ufs()[0]
        ufs.sys('ping -c1 -t5 ' + vm.ip_address, code=0)
        self.status('Removing the route and attempting to ping again...')

        user.ec2.connection.delete_route(
            route_table_id=rt.id,
            destination_cidr_block=current_route.desination_cidr_block)
        self.status('Removing route and retrying...')
        time.sleep(2)
        try:
            ufs.sys('ping -c1 -t5 ' + vm.ip_address, code=0)
        except CommandExitCodeException:
            self.status('Failed to reach VM without route passing')
        else:
            self.log.error('Was able to reach the following VM, after removing the igw route...')
            user.ec2.show_instance(vm)
            user.ec2.show_route_table(rt)
            raise RuntimeError('Was able to reach VM after removing the igw route')
        self.log.debug('restoring original igw route for route table:{0}'.format(rt.id))
        if original_igw_route:
            user.ec2.connection.create_route(rt.id,
                                             original_igw_route.destination_cidr_block,
                                             igw.id)

    def test4b5_route_table_implicit_subnet_association(self):
        """
        Each subnet must be associated with a route table, which controls the routing
        for the subnet. If you don't explicitly associate a subnet with a particular
        route table, the subnet is implicitly associated with the main route table.
        """
        user = self.user
        subnet = self.test4b1_get_subnets_for_route_table_tests(count=1)[0]
        self.status('Using the IGW test on the main route table to verify the main'
                    'route table is implicitly in use on a subnet w/o route table association...')
        return self.test4b2_route_table_verify_internet_gateway_route(subnet=subnet,
                                                                      force_main_rt=True,
                                                                      user=user)

    def test4b6_route_table_default_local_route(self):
        """
        Every route table contains a local route that enables communication within a VPC.
        You cannot modify or delete this route
        """
        user = self.user
        vpc = self.test4b0_get_vpc_for_route_table_tests()
        subnet = self.test4b1_get_subnets_for_route_table_tests(vpc=vpc, count=1)[0]
        new_rt = user.ec2.connection.create_route_table(subnet.vpc_id)
        rts = user.ec2.connection.get_all_route_tables(filters={'vpc-id': vpc.id})
        for rt in rts:
            found = False
            for route in rt.routes:
                if route.gateway_id == 'local' and route.destination_cidr_block == vpc.cidr_block:
                    found = True
                    try:
                        user.ec2.connection.delete_route(rt.id, route.destination_cidr_block)
                    except Exception as EE:
                        if isinstance(EE, EC2ResponseError) and str(EE.status) == '400' and \
                                        EE.reason == 'InvalidParameterValue':
                            self.status('Passed, was not able to delete local default route for '
                                        'VPC communication:"{0}"'.format(EE))
                            break
                        else:
                            self.log.error('Unexpected error during negative test. '
                                           'Deleting default local route, err:{0}'.format(EE))
                            raise EE
                    else:
                        raise RuntimeError('Was able to delete default local route, this should '
                                           'not be permitted')
            if not found:
                user.ec2.show_route_table(rt)
                raise ValueError('No default local route found in route table?')


    def test4b7a_route_table_can_not_delete_main_table(self):
        """
        You cannot delete the main route table, but you can replace the main route table
        with a custom table that you've created (so that this table is the default table
        each new subnet is associated with).
        You can also use replace-route-table-association to change which table is the main
        route table in the VPC. You just specify the main route table's association ID and
        the route table to be the new main route table.
        """
        user = self.user
        vpc = self.test4b0_get_vpc_for_route_table_tests()
        rts = user.ec2.connection.get_all_route_tables(
            filters={'association.main': 'true', 'vpc-id': vpc.id})
        if not rts:
            raise ValueError('Main route table not found for vpc:{0}'.format(vpc.id))
        rt = rts[0]
        try:
            user.ec2.connection.delete_route_table(rt.id)
        except Exception as EE:
            if (isinstance(EE, EC2ResponseError) and str(EE.status) == '400' and
                        EE.reason == 'InvalidParameterValue'):
                self.status('Passed. Was not able to delete main route table:{0}'.format(EE))
            else:
                self.log.error('Unexpected error during negative test deleting main route table, '
                               'err:{0}'.format(EE))
                raise EE
        else:
            user.ec2.show_route_table(rt)
            user.ec2.show_vpc(vpc)
            raise RuntimeError('Was able to delete main route table:{0} for vpc:{1}'
                               .format(rt.id, vpc.id))

    def test4b7b_route_table_main_route_table_can_be_replaced(self, new_rt=None, revert=True):
        """
        You cannot delete the main route table, but you can replace the main route table
        with a custom table that you've created (so that this table is the default table
        each new subnet is associated with).
        You can also use replace-route-table-association to change which table is the main
        route table in the VPC. You just specify the main route table's association ID and
        the route table to be the new main route table.
        """
        user = self.user
        vpc = self.test4b0_get_vpc_for_route_table_tests()
        def get_main_route_table(vpc):
            rts = user.ec2.connection.get_all_route_tables(
                filters={'association.main': 'true', 'vpc-id': vpc.id})
            if not rts:
                raise ValueError('Main route table not found for vpc:{0}'.format(vpc.id))
            main = rts[0]
            return main
        main_rt = get_main_route_table(vpc)
        for ass in main_rt.associations:
            if ass.main:
                break
            else:
                ass = None
        if not ass:
            user.ec2.show_route_table(main_rt)
            raise ValueError('No association found for main route table: {0}'.format(main_rt.id))
        new_rt = new_rt or user.ec2.connection.create_route_table(vpc.id)
        if isinstance(new_rt, basestring):
            new_rt = user.ec2.connection.get_all_route_tables(new_rt)
            if not new_rt:
                raise ValueError('Could not fetch route table for: {0}'.format(new_rt))
            new_rt = new_rt[0]
        user.ec2.connection.replace_route_table_association_with_assoc(association_id=ass.id,
                                                                       route_table_id=new_rt.id)
        new_main = get_main_route_table(vpc)
        if new_main.id != new_rt.id:
            raise ValueError('New main route table:{0} != to expected route table:{1} after '
                             'requesting replacement'.format(new_main.id, new_rt.id))
        self.status('Replaced main route table.')
        if revert:
            self.status('Reverting back to previous main route table...')
            return self.test4b7b_route_table_main_route_table_can_be_replaced(new_rt=main_rt,
                                                                              revert=False)
        else:
            return new_rt

    def test4b10_route_table_add_route_basic_packet_test(self):
        """
        Launch a VM(s) in a subnet referencing the route table to be tested.
        Verify that packets are routed correctly per route provided.
        """
        raise NotImplementedError()

    def test4b11_route_table_delete_route_basic_packet_test(self):
        """
        Launch a VM(s) in a subnet referencing the route table to be tested.
        Add use an exiting route to verify traffic is routed correctly per this route entry.
        Delete the route entry and verify traffic is no longer routed accordingly.
        """
        raise NotImplementedError()


    def test4c1_route_table_max_tables_per_vpc(self):
        """
        There is a limit on the number of route tables you can create per VPC.
        cloud.vpc.routetablespervpc
        """
        raise NotImplementedError()


    def test4c2_route_table_max_routes_per_table(self):
        """
        There is a limit on the number of routes you can add per route table.
        cloud.vpc.routespertable
        """
        raise NotImplementedError()

    def test4d1_route_table_change_main_table(self):
        """
        A user can change which table is the main route table, which changes
        the default for additional new subnets, or any subnets that are not explicitly
        associated with any other route table.
        """
        raise NotImplementedError()

    def test4d3_route_table_replace_route_table_association(self):
        """
        Changes the route table associated with a given subnet in a VPC. After the operation
        completes, the subnet uses the routes in the new route table it's associated with.
        """
        raise NotImplementedError()


    def test4z0_clean_up_route_table_test_vpc_dependencies(self):
        """
        Delete the VPC and dependency artifacts created for the security group testing.
        """
        if not self.args.no_clean:
            user = self.user
            vpc = self.test4b0_get_vpc_for_route_table_tests()
            if vpc:
                user.ec2.delete_vpc_and_dependency_artifacts(vpc)

    ###############################################################################################
    #  SUBNET tests
    ###############################################################################################
    def test5b0_get_vpc_for_subnet_tests(self):
        test_vpc = self.user.ec2.get_all_vpcs(filters={'tag-key': self.SUBNET_TEST_TAG,
                                                       'tag-value': self.test_id})
        if not test_vpc:
            test_vpc = self.create_test_vpcs()
            if not test_vpc:
                raise RuntimeError('Failed to create test VPC for subnet tests?')
            test_vpc = test_vpc[0]
            self.user.ec2.create_tags([test_vpc.id], {self.SUBNET_TEST_TAG: self.test_id})
        else:
            test_vpc = test_vpc[0]
        return test_vpc

    def test5z0_test_clean_up_subnet_test_vpc_dependencies(self):
        """
        Delete the VPC and dependency artifacts created for the security group testing.
        """
        if not self.args.no_clean:
            user = self.user
            vpc = self.test5b0_get_vpc_for_subnet_tests()
            if vpc:
                user.ec2.delete_vpc_and_dependency_artifacts(vpc)

    ###############################################################################################
    #  ENI tests
    ###############################################################################################

    def test6b0_get_vpc_for_eni_tests(self):
        test_vpc = self.user.ec2.get_all_vpcs(filters={'tag-key': self.ENI_TEST_TAG,
                                                       'tag-value': self.test_id})
        if not test_vpc:
            test_vpc = self.create_test_vpcs()
            if not test_vpc:
                raise RuntimeError('Failed to create test VPC for eni tests?')
            test_vpc = test_vpc[0]
            self.user.ec2.create_tags([test_vpc.id], {self.ENI_TEST_TAG: self.test_id})
        else:
            test_vpc = test_vpc[0]
        return test_vpc

    def test6z0_test_clean_up_eni_test_vpc_dependencies(self):
        """
        Delete the VPC and dependency artifacts created for the security group testing.
        """
        if not self.args.no_clean:
            user = self.user
            vpc = self.test6b0_get_vpc_for_eni_tests()
            if vpc:
                user.ec2.delete_vpc_and_dependency_artifacts(vpc)



    ###############################################################################################
    # Misc tests
    ###############################################################################################

    def clean_method(self):
        self.user.ec2.clean_all_test_resources()
        if self.new_ephemeral_user:
            self.log.debug('deleting new user account:"{0}"'
                       .format(self.new_ephemeral_user.account_name))
            self.tc.admin.iam.delete_account(account_name=self.new_ephemeral_user.account_name,
                                             recursive=True)


    ###############################################################################################
    #  Packet tests
    ###############################################################################################



if __name__ == "__main__":
    testcase = VpcBasics()
    # Create a single testcase to wrap and run the image creation tasks.
    result = testcase.run()
    if result:
        testcase.log.error('TEST FAILED WITH RESULT:{0}'.format(result))
    else:
        testcase.status('TEST PASSED')
    exit(result)

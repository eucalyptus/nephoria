



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
from nephoria import CleanTestResourcesException
from nephoria.testcase_utils.cli_test_runner import CliTestRunner, TestResult, SkipTestException
from nephoria.aws.ec2.ec2ops import EC2ResourceNotFoundException
from nephoria.aws.ec2.euinstance import EuInstance
from cloud_utils.net_utils import packet_test, is_address_in_network, test_port_status, \
    get_network_info_for_cidr
from cloud_utils.net_utils.sshconnection import CommandExitCodeException, SshConnection, \
    CommandTimeoutException
from cloud_utils.log_utils import markup, printinfo, get_traceback, TextStyle, ForegroundColor, \
    BackGroundColor, yellow, red, cyan, blue, green
from cloud_utils.system_utils import local
from boto.exception import BotoServerError, EC2ResponseError
from boto.vpc.subnet import Subnet
from boto.vpc.vpc import VPC
from boto.ec2.image import Image
from boto.ec2.group import Group
from boto.ec2.securitygroup import SecurityGroup
from botocore.exceptions import ClientError
import operator
from paramiko import SSHException
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

"""
# Debug for monitoring files open by python. When running the packet test matrix(s) the OS
# can complain about too many open FDs per user.
# Python may be leaking FDs sockets, files, etc from it's sub processes despite closing all
# related FDs (including stdin, out, err etc for pipes, etc)
def printOpenFiles():
    print yellow("\n### %d OPEN FILES: [%s]\n" % (len(openfiles), ", ".join(f.x for f in openfiles)))

class newfile(oldfile):
    def __init__(self, *args):
        self.x = args[0]
        print yellow("### OPENING %s ###" % str(self.x))
        oldfile.__init__(self, *args)
        openfiles.add(self)
        printOpenFiles()

    def close(self):
        print yellow("### CLOSING %s ###" % str(self.x))
        oldfile.close(self)
        openfiles.remove(self)
        printOpenFiles()

oldopen = __builtin__.open
def newopen(*args):
    return newfile(*args)
__builtin__.file = newfile
__builtin__.open = newopen

"""

class VpcSuite(CliTestRunner):

    _CLI_DESCRIPTION = "Tests for Eucalyptus EC2 VPC functionality."

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
    NAT_GW_TEST_TAG = 'NAT_GATEWAY_TEST_TAG'
    NET_ACL_TEST_TAG = 'NET_ACL_TEST_TAG'

    def post_init(self):
        self.test_id = "{0}{1}".format(int(time.time()), randint(0, 50))
        self.id = str(int(time.time()))
        self.test_name = self.__class__.__name__
        self._tc = None
        self._group = None
        self._zonelist = []
        self._keypair = None
        self._emi = None
        self._user = None
        self._addresses = []
        self._test_vpcs = []
        self._proxy_instances = {}
        self._security_groups = {}
        self._test_enis = {}
        self._test_addrs = {}
        self._original_vmtypes = {}
        self.last_status_msg = "Init {0}".format(self.test_name)

    def status(self, msg, markups=None):
        self.last_status_msg = msg
        super(VpcSuite, self).status(msg=msg, markups=markups)

    @property
    def tc(self):
        tc = getattr(self, '_tc', None)
        if not tc and self.args.clc or self.args.environment_file:
            tc = TestController(hostname=self.args.clc,
                                environment_file=self.args.environment_file,
                                password=self.args.password,
                                log_level=self.args.log_level,
                                log_file=self.args.log_file,
                                log_file_level=self.args.log_file_level)
            setattr(self, '_tc', tc)
        return tc

    @property
    def my_tag_name(self):
        return '{0}_CREATED_TESTID'.format(self.__class__.__name__)

    def store_addr(self, user, addr):
        if user in self._test_addrs:
            self._test_addrs[user].add(addr)
        else:
            self._test_addrs[user] = set()
            self._test_addrs[user].add(addr)
        return self._test_addrs

    def modify_vm_type_store_orig(self, vmtype, cpu=None, disk=None, memory=None,
                                  network_interfaces=None):
        if not isinstance(vmtype, basestring):
            vmtype = vmtype.name
        orig = self._original_vmtypes.get(vmtype) or \
               self.tc.admin.ec2.get_instance_type_info(vmtype)
        if not orig:
            raise ValueError('No vmtype info found for type:{0}'.format(vmtype))
        self._original_vmtypes[vmtype] = orig
        return self.tc.admin.ec2.modify_instance_type(vmtype, cpu=cpu, disk=disk,
                                                      memory=memory,
                                                      network_interfaces=network_interfaces)

    def restore_vm_types(self):
        for vmtype, info in self._original_vmtypes.iteritems():
            self.tc.admin.ec2.modify_instance_type(vmtype, cpu=info.cpu, disk=info.disk,
                                                   memory=info.memory,
                                                   network_interfaces=info.networkinterfaces)
        self._original_vmtypes = {}

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
                                    vmtype=self.args.proxy_vmtype,
                                    systemconnection=self.tc.sysadmin)[0]
            proxy_instances[zone] = pi
            self._proxy_instances = proxy_instances
        return pi

    def get_test_enis_for_subnet(self, subnet, status='available', apply_groups=None, count=0,
                                 exclude=None, user=None):
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
        exclude = exclude or []
        if exclude and not isinstance(exclude, list):
            exclude = [exclude]
        exclude_ids = []
        for xeni in exclude:
            if isinstance(xeni, basestring):
                exclude_ids.append(xeni)
            else:
                exclude_ids.append(xeni.id)
        filters = {'subnet-id': subnet.id, 'tag-key': self.my_tag_name, 'tag-value': self.id}
        if status:
            filters['status'] = status
        enis = user.ec2.connection.get_all_network_interfaces(filters=filters) or []
        keep = []
        for eni in enis:
            if eni.id not in exclude_ids:
                keep.append(eni)
        enis = keep
        if count and len(enis) < count:
            for x in xrange(0, (count-len(enis))):
                eni = user.ec2.connection.create_network_interface(
                    subnet_id=subnet.id, description='This was created by: {0}'.format(self.id))
                user.ec2.create_tags(eni.id, {self.my_tag_name: self.id})
                eni.update()
                enis.append(eni)
        if apply_groups:
            for eni in enis:
                user.ec2.modify_network_interface_attributes(eni, group_set=[apply_groups])
                eni.update()
        return enis

    def add_subnet_interface_to_proxy_vm(self, subnet):
        pass

    def get_keypair_name(self, user):
        return "{0}_{1}_{2}".format(self.__class__.__name__, user.account_id, self.test_id)

    def get_keypair(self, user=None):
        user = user or self.user
        keys = getattr(self, '_keypairs', None)
        if keys is None:
            keys = {}
            setattr(self, '_keypairs', keys)
        keypair = keys.get(user, None)
        if not keypair:
            # See if this keypair is already created and present in the local dir...
            keypairs = user.ec2.get_all_current_local_keys(key_name=self.get_keypair_name(user))
            if keypairs:
                keypair = keypairs[0]
            else:
                keypair = user.ec2.get_keypair(key_name=self.get_keypair_name(user))
            keys[user] = keypair
        return keys[user]

    @property
    def group(self):
        group = getattr(self, '_group', None)
        if not group:
            group_name = "{0}_group".format(self.__class__.__name__)
            group = self.user.ec2.add_group(group_name)
            self._security_groups[group.vpc_id].append(group)
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
                self._zonelist = [str(self.args.zone)]
            else:
                self._zonelist = []
                for zone in self.user.ec2.get_zone_names():
                    self._zonelist.append(zone)
            if not self._zonelist:
                msg = "Could not discover an availability zone to perform tests in. Please " \
                      "specify zone"
                self.log.error("{0}\n{1}".format(get_traceback(), msg))
                raise RuntimeError(None)
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
                user.ec2.create_route(default_rt.id, '0.0.0.0/0', gw.id)
            user.log.info('Created the following VPC: {0}'.format(new_vpc.id))
            user.ec2.show_vpc(new_vpc)
        return test_vpcs

    def create_subnet_and_tag(self, vpc_id, cidr_block, availability_zone=None, dry_run=False,
                              user=None, tag=None, tag_value=None):
        user = user or self.user
        tag = tag or self.my_tag_name
        subnet = user.ec2.connection.create_subnet(vpc_id=vpc_id, cidr_block=cidr_block,
                                                   availability_zone=availability_zone,
                                                   dry_run=dry_run)

        user.ec2.create_tags(subnet.id, {tag: tag_value})
        return subnet

    def create_test_subnets(self, vpc, zones=None, count_per_zone=1, user=None, verbose=False):
        """
        This method is intended to provided the convenience of returning a number of subnets per
        zone equal to the provided 'count_per_zone'. The intention is this method will
        take care of first attempting to re-use existing subnets, and creating new ones if needed
        to meet the count requested.

        :param vpc: boto VPC object
        :param count_per_zone: int, number of subnets needed per zone
        :return: list of subnets
        """
        max_net = 253
        user = user or self.user
        test_subnets = []
        zones = zones or self.zones
        if not zones:
            raise ValueError('Could not find zones for this test?')
        if not isinstance(zones, list):
            zones = [zones]
        self.log.debug('create_test_subnets: vpc:{0}, zones:{1}, count_per_zone:{2}, user:{3}'
                       .format(vpc, zones, count_per_zone, user))
        for x in xrange(0, count_per_zone):
            for zone in zones:
                # Use a /24 of the vpc's larger /16
                subnets = user.ec2.get_all_subnets(filters={'vpc-id': vpc.id})

                subnet_cidr = None
                attempts = 0
                while subnet_cidr is None and attempts < max_net:
                    attempts += 1
                    subnet_cidr =  re.sub("(\d+.\d+).\d+.\d+.\d\d",
                                          r"\1.{0}.0/24".format(attempts), vpc.cidr_block)
                    if not subnet_cidr:
                        raise ValueError('Failed to parse subnet_cidr from vpc cidr block:{0}'
                                         .format(vpc.cidr_block))
                    for sub in subnets:
                        if sub.cidr_block == subnet_cidr or \
                                is_address_in_network(subnet_cidr.strip('/24'), sub.cidr_block):
                            if verbose:
                                self.log.debug('Subnet: {0} conflicts with existing:{1}, '
                                               'attempt:{0}/{1}'.format(subnet_cidr,
                                                                        sub.cidr_block,
                                                                        attempts, max_net))
                            subnet_cidr = None
                            break
                try:
                    subnet = self.create_subnet_and_tag(vpc_id=vpc.id, cidr_block=subnet_cidr,
                                                        availability_zone=zone, user=user)
                except:
                    try:
                        self.log.error('Existing subnets during failed create request:')
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
            return existing[0: count]
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
            group = self.set_group_rules(group, rules=rules, user=user)
            ret_groups.append(group)
        user.ec2.show_security_groups(ret_groups)
        return ret_groups

    def set_group_rules(self, group, rules, user=None):
        user = user or self.user
        user.ec2.revoke_all_rules(group)
        for rule in rules:
            protocol, port, end_port, cidr_ip = rule
            user.ec2.authorize_group(group=group, port=port, end_port=end_port,
                                     protocol=protocol)
        group = user.ec2.get_security_group(group.id)
        if not group:
            raise ValueError('Was not able to retrieve sec group: {0}/{1}'
                             .format(group.name, group.id))
        return group


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
    def get_test_instances(self, zone, group_id, vpc_id=None, subnet_id=None,
                           state='running', count=None, monitor_to_running=True,
                           private_addressing=False, instance_type=None, auto_connect=True,
                           timeout=480, user=None, exclude=None):
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
        if private_addressing:
            auto_connect = False
        if exclude:
            if not isinstance(exclude, list):
                exclude = [exclude]
            for i in exclude:
                if isinstance(i, basestring):
                    exclude_instances.append(i)
                else:
                    exclude_instances.append(i.id)
        def check_connections(vms):
            if not auto_connect:
                self.log.debug('Not checking VM connections, auto_connect={0}'
                               .format(auto_connect))
                return
            ipt = user.ec2.show_instances(vms, printme=False)
            self.status('Checking connections for the following instances...\n{0}\n'.format(ipt))
            for vm in vms:
                if not vm.ip_address:
                    self.log.debug('Attempting to allocate and assoc a public addr for VM:{0}'
                                   .format(vm))
                    addr = user.ec2.allocate_address()
                    self.store_addr(user, addr)
                    addr.associate(vm.id)
                start = time.time()
                elapsed = 0
                timeout = 60
                good = False
                while not good and (elapsed < timeout):
                    elapsed = int(time.time() - start)
                    try:
                        if not vm.keypair:
                            vm.keypair = self.get_keypair(user)
                        self.log.debug('Attepting to refresh ssh connection to:{0}, ip:{1}'.
                                       format(vm.id, vm.ip_address))
                        vm.connect_to_instance()
                        if not vm.ssh:
                            vm.keypath = None
                        good = True
                        break
                    except Exception as E:
                        self.log.error('{0}\nError while attempting to connect to vm:{1}, '
                                       'elapsed:{2}, err:{3}'.format(get_traceback(), vm.id,
                                                                     elapsed, E))
                        if elapsed > timeout:
                            raise E
                        time.sleep(5)

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
        if instance_type:
            filters['instance-type'] = instance_type
        queried_instances = user.ec2.get_instances(filters=filters)
        self.log.debug('queried_instances:{0}'.format(queried_instances))
        for q_instance in queried_instances:
            if private_addressing and q_instance.ip_address:
                continue
            if (q_instance.state in ['pending', 'running'] and
                        q_instance.id not in exclude_instances):
                for instance in user.ec2.test_resources.get('instances'):
                    if instance.id == q_instance.id:
                        existing_instances.append(instance)
        # Dont connect in the convert method in case we want to monitor to running state later...
        for instance in existing_instances:
            euinstance = user.ec2.convert_instance_to_euinstance(instance,
                                                                 keypair=self.get_keypair(user),
                                                                 auto_connect=False)
            euinstance.log.set_stdout_loglevel(self.args.log_level)
            euinstance.auto_connect = auto_connect
            instances.append(euinstance)
        self.log.debug('existing_instances:{0}'.format(existing_instances))
        # Monitor to running will connect to instances if the auto connect flag is set
        for instance in instances:
            instance.auto_connect = auto_connect
        if not count:
            if monitor_to_running:
                instances = user.ec2.monitor_euinstances_to_running(instances, timeout=timeout)
            ipt = user.ec2.show_instances(instances, printme=False)
            self.status('Returning the following instances...\n{0}\n'.format(ipt))
            # Make sure these VMs have active connections...
            check_connections(instances)
            return instances
        if len(instances) >= count:
            instances = instances[0:count]
            # Make sure these VMs have active connections...
            check_connections(instances)
            if monitor_to_running:
                return user.ec2.monitor_euinstances_to_running(instances, timeout=timeout)
            ipt = user.ec2.show_instances(instances, printme=False)
            self.status('Returning the following instances...\n{0}\n'.format(ipt))
            return instances
        else:
            # Make sure these VMs have active connections...
            check_connections(instances)
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
                                                 auto_connect = auto_connect,
                                                 private_addressing=private_addressing,
                                                 user=user)
            instances.extend(new_ins)
            if len(instances) != count:
                raise RuntimeError('Less than the desired:{0} number of instances returned?'
                                   .format(count))
            ipt = user.ec2.show_instances(instances, printme=False)
            self.status('Returning the following instances...\n{0}\n'.format(ipt))
            return instances

    @printinfo
    def create_test_instances(self, emi=None, key=None, group=None, zone=None, subnet=None,
                              count=1, monitor_to_running=True, auto_connect=True, tag=True,
                              private_addressing=False, network_interface_collection=None,
                              vmtype='m1.small', user=None):
        """
        Creates test instances using the criteria provided. This method is intended to be
        called from 'get_test_instances()'.

        :param emi: emi id
        :param key: key obj or id
        :param group: group obj or id
        :param zone: zone name
        :param subnet: subnet obj or id
        :param count: number of VMs to run
        :param network_interface_collection: boto NetworkInterfaceCollection() object
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
                                       network_interfaces=network_interface_collection,
                                       private_addressing=private_addressing,
                                       vmtype=vmtype,
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

    def ping_primary_eni_private_ip_from_clc_net_namespace(self, eni, timeout=30):
        start = time.time()
        elapsed = 0
        attempts = 0
        error = None
        while elapsed < timeout:
            error = None
            attempts += 1
            elapsed = int(time.time() - start)
            self.status('Checking eni:{0} private ip:{1} from VPC:{2}\'s network namespace '
                        'on the CLC. Attempt: {3}, Elapsed:{4}'
                        .format(eni.id, eni.private_ip_address, eni.vpc_id, attempts, elapsed))
            clc = self.tc.sysadmin.clc_machine
            ret = clc.ping_cmd(eni.private_ip_address, net_namespace=eni.vpc_id)
            status = ret.get('status')
            output = ret.get('output')
            cmd = ret.get('cmd')

            msg = 'Attempt:{0}. Elapsed:{1}. Cmd:"{2}", exited with status:{3}. Output:"{4}"' \
                .format(attempts, elapsed, cmd, status, output)
            if status:
                error = "ERROR: {0}".format(msg)
            self.log.debug(msg)

        if error:
            raise RuntimeError(error)

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
            if default_vpc:
                user.ec2.show_vpc(default_vpc)
            raise ValueError('{0}: Default Internet Gateway not found for default vpc:{1}'
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
        """
        Note:
        route.origin - Describes how the route was created. create-route-table indicates that
        the route was automatically created when the route table was created; create-route
        indicates that the route was manually added to the route table;
        enable-vgw-route-propagation indicates that the route was propagated by route propagation

        """
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
                if route.origin != 'CreateRouteTable':
                    raise ValueError('Default Cidr route has incorrect route origin:{0}, '
                                     'should be:{1}'.format(route.origin, 'CreateRouteTable'))
                default_cidr_route = True
            if check_igw:
                if route.gateway_id == igw.id and route.destination_cidr_block == '0.0.0.0/0':
                    if route.origin != 'CreateRoute':
                        raise ValueError('Default IGW route has incorrect route origin:{0}, '
                                         'should be:{1}'.format(route.origin, 'CreateRoute'))
                    default_igw_route = True
            if default_igw_route and default_cidr_route:
                break
        if not default_cidr_route:
            raise ValueError('{0}: Default route for VPC network:{1} not found'
                             .format(vpc.id, vpc.cidr_block))
        if not default_igw_route:
            raise ValueError('{0}: Default route for IGW:{1} not found'
                             .format(vpc.id, igw.id))

    def check_user_default_security_group_rules(self, user=None, vpc=None):
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
        vpc = vpc or self.check_user_default_vpcs(user=user)
        default_group = user.ec2.get_security_group(name='default', vpc_id=vpc.id)
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
                                                     group_id=sec_group.id,
                                                     subnet_id=subnet.id,
                                                     vpc_id=vpc.id,
                                                     count=instance_count,
                                                     monitor_to_running=False,
                                                     user=user))
        user.ec2.monitor_euinstances_to_running(instances=instances)
        self.log.info('basic_instance_ssh_default_vpc passed')
        return instances


    def vm_packet_test(self, vm_tx, vm_rx, dest_ip, protocol='icmp', port=100, packet_count=2,
                       src_addrs=None, user=None, expected_count=None, verbose=True,
                       header_info=None):
        """
        Basic VM to VM packet test. Test sets up a simple client (on vm_tx) and server  (on vm_rx)
        to send, recieve, and filter packets between 2 VMs using a provided protocol and
        port (if applicable). The test allows for 4 protocols; icmp, udp, tcp, and sctp.

        Args:
            vm_tx: nephoria euinstance obj
            vm_rx: nephoria euinstance obj
            dest_ip: Destination IP to run this test. Note: The test will attempt to determine the
                     outgoing interface on vm_tx based on this ip.
            protocol: Protocol to use for this test; icmp, udp, tcp or sctp. Name or number can
                      be provided.
            port: port to send and received packets on. Note: if using ICMP the port will be set
                  to None.
            packet_count: Number of packets to send
            expected_count: Number of packets expected to be received on vm_rx. The default/None,
                            will set this equal to the sent 'packet_count' value.
            src_addrs: IP string or list of IP strings for the vm_rx side to use to filter
                       incoming packets. By default the test attempts to determine the outgoing
                       interface on vm_tx and set this as the filter. Set this to '[]' if no
                       filtering on source address is desired.
            user: nephoria user_context obj.
            verbose: send test output on each euinstance obj to log.debug, and print table to
                     log.info.

        Returns: set containing: (dictionary of packets received, pass/fail boolean,
        Prettytable of results)

        """
        for vm in [vm_tx, vm_rx]:
            if not vm.ssh:
                self.log.error('{0}\nPacket test requires vm_tx and vm_rx to have established SSH '
                                 'sessions. {0} did not'.format(get_traceback(), vm.id))
                raise ValueError('Packet test requires vm_tx and vm_rx to have established SSH '
                                 'sessions. {0} did not'.format(vm.id))
            vm.update()

        def bold(txt):
            return markup(txt, markups=TextStyle.BOLD)
        user = user or self.user
        proto_dict = {'icmp': 1,
                      'tcp': 6,
                      'udp': 17,
                      'sctp': 132}
        proto_names = {1: 'icmp',
                      6: 'tcp',
                      17: 'udp',
                      132: 'sctp'}
        if expected_count is None:
            expected_count = packet_count
        if protocol and str(protocol).lower() in proto_dict.keys():
            protocol = proto_dict[protocol]
        protocol = int(protocol)
        if protocol not in proto_dict.values():
            raise ValueError('Protocol:"{0}" not supported. Only protocols:"{1}"'
                             .format(protocol, proto_dict))
        if protocol == 1:
            port = None
        if protocol in [6, 132]:
            bind = True
        else:
            bind = False
        proto_name = proto_names[protocol]
        eni_rx = None
        private = None
        if vm_tx.vpc_id != vm_rx.vpc_id:
            private = False
        else:
            for eni in vm_rx.interfaces:
                if eni.private_ip_address == dest_ip:
                    eni_rx = eni
                    private = True
                    break
                elif getattr(eni, 'publicIp', None) and \
                                dest_ip == str(getattr(eni, 'publicIp', None)):
                    eni_rx = eni
                    private = False
                    break
        if not eni_rx:
            try:
                vm_rx.show_enis()
                vm_rx.show_network_device_info()
            except Exception as E:
                self.log.error('{0}\nIgnoring error showing network dev info:"{1}"'
                               .format(get_traceback(), E))
            raise ValueError('Could not find ENI on {0} for dest_ip:{1}'.format(vm_rx, dest_ip))
        eni_tx = None
        for eni in vm_tx.interfaces:
            subnet = user.ec2.get_subnet(eni.subnet_id)
            if is_address_in_network(eni_rx.private_ip_address, subnet.cidr_block):
                eni_tx = eni
                break
        if eni_tx is None:
            # Assume the packet will be sent to the default GW on the primary interface
            eni_tx = vm_tx.interfaces[0]
        if src_addrs is None:
            # If the test is not using the rx VM's private IP, and the expected source address
            # was not provided, remove the src_addrs filter since the src could be unknown.
            if not private:
                src_addrs = []
            else:
                src_addrs = eni_tx.private_ip_address

        self.status('Sending from ENI:{0} to ENI:{1} DEST_IP:{2}'.format(eni_rx.id, eni_tx.id,
                                                                         dest_ip))
        user.ec2.show_network_interfaces([eni_rx, eni_tx])
        result = {}
        tx_dev_info = None
        rx_dev_info = None
        start = time.time()
        elapsed = 0
        timeout = 30
        while not (tx_dev_info and rx_dev_info) and (elapsed < timeout):
            elapsed = int(time.time() - start)
            tx_dev_info = vm_tx.get_network_local_device_for_eni(eni_tx)
            rx_dev_info = vm_rx.get_network_local_device_for_eni(eni_rx)
            if not tx_dev_info:
                self.log.error(red('Failed to get net dev info from vm_tx:"{0}". Elapsed:{1}'
                                   .format(vm_tx, elapsed)))
            if not rx_dev_info:
                self.log.error(red('Failed to get net dev info from vm_rx:"{0}". Elapsed:{1}'
                                   .format(vm_rx, elapsed)))
            if tx_dev_info and rx_dev_info:
                break

        if not (tx_dev_info and rx_dev_info):
            raise RuntimeError('Failed to get dev info. vm_rx:{0}={1}, vm_tx:{2}={3}'
                               .format(vm_rx, rx_dev_info, vm_tx, tx_dev_info))
        try:
            result = packet_test(vm_tx.ssh, vm_rx.ssh, dest_ip=dest_ip,
                                 protocol=protocol, bind=bind, port=port, count=packet_count,
                                 verbose=True, src_addrs=src_addrs)
        except Exception as DOH:
            self.log.error("{0}\nError in packet test:{1}".format(get_traceback(), DOH))
            result['error'] = "{0}, {1}".format(result.get('error') or "", DOH)
        packet_dict = result.get('packets')
        total_pkts = 0
        if packet_dict:
            for src, dest_dict in packet_dict.iteritems():
                for dest_ip, port_dict in dest_dict.iteritems():
                    for port, count in port_dict.iteritems():
                        total_pkts += int(count)
        if total_pkts != expected_count:
            test_passed = False
            test_result = markup('FAILED', markups=[ForegroundColor.WHITE,
                                                    BackGroundColor.BG_RED])
            result['error'] = "{0}, {1}".format(result.get('error') or "",
                                                "Rx'd packets:{0} != expected_packets:{1}"
                                                .format(total_pkts, expected_count))
        else:
            test_passed  = True
            test_result = markup('PASSED', markups=[ForegroundColor.WHITE,
                                                    BackGroundColor.BG_GREEN])
        # Build the results table...
        column_width = 25
        info_hdr = ''.center(column_width)
        tx_hdr = bold('SENDER').center(column_width)
        rx_hdr = bold('RECEIVER').center(column_width)
        pt = PrettyTable([info_hdr, tx_hdr, rx_hdr])
        pt.hrules = 1
        pt.vrules = 1
        pt.horizontal_char = '-'
        pt.vertical_char = " "
        pt.junction_char = '+'
        pt.align = 'l'
        pt.max_width[info_hdr] = column_width
        pt.max_width[tx_hdr] = column_width
        pt.max_width[rx_hdr] = column_width

        same = markup('SAME', markups=[TextStyle.BOLD, ForegroundColor.BLUE,
                                       BackGroundColor.BG_WHITE])
        diff = markup('DIFF', markups=[TextStyle.BOLD, ForegroundColor.WHITE,
                                       BackGroundColor.BG_BLUE])
        if eni_tx.subnet_id != eni_rx.subnet_id:
            sub_diff = diff
        else:
            sub_diff = same
        tx_groups = [x.id for x in eni_tx.groups]
        tx_groups.sort()
        rx_groups = [x.id for x in eni_rx.groups]
        rx_groups.sort()
        if tx_groups != rx_groups:
            group_diff = diff
        else:
            group_diff = same
        if vm_tx.placement != vm_rx.placement:
            zone_diff = diff
        else:
            zone_diff = same
        tx_guest_ip = tx_dev_info.get('local_ip')
        if tx_guest_ip != eni_tx.private_ip_address:
            tx_guest_ip = red(tx_guest_ip)
        rx_guest_ip = rx_dev_info.get('local_ip')
        if rx_guest_ip != eni_rx.private_ip_address:
            rx_guest_ip = red(rx_guest_ip)
        rx_pkts = "{0} / {1}".format(total_pkts, expected_count)
        if not test_passed:
            rx_pkts = red(rx_pkts)
        # Add the client side info...
        pt.add_row(['VM_ID'.ljust(column_width), str(vm_tx.id).ljust(column_width),
                    str(vm_rx.id).ljust(column_width)])
        pt.add_row(['ENI', eni_tx.id, eni_rx.id])
        pt.add_row(['INDEX-DEV', "{0}-{1} ({2})".format(eni_tx.attachment.device_index,
                                                       tx_dev_info.get('dev_name'),
                                                       tx_dev_info.get('operstate')),
                    "{0}-{1} ({2})".format(eni_rx.attachment.device_index,
                                          rx_dev_info.get('dev_name'),
                                          rx_dev_info.get('operstate'))])
        pt.add_row(['ZONE', "{0}\n'{1}'".format(zone_diff, vm_tx.placement),
                    "{0}\n'{1}'".format(zone_diff, vm_rx.placement)])
        pt.add_row(['SUBNET', "{0}\n{1}".format(sub_diff, eni_tx.subnet_id),
                    "{0}\n{1}".format(sub_diff, eni_rx.subnet_id),])
        pt.add_row(['GROUPS', "{0}\n{1}".format(group_diff, ",".join(tx_groups)),
                    "{0}\n{1}".format(group_diff, ",".join(rx_groups))])
        pt.add_row(['ENI-IP', eni_tx.private_ip_address, eni_rx.private_ip_address])
        pt.add_row(['GUEST IP', tx_guest_ip, rx_guest_ip    ])
        pt.add_row(['PUB_IP', getattr(eni_tx, 'publicIp', None),
                    getattr(eni_rx, 'publicIp', None)])
        pt.add_row(['PROTOCOL', proto_name, proto_name])
        pt.add_row([bold('TX PKTS'), packet_count, "--"])
        pt.add_row([bold("RX PKTS"), "--", rx_pkts])
        pt.add_row([bold('RESULT'), test_result, test_result])

        title = markup('{0} PACKET TEST RESULTS'.format(proto_name.upper()),
                       [TextStyle.INVERSE, TextStyle.BOLD])

        max_width = (column_width * 3) + 10
        header_info = header_info or '{0} PACKET TEST RESULTS'.format(proto_name.upper())

        title = markup(str(header_info).center(max_width-10),
                       [TextStyle.INVERSE, TextStyle.BOLD])
        main_pt = PrettyTable([title])

        main_pt.padding_width = 0
        main_pt.hrules = 1
        main_pt.horizontal_char = "="
        main_pt.max_width[title] = max_width
        main_pt.add_row([pt.get_string()])
        if result.get('error', None):
            main_pt.add_row([red('TEST ERRORS:{0}'.format(result.get('error')))])
        else:
            main_pt.add_row(['TEST ERRORS: None'])
        if verbose:
            self.log.debug("\n{0}\n".format(main_pt))
        return (result, test_passed, main_pt)

    @printinfo
    def packet_test_scenario(self, zone_tx, zone_rx, sec_group_tx, sec_group_rx, subnet_tx,
                             subnet_rx, use_private, protocol, port, count, bind, retries=2,
                             expected_packets=None, set_security_group=True, user=None,
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
        user = user or self.user
        ins1 = self.get_test_instances(zone=zone_tx, group_id=sec_group_tx, subnet_id=subnet_tx,
                                       user=user, count=1)
        if not ins1:
            raise RuntimeError('Could not fetch or create test instance #1 with the following '
                               'criteria; zone:{0}, sec_group:{1}, subnet:{2}, count:{3}'
                               .format(zone_tx, sec_group_tx, subnet_tx, 1))
        ins1 = ins1[0]
        ins2 = self.get_test_instances(zone=zone_rx, group_id=sec_group_rx, subnet_id=subnet_rx,
                                       user=user,count=1, exclude=[ins1.id])
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
                user.ec2.authorize_group(group=group, port=port, end_port=end_port,
                                         protocol=protocol)
        if set_security_group:
            user.ec2.revoke_all_rules(sec_group_tx)
            user.ec2.revoke_all_rules(sec_group_rx)
            base_rule = ('tcp', 22, 22, '0.0.0.0/0')
            test_rule = (protocol, port or -1, port or -1, src_ip)
            apply_rule(base_rule, [sec_group_tx, sec_group_rx])
            apply_rule(test_rule, [sec_group_rx])

        self.log.debug('{0}{1}\n'.format(markup('\nAttempting packet test with instances:\n',
                                                [ForegroundColor.BLUE, BackGroundColor.BG_WHITE]),
                        self.tc.admin.ec2.show_instances([ins1, ins2], printme=False)))
        user.ec2.show_security_groups([sec_group_tx, sec_group_rx])
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

                self.log.debug(markup('Got results:{0}'.format(results),
                                      [BackGroundColor.BG_BLACK, ForegroundColor.WHITE]))


                if results['count'] != expected_packets and not results['error']:
                    raise RuntimeError('Packet count does not equal expected count provided. '
                                       'No error in output found')
                results['header'] = header_pt.get_string()
                self.log.debug("\n{0}".format(results.get('header')))
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
        Check default route entries...
        Regarding route.origin...
        route.origin - Describes how the route was created.
        This test checks for CreateRouteTable as the origin. ec2ops checks for user created
        origins for all other create route requests.
        References
        """
        return self.check_user_default_routes_present(user=self.new_ephemeral_user)

    def test1ga_new_user_default_security_group_rules(self):
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

    def test1gb_new_user_default_security_group_packet_test(self, egress_test_ip=None):
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
        user = self.new_ephemeral_user
        vpc = self.test1b_new_user_default_vpc()
        subnet = user.ec2.connection.get_all_subnets(filters={'vpc-id': vpc.id,
                                                              'default-for-az': 'true'})[0]
        def_sg = user.ec2.get_security_group(name='default', vpc_id=vpc.id)
        self.log.debug('This tests is making the assumption that the test user was created '
                       'in this test and the default security group has not been manipulated.')
        # tbd - change this assumption? ^
        user.ec2.show_security_group(def_sg)
        vms = self.create_test_instances(group=def_sg, subnet=subnet,
                                         auto_connect=False, count=2, user=user)
        self.status('Attempting to reach vm on tcp/22 this should not be allowed...')

        for vm in vms:
            try:
                test_port_status(vm.ip_address, 22)
                raise RuntimeError('Was able to connect to a {0} in the default security group. '
                                   'Note: This test makes the assumption the sec group is newly '
                                   'created and not manipulated'.format(vm.id))
            except socket.error as SE:
                self.status('Could not reach vm {0} in default sg, passed:{0}'.format(vm.id, SE))
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
                                  use_private=False, protocol=1, port=None, count=5, user=user,
                                  bind=False, set_security_group=False,
                                  ssh_tx=vm1.ssh, ssh_rx=vm2.ssh))
        results.append(self.packet_test_scenario(zone_tx=vm2.placement, zone_rx=vm1.placement,
                                  sec_group_tx=def_sg.id, sec_group_rx=def_sg.id,
                                  subnet_tx=vm2.subnet_id, subnet_rx=vm1.subnet_id,
                                  use_private=False, protocol=6, port=100, count=5, user=user,
                                  bind=True, set_security_group=False,
                                  ssh_tx=vm1.ssh, ssh_rx=vm2.ssh))
        results.append(self.packet_test_scenario(zone_tx=vm2.placement, zone_rx=vm1.placement,
                                  sec_group_tx=def_sg.id, sec_group_rx=def_sg.id,
                                  subnet_tx=vm2.subnet_id, subnet_rx=vm1.subnet_id,
                                  use_private=False, protocol=17, port=101, count=5, user=user,
                                  bind=False, set_security_group=False,
                                  ssh_tx=vm1.ssh, ssh_rx=vm2.ssh))
        results.append(self.packet_test_scenario(zone_tx=vm2.placement, zone_rx=vm1.placement,
                                  sec_group_tx=def_sg.id, sec_group_rx=def_sg.id,
                                  subnet_tx=vm2.subnet_id, subnet_rx=vm1.subnet_id,
                                  use_private=False, protocol=132, port=101, count=5, user=user,
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
        self.status('Packet test Complete. Passed')


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
            test = self.get_testunit_by_method(self.test1e_new_user_default_route_table)
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
            test = self.get_testunit_by_method(self.test1ga_new_user_default_security_group_rules)
            if test and test.result != TestResult.not_run:
                raise SkipTestException('Test already run for the test user')
        return self.check_user_default_security_group_rules(user=self.user)

    def test2g_test_user_default_routes(self):
        """
        Definition:
        Attempts to verify that a test user has a default routes present for the vpc
        cidr block and default igw in it's route table
        Check default route entries...
        Regarding route.origin...
        route.origin - Describes how the route was created.
        This test checks for CreateRouteTable as the origin. ec2ops checks for user created
        origins for all other create route requests.
        References
        """
        return self.check_user_default_routes_present(user=self.user)

    def test2v1_vpc_cidr_block_range_large(self):
        """
        This test attempts to create a vpc larger than allowed cidr block range...
        You can assign a single CIDR block to a VPC. The allowed block size is between
        a /28 netmask and /16 netmask. In other words, the VPC can contain from 16 to 65,536 IP
         addresses. You can't change the size of a VPC after you create it. If your VPC is too
         small to meet your needs, create a new, larger VPC, and then migrate your instances
         to the new VPC.
        """
        user = self.user
        self.status('Attempting to create a new vpc which exceeds the max cidr range of /16...')
        vpc = None
        try:
            try:
                vpc = user.ec2.connection.create_vpc(cidr_block='192.0.0.0/8')
                user.ec2.create_tags(vpc.id, {self.my_tag_name: 'test_vpc'})
            except Exception as E:
                if (isinstance(E, EC2ResponseError) and int(E.status) == 400 and
                    E.reason == 'InvalidVpc.Range'):
                    self.status('Passed. System provided proper error when attempting to create a VPC '
                                'larger than /16. Err:{0}'.format(E))
                else:
                    self.log.error('System responded with incorrect error for this negative test...')
                    raise
            else:
                if vpc:
                    user.ec2.show_vpc(vpc)
                raise RuntimeError('System either allowed the user to create a VPC with cidr larger '
                                   'than /16, or did not respond with the proper error')
        finally:
            if vpc:
                self.status('attempting to delete vpc after this test...')
                user.ec2.delete_vpc_and_dependency_artifacts(vpc)

    def test2v2_vpc_cidr_block_range_small(self):
        """
        This test attempts to create a vpc smaller than allowed cidr block range...
        You can assign a single CIDR block to a VPC. The allowed block size is between
        a /28 netmask and /16 netmask. In other words, the VPC can contain from 16 to 65,536 IP
         addresses. You can't change the size of a VPC after you create it. If your VPC is too
         small to meet your needs, create a new, larger VPC, and then migrate your instances
         to the new VPC.
        """
        user = self.user
        self.status('Attempting to create a new vpc which is smaller than the min cidr range'
                    ' of /28...')
        vpc = None
        try:
            try:
                vpc = user.ec2.connection.create_vpc(cidr_block='192.0.0.0/29')
                user.ec2.create_tags(vpc.id, {self.my_tag_name: 'test_vpc'})
            except Exception as E:
                if (isinstance(E, EC2ResponseError) and int(E.status) == 400 and
                            E.reason == 'InvalidVpc.Range'):
                    self.status(
                        'Passed. System provided proper error when attempting to create a VPC '
                        'smaller than /28. Err:{0}'.format(E))
                else:
                    self.log.error(
                        'System responded with incorrect error for this negative test...')
                    raise
            else:
                if vpc:
                    user.ec2.show_vpc(vpc)
                raise RuntimeError(
                    'System either allowed the user to create a VPC with cidr smaller '
                    'than /28, or did not respond with the proper error')
        finally:
            if vpc:
                self.status('attempting to delete vpc after this test...')
                user.ec2.delete_vpc_and_dependency_artifacts(vpc)

    def test2v3_vpc_cidr_block_range_invalid_blocks(self):
        """
        This test attempts to create vpcs which with cidr values which are not permitted.

        Per euca-12101
        Looks like use of these subnets should not be permitted:
        0.0.0.0/8
        127.0.0.0/8
        169.254.0.0/16
        224.0.0.0/4
        """
        user = self.user
        for cidr in ['0.0.0.0/8', '0.0.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4']:
            self.status('Attempting to create a new vpc using the invalid cidr: {0}'.format(cidr))
            vpc = None
            try:
                try:
                    self.status('Attempting to create a VPC with invalid CIDR:"{0}"'.format(cidr))
                    vpc = user.ec2.connection.create_vpc(cidr_block=cidr)
                    user.ec2.create_tags(vpc.id, {self.my_tag_name: 'test_vpc'})
                except Exception as E:
                    if (isinstance(E, EC2ResponseError) and int(E.status) == 400 and
                                E.reason == 'InvalidVpc.Range'):
                        self.status(
                            'Passed. System provided proper error when attempting to create a VPC '
                            'with invalid cidr block:"{0}". Err:{1}'.format(cidr, E))
                    else:
                        self.log.error(
                            'System responded with incorrect error for this negative test...')
                        raise
                else:
                    if vpc:
                        user.ec2.show_vpc(vpc)
                    raise RuntimeError(
                        'System either allowed the user to create a VPC with invalid cidr:"{0}", '
                        'or did not respond with the proper error'.format(cidr))
            finally:
                if vpc:
                    self.status('attempting to delete vpc after this test...')
                    user.ec2.delete_vpc_and_dependency_artifacts(vpc)



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
        if (ig.from_port or ig.groups or ig.ipRanges or str(ig.ip_protocol) != "-1" or ig.to_port):
            raise ValueError('Expected the following ingress_rule attributes to be unset. Got: '
                             'from_port:{0}, groups:{1}, '
                             'ipRanges:{2}, ip_protocol:{3}, to_port:{4}'
                             .format(ig.from_port, ig.groups, ig.ipRanges,
                                     ig.ip_protocol, ig.to_port))
        grant = ig.grants[0]
        expected_ingress_grant = {'cidr_ip': None,
                                  'groupId': def_sg.id,
                                  'groupName': 'default',
                                  'group_id': def_sg.id,
                                  'item': '',
                                  'name': 'default',
                                  'owner_id': self.user.aws_account_id,
                                  'userId': self.user.aws_account_id}
        for key, value in expected_ingress_grant.iteritems():
            if getattr(grant, key) != value:
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
        eg = egress_rules[0]
        if (eg.from_port or eg.groups or eg.ipRanges or
                str(eg.ip_protocol) != '-1' or eg.to_port):
            raise ValueError('Expected the following egress_rule attributes to be unset. '
                             'Got: from_port{0}, groups:{1}, ipRanges:{2}, ip_protocol:{3}, '
                             'to_port:{4}'.format(eg.from_port, eg.groups, eg.ipRanges,
                                                  eg.ip_protocol, eg.to_port))
        grant = eg.grants[0]
        expected_egress_grant = {'cidr_ip': '0.0.0.0/0',
                                 'group_id': None,
                                 'item': '',
                                 'name': None,
                                 'owner_id': None}
        for key, value in expected_egress_grant.iteritems():
            if getattr(grant, key) != value:
                raise ValueError('Default grant attribute: "{0}" value:"{1}", does not'
                                 ' match expected attribute value:{2}'.format(key, grant[key],
                                                                              value))



    def test3b4_test_security_group_count_limit(self):
        """
        AWS: You can create up to 500 security groups per VPC.
        EUCA: Verify cloud property 'cloud.vpc.securitygroupspervpc'.
        """
        user = self.user
        vpc = self.test3b0_get_vpc_for_security_group_tests()
        prop = self.tc.sysadmin.get_property('cloud.vpc.securitygroupspervpc')
        prop.show()
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
        prop.show()
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
            if int(EE.status) == 400 and EE.reason == 'RulesPerSecurityGroupLimitExceeded':
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
        prop.show()
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
            if int(EE.status) == 400 and EE.reason == 'SecurityGroupsPerInterfaceLimitExceeded':
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
        """
        Creates or fetches a VPC matching the filters for this test section to share.
        By default this will create an IGW, a default route using the IGW, and TAG the VPC
        for later filtering.
        """
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


    def test4b1_get_subnets_for_route_table_tests(self, vpc=None, zones=None, count=1):
        """
        Creates or fetches subnets matching the filters for this test section to share.
        By default this test will search for available cidr blocks of /24 in size within the
        VPC provided, or the default VPC for this test section.
        The test will TAG the subnets for this test section for later filtering.
        """
        vpc = vpc or self.test4b0_get_vpc_for_route_table_tests()
        subnets = self.user.ec2.get_all_subnets(filters={'vpc_id': vpc.id,
                                                         'tag-key': self.ROUTE_TABLE_TEST_TAG,
                                                         'tag-value': self.test_id}) or []
        zones = zones or self.zones
        if not zones:
            raise ValueError('Could not find any zones?')
        subnets = subnets[:count]
        self.log.debug('Found {0} pre-existing subnets'.format(len(subnets)))
        if len(subnets) < count:
            need = count - len(subnets)

            # Try to create subnets across zones if possible...
            for sub_count in [ (need / len(zones)) , (need % len(zones))]:
                if sub_count:
                    zones_to_use = zones[:sub_count]
                    self.log.debug('Attepting to create {0} number of subnets in each zone:{1}'
                                   .format(sub_count, ",".join(zones_to_use)))
                    new_subnets = self.create_test_subnets(vpc=vpc, zones=zones_to_use,
                                                           count_per_zone=sub_count)
                    sub_ids = [str(x.id) for x in new_subnets]
                    self.user.ec2.create_tags(sub_ids, {self.ROUTE_TABLE_TEST_TAG: self.test_id})
                    subnets += new_subnets
                    self.log.debug('Created {0}/{1} new subnets, total subnets:{2}, requested{3}'
                                   .format(len(new_subnets), need, len(subnets), count))
        if len(subnets) != count:
            self.user.ec2.show_subnets(subnets)
            raise ValueError('Did not retrieve {0} number of subnets for route table tests? '
                             'Got:{1}'.format(count, len(subnets)))
        return subnets

    def test4b2_route_table_verify_internet_gateway_route(self, subnet=None, user=None,
                                                           force_main_rt=False):
        """
        Launch a VM(s) in a subnet referencing the route table to be tested.
        Add use an exiting route referencing an internet gateway. Verify traffic is routed
        correctly with regards to this IGW route

        """
        user = user or self.user
        vpc = None
        if subnet:
            if isinstance(subnet, basestring):
                subnetobj = user.ec2.get_subnet(subnet)
                if not subnetobj:
                    raise ValueError('user:{0}, could not fetch subnet:{1}/{2}'
                                     .format(user, subnet, type(subnet)))
                subnet = subnetobj
            vpc = user.ec2.get_vpc(subnet.vpc_id)
        vpc = vpc or self.test4b0_get_vpc_for_route_table_tests()
        subnet = subnet or self.test4b1_get_subnets_for_route_table_tests(vpc, count=1)[0]

        user.ec2.show_subnet(subnet)

        rts = user.ec2.connection.get_all_route_tables(
            filters={'association.subnet_id': subnet.id}) or []

        if force_main_rt:
            # if force main is setup, disassociate all other router so the test is forced
            # to use the main table
            for rt in rts:
                for ass in rt.associations:
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
                destination_cidr_block=original_igw_route.destination_cidr_block)
            user.ec2.create_route(rt.id, '0.0.0.0/0', igw.id)
            current_route = new_route
        group = self.get_test_security_groups(vpc=vpc, rules = [('tcp', 22, 22, '0.0.0.0/0'),
                                                                ('icmp', -1, -1, '0.0.0.0/0')])[0]
        vm = self.get_test_instances(zone=subnet.availability_zone, group_id=group.id,
                                     subnet_id=subnet.id, user=user, count=1)[0]
        self.status('Attempting to ping the VM from the UFS using the default IGW route...')
        ufs = self.tc.sysadmin.get_hosts_for_ufs()[0]
        ufs.sys('ping -c1 -W5 ' + vm.ip_address, code=0)
        self.status('Removing the route and attempting to ping again...')

        user.ec2.connection.delete_route(
            route_table_id=rt.id,
            destination_cidr_block=current_route.destination_cidr_block)
        self.status('Removing route and retrying...')
        start = time.time()
        elapsed = 0
        timeout = 30
        good = False
        while not good and (elapsed < timeout):
            try:
                ufs.sys('ping -c1 -W5 ' + vm.ip_address, code=0)
            except CommandExitCodeException:
                self.status('Success. Failed to reach VM without route, passing this test')
                good = True
                break
            else:
                elapsed = int(time.time() - start)
                self.log.error('Was still able to reach VM:{0}, after removing the igw '
                               'route. Elapsed:{1}'.format(vm.id, elapsed))
                user.ec2.show_instance(vm)
                user.ec2.show_vpc(vpc)
                user.ec2.show_subnet(subnet)
                user.ec2.show_route_table(rt)

                if elapsed < timeout:
                    self.log.info('sleeping briefly and then retrying...')
                    time.sleep(3)

        if not good:
            raise RuntimeError('Was still able to reach VM after removing the igw route '
                               'after elapsed:{0}'.format(elapsed))
        self.log.debug('restoring original igw route for route table:{0}'.format(rt.id))
        if original_igw_route:
            user.ec2.create_route(rt.id,
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

    def test4b10_route_table_add_and_delete_eni_route_packet_test(self, test_net='192.168.190.0'):
        """
        Test intends to verify routes which reference an ENI as the route point/gateway.
        Launch a VM(s) in a subnet referencing the route table to be tested.
        Find an IP that is not reachable by the tx VM. Assign this TEST IP to the rx VM.
        Enable IP forwarding on the rx VM. Set the route for the TEST IP to the eni of the rx
        VM. Attempt to reach the the TEST IP from the tx VM to verify the new route works.
        Remove the route and verify the tx can no longer reach the TEST IP.
        Verify that packets are routed correctly per route provided.
        """
        user = self.user
        vpc = self.test4b0_get_vpc_for_route_table_tests()
        subnet = self.test4b1_get_subnets_for_route_table_tests(vpc=vpc, count=1)[0]
        igw = user.ec2.connection.get_all_internet_gateways(
            filters={'attachment.vpc-id': vpc.id})[0]
        for rt in user.ec2.connection.get_all_route_tables(
                filters={'association.subnet_id': subnet.id}):
            for ass in rt.associations:
                if ass.subnet_id == subnet.id:
                    user.ec2.connection.disassociate_route_table(association_id=ass.id)
        new_rt = user.ec2.connection.create_route_table(subnet.vpc_id)
        user.ec2.connection.associate_route_table(route_table_id=new_rt.id, subnet_id=subnet.id)
        user.ec2.create_route(route_table_id=new_rt.id,
                                         destination_cidr_block='0.0.0.0/0',
                                         gateway_id=igw.id)
        group = self.get_test_security_groups(vpc=vpc, rules=[('tcp', 22, 22, '0.0.0.0/0'),
                                                              ('icmp', -1, -1, '0.0.0.0/0')])[0]

        vm_tx, vm_rx = self.get_test_instances(zone=subnet.availability_zone, group_id=group.id,
                                               subnet_id=subnet.id, user=user, count=2)
        vm_tx = user.ec2.convert_instance_to_euinstance(vm_tx.id, auto_connect=True)
        vm_rx = user.ec2.convert_instance_to_euinstance(vm_rx.id, auto_connect=True)

        keep_pinging = True
        octets = [int(x) for x in test_net.split('.')]
        test_net = "{0}.{1}".format(octets[0], octets[1])
        net, ip = [octets[2], octets[3]]
        # Find a free ip address...
        test_ip = None
        while keep_pinging:
            ip += 1
            if ip > 254:
                if net >= 255:
                    raise ValueError('Could not find available ip for test. Maxed out at:'
                                     '"{0}.{1}.{2}"'.format(test_net, net, ip))
                net += 1
                ip = 2

            test_ip = "{0}.{1}.{2}".format(test_net, net, ip)
            try:
                vm_tx.sys('ping -c1 -W3 {0}'.format(test_ip), code=0)
            except CommandExitCodeException as CE:
                self.log.debug('Assuming ip:{0} is available ping test returned:{0}'.format(CE))
                keep_pinging = False
                break
            else:
                test_ip = None
        if not test_ip:
            raise ValueError('Could not find available ip for test?')
        interfaces = vm_rx.sys("ip -o link show | awk -F': ' '{print $2}' | grep 'eth\|em'",
                               code=0) or []
        eth_itfc = 'dummy0'
        """
        virt_eth = None
        for x in [0, 1]:
            if eth_itfc:
                break
            for prefix in ['eth', 'em']:
                eth_itfc = prefix + str(x)
                if eth_itfc in interfaces:
                    break
                else:
                    eth_itfc = None
        if not eth_itfc:
            raise ValueError('Could not find test interface (eth0, eth1, em0, em1, etc) on '
                             'vm:{0}, interfaces:{1}'.format(vm_rx.id, ",".join(interfaces)))
        """
        ethdummy = 'dummy0'

        try:
            vm_rx.sys('lsmod | grep dummy || modprobe dummy', code=0)
            for x in xrange(0, 10):
                try:
                    vm_rx.sys('lsmod | grep dummy', code=0)
                    break
                except CommandExitCodeException as DE:
                    self.log.debug('Couldnt find loaded dummy module, sleeping + retrying...')
                    time.sleep(2)
            #vm_rx.sys('ip link set name {0} dev dummy0'.format(ethdummy), code=0)
            vm_rx.sys('ifconfig {0} {1}'.format(ethdummy, test_ip), code=0)
            vm_rx.sys('ifconfig {0} up'.format(ethdummy), code=0)
        except CommandExitCodeException as CE:
            if ethdummy:
                vm_rx.sys('ifconfig {0} down'.format(ethdummy))
            self.log.error('Could not create test network interface on vm_rx:{0}, err:{1}'
                           .format(vm_rx.id, CE))
            raise CE
        try:
            vm_rx.sys('echo 1 > /proc/sys/net/ipv4/ip_forward', code=0)
            eni = None
            for eni in vm_rx.interfaces:
                if eni.subnet_id == vm_tx.subnet_id:
                    break
            if not eni:
                vm_tx.show_enis()
                vm_rx.show_enis()
                raise ValueError('Could not find eni on {0} with subnet for {1}, {2}'
                                 .format(vm_rx.id, vm_tx.id, vm_tx.subnet_id))
            self.log.debug('Disabling source/dest checks on the eni: {0}'.format(eni.id))
            user.ec2.connection.modify_network_interface_attribute(interface_id=eni.id,
                                                                   attr='sourceDestCheck',
                                                                   value='false')
            test_route = test_ip + "/32"
            self.log.debug("Adding test route: {0}, to router:{1} using VM:{2} 's ENI:{3}"
                           .format(test_route, new_rt.id, vm_rx.id, eni.id))
            user.ec2.create_route(route_table_id=new_rt.id,
                                             destination_cidr_block=test_route,
                                             interface_id=eni.id)

            #  self.log.debug('Rebooting the vm_tx instance to make sure it has the latest route info'
            #                'provided via DHCP...')
            #  vm_tx.reboot_instance_and_verify()
            self.log.info("\n".join(vm_tx.sys('route') or []))
            timeout = 60
            start = time.time()
            elapsed = 0
            attempt = 1
            success = False
            # Retry this test in case rule needs time to take effect...
            while elapsed < timeout:
                elapsed = int(time.time() - start)
                msg = ""
                try:
                    try:
                        self.status('Attempting to ping the vm_rx/vm_tx private IPs to populate each'
                                    'others arp tables...')
                        vm_tx.sys('ping -c1 {0}'.format(vm_rx.private_ip_address), code=0)
                        vm_rx.sys('ping -c1 {0}'.format(vm_tx.private_ip_address), code=0)
                    except CommandExitCodeException as PE:
                        msg = "Failed to ping to pre-populate ARP cache with test VM private addr" \
                              "info, err:{0}".format(PE)
                        raise CommandExitCodeException(msg)
                    self.status('Attempting to ping test ip after new route has been ADDED. '
                                'Attempt: {0}, Elapsed:{1}/{2}'.format(attempt, elapsed, timeout))
                    vm_tx.sys('ping -c2 -W5 {0}'.format(test_ip), code=0)
                    success = True
                    break
                except CommandExitCodeException as CE:
                    msg += 'Ping vm to vm failed on attempt:{0} elapsed::{1}/{2}. Err:{3}'\
                        .format(attempt, elapsed, timeout, CE)
                    if elapsed >= timeout:
                        raise RuntimeError(msg)
                    else:
                        self.log.debug(msg)
                        time.sleep(5)
            if not success:
                msg = 'Error. Ping vm:{0} to vm:{1} test_ip:{2} failed on attempt:{3} ' \
                      'elapsed::{4}/{5}'.format(vm_tx.id, vm_rx.id, test_ip, attempt, elapsed,
                                                timeout)
                raise RuntimeError(msg)
            self.status('Test IP was reachable from {0} after route was added'.format(vm_tx.id))
            self.status('Revoking route and retesting...')

            user.ec2.connection.delete_route(route_table_id=new_rt.id,
                                             destination_cidr_block=test_route)
            timeout = 60
            start = time.time()
            elapsed = 0
            attempt = 1
            success = False
            # Retry this test in case rule needs time to take effect...
            while elapsed < timeout:
                elapsed = int(time.time() - start)
                try:
                    self.status('Attempting to ping test ip after new route has been DELETED. '
                                'Attempt: {0}, Elapsed:{1}/{2}'.format(attempt, elapsed, timeout))
                    vm_tx.sys('ping -c2 -W5 {0}'.format(test_ip), code=0)
                except CommandExitCodeException as CE:
                    msg = 'SUCCESS, Ping vm:{0} to vm:{1} test_ip:{2} failed on attempt:{3} ' \
                          'elapsed::{4}/{5}. Err:{6}'.format(vm_tx.id, vm_rx.id, test_ip, attempt,
                                                             elapsed, timeout, CE)
                    success = True
                    break

                if elapsed >= timeout:
                    raise RuntimeError(msg)
                else:
                    self.log.debug('Error, Ping vm to vm succeeded on attempt:{0} '
                                   'elapsed::{1}/{2}'.format(attempt, elapsed, timeout))
                    time.sleep(5)
            self.status('Test IP was no longer reachable from {0} after route was deleted'
                        .format(vm_tx.id))

        finally:
            vm_rx.sys('ifconfig {0} down'.format(ethdummy, test_ip))

    def test4b12_route_table_instance_id_with_multiple_eni_test(self,
                                                                test_route='192.168.191.0/24',
                                                                clean=True):
        """
        Test intends to verify routes which reference an INSTANCE ID as the route point/gateway.
        - The test will first attempt an instance with more than a single ENI, this should not
        be allowed. Expecting the request to create a route referencing an instance with multiple
        ENIs will be rejected with the proper error response.
        - Next the test will remove all ENIs leaving only a single ENI at device index 0. It will
        again try creating a route referencing this instance id. This should be allowed.

        """
        user = self.user
        vpc = self.test4b0_get_vpc_for_route_table_tests()
        subnet = self.test4b1_get_subnets_for_route_table_tests(vpc=vpc, count=1)[0]
        igw = user.ec2.connection.get_all_internet_gateways(
            filters={'attachment.vpc-id': vpc.id})[0]
        for rt in user.ec2.connection.get_all_route_tables(
                filters={'association.subnet_id': subnet.id}):
            for ass in rt.associations:
                if ass.subnet_id == subnet.id:
                    user.ec2.connection.disassociate_route_table(association_id=ass.id)
        new_rt = user.ec2.connection.create_route_table(subnet.vpc_id)
        user.ec2.connection.associate_route_table(route_table_id=new_rt.id, subnet_id=subnet.id)
        user.ec2.create_route(route_table_id=new_rt.id,
                                         destination_cidr_block='0.0.0.0/0',
                                         gateway_id=igw.id)
        group = self.get_test_security_groups(vpc=vpc, rules=[('tcp', 22, 22, '0.0.0.0/0'),
                                                              ('icmp', -1, -1, '0.0.0.0/0')])[0]

        vm_rx = self.get_test_instances(zone=subnet.availability_zone, subnet_id=subnet.id,
                                        group_id=group.id, user=user, auto_connect=True,
                                        count=1)[0]
        vm_rx = user.ec2.convert_instance_to_euinstance(vm_rx.id, auto_connect=True)
        self.status('Attempting to attach an additional eni to the the VM:{0} used in the route'
                    .format(vm_rx.id))
        eni = self.get_test_enis_for_subnet(subnet=subnet, count=1)[0]
        eni.attach(instance_id=vm_rx.id, device_index=(len(vm_rx.interfaces) + 1))
        vm_rx.update()
        vm_rx.show_enis()
        self.status('Attempting to create a route referencing an Instance ID which has multiple'
                    'ENIs attached. This should not be allowed...')
        route = None
        try:
            try:
                route = user.ec2.create_route(route_table_id=new_rt.id,
                                                         destination_cidr_block=test_route,
                                                         instance_id=vm_rx.id)
            except Exception as E:
                rmd = E.response.get('ResponseMetadata', None)
                if rmd:
                    status = rmd.get('HTTPStatusCode', None) or rmd.get('HTTPtatusCode', None)
                else:
                    status = 'unknown'
                error = E.response.get('Error', {})
                code = error.get('Code', '')
                msg = error.get('Message', '')


                if isinstance(E, ClientError) and status == 400 and \
                    code == 'InvalidInstanceID':
                    self.status('Passed. Attempt to create a route referencing an instance with '
                                'multiple ENI was rejected with the proper errror:{0}'.format(E))
                else:
                    raise ValueError('Attempt to create a route referencing an instance with '
                                     'multiple ENI returned an error but no the one this test '
                                     'expected. Etype: {0}, Error dict:{1}'.format(type(E),
                                                                                   E.__dict__))
            else:
                raise RuntimeError('System either created a route or did not respond with an '
                                   'error when attempting to create a route referencing an '
                                   'instance with multiple ENIs. Route:{0}'.format(route))
            try:
                self.status('Detaching any additional network interfaces other than device index 0'
                            'on the rx vm...')
                for eni in vm_rx.interfaces:
                    if int(eni.attachment.device_index) != 0:
                        vm_rx.detach_eni(eni)
                self.status('Sleeping for 5 seconds to allow detachments to settle. Then attempting'
                            'to create a route referencing the previous instance now with a '
                            'single ENI. This should work...')

                time.sleep(5)
                attempts = 0
                elapsed = 0
                start = time.time()
                error = None
                while elapsed < 60:
                    attempts += 1
                    elapsed = int(time.time() - start)
                    error = None
                    try:
                        self.log.debug('Attempting to create route. table:{0}, dest_cidr:{1}, '
                                       'instance:{2}. Attempt:{3}, elapsed:{4}'
                                       .format(new_rt.id, test_route, vm_rx.id, attempts, elapsed))
                        route = user.ec2.create_route(route_table_id=new_rt.id,
                                                      destination_cidr_block=test_route,
                                                      instance_id=vm_rx.id)
                        break
                    except Exception as E:
                        if isinstance(E, EC2ResponseError) and int(E.status) == 400 and \
                                        E.reason == 'InvalidInstanceID':
                            self.status('Elapsed:{0}, Attempt:{1} to create a route referencing an '
                                        'instance returned error:{2}'.format(elapsed, attempts, E))
                            self.log.debug('Sleeping and retrying...')
                            time.sleep(5)
                        error = E
                if not route:
                    raise RuntimeError('Create_route failed. Returned:"{0}". Attempt:{1}, '
                                       'Elapsed:{2}. Error:"{3}"'
                                       .format(route, attempts, elapsed, error))
                route_found = False
                new_rt = user.ec2.connection.get_all_route_tables(new_rt.id)[0]
                for route in new_rt.routes:
                    if route.destination_cidr_block == test_route and \
                                    route.instance_id == vm_rx.id:
                        route_found = True
                        break
                if not route_found:
                    user.ec2.show_route_table(new_rt)
                    raise RuntimeError('Added valid Route: "{0} -> {1}", but its not in the route '
                                       'table:{2}.'.format(test_route, vm_rx.id, new_rt.id))
            except Exception as E:
                vm_rx.show_enis()
                self.log.error(red('{0}\nError while attempting to create a route to an '
                                   'instance which previously had multiple ENIs but now does not. '
                                   'Error:{1}'.format(get_traceback(), E)))
                raise E
            self.status('Test Completed Successfully ')
        finally:
            if clean and vpc:
                user.ec2.delete_vpc_and_dependency_artifacts(vpc)



    def test4b12_route_table_add_and_delete_vm_id_route_packet_test(self,
                                                                    test_net='192.168.190.0'):
        """
        Test intends to verify routes which reference an INSTANCE ID as the route point/gateway.
        Launch a VM(s) in a subnet referencing the route table to be tested.
        Removes all ENIs but device index 0 for the rx'ing VM which is used as the route entry.
        Find an IP that is not reachable by the tx VM. Assign this TEST IP to the rx VM.
        Enable IP forwarding on the rx VM. Set the route for the TEST IP to the eni of the rx
        VM. Attempt to reach the the TEST IP from the tx VM to verify the new route works.
        Remove the route and verify the tx can no longer reach the TEST IP.
        Verify that packets are routed correctly per route provided.
        """
        user = self.user
        vpc = self.test4b0_get_vpc_for_route_table_tests()
        subnet = self.test4b1_get_subnets_for_route_table_tests(vpc=vpc, count=1)[0]
        igw = user.ec2.connection.get_all_internet_gateways(
            filters={'attachment.vpc-id': vpc.id})[0]
        for rt in user.ec2.connection.get_all_route_tables(
                filters={'association.subnet_id': subnet.id}):
            for ass in rt.associations:
                if ass.subnet_id == subnet.id:
                    user.ec2.connection.disassociate_route_table(association_id=ass.id)
        new_rt = user.ec2.connection.create_route_table(subnet.vpc_id)
        user.ec2.connection.associate_route_table(route_table_id=new_rt.id, subnet_id=subnet.id)
        user.ec2.create_route(route_table_id=new_rt.id,
                                         destination_cidr_block='0.0.0.0/0',
                                         gateway_id=igw.id)
        group = self.get_test_security_groups(vpc=vpc, rules=[('tcp', 22, 22, '0.0.0.0/0'),
                                                              ('icmp', -1, -1, '0.0.0.0/0')])[0]

        vm_tx, vm_rx = self.get_test_instances(zone=subnet.availability_zone, subnet_id=subnet.id,
                                               group_id=group.id, user=user, count=2)
        vm_tx = user.ec2.convert_instance_to_euinstance(vm_tx.id, auto_connect=True)
        vm_rx = user.ec2.convert_instance_to_euinstance(vm_rx.id, auto_connect=True)
        self.status('Attempting to attach an additional eni to the the rx VM')
        self.log.debug('Detaching any additional network interfaces other than device index 0'
                       'on the rx vm...')
        for eni in vm_rx.interfaces:
            if eni.attachment.device_index != 0:
                eni.detach()
        keep_pinging = True
        octets = [int(x) for x in test_net.split('.')]
        test_net = "{0}.{1}".format(octets[0], octets[1])
        net, ip = [octets[2], octets[3]]
        # Find a free ip address...
        test_ip = None
        while keep_pinging:
            ip += 1
            if ip > 254:
                if net >= 255:
                    raise ValueError('Could not find available ip for test. Maxed out at:'
                                     '"{0}.{1}.{2}"'.format(test_net, net, ip))
                net += 1
                ip = 2

            test_ip = "{0}.{1}.{2}".format(test_net, net, ip)
            try:
                vm_tx.sys('ping -c1 -W3 {0}'.format(test_ip), code=0)
            except CommandExitCodeException as CE:
                self.log.debug('Assuming ip:{0} is available ping test returned:{0}'.format(CE))
                keep_pinging = False
                break
            else:
                test_ip = None
        if not test_ip:
            raise ValueError('Could not find available ip for test?')
        interfaces = vm_rx.sys("ip -o link show | awk -F': ' '{print $2}' | grep 'eth\|em'",
                               code=0) or []
        eth_itfc = None
        virt_eth = None
        for x in [0, 1]:
            if eth_itfc:
                break
            for prefix in ['eth', 'em']:
                eth_itfc = prefix + str(x)
                if eth_itfc in interfaces:
                    break
                else:
                    eth_itfc = None
        if not eth_itfc:
            raise ValueError('Could not find test interface (eth0, eth1, em0, em1, etc) on '
                             'vm:{0}, interfaces:{1}'.format(vm_rx.id, ",".join(interfaces)))
        ethdummy = None
        try:
            for x in xrange(1, 100):
                ethdummy = "eth{0}".format(10 + x)
                if ethdummy not in interfaces:
                    break
            vm_rx.sys('modprobe dummy', code=0)
            vm_rx.sys('ip link set name {0} dev dummy0'.format(ethdummy), code=0)
            vm_rx.sys('ifconfig {0} {1}'.format(ethdummy, test_ip), code=0)
            vm_rx.sys('ifconfig {0} up'.format(ethdummy), code=0)
        except CommandExitCodeException as CE:
            if ethdummy:
                vm_rx.sys('ifconfig {0} down'.format(ethdummy))
            self.log.error('Could not create test network interface on vm_rx:{0}, err:{1}'
                           .format(vm_rx.id, CE))
            raise CE
        try:
            vm_rx.sys('echo 1 > /proc/sys/net/ipv4/ip_forward', code=0)
            eni = None
            for eni in vm_rx.interfaces:
                if eni.subnet_id == vm_tx.subnet_id:
                    break
            if not eni:
                vm_tx.show_enis()
                vm_rx.show_enis()
                raise ValueError('Could not find eni on {0} with subnet for {1}, {2}'
                                 .format(vm_rx.id, vm_tx.id, vm_tx.subnet_id))
            self.log.debug('Disabling source/dest checks on the eni: {0}'.format(eni.id))
            user.ec2.connection.modify_network_interface_attribute(interface_id=eni.id,
                                                                   attr='sourceDestCheck',
                                                                   value='false')
            test_route = test_ip + "/32"
            self.log.debug("Adding test route: {0}, to router:{1} using VM:{2} 's ENI:{3}"
                           .format(test_route, new_rt.id, vm_rx.id, eni.id))
            user.ec2.create_route(route_table_id=new_rt.id,
                                             destination_cidr_block=test_route,
                                             interface_id=eni.id)

            #  self.log.debug('Rebooting the vm_tx instance to make sure it has the latest route info'
            #                 'provided via DHCP...')
            #  vm_tx.reboot_instance_and_verify()
            self.log.info("\n".join(vm_tx.sys('route') or []))
            timeout = 60
            start = time.time()
            elapsed = 0
            attempt = 1
            success = False
            # Retry this test in case rule needs time to take effect...
            while elapsed < timeout:
                elapsed = int(time.time() - start)
                msg = ""
                try:
                    try:
                        self.status(
                            'Attempting to ping the vm_rx/vm_tx private IPs to populate each'
                            'others arp tables...')
                        vm_tx.sys('ping -c1 {0}'.format(vm_rx.private_ip_address), code=0)
                        vm_rx.sys('ping -c1 {0}'.format(vm_tx.private_ip_address), code=0)
                    except CommandExitCodeException as PE:
                        msg = "Failed to ping to pre-populate ARP cache with test VM private addr" \
                              "info, err:{0}".format(PE)
                        raise CommandExitCodeException(msg)
                    self.status('Attempting to ping test ip after new route has been ADDED. '
                                'Attempt: {0}, Elapsed:{1}/{2}'.format(attempt, elapsed, timeout))
                    vm_tx.sys('ping -c2  -W5 {0}'.format(test_ip), code=0)
                    success = True
                    break
                except CommandExitCodeException as CE:
                    msg += 'Ping vm to vm failed on attempt:{0} elapsed::{1}/{2}. Err:{3}' \
                        .format(attempt, elapsed, timeout, CE)
                    if elapsed >= timeout:
                        raise RuntimeError(msg)
                    else:
                        self.log.debug(msg)
                        time.sleep(5)
            if not success:
                msg = 'Error. Ping vm:{0} to vm:{1} test_ip:{2} failed on attempt:{3} ' \
                      'elapsed::{4}/{5}'.format(vm_tx.id, vm_rx.id, test_ip, attempt, elapsed,
                                                timeout)
                raise RuntimeError(msg)
            self.status('Test IP was reachable from {0} after route was added'.format(vm_tx.id))
            self.status('Revoking route and retesting...')

            user.ec2.connection.delete_route(route_table_id=new_rt.id,
                                             destination_cidr_block=test_route)
            timeout = 60
            start = time.time()
            elapsed = 0
            attempt = 1
            success = False
            # Retry this test in case rule needs time to take effect...
            while elapsed < timeout:
                elapsed = int(time.time() - start)
                try:
                    self.status('Attempting to ping test ip after new route has been DELETED. '
                                'Attempt: {0}, Elapsed:{1}/{2}'.format(attempt, elapsed, timeout))
                    vm_tx.sys('ping -c2  -W5 {0}'.format(test_ip), code=0)
                except CommandExitCodeException as CE:
                    msg = 'SUCCESS, Ping vm:{0} to vm:{1} test_ip:{2} failed on attempt:{3} ' \
                          'elapsed::{4}/{5}. Err:{6}'.format(vm_tx.id, vm_rx.id, test_ip, attempt,
                                                             elapsed, timeout, CE)
                    success = True
                    break

                if elapsed >= timeout:
                    raise RuntimeError(msg)
                else:
                    self.log.debug('Error, Ping vm to vm succeeded on attempt:{0} '
                                   'elapsed::{1}/{2}'.format(attempt, elapsed, timeout))
                    time.sleep(5)
            if success:
                self.status('Test IP was no longer reachable from {0} after route was deleted'
                            .format(vm_tx.id))
            else:
                raise RuntimeError('Error, Ping vm to vm succeeded after route was deleted. '
                                   'Attempts:{0} elapsed::{1}/{2}'
                                   .format(attempt, elapsed, timeout))
        finally:
            vm_rx.sys('ifconfig {0} down'.format(virt_eth, test_ip))
            if vpc:
                user.ec2.delete_vpc_and_dependency_artifacts(vpc)
        self.status('Test Completed Successfully')


    def test4c1_route_table_max_tables_per_vpc(self):
        """
        There is a limit on the number of route tables you can create per VPC.
        cloud.vpc.routetablespervpc
        """
        user = self.user
        vpc = self.test4b0_get_vpc_for_route_table_tests()
        prop = self.tc.sysadmin.get_property('cloud.vpc.routetablespervpc')
        prop.show()
        limit = int(prop.value)
        existing = user.ec2.connection.get_all_route_tables(filters={'vpc-id': vpc.id})
        new_rts = []
        for x in xrange(0, limit-len(existing)):
            new_rts.append(user.ec2.connection.create_route_table(vpc_id=vpc.id))
        existing = user.ec2.connection.get_all_route_tables(filters={'vpc-id': vpc.id})
        if len(existing) != limit:
            raise ValueError('Was not able to create route tables of count limit, got:{0}/{1}'
                             .format(existing, limit))
        self.status('Passed. Could create route tables up to limit per vpc set')
        try:
            user.ec2.connection.create_route_table(vpc_id=vpc.id)
        except EC2ResponseError as EE:
            if int(EE.status) == 400 and EE.reason == 'RouteTableLimitExceeded':
                self.status('Passed. Could not exceed route table limit per VPC')


    def test4c2_route_table_max_routes_per_table(self):
        """
        There is a limit on the number of routes you can add per route table.
        cloud.vpc.routespertable
        """
        user = self.user
        vpc = self.test4b0_get_vpc_for_route_table_tests()
        subnet = self.test4b1_get_subnets_for_route_table_tests(vpc=vpc, count=1)[0]
        eni = self.get_test_enis_for_subnet(subnet=subnet, count=1)[0]
        prop = self.tc.sysadmin.get_property('cloud.vpc.routespertable')
        prop.show()
        limit = int(prop.value)
        rts = user.ec2.connection.get_all_route_tables(
            filters={'association.main': 'true', 'vpc-id': vpc.id})
        if rts:
            rt = rts[0]
        else:
            rt = user.ec2.connection.create_route_table(vpc_id=vpc.id)[0]
        for route in rt.routes:
            if route.gateway_id != 'local':
                user.ec2.connection.delete_route(
                    route_table_id=rt.id, destination_cidr_block=route.destination_cidr_block)
        rt = user.ec2.connection.get_all_route_tables(route_table_ids=[rt.id])[0]
        existing = len(rt.routes or [])
        limit = limit - existing
        test_net = '192.168'
        def add_route(count):
            n4 = count % 255
            n3 = count / 255
            test_cidr = "{0}.{1}.{2}/32".format(test_net, n3, n4)
            self.log.debug('Attempting to add route#{0}, cidr:{1} via:{2} to {3}'
                           .format(count, test_cidr, eni.id, rt.id))
            user.ec2.create_route(route_table_id=rt.id,
                                             destination_cidr_block=test_cidr,
                                             interface_id=eni.id)
        x = 0
        for x in xrange(0, limit):
            try:
                add_route(x)
            except Exception as E:
                rt = user.ec2.connection.get_all_route_tables(route_table_ids=[rt.id])[0]
                if len(rt.routes) != int(prop.value):
                    self.log.error('Error while trying to add routes up to acceptable limit:"0", '
                                   'got:"{1}", err:"{2}"'.format(int(prop.value),
                                                                 len(rt.routes or []), E))
                    raise E
        # Double check here...
        rt = user.ec2.connection.get_all_route_tables(rt.id)[0]
        if len(rt.routes) != int(prop.value):
            raise ValueError('Route count:{0} != limit:{1} after adding routes'
                             .format(len(rt.routes), int(prop.value)))
        self.status('Was able to add count equal to limit of: {0}'.format(limit))
        try:
            x += 1
            add_route(x)
        except Exception as E:
            if (isinstance(E, EC2ResponseError) and int(E.status == 400) and
                E.reason == 'RouteLimitExceeded'):
                self.status('Passing. Could not exceed route limit')
                return
        else:
            raise ValueError('Was able to exceed route limit per table of :{0}'.format(limit))


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
        """
        Creates or fetches a VPC matching the filters for this test section to share.
        By default this will create an IGW, a default route using the IGW, and TAG the VPC
        for later filtering.
        """
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

    def test5g0_vpc_cidr_block_range_full_vpc_cidr_block(self):
        """
        This test attempts to create a subnet equal to the size of the vpc cidr block.

        The CIDR block of a subnet can be the same as the CIDR block for the VPC (for a single
        subnet in the VPC), or a subset (for multiple subnets). The allowed block size is
        between a /28 netmask and /16 netmask. If you create more than one subnet in a VPC,
        the CIDR blocks of the subnets cannot overlap.
        """
        user = self.user
        vpc = self.test5b0_get_vpc_for_subnet_tests()
        self.status('Attempting to create a new subnet which is equal to the VPC CIDR block...')
        subnet = None
        self.status('Deleting any potentially conflicting subnets from this test vpc:{0}'
                    .format(vpc.id))
        test_cidr = vpc.cidr_block
        subs = user.ec2.get_all_subnets(filters={'vpc_id': vpc.id})
        for sub in subs:
            user.ec2.delete_subnet_and_dependency_artifacts(sub)
        try:
            self.status('Attempting to create subnet with VALID cidr equal to vpc cidr:{0}'
                        .format(test_cidr))
            subnet = self.create_subnet_and_tag(vpc_id=vpc.id, cidr_block=test_cidr,user=user)

        finally:
            if subnet:
                self.status('attempting to delete SUBNET after this test...')
                user.ec2.delete_subnet_and_dependency_artifacts(subnet)

    def test5v1_subnet_duplicate_subnets(self):
        """
        This test attempts to create 2 duplicate subnets, this should not be allowed...

        The CIDR block of a subnet can be the same as the CIDR block for the VPC (for a single
        subnet in the VPC), or a subset (for multiple subnets). The allowed block size is
        between a /28 netmask and /16 netmask. If you create more than one subnet in a VPC,
        the CIDR blocks of the subnets cannot overlap.
        """
        user = self.user
        vpc = self.test5b0_get_vpc_for_subnet_tests()
        self.status('Attempting to create a new subnets with duplicate cidr...')
        subnets =[]
        self.status('Deleting any potentially conflicting subnets from this test vpc:{0}'
                    .format(vpc.id))
        subs = user.ec2.get_all_subnets(filters={'vpc_id': vpc.id})
        zone = self.zones[0]
        for sub in subs:
            user.ec2.delete_subnet_and_dependency_artifacts(sub)
        try:
            try:
                self.status('Attempting to create the intial subnet in zone:{0}...'.format(zone))
                subnet1 = self.create_test_subnets(vpc=vpc, zones=[zone], count_per_zone=1)[0]
                subnets.append(subnet1)
                self.status('Attempting to create a subnet with duplicate cidr block. This '
                            'should not be allowed')

                subnet2 = self.create_subnet_and_tag(vpc_id=vpc.id, cidr_block=subnet1.cidr_block,
                                                     user=user)
                subnets.append(subnet2)
            except Exception as E:
                if (isinstance(E, EC2ResponseError) and int(E.status) == 400 and
                            E.reason == 'InvalidSubnet.Conflict'):
                    self.status(
                        'Passed. System provided proper error when attempting to create a SUBNET '
                        'with duplicate cidr block. Err:{0}'.format(E))
                else:
                    self.log.error(
                        'System responded with incorrect error for this negative test...')
                    raise
            else:
                if subnets:
                    user.ec2.show_subnets(subnets)
                raise RuntimeError(
                    'System either allowed the user to create a SUBNET with duplicate cidr, '
                    'or did not respond with the proper error')
        finally:
            self.status('Attempting to delete SUBNETs after this test...')
            for sub in subnets:
                user.ec2.delete_subnet_and_dependency_artifacts(sub)

    def test5v1_subnet_overlapping_cidr(self):
        """
        This test attempts to create 2 subnets with overlapping cidr, this should not be allowed...

        The CIDR block of a subnet can be the same as the CIDR block for the VPC (for a single
        subnet in the VPC), or a subset (for multiple subnets). The allowed block size is
        between a /28 netmask and /16 netmask. If you create more than one subnet in a VPC,
        the CIDR blocks of the subnets cannot overlap.
        """
        user = self.user
        vpc = self.test5b0_get_vpc_for_subnet_tests()
        self.status('Attempting to create subnets with overlapping cidr...')
        subnets = []
        zone = self.zones[0]

        # Create the test CIDR values to use when creating the test subnets...
        base_cidr, base_mask = vpc.cidr_block.split('/')
        base_mask = int(base_mask)
        if base_mask > 27:
            user.ec2.show(vpc)
            raise ValueError('This test is not written to handle a vpc with masks > /27')
        net_info = get_network_info_for_cidr("{0}/{1}".format(base_cidr, 28))
        if not is_address_in_network(net_info.get('network'), vpc.cidr_block):
            raise ValueError('Error in this test, the test network is not within the larger'
                             'vpc cidr block?')
        test_cidr = "{0}/{1}".format(net_info.get('network') or base_cidr, 28)
        self.status('Deleting any potentially conflicting subnets from this test vpc:{0}'
                    .format(vpc.id))

        subs = user.ec2.get_all_subnets(filters={'vpc_id': vpc.id})
        for sub in subs:
            user.ec2.delete_subnet_and_dependency_artifacts(sub)
        try:
            try:
                self.status('Attempting to create the intial subnet  equal to the entire'
                            'vpc cidr block:{0}...'.format(vpc.cidr_block))
                subnet1 = self.create_subnet_and_tag(vpc_id=vpc.id, cidr_block=vpc.cidr_block,
                                                     user=user)
                subnets.append(subnet1)
                self.status('Attempting to create a subnet with cidr block:{0} which overlaps'
                            'the inital subnet cidr_block:{0}'.format(test_cidr,
                                                                      subnet1.cidr_block))
                subnet2 = self.create_subnet_and_tag(vpc_id=vpc.id, cidr_block=test_cidr,
                                                     user=user)
                subnets.append(subnet2)
            except Exception as E:
                if (isinstance(E, EC2ResponseError) and int(E.status) == 400 and
                            E.reason == 'InvalidSubnet.Conflict'):
                    self.status(
                        'Passed. System provided proper error when attempting to create a SUBNET '
                        'with overlapping cidr block. Err:{0}'.format(E))
                else:
                    self.log.error(
                        'System responded with incorrect error for this negative test...')
                    raise
            else:
                if subnets:
                    user.ec2.show_subnets(subnets)
                raise RuntimeError(
                    'System either allowed the user to create a SUBNET with overlapping cidr, '
                    'or did not respond with the proper error')
        finally:
            self.status('Attempting to delete SUBNETs after this test...')
            for sub in subnets:
                user.ec2.delete_subnet_and_dependency_artifacts(sub)



    def test5v1_subnet_cidr_block_range_large(self, cidr_mask=8):
        """
        This test attempts to create a subnet larger than allowed cidr block range...
        The CIDR block of a subnet can be the same as the CIDR block for the VPC (for a single
        subnet in the VPC), or a subset (for multiple subnets). The allowed block size is
        between a /28 netmask and /16 netmask. If you create more than one subnet in a VPC,
        the CIDR blocks of the subnets cannot overlap.
        """
        user = self.user
        vpc = self.test5b0_get_vpc_for_subnet_tests()
        self.status('Attempting to create a new subnet which exceeds the max cidr range of /16...')
        subnet = None
        self.status('Deleting any potentially conflicting subnets from this test vpc:{0}'
                    .format(vpc.id))
        base_cidr = vpc.cidr_block.split('/')[0]
        net_info = get_network_info_for_cidr("{0}/{1}".format(base_cidr, cidr_mask))
        test_cidr = "{0}/{1}".format(net_info.get('network') or base_cidr, cidr_mask)
        subs = user.ec2.get_all_subnets(filters={'vpc_id':vpc.id})
        for sub in subs:
            user.ec2.delete_subnet_and_dependency_artifacts(sub)
        try:
            try:
                self.status('Attempting to create subnet with invalid cidr:{0}'
                            .format(test_cidr))
                subnet = self.create_subnet_and_tag(vpc_id=vpc.id, cidr_block=test_cidr,
                                                    user=user)
            except Exception as E:
                if (isinstance(E, EC2ResponseError) and int(E.status) == 400 and
                            E.reason == 'InvalidSubnet.Range'):
                    self.status(
                        'Passed. System provided proper error when attempting to create a SUBNET '
                        'larger than /16. Err:{0}'.format(E))
                else:
                    self.log.error(
                        'System responded with incorrect error for this negative test...')
                    raise
            else:
                if subnet:
                    user.ec2.show_subnet(subnet)
                raise RuntimeError(
                    'System either allowed the user to create a SUBNET with cidr larger '
                    'than /16, or did not respond with the proper error')
        finally:
            if subnet:
                self.status('attempting to delete SUBNET after this test...')
                user.ec2.delete_subnet_and_dependency_artifacts(subnet)

    def test5v2_subnet_cidr_block_range_large(self, cidr_mask=29):
        """
        This test attempts to create a subnet smaller than allowed cidr block range...
        The CIDR block of a subnet can be the same as the CIDR block for the VPC (for a single
        subnet in the VPC), or a subset (for multiple subnets). The allowed block size is
        between a /28 netmask and /16 netmask. If you create more than one subnet in a VPC,
        the CIDR blocks of the subnets cannot overlap.
        """
        user = self.user
        vpc = self.test5b0_get_vpc_for_subnet_tests()
        self.status('Attempting to create a new subnet which is smaller than the min '
                    'cidr range of /28...')
        subnet = None
        self.status('Deleting any potentially conflicting subnets from this test vpc:{0}'
                    .format(vpc.id))
        base_cidr = vpc.cidr_block.split('/')[0]
        net_info = get_network_info_for_cidr("{0}/{1}".format(base_cidr, cidr_mask))
        test_cidr = "{0}/{1}".format(net_info.get('network') or base_cidr, cidr_mask)
        subs = user.ec2.get_all_subnets(filters={'vpc_id':vpc.id})
        for sub in subs:
            user.ec2.delete_subnet_and_dependency_artifacts(sub)
        try:
            try:
                self.status('Attempting to create subnet with invalid cidr:{0}'
                            .format(test_cidr))
                subnet = self.create_subnet_and_tag(vpc_id=vpc.id, cidr_block=test_cidr,
                                                    user=user)
            except Exception as E:
                if (isinstance(E, EC2ResponseError) and int(E.status) == 400 and
                            E.reason == 'InvalidSubnet.Range'):
                    self.status(
                        'Passed. System provided proper error when attempting to create a SUBNET '
                        'smaller than /28. Err:{0}'.format(E))
                else:
                    self.log.error(
                        'System responded with incorrect error for this negative test...')
                    raise
            else:
                if subnet:
                    user.ec2.show_subnet(subnet)
                raise RuntimeError(
                    'System either allowed the user to create a SUBNET with cidr smaller '
                    'than /28, or did not respond with the proper error')
        finally:
            if subnet:
                self.status('attempting to delete SUBNET after this test...')
                user.ec2.delete_subnet_and_dependency_artifacts(subnet)

    def test5x0_subnets_per_vpc_limit(self, vpc=None):
        """
        Test that the max subnets per vpc defined in the following property can not be exceeded,
        and the user can create the amount defined in the property.
        cloud.vpc.subnetspervpc
        """
        user = self.user
        vpc = vpc or self.test5b0_get_vpc_for_subnet_tests()
        prop = self.tc.sysadmin.get_property('cloud.vpc.subnetspervpc')
        prop.show()
        limit = int(prop.value)
        existing = user.ec2.get_all_subnets(vpc=vpc)
        zone1 = self.zones[0]
        if len(self.zones) > 1:
            zone2 = self.zones[1]
        else:
            zone2 = zone1
        remaining = limit - len(existing)
        amount1 = remaining / 2
        amount2 = remaining - amount1
        self.status('Creating {0} subnets. Existing:{1}, limit:{2}'
                    .format(amount1, len(existing), limit))
        cleanup = []
        try:
            try:
                new = self.create_test_subnets(vpc=vpc, zones=[zone1], count_per_zone=amount1)
            except EC2ResponseError as EE:
                subs  = user.ec2.get_all_subnets(vpc=vpc)
                if len(subs) != limit:
                    self.log.error('Was not able to create subnets == acceptable limit:"{0}". '
                                   'Got:"{1}". Error:"{2}"'.format(limit, len(subs), EE))
                    raise
                else:
                    self.status('Was able to create {0} number of subs equal to acceptable limit'
                                .format(limit))
            # Double check
            cleanup = new
            self.status('Created {0} new subnets'.format(len(new)))
            existing = user.ec2.get_all_subnets(vpc=vpc)
            self.status('Creating {0} subnets. Existing:{1}, limit:{2}'
                       .format(amount2, len(existing), limit))
            new2 = self.create_test_subnets(vpc=vpc, zones=[zone2], count_per_zone=amount2)
            cleanup += new2
            self.status('Created {0} new subnets'.format(len(new2)))

            existing = user.ec2.get_all_subnets(vpc=vpc)
            if len(existing) != limit:
                raise ValueError('Attempted to create subnets of limit count, but existing '
                                 'subnets:{0} != limit:{1}?'.format(len(existing), limit))
            self.status('Negative test. Attempting to exceed limit:{0}. Creating {1} subnets. '
                        'Existing:{1}'.format(limit, len(self.zones), len(existing)))
            try:
                new2 = self.create_test_subnets(vpc=vpc, zones=self.zones, count_per_zone=1)
            except Exception as EE:
                if isinstance(EE, EC2ResponseError) and int(EE.status) == 400 and \
                                EE.reason == 'SubnetLimitExceeded':
                    self.status('Success. Was not able to exceed subnet per vpc limit. Error:{0}'
                                .format(EE))
                else:
                    self.log.error('Expected an error, but not this one(?), while trying to '
                                   'subnet limt:"{0}"'.format(EE))
                    raise EE
            else:
                raise RuntimeError('Attempted to exceed max subnets per vpc and did not rx proper '
                                   'error')
        finally:
            self.status('Attempting to delete the recently created subnets and '
                        'any dependencies...')
            for subnet in cleanup:
                user.ec2.delete_subnet_and_dependency_artifacts(subnet)

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
    #  An elastic network interface (ENI) is a virtual network interface that you can attach to an
    #  instance in a VPC. ENIs are available only for instances running in a VPC.
    ###############################################################################################

    def show_vm_net_info(self, vm):
        try:
            vm.show_enis()
            vm.show_network_interfaces_table()
            vm.show_network_device_info()
        except Exception as E:
            self.log.warning('{0}\nFailed to print network device info for vm:{1}, '
                             'Error:"{2}"'.format(get_traceback(), vm, E))


    def test6b0_get_vpc_for_eni_tests(self):
        """
        Creates or fetches a VPC matching the filters for this test section to share.
        By default this will create an IGW, a default route using the IGW, and TAG the VPC
        for later filtering.
        """

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


    def test6b5_basic_create_and_delete_eni_test(self):
        """
        Create a set of valid ENIs with different attributes
        check the ENI attributes in the response.
        Example Attributes: subnet id, w/ and w/o a private ip, eni description, etc..
        see ec2ops.create_network_interface for specifics on attribute checks.

        """
        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        zones = self.zones
        subnets = []
        subnets = self.create_test_subnets(vpc=vpc, zones=zones, user=user, count_per_zone=1)
        if not subnets:
            raise RuntimeError('No subnets found or created for this eni-test vpc:{0}'
                               .format(vpc.id))
        self.status('Using subnets:"{0}" for this eni test.'
                    .format(", ".join([str(x.id) for x in subnets])))
        enis = []
        for sub in subnets:
            net_info = get_network_info_for_cidr(sub.cidr_block)
            network = net_info.get('network')
            octets = network.split('.')
            valid_ip = "{0}.{1}.{2}.{3}".format(octets[0], octets[1], octets[2],
                                                    (int(octets[3]) + 10))
            self.status('Attempting to remove all existing artifacts from subnet:{0}'
                        .format(sub.id))

            self.status('Attempting to create valid eni without specifying the private ip...')
            eni = user.ec2.create_network_interface(subnet_id=sub.id, show_eni=True)
            enis.append(eni)
            if eni.private_ip_address == valid_ip:
                valid_ip = "{0}.{1}.{2}.{3}".format(octets[0], octets[1], octets[2],
                                                    (int(octets[3]) + 11))

            self.status('Attempting to create a valid eni providing the private ip:{0}'
                        .format(valid_ip))
            eni = user.ec2.create_network_interface(subnet_id=sub.id, private_ip_address=valid_ip)
            enis.append(eni)
            groups = self.get_test_security_groups(vpc=vpc, count=3)
            self.status('Attempting to create a valid eni providing a list of security groups:{0}'
                        .format(",".join(str(x.id) for x in groups)))
            eni = user.ec2.create_network_interface(subnet_id=sub.id, groups=groups)
            enis.append(eni)
            description = 'TEST ENI DESCRIPTION for subnet:{0}'.format(sub.id)
            self.status('Attempting to create a valid eni with a description:{0}'
                        .format(description))
            eni = user.ec2.create_network_interface(subnet_id=sub.id, description=description)
            enis.append(eni)
        self.status('Finished Creating the following network interfaces...')
        user.ec2.show_network_interfaces(enis)
        self.status('Attempting to delete the network interfaces created in this test...')
        for eni in enis:
            eni.delete()
        delete_me = [str(x.id) for x in enis]
        timeout = 120
        start = time.time()
        elapsed = 0
        attempts = 0
        errors = ""
        while delete_me and elapsed < timeout:
            attempts += 1
            self.log.info('Attempting to delete enis:"{0}", attempt:{1}'
                          .format(",".join([str(x.id) for x in enis]), attempts))
            for eni in enis:
                self.log.debug('Attempting to delete ENI:{0}, elapsed:{1}'.format(eni.id, elapsed))
                try:
                    eni.delete()
                    eni.update()
                except EC2ResponseError as EE:
                    if int(EE.status) == 400 and EE.reason == 'InvalidNetworkInterfaceID.NotFound':
                        if eni.id in delete_me:
                            delete_me.remove(eni.id)
                        self.log.debug('Deleted eni:{0}'.format(eni.id))
        if delete_me:
            raise RuntimeError('Attempts:{0}, Elapsed:{1}. Failed to delete the following ENIs:{2}'
                               .format(attempts, elapsed, ",".join(delete_me)))
        self.status('Passed. Basic create and delete ENI checks complete')

    def test6c0_eni_basic_creation_deletion_tests_extended(self):
        """
        Test will attempt to create ENIs using invalid requests/attributes.
        - Request a private ip outside the subnet range
        - Request a private ip already in use by another ENI
        """
        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        zones = self.zones
        subnets = []
        for zone in zones:
            subnets.append(self.get_non_default_test_subnets_for_vpc(vpc, zone=zone, count=1)[0])
        if not subnets:
            raise RuntimeError('No subnets found or created for this eni-test vpc:{0}'
                               .format(vpc.id))
        self.status('Using subnets:"{0}" for this eni test.'
                    .format(", ".join([str(x.id) for x in subnets])))
        enis = []
        for sub in subnets:
            try:
                net_info = get_network_info_for_cidr(sub.cidr_block)
                # Find an address outside the range of the subnet...
                network = net_info.get('network')
                octets = network.split('.')
                invalid_ip = None
                test_count = 0
                for octet in xrange(0, 3):
                    if test_count > 100:
                        break
                    test_octets = copy.copy(octets)
                    test_octets[3] = str(int(test_octets[3]) + 100)
                    for x in range(1, 254):
                        test_octets[octet] = x
                        invalid_ip = ".".join([str(x) for x in test_octets])
                        if not is_address_in_network(invalid_ip, sub.cidr_block):
                            test_count += 1
                            try:
                                eni = user.ec2.connection.create_network_interface(
                                    sub.id, private_ip_address=invalid_ip)
                            except EC2ResponseError as EE:
                                if int(EE.status) == 400 and EE.reason == 'InvalidParameterValue':
                                    self.log.debug('Received correct error response for private IP '
                                                   'out range: {0}'.format(EE))
                                else:
                                    raise ValueError('Received the incorrect error for private IP out'
                                                     ' of range: {0}'.format(EE))
                            else:
                                raise RuntimeError('Attempting to create ENI using IP:{0} outside of '
                                                   'subnet:{1} cidr:{2} was either allowed or did not'
                                                   'respond with an error'
                                                   .format(invalid_ip, sub.id, sub.cidr_block))
                self.status('Verified system responded with proper errors for {0} out of range '
                            'IPs in ENI creation requests'.format(test_count))
                self.log.debug('Attempting to create initial ENI for duplicate ENI test...')
                eni1 = user.ec2.connection.create_network_interface(sub.id)
                self.status('Attempting to create an ENI with an address already in use by another '
                            'ENI...')
                try:
                    eni2 = user.ec2.connection.create_network_interface(
                        sub.id, private_ip_address=eni1.private_ip_address)
                except EC2ResponseError as EE:
                    if int(EE.status) == 400 and EE.reason == 'InvalidParameterValue':
                        self.log.debug('Received correct error response for  duplicate private IP: {0}'
                                       .format(EE))
                    else:
                        raise ValueError('Received the incorrect error for  duplicate private IP: {0}'
                                         .format(EE))
                else:
                    raise RuntimeError('Attempting to create ENI using IP:{0} duplicate of '
                                       'eni:{1} was either allowed or did not'
                                       'respond with an error'
                                       .format(eni1.private_ip_address, eni1.id))
                self.status('Attempting to create an ENI using an IP of a deleted ENI...')
                eni1.delete()
                elapsed = 0
                start = time.time()
                timeout = 60
                attempts = 0
                while elapsed < timeout:
                    attempts += 1
                    elapsed = int(time.time() - start)
                    try:
                        eni2 = user.ec2.create_network_interface(
                            sub.id, private_ip_address=eni1.private_ip_address)
                        self.status('Success. Was able to create an ENI:{0} reusing IP:{1} of '
                                    'deleted ENI:{2}'.format(eni2.id, eni1.private_ip_address,
                                                             eni1.id))
                        break
                    except Exception as E:
                        if elapsed > timeout:
                            self.log.error('{0}. Was unable to re-use IP address:{1} after '
                                           'elasped:{2}. Error:"{3}"'
                                           .format(get_traceback(), eni1.private_ip_address,
                                                   elapsed, E))
                            raise RuntimeError('Was unable to re-use IP address:{0} after '
                                               'elasped:{1}. Error:"{2}"'
                                               .format(eni1.private_ip_address, elapsed, E))
            finally:
                if sub:
                    self.status('Deleteing subnet and artifacts from this ENI test...')
                    user.ec2.delete_subnet_and_dependency_artifacts(sub)


    def test6c_eni_eip_vpc_reserved_addresses(self):
        """
        Confirm the system does not allow the following reserved IP addresses.
        This test will create a test vpc, and a single subnet within that vpc with a cidr block
        equal to the vpc cidr block. It will attempt to create ENIs with private ip addresses
        which conflict with the VPC reserved addresses. These ENI create requests should fail
        with the proper error response.
        example using a 10.0.0.0/24
        10.0.0.0: Network address.
        10.0.0.1: Reserved by AWS for the VPC router.
        10.0.0.2: Reserved by AWS for mapping to the Amazon-provided DNS. (Note that the IP
                  address of the DNS server is the base of the VPC network range plus two.)
        10.0.0.3: Reserved by AWS for future use.
        10.0.0.255: Network broadcast address. We do not support broadcast in a VPC, therefore
                    we reserve this address.
        """
        user = self.user
        self.log.debug('creating test vpc...')
        vpc = user.ec2.connection.create_vpc('10.0.0.0/24')
        user.ec2.create_tags(vpc.id, {self.my_tag_name: 'test_vpc'})
        self.log.debug('creating test subnet....')
        subnet = self.create_subnet_and_tag(vpc_id=vpc.id, cidr_block=vpc.cidr_block, user=user)
        net_info = get_network_info_for_cidr(vpc.cidr_block)
        net_addr = net_info.get('network')
        bcast_addr = net_info.get('broadcast')
        octets = net_addr.split('.')
        octets[3]  = int(octets[3]) + 1
        router_addr = ".".join([str(x) for x in octets])
        octets[3] = int(octets[3]) + 1
        dns_addr =  ".".join([str(x) for x in octets])
        octets[3] = int(octets[3]) + 1
        future_addr = ".".join([str(x) for x in octets])

        for res_addr in [net_addr, bcast_addr, router_addr, dns_addr, future_addr]:
            try:
                eni = user.ec2.connection.create_network_interface(subnet_id=subnet.id,
                                                                   private_ip_address=res_addr)
            except Exception as E:
                if isinstance(E, EC2ResponseError) and int(E.status) == 400 and \
                    E.reason == 'InvalidParameterValue':
                    self.status('Passed. System returned proper error for ENI with reserved'
                                   'IP addr:{0}. Err: {1}'.format(res_addr, E))
                    good = True
                    continue
                else:
                    self.log.error('System responded with an error but no the one we expected '
                                   '"for creating an ENI with a reserved IP addr:{0}". Error:{1}'
                                   .format(res_addr, E))
                    raise E
            else:
                user.ec2.show_network_interfaces([eni])
                raise ValueError('System allowed either allowed an ENI to be created with '
                                 'the reserved IP address:"{0}", or did not respond with an '
                                 'error'.format(res_addr))
        self.status('Passed all attempts to use reserved addresses in ENI create requests')
        self.status('Attempting to clean up this eni test vpc artifacts...')
        if vpc:
            user.ec2.delete_vpc_and_dependency_artifacts(vpc)

    def test6d1_eni_multiple_post_run_attach_detach_and_terminate_tests(self):
        """
        Test Attaching and detaching an ENI to running instances in each zone.
        Note most checks are performed in the euinstance class attach/detach methods.
        Attach:
        Verify the ENI is reported correctly as attached.
        Verify the device is seen on the guest on attach.
        Verify the ENI can not be attached to another VM while attached.
        Verify the ENI can not be deleted while attached.

        Detach:
        Verify the ENI is reported correctly as detached
        Verify the device is no longer seen on the guest
        Verify the IP associated with this VM is no longer reachable.
        Verify the ENI can be deleted once detached.

        Terminate:
        Verify the attached ENIs are
        """

        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        instances = []
        subnets = []
        group = self.get_test_security_groups(vpc=vpc, user=user, count=1)[0]
        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet = self.get_non_default_test_subnets_for_vpc(vpc=vpc, user=user, zone=zone,
                                                                   count=1)[0]
                subnets.append(subnet)
                vm1, vm2 = self.create_test_instances(zone=zone, group=group,
                                                      subnet=subnet.id,
                                                      count=2, user=user, auto_connect=True)
                instances += [vm1, vm2]

                for vm in [vm1, vm2]:
                    if len(vm.interfaces) > 1:
                        self.log.debug('Detaching all pre-existing ENIS other than index0 from '
                                       '{0}'.format(vm.id))
                        vm.detach_all_enis()
                    self.show_vm_net_info(vm)
                    self.status('Instance {0} ENI info before attaching...'.format(vm.id))
                    enis  = self.get_test_enis_for_subnet(subnet=subnet, user=user, count=2)

                    self.status('Attaching two ENIs to test VM:{0}...'.format(vm.id))
                    for eni in enis:
                        vm.attach_eni(eni)
                    self.show_vm_net_info(vm)
                    self.status('Successfully attached ENIs to {0}'.format(vm.id))
                self.status('All network interfaces attached correctly for zone:{0}'.format(zone))
                self.status('Now attempting detach for all network interfacces...')
                for vm in [vm1, vm2]:
                    if len(vm.interfaces) > 1:
                        self.log.debug('Detaching all ENIS other than index0 from '
                                       '{0}'.format(vm.id))
                        vm.detach_all_enis()
                self.show_vm_net_info(vm)
                self.status('All network interfaces dettached correctly for zone:{0}'.format(zone))
            self.status('Success. Basic attach/detach tests passed. Now termination tests...')
            for instance in instances:
                instance.terminate_and_verify()
        finally:
            self.restore_vm_types()
            for subnet in subnets:
                self.status('Attempting to delete subnet and dependency artifacts from this test')
                user.ec2.delete_subnet_and_dependency_artifacts(subnet)

    def test6d2_eni_attribute_delete_on_terminate(self):
        """
        Attempts to verify the delete on terminate network interface attachment attribute.
        - Attach an ENI to VM in each zone.
        - Set and verify the delete on terminate attachment attribute
        - Terminate the VMs and verify the ENI per the D.O.T. flag.

        """
        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        instances = []
        subnets = []
        group = self.get_test_security_groups(vpc=vpc, user=user, count=1)[0]
        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet = self.get_non_default_test_subnets_for_vpc(vpc=vpc, user=user, zone=zone,
                                                                   count=1)[0]
                subnets.append(subnet)
                vm = self.get_test_instances(zone=zone, group_id=group, subnet_id=subnet.id,
                                             count=1, user=user, auto_connect=True,
                                             instance_type='m1.small')[0]
                instances.append(vm)

                if len(vm.interfaces) > 1:
                    self.log.debug('Detaching all pre-existing ENIS other than index0 from '
                                   '{0}'.format(vm.id))
                    vm.detach_all_enis()
                self.show_vm_net_info(vm)
                self.status('Instance ENI info before attaching...')

                eni1, eni2 = self.get_test_enis_for_subnet(subnet=subnet, user=user, count=2)
                self.status('Attaching two ENIs to test VMs:{0}.'.format(vm.id))
                for eni in [eni1, eni2]:
                    vm.attach_eni(eni)
                self.status('All network interfaces attached correctly for zone:'.format(zone))
                self.status('Setting delete on terminate flag and verifying post vm terminate...')
                user.ec2.modify_network_interface_attributes(eni1, delete_on_terminate=True)
                user.ec2.modify_network_interface_attributes(eni2, delete_on_terminate=False)
                self.status('Terminating instance {0} and verifying DOT flag for attached ENIs...'
                            .format(vm.id))
                vm.show_enis()
                vm.terminate_and_verify()
                self.status('Done Verifying DOT flag for zone:{0}'.format(zone))
        finally:
            self.restore_vm_types()
            for subnet in subnets:
                self.status('Attempting to delete subnet and dependency artifacts from this test')
                user.ec2.delete_subnet_and_dependency_artifacts(subnet)


    def test6e0_eni_runtime_attach_mutiple_eni_w_eip_and_delete_on_terminate(self):
        """
        Request multiple ENIs during the run instance request.
        Verify the network devices on are present on the guests, and the ENI attributes have
        the correct values.
        subnet of the primary ENI to the instance under test.
        """
        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        instances = []
        subnets = []
        group = self.get_test_security_groups(vpc=vpc, count=1, rules=self.DEFAULT_SG_RULES,
                                              user=user)[0]
        self.log.debug('Using Security group:{0}'.format(group.id))
        user.ec2.show_security_group(group)
        try:
            # Temporarily bump up the default VM type ENI count...
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet = self.get_non_default_test_subnets_for_vpc(vpc=vpc, user=user, zone=zone,
                                                                   count=1)[0]
                subnets.append(subnet)

                eni1, eni2, eni3 = self.get_test_enis_for_subnet(subnet=subnet, user=user, count=3)
                user.ec2.modify_network_interface_attributes(eni1, group_set=[group])
                eip = user.ec2.allocate_address()
                self.store_addr(user, eip)
                self.log.debug('Using EIP:{0}'.format(eip))
                eip.associate(network_interface_id=eni1.id)
                self.log.debug('Creating ENI collection containing 3 test ENIs...')
                eni_collection = user.ec2.create_network_interface_collection(eni=eni1,
                                                                              device_index=0,
                                                                              subnet_id=subnet,
                                                                              zone=zone,
                                                                              groups=group)
                eni_collection.add_eni(eni2, groups=[group.id], delete_on_termination=True)
                eni_collection.add_eni(eni3, groups=[group.id], delete_on_termination=False)
                self.log.debug('Creating test instance...')
                test_vm = self.create_test_instances(subnet=subnet,
                                                     count=1,
                                                     monitor_to_running=True,
                                                     network_interface_collection=eni_collection,
                                                     auto_connect=True)[0]
                test_vm.show_enis()
                for eni in [eni1, eni2, eni3]:
                    if not test_vm.get_network_local_device_for_eni(eni):
                        test_vm.show_network_device_info()
                        raise RuntimeError('Device for {0} not found on guest:{1} in running '
                                           'state'.format(eni, test_vm.id))
                test_vm.terminate_and_verify()

        finally:
            self.restore_vm_types()
            for subnet in subnets:
                self.status('Attempting to delete subnet and dependency artifacts from this test')
                user.ec2.delete_subnet_and_dependency_artifacts(subnet)


    def test6e2_eni_ebs_multiple_attach_on_run_stop_start_detach(self):
        """
            Using an EBS backed Instance...
            Request multiple ENIs during the run instance request.
            Verify the network devices on are present on the guests, and the ENI attributes have
            the correct values.
            subnet of the primary ENI to the instance under test.
            """
        user = self.user
        try:
            emi = user.ec2.get_emi(root_device_type='ebs', not_platform='windows')
        except EC2ResourceNotFoundException as E:
            E.value = "Unable to find an EBS backed EMI. Error:{0}".format(E.value)
            raise E
        if not emi:
            raise SkipTestException('Could not find an EBS backed image for this test?')
        vpc = self.test6b0_get_vpc_for_eni_tests()
        subnets = []
        group = self.get_test_security_groups(vpc=vpc, count=1, user=user)[0]

        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet = self.get_non_default_test_subnets_for_vpc(vpc=vpc, user=user, zone=zone,
                                                                   count=1)[0]
                subnets.append(subnet)

                eni1, eni2, eni3 = self.get_test_enis_for_subnet(subnet=subnet, user=user, count=3)
                user.ec2.modify_network_interface_attributes(eni1, group_set=[group])
                eip = user.ec2.allocate_address()
                self.store_addr(user, eip)
                eip.associate(network_interface_id=eni1.id)
                eni_collection = user.ec2.create_network_interface_collection(eni=eni1,
                                                                              subnet_id=subnet,
                                                                              zone=zone,
                                                                              groups=group)
                eni_collection.add_eni(eni2, groups=[group.id], delete_on_termination=True)
                eni_collection.add_eni(eni3, groups=[group.id], delete_on_termination=False)

                test_vm = self.create_test_instances(emi=emi,
                                                     subnet=subnet,
                                                     count=1,
                                                     monitor_to_running=True,
                                                     network_interface_collection=eni_collection,
                                                     auto_connect=True)[0]
                test_vm.show_enis()
                for eni in [eni1, eni2, eni3]:
                    if not test_vm.get_network_local_device_for_eni(eni):
                        test_vm.show_network_device_info()
                        raise RuntimeError('Device for {0} not found on guest:{1} in running '
                                           'state'.format(eni, test_vm.id))
                self.status('Stopping instance:{0} and checking eni status'.format(test_vm.id))
                # euinstance stop_start methods contain eni checks...
                test_vm.stop_instance_and_verify()
                self.status('Starting intance:{0} and checking eni status'.format(test_vm.id))
                test_vm.start_instance_and_verify()
                self.status('Done with. Stop / Start checks. Terminating VM:{0} and checking '
                            'ENI status'.format(test_vm.id))
                test_vm.terminate_and_verify()
                self.status('Success. EBS stop/start multiple ENI verification complete for '
                            'zone:{0}'.format(zone))

        finally:
            self.restore_vm_types()
            for subnet in subnets:
                self.status('Attempting to delete subnet and dependency artifacts from this test')
                user.ec2.delete_subnet_and_dependency_artifacts(subnet)

    def test6f1_eni_per_vmtype_test(self, vmtype='m1.large'):
        """
        Verify that a user can attach the number of ENIs the vmtype allows.
        Verify that if a user attemtps to exceed the # of ENIs the proper error is returned.
        "AttachmentLimitExceeded"
        """
        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        instances = []
        subnets = []
        group = self.get_test_security_groups(vpc=vpc, count=1, user=user)[0]
        vmtype = user.ec2.get_vm_type_info(vmtype)

        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet = self.get_non_default_test_subnets_for_vpc(vpc=vpc, user=user, zone=zone,
                                                                   count=1)[0]
                subnets.append(subnet)
                enis = self.get_test_enis_for_subnet(subnet=subnet, user=user,
                                                     count=int(vmtype.networkinterfaces))
                eni1 =enis[0]
                user.ec2.modify_network_interface_attributes(eni1, group_set=[group])
                eip = user.ec2.allocate_address()
                self.store_addr(user, eip)
                eip.associate(network_interface_id=eni1.id)
                eni_collection = user.ec2.create_network_interface_collection(eni=eni1,
                                                                              subnet_id=subnet,
                                                                              zone=zone,
                                                                              groups=group)
                for eni in enis[1:]:
                    eni_collection.add_eni(eni, groups=[group.id], delete_on_termination=True)

                self.status('Running instance with {0} enis, vmtype limit:{1}. Performing eni '
                            'attachment verification post run...'.format(len(enis),
                                                                         vmtype.networkinterfaces))
                test_vm = self.create_test_instances(subnet=subnet,
                                                     count=1,
                                                     monitor_to_running=True,
                                                     network_interface_collection=eni_collection,
                                                     auto_connect=True)[0]
                test_vm.show_enis()
                self.status('Successfully attached {0} enis to {1}, vmtype limit:{2}'
                            .format(len(test_vm.interfaces), test_vm.id, vmtype.networkinterfaces))
                self.status('Attempting to exceed the vmtype limit by attached 1 additional eni')
                try:
                    bad_eni = self.get_test_enis_for_subnet(subnet=subnet, user=user, count=1)[0]
                    test_vm.attach_eni(bad_eni)
                except EC2ResponseError as EE:
                    if int(EE.status) == 400 and EE.reason == 'AttachmentLimitExceeded':
                        self.status('Success. Was not able to exceed vmtype:{0} limit:{1}'
                                    .format(vmtype.name, vmtype.networkinterfaces))

        finally:
            self.restore_vm_types()
            for subnet in subnets:
                self.status('Attempting to delete subnet and dependency artifacts from this test')
                user.ec2.delete_subnet_and_dependency_artifacts(subnet)


    def test6h1_eni_eip_reassociate_toggle_basic_test(self, clean=None):
        """
        Test running a VM with an eip associated with the primary ENI.
        Verify connectivity to the EIP using ssh/ping.
        Swap in another EIP and verifiy connectivity using ssh/ping.
        Move the EIP to another VM's ENI and verify connectivity to the new instance using
        ssh/ping.
        """
        if clean is None:
            clean = not self.args.no_clean
        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        subnets = []
        group = self.get_test_security_groups(vpc=vpc, count=1, user=user)[0]
        def check_tcp_status(vm, timeout=120):
            vm.update()
            ip = vm.ip_address
            start = time.time()
            elapsed = 0
            attempts = 0
            while elapsed < timeout:
                attempts += 1
                elapsed = int(time.time() - start)
                try:
                    test_port_status(ip, port=22)
                    self.status('Success. TCP port 22 status is good. IP:{0}, Attempt:{1}, '
                                   'Elapsed:{2}'.format(ip, attempts, elapsed))
                    self.status('Checking instance ID in ssh login dir..')
                    while elapsed < timeout:
                        elapsed = int(time.time() - start)
                        try:
                            # reset ssh info...
                            vm.connect_to_instance()
                            # check testfile for unique instance id
                            vm.sys('cat testfile')
                            vm.sys('cat testfile | grep {0}'.format(vm.id), code=0)
                            self.status('Testfile and TCP check success after elapsed: {0}'
                                        .format(elapsed))
                            break
                        except CommandExitCodeException as CE:
                            try:
                                self.log.warning("LOCAL TEST MACHINE ARP INFO:\n{0}"
                                                 .format("\n".join(local('arp -a') or [])))
                            except Exception as ARPERROR:
                                self.log.warning('Error dumping ARP table:{0}'.format(ARPERROR))
                            self.log.warning('{0}\nError fetching instance id from test file. '
                                             'Elapsed:"{1}", ERR:"{2}"'
                                             .format(get_traceback(), elapsed, CE))
                            if elapsed > timeout:
                                raise CE
                            else:
                                time.sleep(10)

                    return vm
                except (socket.error, socket.timeout) as SE:
                    self.log.debug('TCP port 22 status failed for ip:"{0}". Attempt:{1}, '
                                   'elapsed:{2}/{3}'.format(ip, attempts, elapsed, timeout ))
                    time.sleep(1)
            raise RuntimeError('TCP port 22 status failed for ip:"{0}". Attempt:{1}, '
                               'elapsed:{2}/{3}'.format(ip, attempts, elapsed, timeout ))
        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet = self.get_non_default_test_subnets_for_vpc(vpc=vpc, user=user, zone=zone,
                                                                   count=1)[0]
                subnets.append(subnet)
                eni = self.get_test_enis_for_subnet(subnet=subnet, user=user, count=1)[0]
                eip1 = user.ec2.allocate_address()
                self.store_addr(user, eip1)
                eip2 = user.ec2.allocate_address()
                self.store_addr(user, eip2)
                eip1.associate(network_interface_id=eni.id)
                user.ec2.modify_network_interface_attributes(eni, group_set=[group])
                eni_collection = user.ec2.create_network_interface_collection(eni=eni,
                                                                               subnet_id=subnet.id,
                                                                               zone=zone,
                                                                               groups=group)

                self.status('Creating first Test VM with EIP provided in ENI collection at '
                            'run time...')
                vm1 = self.create_test_instances(subnet=subnet,
                                                     count=1,
                                                     monitor_to_running=True,
                                                     network_interface_collection=eni_collection,
                                                     auto_connect=True)[0]
                vm1.show_enis()
                self.status('Creating second Test VM...')
                vm2 = self.create_test_instances(subnet=subnet,
                                                 count=1,
                                                 monitor_to_running=True,
                                                 auto_connect=True)[0]
                self.status('Testing tcp port 22 status for each VM, this should work on the'
                            'first attempt. Writing instance ID to login directory for each'
                            'vm...')

                for vm in [vm1, vm2]:
                    test_port_status(vm1.ip_address, port=22)
                    vm.sys('echo "{0}" > testfile'.format(vm.id))
                self.status('SWAP#1: Swapping in eip:{0} for test vm1: {1}'.format(eip2,
                                                                           vm1.interfaces[0].id))
                self.status('vm1 {0} before eip {1} swap...'.format(vm1.id, eip2))
                vm1.show_enis()
                eip2.associate(network_interface_id=vm1.interfaces[0].id)
                vm1.update()
                self.status('VM1 {0} after eip {1} swap...'.format(vm1.id, eip2))
                vm1.show_enis()
                vm1 = check_tcp_status(vm1)

                self.status('SWAP#2: Associating vm1:{0}s original eip:{1} with vm2:{2}...'
                            .format(vm1.id, eip1, vm2.id))
                vm2.update()
                self.status('vm2 {0} before ip {1} association...'.format(vm2.id, eip1))
                vm2.show_enis()
                eip1.associate(network_interface_id=vm2.interfaces[0].id)
                vm2.update()
                self.status('vm2 {0} after ip {1} association...'.format(vm2.id, eip1))
                vm2.show_enis()
                vm2 = check_tcp_status(vm2)
                self.status('SWAP#3: Associating vm1:{0} original eip:{1} back to vm1:{0}'
                            .format(vm1.id, eip1))

                self.status('vm1 {0} before eip {1} swap...'.format(vm1.id, eip1))
                vm1.show_enis()
                eip1.associate(network_interface_id=vm1.interfaces[0].id)
                vm1.update()
                self.status('VM1 {0} after eip {1} swap...'.format(vm1, eip1))
                vm1.show_enis()
                vm1 = check_tcp_status(vm1)

                self.status('SWAP#4: Associating vm1:{0}s original eip:{1} with vm2:{2} for the 2nd '
                            'time...'.format(vm1.id, eip1, vm2.id))
                vm2.update()
                self.status('vm2 {0} before ip {1} association...'.format(vm2.id, eip1))
                vm2.show_enis()
                eip1.associate(network_interface_id=vm2.interfaces[0].id)
                vm2.update()
                self.status('vm2 {0} after ip {1} association...'.format(vm2.id, eip1))
                vm2.show_enis()
                vm2 = check_tcp_status(vm2)

                self.status('SWAP#5: Associating eip2:{0} with vm2:{1}...'
                            .format(eip2, vm2.id))
                vm2.update()
                self.status('vm2 {0} before ip {1} association...'.format(vm2.id, eip2))
                vm2.show_enis()
                eip2.associate(network_interface_id=vm2.interfaces[0].id)
                vm2.update()
                self.status('vm2 {0} after ip {1} association...'.format(vm2.id, eip2))
                vm2.show_enis()
                vm2 = check_tcp_status(vm2)

                self.status('Success. EIP toggle tests have passed')
        except Exception as E:
            self.log.error(red('{0}\nError during eip_reassociate_toggle_basic_test:{1}'
                               .format(get_traceback(), E)))
            raise E
        finally:
            self.log.debug('Attempting to clean up test artifacts now...')
            self.restore_vm_types()
            if clean:
                for subnet in subnets:
                    self.status('Attempting to delete subnet and dependency artifacts from '
                                'this test')
                    user.ec2.delete_subnet_and_dependency_artifacts(subnet)

    def test6m1_eni_migration_test_with_secondary_eni(self, clean=True):
        """
        Attempts to migrate an instance in each zone with a secondary ENI attached and
        verify the VMs and their ENIs migrate correctly.
        """
        if len(self.tc.sysadmin.get_all_node_controller_services()) <= 1:
            raise SkipTestException('This test requires 2 or more Node Controllers')

        def migrate_and_monitor_state(vm, start_node=None, timeout=360):
            if isinstance(vm, basestring):
                vm_id = vm
            else:
                vm_id = vm.id
            if not start_node:
                nodes = self.tc.sysadmin.get_hosts_for_node_controllers(instanceid=vm_id)
                if not nodes:
                    raise RuntimeError('Node Controller for vm:{0} not found before migration?')
                start_node = nodes[0]
            self.status('Sending migrate request for:{0}, starting on node:{1}'
                        .format(vm_id, start_node))
            self.tc.sysadmin.migrate_instances(instance_id=vm_id)
            self.status('Migrate request complete now monitoring migration for:{0}'
                        .format(vm_id))
            vm = self.tc.admin.ec2.get_instances(vm_id)[0]
            start = time.time()
            elapsed = 0
            source_node = None
            dest_node = None
            migrate_state = None
            self.status('Waiting for source and dest migration tags to appear for:{0}'
                        .format(vm_id))
            while (not migrate_state or not dest_node) and elapsed < 60:
                elapsed = int(time.time() - start)
                self.tc.admin.ec2.show_tags(vm.tags)
                source_node = vm.tags.get('euca:node:migration:source', None)
                dest_node = vm.tags.get('euca:node:migration:destination', None)
                current_node = vm.tags.get('euca:node', None)
                migrate_state = vm.tags.get('euca:node:migration:state', None)
                if not source_node or not dest_node:
                    time.sleep(5)
                    vm.update()
            self.status('Wait for tags complete. Tags state:{0}, dest:{1}'
                        .format(migrate_state, dest_node))
            self.tc.admin.ec2.show_tags(vm.tags)
            if not migrate_state or not dest_node:
                raise ValueError('{0} tags did not have migration state and dest info after'
                                 ' elapsed:{1}'.format(vm.id, elapsed))
            elapsed = 0
            start = time.time()
            migrate_state = None
            done = False
            state_passes = 0
            self.status('Monitor {0} tag info for migration status...'.format(vm_id))
            while not done and elapsed < timeout:
                self.log.debug('{0} migration status:"{1}" after elapsed {2}/{3}'
                               .format(vm_id, migrate_state, elapsed, timeout))
                vm.update()
                self.tc.admin.ec2.show_tags(vm.tags)
                elapsed = int(time.time() - start)
                migrate_state = vm.tags.get('euca:node:migration:state', None)
                current_node = vm.tags.get('euca:node', None)
                self.log.debug('Still monitoring vm:{0} migration status:"{1}", elapsed:{2}/{3}'
                               .format(vm.id, migrate_state, elapsed, timeout))
                # Tags may briefly disappear.
                # Use state passes to ensure the tags are consistent across multiple monitoring
                # intervals.
                if not migrate_state:
                    if state_passes:
                        done = True
                        break
                    else:
                        time.sleep(5)
                    state_passes += 1
                else:
                    time.sleep(5)
                    state_passes = 0
            self.status('Monitoring complete. State tag was either missing or we timed out. '
                        'Migration state:{0}, elapsed:{1}/{2}'
                        .format(migrate_state, elapsed, timeout))
            self.status('Checking to see if the VM actually moved to the correct node now...')
            nodes = self.tc.sysadmin.get_hosts_for_node_controllers(instanceid=vm_id)
            if not nodes:
                raise RuntimeError('Node Controller for vm:{0} not found after migration?')
            current_node = nodes[0]
            if str(dest_node).strip() != str(current_node.hostname).strip():
                self.log.error(red('{0}\nFinal node:{1} != tag destination:{2} for {3} migration'
                                   .format(get_traceback(), current_node.hostname, dest_node,
                                           vm_id)))
            if current_node.hostname != start_node.hostname:
                self.log.debug('Success. Migrated VM:{0} from {1} to {2}'
                               .format(vm.id, source_node, dest_node))
                return
            self.log.error(red('{0} ended on the same node:{1} that it started on:{2} post migration'
                               .format(vm_id, current_node.hostname, start_node.hostname)))

            errmsg = ('Instance: {0} Failed to migrate after {1}/{2} seconds. '
                               'Last migration state:{3}'.format(vm.id, elapsed, timeout,
                                                                 migrate_state))
            self.log.error(red(errmsg))
            raise RuntimeError(errmsg)

        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        instances = []
        subnets = []

        group = self.get_test_security_groups(vpc=vpc, count=1, user=user)[0]

        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                self.status('Beginning Migration test setup for zone:"{0}"'.format(zone))
                self.tc.admin.ec2.show_vm_types(zone=zone)
                subnet1, subnet2 = self.get_non_default_test_subnets_for_vpc(vpc=vpc, user=user,
                                                                             zone=zone, count=2)
                subnets += [subnet1, subnet2]
                eni1, eni2 = self.get_test_enis_for_subnet(subnet=subnet2, user=user, count=2)
                self.status('Creating VMs for this test...')
                vm1, vm2 = self.get_test_instances(zone=zone, group_id=group.id, vpc_id=vpc.id,
                                                   subnet_id=subnet1.id, instance_type='m1.small',
                                                   count=2)
                instances += [vm1, vm2]
                self.status('Prepping test Vms. '
                            'Detaching all ENIs other than the primary before beginning this test')
                for vm in [vm1, vm2]:
                    vm.detach_all_enis(exclude_indexes=[0])
                self.status('Attaching secondary enis to the test VMs...')
                vm1.attach_eni(eni1)
                vm2.attach_eni(eni2)
                self.status('Configuring secondary ENIs with static IP info on VMs...')
                vm1.sync_enis_static_ip_config(exclude_indexes=[0])
                vm2.sync_enis_static_ip_config(exclude_indexes=[0])
                self.status('Checking the secondary ENI by pinging each other VM to VM as well '
                            'as from the CLCs VPC network namespace...')
                vm1.sys('ping -c1 -W5 {0}'.format(eni2.private_ip_address), code=0)
                vm2.sys('ping -c1 -W5 {0}'.format(eni1.private_ip_address), code=0)
                self.status('Ping test passed. Nodes before migration request...')
                self.tc.sysadmin.show_nodes()
                self.status('Starting migration for VM:{0} ...'.format(vm1.id))
                nodes = self.tc.sysadmin.get_hosts_for_node_controllers(instanceid=vm1.id)
                if not nodes:
                    raise RuntimeError('Node Controller for vm:{0} not found before migration?')
                start_node = nodes[0]
                migrate_and_monitor_state(vm1, start_node=start_node)
                nodes = self.tc.sysadmin.get_hosts_for_node_controllers(instanceid=vm1.id)
                if not nodes:
                    raise RuntimeError('Node Controller for vm:{0} not found after migration?')
                end_node = nodes[0]
                self.log.debug('VM:{0} migrated from node:{1} to node:{2}'.format(vm1.id,
                                                                                  start_node,
                                                                                  end_node))
                if start_node.hostname == end_node.hostname:
                    raise ValueError('ERROR: VM:{0} ended up on the same node post migration.'
                                     ' Starting node:{1}, ending node:{2}'.format(vm1.id,
                                                                                  start_node,
                                                                                  end_node))
                vm1.refresh_ssh()
                vm1.check_eni_attachments()
                elapsed = 0
                start = time.time()
                good = False
                self.log.debug('Attempting ENI ping checks post migration...')
                for x in xrange(0, 6):
                    try:
                        elapsed = int(time.time() - start)
                        self.log.debug('Attempting to ping eni2:{0} from vm1:{1}'
                                       .format(eni2.private_ip_address, vm1.id))
                        vm1.sys('ping -c1 -W5 {0}'.format(eni2.private_ip_address), code=0)
                        good = True
                        break
                    except CommandExitCodeException as CE:
                        self.log.warning('Ping attempt to eni2:{0} from vm1:{1} failed on'
                                         ' attempt:{2}, elapsed:{3}'
                                         .format(eni2.private_ip_address, vm1.id, x, elapsed))
                        time.sleep(5)
                if not good:
                    raise RuntimeError('Ping attempt to eni2:{0} from vm1:{1} failed on'
                                         ' attempt:{2}, elapsed:{3}'
                                         .format(eni2.private_ip_address, vm1.id, x, elapsed))

                elapsed = 0
                start = time.time()
                good = False
                for x in xrange(0, 6):
                    try:
                        elapsed = int(time.time() - start)
                        self.log.debug('Attempting to ping eni1:{0} from vm2:{1}'
                                       .format(eni2.private_ip_address, vm1.id))
                        vm2.sys('ping -c1 -W5 {0}'.format(eni1.private_ip_address), code=0)
                        good = True
                        break
                    except CommandExitCodeException as CE:
                        self.log.warning('Ping attempt to eni1:{0} from vm2:{1} failed on'
                                         ' attempt:{2}, elapsed:{3}'
                                         .format(eni1.private_ip_address, vm2.id, x, elapsed))
                        time.sleep(5)
                if not good:
                    raise RuntimeError('Ping attempt to eni1:{0} from vm2:{1} failed on'
                                       ' attempt:{2}, elapsed:{3}'
                                       .format(eni1.private_ip_address, vm2.id, x, elapsed))


                self.status('Ping check post migration complete.')
                self.status('Nodes after migration completed...')
                self.tc.sysadmin.show_nodes()
                self.status('Migration ENI tests complete for zone:{0}'.format(zone))
        except Exception as E:
            self.log.error(red('{0}\nError during ENI migration tests:{1}'
                               .format(get_traceback(), E)))
            raise E

        finally:
            self.restore_vm_types()
            if clean:
                start = time.time()
                elapsed = 0
                timeout = 90
                retry = instances
                while retry and elapsed < timeout:
                    elapsed = int(time.time() - start)
                    # Send an initial terminate to all instances, do not wait for state yet...
                    for instance in instances:
                        try:
                            instance = self.tc.admin.ec2.get_instances(instance.id)[0]
                            if instance.tags.get('euca:node:migration:state'):
                                self.log.debug('Waiting on instance {0} to clear migration '
                                               'state. Elapsed:{1}'.format(instance.id, elapsed))
                                self.tc.admin.ec2.show_tags(instance.tags)
                            else:
                                for i in retry:
                                    if i.id == instance.id:
                                        retry.remove(i)
                        except:
                            pass
                    if retry:
                        time.sleep(5)
                for instance in instances:
                    instance.terminate_and_verify()

                for subnet in subnets:
                    self.status('Attempting to delete subnet and dependency artifacts from '
                                'this test')
                    user.ec2.delete_subnet_and_dependency_artifacts(subnet)

    def test6n1_eni_swap_between_vms_packet_test(self, clean=True):
        """
        Verify connectivity moving a network interface between two or more VMs, and back.
        Check ENI attribute state and verify packets are going to the correct recipient.
        Run 3 VMs with the primary interfaces in the same subnet, group and with public ips.
        Write the Instance IDs to files on the guest to use for confirming IP ownership.
        Create 3 new ENIs in a second subnet and attach 1 ENI to each of the 3 VMs.
        No public IPs on the 2nd ENIS.
        Configure the Guests with Static IP assignments using the ENI's private IPS.
        Shut down the guest interfaces for the primary ENIs on 2 VMs, the 3rd VM will act as
        an SSH proxy/gateway for the machine running this test.
        Verify SSH connectivity through the Proxy VM to the guests 2nd ENIs private interfaces.
        Check the testfiles for proper VM ids.
        Swap the ENIs on the 2 non-proxy VMs.
        Re-connect through the proxy vm to the 2 test VMs and verify the testfiles for proper ids.
        Swap the ENIs back and repeat verifications
        """
        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        instances = []
        subnets = []
        status = self.status
        group = self.get_test_security_groups(vpc=vpc, count=1, user=user)[0]
        self.last_status_msg = ""
        def bring_vm_primary_interface_up(vm, vm_ssh):
            status('Bringing up primary interface for:{0}'.format(vm.id))
            vm_ssh.sys('ifconfig {0} up'.format(vm.primary_dev), code=0, verbose=True)
            vm.ssh = vm_ssh
            status('Syncing ENI info for vm:{0}...'.format(vm.id))
            vm.sync_enis_static_ip_config(exclude_indexes=[1,2])
            vm.show_network_device_info()
            vm_ssh.sys('route add -net 0.0.0.0/0 gw {0}'.format(gateway))
            self.log.debug(vm_ssh.sys('netstat -rn', listformat=False))
            status('Attempting to connect to vm1 @ {0}'.format(vm.ip_address))
            vm.connect_to_instance()
            status('Done Bringing up primary interface for:{0}'.format(vm.id))


        def vm_id_check(ssh, id):
            try:
                self.status('Checking host "{0}" for testfile id:"{1}"'.format(ssh.host, id))
                out = ssh.sys('cat testfile'.format(id), verbose=True,
                              listformat=False)
                self.log.debug('Got testfile output from host:{0}. id{1}, output:"{2}"'
                               .format(ssh.host, id, out))
                if not out:
                    raise Exception('Testfile not found or empty on ssh host:{0}, id:{1}'
                                    .format(ssh.host, id))
                instance_id = re.search('i-\w{8}', out)
                if instance_id:
                    instance_id = instance_id.group()
                    if instance_id != id:
                        msg = 'Connected to wrong instance in ENI check. Instance ID found in ' \
                              'testfile:{0} does not match expected:{1} on ' \
                              'host:{2}'.format(instance_id, id, ssh.host)
                        self.log.error(red(msg))
                        try:
                            vm = user.ec2.convert_instance_to_euinstance(id)
                            self.log.error('ENI info for the expected owner of {0} instance:{1}'
                                           '...'.format(ssh.host, id))
                            vm.show_enis()
                            test_file_vm = user.ec2.convert_instance_to_euinstance(instance_id)
                            self.log.error('ENI info for the VM ID:{0} the test connected to at'
                                           'IP:{1}'.format(instance_id, ssh.host))
                            test_file_vm.show_enis()
                        except Exception as OOPS:
                            self.log.warning('{0}\nIgnoring error while printing ENI debug '
                                             'info. Error:{1}'.format(get_traceback(), OOPS))

                        raise ValueError(msg)
            except Exception as E:
                self.log.error(red('{0}\nvm_id_check failed for host:{1}, id:{2}. Error:"{3}"'
                                   .format(get_traceback(), ssh.host, id, E)))
                try:
                    out = ssh.sys('hostname; ifconfig', listformat=False)
                    self.log.error('hostname and ifconfig from failed vm_id_check guest:\n{0}'
                                   .format(out))
                except:
                    pass
                raise E
        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet1, subnet2 = self.get_non_default_test_subnets_for_vpc(vpc=vpc, user=user,
                                                                             zone=zone, count=2)
                subnets += [subnet1, subnet2]
                net_info = get_network_info_for_cidr(subnet1.cidr_block)
                net_octets = net_info.get('network').split('.')
                gateway = "{0}.{1}.{2}.{3}".format(net_octets[0], net_octets[1], net_octets[2],
                                                   (int(net_octets[3]) + 1))
                eni1, eni2, eni3 = self.get_test_enis_for_subnet(subnet=subnet2, user=user,
                                                                 count=3)
                self.status('Creating VMs for this test...')
                vm1, vm2, proxyvm = self.get_test_instances(zone=zone, group_id=group.id,
                                                        vpc_id=vpc.id, subnet_id=subnet1.id,
                                                        instance_type='m1.small',
                                                        auto_connect=True, count=3)
                instances = [vm1, vm2, proxyvm]
                status('Writing Instance ID files to guests')
                for vm in [vm1, vm2, proxyvm]:
                    vm.sys('echo "{0}" > testfile'.format(vm.id), code=0)
                status('Attaching Secondary ENIs and setting up static IP '
                            'config for the secondary ENIs')
                vm1.attach_eni(eni1)
                vm2.attach_eni(eni2)
                proxyvm.attach_eni(eni3)
                status('Setting up ENI interface IPs with static configurations...')
                for vm in [vm1, vm2, proxyvm]:
                    vm.sync_enis_static_ip_config(exclude_indexes=[0])
                status('Shutting down the primary interfaces on vm1 and vm2 to ensure '
                            'packet path uses secondary ENIs...')
                for vm in [vm1, vm2]:
                    net_info = vm.get_network_local_device_for_eni(vm.interfaces[0].id)
                    dev_name = net_info.get('dev_name')
                    vm.primary_dev = dev_name
                    try:
                        vm.sys('ifconfig {0} down'.format(dev_name), code=0, timeout=2)
                    except CommandTimeoutException:
                        pass
                status('Creating new ssh sessions to vm1 and vm2 through proxy VM3:{0}'
                            .format(proxyvm.id))
                vm1_ssh = SshConnection(host=vm1.interfaces[1].private_ip_address,
                                        keypath=vm1.keypath, proxy=proxyvm.ip_address,
                                        proxy_keypath=proxyvm.keypath)
                vm2_ssh = SshConnection(host=vm2.interfaces[1].private_ip_address,
                                        keypath=vm2.keypath, proxy=proxyvm.ip_address,
                                        proxy_keypath=proxyvm.keypath)
                status('Proxy SSH connections established, checking id files on guests...')
                vm_id_check(vm1_ssh, vm1.id)
                vm_id_check(vm2_ssh, vm2.id)
                status('ID file check passed')
                status('Bringing the primary interfaces back up temporarily to allow ssh '
                       'to connect on those interfaces during secondary eni swap out...')
                bring_vm_primary_interface_up(vm1, vm1_ssh)
                bring_vm_primary_interface_up(vm2, vm2_ssh)


                status('Swapping secondary ENIs on VM1:{0} and VM2:{1} ...'
                            .format(vm1.id, vm2.id))
                status('VM1 before swap...')
                vm1.show_enis()
                status('VM2 before swap...')
                vm2.show_enis()
                try:
                    self.status('Detaching ENI1 from VM1 for swap...')
                    vm1.detach_eni(eni1)
                    self.status('Detaching ENI2 from VM2 for swap...')
                    vm2.detach_eni(eni2)
                    self.status('Attaching swapped ENI2 to VM1')
                    vm1.attach_eni(eni2)
                    self.status('Attaching swapped ENI1 to VM2')
                    vm2.attach_eni(eni1)
                except Exception as E:
                    self.log.error('{0}\nERROR:{1}\nset self.bad_instances now...'
                                   .format(get_traceback(), E))
                    self.bad_instances = [vm1, vm2]
                    return
                status('Setting up secondary interface IPs with static configurations...')
                for vm in [vm1, vm2]:
                    vm.sync_enis_static_ip_config(exclude_indexes=[0])
                    vm.show_network_device_info()
                status('Shutting down the primary interfaces on vm1 and vm2 to ensure '
                            'packet path uses secondary ENIs...')
                for vm in [vm1, vm2]:
                    try:
                        vm.sys('ifconfig {0} down'.format(vm.primary_dev), code=0, timeout=2,
                               verbose=True)
                    except CommandTimeoutException:
                        pass

                status('ENIS have been swapped. Attempting to establish ssh sessions'
                            'to new secondary ENI attachments through proxy vm...')
                vm1_ssh = SshConnection(host=vm1.interfaces[1].private_ip_address,
                                        keypath=vm1.keypath, proxy=proxyvm.ip_address,
                                        proxy_keypath=proxyvm.keypath, logger=vm1.log)
                vm2_ssh = SshConnection(host=vm2.interfaces[1].private_ip_address,
                                        keypath=vm2.keypath, proxy=proxyvm.ip_address,
                                        proxy_keypath=proxyvm.keypath, logger=vm2.log)

                status('Proxy SSH connections established through proxy, '
                            'checking id files on guests...')
                vm_id_check(vm1_ssh, vm1.id)
                vm_id_check(vm2_ssh, vm2.id)
                status('First ENI swap and packet path checks succeeded...')
                status('Bringing the primary interfaces back up temporarily to allow ssh '
                            'to connect on those interfaces during secondary eni swap out...')
                bring_vm_primary_interface_up(vm1, vm1_ssh)
                bring_vm_primary_interface_up(vm2, vm2_ssh)
                status('Swapping ENIs back again...')
                status('VM1 before swap...')
                vm1.show_enis()
                status('VM2 before swap...')
                vm2.show_enis()
                status('swapping ENIs back again now...')
                self.status('Detaching ENI2 from VM1 for swap back...')
                vm1.detach_eni(eni2)
                self.status('Detaching ENI1 from VM2 for swap back...')
                vm2.detach_eni(eni1)
                self.status('Attaching ENI1 to VM1 for swap back...')
                vm1.attach_eni(eni1)
                self.status('Attaching ENI2 to VM2 for swap back...')
                vm2.attach_eni(eni2)
                status('Setting up secondary interface IPs with static configurations...')
                for vm in [vm1, vm2]:
                    vm.sync_enis_static_ip_config(exclude_indexes=[0])
                    vm.show_network_device_info()
                status('Shutting down the primary interfaces on vm1 and vm2 to ensure '
                                'packet path uses secondary ENIs...')
                for vm in [vm1, vm2]:
                    try:
                        vm.sys('ifconfig {0} down'.format(vm.primary_dev), code=0, timeout=2)
                    except CommandTimeoutException:
                        pass
                status('ENIS have been swapped. Attempting to establish ssh sessions'
                            'to new ENI attachments...')
                try:
                    vm1_ssh = SshConnection(host=vm1.interfaces[1].private_ip_address,
                                            keypath=vm1.keypath, proxy=proxyvm.ip_address,
                                            proxy_keypath=proxyvm.keypath)
                    vm2_ssh = SshConnection(host=vm2.interfaces[1].private_ip_address,
                                            keypath=vm2.keypath, proxy=proxyvm.ip_address,
                                        proxy_keypath=proxyvm.keypath)
                except Exception as SE:
                    self.log.error(red('{0}\nError trying to establish SSH sessions post 2nd ENI '
                                       'swap:{1}'.format(get_traceback(), SE)))
                    raise

                status('Proxy SSH connections established through proxy, '
                            'checking id files on guests...')
                vm_id_check(vm1_ssh, vm1.id)
                vm_id_check(vm2_ssh, vm2.id)
                status('Second ENI swap and packet path checks succeeded...')
                status('ENI swap tests complete for zone:{0}'.format(zone))
        except Exception as E:
            self.log.error(red('{0}\nTest Failed. Last Status Msg:{1}, error:{2}'
                               .format(get_traceback(), self.last_status_msg, E)))
            raise E

        finally:
            if clean:
                self.status('Beginning test cleanup. Last Status msg:"{0}"...'
                                .format(self.last_status_msg))
                self.restore_vm_types()
                for vm in instances:
                    try:
                        vm.terminate_and_verify()
                    except Exception as E:
                        self.log.debug('{0}\nError:{1}'.format(get_traceback(), E))
                for subnet in subnets:
                    self.status('Attempting to delete subnet and dependency artifacts from this test')
                    user.ec2.delete_subnet_and_dependency_artifacts(subnet)

    def test6p1_eni_sec_group_tcp_icmp_udp_sctp_inner_vpc_eni_packet_tests(self, clean=True,
                                                                           icmp=True, udp=True,
                                                                           tcp=True, sctp=True,
                                                                           stop_on_fail=False,
                                                                           verbose=True):
        """
        Launches 2 VMs in the same VPC to test VM to VM traffic of types ICMP, UDP, TCP and SCTP.

        -The primary ENIS will be in the same subnet and security group.
        -The test will create multiple ENIs to attach/detach to the test VMs.
         These ENIs will test variations of packet tests between ENIs within the same and different
         subnets and security groups using a simple packet test between ENIs within the same
        subnet.
        -The packet tests will include udp, tcp, icmp and sctp.
        -The test will adjust the security group rules to allow the traffic type and port(s) for
         the tests.
        -At this time the test does not test revoking these rules, although this functionality is
         covered in other tests in this suite.
        """
        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        err = ""
        instances = []
        subnets = []
        protocols = []
        tables = []
        self.test_count = 0
        self.current_test_scenario = None
        status = self.status
        test_scenario_summary = {}
        self.last_status_msg = ""
        test_errors = []
        failed_scenarios = []
        current_zone = None

        def show_scenario_summary():
            spt = PrettyTable(["#", 'TEST SCENARIO', 'SUMMARY', 'PROTOCOL', 'RESULT'])
            spt.max_width['TEST SCENARIO'] = 75
            spt.max_width['#'] = 3
            spt.max_width['SUMMARY'] = 7
            spt.max_width['PROTOCOL'] = 4
            spt.max_width['RESULT'] = 6
            spt.padding_width = 0
            spt.align = 'l'
            count = 0
            for scenario, result in test_scenario_summary.iteritems():
                count += 1
                scenario = str(scenario).upper().replace('TEST SCENARIO', '')
                header = markup(scenario, [ForegroundColor.BLACK,
                                                       BackGroundColor.BG_WHITE])
                spt.add_row([count, header, result.get('result'), "", ""])
                for protocol, presult in result.get('protocols', {}).iteritems():
                    count += 1
                    spt.add_row([count, scenario, "", protocol, presult])
            self.log.info("\n{0}\n".format(spt.get_string(sortby="#")))
            self.log.info('Current test errors:\n{0}'.format("\n".join(test_errors)))
            self.log.info('\nCurrent Failed scenarios:\n{0}'.format("\n".join(failed_scenarios)))

        def new_test_status(msg):
            show_scenario_summary()
            msg = "Zone:{0}, {1}".format(current_zone, msg)
            if msg not in test_scenario_summary:
                test_scenario_summary[msg] = {'result': None, 'protocols':{}}
                test_scenario_summary[msg]['result'] = green('PASS')
            self.current_test_scenario = msg
            msg = markup("\n{0}\n".format(msg),
                         markups=[ForegroundColor.WHITE, BackGroundColor.BG_BLUE])
            return status(msg)


        test_rules = [('tcp', 22, 22, '0.0.0.0/0'), ('icmp', -1, -1, '0.0.0.0/0')]
        if tcp:
            protocols.append('tcp')
            test_rules.append(('tcp', 100, 100, '0.0.0.0/0'))
        if icmp:
            protocols.append('icmp')
            test_rules.append(('icmp', -1, -1, '0.0.0.0/0'))
        if udp:
            protocols.append('udp')
            test_rules.append(('udp', 100, 100, '0.0.0.0/0'))
        if sctp:
            protocols.append('sctp')
            test_rules.append((132, 22, 22, '0.0.0.0/0'))

        def run_tests(vm_tx, vm_rx, dest_ip, expected=None, protocol_list=None):
            res_dict = {}
            vm_rx.update()
            vm_tx.update()
            protocol_list = protocol_list or protocols
            for protocol in protocol_list:
                header = "{0}, Zone:{1}, {2}".format(protocol, current_zone,
                                                     self.current_test_scenario)
                test_dict, passed, table = self.vm_packet_test(vm_tx=vm_tx, vm_rx=vm_rx,
                                                               dest_ip=dest_ip, protocol=protocol,
                                                               packet_count=5,
                                                               expected_count=expected,
                                                               header_info=header)
                if not passed:
                    result = red('FAILED')
                else:
                    result = green('PASSED')
                    test_scenario_summary[self.current_test_scenario]['protocols'][protocol] = \
                        result
                tables.append(table)
                self.test_count += 1
                res_dict[protocol] = {'test_dict': test_dict, 'passed': passed, 'table': table}
            return res_dict


        primary_group = self.get_test_security_groups(vpc=vpc, count=1, rules=test_rules,
                                                      user=user)[0]
        primary_group2 = self.get_test_security_groups(vpc=vpc, count=1, rules=test_rules,
                                                      user=user)[0]
        eni_group1 = self.get_test_security_groups(vpc=vpc, count=1, rules=test_rules, user=user)[0]
        eni_group2 = self.get_test_security_groups(vpc=vpc, count=1, rules=test_rules, user=user)[0]
        test_groups = [primary_group, primary_group2, eni_group1, eni_group2]


        def ping_for_status(vm_tx, ip):
            status('Using ping from:{0} to {1} to test for when rules are applied....'
                   .format(vm_tx, ip))
            if not isinstance(ip, basestring):
                ip = ip.private_ip_address
            start = time.time()
            elapsed = 0
            timeout = 90
            good = False
            while not good and elapsed < timeout:
                elapsed = int(time.time() - start)
                try:
                    vm_tx.sys('ping -c1 -W2 {0}'.format(ip), code=0)
                    self.log.debug('ping_for_status succeeded after elapsed: {0}/{1}'.
                                   format(elapsed, timeout))
                    good = True
                    break
                except CommandExitCodeException:
                    self.log.debug('Still waiting for {0} to ping {1} test after elapsed: {2}/{3}'.
                                   format(vm_tx, ip, elapsed, timeout))
                    time.sleep(5)
                except SSHException as SE:
                    self.log.warning('Caught SSH Error:"{0}"'.format(SE))
                    self.log.debug('Attempting to reconnect SSH...')
                    try:
                        vm_tx.connect_to_instance()
                    except Exception as E:
                        self.log.error(red("{0}\n{1}".format(get_traceback(), E)))
                        elapsed = int(time.time() - start)
                        if elapsed > timeout:
                            raise E
            if not good:
                raise RuntimeError('{0} was not ping-able from {1} after {2}/{3} seconds'
                                   .format(ip, vm_tx, elapsed,timeout))

        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                current_zone = zone
                status('Setting security group rules...')
                for group in test_groups:
                    group = self.set_group_rules(group, test_rules, user=user)
                status('Creating test subnets...')
                primary_subnet, primary_subnet2, subnet1, subnet2 = self.get_non_default_test_subnets_for_vpc(
                    vpc=vpc, user=user, zone=zone, count=4)
                subnets += [primary_subnet, subnet1, subnet2]
                status('Creating test ENIs')
                eni1_s1_g1, eni2_s1_g1 = self.get_test_enis_for_subnet(subnet=subnet1,
                                                           apply_groups=eni_group1.id,
                                                           user=user, count=2)
                eni3_s1_g2 = self.get_test_enis_for_subnet(subnet=subnet1,
                                                           apply_groups=eni_group2.id,
                                                           user=user, count=1,
                                                           exclude=[eni1_s1_g1, eni2_s1_g1])[0]
                eni4_s2_g2 = self.get_test_enis_for_subnet(subnet=subnet2,
                                                           apply_groups=eni_group2.id,
                                                           user=user, count=1)[0]
                eni5_s2_g1 = self.get_test_enis_for_subnet(subnet=subnet2,
                                                           apply_groups=eni_group1.id,
                                                           user=user, count=1,
                                                           exclude=[eni4_s2_g2])[0]

                status('Creating VMs for this test...')
                vm_tx, vm_rx  = self.get_test_instances(zone=zone, group_id=primary_group.id,
                                                        vpc_id=vpc.id, subnet_id=primary_subnet.id,
                                                        instance_type='m1.small',
                                                        auto_connect=True, count=2,
                                                        monitor_to_running=False)
                vm_rx2 = self.get_test_instances(zone=zone, group_id=primary_group2,
                                                 vpc_id=vpc.id, subnet_id=primary_subnet2.id,
                                                 instance_type='m1.small',
                                                 auto_connect=True, count=1,
                                                 monitor_to_running=False)[0]
                instances = [vm_tx, vm_rx, vm_rx2]
                user.ec2.monitor_euinstances_to_running(instances=instances)

                new_test_status('Test scenario Primary ENIs same group same subnet private IP')
                try:
                    vm_tx.show_enis()
                    vm_rx.show_enis()
                    results = run_tests(vm_tx, vm_rx, vm_rx.private_ip_address)
                    self.log.debug(blue(results))
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            self.log.error('No passed in result?\n{0}'.format(res_dict))
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                    protocol,
                                                                    res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E

                new_test_status('Test scenario Primary ENIs same group same subnet public IP')
                try:
                    results = run_tests(vm_tx, vm_rx, vm_rx.ip_address)
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E

                new_test_status('Test scenario Secondary ENIs same group same subnet private IP')
                try:
                    vm_tx.attach_eni(eni1_s1_g1)
                    vm_tx.sync_enis_static_ip_config()
                    vm_rx.attach_eni(eni2_s1_g1)
                    vm_rx.sync_enis_static_ip_config()
                    ping_for_status(vm_tx, eni2_s1_g1)
                    results = run_tests(vm_tx, vm_rx, eni2_s1_g1.private_ip_address)
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E
                finally:
                    vm_rx.detach_eni(eni2_s1_g1, ignore_missing=True)

                new_test_status('Test scenario Secondary ENI different group same subnet private IP')
                try:
                    vm_rx.attach_eni(eni3_s1_g2)
                    vm_rx.sync_enis_static_ip_config()
                    ping_for_status(vm_tx, eni3_s1_g2)
                    results = run_tests(vm_tx, vm_rx, eni3_s1_g2.private_ip_address)
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E
                finally:
                    vm_rx.detach_eni(eni3_s1_g2, ignore_missing=True)

                new_test_status('Test scenario Primary ENI different group different '
                                'subnet private IP')
                try:
                    #vm_rx.attach_eni(eni5_s2_g1)
                    #vm_rx.sync_enis_static_ip_config()
                    #ping_for_status(vm_tx, eni5_s2_g1)
                    results = run_tests(vm_tx, vm_rx2, vm_rx2.private_ip_address)
                                        #protocol_list=['icmp'])
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E
                #finally:
                #    vm_rx.detach_eni(eni5_s2_g1, ignore_missing=True)

                """
                new_test_status('Test scenario Secondary ENIs different group different subnet private IP')
                try:
                    vm_rx.attach_eni(eni4_s2_g2)
                    vm_rx.sync_enis_static_ip_config()
                    ping_for_status(vm_tx, eni4_s2_g2)
                    results = run_tests(vm_tx, vm_rx, eni4_s2_g2.private_ip_address,
                                        protocol_list=['icmp'])
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.last_status_msg,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    test_errors.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E
                finally:
                    vm_rx.detach_eni(eni4_s2_g2, ignore_missing=True)
                """
                status('Beginning negative, revoke tests...')
                status('Revoking all security group rules from sec groups, leaving ssh on the'
                         'primary interface')

                user.ec2.revoke_all_rules(primary_group)
                user.ec2.revoke_all_rules(primary_group2)
                user.ec2.revoke_all_rules(eni_group1)
                user.ec2.revoke_all_rules(eni_group2)
                user.ec2.authorize_group(primary_group, protocol='tcp', port=22,
                                         cidr_ip="0.0.0.0/0")
                user.ec2.authorize_group(primary_group2, protocol='tcp', port=22,
                                         cidr_ip="0.0.0.0/0")
                user.ec2.show_security_groups([primary_group, primary_group2])
                status('Using ping to test for when rules are applied...')
                start = time.time()
                elapsed = 0
                timeout = 90
                good = False
                while not good and elapsed < timeout:
                    elapsed = int(time.time() - start)
                    try:
                        vm_tx.connect_to_instance()
                        vm_tx.sys('ping -c1 -W5 {0}'.format(vm_rx.ip_address), code=0)
                        self.log.debug('Was able to ping VM after revoking rules after elapsed: '
                                       '{0}/{1}'.format(elapsed, timeout))
                        time.sleep(5)
                    except CommandExitCodeException:
                        good = True
                        break
                    except (SSHException, RuntimeError) as SE:
                        self.log.warning('{0}\nCaught SSH Error:"{1}"'.format(get_traceback(), SE))
                        vm_tx.show_enis()
                        elapsed = int(time.time() - start)
                        if elapsed > timeout:
                            raise SE
                if not good:
                    raise RuntimeError('Security group rules were not applied after {0} seconds'
                                       .format(elapsed))

                new_test_status('Test scenario NEGATIVE Primary ENIs same group same subnet private IP')
                try:
                    results = run_tests(vm_tx, vm_rx, vm_rx.private_ip_address, expected=0)
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E

                new_test_status('Test scenario NEGATIVE Primary ENIs same group same subnet public IP')
                try:
                    results = run_tests(vm_tx, vm_rx, vm_rx.ip_address, expected=0)
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E

                new_test_status('Test scenario NEGATIVE Secondary ENIs same group same subnet private IP')
                try:
                    vm_rx.attach_eni(eni2_s1_g1)
                    vm_rx.sync_enis_static_ip_config()
                    results = run_tests(vm_tx, vm_rx, eni2_s1_g1.private_ip_address, expected=0)
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E
                finally:
                    vm_rx.detach_eni(eni2_s1_g1, ignore_missing=True)

                new_test_status('Test scenario NEGATIVE Secondary ENI different group same subnet private '
                       'IP')
                try:
                    vm_rx.attach_eni(eni3_s1_g2)
                    vm_rx.sync_enis_static_ip_config()
                    results = run_tests(vm_tx, vm_rx, eni3_s1_g2.private_ip_address, expected=0)
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E
                finally:
                    vm_rx.detach_eni(eni3_s1_g2, ignore_missing=True)

                new_test_status('Test scenario NEGATIVE Secondary ENIs same group different subnet private '
                       'IP')
                try:
                    vm_rx.attach_eni(eni5_s2_g1)
                    vm_rx.sync_enis_static_ip_config()
                    results = run_tests(vm_tx, vm_rx, eni5_s2_g1.private_ip_address, expected=0)
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E
                finally:
                    vm_rx.detach_eni(eni5_s2_g1, ignore_missing=True)

                new_test_status('Test scenario NEGATIVE Secondary ENIs different group different subnet '
                       'private IP')
                try:
                    vm_rx.attach_eni(eni4_s2_g2)
                    vm_rx.sync_enis_static_ip_config()
                    results = run_tests(vm_tx, vm_rx, eni4_s2_g2.private_ip_address, expected=0)
                    for protocol, res_dict in results.iteritems():
                        if not res_dict.get('passed'):
                            test_errors.append("{0}, {1}:{2}".format(self.current_test_scenario,
                                                                     protocol,
                                                                     res_dict.get('passed')))
                except Exception as E:
                    err = "{0}\nERROR during:'{1}', Error:{2}".format(get_traceback(),
                                                                      self.last_status_msg, E)
                    err += '\nIN TEST: "{0}"'.format(self.current_test_scenario)
                    self.log.error(red(err))
                    failed_scenarios.append("{0}, ERROR:{1}".format(self.current_test_scenario, E))
                    test_scenario_summary[self.current_test_scenario]['result'] = red('FAIL')
                    if stop_on_fail:
                        raise E
                finally:
                    vm_rx.detach_eni(eni4_s2_g2, ignore_missing=True)

            status('Done with Packet tests for zone:{0}'.format(zone))
        except Exception as SE:
            self.log.error(red('{0}\nEXITING. FATAL ERROR IN TEST:"{1}"'
                               .format(get_traceback(), SE)))
            self.log.info(red('Last status message before failure:"{0}"'
                              .format(self.last_status_msg)))
            raise SE
        finally:
            self.log.info('Last Test Results:')
            show_scenario_summary()
            if verbose:
                for table in tables:
                    self.log.info("\n{0}\n".format(table))
            if clean:
                self.status('Last Status msg:"{0}"\n Last Test '
                            'Message:"{1}"\nBeginning test cleanup... '
                            .format(self.last_status_msg, self.current_test_scenario))
                self.restore_vm_types()
                for vm in instances:
                    try:
                        vm.terminate_and_verify()
                    except Exception as E:
                        self.log.debug('{0}\nError:{1}'.format(get_traceback(), E))
                for subnet in subnets:
                    self.status(
                        'Attempting to delete subnet and dependency artifacts from this test')
                    user.ec2.delete_subnet_and_dependency_artifacts(subnet)
            show_scenario_summary()
            if test_errors or failed_scenarios:
                errmsg = ""
                if test_errors:
                    errmsg = red('{0}/{1} FAILED PACKET TESTS:"{2}"'
                                 .format(len(test_errors), self.test_count,
                                         "\n".join(test_errors)))
                if failed_scenarios:
                    errmsg += red('\n"{0}" FAILED TEST SCENARIOS (ie errors outside packet '
                                  'tests):\n{1}'
                                  .format(len(failed_scenarios), "\n".join(failed_scenarios)))
                self.log.error(errmsg)
                raise RuntimeError(errmsg)
            else:
                self.status('PACKET TEST PASSED')
        return tables

    def test6q0_eni_attach_detach_ping_multiple_enis_subnets_groups(self, ping=False, clean=None):
        """
        Attempts to attach and quickly detach several ENIs to a single VM in each zone verifying
        the private IP of each ENI with PING from a 2nd VM with ENIs in each subnet of the VM
        under test.
        The test will repeat the following attach, detach sequence 3 times each time with a
        different ENI.
        Upon attach the test will wait for the ENI(s) and Instance to report the correct attached state, as well
        as check the guest and wait for the guest device to appear.
        Upon detach the test will wait for the ENI(s) and Instance to report the correct detached
        state, as well as wait for the guest device to be removed.
        {yaml}
        tags:
          - 'ec2'
          - 'eni'
          - 'security group'
          - 'sctp'
          - 'udp'
          - 'tcp'
          - 'icmp'
          - 'subnet'
        {yaml}
        """

        if clean is None:
            clean = not self.args.no_clean
        user = self.user
        vpc = self.test6b0_get_vpc_for_eni_tests()
        status = self.status
        instances = []
        subnets = []
        test_rules = [('tcp', 22, 22, '0.0.0.0/0'), ('icmp', -1, -1, '0.0.0.0/0')]
        test_rules.append(('tcp', 100, 100, '0.0.0.0/0'))
        test_rules.append(('icmp', -1, -1, '0.0.0.0/0'))
        test_rules.append(('udp', 100, 100, '0.0.0.0/0'))
        test_rules.append((132, 22, 22, '0.0.0.0/0'))
        primary_group = self.get_test_security_groups(vpc=vpc, rules=test_rules, count=1,
                                                      user=user)[0]
        group1 = self.get_test_security_groups(vpc=vpc, count=1, rules=test_rules, user=user)[0]
        group2 = self.get_test_security_groups(vpc=vpc, count=1, rules=test_rules, user=user)[0]

        try:
            status('Modifying instance type m1.small to allow for more ENIs...')
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                primary_sub, subnet1, subnet2 = self.get_non_default_test_subnets_for_vpc(
                    vpc=vpc, user=user, zone=zone, count=3)
                subnets += [primary_sub, subnet1, subnet2]
                eni1, eni1b = self.get_test_enis_for_subnet(subnet=subnet1, user=user,
                                                     apply_groups=group1, count=2)
                eni2, eni2b = self.get_test_enis_for_subnet(subnet=subnet2, user=user,
                                                     apply_groups=group2, count=2)
                status('Creating VM in zone:{0} for this test...'.format(zone))
                vm1, vm2 = self.get_test_instances(zone=zone, group_id=primary_group.id,
                                                   vpc_id=vpc.id, subnet_id=primary_sub.id,
                                                   instance_type='m1.small', count=2)
                for eni in [eni1b, eni2b]:
                    vm2.attach_eni(eni)
                    user.ec2.modify_network_interface_attributes(eni, source_dest_check=False)
                vm2.sync_enis_static_ip_config()
                instances += [vm1, vm2]
                enis = [eni1, eni2]
                for eni in enis:
                    user.ec2.modify_network_interface_attributes(eni, source_dest_check=False)
                    status('Test#:{0}/{1},Attempting quick attach and detach of eni:{2} to {3}'
                           .format(enis.index(eni), len(enis), eni.id, vm1.id))
                    vm1.attach_eni(eni=eni)
                    status('Syncing IP info for {0}'.format(vm1.id))
                    vm1.sync_enis_static_ip_config()
                    if ping:
                        status('Pinging eni:{0} private_ip:{1} on {2} from {3}'
                               .format(eni.id, eni.private_ip_address, vm1.id, vm2.id))
                        vm2.sys('ping -c2 -W5 {0}'.format(eni.private_ip_address))
                    status('Detaching ENI:{0} from {1}'.format(eni.id, vm1.id))
                    vm1.detach_eni(eni=eni)
        except Exception as SE:
            self.log.error(red('{0}\nERROR DURING QUICK ATTACH/DETACH TEST:"{1}"'
                               .format(get_traceback(), SE)))
            raise
        finally:
            if clean:
                self.status('Beginning test cleanup. Last Status msg:"{0}"...'
                            .format(self.last_status_msg))
                self.restore_vm_types()
                for vm in instances:
                    try:
                        vm.terminate_and_verify()
                    except Exception as E:
                        self.log.debug('{0}\nError:{1}'.format(get_traceback(), E))
                for subnet in subnets:
                    self.status(
                        'Attempting to delete subnet and dependency artifacts from this test')
                    user.ec2.delete_subnet_and_dependency_artifacts(subnet)


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
    # NAT Gateway tests
    ###############################################################################################
    def test8b0_get_vpc_for_nat_gw_tests(self):
        """
        Finds an existing VPC
        """
        test_vpc = self.user.ec2.get_all_vpcs(filters={'tag-key': self.NAT_GW_TEST_TAG,
                                                       'tag-value': self.test_id})
        if not test_vpc:
            test_vpc = self.create_test_vpcs()
            if not test_vpc:
                raise RuntimeError('Failed to create test VPC for nat gw tests?')
            test_vpc = test_vpc[0]
            self.user.ec2.create_tags([test_vpc.id], {self.NAT_GW_TEST_TAG: self.test_id})
        else:
            test_vpc = test_vpc[0]
        return test_vpc

    def test8d0_nat_gw_basic_creation_and_attribute_check(self, clean=None):
        """
        When a NAT gateway is created, it receives an elastic network interface that's
        automatically assigned a private IP address from the IP address range of your subnet.
        This test verfiies the following:
        - A Nat GW can be created within a subnet
        - The GW can be described using the available request filters
        - An ENI is properly assigned to that NAT GW
        - The ENI can described using the available request filters
        - An Elastic public ip can be associated with the NATGW upon creation
        - The ENI and EIP attributes can be described using available request filters
        - Checks the subnet and vpc in the request to that in the describe natgw response
        - Attempts to use the filters for NATGW ID, STATE, SUBNET, and VPC to fetch the NATGW

        """
        if clean is None:
            clean = not self.args.no_clean
        user = self.user
        vpc = self.test8b0_get_vpc_for_nat_gw_tests()
        subnets = []
        eips = []
        gws = []

        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet = self.create_test_subnets(vpc=vpc, zones=[zone], user=user)[0]
                subnets.append(subnet)
                eip = user.ec2.allocate_address()
                self.store_addr(user, eip)
                eips.append(eip)
                self.status('Creating the NATGW with EIP:{0}'.format(eip.public_ip))
                natgw = user.ec2.create_nat_gateway(subnet, eip_allocation=eip.allocation_id)
                gwid = natgw.get('NatGatewayId')
                gws.append(gwid)
                self.status('Created NatGateway:{0}'.format(gwid))
                gw_enis = []
                for addr in natgw.get('NatGatewayAddresses'):
                    gw_enis.append(addr.get('NetworkInterfaceId'))

                for filter in [{'attachment.nat-gateway-id': gwid},
                               {'addresses.association.public-ip':
                                    natgw.get('NatGatewayAddresses')[0].get('PublicIp')}]:

                    enis = user.ec2.connection.get_all_network_interfaces(filters=filter) or []
                    enis = [x.id for x in enis]
                    if enis:
                        if len(enis) != len(gw_enis):
                            raise ValueError('Filter:"{0}" returned more than {1} ENI: "{2}"'
                                             .format(filter, len(gw_enis),
                                                     ",".join([x.id for x in enis])))
                        else:
                            for eni in enis:
                                if eni in gw_enis:
                                    self.status('PASS: Filter:"{0}" returned attached ENI:{1}'
                                                .format(filter, eni))
                                else:
                                    raise ValueError('Filter:"{0}" returned ENI:{1} that is not '
                                                     'part of GW:{2}'.format(filter, eni, gwid))
                    else:
                        raise ValueError('Filter:"{0} did not return ENIs:"{1}" for NATGW:{2}'
                                         .format(filter, ",".join([x for x in gw_enis]), gwid))
                if subnet.id != natgw.get('SubnetId'):
                    raise  ValueError('Nat GW subnetid:{0} != subnet in request:{1}'
                                      .format(natgw.get('SubnetId'), subnet.id))
                if subnet.vpc_id != natgw.get('VpcId'):
                    raise  ValueError('Nat GW vpc_id:{0} doesnt equal requested subnet:{1} and '
                                      'vpc{2}'.format(natgw.get('VpcId'),
                                                      subnet.id, subnet.vpc_id))
                self.status('Attempt to fetch the NATGW with filters for id, state, vpc, '
                            'and subnet...')
                gws = user.ec2.get_nat_gateways(gwid, state=natgw.get('State'),
                                               vpc=natgw.get('VpcId'),
                                               subnet=natgw.get('SubnetId')) or []
                if len(gws) != 1:
                    raise ValueError('Expected "1" NatGw with filters: id:{0}, state:{1}, '
                                     'vpc:{2}, subnet:{3}. Got:"{4}"'
                                     .format(gwid, natgw.get('State'), natgw.get('VpcId'),
                                             natgw.get('SubnetId')))
                gw = gws[0]
                if gwid != gw.get('NatGatewayId'):
                    raise ValueError('Describe NATGWs with filters for id, state, subnet and vpc '
                                     'failed to return the newly created natgw:{0}'.format(gwid))

        except Exception as E:
            self.log.error(red('{0}\nError during nat_gw_basic_creation_and_attribute_checks:{1}'
                               .format(get_traceback(), E)))
            raise E
        finally:
            self.status('Beginning test cleanup. Last Status msg:"{0}"...'
                        .format(self.last_status_msg))
            if clean:
                for subnet in subnets:
                    self.status('Attempting to delete subnet and dependency artifacts from '
                                'this test')
                    user.ec2.delete_subnet_and_dependency_artifacts(subnet)
                for eip in eips:
                    eip.delete()
        self.status('test complete')

    def test8e0_nat_gw_create_gw_with_in_use_eip(self, clean=None):
        """
        Attempt to create a NAT GW with an elastic IP which is already associated to a VM. This
        should not be allowed.
        """
        if clean is None:
            clean = not self.args.no_clean
        user = self.user
        vpc = self.test8b0_get_vpc_for_nat_gw_tests()
        subnets = []
        eips = []
        gws = []

        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet = self.create_test_subnets(vpc=vpc, zones=[zone], user=user)[0]
                subnets.append(subnet)
                eip = user.ec2.allocate_address()
                self.store_addr(user, eip)
                eips.append(eip)
                self.status('Creating the NATGW with EIP:{0}'.format(eip.public_ip))
                natgw = user.ec2.create_nat_gateway(subnet, eip_allocation=eip.allocation_id)
                gwid = natgw.get('NatGatewayId')
                gws.append(gwid)
                user.ec2.show_nat_gateways(natgw)
                self.status('Created First NatGateway:{0}'.format(gwid))
                try:
                    self.status('Attempting to create a 2nd NATGW with the same EIP, '
                                'this should fail...')
                    natgw = user.ec2.create_nat_gateway(subnet, eip_allocation=eip.allocation_id,
                                                        desired_state='failed',
                                                        failed_states=['available', 'deleting',
                                                                       'deleted'])
                    user.ec2.show_nat_gateways([natgw])
                    if natgw:
                        if not 'FailureMessage' in natgw:
                            errmsg = red('NatGW failed with dup EIP but did not contain '
                                     'FailureMessage attr?')
                            self.log.error(errmsg)
                            self.log.error(natgw)
                            gw_id = None
                            if isinstance(natgw, dict):
                                gw_id = natgw.get('NatGatewayId', None)
                                for key, value in natgw.iteritems():
                                    self.log.error(red("{0} -> {1}".format(key, value)))
                            raise ValueError('NatGW id:{0}, failed with dup EIP but did not contain '
                                             'FailureMessage attr?'.format(gw_id))
                        if not re.search('already associated', natgw.get('FailureMessage')):
                            raise ValueError('NatGW:{0} Failure message did not contain '
                                             'expected text, got:"{1}"'
                                             .format(gwid, natgw.get('FailureMessage')))
                        else:
                            self.status('PASS: Failed to create NATGW with EIP that was in-use')
                    else:
                        raise ValueError('Create Failed as expected but did not return '
                                         'failed NATGW obj in response')
                except Exception as E:
                    self.log.error(red('{0}\nGOT UNEXPECTED ERROR  - creating an NATGW with an in-use '
                                   'EIP should return the gw in pending or failed status '
                                   'w/o error in the response. ERR:{1}'
                                       .format(get_traceback(), E)))
                    raise E
                self.status('Test completed successfully for all zones')
        except Exception as E:
            self.log.error(red('{0}\nError during test:{1}'
                               .format(get_traceback(), E)))
            raise E
        finally:
            self.status('Beginning test cleanup. Last Status msg:"{0}"...'
                        .format(self.last_status_msg))
            if clean:
                for subnet in subnets:
                    self.status('Attempting to delete subnet and dependency artifacts from '
                                'this test')
                    user.ec2.delete_subnet_and_dependency_artifacts(subnet)
                for eip in eips:
                    eip.delete()
        self.status('test complete')

    def test8e1_nat_gw_eip_association_negative_tests(self, clean=None):
        """
        You can associate exactly one Elastic IP address with a NAT gateway.
        You cannot disassociate an Elastic IP address from a NAT gateway after it's created.
        If you need to use a different Elastic IP address for your NAT gateway,
        you must create a new NAT gateway with the required address, update your route tables,
        and then delete the existing NAT gateway if it's no longer required.
        Test Attempts:
        - Creates a NAT GW in each zone
        - Attempts to delete the associated EIP
        - Attempts to dis-associate the EIP
        """
        if clean is None:
            clean = not self.args.no_clean
        user = self.user
        vpc = self.test8b0_get_vpc_for_nat_gw_tests()
        subnets = []
        eips = []
        gws = []

        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet = self.create_test_subnets(vpc=vpc, zones=[zone], user=user)[0]
                subnets.append(subnet)
                eip = user.ec2.allocate_address()
                eips.append(eip)
                self.status('Creating the NATGW with EIP:{0}'.format(eip.public_ip))
                natgw = user.ec2.create_nat_gateway(subnet, eip_allocation=eip.allocation_id)
                gwid = natgw.get('NatGatewayId')
                gws.append(gwid)
                user.ec2.show_nat_gateways(natgw)
                self.status('Created NatGateway:{0}'.format(gwid))
                for action in [eip.delete, eip.disassociate]:
                    try:
                        action_name = action.__func__.__name__
                        action()
                    except EC2ResponseError as EE:
                        if EE.status == 400 and EE.reason == 'InvalidIPAddress.InUse':
                            self.status('Got correct error for NATGW IN-USE EIP {0} attempt'
                                        .format(action_name))
                        else:
                            self.status('Attempting to {0} an EIP in use by natgw, got error but '
                                        'not the expected one:"{1}"'.format(action_name, EE))
                    else:
                        raise RuntimeError('Test was able to {0} an EIP:{1} in use by:{2}'
                                           .format(action_name, eip.id, gwid))
            self.status('Test Completed Successfully for all zones')
        except Exception as E:
            self.log.error(red('{0}\nError during test:{1}'
                               .format(get_traceback(), E)))
            raise E
        finally:
            self.status('Beginning test cleanup. Last Status msg:"{0}"...'
                        .format(self.last_status_msg))
            if clean:
                for subnet in subnets:
                    self.status('Attempting to delete subnet and dependency artifacts from '
                                'this test')
                    user.ec2.delete_subnet_and_dependency_artifacts(subnet)
                for eip in eips:
                    eip.delete()
        self.status('test and cleanup complete')

    def test8s0_nat_gw_basic_packet_type_tests(self, host_machine=None,
                                                                  non_nat_host=None, clean=None):
        """
        A NAT gateway supports the following protocols: TCP, UDP, and ICMP.
        The instances in the public subnet can receive inbound traffic directly from the
        Internet, whereas the instances in the private subnet can't. The instances in the
        public subnet can send outbound traffic directly to the Internet, whereas the instances
        in the private subnet can't. Instead, the instances in the private subnet can access
        the Internet by using a network address translation (NAT) gateway that resides in
        the public subnet.
        - Create a subnet, route table, and NAT GW per zone
        - Create a default route through an associated Internet Gateway and a specific route to a
          a remote test host through the NAT GW. This host defaults to the UFS machine.
        - Creates a VM within the subnet and runs several packet tests using ICMP, TCP and UDP.
        - The source address of packets from the VM are verified to be the NAT GW's public ip
        - The source address of packets from the remote host are verified to be it's own.
        - The source address of packets sent from the VM to hosts not routed to through the NATGW
          are verified to the VM's own IP.
        - Remove the route via NATGW test that packets are relieved at the previously nat'd
          destination with the VM's public IP as the source address.
        """
        self.status('Starting nat gw basic packet type tests... ')
        if clean is None:
            clean = not self.args.no_clean
        user = self.user
        vpc = self.test8b0_get_vpc_for_nat_gw_tests()
        subnets = []
        eips = []
        gws = []
        natd_host = host_machine or self.tc.sysadmin.get_hosts_for_ufs()[0]
        no_nat = non_nat_host
        if not no_nat:
            clc = self.tc.sysadmin.clc_machine
            if clc.hostname != natd_host.hostname:
                no_nat = clc
            else:
                nc = self.tc.sysadmin.get_hosts_for_node_controllers()[0]
                if nc.hostname != natd_host.hostname:
                    no_nat = nc
                else:
                    self.log.warning('A separate host for the no NAT GW case could not be found, '
                                     'and none were provided to this test. These tests will '
                                     'be skipped')
        self.status('Test will be using remote hosts: nat\'d traffic host:{0}, non-nat host:{1}'
                    .format(natd_host, no_nat))
        group = self.get_test_security_groups(vpc=vpc, rules=[('tcp', 22, 22, '0.0.0.0/0'),
                                                              ('tcp', 100, 101, '0.0.0.0/0'),
                                                              ('icmp', -1, -1, '0.0.0.0/0'),
                                                              ('udp', 100, 101, '0.0.0.0/0')])[0]
        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                subnet = self.create_test_subnets(vpc=vpc, zones=[zone], user=user,
                                                  count_per_zone=1)[0]
                subnets.append(subnet)
                rt = user.ec2.connection.create_route_table(subnet.vpc_id)
                user.ec2.connection.associate_route_table(rt.id, subnet.id)
                igw = user.ec2.connection.get_all_internet_gateways(
                    filters={'attachment.vpc-id': vpc.id})
                if igw:
                    igw = igw[0]
                else:
                    igw = user.ec2.connection.create_internet_gateway()
                    user.ec2.connection.attach_internet_gateway(igw.id, vpc.id)
                igwroute = user.ec2.create_route(rt.id, '0.0.0.0/0', gateway_id=igw.id)
                if not igwroute:
                    raise RuntimeError('Failed to created route to host:{0} via "{1}"'
                                       .format('0.0.0.0/0', igw.id))
                eip = user.ec2.allocate_address()
                self.store_addr(user, eip)
                eips.append(eip)
                self.status('Creating the NATGW with EIP:{0}'.format(eip.public_ip))
                natgw = user.ec2.create_nat_gateway(subnet, eip_allocation=eip.allocation_id)
                gwid = natgw.get('NatGatewayId')
                gw_ips = ",".join([x.get('PublicIp') for x in natgw.get('NatGatewayAddresses')])
                gws.append(gwid)
                user.ec2.show_nat_gateways(natgw)
                self.status('Created First NatGateway:{0}'.format(gwid))
                self.status('Adding route to testhost:{0} through natgway:{1}'
                            .format(natd_host.hostname, gwid))
                route = user.ec2.create_route(rt.id, natd_host.hostname + "/32", natgateway_id=gwid)
                if not route:
                    raise RuntimeError('Failed to created route to host:{0} via "{1}"'
                                       .format(host.hostname + "/32", gwid))
                user.ec2.show_route_table(rt.id)
                self.status('Launching test VMs...')
                vm = self.get_test_instances(zone='one', group_id=group.id, vpc_id=vpc.id,
                                                 subnet_id=subnet.id, count=1,
                                                 private_addressing=False)[0]

                ################# VM to REMOTE HOST THROUGH NAT GW - TESTS ##################
                host = natd_host
                self.status('Starting NAT GW packet tests between VM:{0} and remote host:{1}'
                            .format(vm.id, host.hostname))
                self.status('Natd destination. Attempting VM:{0}:private{1}:public:{2} -- '
                            'ICMP -> {3}'
                            .format(vm.id, vm.private_ip_address, vm.ip_address, host.hostname))
                packet_test(vm.ssh, host.ssh, protocol=1, count=2, dest_ip=host.hostname,
                            src_addrs=gw_ips, verbose=True)
                self.status('VM to host NATGW ICMP test passed')

                self.status('Natd destination. Attempting VM:{0}:private{1}:public:{2} -- '
                            'UDP port 100 -> {3}'
                            .format(vm.id, vm.private_ip_address, vm.ip_address, host.hostname))
                packet_test(vm.ssh, host.ssh, protocol=17, count=2, dest_ip=host.hostname,
                            bind=True, port=100, src_addrs=gw_ips, verbose=True)
                self.status('VM to host NATGW UDP test passed')

                self.status('Natd destination. Attempting VM:{0}:private{1}:public:{2} -- '
                            'TCP port 101 -> {3}'
                            .format(vm.id, vm.private_ip_address, vm.ip_address, host.hostname))
                packet_test(vm.ssh, host.ssh, protocol=6, count=2, dest_ip=host.hostname,
                            bind=True, port=101, src_addrs=gw_ips, verbose=True)
                self.status('VM to host NATGW TCP test passed')

                ################# REMOTE HOST TO VM - TESTS ###################################
                ### Skip TCP, TCP may not work in this scenario due to asymmetric path?

                self.status('Remost host to VM. Attempting reverse direction VM:{0}:private{1}:'
                            'public:{2} <--ICMP '
                            '-- {3}'.format(vm.id, vm.private_ip_address,
                                                   vm.ip_address, host.hostname))
                packet_test(host.ssh, vm.ssh, protocol=1, count=2, dest_ip=vm.ip_address,
                            verbose=True)
                self.status('HOST to VM NATGW ICMP test passed')

                self.status('Remost host to VM. Attempting reverse direction VM:{0}:private{1}:'
                            'public:{2} <--UDP '
                            'port100 -- {3}'.format(vm.id, vm.private_ip_address,
                                                   vm.ip_address, host.hostname))
                packet_test(host.ssh, vm.ssh, protocol=17, count=2, dest_ip=vm.ip_address,
                            bind=True, port=100, verbose=True)
                self.status('HOST to VM NATGW UDP test passed')



                ################# VM to REMOTE HOST 'NOT' THROUGH NAT GW - TESTS #############
                if no_nat:
                    host = no_nat
                    vm_ip = vm.ip_address
                    self.status('Starting non-NAT GW packet tests between VM:{0} and remote '
                                'host:{1}'.format(vm.id, host.hostname))

                    self.status('Non natd destination. Attempting VM:{0}:private{1}:public:'
                                '{2} -- ICMP -> {3}'
                                .format(vm.id, vm.private_ip_address, vm.ip_address,
                                        host.hostname))
                    packet_test(vm.ssh, host.ssh, protocol=1, count=2, dest_ip=host.hostname,
                                src_addrs=vm_ip, verbose=True)
                    self.status('VM to host NATGW ICMP test passed')

                    self.status('Non natd destination. Attempting VM:{0}:private{1}:public:'
                                '{2} -- UDP port 100 -> {3}'
                                .format(vm.id, vm.private_ip_address, vm.ip_address,
                                        host.hostname))
                    packet_test(vm.ssh, host.ssh, protocol=17, count=2, dest_ip=host.hostname,
                                bind=True,
                                port=100, src_addrs=vm_ip, verbose=True)
                    self.status('VM to host NATGW UDP test passed')

                    self.status('Non natd destination. Attempting VM:{0}:private{1}:public:'
                                '{2} --TCP port 101 -> {3}'
                                .format(vm.id, vm.private_ip_address, vm.ip_address,
                                        host.hostname))
                    packet_test(vm.ssh, host.ssh, protocol=6, count=2, dest_ip=host.hostname,
                                bind=True, port=101, src_addrs=vm_ip, verbose=True)
                    self.status('VM to host NATGW TCP test passed')
                else:
                    self.log.warning('Skipping the "No NAT Gateway" cases because no 2nd host was '
                                     'found or provided')
                # Test after deleting the route via the NAT GW...
                self.status('Deleting the NAT GW route and re-testing each packet type...')
                user.ec2.connection.delete_route(rt.id, natd_host.hostname + "/32")
                host = natd_host
                elapsed = 0
                start = time.time()
                attempt = 0
                timeout = 40
                good = False
                TE = None
                while not good and elapsed < timeout:
                    attempt += 1
                    elapsed = int(time.time() - start)
                    try:
                        self.status('Starting IGW packet tests between VM:{0} and remote host:{1}, '
                                    'attempt:{2}, elapsed:{3}/{4}'
                                    .format(vm.id, host.hostname, attempt, elapsed, timeout))
                        self.status('Post nat route deletion. Attempting VM:{0}:private{1}:'
                                    'public:{2} -- ICMP -> {3}'
                                    .format(vm.id, vm.private_ip_address, vm.ip_address,
                                            host.hostname))
                        packet_test(vm.ssh, host.ssh, protocol=1, count=2, dest_ip=host.hostname,
                                    src_addrs=vm.ip_address, verbose=True)
                        self.status('VM to host IGW ICMP test passed')

                        self.status('Post nat route deletion. Attempting VM:{0}:private{1}:'
                                    'public:{2} -- UDP port 100 -> {3}'
                                    .format(vm.id, vm.private_ip_address, vm.ip_address,
                                            host.hostname))
                        packet_test(vm.ssh, host.ssh, protocol=17, count=2, dest_ip=host.hostname,
                                    bind=True, port=100, src_addrs=vm.ip_address, verbose=True)
                        self.status('VM to host IGW UDP test passed')

                        self.status('Post nat route deletion. Attempting VM:{0}:private{1}:'
                                    'public:{2} --TCP port 101 -> {3}'
                                    .format(vm.id, vm.private_ip_address, vm.ip_address,
                                            host.hostname))
                        packet_test(vm.ssh, host.ssh, protocol=6, count=2, dest_ip=host.hostname,
                                    bind=True, port=101, src_addrs=vm.ip_address, verbose=True)
                        self.status('VM to host IGW TCP test passed')
                        good = True
                    except Exception as TE:
                        self.log.debug('Failed attempt IGW packet tests between VM:{0} and remote '
                                       'host:{1}, attempt:{2}, elapsed:{3}/{4}. Error:{5}'
                                       .format(vm.id, host.hostname, attempt, elapsed, timeout,
                                               TE))
                        if elapsed < timeout:
                            time.sleep(5)
                if not good:
                    if TE:
                        raise TE
                    else:
                        raise RuntimeError('Failed packet tests after removing NATGW route, '
                                           'but no error? Check the test?')


                self.status('All NATGW packet tests for zone:{0} are complete'.format(zone))

        except Exception as E:
            self.log.error('LAST STATUS BEFORE FAILURE:"{0}"'.format(self.last_status_msg))
            self.log.error(red('{0}\nError during test:{1}'
                               .format(get_traceback(), E)))
            raise E
        finally:
            self.status('Beginning test cleanup. Last Status msg:"{0}"...'
                        .format(self.last_status_msg))
            if clean:
                for subnet in subnets:
                    self.status('Attempting to delete subnet and dependency artifacts from '
                                'this test')
                    user.ec2.delete_subnet_and_dependency_artifacts(subnet)
                for eip in eips:
                    eip.delete()
        self.status('test and cleanup complete')


    def test8x0_nat_gw_max_gw_per_zone_limit(self, clean=None):
        """
        Test the eucalyptus property:cloud.vpc.natgatewaysperavailabilityzone
        For All Zones...
        - Confirm the limit can be reached
        - Confirm the limit can not not be exceeded, and proper errors are returned
        - Confirm that when NATGWs are deleted they can be replaced up to limit amount
        """

        prop = self.tc.sysadmin.get_property('cloud.vpc.natgatewaysperavailabilityzone')
        prop.show()
        proplimit = int(prop.value)
        if clean is None:
            clean = not self.args.no_clean
        user = self.user
        vpc = self.test8b0_get_vpc_for_nat_gw_tests()
        subnets = []
        eips = []
        try:
            self.modify_vm_type_store_orig('m1.small', network_interfaces=3)
            for zone in self.zones:
                limit = proplimit
                gws = []
                subnet = self.create_test_subnets(vpc=vpc, zones=[zone], user=user)[0]
                subnets.append(subnet)
                # Subtract GWs which already exist in this zone...
                existing_gws = user.ec2.get_nat_gateways(state='available', zone=zone)

                limit = proplimit - len(existing_gws)
                user.ec2.show_nat_gateways(existing_gws)

                for x in xrange(1, limit + 1):
                    eip = user.ec2.allocate_address()
                    self.store_addr(user, eip)
                    eips.append(eip)
                    self.status('Creating the NATGW with EIP:{0}'.format(eip.public_ip))
                    natgw = user.ec2.create_nat_gateway(subnet, eip_allocation=eip.allocation_id,
                                                        desired_state='available')
                    gwid = natgw.get('NatGatewayId')
                    gws.append(gwid)
                    user.ec2.show_nat_gateways(natgw)
                    self.status('Created NatGateway #{0}/{1}, {2}'.format(x, limit, gwid))

                if x != limit:
                    raise ValueError('Test did not create the correct number of '
                                     'NATGWs:{0} != prop:{1} for zone:{2}'.format(x, limit, zone))
                gws = user.ec2.get_nat_gateways(state='available', zone=zone)
                user.ec2.show_nat_gateways(gws)
                if len(gws) != limit:
                    raise ValueError('Fetched GWs {0} != limit set by property:{1}'
                                     .format(len(gws), limit))
                else:
                    self.status('PASS: Could create {0} NATGWs in Zone:{1} == prop limit:{2}'
                                .format(len(gws), zone, limit))
                self.status('Attempting to exceed property value natgw limit...')
                try:
                    eip = user.ec2.allocate_address()
                    self.store_addr(user, eip)
                    eips.append(eip)
                    self.status('Creating the NATGW with EIP:{0}'.format(eip.public_ip))
                    natgw = user.ec2.create_nat_gateway(subnet, eip_allocation=eip.allocation_id)
                    gwid = natgw.get('NatGatewayId')
                    gws.append(gwid)
                    user.ec2.show_nat_gateways(natgw)
                    self.status('Created NatGateway #{0}/{1}, {2}'.format(len(gws), limit, gwid))
                except ValueError as VE:
                    if re.search('NatGatewayLimitExceeded', str(VE)):
                        self.status('PASS Natgw failed with proper fail message:"{0}"'.format(VE))
                    else:
                        raise VE
                except ClientError as CE:
                    if re.search('NatGatewayLimitExceeded', CE.message):
                        self.status('PASS Natgw failed with proper fail message:"{0}"'.format(CE))
                    else:
                        raise CE
                self.status('PASS: Was not able to exceed NATGWs:{0} per zone:{1}'
                            .format(limit, zone))
                self.status('Deleting a NATGW and attempting to replace it...')
                try:
                    gw = gws.pop()
                    user.ec2.delete_nat_gateways(gw)
                    time.sleep(2)
                    eip = user.ec2.allocate_address()
                    self.store_addr(user, eip)
                    eips.append(eip)
                    self.status('Creating the NATGW with EIP:{0}'.format(eip.public_ip))
                    natgw = user.ec2.create_nat_gateway(subnet, eip_allocation=eip.allocation_id)
                    gwid = natgw.get('NatGatewayId')
                    gws.append(gwid)
                    user.ec2.show_nat_gateways(natgw)
                    self.status('Created NatGateway #{0}/{1}, {2}'.format(x, limit, gwid))
                except Exception as E:
                    self.log.error("{0}\nFailed to create replacement NATGW within property "
                                   "limit:{1}".format(get_traceback(), limit))
                    raise E
                self.status('All prop limit tests passed for zone:{0}'.format(zone))
            self.status('Prop limit tests complete for all zones')
        except Exception as E:
            self.log.error(red('{0}\nError during test:{1}'
                               .format(get_traceback(), E)))
            raise E
        finally:
            self.status('Beginning test cleanup. Last Status msg:"{0}"...'
                        .format(self.last_status_msg))
            if clean:
                for subnet in subnets:
                    self.status('Attempting to delete subnet and dependency artifacts from '
                                'this test')
                    user.ec2.delete_subnet_and_dependency_artifacts(subnet)
                for eip in eips:
                    eip.delete()
        self.status('Test and test cleanup complete')

    def test8z0_test_clean_up_nat_gw_test_vpc_dependencies(self):
        """
        Delete the VPC and dependency artifacts created for the security group testing.
        """
        if not self.args.no_clean:
            user = self.user
            vpc = self.test8b0_get_vpc_for_nat_gw_tests()
            if vpc:
                user.ec2.delete_vpc_and_dependency_artifacts(vpc)


    ###############################################################################################
    # ACL tests
    """
    AWS provides two features that you can use to increase security in your VPC: security
    groups and network ACLs. Both features enable you to control the inbound and outbound
    traffic for your instances, but security groups work at the instance level, while network ACLs
    work at the subnet level.
    By design, each subnet must be associated with a network ACL. Every subnet that you create is
    automatically associated with the VPC's default network ACL. You can change the association,
    and you can change the contents of the default network ACL
    """
    ###############################################################################################
    def test10c0_net_acl_max_net_acl_per_vpc_limit(self):
        """
        Test the eucalyptus property:cloud.vpc.networkaclspervpc
        Confirm the limit can be reached and not exceeded.
        """
        raise SkipTestException('ACLs Not supported at this time')

    ###############################################################################################
    # Misc tests
    ###############################################################################################

    def clean_method(self):
        errors = []
        subnets = []
        vpcs =[]
        if not self.args.no_clean:
            try:
                keys = getattr(self, '_keypair', {}) or {}
                key = keys.get(self.user)
                if key:
                    key.delete()
            except Exception as E:
                self.log.error(red("{0}\nError#{1} deleting test keypairs:{2}"
                               .format(get_traceback(), len(errors), E)))
                errors.append('clean_method error#{0}, ERR:"{1}"'.format(len(errors), E))
            try:
                subnets = self.user.ec2.get_all_subnets(filters={'tag-key': self.my_tag_name}) or []
                vpcs = self.user.ec2.get_all_vpcs(filters={'tag-key': self.my_tag_name}) or []
            except Exception as E:
                self.log.error(red("{0}\nError#{1} fetching subnets and vpcs during clean up:{2}"
                               .format(get_traceback(), len(errors), E)))
                errors.append('clean_method error#{0}, ERR:"{1}"'.format(len(errors), E))
            for subnet in subnets:
                try:
                    self.user.ec2.delete_subnet_and_dependency_artifacts(subnet)
                except Exception as E:
                    self.log.error(red("{0}\nError#{1} during vpc clean up:{2}"
                                   .format(get_traceback(), len(errors), E)))
                    errors.append('clean_method error#{0}, ERR:"{1}"'.format(len(errors), E))
            for vpc in vpcs:
                try:
                    self.user.ec2.delete_vpc_and_dependency_artifacts(vpc)
                except Exception as E:
                    self.log.error(red("{0}\nError#{1} during vpc clean up:{2}"
                                   .format(get_traceback(), len(errors), E)))
                    errors.append('clean_method error#{0}, ERR:"{1}"'.format(len(errors), E))


            if self.new_ephemeral_user and self.new_ephemeral_user != self.user:
                subnets = []
                vpcs = []
                try:
                    keys = getattr(self, '_keypair', {}) or {}
                    key = keys.get(self.new_ephemeral_user)
                    if key:
                        key.delete()
                except Exception as E:
                    self.log.error(red("{0}\nError#{1} deleting test keypairs:{2}"
                                   .format(get_traceback(), len(errors), E)))
                    errors.append('clean_method error#{0}, ERR:"{1}"'.format(len(errors), E))
                try:
                    subnets = self.new_ephemeral_user.ec2.get_all_subnets(
                        filters={'tag-key': self.my_tag_name}) or []
                    vpcs = self.new_ephemeral_user.ec2.get_all_vpcs(filters={'tag-key':
                                                                                 self.my_tag_name})
                except Exception as E:
                    self.log.error(red("{0}\nError#{1} fetching subnets and vpcs during clean "
                                       "up:{2}".format(get_traceback(), len(errors), E)))
                    errors.append('clean_method error#{0}, ERR:"{1}"'.format(len(errors), E))
                for subnet in subnets:
                    try:
                        self.new_ephemeral_user.ec2.delete_subnet_and_dependency_artifacts(subnet)
                    except Exception as E:
                        self.log.error(red("{0}\nError#{1} during vpc clean up:{2}"
                                       .format(get_traceback(), len(errors), E)))
                        errors.append('clean_method error#{0}, ERR:"{1}"'.format(len(errors), E))
                for vpc in vpcs:
                    try:
                        self.new_ephemeral_user.ec2.delete_vpc_and_dependency_artifacts(vpc)
                    except Exception as E:
                        self.log.error(red("{0}\nError#{1} during vpc clean up:{2}"
                                       .format(get_traceback(), len(errors), E)))
                        errors.append('clean_method error#{0}, ERR:"{1}"'.format(len(errors), E))
                try:
                    self.log.debug('deleting new user account:"{0}"'
                               .format(self.new_ephemeral_user.account_name))
                    self.tc.admin.iam.delete_account(
                        account_name=self.new_ephemeral_user.account_name, recursive=True)
                except Exception as E:
                    self.log.error(red("{0}\nError#{1} during ephemeral user clean up:{2}"
                                   .format(get_traceback(), len(errors), E)))
                    errors.append('clean_method error#{0}, ERR:"{1}"'.format(len(errors), E))
            # Delete any stored addresses
            if self._test_addrs:
                for user, addrs in self._test_addrs.iteritems():
                    for addr in addrs:
                        try:
                            addr.delete()
                        except Exception as E:
                            if isinstance(E, EC2ResponseError) and E.status == 400 and \
                                            E.reason == 'InvalidAddressID.NotFound':
                                self.log.debug('Ignoring Error during addr delete:"{0}"'.format(E))
                            else:
                                self.log.error(red("{0}\nError#{1} during address clean up:{2}"
                                                   .format(get_traceback(), len(errors), E)))
                                errors.append('clean_method error#{0}, ERR:"{1}"'
                                              .format(len(errors), E))
            for groups in self._security_groups.itervalues():
                for group in groups:
                    try:
                        group.delete()
                    except Exception as E:
                        if isinstance(E, EC2ResponseError) and E.status == 400 and \
                                        E.reason == 'InvalidGroup.NotFound':
                            self.log.debug('Ignoring Error during group delete:"{0}"'.format(E))
                        else:
                            self.log.error(red("{0}\nError#{1} during group clean up:{2}"
                                               .format(get_traceback(), len(errors), E)))
                            errors.append('clean_method error#{0}, ERR:"{1}"'
                                          .format(len(errors), E))

            if errors:
                self.log.error(red("{0} Number of Errors During Cleanup:\n{1}"
                               .format(len(errors), "\n".join(str(x) for x in errors))))
                raise CleanTestResourcesException("{0} Number of Errors During Cleanup"
                                                  .format(len(errors)))


    ###############################################################################################
    #  Packet tests
    ###############################################################################################



if __name__ == "__main__":
    testcase = VpcSuite()
    # Create a single testcase to wrap and run the image creation tasks.
    result = testcase.run()
    if result:
        testcase.log.error('TEST FAILED WITH RESULT:{0}'.format(result))
    else:
        testcase.status('TEST PASSED')
    exit(result)

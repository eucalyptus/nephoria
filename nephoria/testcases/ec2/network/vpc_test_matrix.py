



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
from nephoria.testcase_utils.cli_test_runner import CliTestRunner
from cloud_utils.net_utils import packet_test, is_address_in_network
from cloud_utils.log_utils import markup, printinfo, get_traceback
from boto.vpc.subnet import Subnet
from boto.vpc.vpc import VPC
from boto.ec2.image import Image
from boto.ec2.group import Group
from boto.ec2.securitygroup import SecurityGroup
from random import randint
from prettytable import PrettyTable
import copy
import re
import time
from os.path import basename

ICMP = 1
TCP = 6
UDP = 17
SCTP = 132


class VpcBasics(CliTestRunner):

    _CLI_DESCRIPTION = "Test the Eucalyptus EC2 instance store image functionality."

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    DEFAULT_SG_RULES =  [('tcp', 22, 22, '0.0.0.0/0'), ('icmp', -1, -1, '0.0.0.0/0')]
    _DEFAULT_CLI_ARGS['vpc_cidr'] = {
        'args': ['--vpc-cidr'],
        'kwargs': {'help': 'Cidr network range for VPC(s) created in this test',
                   'default': "172.{0}.0.0/16"}}

    def post_init(self):
        self.test_id = randint(0, 100000)
        self.id = str(self.__class__.__name__)
        self.test_name = self.__class__.__name__
        self._zonelist = None
        self._ssh_key = None
        self._emi = None
        self._addresses = []
        self._test_vpcs = []
        self._security_groups = {}
        self.test_tag_name = '{0}_CREATED_NUMBER'.format(self.id)

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
                    self.user.ec2.get_emi(basic_image=True)
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

    def create_test_vpcs(self, count=1, gateways_per_vpc=1):
        test_vpcs = []
        for vpc_count in xrange(0, count):
            # Make the new vpc cidr net in the private range based upon the number of existing VPCs
            net_octet = 1 + (250 % len(self.user.ec2.get_all_vpcs()))
            new_vpc = self.user.ec2.create_vpc(cidr_block='172.{0}.0.0/16'.format(net_octet))
            self.user.ec2.create_tags(new_vpc.id, {self.test_tag_name: count})
            test_vpcs.append(new_vpc)
            for gw in xrange(0, gateways_per_vpc):
                gw = self.user.ec2.create_internet_gateway()
                self.user.ec2.attach_internet_gateway(internet_gateway_id=gw.id, vpc_id=new_vpc.id)
            self.user.log.info('Created the following VPC: {0}'.format(new_vpc.id))
            self.user.ec2.show_vpc(new_vpc)
        return test_vpcs



    def create_test_subnets(self, vpc, count_per_zone=1):
        """
        This method is intended to provided the convenience of returning a number of subnets per
        zone equal to the provided 'count_per_zone'. The intention is this method will
        take care of first attempting to re-use existing subnets, and creating new ones if needed
        to meet the count requested.

        :param vpc: boto VPC object
        :param count_per_zone: int, number of subnets needed per zone
        :return: list of subnets
        """
        test_subnets = []
        for x in xrange(0, count_per_zone):
            for zone in self.zones:
                # Use a /24 of the vpc's larger /16
                subnets = self.user.ec2.get_all_subnets(filters={'vpc-id': vpc.id})

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
                    subnet = self.user.ec2.create_subnet(vpc_id=vpc.id,
                                                         cidr_block=subnet_cidr,
                                                         availability_zone=zone)
                except:
                    try:
                        self.log.error('Existing subnets during create request:')
                        self.user.ec2.show_subnets(subnets, printmethod=self.log.error)
                    except:
                        pass
                    self.log.error('Failed to create subnet for vpc:{0}, cidr:{1} zone:{2}'
                                   .format(vpc.id, subnet_cidr, zone))
                    raise
                self.user.ec2.create_tags(subnet.id, {self.test_tag_name: x})
                test_subnets.append(subnet)
                self.user.log.info('Created the following SUBNET: {0}'.format(subnet.id))
                self.user.ec2.show_subnet(subnet)
        return test_subnets

    def get_test_vpcs(self, count=1):
        """
        This method is intended to provided the convenience of returning a number of VPCs equal
        to 'count'. The intention is this method will take care of first attempting to
        re-use existing VPCs, and creating new ones if needed to meet the count requested.

        :param count: number of VPCs requested
        :return: list of VPC boto objects
        """
        existing = self.user.ec2.get_all_vpcs(filters={'tag-key': self.test_tag_name})
        if len(existing) >= count:
            return existing[0:count]
        needed = count - len(existing)
        new_vpcs = self.create_test_vpcs(count=needed, gateways_per_vpc=1)
        ret_list = existing + new_vpcs
        return ret_list

    def get_test_subnets_for_vpc(self, vpc, count=1):
        """
        Fetch a given number of subnets within the provided VPC by either finding existing
        or creating new subnets to meet the count requested.
        :param vpc: boto vpc object
        :param count: number of subnets requested
        :return: list of subnets
        """
        existing = self.user.ec2.get_all_subnets(filters={'vpc-id': vpc.id,
                                                          'tag-key': self.test_tag_name})
        if len(existing) >= count:
            return  existing[0:count]
        needed = count - len(existing)
        new_subnets = self.create_test_subnets(vpc=vpc, count_per_zone=needed)
        ret_subnets = existing + new_subnets
        return ret_subnets

    def get_test_security_groups(self, vpc=None, count=1, rules=None):
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
        if rules is None:
            rules = self.DEFAULT_SG_RULES
        ret_groups = []
        vpc = vpc or self.default_vpc
        if vpc and not isinstance(vpc, basestring):
            vpc = vpc.id
        existing = self._security_groups.get(vpc, None)
        if existing is None:
            existing = []
            self._security_groups[vpc] = existing
        if len(existing) >= count:
            ret_groups =  existing[0:count]
        else:
            for x in xrange(0, count-len(existing)):
                name = "{0}_{1}_{2}".format(self.test_name,
                                            len(self._security_groups[vpc]) + 1,
                                            self.test_id)
                self._security_groups[vpc].append(
                    self.user.ec2.create_security_group(name=name, description=name, vpc_id=vpc))
            ret_groups = self._security_groups[vpc]
        for group in ret_groups:
            self.user.ec2.revoke_all_rules(group)
            for rule in rules:
                protocol, port, end_port, cidr_ip = rule
                self.user.ec2.authorize_group(group=group, port=port, end_port=end_port,
                                              protocol=protocol)
            self.user.ec2.show_security_group(group)
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
                           state='running', count=None, monitor_to_running=True):
        """
        Finds existing instances created by this test which match the criteria provided,
        or creates new ones to meet the count requested.
        returns list of instances.
        """
        instances = []
        if zone is None or group_id is None:
            raise ValueError('Must provide both zone:"{0}" and group_id:"{1}"'
                             .format(zone, group_id))
        existing_instances = []
        count = int(count or 0)
        filters = {'tag-key': self.test_name, 'tag-value': self.test_id}
        filters['availability-zone'] = zone
        if not isinstance(group_id, basestring):
            group_id = group_id.id
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
        queried_instances = self.user.ec2.get_instances(filters=filters)
        self.log.debug('queried_instances:{0}'.format(queried_instances))
        for q_instance in queried_instances:
            for instance in self.user.ec2.test_resources.get('instances'):
                if instance.id == q_instance.id:
                    existing_instances.append(instance)
        for instance in existing_instances:
            euinstance = self.user.ec2.convert_instance_to_euinstance(instance,
                                                                      keypair=self.ssh_key,
                                                                      auto_connect=False)
            euinstance.log.set_stdout_loglevel(self.args.log_level)
            instances.append(euinstance)
        self.log.debug('existing_instances:{0}'.format(existing_instances))
        if not count:
            if monitor_to_running:
                return self.user.ec2.monitor_euinstances_to_running(instances)
            return instances
        if len(instances) >= count:
            instances = instances[0:count]
            if monitor_to_running:
                return self.user.ec2.monitor_euinstances_to_running(instances)
            return instances
        else:
            needed = count - len(instances)
            if vpc_id and not subnet_id:
                vpc_filters = {'vpc-id':vpc_id}
                if zone:
                    vpc_filters['availability-zone'] = zone
                subnets = self.user.ec2.get_all_subnets(filters=vpc_filters)
                if not subnets:
                    raise ValueError('No subnet found for vpc: {0}'.format(vpc_id))
                subnet = subnets[0]
                subnet_id = subnet.id
            new_ins = self.create_test_instances(zone=zone, group=group_id,
                                                 subnet=subnet_id, count=needed,
                                                 monitor_to_running=monitor_to_running)
            instances.extend(new_ins)
            if len(instances) != count:
                raise RuntimeError('Less than the desired:{0} number of instances returned?'
                                   .format(count))
            return instances

    @printinfo
    def create_test_instances(self, emi=None, key=None, group=None, zone=None, subnet=None,
                              count=1, monitor_to_running=True, auto_connect=True, tag=True):
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
        vpc_id = None
        subnet_id = None
        subnet_obj = None
        if subnet:
            if not isinstance(subnet, Subnet):
                subnet_obj = self.user.ec2.get_subnet(subnet)
            if not subnet_obj:
                raise ValueError('Failed to retrieve subnet with id "{0}" from cloud'
                                 .format(subnet))
            vpc_id = subnet.vpc_id
            subnet_id = subnet_obj.id
        if group:
            if not isinstance(group, SecurityGroup):
                group = self.user.ec2.get_security_group(group)
        else:
            group = self.get_test_security_groups(vpc=vpc_id, count=1)[0]
        emi = emi or self.emi
        key = key or self.ssh_key
        instances = self.user.ec2.run_image(image=emi,
                                            keypair=key,
                                            group=group,
                                            zone=zone,
                                            subnet_id=subnet_id,
                                            max=count,
                                            auto_connect=auto_connect,
                                            monitor_to_running=False)
        for instance in instances:
            instance.add_tag(key=self.test_name, value=self.test_id)
        if monitor_to_running:
            return self.user.ec2.monitor_euinstances_to_running(instances=instances)
        return instances

    def test1_basic_instance_ssh_default_vpc(self, instances_per_zone=2):
        instances = []
        vpc = self.default_vpc
        sec_group = self.get_test_security_groups(vpc=vpc, count=1, rules=self.DEFAULT_RULES)[0]
        instance_count = instances_per_zone
        for zone in self.zones:
            subnet = self.user.ec2.get_default_subnets(zone=zone) or None
            if subnet:
                subnet = subnet[0]
            instances.extend(self.get_test_instances(zone=zone,
                                                     subnet_id=subnet.id,
                                                     group_id=sec_group.id,
                                                     vpc_id=vpc.id,
                                                     count=instance_count,
                                                     monitor_to_running=False))
        self.user.ec2.monitor_euinstances_to_running(instances=instances)
        self.log.info('test1_basic_instance_ssh_default_vpc passed')
        return instances

    def packet_test_scenario(self, zone1, zone2, sec_group1, sec_group_2, vpc1, vpc2,
                             subnets, use_private, protocol, pkt_count=5, retries=2, verbose=None):
        """
        This method is intended to be used as the core test method. It can be fed different
        sets of params each representing a different test scenario. This should allow for
        dictionaries of params to be autogenerated and fed to this test method forming a
        auto-generated test matrix. Used with cli_runner each param set can be ran as a testunit
        providing formatted results. This method should also provide a dict of results for
        additional usage.
        :param zone1: zone name
        :param zone2: zone name
        :param sec_group1: group obj or id
        :param sec_group_2: group obj or id
        :param vpc1: vpc obj or id
        :param vpc2: vpc obj or id
        :param subnet1: subnet obj or id
        :param subnet2: subnet obj or id
        :param use_private: bool, to use private addressing or not
        :param protocol: a dict to be fed to 'packet_test'. Example:{'protocol': ICMP, 'count': pkt_count}
        :param pkt_count: number of packets
        :param retries: number of retries
        :param verbose: bool, for verbose output
        :return dict of results (tbd)
        """
        vpc = self.default_vpc
        results = {}
        start = time.time()
        if verbose is None:
            if self.args.log_level == 'DEBUG':
                verbose = 2
            else:
                verbose = 0
        sec_group = self.get_test_security_groups(vpc=vpc, count=1, rules=self.DEFAULT_RULES)[0]
        try:
            for zone in self.zones:
                self.log.info('STARTING PACKET TEST AGAINST ZONE:"{0}"'.format(zone))
                ins1, ins2 = self.get_test_instances(zone=zone, group_id=sec_group.id, count=2)
                for retry in xrange(1, retries + 1):
                    try:
                        pkt_dict = packet_test(sender_ssh=ins1.ssh, receiver_ssh=ins2.ssh,
                                               protocol=1, count=pkt_count, verbose=verbose)
                        if pkt_dict.get('error', None) or (pkt_dict.get('count') != pkt_count):
                            raise RuntimeError('Packet test failed, results:{0}'.format(pkt_dict))
                        self.log.debug("Results for Zone: {0}\n{1}".format(zone, pkt_dict))
                        results[zone] = pkt_dict
                    except Exception as PE:
                        self.log.error("{0}\nPacket Test for zone: {1} failed attempt:{2}/{3}"
                                       .format(get_traceback(), zone, retry, retries))
                        wait = 30 - int(time.time()-start)
                        if wait > 0:
                            self.log.debug('Waiting "{0}" seconds to retry packet test'.format(wait))
                            time.sleep(wait)
                if zone not in results:
                    raise RuntimeError('Failed packet test for zone: {0}'.format(zone))
        finally:
            for zone, pkt_dict in results.iteritems():
                self.show_packet_test_results(pkt_dict,
                                              header='test2_icmp_packet_test_same_az_and_sg. '
                                                     'Zone:{0}'.format(zone))
        self.log.info('test2_icmp_packet_test_same_az_and_sg passed')
        # todo decide up results format
        return results

    def net_test(self, zone1, zone2, sec_group1, sec_group_2, vpc1, vpc2, subnet1, subnet2,
                 use_private, protocol, pkt_count=5, retries=2, verbose=None):
        pass

    def generate_vpc_test_matrix(self):
        """
        Sample method to show how a set of test parameters might be defined for feeding to
        self.packet_test_scenario(). The set of parameters defines the test matrix to be run.
        :return: test matrix dict
        """
        pkt_count = 5
        start_port = 100
        end_port = 110
        matrix = {}
        addressing = {'public': True, 'private': True, 'eip': True}
        vpc1 = self.default_vpc
        vpc2 = self.get_test_vpcs(count=1)[0]
        protocols = {'ICMP': {'protocol': ICMP, 'count': pkt_count},
                     'TCP': {'protocol': TCP, 'count': pkt_count, 'bind': True},
                     'UDP': {'protocol': UDP, 'count': pkt_count},
                     'SCTP': {'protocol': SCTP, 'count': pkt_count, 'bind': True}}
        vpc1_sec_group1, vpc1_sec_group2 = self.get_test_security_groups(vpc=vpc1,
                                                                         count=2,
                                                                         rules=[])
        vpc2_sec_group1, vpc2_sec_group2 = self.get_test_security_groups(vpc=vpc2,
                                                                         count=2,
                                                                         rules=[])
        # Create the available test params per zone...
        for zone in self.zones:
            new_def = {}
            new_def['addressing'] = addressing
            new_def['start_port'] = start_port
            new_def['end_port'] = end_port
            new_def['protocols'] = protocols
            default_vpc = {'vpc': vpc1}
            second_vpc = {'vpc': vpc2}

            default_vpc['security_groups'] = [vpc1_sec_group1, vpc1_sec_group2]
            second_vpc['security_groups'] = [vpc2_sec_group1, vpc2_sec_group2]

            # VPC1 'should' be the default vpc, and the first subnet tested should be the
            # default subnet for the zone to cover 'default vpc+subnet' the rest will be
            # created by this test suite...
            default_vpc['subnets'] = self.user.ec2.get_default_subnets(zone=zone) + \
                                      self.get_test_subnets_for_vpc(vpc1, count=1)
            second_vpc['subnets'] = self.get_test_subnets_for_vpc(vpc2, count=2)
            new_def['default_vpc'] = default_vpc
            new_def['vpc2'] =  second_vpc
            matrix[zone] = new_def
        return matrix

    def build_test_kwargs_from_testdefs(self, matrix):
        test_case_kwargs = []
        for zone, testdef in matrix.iteritems():
            protocol_dict = testdef.get('protocols')
            for protocol, proto_kwargs in protocol_dict.iteritems():
                addressing_dict = testdef.get('addressing' or {})
                for addressing, value in addressing_dict.iteritems():
                    for vm1_vpc in [testdef.get('vpc1'), testdef.get('vpc2')]:
                        pass


    def show_packet_test_results(self, results_dict, header=None, printmethod=None, printme=True):
        if not results_dict:
            self.log.warning('Empty results dict passed to show_packet_test_results')
            return
        protocol = results_dict.get('protocol', "???")
        header = header or 'PACKET_TEST_RESULTS'
        main_pt = PrettyTable([header])
        main_pt.align = 'l'
        main_pt.padding_width = 0
        main_pt.add_row(["{0}".format(results_dict.get('name'))])
        main_pt.add_row(["Elapsed:{0}, Packet Count:{1}".format(results_dict.get('elapsed'),
                                                        results_dict.get('count'))])
        if results_dict.get('error'):
            main_pt.add_row(["ERROR: {0}".format(markup(results_dict.get('error'), [1, 91]))])
        pt = PrettyTable(['pkt_src_addr', 'pkt_dst_addr', 'protocol', 'port', 'pkt_count'])
        for src_addr, s_dict in results_dict.get('packets', {}).iteritems():
            for dst_addr, d_dict in s_dict.iteritems():
                for port, count in d_dict.iteritems():
                    pt.add_row([src_addr, dst_addr, protocol, port, count])
        main_pt.add_row(["{0}".format(pt)])
        if not printme:
            return main_pt
        printmethod = printmethod or self.log.info
        printmethod("\n{0}\n".format(main_pt))

    def clean_method(self):
        self.user.ec2.clean_all_test_resources()

if __name__ == "__main__":
    testcase = VpcBasics()
    if testcase.args.tests:
        testlist = testcase.args.tests.splitlines(',')
    else:
        testlist = ['test1_basic_instance_ssh_default_vpc']

    ### Convert test suite methods to EutesterUnitTest objects
    unit_list = [ ]
    for test in testlist:
        unit_list.append(testcase.create_testunit_by_name(test))

    clean_on_exit = not testcase.args.freeze_on_exit
    ### Run the EutesterUnitTest objects
    result = testcase.run_test_case_list(unit_list,
                                         eof=False,
                                         clean_on_exit=clean_on_exit)
    exit(result)

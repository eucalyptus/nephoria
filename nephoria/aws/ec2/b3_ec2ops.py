# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2014, Eucalyptus Systems, Inc.
# All rights reserved.
#
# Redistribution and use of this software in source and binary forms, with or
# without modification, are permitted provided that the following conditions
# are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author: vic.iglesias@eucalyptus.com

from nephoria.baseops.boto3baseops import Boto3BaseOps
from cloud_utils.log_utils import printinfo


class B3_EC2ops(Boto3BaseOps):

    enable_root_user_data = """#cloud-config
disable_root: false"""
    SERVICE_PREFIX = 'ec2'
    EUCARC_URL_NAME = 'ec2_url'
    CONNECTION_CLASS = None

    def setup(self):
        self.key_dir = "./"
        self.local_machine_source_ip = None  # Source ip on local test machine used to reach VMs
        super(B3_EC2ops, self).setup()

    def setup_resource_trackers(self):
        """
        Setup keys in the test_resources hash in order to track artifacts created
        Populate test_resources_clean_methods with resourece type to clean method mappings.
        Note: Some items may have dependencies on other when deleting/removing. Order the list
        in the same order resources should be deleted.
        """
        """
        self.test_resources_clean_methods["instances"] = self.cleanup_test_instances
        self.test_resources_clean_methods["volumes"] = self.clean_up_test_volumes
        self.test_resources_clean_methods["snapshots"] = self.cleanup_test_snapshots
        self.test_resources_clean_methods["keypairs"] = self.delete_ec2_resources
        self.test_resources_clean_methods["security_groups"] = self.delete_ec2_resources
        self.test_resources_clean_methods["images"] = self.delete_ec2_resources
        self.test_resources_clean_methods["addresses"] = self.cleanup_addresses
        self.test_resources_clean_methods["conversion_tasks"] = \
            self.cleanup_conversion_task_resources
        for resource_type in self.test_resources_clean_methods.keys():
            self.test_resources[resource_type] = []
        """

    def get_all_subnets(self, verbose=True):
        if verbose:
            sgs = self.connection.Subnet


    @printinfo
    def run_image(self,
                  image=None,
                  keypair=None,
                  group="default",
                  type=None,
                  zone=None,
                  min=1,
                  max=1,
                  block_device_map=None,
                  user_data=None,
                  private_addressing=False,
                  username=None,
                  password=None,
                  subnet_id=None,
                  auto_connect=True,
                  clean_on_fail=True,
                  monitor_to_running = True,
                  return_reservation=False,
                  auto_create_eni=True,
                  network_interfaces=None,
                  timeout=480,
                  boto_debug_level=2,
                  **boto_run_args):
        """

        :param image: image object or string image_id to create instances with
        :param keypair: keypair to create instances with
        :param group: security group (or list of groups) to run instances in
        :param type: vmtype to run instances as
        :param zone: availability zone (aka cluster, aka parition) to run instances in
        :param min: minimum amount of instances to try to run
        :param max: max amount of instances to try to run
        :param user_data: user_data to run instances with
        :param private_addressing: boolean to run instances without public ips
        :param username: username for connecting ssh to instances.
                         Default usernames: Linux=root, Windows=Administrator
        :param password: password for connnecting ssh to instances
        :param subnet_id: (VPC MODE) the subnet to create this instances network interface in
        :param auto_connect: boolean flag whether or not ssh connections should be
                            automatically attempted
        :param clean_on_fail: boolean flag whether or not to attempt to delete/remove
                             failed instances-(not implemented)
        :param monitor_to_running: boolean flag whether or not to monitor instances to a
                                  running state
        :pararm block_device_map: block device map obj
        :param auto_create_eni: flag to indicate whether this method should auto create and assign
                        an elastic network interfaces to associate w/ a public ip. This
                        is only used for VPC where subnets default behavior does not match the
                        requested private/public addressing.
        :param network_interfaces: A boto NetworkInterfaceCollection type obj.
                       This obj contains a list of existing boto NetworkInterface
                       or NetworkInterfaceSpecification objs.
                        Note:
                       when providing network interfaces, the group and subnet_ids
                       will be derived from these and the args; group, subnet_id will
                       be ignored.
        :param timeout: time allowed before failing this operation
        :return: list of euinstances
        """
        reservation = None
        instances = []
        addressing_type = None
        secgroups = None
        try:
            if not isinstance(image, Image):
                image = self.get_emi(emi=str(image))
            if image is None:
                raise Exception("emi is None. run_instance could not auto find an emi?")
            if user_data is None:
                user_data = self.enable_root_user_data
            if isinstance(subnet_id, Subnet):
                subnet_ = subnet_id.id
            if private_addressing is True:
                if not self.vpc_supported:
                    addressing_type = "private"
                auto_connect = False
            #In the case a keypair object was passed instead of the keypair name
            if keypair:
                if isinstance(keypair, KeyPair):
                    keypair = keypair.name

            # Format the provided security group arg, and store it for debug purposes.
            if group:
                secgroups = []
                if isinstance(group, list):
                    groups = group
                else:
                    groups = [group]
                for group in groups:
                    if group:
                        if isinstance(group, basestring):
                            if not re.match('^sg-\w{8}$',str(group).strip()):
                                try:
                                    group = self.get_security_group(name=group)
                                    group = group.id
                                except:
                                    self.log.critical('Run Image, Unable to find security group '
                                                  'for: "{0}"'.format(group))
                                    raise
                        elif isinstance(group, SecurityGroup):
                            group = group.id
                        else:
                            raise ValueError('Unknown arg passed for group to RunImage,'
                                             ' group: "{0}", (type:{1})'
                                             .format(group, type(group)))
                        secgroups.append(group)


            # Do some convenience work around network interfaces for run requests in a VPC cloud...
            if network_interfaces:
                self.log.debug('Network interfaces were provided')
                if not isinstance(network_interfaces, NetworkInterfaceCollection):
                    raise ValueError('network_interfaces must be of type'
                                     ' NetworkInterfaceSpecification which contains type'
                                     ' NetworkInterface eni objs')
                if group or subnet_id:
                    self.log.critical('WARNING: group and subnet_id args will be ignored when'
                                  'providing network_interfaces. The ENIs provided should'
                                  'contain this info')
                secgroups = None
                subnet_id = None
            elif auto_create_eni:
                #  Attempts to create an ENI only if the ip request does not match the default
                # behavior of the subnet running these instances.
                subnet = None
                if subnet_id:
                    # No network_interfaces were provided, check to see if this subnet already
                    # maps a public ip by default or if a new eni should be created to
                    # request one...
                    if not isinstance(subnet, BotoSubnet):
                        subnets = self.get_all_subnets(subnet_id)
                        if subnets:
                            subnet = subnets[0]
                        else:
                            raise ValueError('Subnet: "{0}" not found during run_image'
                                             .format(subnet_id))
                else:
                    subnets = self.get_default_subnets(zone=zone)
                    if subnets:
                        subnet = subnets[0]
                if subnet:
                    subnet_id = subnet.id
                    # mapPublicIpOnLaunch may be unicode true/false...
                    if not isinstance(subnet.mapPublicIpOnLaunch, bool):
                        if str(subnet.mapPublicIpOnLaunch).upper().strip() == 'TRUE':
                            subnet.mapPublicIpOnLaunch = True
                        else:
                            subnet.mapPublicIpOnLaunch = False
                    # Default subnets or subnets whos attributes have been modified to
                    # provide a public ip should automatically provide an ENI and public ip
                    # association, skip if this is true...
                    if subnet.mapPublicIpOnLaunch == private_addressing:
                        eni = NetworkInterfaceSpecification(
                            device_index=0, subnet_id=subnet_id,
                            groups=secgroups,
                            delete_on_termination=True,
                            description='nephoria_auto_assigned',
                            associate_public_ip_address=(not private_addressing))
                        network_interfaces = NetworkInterfaceCollection(eni)
                        # sec group  and subnet info is now passed via the eni(s),
                        # not to the run request
                        secgroups = None
                        subnet_id = None
            # For debug purposes, attempt to print a table showing all the instances
            #  visible to this user on this system prior to making this run instance request...
            self.log.debug(markup('Euinstance list prior to running image...', 1))
            try:
                self.log.debug('\n{0}\n{1}'
                           .format(markup('Euinstance list prior to running image:'),
                                   self.show_instances(printme=False)))
            except Exception, e:
                self.log.debug('Failed to print euinstance list before running image, err:' +str(e))
            cmdstart=time.time()

            self.log.debug(markup("\n\n Making Run instance request...."))
            if network_interfaces:
                params = {}
                network_interfaces.build_list_params(params)
                self.log.debug('network interface params:{0}'.format(params))
            orig_boto_debug_level = getattr(self.connection, 'debuglevel', None)
            try:
                self.connection.debuglevel = boto_debug_level
                reservation = self.connection.run_instances(image_id = image.id,
                                                     key_name=keypair,
                                                     security_group_ids=secgroups,
                                                     instance_type=type,
                                                     placement=zone,
                                                     min_count=min,
                                                     max_count=max,
                                                     user_data=user_data,
                                                     addressing_type=addressing_type,
                                                     block_device_map=block_device_map,
                                                     subnet_id=subnet_id,
                                                     network_interfaces=network_interfaces,
                                                     **boto_run_args)
            except:
                self.connection.debuglevel = orig_boto_debug_level
                raise
            self.test_resources["instances"].extend(reservation.instances)

            if (len(reservation.instances) < min) or (len(reservation.instances) > max):
                fail = "Reservation:" + str(reservation.id) + " returned " + \
                       str(len(reservation.instances)) +\
                       " instances, not within min("+str(min)+") and max("+str(max)+")"

            if image.root_device_type == 'ebs':
                self.wait_for_instances_block_dev_mapping(reservation.instances, timeout=timeout)
            for instance in reservation.instances:
                try:
                    self.log.debug(str(instance.id)+':Converting instance to euinstance type.')
                    #convert to euinstances, connect ssh later...
                    if image.platform == 'windows':
                        if username is None:
                            username = 'Administrator'
                        eu_instance = WinInstance.make_euinstance_from_instance(
                            instance,
                            self,
                            keypair=keypair,
                            username=username,
                            password=password,
                            reservation=reservation,
                            private_addressing=private_addressing,
                            timeout=timeout,
                            cmdstart=cmdstart,
                            auto_connect=False)
                    else:
                        if username is None:
                            username = 'root'
                        eu_instance =  EuInstance.make_euinstance_from_instance(
                            instance,
                            self,
                            keypair=keypair,
                            username = username,
                            password=password,
                            reservation = reservation,
                            private_addressing=private_addressing,
                            timeout=timeout,
                            cmdstart=cmdstart,
                            do_ssh_connect=False )
                    #set the connect flag in the euinstance object for future use
                    eu_instance.auto_connect = auto_connect
                    instances.append(eu_instance)
                except Exception, e:
                    self.log.debug(get_traceback())
                    raise Exception("Unable to create Euinstance from " + str(instance) +
                                    ", err:\n" + str(e))
            if monitor_to_running:
                instances = self.monitor_euinstances_to_running(instances, timeout=timeout)
            if return_reservation:
                reservation.instances = instances
                return reservation
            return instances
        except Exception as E:
            trace = get_traceback()
            self.log.error('{0}\n!!! Run_instance failed, terminating reservation. Error: {1}'
                           .format(trace, E))
            if reservation and clean_on_fail:
                self.terminate_instances(reservation=reservation)
            raise E

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

import re
import os
import copy
import socket
import hmac
import hashlib
import base64
from prettytable import PrettyTable, ALL
import time
import types
import traceback
from datetime import datetime, timedelta
from subprocess import Popen, PIPE
from nephoria.exceptions import EucaAdminRequired

from boto.ec2.image import Image
from boto.ec2.instance import Reservation, Instance
from boto.ec2.keypair import KeyPair
from boto.ec2.blockdevicemapping import BlockDeviceMapping, BlockDeviceType
from boto.ec2.group import Group as BotoGroup
from boto.ec2.volume import Volume
from boto.ec2.bundleinstance import BundleInstanceTask
from boto.exception import EC2ResponseError
from boto.resultset import ResultSet
from boto.ec2.securitygroup import SecurityGroup, IPPermissions
from boto.ec2.address import Address
from boto.ec2.tag import TagSet
from boto.ec2.zone import Zone
from boto.vpc.subnet import Subnet as BotoSubnet
from boto.vpc import VPCConnection, VPC, Subnet
from boto.ec2.networkinterface import NetworkInterfaceSpecification, NetworkInterfaceCollection
from boto.ec2.networkinterface import NetworkInterface


from nephoria import CleanTestResourcesException
from nephoria.baseops.botobaseops import BotoBaseOps
from nephoria.testcase_utils import wait_for_result
from cloud_utils.net_utils import sshconnection, ping, is_address_in_network
from cloud_utils.log_utils import printinfo, get_traceback, markup, red
from nephoria.aws.ec2.euinstance import EuInstance
from nephoria.aws.ec2.windows_instance import WinInstance
from nephoria.aws.ec2.euvolume import EuVolume
from nephoria.aws.ec2.eusnapshot import EuSnapshot
from nephoria.aws.ec2.euzone import EuZone
from nephoria.aws.ec2.conversiontask import ConversionTask
from boto3.session import Session


class EucaSubnet(BotoSubnet):
    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self._defaultForAz = None
        self._mapPublicIpOnLaunch = None

    @property
    def defaultForAz(self):
        return self._defaultForAz

    @defaultForAz.setter
    def defaultForAz(self, value):
        if re.search('true', value, flags=re.IGNORECASE):
            self._defaultForAz = True
        else:
            self._defaultForAz = False

    @property
    def mapPublicIpOnLaunch(self):
        return self._mapPublicIpOnLaunch

    @mapPublicIpOnLaunch.setter
    def mapPublicIpOnLaunch(self, value):
        if re.search('true', value, flags=re.IGNORECASE):
            self._mapPublicIpOnLaunch = True
        else:
            self._mapPublicIpOnLaunch = False

    def endElement(self, name, value, connection):
        BotoSubnet.endElement(self, name, value, connection)
        if name == 'mapPublicIpOnLaunch':
            self.mapPublicIpOnLaunch = value
        elif name == 'defaultForAz':
            self.defaultForAz = value


EC2RegionData = {
    'us-east-1': 'ec2.us-east-1.amazonaws.com',
    'us-west-1': 'ec2.us-west-1.amazonaws.com',
    'eu-west-1': 'ec2.eu-west-1.amazonaws.com',
    'ap-northeast-1': 'ec2.ap-northeast-1.amazonaws.com',
    'ap-southeast-1': 'ec2.ap-southeast-1.amazonaws.com'}


class EC2ops(BotoBaseOps):

    enable_root_user_data = """#cloud-config
disable_root: false"""
    SERVICE_PREFIX = 'ec2'
    EUCARC_URL_NAME = 'ec2_url'
    CONNECTION_CLASS = VPCConnection

    def setup(self):
        self.key_dir = "./"
        self.local_machine_source_ip = None  # Source ip on local test machine used to reach VMs
        self._zone_cache = []
        self._vpc_supported = None
        super(EC2ops, self).setup()

    def setup_resource_trackers(self):
        """
        Setup keys in the test_resources hash in order to track artifacts created
        Populate test_resources_clean_methods with resourece type to clean method mappings.
        Note: Some items may have dependencies on other when deleting/removing. Order the list
        in the same order resources should be deleted. 
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

    def delete_ec2_resources(self, resources):
        failcount = 0
        failmsg = ""
        resource_type = "unknown"
        resources = resources or []
        if not isinstance(resources, list):
            resources = [resources]
        if resources:
            resource_type = type(resources[0])
        for item in resources:
            try:
                ### SWITCH statement for particulars of removing a certain type of resources
                self.log.debug("Deleting " + str(item))
                if isinstance(item, Image):
                    item.deregister()
                elif isinstance(item, Reservation):
                    continue
                else:
                    try:
                        if not isinstance(item, str):
                            item.delete()
                    except EC2ResponseError as ec2re:
                        if ec2re.status == 400:
                            self.log.debug('Resource not found assuming it is'
                                       ' already deleted, resource:'
                                       + str(item))
            except Exception, e:
                tb = get_traceback()
                failcount += 1
                failmsg += str(tb) + "\nUnable to delete item: " + str(item) + "\n" + str(e)+"\n"
        if failmsg:
            raise CleanTestResourcesException('Errors attempting to clean up "{0}" resources:\n{1}'
                                              .format(resource_type, failmsg))


    def create_tags(self, resource_ids, tags, *args, **kwargs):
        """
        Add tags to the given resource

        :param resource_ids:      List of resources IDs to tag
        :param tags:              Dict of key value pairs to add, for just a name include a key with a '' value
        """
        self.log.debug("Adding the following tags:" + str(tags))
        self.log.debug("To Resources: " + str(resource_ids))
        self.connection.create_tags(resource_ids=resource_ids, tags=tags, *args, **kwargs)

    def delete_tags(self, resource_ids, tags):
        """
        Add tags to the given resource

        :param resource_ids:      List of resources IDs to tag
        :param tags:              Dict of key value pairs to add, for just a name include a key with a '' value
        """
        self.log.debug("Deleting the following tags:" + str(tags))
        self.log.debug("From Resources: " + str(resource_ids))
        self.connection.delete_tags(resource_ids=resource_ids, tags=tags)

    def create_keypair_and_localcert(self, key_name=None, key_dir=None, extension='.pem'):
        """
        Add a keypair with name key_name unless it already exists

        :param key_name: The name of the keypair to add and download.
        :param extension: The File extension used when creating the local cert/file.
        """
        key_dir = key_dir or self.key_dir
        if key_name is None:
            key_name = "keypair-" + str(int(time.time())) 
        self.log.debug("Looking up keypair " + key_name)
        try:
            key = self.connection.get_key_pair(key_name)
        except EC2ResponseError:
            pass
        if not key:
            self.log.debug('Creating keypair: %s' % key_name)
            # Create an SSH key to use when logging into instances.
            key = self.connection.create_key_pair(key_name)
            # AWS will store the public key but the private key is
            # generated and returned and needs to be stored locally.
            # The save method will also chmod the file to protect
            # your private key.
            key.save(key_dir)
            #Add the fingerprint header to file
            keyfile = open(key_dir + key.name + '.pem', 'r')
            data = keyfile.read()
            keyfile.close()
            keyfile = open(key_dir + key.name + '.pem', 'w')
            keyfile.write('KEYPAIR ' + str(key.name) + ' '+str(key.fingerprint)+"\n")
            keyfile.write(data)
            keyfile.close()
            self.test_resources["keypairs"].append(key)
            return key
        else:
            if self.get_all_current_local_keys(key_name=key_name,
                                               path=key_dir,
                                               extension=extension):
                self.log.info('Existing EC2 key {0} and local cert found at: "{1}"'
                              .format(key_name,
                                      os.path.join(key_dir, "{0}{1}".format(key_name, extension))))
                return key
            else:
                self.log.warn(
                    red('Key {0} already exists, but cert not found at:"{1}"'
                        .format(key_name,
                                os.path.join(key_dir, "{0}{1}".format(key_name, extension)))))
                return None

            
    def get_keypair(self, key_name=None, key_dir=None, extension='.pem'):
        return self.create_keypair_and_localcert(key_name=key_name, key_dir=key_dir,
                                                 extension=extension)
            
    def verify_local_keypath(self, keyname, path=None, exten=".pem"):
        """
        Convenience function to verify if a given ssh key 'keyname' exists on the local
        server at 'path'

        :returns: the keypath if the key is found.
        """
        if path is None:
            path = os.getcwd()
        keypath = os.path.join(path, "{0}{1}".format(keyname, exten))
        try:
            os.stat(keypath)
            self.log.debug("Found key at path:"+str(keypath))
        except:
            raise IOError("File not found at the provided key path:" + str(keypath))
        return keypath
    
    
    @printinfo
    def get_all_current_local_keys(self, key_name=None, path=None, extension=".pem"):
        """
        Convenience function to provide a list of all keys in the local dir at 'path' that exist
        on the server to help
        avoid producing additional keys in test dev.

        :param path: Filesystem path to search in
        :param extension: extension of private key file
        :return: list of key names
        """
        keylist = []
        if key_name:
            # this will error out here if key_name is not found on the cloud
            keys = self.connection.get_key_pair(key_name)
            if keys:
                keys = [keys]
        else:
            keys = self.connection.get_all_key_pairs()
        keyfile = None
        for k in keys:
            self.log.debug('Checking local path: {0} for keyfile: {1}{2}'
                           .format(path, k.name, extension))
            try:
                #will raise exception if keypath is not found
                keypath = self.verify_local_keypath(k.name, path, extension)
                if not keypath:
                    continue
                keyfile = open(keypath, 'r')
                for line in keyfile.readlines():
                    if re.search('KEYPAIR',line):
                        fingerprint = line.split()[2]
                        break
                keyfile.close()
                if fingerprint == k.fingerprint:
                    self.log.debug('Found file with matching finger print for key:' + k.name)
                    keylist.append(k)
            except Exception as KE:
                self.log.debug('Did not find local match for key:"{0}". Err:{1}'
                               .format(k.name, KE))
            finally:
                if keyfile and not keyfile.closed:
                    keyfile.close()
        return keylist

    def delete_keypair(self,keypair):

        """
        Delete the keypair object passed in and check that it no longer shows up

        :param keypair: Keypair object to delete and check
        :return: boolean of whether the operation succeeded
        """
        name = keypair.name
        self.log.debug(  "Sending delete for keypair: " + name)
        keypair.delete()
        try:
            keypair = self.connection.get_all_key_pairs(keynames=[name])
        except EC2ResponseError:
            keypair = []
            
        if len(keypair) > 0:
            self.fail("Keypair found after attempt to delete it")
            return False
        return True
    
    
    @printinfo
    def get_windows_instance_password(self,
                                      instance,
                                      private_key_path=None,
                                      key=None,
                                      dir=None,
                                      exten=".pem",
                                      encoded=True):
        """
        Get password for a windows instance.

        :param instance: euinstance object
        :param private_key_path: private key file used to decrypt password
        :param key: name of private key
        :param dir: Path to private key
        :param exten: extension of private key
        :param encoded: boolean of whether string returned from server is Base64 encoded
        :return: decrypted password
        :raise: Exception when private key cannot be found on filesystem
        """
        self.log.debug("get_windows_instance_password, instance:"+str(instance.id)+", keypath:"+str(private_key_path)+
                   ", dir:"+str(dir)+", exten:"+str(exten)+", encoded:"+str(encoded))
        key = key or self.get_keypair(instance.key_name)
        if private_key_path is None and key is not None:
            private_key_path = str(self.verify_local_keypath(key.name, dir, exten))
        if not private_key_path:
            raise Exception('get_windows_instance_password, keypath not found?')
        encrypted_string = self.connection.get_password_data(instance.id)
        if encoded:
            string_to_decrypt = base64.b64decode(encrypted_string)
        else:
            string_to_decrypt = encrypted_string
        popen = None
        try:
            popen = Popen(['openssl', 'rsautl', '-decrypt', '-inkey',
                           private_key_path, '-pkcs'], stdin=PIPE, stdout=PIPE)
            (stdout, _) = popen.communicate(string_to_decrypt)
        finally:
            if popen:
                try:
                    popen.stdin.close()
                    popen.stdout.close()
                    popen.stderr.close()
                except Exception as FDE:
                    self.log.warning('get_windows_instance_password, err closing fds:"{0}"'
                                     .format(FDE))

        return stdout

    @printinfo
    def add_group(self, group_name=None, description=None, vpc_id=None, fail_if_exists=False ):
        """
        Add a security group to the system with name group_name, if it exists dont create it

        :param group_name: Name of the security group to create
        :param fail_if_exists: IF set, will fail if group already exists, otherwise will return the existing group
        :return: boto group object upon success or None for failure
        """
        filters = {}
        if vpc_id:
            filters={'VpcId':vpc_id}
        if group_name is None:
            group_name = "group-" + str(int(time.time()))
        if self.check_group(group_name, vpc_id=vpc_id):
            if fail_if_exists:
                raise ValueError("Cant add security group, '{0}' already exists. Using vpc:{1}"
                                 .format(group_name, vpc_id))
            else:
                self.log.debug(  "Group '{0}' group already exists using vpc:'{1}'"
                                 .format(group_name, vpc_id))
                groups = self.connection.get_all_security_groups(group_name, filters=filters)
                if groups:
                    return groups[0]

        self.log.debug( 'Creating Security Group: %s' % group_name)
        # Create a security group to control access to instance via SSH.
        if not description:
            description = group_name
        group = self.connection.create_security_group(group_name, description, vpc_id=vpc_id)
        self.test_resources["security_groups"].append(group)
        return group

    def delete_group(self, group):
        """
        Delete the security group object passed in and check that it no longer shows up

        :param group: Group object to delete and check
        :return: bool whether operation succeeded
        """
        name = group.name
        self.log.debug( "Sending delete for security group: " + name )
        group.delete()
        if self.check_group(name):
            self.log.error("Group still found after attempt to delete it")
            return False
        return True

    def check_group(self, group_name, vpc_id=None):
        """
        Check if a group with group_name exists in the system for a given vpc

        :param group_name: Group name to check for existence
        :return: bool whether operation succeeded
        """
        filters = {}
        if vpc_id:
            filters={'VpcId':vpc_id}
        self.log.debug( "Looking up group " + group_name )
        if self._use_verbose_requests:
            group_names = ['verbose']
        else:
            group_names = []
        group_names.append(group_name)
        try:
            group = self.connection.get_all_security_groups(groupnames=group_names,
                                                            filters=filters)
        except EC2ResponseError:
            return False
        if not group:
            return False
        else:
            return True

    @printinfo
    def authorize_group(self,
                        group=None,
                        group_name=None,
                        group_id=None,
                        port=None,
                        end_port=None,
                        protocol=None,
                        cidr_ip="0.0.0.0/0",
                        src_security_group=None,
                        src_security_group_id=None,
                        src_security_group_name=None,
                        src_security_group_owner_id=None):

        """
        Authorize the boto.group object

        :param group: boto.group object
        :param port: Port to open, default=22
        :param end_port: End of port range to open, defaults to 'port' arg.
        :param protocol: Protocol to authorize, default=tcp
        :param cidr_ip: CIDR subnet to authorize, default="0.0.0.0/0" everything
        :param src_security_group_name: Grant access to 'group' from src_security_group_name, default=None
        :param force_args: boolean to send arguments w/o the test method sanitizing them
        :return: True on success
        :raise: Exception if operation fails
        """
        if isinstance(group, SecurityGroup):
            group_name = group.name
            group_id = group.id


        if not group_id:
            if isinstance(group, basestring):
                if re.match('^sg-\w{8}\s*$', group):
                    group_id = group
                else:
                    group_name = group
            if group_name and not group_id:
                group = self.get_security_group(name=group_name)
                group_name = group.name
                group_id = group.id
            else:
                raise ValueError('Authorize group. Must provide security group name, id.')
        end_port=end_port or port
        if src_security_group:
            src_security_group_name = src_security_group.name
            src_security_group_id = src_security_group.id
            src_security_group_owner_id = src_security_group.owner_id
        if not src_security_group_id:
            if src_security_group_name or src_security_group_owner_id:
                if not (src_security_group_owner_id and src_security_group_name):
                    raise ValueError('Must provide both src group name, and src group owner id in '
                                     'request, name:{0}, ownerid:{1}'
                                     .format(src_security_group_name, src_security_group_owner_id))

        return self.connection.authorize_security_group(
            group_id=group_id,
            src_security_group_name=src_security_group_name,
            src_security_group_owner_id=src_security_group_owner_id,
            src_security_group_group_id=src_security_group_id,
            ip_protocol=protocol,
            from_port=port,
            to_port=end_port,
            cidr_ip=cidr_ip,
            group_name=None,
            )

    def revoke_all_rules(self, group):

        if not isinstance(group, SecurityGroup):
            group = self.get_security_group(name=group)
        else:
            # group obj does not have update() yet...
            group = self.get_security_group(id=group.id)
        if not group:
            raise ValueError('Security group "{0}" not found'.format(group))
        self.show_security_group(group)
        assert isinstance(group, SecurityGroup)
        rules = copy.copy(group.rules)
        for r in rules:
            self.log.debug('Attempting to revoke rule:{0}, grants:{1}'
                       .format(r, r.grants))
            assert isinstance(r, IPPermissions)
            for grant in r.grants:
                if grant.cidr_ip:
                    self.log.debug('{0}.revoke(ip_protocol:{1}, from_port:{2}, '
                               'to_port{3}, cidr_ip:{4})'.format(group.name,
                                                                 r.ip_protocol,
                                                                 r.from_port,
                                                                 r.to_port,
                                                                 grant))
                    group.revoke(ip_protocol=r.ip_protocol, from_port=r.from_port,
                                 to_port=r.to_port, cidr_ip=grant.cidr_ip)
                if grant.name or grant.group_id:
                    group.revoke(ip_protocol=r.ip_protocol,
                                 from_port=r.from_port,
                                 to_port=r.to_port,
                                 src_group=grant,
                                 cidr_ip=None )
                    self.log.debug('{0}.revoke(ip_protocol:{1}, from_port:{2}, '
                               'to_port:{3}, src_group:{4})'.format(group.name,
                                                                   r.ip_protocol,
                                                                   r.from_port,
                                                                   r.to_port,
                                                                   grant))
        group = self.get_security_group(id=group.id)
        self.log.debug('AFTER removing all rules...')
        self.show_security_group(group)
        return group

    def show_security_group(self, group):
        try:
            from prettytable import PrettyTable, ALL
        except ImportError as IE:
            self.log.info('No pretty table import failed:' + str(IE))
            return
        group = self.get_security_group(id=group.id)
        if not group:
            raise ValueError('Show sec group failed. Could not fetch group:'
                             + str(group))
        header = PrettyTable(["Security Group:" + group.name + "/" + group.id])
        table = PrettyTable(["CIDR_IP", "SRC_GRP_NAME",
                             "SRC_GRP_ID", "OWNER_ID", "PORT",
                             "END_PORT", "PROTO"])
        table.align["CIDR_IP"] = 'l'
        table.padding_width = 1
        for rule in group.rules:
            port = rule.from_port
            end_port = rule.to_port
            proto = rule.ip_protocol
            for grant in rule.grants:
                table.add_row([grant.cidr_ip, grant.name,
                               grant.group_id, grant.owner_id, port,
                               end_port, proto])
        table.hrules = ALL
        header.add_row([str(table)])
        self.log.info("\n{0}".format(str(header)))

    def revoke_security_group(self, group, from_port, to_port=None, protocol="tcp",
                              src_security_group_name=None, src_security_group_owner_id=None,
                              cidr_ip="0.0.0.0/0"):
        if isinstance(group, SecurityGroup):
            group_name = group.name
        else:
            group_name = group
        if to_port is None:
            to_port = from_port
        if src_security_group_name:
            self.log.debug( "Attempting revoke of {0} from {1} for proto/ports: {2}/{3}-{4}"
                            .format(group_name, src_security_group_name,
                                    protocol, from_port, to_port))
        else:
            self.log.debug( "Attempting revoke proto/ports {0}/{1}-{2} from group:{3}"
                            .format(protocol, from_port, to_port, group_name))
        self.connection.revoke_security_group(
            group_name,
            ip_protocol=protocol,
            from_port=from_port,
            to_port=to_port,
            cidr_ip=cidr_ip,
            src_security_group_name=src_security_group_name,
            src_security_group_owner_id=src_security_group_owner_id)

    def show_account_attributes(self, attribute_names=None, printmethod=None, printme=True):
        attrs = self.connection.describe_account_attributes(attribute_names=attribute_names)

        main_pt = PrettyTable([markup('ACCOUNT ATTRIBUTES')])
        pt = PrettyTable([markup('NAME'), markup('VALUE')])
        pt.hrules = ALL
        for attr in attrs:
            pt.add_row([attr.attribute_name, attr.attribute_values])
        main_pt.add_row([str(pt)])
        if printme:
            printmethod = printmethod or self.log.info
            printmethod( "\n" + str(main_pt) + "\n")
        else:
            return main_pt

    def get_supported_platforms(self):
        attr = None
        try:
            attr = self.connection.describe_account_attributes(
                attribute_names='supported-platforms')
        except Exception as E:
            self.log.warning('{0}\n{1}'
                             .format(markup('Could not describe account attributes', [1, 31]),
                                     get_traceback()))

            err = "{0}\nFailed to get 'supported-platforms' fromcloud, err:'{1}'"\
                  .format(get_traceback(),str(E))
            self.log.warning(markup(err, markups=[1, 31]))
        if attr:
            return attr[0].attribute_values
        else:
            return []

    def get_default_vpc_attribute(self):
        attr = self.connection.describe_account_attributes(attribute_names='default-vpc')
        if attr:
            return attr[0].attribute_values
        return []

    @property
    def vpc_supported(self):
        if self._vpc_supported is None:
            self._vpc_supported = 'VPC' in self.get_supported_platforms()
        return self._vpc_supported

    def get_default_vpcs(self):
        vpc_ids = self.get_default_vpc_attribute() or None
        if vpc_ids:
            return self.get_all_vpcs(vpc_ids=vpc_ids)
        return []

    def get_all_vpcs(self, vpc_ids=None, filters=None, dry_run=False, verbose=True):
         if verbose:
            if vpc_ids is not None:
                if not isinstance(vpc_ids, list):
                    if vpc_ids != 'verbose':
                        subnet_ids = [vpc_ids, 'verbose']
                elif 'verbose' not in vpc_ids:
                    vpc_ids.append('verbose')
            else:
                vpc_ids = ['verbose']
         return self.connection.get_all_vpcs(vpc_ids=vpc_ids, filters=filters, dry_run=dry_run)

    get_all_vpcs.__doc__ = "{0}".format(VPCConnection.get_all_vpcs.__doc__)

    def get_vpc(self, vpc_id, verbose=True):
        vpcs = self.get_all_vpcs(vpc_ids=[vpc_id], verbose=verbose) or []
        for vpc in vpcs:
            if vpc.id == vpc_id:
                return vpc
        return None

    def show_vpc(self, vpc, printmethod=None, show_tags=True, printme=True):
        if isinstance(vpc, str):
            vpcs = self.get_all_vpcs(vpc)
            if vpcs:
                vpc = vpcs[0]
        if not isinstance(vpc, VPC):
             raise ValueError('show_vpc passed on non VPC type: "{0}:{1}"'.format(vpc, type(vpc)))
        title = markup('  VPC SUMMARY: "{0}"'.format(vpc.id), markups=[1, 94])
        main_pt = PrettyTable([title])
        main_pt.align[title] = 'l'
        main_pt.padding_width = 0
        mainbuf = ""
        summary_pt = PrettyTable(["CIDR BLOCK", "DHCP OPT ID", "INS TENANCY", "STATE",
                                  "IS DEFAULT"])
        summary_pt.padding_width = 0
        summary_pt.add_row([vpc.cidr_block, vpc.dhcp_options_id, vpc.instance_tenancy, vpc.state,
                            vpc.is_default])
        mainbuf += str(summary_pt)
        if show_tags and vpc.tags:
            mainbuf += markup('\nVPC "{0}" TAGS:\n'.format(vpc.id), markups=[1,4])
            mainbuf += str(self.show_tags(vpc.tags, printme=False)) + "\n"
        main_pt.add_row([mainbuf])
        if printme:
            printmethod = printmethod or self.log.info
            printmethod( "\n" + str(main_pt) + "\n")
        else:
            return main_pt

    def show_vpcs(self, vpcs=None, printmethod=None, show_tags=True, verbose=None, printme=True):
        ret_buf = markup('--------------VPC LIST--------------', markups=[1, 94])
        if verbose is None:
            verbose = self._use_verbose_requests
        if not vpcs:
            vpcs = self.get_all_vpcs(verbose=verbose)
        for vpc in vpcs:
            ret_buf += "\n" + str(self.show_vpc(vpc, show_tags=show_tags, printme=False))
        if printme:
            printmethod = printmethod or self.log.info
            printmethod( "\n" + str(ret_buf) + "\n")
        else:
            return ret_buf

    def get_all_subnets(self, subnet_ids=None, zone=None, filters=None, dry_run=False, verbose=None):
        ret_list = []
        filters = filters or {}
        if zone:
            if not isinstance(zone, Zone):
                zone = zone.name
            filters['availabilityZone'] = zone
        if verbose is None:
            verbose = self._use_verbose_requests
        if verbose:
            if subnet_ids:
                if not isinstance(subnet_ids, list):
                    if subnet_ids != 'verbose':
                        subnet_ids = [subnet_ids, 'verbose']
                elif 'verbose' not in subnet_ids:
                    subnet_ids.append('verbose')
            else:
                subnet_ids = ['verbose']
        subnets = self.connection.get_all_subnets(subnet_ids=subnet_ids, filters=filters,
                                                  dry_run=dry_run)
        # map unicode to actual bool values...
        for subnet in subnets:
            euca_sub = EucaSubnet()
            euca_sub.__dict__ = dict(euca_sub.__dict__.items() + subnet.__dict__.items())
            euca_sub.mapPublicIpOnLaunch = subnet.mapPublicIpOnLaunch
            euca_sub.defaultForAz = subnet.defaultForAz
            ret_list.append(euca_sub)
        return ret_list

    get_all_subnets.__doc__ = "{0}".format(VPCConnection.get_all_subnets.__doc__)

    def get_subnet(self, subnet_id, verbose=None):
        if verbose is None:
            verbose = self._use_verbose_requests
        subnets = self.get_all_subnets(subnet_ids=[subnet_id], verbose=verbose) or []
        for subnet in subnets:
            if subnet.id == subnet_id:
                return subnet
        return None


    def get_default_subnets(self, zone=None):
        ret_list = []
        filters = None
        if zone:
            filters = {'availabilityZone':zone}
        subnets = self.get_all_subnets(filters = filters, verbose=False)
        for subnet in subnets:
            if subnet.defaultForAz:
                ret_list.append(subnet)
        return ret_list

    def modify_subnet_attribute(self, subnet, mapPublicIpAtLaunch):
        if isinstance(subnet, str):
            subnets = self.get_all_subnets(subnet)
            if subnets:
                subnet=subnets[0]
        if not isinstance(subnet, BotoSubnet):
             raise ValueError('modify_subnet_attribute passed on non Subnet type for subnet: '
                              '"{0}:{1}"'.format(subnet, type(subnet)))
        if not isinstance(mapPublicIpAtLaunch, bool):
            raise ValueError('modify_subnet_attribute passed on non bool type for'
                             ' mapPublicIpAtLaunch: "{0}:{1}"'.format(mapPublicIpAtLaunch,
                                                                      type(mapPublicIpAtLaunch)))
        ret = self.get_status('ModifySubnetAttribute',
                                  {'SubnetId': subnet.id,
                                   'MapPublicIpOnLaunch.Value': mapPublicIpAtLaunch},
                                  verb='POST')
        subnet = self.get_subnet(subnet.id)
        if not str(subnet.mapPublicIpOnLaunch).upper().strip() == str(mapPublicIpAtLaunch).upper():
            raise ValueError("Subnet: {0} mapPublicIpAtLaunch current value:'{1}' does not "
                             "match the request value: '{2}'".format(subnet.id,
                                                                     subnet.mapPublicIpOnLaunch,
                                                                     mapPublicIpAtLaunch))
        return ret

    def show_subnet(self, subnet, printmethod=None, show_tags=True, printme=True):
        subnet_id = subnet
        if isinstance(subnet, basestring):
            subnet = self.get_subnet(subnet_id)
            if not subnet:
                self.log.warn('No subnet found for:"{0}"'.format(subnet_id))
        if not isinstance(subnet, BotoSubnet):
             raise ValueError('show_subnet passed on non Subnet type: "{0}:{1}"'
                              .format(subnet, type(subnet)))
        title = markup('  SUBNET SUMMARY: "{0}"'.format(subnet.id), markups=[1,94])
        main_pt = PrettyTable([title])
        main_pt.align[title] = 'l'
        main_pt.padding_width = 0
        mainbuf = ""
        summary_pt = PrettyTable(["VPC ID", "CIDR BLOCK", "AVAIL IP CNT", "MAP PUB IP",
                                  "STATE", "ZONE", "ZONE DEFAULT"])
        summary_pt.padding_width = 0
        if subnet:
            summary_pt.add_row([subnet.vpc_id, subnet.cidr_block,
                                subnet.available_ip_address_count, subnet.mapPublicIpOnLaunch,
                                subnet.state, subnet.availability_zone, subnet.defaultForAz])
        else:
            summary_pt.add_row([subnet_id, 'Not Found', "N/A", "N/A", "N/A", "N/A", "N/A"])
        mainbuf += str(summary_pt)
        if show_tags and subnet.tags:
            mainbuf += markup('\nSUBNET "{0}" TAGS:\n'.format(subnet.id), markups=[1,4])
            mainbuf += str(self.show_tags(subnet.tags, printme=False)) + "\n"
        main_pt.add_row([mainbuf])
        if printme:
            printmethod = printmethod or self.log.info
            printmethod( "\n" + str(main_pt) + "\n")
        else:
            return main_pt

    def show_subnets(self, subnets=None, printmethod=None, verbose=None,
                     show_tags=True, printme=True):
        ret_buf = markup('--------------SUBNET LIST--------------', markups=[1,4,94])
        if verbose is None:
            verbose = self._use_verbose_requests
        if not subnets:
            subnets = self.get_all_subnets(verbose=verbose)
        for subnet in subnets:
            subnet_pt = self.show_subnet(subnet, show_tags=show_tags, printme=False)
            if subnet_pt:
                ret_buf += "\n" + str(subnet_pt)
        if printme:
            printmethod = printmethod or self.log.info
            printmethod( "\n" + str(ret_buf) + "\n")
        else:
            return ret_buf

    def terminate_single_instance(self, instance, timeout=300 ):
        """
        Terminate an instance

        :param instance: boto.instance object to terminate
        :param timeout: Time in seconds to wait for terminated state
        :return: True on success
        """
        instance.terminate()
        return self.wait_for_instance(instance, state='terminated', timeout=timeout)

    def wait_for_instance(self,    instance, state="running", poll_count = None, timeout=480):
        """
        Wait for the instance to enter the state

        :param instance: Boto instance object to check the state on
        :param state: state that we are looking for
        :param poll_count: Number of 10 second poll intervals to wait before failure (for legacy test script support)
        :param timeout: Time in seconds to wait before failure
        :return: True on success
        :raise: Exception when instance does not enter proper state
        """
        if poll_count is not None:
            timeout = poll_count*10 
        self.log.debug( "Beginning poll loop for instance " + str(instance) + " to go to " + str(state) )
        if not isinstance(instance, Instance):
            instance = self.get_instances(idstring=instance)
            if not instance:
                instance = instance[0]
        instance.update()
        instance_original_state = instance.state
        start = time.time()
        elapsed = 0
        ### If the instance changes state or goes to the desired state before my poll count is complete
        while( elapsed <  timeout ) and (instance.state != state) and (instance.state != 'terminated'):
            #poll_count -= 1
            self.log.debug( "Instance("+instance.id+") State("+instance.state+"), elapsed:"+str(elapsed)+"/"+str(timeout))
            time.sleep(10)
            instance.update()
            elapsed = int(time.time()- start)
            if instance.state != instance_original_state:
                break
        self.log.debug("Instance("+instance.id+") State("+instance.state+") time elapsed (" +str(elapsed).split('.')[0]+")")
        if instance.state != state:
            raise Exception( str(instance) + " did not enter "+str(state)+" state after elapsed:"+str(elapsed))

        self.log.debug( str(instance) + ' is now in ' + instance.state )
        return True

    def wait_for_reservation(self,reservation, state="running",timeout=480):
        """
        Wait for an entire reservation to enter the state

        :param reservation: Boto reservation object to check the state on
        :param state: state that we are looking for
        :param timeout: How long in seconds to wait for state
        :return: True on success
        """
        aggregate_result = True
        instance_list = reservation
        if isinstance(reservation, Reservation):
            instance_list = reservation.instances
        self.log.debug( "Beginning poll loop for the " + str(len(instance_list))   + " instance found in " + str(instance_list) )
        for instance in instance_list:
            if not self.wait_for_instance(instance, state, timeout=timeout):
                aggregate_result = False
        return aggregate_result
    
    
    @printinfo
    def create_volume(self, zone, size=1, eof=True, snapshot=None, timeout=0, poll_interval=10,timepergig=120):
        """
        Create a new EBS volume then wait for it to go to available state, size or snapshot is mandatory

        :param zone: Availability zone to create the volume in
        :param size: Size of the volume to be created
        :param count: Number of volumes to be created
        :param eof: Boolean, indicates whether to end on first instance of failure
        :param snapshot: Snapshot to create the volume from
        :param timeout: Time to wait before failing. timeout of 0 results in size of volume * timepergig seconds
        :param poll_interval: How often in seconds to poll volume state
        :param timepergig: Time to wait per gigabyte size of volume, used when timeout is set to 0
        :return:
        """
        return self.create_volumes(zone, size=size, count=1, mincount=1, eof=eof,
                                   snapshot=snapshot, timeout=timeout,
                                   poll_interval=poll_interval, timepergig=timepergig)[0]



    @printinfo
    def create_volumes(self, 
                       zone,
                       size = 1, 
                       count = 1, 
                       mincount = None, 
                       eof = True, 
                       monitor_to_state = 'available',
                       delay = 0, 
                       snapshot = None, 
                       timeout=0, 
                       poll_interval = 10,
                       timepergig = 120 ):
        """
        Definition:
                    Create a multiple new EBS volumes then wait for them to go to available state, 
                    size or snapshot is mandatory

        :param zone: Availability zone to create the volume in
        :param size: Size of the volume to be created
        :param count: Number of volumes to be created
        :param mincount: Minimum number of volumes to be created to be considered a success.Default = 'count'
        :param eof: Boolean, indicates whether to end on first instance of failure
        :param monitor_to_state: String, if not 'None' will monitor created volumes to the provided state
        :param snapshot: Snapshot to create the volume from
        :param timeout: Time to wait before failing. timeout of 0 results in size of volume * timepergig seconds
        :param poll_interval: How often in seconds to poll volume state
        :param timepergig: Time to wait per gigabyte size of volume, used when timeout is set to 0
        :return: list of volumes
        """
        start = time.time()
        elapsed = 0
        volumes = []
        
        mincount = mincount or count
        if mincount > count:
            raise Exception('Mincount can not be greater than count')
        #if timeout is set to 0, use size to create a reasonable timeout for this volume creation
        if timeout == 0:
            if snapshot is not None:
                timeout = timepergig * int(snapshot.volume_size)
            else:
                timeout = timepergig * size
        
        if snapshot and not hasattr(snapshot,'eutest_volumes'):
                snapshot = self.get_snapshot(snapshot.id)
        self.log.debug( "Sending create volume request, count:"+str(count) )
        for x in xrange(0,count):
            vol = None
            try:
                cmdstart = time.time()
                vol = self.connection.create_volume(size, zone, snapshot)
                cmdtime = time.time() - cmdstart
                if vol:
                    vol = EuVolume.make_euvol_from_vol(vol, tester=self, cmdstart=cmdstart)
                    vol.eutest_cmdstart = cmdstart
                    vol.eutest_createorder = x
                    vol.eutest_cmdtime = "{0:.2f}".format(cmdtime)
                    vol.size = size
                    volumes.append(vol)
            except Exception, e:
                if eof:
                    #Clean up any volumes from this operation and raise exception
                    for vol in volumes:
                        vol.delete()
                    raise e
                else:
                    self.log.debug("Caught exception creating volume,eof is False, continuing. Error:"+str(e))
            if delay:
                time.sleep(delay)
        if len(volumes) < mincount:
             #Clean up any volumes from this operation and raise exception
            for vol in volumes:
                vol.delete()
            raise Exception("Created "+str(len(volumes))+"/"+str(count)+
                            ' volumes. Less than minimum specified:'+str(mincount))
        self.log.debug( str(len(volumes))+"/"+str(count)+" requests for volume creation succeeded." )
        
        if volumes:
            self.show_volumes(volumes)
        
        if not monitor_to_state:
            self.test_resources["volumes"].extend(volumes)
            if snapshot:
                snapshot.eutest_volumes.extend(volumes)
            return volumes
        #If we begain the creation of the min volumes, monitor till completion, otherwise cleanup and fail out
        retlist = self.monitor_created_euvolumes_to_state(volumes,
                                                          eof=eof,
                                                          mincount=mincount,
                                                          state=monitor_to_state,
                                                          poll_interval=poll_interval,
                                                          timepergig=timepergig)
        self.test_resources["volumes"].extend(retlist)
        if snapshot:
            snapshot.eutest_volumes.extend(retlist)
        return retlist
    
    
    @printinfo
    def monitor_created_euvolumes_to_state(self,
                                           volumes,
                                           eof=True,
                                           mincount=None,
                                           state='available',
                                           poll_interval=10,
                                           deletefailed=True,
                                           size=1,
                                           timepergig=120):
        """


        Description:
                    Monitors a list of created volumes until 'state' or failure. Allows for a variety of volumes, using
                    different types and creation methods to be monitored by a central method.
        :param volumes: list of created volumes
        :param eof: boolean, if True will end on first failure
        :param mincount: minimum number of successful volumes, else fail
        :param state: string indicating the expected state to monitor to
        :param deletefailed: delete all failed volumes, in eof case deletes 'volumes' list.
               In non-eof, if mincount is met, will delete any failed volumes.
        :param timepergig: integer, time allowed per gig before failing.
        :param poll_interval: int seconds to wait between polling for status
        :param size: int size in gigs to request for volume creation
        """
        
        retlist = []
        failed = []
        elapsed = 0
        
        if not volumes:
            raise Exception("Volumes list empty in monitor_created_volumes_to_state")
        count = len(volumes)
        mincount = mincount or count 
        self.log.debug("Monitoring "+str(count)+" volumes for at least "+str(mincount)+" to reach state:"+str(state))
        origlist = copy.copy(volumes)
        self.log.debug("Monitoring "+str(count)+" volumes for at least "+str(mincount)+" to reach state:"+str(state))
        for volume in volumes:
            if not isinstance(volume, EuVolume):
                raise Exception("object not of type EuVolume. Found type:"+str(type(volume)))
        #volume = EuVolume()
        # Wait for the volume to be created.
        self.log.debug( "Polling "+str(len(volumes))+" volumes for status:\""+str(state)+"\"...")
        start = time.time()
        while volumes:
            for volume in volumes:
                volume.update()
                voltimeout = timepergig * (volume.size or size)
                elapsed = time.time()-start
                self.log.debug("Volume #"+str(volume.eutest_createorder)+" ("+volume.id+") State("+volume.status+
                           "), seconds elapsed: " + str(int(elapsed))+'/'+str(voltimeout))
                if volume.status == state:
                    #add to return list and remove from volumes list
                    retlist.append(volumes.pop(volumes.index(volume)))
                else:
                    if elapsed > voltimeout:
                        volume.status = 'timed-out'
                    if volume.status == 'failed' or volume.status == 'timed-out':
                        if eof:
                            #Clean up any volumes from this operation and raise exception
                            self.log.debug(str(volume.id) + " - Failed current status:" + str(volume.status))
                            if deletefailed:
                                self.log.debug('Failure caught in monitor volumes, attempting to delete all volumes...')
                                for vol in origlist:
                                    try:
                                        self.delete_volume(vol)
                                    except Exception, e:
                                        self.log.debug('Could not delete volume:'+str(vol.id)+", err:"+str(e))
                            raise Exception(str(volume) + ", failed to reach state:"+str(state)+", vol status:"+
                                            str(volume.eutest_laststatus)+", test status:"+str(vol.status))
                        else:
                            #End on failure is not set, so record this failure and move on
                            msg = str(volume) + " went to: " + volume.status
                            self.log.debug(msg)
                            volume.eutest_failmsg = msg
                            failed.append(volumes.pop(volumes.index(volume)))
                    #Fail fast if we know we've exceeded our mincount already
                    if (count - len(failed)) < mincount:
                        if deletefailed:
                            buf = ""
                            for failedvol in failed:
                                retlist.remove(failedvol)
                                buf += str(failedvol.id)+"-state:"+str(failedvol.status) + ","
                            self.log.debug(buf)
                            for vol in origlist:
                                self.log.debug('Failure caught in monitor volumes, attempting to delete all volumes...')
                                try:
                                    self.delete_volume(vol)
                                except Exception, e:
                                    self.log.debug('Could not delete volume:'+str(vol.id)+", err:"+str(e))
                        raise Exception("Mincount of volumes did not enter state:"+str(state)+" due to faults")
            self.log.debug("----Time Elapsed:"+str(int(elapsed))+", Waiting on "+str(len(volumes))+
                       " volumes to enter state:"+str(state)+"-----")
            if volumes:
                time.sleep(poll_interval)
            else:
                break
        #We have at least mincount of volumes, delete any failed volumes
        if failed and deletefailed:
            self.log.debug( "Deleting volumes that never became available...")
            for volume in failed:
                self.log.debug('Failure caught in monitor volumes, attempting to delete all volumes...')
                try:
                    self.delete_volume(volume)
                except Exception, e:
                    self.log.debug('Could not delete volume:'+str(volume.id)+", err:"+str(e))
            buf = str(len(failed))+'/'+str(count)+ " Failed volumes after " +str(elapsed)+" seconds:"
            for failedvol in failed:
                retlist.remove(failedvol)
                buf += str(failedvol.id)+"-state:"+str(failedvol.status)+","
                self.log.debug(buf)
        self.show_volumes(origlist)
        return retlist

    @printinfo
    def monitor_euvolumes_to_status(self,
                                   euvolumes,
                                   status = None,
                                   attached_status = None,
                                   poll_interval=10,
                                   timeout=180,
                                   eof=True,
                                   validate_args=True):
        """
        (See: monitor_created_euvolumes_to_state() if monitoring newly created volumes, otherwise this method is
              intended for monitoring attached and in-use states of volume(s). )
        Definition: monitors a list of euvolumes to a given state.
        Some example valid states:
            status = available, attached_status = None
            status = in-use, attached_status = attached, attaching, detaching

        :param euvolumes:  list of euvolumes to monitor
        :param status: state of volume expected: ie 'in-use', 'available', 'deleted'
        :param attached_status: state of volume's attached data. ie 'attached', 'attaching', 'detaching', 'none'
        :param poll_interval: integer seconds between polling for status updates
        :param timeout: time to wait before failing
        :param eof: exit on first failure encountered, otherwise wait until other volumes pass/fail. Default=True
        :param validate_args: boolean, Will check args for a valid status/available_status pair.
                                If False will monitor to a non-valid state for testing purposes
        """
        good = []
        failed = []
        monitor = []
        failmsg = ""
        self.log.debug('Monitor_euvolumes_to_state:'+str(status)+"/"+str(attached_status))
        if attached_status and not status:
            status = 'in-use'
        #check for valid states in given arguments...
        if validate_args:
            if (status != 'available') and (status != 'in-use') and (status != 'deleted') and (status != 'failed'):
                raise Exception('Invalid volume states in monitor request:'+str(status)+" != in-use or available")
            if attached_status is None:
                if status != 'available':
                    raise Exception('Invalid volume states in monitor request:'+str(status)+"/"+str(attached_status))
            else:
                if (attached_status == 'attached') or (attached_status == 'attaching') or \
                        (attached_status == 'detaching') or (attached_status == 'detaching'):
                    if status != 'in-use':
                        raise Exception('Invalid volume states in monitor request:'+str(status)+"/"+str(attached_status))
                else:
                    raise Exception('Invalid volume states in monitor request:'+str(status)+"/"+str(attached_status)+
                                    " != attached, attaching, detaching")

        start = time.time()
        elapsed = 0
        self.log.debug('Updating volume list before monitoring...')
        for vol in euvolumes:
            try:
                vol = self.get_volume(vol.id)
                if not isinstance(vol, EuVolume):
                    vol = EuVolume.make_euvol_from_vol(vol,self)
                monitor.append(vol)
            except:
                self.log.debug(get_traceback())

        self.show_volumes(monitor)
        while monitor and (elapsed < timeout):
            elapsed = int(time.time()-start)
            for vol in monitor:
                last_attached_status = vol.eutest_attached_status
                vol.update()
                if vol.eutest_attached_instance_id:
                    instance_debug_str = ', (att_instance'+str(vol.eutest_attached_instance_id)+")"
                else:
                    instance_debug_str = ""
                self.log.debug("Monitoring volume:"+str(vol.id)+". Currently state/attached_state:'"+str(vol.status)
                            + "/" + str(vol.eutest_attached_status)+"', needed: '"+str(status)+"/"+str(attached_status)+
                           "'"+instance_debug_str)
                #fail fast for improper state transitions when attaching:
                if attached_status and last_attached_status and not vol.eutest_attached_status:
                    failmsg += str(vol.id)+" - state:"+str(vol.status)+", reverted from attached state:'"\
                              +str(last_attached_status)+"' to '"+str(vol.eutest_attached_status)+"', elapsed:" \
                              +str(elapsed)+"/"+str(timeout)+"\n"
                    if eof:
                        raise VolumeStateException(failmsg)
                    else:
                        failed.append(monitor.pop(monitor.index(vol)))
                        continue
                if (vol.status == 'deleted' and status != 'deleted') or (vol.status == 'failed' and status != 'failed'):
                    failmsg += str(vol.id)+" - detected error in state:'"+str(vol.status)+\
                               "/"+str(vol.eutest_attached_status)+"'"+str(elapsed)+"/"+str(timeout)+"\n"
                    if eof:
                        raise Exception(failmsg)
                    else:
                        failed.append(monitor.pop(monitor.index(vol)))
                        continue
                if vol.status == status:
                        if vol.eutest_attached_status == attached_status:
                            good.append(monitor.pop(monitor.index(vol)))
            self.log.debug('Waiting for '+str(len(monitor))+ " remaining Volumes. Sleeping for poll_interval: "
                       +str(poll_interval)+" seconds ...")
            self.show_volumes(euvolumes)
            time.sleep(poll_interval)
        self.log.debug('Done with monitor volumes after '+str(elapsed)+"/"+str(timeout)+"...")
        self.show_volumes(euvolumes)
        if monitor:
            for vol in monitor:
                failmsg +=  str(vol.id)+" -TIMED OUT current state/attached_state:'" \
                        +str(vol.status) + "/" + str(vol.eutest_attached_status) + "' ! = '" \
                        + str(status)+"/" + str(attached_status)+ "', elapsed:" \
                        +str(elapsed)+"/"+str(timeout)+"\n"
            failed.extend(monitor)
        #finally raise an exception if any failures were detected al    long the way...
        if failmsg:
            self.show_volumes(failed)
            raise Exception(failmsg)
        return good

    def show_volumes(self, euvolumelist=None, printme=True):
        """
        Creates and displays a table of volumes with summary information
        :param euvolumelist: list of euvolumes to be included in the table, if not provided
                             all volumes available to this account will be fetched and displayed
        :param printme: boolean flag, if True table will be displayed with self.log.debug, else
                        the PrettyTable obj will be returned
        :returns: None if printme is True, else will return the PrettyTable obj
        """
        buf=""
        euvolumes = []
        if not euvolumelist:
            euvolumelist = self.get_volumes()
        if not euvolumelist:
            self.log.info('No volumes to print')
            return
        for volume in euvolumelist:
            if not isinstance(volume, EuVolume):
                volume = EuVolume.make_euvol_from_vol(volume=volume, tester=self)
            else:
                try:
                    volume.update()
                except EC2ResponseError as ER:
                    if ER.status == 400 and ER.error_code == 'InvalidVolume.NotFound':
                        volume.status = 'deleted'
            euvolumes.append(volume)
        if not euvolumes:
            return
        first = euvolumes.pop(0)
        maintable = first.printself(printme=False)
        maintable.hrules = 1
        for volume in euvolumes:
            pt = volume.printself(printme=False)
            if pt._rows:
                maintable.add_row(pt._rows[0])
        if printme:
            self.log.info("\n"+str(maintable)+"\n")
        else:
            return str(maintable)



    def show_snapshots(self, eusnapshots=None, printme=True):
        """
        Creates and displays a table showing snapshot summary information
        :param eusnapshots: list of eusnapshots, if None all snapshots available to this user
                            will be shown
        :param printme: boolean, if True the table will be printed with self.log.debug, if False the
                        PrettyTable obj will be returned.
        :returns: None if printme is True and/or no snapshots are available,
                  else will return PrettyTable obj
        """
        buf=""
        plist = []
        if not eusnapshots:
            eusnapshots = self.get_snapshots()
        if not eusnapshots:
            self.log.info('No snapshots to print')
            return None
        for snapshot in eusnapshots:
            if not isinstance(snapshot, EuSnapshot):
                snapshot = EuSnapshot.make_eusnap_from_snap(snapshot=snapshot, tester=self)
            else:
                snapshot.update()
            plist.append(snapshot)
        first = plist.pop(0)
        maintable = first.printself(printme=False)
        maintable.hrules = 1
        for snap in plist:
            pt = snap.printself(printme=False)
            if pt._rows:
                maintable.add_row(pt._rows[0])
        if printme:
            self.log.info("\n"+str(maintable)+"\n")
            return None
        else:
            return str(maintable)


    def wait_for_volume(self, volume, status="available"):
        def get_volume_state():
            volume.update()
            return volume.status
        wait_for_result(get_volume_state, status)

    def delete_volume(self, volume, poll_interval=10, timeout=180):
        """
        Delete the EBS volume then check that it no longer exists

        :param poll_interval: int seconds to wait between polls to server for status
        :param timeout: int in seconds used for time to wait before failure
        :param volume: Volume object to delete
        :return: bool, success of the operation
        """
        if not volume:
            raise ValueError('Bad value passed to delete_volume: "{0}/{1}"'
                             .format(volume, type(volume)))

        if isinstance(volume, basestring):
            volume_id = volume
        else:
            volume_id = volume.id

        try:

            self.connection.delete_volume(volume_id)
        except Exception, e:
            self.log.warning('Caught err while sending delete for volume:'+ str(volume_id) +
                           " err:" + str(e))
            self.log.warning('Monitoring to deleted state after catching error...')
        self.log.debug("Sent delete for volume: " +  str(volume_id) +
                       ", monitor to deleted state or failure")
        start = time.time()
        elapsed = 0
        volume_id = volume_id
        while elapsed < timeout:
            try:
                chk_volume = self.get_volume(volume_id=volume_id)
                if not chk_volume:
                    self.log.debug(str(volume_id) + ', Volume no longer exists on system, deleted')
                    break
                chk_volume.update()
                self.log.debug(str(chk_volume) + " in " + chk_volume.status +
                                " sleeping:" + str(poll_interval) + ", elapsed:" + str(elapsed))
                if chk_volume.status == "deleted":
                    break
                time.sleep(poll_interval)
                elapsed = int(time.time()-start)
            except EC2ResponseError as e:
                if e.status == 400:
                    self.log.debug(str(volume_id) + "no longer exists in system")
                    if volume in self.test_resources['volumes']:
                        self.test_resources['volumes'].remove(volume)
                    return True
                else:
                    raise e
            if volume in self.test_resources['volumes']:
                self.test_resources['volumes'].remove(volume)
            return True

        if volume.status != 'deleted':
            self.log.error(str(volume) + " left in " +  volume.status + ',elapsed:' + str(elapsed))
            return False
        return True
    
    def delete_volumes(self, volume_list, poll_interval=10, force_send=False, timeout=180):
        """
        Deletes a list of EBS volumes then checks for proper state transition

        :param volume_list: List of volume objects to be deleted
        :param poll_interval: integer, seconds between polls on volumes' state
        :param timeout: integer time allowed before this method fails
        """
        errmsg = ''
        errlist = []
        if volume_list:
            vollist = copy.copy(volume_list)
        else:
            raise Exception("delete_volumes: volume_list was empty")
        for volume in vollist:
            try:
                self.log.debug( "Sending delete for volume: " +  str(volume.id))
                if volume in self.test_resources['volumes']:
                    self.test_resources['volumes'].remove(volume)
                volumes = self.connection.get_all_volumes([volume.id])
                if len(volumes) == 1:
                    volume = volumes[0]
                    #previous_status = volume.status
                    #self.delete_volume(volume.id)
                elif len(volumes) == 0:
                    vollist.remove(volume)
                    continue
                previous_status = volume.status
                self.delete_volume(volume.id)
            except EC2ResponseError, be:
                err = "ERROR: " + str(volume.id) + ", " + str(be.status)+ ", " + str(be.reason) + \
                          ", " +str(be.error_message) + "\n"
                if previous_status == 'deleting':
                    self.log.warning(str(volume.id)+ ":" + str(previous_status) + ', err:' +
                                     str(err))
                else:
                    errmsg += err
                    errlist.append(volume)
                    self.log.debug(err)
        for volume in errlist:
            if volume in vollist:
                vollist.remove(volume)
        start = time.time()
        elapsed = 0
        while vollist and elapsed < timeout:
            for volume in vollist:
                try:
                    volumes = self.connection.get_all_volumes([volume.id])
                except EC2ResponseError as e:
                    if e.status == 400:
                        volumes = []
                    else:
                        raise(e)
                if len(volumes) == 1:
                    volume = volumes[0]
                elif len(volumes) == 0:
                    vollist.remove(volume)
                    self.log.debug("Volume no longer found")
                    continue
                self.log.debug(str(volume) + " in " + volume.status)
                if volume and volume.status == "deleted"and volume in vollist:
                    vollist.remove(volume)
                    if volume in self.test_resources['volumes']:
                        self.test_resources['volumes'].remove(volume)
                elapsed = int(time.time()-start)
            time.sleep(poll_interval)
            self.log.debug("---Waiting for:"+str(len(vollist))+" volumes to delete. Sleeping:"+
                       str(poll_interval)+", elapsed:"+str(elapsed)+"/"+str(timeout)+"---")
        if vollist or errmsg:
                for volume in vollist:

                  errmsg += "ERROR:"+str(volume) + " left in " +  volume.status + ',elapsed:'+str(elapsed) + "\n"
                raise Exception(errmsg)

    def delete_all_volumes(self):
        """
        Deletes all volumes on the cloud
        """
        volumes = self.connection.get_all_volumes()
        self.delete_volumes(volumes)

        
    @printinfo    
    def attach_volume(self, instance, volume, device_path, pause=10, timeout=120):
        """
        Attach a volume to an instance

        :param instance: instance object to attach volume to
        :param volume: volume object to attach
        :param device_path: device name to request on guest
        :param pause: Time in seconds to wait before checking volume state
        :param timeout: Total time in seconds to wait for volume to reach the attached state
        :return:
        :raise: Exception of failure to reach proper state or enter previous state
        """
        self.log.debug("Sending attach for " + str(volume) + " to be attached to " + str(instance) +
                   " at requested device  " + device_path)
        volume.attach(instance.id,device_path )
        start = time.time()
        elapsed = 0  
        volume.update()
        status = ""
        failmsg = ""
        laststatus=None
        while elapsed < timeout:
            volume.update()
            attach_status=None
            if volume.attach_data is not None:
                if re.search("attached",str(volume.attach_data.status)):
                    self.log.debug(str(volume) + ", Attached: " +  volume.status+ " - " +
                               str(volume.attach_data.status) + ", elapsed:"+str(elapsed))
                    return True
                else:
                    attach_status = volume.attach_data.status
                    if attach_status:
                        laststatus = attach_status
                    elif laststatus and not attach_status:
                        failmsg += str(volume.id)+" - state:"+str(volume.status)+", reverted from attached state:'" \
                                   +str(laststatus)+"' to '"+str(attach_status)+"', elapsed:" \
                                   +str(elapsed)+"/"+str(timeout)+"\n"
                        raise VolumeStateException(failmsg)
            self.log.debug( str(volume) + ", state:" + volume.status+', attached status:'+str(attach_status) +
                        ", elapsed:"+str(elapsed)+'/'+str(timeout))
            if elapsed < timeout:
                time.sleep(pause)
            elapsed = int(time.time()-start)

    def detach_volume(self, volume, pause = 10, timeout=60):
        """
        Detach a volume

        :param volume: volume to detach
        :param pause: Time in seconds to wait before checking volume state
        :param timeout: Total time in seconds to wait for volume to reach the attached state
        :return: True on success
        """
        attach_data_status = None
        instance_id = None
        if volume is None:
            raise Exception(str(volume) + " does not exist")
        volume.detach()
        self.log.debug( "Sent detach for volume: " + volume.id + " which is currently in state: " + volume.status)
        start = time.time()
        elapsed = 0  
        while elapsed < timeout:
            volume.update()
            if volume.status != "in-use":
                self.log.debug(str(volume) + " left in " +  volume.status)
                return True
            if volume.attach_data is not None:
                attach_data_status = volume.attach_data.status
                if not instance_id:
                    instance_id = volume.attach_data.instance_id
            else:
                attach_data_status = None
            self.log.debug( str(volume) + " state:" + volume.status + ", attached_data:"+
                        str(attach_data_status)+", pause:"+str(pause)+", instance:"+str(instance_id)+", elapsed:"+str(elapsed))
            if elapsed < timeout:
                time.sleep(pause)
            elapsed = int(time.time() - start)
        raise Exception(str(volume.id)+':DETACH FAILED - Volume status remained at:'+
                        str(volume.status)+', attach_data_status:'+str(attach_data_status)+", instance: "+str(instance_id))
    
    def get_volume_time_attached(self,volume):
        """
        Get the seconds elapsed since the volume was attached.

        :type volume: boto volume object
        :param volume: The volume used to calculate the elapsed time since attached.

        :rtype: integer
        :returns: The number of seconds elapsed since this volume was attached.
        """
        self.log.debug("Getting time elapsed since volume attached...")
        volume.update()
        if volume.attach_data is None:
            raise Exception('get_time_since_vol_attached: Volume '+str(volume.id)+" not attached")
        #get timestamp from attach_data
        attached_time = self.get_datetime_from_resource_string(volume.attach_data.attach_time)
        #return the elapsed time in seconds
        return time.mktime(datetime.utcnow().utctimetuple()) - time.mktime(attached_time.utctimetuple())
    
    @classmethod
    def get_volume_time_created(cls,volume):
        """
        Get the seconds elapsed since the volume was created.

        :type volume: boto volume object
        :param volume: The volume used to calculate the elapsed time since created.

        :rtype: integer
        :returns: The number of seconds elapsed since this volume was created.
        """
        volume.update()
        #get timestamp from attach_data
        create_time = cls.get_datetime_from_resource_string(volume.create_time)
        #return the elapsed time in seconds
        return time.mktime(datetime.utcnow().utctimetuple()) - time.mktime(create_time.utctimetuple())
    
    @classmethod
    def get_snapshot_time_started(cls,snapshot):
        """
        Get the seconds elapsed since the snapshot was started.

        :type snapshot: boto snapshot object
        :param snapshot: The volume used to calculate the elapsed time since started.

        :rtype: integer
        :returns: The number of seconds elapsed since this snapshot was started.
        """
        snapshot.update()
        #get timestamp from attach_data
        start_time = cls.get_datetime_from_resource_string(snapshot.start_time)
        #return the elapsed time in seconds
        return time.mktime(datetime.utcnow().utctimetuple()) - time.mktime(start_time.utctimetuple())
    
    @classmethod
    def get_instance_time_launched(cls,instance):
        """
        Get the seconds elapsed since the volume was attached.

        :type volume: boto volume object
        :param volume: The volume used to calculate the elapsed time since attached.

        :rtype: integer
        :returns: The number of seconds elapsed since this volume was attached.
        """
        #instance.update()
        #get timestamp from launch data
        if not instance.launch_time:
            return None
        launch_time = cls.get_datetime_from_resource_string(instance.launch_time)
        #return the elapsed time in seconds
        return time.mktime(datetime.utcnow().utctimetuple()) - time.mktime(launch_time.utctimetuple())
    
    @classmethod
    def get_datetime_from_resource_string(cls,
                                          timestamp,
                                          time_format="%Y %m %d %H %M %S"):
        """
        Convert a typical resource timestamp to datetime time_struct.

        :type timestamp: string
        :param timestamp: Timestamp held within specific boto resource objects.
                          Example timestamp format: 2012-09-19T21:24:03.864Z

        :rtype: time_struct
        :returns: The time_struct representation of the timestamp provided.
        """
        t = re.findall('\w+',str(timestamp).replace('T',' '))
        #remove milliseconds from list...
        t.pop()
        #create a time_struct out of our list
        return datetime.strptime(" ".join(t), time_format)
    
    
    @printinfo
    def create_snapshot_from_volume(self, volume, wait_on_progress=40, poll_interval=10, timeout=0, description=""):
        """
        Create a new EBS snapshot from an existing volume then wait for it to go to the created state.
        By default will poll for poll_count.  If wait_on_progress is specified than will wait on "wait_on_progress"
        overrides # of poll_interval periods, using wait_on_progress # of periods of poll_interval length in seconds
        w/o progress before failing. If volume.id is passed, euvolume data will not be transfered to snapshot created. 

        :param volume_id: (mandatory string) Volume id of the volume to create snapshot from
        :param wait_on_progress:(optional integer) # of poll intervals to wait while 0 progress is made before exiting,
         overrides "poll_count" when used
        :param poll_interval: (optional integer) time to sleep between polling snapshot status
        :param timeout: (optional integer) over all time to wait before exiting as failure
        :param description:  (optional string) string used to describe the snapshot
        :return: EuSnapshot
        """
        return self.create_snapshots(volume, count=1, mincount=1, eof=True, wait_on_progress=wait_on_progress,
                                     poll_interval=poll_interval, timeout=timeout, description=description)[0]
        
        
    @printinfo
    def create_snapshot(self, volume_id, wait_on_progress=40, poll_interval=10, timeout=0, description=""):
        """
        Create a new single EBS snapshot from an existing volume id then wait for it to go to the created state.
        By default will poll for poll_count.  If wait_on_progress is specified than will wait on "wait_on_progress"
        overrides # of poll_interval periods, using wait_on_progress # of periods of poll_interval length in seconds
        w/o progress before failing. If volume.id is passed, euvolume data will not be transfered to snapshot created. 

        :param volume_id: (mandatory string) Volume id of the volume to create snapshot from
        :param wait_on_progress:(optional integer) # of poll intervals to wait while 0 progress is made before exiting,
         overrides "poll_count" when used
        :param poll_interval: (optional integer) time to sleep between polling snapshot status
        :param timeout: (optional integer) over all time to wait before exiting as failure
        :param description:  (optional string) string used to describe the snapshot
        :return: EuSnapshot
        """
        snapshots = self.create_snapshots_from_vol_id(volume_id, count=1, mincount=1, eof=True,
                                                      wait_on_progress=wait_on_progress, poll_interval=poll_interval,
                                                      timeout=timeout, description=description)
        if len(snapshots) == 1:
            return snapshots[0]
        else:
            raise Exception("create_snapshot: Expected 1 snapshot, got '"+str(len(snapshots))+"' snapshots")
    
    
    @printinfo
    def create_snapshots_from_vol_id(self,
                                     volume_id,
                                     count=1,
                                     mincount=None,
                                     eof=True,
                                     delay=0,
                                     wait_on_progress=40,
                                     poll_interval=10,
                                     timeout=0,
                                     description=""):
        """
        Create a new EBS snapshot from an existing volume' string then wait for it to go to the created state.
        By default will poll for poll_count.  If wait_on_progress is specified than will wait on "wait_on_progress"
        overrides # of poll_interval periods, using wait_on_progress # of periods of poll_interval length in seconds
        w/o progress before failing

        :param volume_id: (mandatory string) Volume id of the volume to create snapshot from
        :parram count: (optional Integer) Specify how many snapshots to attempt to create
        :param mincount: (optional Integer) Specify the min success count, defaults to 'count'
        :param eof: (optional boolean) End on failure.If true will end on first failure, otherwise will continue to try
         and fufill mincount
        :param wait_on_progress:(optional integer) # of poll intervals to wait while 0 progress is made before exiting,
         overrides "poll_count" when used
        :param poll_interval: (optional integer) time to sleep between polling snapshot status
        :param timeout: (optional integer) over all time to wait before exiting as failure
        :param description:  (optional string) string used to describe the snapshot
        :return: EuSnapshot list
        """
        if isinstance(volume_id, Volume):
            raise Exception('Expected volume.id got Volume, try create_snapshots or create_snapshot_from_volume methods instead')
        volume = EuVolume.make_euvol_from_vol(self.get_volume(volume_id), tester=self)
        return self.create_snapshots(volume,
                                     count=count, mincount=mincount, eof=eof, delay=delay,
                                     wait_on_progress=wait_on_progress, poll_interval=poll_interval,
                                     timeout=timeout, description=description)



    @printinfo
    def create_snapshots(self, 
                         volume, 
                         count=1, 
                         mincount=None, 
                         eof=True, 
                         delay=0, 
                         wait_on_progress=40,
                         poll_count=48,
                         poll_interval=10, 
                         timeout=0, 
                         monitor_to_completed=True,
                         delete_failed = True, 
                         description="Created by nephoria"):
        """
        Create a new EBS snapshot from an existing volume then wait for it to go to the created state.
        By default will poll for poll_count.  If wait_on_progress is specified than will wait on "wait_on_progress"
        overrides # of poll_interval periods, using wait_on_progress # of periods of poll_interval length in seconds
        w/o progress before failing

        :param volume: (mandatory Volume object) Volume to create snapshot from
        :parram count: (optional Integer) Specify how many snapshots to attempt to create
        :param mincount: (optional Integer) Specify the min success count, defaults to 'count'
        :param eof: (optional boolean) End on failure.
                    If true will end on first failure, otherwise will continue to try and fufill mincount
        :param wait_on_progress: (optional integer) # of poll intervals to wait while 0 progress is made before exiting,
                                 overrides "poll_count" when used
        :param poll_interval: (optional integer) time to sleep between polling snapshot status
        :param monitor_to_completed: (optional boolean) If true will monitor created snapshots to the completed state,
                                     else return a list of created snaps
        :param timeout: (optional integer) over all time to wait before exiting as failure
        :param delete_failed: (optional boolean) automatically delete failed volumes
        :param description: (optional string) string used to describe the snapshot
        :return: EuSnapshot list
        """
        #Fix EuSnapshot for isinstance() use later...
        if not hasattr(volume, 'md5'):
            volume = EuVolume.make_euvol_from_vol(volume,tester= self)
        volume_id = volume.id
        snapshots = []
        retlist = []
        failed = []
        mincount = mincount or count
        if mincount > count:
            raise Exception('Mincount can not be greater than count')
        if wait_on_progress > 0:
            poll_count = wait_on_progress
        last_progress = 0
        elapsed = 0
        polls = 0
        self.log.debug('Create_snapshots count:'+str(count)+", mincount:"+str(mincount)+', wait_on_progress:'+
                    str(wait_on_progress)+",eof:"+str(eof))
        for x in xrange(0,count):
            try:
                start = time.time()
                snapshot = self.connection.create_snapshot(volume_id, description=str(description))
                cmdtime = time.time()-start
                if snapshot:
                    self.log.debug("Attempting to create snapshot #"+str(x)+ ", id:"+str(snapshot.id))
                    snapshot = EuSnapshot().make_eusnap_from_snap(snapshot, tester=self ,cmdstart=start)
                    #Append some attributes for tracking snapshot through creation and test lifecycle.
                    snapshot.eutest_polls = 0
                    snapshot.eutest_poll_count = poll_count
                    snapshot.eutest_last_progress = 0
                    snapshot.eutest_failmsg = "FAILED"
                    snapshot.eutest_laststatus = None
                    snapshot.eutest_timeintest = 0
                    snapshot.eutest_createorder = x
                    snapshot.eutest_cmdtime = "{0:.2f}".format(cmdtime)
                    snapshot.eutest_volume_md5 = volume.md5
                    snapshot.eutest_volume_md5len = volume.md5len
                    snapshot.eutest_volume_zone = volume.zone
                    
                    snapshot.update()
                    if description and (not re.match(str(snapshot.description), str(description)) ):
                        raise Exception('Snapshot Description does not match request: Snap.description:"'+
                                        str(snapshot.description)+'" -vs- "'+str(description)+'"')

                    if snapshot:
                        snapshots.append(snapshot)
            except Exception, e:
                self.log.debug("Caught exception creating snapshot,eof is False, continuing. Error:"+str(e))
                if eof:
                    if delete_failed:
                        try:
                            self.delete_snapshots(snapshots)
                        except: pass
                    raise e
                else:
                    failed.append(snapshot)
                    #Check to see if our min count of snapshots succeeded, we allow this for specific nephoria_unit_tests.
                    #If not clean up all snapshots from this system created from this operation
                    if (count - len(failed)) > mincount:
                        if delete_failed: 
                            snapshots.extend(failed)
                            try:
                                self.delete_snapshots(snapshots)
                            except:pass
                            raise Exception('Failed to created mincount('+str(mincount)+
                                            ') number of snapshots from volume:'+str(volume_id))
            #If a delay was given, wait before next snapshot gets created
            if delay:
                time.sleep(delay)
        #If we have failed snapshots,
        # but still met our minimum clean up the failed and continue (this might be better as a thread?)...
        if failed and delete_failed:
                try:
                    self.delete_snapshots(failed)
                except: pass
        #Pass the list of created snapshots to monitor method if state was not None,
        # otherwise just return the list of newly created
        #snapshots. 
        if monitor_to_completed:
            snapshots = self.monitor_eusnaps_to_completed(snapshots, 
                                                        mincount=mincount, 
                                                        eof=eof, 
                                                        wait_on_progress=wait_on_progress, 
                                                        poll_interval=poll_interval, 
                                                        timeout=timeout, 
                                                        delete_failed=delete_failed
                                                        )
        return snapshots
        
        
    @printinfo
    def monitor_eusnaps_to_completed(self,
                                     snaps,
                                     mincount=None, 
                                     eof=True,
                                     wait_on_progress=40,
                                     poll_count=48,
                                     poll_interval=10, 
                                     timeout=0,
                                     monitor_to_progress = None,
                                     delete_failed=True ):
        """
        Monitor an EBS snapshot list for snapshots to enter the to the completed state.
        By default will poll for poll_count.  If wait_on_progress is specified than will wait on "wait_on_progress"
        overrides # of poll_interval periods, using wait_on_progress # of periods of poll_interval length in seconds
        w/o progress before failing

        :param snaps: list of eusnapshots to monitor
        :param mincount: (optional Integer) Specify the min success count, defaults to length of list provided
        :param eof: (optional boolean) End on failure.If true will end on first failure,
                    otherwise will continue to try and fufill mincount
        :param wait_on_progress: (optional integer) # of poll intervals to wait while 0 progress is made before exiting,
                                 overrides "poll_count" when used
        :param poll_interval: (optional integer) time to sleep between polling snapshot status
        :param timeout: (optional integer) over all time to wait before exiting as failure
        :param monitor_to_progress (optional integer): will consider the monitor successful and exit when the snapshot's
                                                        progress is >= this value
        :param delete_failed: (optional boolean) automatically delete failed volumes
        :return: EuSnapshot list
        """
              
        failed = []
        retlist = []
        elapsed = 0
        self.log.debug("Monitor_snapshot_to_completed starting...")
        mincount = mincount or len(snaps)
        if mincount > len(snaps):
            raise Exception('Mincount can not be greater than count')
        if wait_on_progress > 0:
            poll_count = wait_on_progress
        last_progress = 0
        monitor_start = time.time()
        for snap in snaps:
            if not isinstance(snap, EuSnapshot):
                raise Exception("object not of type EuSnapshot. Found type:"+str(type(snap)))
        snapshots = copy.copy(snaps)      
        for snap in snapshots:
            if not snap.eutest_polls:
                snap.eutest_poll_count = poll_count
        
        self.log.debug('Waiting for '+str(len(snapshots))+" snapshots to go to completed state...")
        
        while (timeout == 0 or elapsed <= timeout) and snapshots:
            self.log.debug("Waiting for "+str(len(snapshots))+" snapshots to complete creation")
            for snapshot in snapshots:
                try:
                    snapshot.eutest_polls += 1
                    snapshot.update()
                    snapshot.eutest_laststatus = snapshot.status
                    if snapshot.status == 'failed':
                        raise Exception(str(snapshot) + " failed after Polling("+str(snapshot.eutest_polls)+
                                        ") ,Waited("+str(elapsed)+" sec), last reported (status:" + snapshot.status+
                                        " progress:"+snapshot.progress+")")
                    curr_progress = int(snapshot.progress.replace('%',''))
                    #if progress was made, then reset timer 
                    if (wait_on_progress > 0) and (curr_progress > snapshot.eutest_last_progress):
                        snapshot.eutest_poll_count = wait_on_progress
                    else: 
                        snapshot.eutest_poll_count -= 1
                    snapshot.eutest_last_progress = curr_progress
                    elapsed = int(time.time()-monitor_start)
                    if snapshot.eutest_poll_count <= 0:
                        raise Exception("Snapshot did not make progress for "+str(wait_on_progress)+" polls, after "+
                                        str(elapsed)+" seconds")
                    self.log.debug(str(snapshot.id)+", Status:"+snapshot.status+", Progress:"+snapshot.progress+
                               ", Polls w/o progress:"+str(wait_on_progress-snapshot.eutest_poll_count)+"/"+
                               str(wait_on_progress)+", Time Elapsed:"+str(elapsed)+"/"+str(timeout))
                    if snapshot.status == 'completed':
                        self.log.debug(str(snapshot.id)+" created after " + str(elapsed) + " seconds. Status:"+
                                   snapshot.status+", Progress:"+snapshot.progress)
                        self.test_resources["snapshots"].append(snapshot)
                        snapshot.eutest_timeintest = elapsed
                        snapshot.eutest_failmsg ='SUCCESS'
                        retlist.append(snapshot)
                        snapshots.remove(snapshot)
                    if monitor_to_progress and (curr_progress >=  monitor_to_progress):
                        self.log.debug(str(snapshot.id)+" reached designated monitor state after " + str(elapsed) + " seconds. Status:"+
                                   snapshot.status+", Progress:"+snapshot.progress)
                        self.test_resources["snapshots"].append(snapshot)
                        snapshot.eutest_timeintest = elapsed
                        retlist.append(snapshot)
                        snapshots.remove(snapshot)
                except Exception, e:
                    tb = get_traceback()
                    errbuf = '\n' + str(tb) + '\n' + str(e)
                    self.log.debug("Exception caught in snapshot creation, snapshot:"+str(snapshot.id)+".Err:"+str(errbuf))
                    if eof:
                        #If exit on fail, delete all snaps and raise exception
                        self.delete_snapshots(snapshots)
                        raise e
                    else:
                        snapshot.eutest_failmsg = str(e)
                        snapshot.eutest_timeintest = elapsed
                        failed.append(snapshot)
                        snapshots.remove(snapshot)
            elapsed = int(time.time()-monitor_start)
            if snapshots:
                time.sleep(poll_interval)
        for snap in snapshots:
            snapshot.eutest_failmsg = "Snapshot timed out in creation after "+str(elapsed)+" seconds"
            snapshot.eutest_timeintest = elapsed
            failed.append(snapshot)
            snapshots.remove(snapshot)
        #If delete_failed flag is set, delete the snapshots believed to have failed...
        if delete_failed:
                try:
                   self.delete_snapshots(failed)
                except: pass
        #join the lists again for printing debug purposes, retlist should only contain snaps believed to be good
        snapshots = copy.copy(retlist)
        snapshots.extend(failed)
        #Print the results in a formated table
        self.show_snapshots(snapshots)
        #Check for failure and failure criteria and return 
        self.test_resources['snapshots'].extend(snapshots)
        if failed and eof:
            raise(str(len(failed))+' snapshots failed in create, see debug output for more info')
        if len(retlist) < mincount:
            raise('Created '+str(len(retlist))+'/'+str(mincount)+
                  ' snapshots is less than provided mincount, see debug output for more info')
        return retlist
    
    
    def get_snapshot(self,snapid=None):
        snaps = self.get_snapshots(snapid=snapid, maxcount=1)
        if snaps:
            return snaps[0]
        else:
            return None
    
    
    
    @printinfo   
    def get_snapshots(self,
                      snapid=None,
                      volume_id=None,
                      volume_size=None,
                      volume_md5=None,
                      filters=None,
                      maxcount=None,
                      owner_id=None):
        """

        :param snapid: string, snapshot id to use as filter
        :param volume_id: string, volume id to use as filter
        :param volume_size: int size of volume snap'd to use as filter
        :param volume_md5: string md5 checksum of vol snap'd to use as filter
        :param maxcount: int max number of snaps to match before returning list
        :param owner_id: string owner id to use as filter
        :return: list of snapshots found
        """
        retlist = []
        #Start by comparing resources the current test obj is tracking to see if they are still in sync with the system
        snapshots = copy.copy(self.test_resources['snapshots'])
        snapshot_list = []
        if snapid:
            snapshot_list.append(snapid)
        ec2_snaps =  self.connection.get_all_snapshots(snapshot_ids=snapshot_list, filters=filters,
                                                       owner=owner_id)
        for snap in ec2_snaps:
            if snap not in snapshots:
                snapshots.append(snap)
        for snap in snapshots:
            if not snap in ec2_snaps:
                self.log.debug('Snapshot:'+str(snap.id)+' no longer found on system')
            if not hasattr(snap,'eutest_volume_md5'):
                snap = EuSnapshot.make_eusnap_from_snap(snap, tester=self)
            self.log.debug("Checking snap:"+str(snap.id)+" for match...")
            if volume_id and snap.volume_id != volume_id:
                continue
            if volume_size and snap.volume_size != volume_size:
                continue
            if volume_md5 and snap.eutest_volume_md5 != volume_md5:
                continue
            retlist.append(snap)
            if maxcount and (len(retlist) >= maxcount):
                return retlist
        self.log.debug("Found "+str(len(retlist))+" snapshots matching criteria")
        return retlist
    
    
    @printinfo
    def delete_snapshots(self,
                         snapshots, 
                         valid_states='completed,failed', 
                         base_timeout=60, 
                         add_time_per_snap=10, 
                         wait_for_valid_state=120,
                         poll_interval=10, 
                         eof=False):
        """
        Delete a list of snapshots.

        :param snapshots: List of snapshot IDs
        :param valid_states: Valid status for snapshot to
                             enter (Default: 'completed,failed')
        :param base_timeout: Timeout for waiting for poll interval
        :param add_time_per_snap: Amount of time to add to base_timeout
                                  per snapshot in the list
        :param wait_for_valid_state: How long to wait for a valid state to
                                     be reached before attempting delete, as
                                     some states will reject a delete request.
        :param poll_interval: Time to wait between checking the snapshot states
        :param eof: Whether or not to call an Exception() when first
                    failure is reached
        :raise:
        """
        snaps = copy.copy(snapshots)
        delete_me = []
        start = time.time()
        elapsed = 0
        valid_delete_states = str(valid_states).split(',')
        if not valid_delete_states:
            raise Exception("delete_snapshots, error in valid_states "
                            "provided:" + str(valid_states))

        #Wait for snapshot to enter a state that will accept the deletion action, before attempting to delete it...
        while snaps and (elapsed < wait_for_valid_state):
            elapsed = int(time.time()-start)
            check_state_list = copy.copy(snaps)
            for snap in check_state_list:
                try:
                    snap_id = self.get_snapshot(snap.id)
                    if not snap_id:
                        self.log.debug("Get Snapshot not found, assuming it's "
                                   "already deleted:" + str(snap.id))
                        delete_me.append(snap)
                        break
                except EC2ResponseError as ec2e:
                    if ec2e.status == 400:
                        self.log.debug("Get Snapshot not found, assuming it's "
                                   "already deleted:" + str(snap.id) +
                                   ", err:" + str(ec2e))
                        delete_me.append(snap)
                else:
                    snap.update()
                    self.log.debug("Checking snapshot:" + str(snap.id) +
                               " status:"+str(snap.status))
                    for v_state in valid_delete_states:
                        v_state = str(v_state).rstrip().lstrip()
                        if snap.status == v_state:
                            delete_me.append(snap)
                            try:
                                snap.delete()
                            except EC2ResponseError as ec2e:
                                self.log.debug("Snapshot not found, assuming "
                                           "it's already deleted:" +
                                           str(snap.id))
                                delete_me.append(snap)
                            break
            for snap in delete_me:
                if snap in snaps:
                    snaps.remove(snap)
            if snaps:
                buf = "\n-------| WAITING ON " + str(len(snaps)) + \
                      " SNAPSHOTS TO ENTER A DELETE-ABLE STATE:(" + \
                      str(valid_states) + "), elapsed:" + str(elapsed) + \
                      '/' + str(wait_for_valid_state) + "|-----"
                for snap in snaps:
                    buf = buf + "\nSnapshot:"+str(snap.id) + ",status:" + \
                          str(snap.status)+", progress:"+str(snap.progress)
                self.log.debug(buf)
                self.log.debug('waiting poll_interval to recheck snapshots:' +
                           str(poll_interval) +' seconds')
                time.sleep(poll_interval)
        #Now poll all the snapshots which a delete() request was made for
        if snaps:
            buf = ""
            for snap in snaps:
                buf = buf+','+str(snap.id)
            msg = "Following snapshots did not enter a valid state(" + \
                  str(valid_states) + ") for deletion:" + str(buf)
            if eof:
                raise Exception(msg)
            else:
                self.log.debug(msg)
        start = time.time()
        elapsed = 0
        timeout= base_timeout + (add_time_per_snap*len(delete_me))
        # Wait for all snapshots in delete_me list to be deleted or timeout...
        while delete_me and (elapsed < timeout):
            self.log.debug('Waiting for remaining ' + str(int(len(delete_me))) +
                       ' snaps to delete...' )
            waiting_list = copy.copy(delete_me)
            for snapshot in waiting_list:
                get_snapshot = None
                try:
                    snapshot.update()
                    get_snapshot = self.connection.get_all_snapshots(snapshot_ids=[snapshot.id])
                except EC2ResponseError as ec2re:
                    self.log.debug("Snapshot not found, assuming "
                                           "it's already deleted:" +
                                           str(snapshot.id))
                if not get_snapshot or snapshot.status == 'deleted':
                    self.log.debug('Snapshot:'+str(snapshot.id)+" is deleted")
                    delete_me.remove(snapshot)
                    #snapshot is deleted remove it from test resources list
                    for testsnap in self.test_resources['snapshots']:
                        if snapshot.id == testsnap.id:
                            self.test_resources['snapshots'].remove(testsnap)
            if delete_me and (elapsed < timeout):
                time.sleep(poll_interval)
            elapsed = int(time.time()-start)
        # Record any snapshots not yet deleted as errors...
        if delete_me:
            buf = ""
            for snap in snaps:
                buf += "\nSnapshot:" + str(snap.id)+",status:" + \
                       str(snap.status) + ", progress:"+str(snap.progress) +\
                       ", elapsed:" + str(elapsed) + '/' + str(timeout)
            raise Exception("Snapshots did not delete within timeout:" +
                            str(timeout) + "\n" + str(buf))
                
             
        
    
    def delete_snapshot(self,snapshot,timeout=60):
        """
        Delete the snapshot object

        :param snapshot: boto.ec2.snapshot object to delete
        :param timeout: Time in seconds to wait for deletion
        """
        snapshot.delete()
        self.log.debug( "Sent snapshot delete request for snapshot: " + snapshot.id)
        return self.connection.delete_snapshots([snapshot], base_timeout=60)
    
    @printinfo
    def register_snapshot(self,
                          snapshot,
                          root_device_name="/dev/sda",
                          description="bfebs",
                          windows=False,
                          bdmdev=None,
                          name=None,
                          ramdisk=None,
                          kernel=None,
                          dot=True,
                          block_device_map=None):
        """Convience function for passing a snapshot instead of its id. See register_snapshot_by_id
        :param snapshot: Snapshot object to use as an image
        :param root_device_name: root device name to use when registering
        :param description: Description of image that will be registered
        :param windows: Is the image a Windows image
        :param bdmdev: Block device mapping
        :param name: Name to register the image as
        :param ramdisk: Ramdisk ID to use
        :param kernel: Kernel ID to use
        :param dot: Delete on terminate flag
        :param block_device_map: existing block device map to append snapshot block dev to
        """
        return self.register_snapshot_by_id( snap_id=snapshot.id,
                                             root_device_name=root_device_name,
                                             description=description,
                                             windows=windows,
                                             bdmdev=bdmdev,
                                             name=name,
                                             ramdisk=ramdisk,
                                             kernel=kernel,
                                             dot=dot,
                                             block_device_map=block_device_map)
    
    @printinfo
    def register_snapshot_by_id( self,
                                 snap_id,
                                 root_device_name="/dev/sda1",
                                 description="bfebs",
                                 windows=False,
                                 bdmdev=None,
                                 name=None,
                                 ramdisk=None,
                                 kernel=None,
                                 size=None,
                                 dot=True,
                                 block_device_map=None,
                                 custom_params=None):
        """
        Register an image snapshot

        :param snap_id: snapshot id
        :param root_device_name: root-device-name for image
        :param description: description of image to be registered
        :param windows: Is windows image boolean
        :param bdmdev: block-device-mapping device for image
        :param name: name of image to be registered
        :param ramdisk: ramdisk id
        :param kernel: kernel id (note for windows this name should be "windows")
        :param dot: Delete On Terminate boolean
        :param block_device_map: existing block device map to add the snapshot block dev type to
        :return: emi id of registered image
        """
        custom_params = custom_params or {}
        if bdmdev is None:
            bdmdev=root_device_name
        if name is None:
            name="bfebs_"+ snap_id
        if windows:
            custom_params['Platform'] = "windows"
            
        bdmap = block_device_map or BlockDeviceMapping()
        block_dev_type = BlockDeviceType()
        block_dev_type.snapshot_id = snap_id
        block_dev_type.delete_on_termination = dot
        block_dev_type.size = size
        bdmap[bdmdev] = block_dev_type
            
        self.log.debug("Register image with: snap_id:"+str(snap_id)+", root_device_name:"+str(root_device_name)+", desc:"+str(description)+
                   ", windows:"+str(windows)+", bdname:"+str(bdmdev)+", name:"+str(name)+", ramdisk:"+
                   str(ramdisk)+", kernel:"+str(kernel))
        image_id = self._register_image_custom_params(name=name, description=description, kernel_id=kernel, ramdisk_id=ramdisk,
                                           block_device_map=bdmap, root_device_name=root_device_name, **custom_params)
        self.log.debug("Image now registered as " + image_id)
        return image_id


    @printinfo
    def register_image( self,
                        image_location,
                        root_device_name=None,
                        description=None,
                        architecture=None,
                        virtualization_type=None,
                        platform=None,
                        bdmdev=None,
                        name=None,
                        ramdisk=None,
                        kernel=None,
                        custom_params=None):
        """
        Register an image based on the s3 stored manifest location

        :param image_location:
        :param root_device_name: root-device-name for image
        :param description: description of image to be registered
        :param bdmdev: block-device-mapping object for image
        :param name: name of image to be registered
        :param ramdisk: ramdisk id
        :param kernel: kernel id (note for windows this name should be "windows")
        :return: image id string
        """
        custom_params = custom_params or {}
        if platform:
             custom_params['Platform']= platform
        #Check to see if boto is recent enough to have this param...
        image_id = self._register_image_custom_params(name=name,
                                                      description=description,
                                                      kernel_id=kernel,
                                                      image_location=image_location,
                                                      ramdisk_id=ramdisk,
                                                      architecture=architecture,
                                                      virtualization_type=virtualization_type,
                                                      block_device_map=bdmdev,
                                                      root_device_name=root_device_name,
                                                      **custom_params)
        self.test_resources["images"].append(self.connection.get_all_images([image_id])[0])
        return image_id

    def delete_image(self, image, timeout=60):
        """
        Delete image by multiple deregistrations.

        :param timeout: int seconds to wait before failing operation
        :param image: boto image object to deregister
        :param delete: boolean, if True will attempt to deregister until removed/deleted, default:False
        """
        return self.deregister_image(image)

    def deregister_image(self, image):
        """
        Deregister an image.

        :param image: boto image object to deregister
        """
        gotimage = image
        self.log.debug("Deregistering image: " + str(image))
        try:
            gotimage = self.connection.get_all_images(image_ids=[image.id])[0]
        except IndexError, ie:
            raise Exception("deregister_image:" + str(image.id) + ", No image found in get_all_images.Error: ")
        except Exception, e:
            #should return [] if not found, exception indicates an error with the command maybe?
            tb = get_traceback()
            raise Exception(
                'deregister_image: Error attempting to get image:' + str(image.id) + ", err:" + str(tb) + '\n' + str(e))
        self.deregister_image(image.id)
        try:
            # make sure the image was removed (should throw an exception),if not make sure it is in the deregistered state
            # if it is still associated with a running instance'
            gotimage = self.connection.get_all_images(image_ids=[image.id])[0]
            # this will not be executed if image was removed
            if( gotimage.state != 'deregistered') :
                raise Exception('deregister_image: Error attempting to deregister image:' + str(image.id)  + '\n')
        except IndexError, ie:
            pass


    @printinfo
    def get_images(self,
                   emi=None,
                   name=None,
                   root_device_type=None,
                   root_device_name=None,
                   virtualization_type=None,
                   location=None,
                   state="available",
                   arch=None,
                   owner_id=None,
                   filters=None,
                   basic_image=None,
                   platform=None,
                   not_platform=None,
                   tagkey=None,
                   tagvalue=None,
                   max_count=None,
                   _args_dict=None):
        """
        Get a list of images which match the provided criteria.

        :param emi: Partial ID of the emi to return, defaults to the 'emi-" prefix to grab any
        :param root_device_type: example: 'instance-store' or 'ebs'
        :param root_device_name: example: '/dev/sdb'
        :param virtualization_type: example: 'hvm' or 'paravirtualized'
        :param location: partial on location match example: 'centos'
        :param state: example: 'available'
        :param arch: example: 'x86_64'
        :param owner_id: owners numeric id
        :param filters: standard filters
        :param basic_image: boolean, avoids returning windows, load balancer and service images
        :param not_platform: skip if platform string matches this string. Example: not_platform='windows'
        :param max_count: return after finding 'max_count' number of matching images
        :param _args_dict: dict which can be populated by annotation to give
                            insight into the args/kwargs this was called with
        :return: image id
        :raise: Exception if image is not found
        """

        ret_list = []
        if not filters:
            filters = {}
            if emi:
                filters['image-id'] = emi
            if name:
                filters['name'] = name
            if root_device_type:
                filters['root-device-type'] = root_device_type
            if root_device_name:
                filters['root-device-name'] = root_device_name
            if state:
                filters['state'] = state
            if virtualization_type:
                filters['virtualization-type'] = virtualization_type
            if arch:
                filters['architecture'] = arch
            if owner_id:
                filters['owner-id'] = owner_id
            if platform:
                filters['platform'] = platform
            if tagkey:
                filters['tag-key'] = tagkey
            if tagvalue:
                filters['tag-value'] = tagvalue

        # if emi is None and not platform:
        if basic_image is None and not _args_dict:
            # If a specific EMI was not provided, set some sane defaults for
            # fetching a test image to work with...
            basic_image = True
        if name is None:
             emi = ""
        if filters:
            self.log.debug('Using following filters for image request:"{0}"'.format(filters))
            images = self.connection.get_all_images(filters=filters)
        else:
            images = self.connection.get_all_images()
        self.log.debug("Got " + str(len(images)) + " total images " + str(emi) + ", now filtering..." )
        for image in images:
            if (re.search(emi, image.id) is None) and (re.search(emi, image.name) is None):
                continue
            if (root_device_type is not None) and (image.root_device_type != root_device_type):
                continue
            if (virtualization_type is not None):
                if hasattr(image, 'virtualization_type'):
                    if image.virtualization_type != virtualization_type:
                        continue
                else:
                    self.log.debug('Filter by virtualization type requested but not supported in this boto version?')
            if (root_device_name is not None) and (image.root_device_name != root_device_name):
                continue       
            if (state is not None) and (image.state != state):
                continue            
            if (location is not None) and (not re.search( location, image.location)):
                continue
            if (name is not None) and (image.name != name):
                continue
            if (arch is not None) and (image.architecture != arch):
                continue
            if (owner_id is not None) and (image.owner_id != owner_id):
                continue
            if basic_image:
                not_location = ["windows", "imaging-worker", "loadbalancer"]
                skip = False
                for loc in not_location:
                    if (re.search( str(loc), image.location)):
                        skip = True
                        break
                if skip:
                    continue
            if (not_platform is not None) and (image.platform == not_platform):
                continue
            self.log.debug("Returning image:"+str(image.id))
            ret_list.append(image)
            if max_count and len(ret_list) >= max_count:
                return ret_list
        if not ret_list:
            raise EC2ResourceNotFoundException("Unable to find an EMI")
        return ret_list


    @printinfo
    def get_emi(self,
                   emi=None,
                   name=None,
                   root_device_type=None,
                   root_device_name=None,
                   location=None,
                   state="available",
                   arch=None,
                   owner_id=None,
                   filters=None,
                   basic_image=True,
                   platform=None,
                   not_platform=None,
                   tagkey=None,
                   tagvalue=None,
                   _args_dict=None,
                   ):
        """
        Get an emi with name emi, or just grab any emi in the system. Additional 'optional' match criteria can be defined.

        :param emi: Partial ID of the emi to return, defaults to the 'emi-" prefix to grab any
        :param root_device_type: example: 'instance-store' or 'ebs'
        :param root_device_name: example: '/dev/sdb'
        :param location: partial on location match example: 'centos'
        :param state: example: 'available'
        :param arch: example: 'x86_64'
        :param owner_id: owners numeric id
        :param filters: standard filters, dict.
        :param basic_image: boolean, avoids returning windows, load balancer and service images
        :param not_platform: skip if platform string matches this string. Example: not_platform='windows'
        :param _args_dict: dict which can be populated by annotation to give
                            insight into the args/kwargs this was called with
        :return: image id
        :raise: Exception if image is not found
        """
        # If no criteria was provided for filter an image, use 'basic_image'
        # flag to provide some sane defaults
        if basic_image is None:
            if not _args_dict:
                basic_image = True
            else:
                basic_image = False
        if filters is None and emi is None and \
                        name is None and location is None:
            # Attempt to get a nephoria created image if it happens to meet
            # the other criteria provided. Otherwise remove filter and
            # return the image found without the imposed filters.
            filters={'tag-key':'nephoria-created'}
            try:
                return self.get_images(emi=emi,
                                   name=name,
                                   root_device_type=root_device_type,
                                   root_device_name=root_device_name,
                                   location=location,
                                   state=state,
                                   arch=arch,
                                   owner_id=owner_id,
                                   filters=filters,
                                   basic_image=basic_image,
                                   platform=platform,
                                   not_platform=not_platform,
                                   tagkey=tagkey,
                                   tagvalue=tagvalue,
                                   max_count=1)[0]
            except:
                filters = None
        return self.get_images(emi=emi,
                               name=name,
                               root_device_type=root_device_type,
                               root_device_name=root_device_name,
                               location=location,
                               state=state,
                               arch=arch,
                               owner_id=owner_id,
                               filters=filters,
                               basic_image=basic_image,
                               platform=platform,
                               not_platform=not_platform,
                               tagkey=tagkey,
                               tagvalue=tagvalue,
                               max_count=1)[0]


    
    def get_all_allocated_addresses(self,account_id=None):
        """
        Return all allocated addresses for a given account_id as boto.ec2.address objects

        :param account_id: account number to filter on
        :return: list of boto.ec2.address objects
        """
        self.log.debug("get_all_allocated_addresses...")
        account_id = account_id or self.connection.get_account_id()
        ret = []
        if account_id:
            account_id = str(account_id)
            addrs = self.connection.get_all_addresses()
            for addr in addrs:
                if addr.instance_id and re.search(account_id, str(addr.instance_id)):
                    ret.append(addr)
        return ret
    
    def get_available_addresses(self):
        """
        Get all available addresses

        :return: a list of all available boto.ec2.address
        """
        self.log.debug("get_available_addresses...")
        ret = []
        addrs = self.connection.get_all_addresses()
        for addr in addrs:
            if addr.instance_id and re.search(r"(available|nobody)", addr.instance_id):
                ret.append(addr)
        return ret


    def show_all_addresses_verbose(self, iam_connection=None, display=True):
        """
        Print table to debug output showing all addresses available to cloud admin using verbose filter
        """
        address_width = 20
        info_width = 64
        account_width = 24
        buf = ""
        line = ""
        header = "| " + str("PUBLIC IP").ljust(address_width) + " | " + str("ADDRESS INFO").ljust(info_width) + \
                 " | " + str("ACCOUNT NAME").ljust(account_width) + " | " + str("REGION") + "\n"
        longest = len(header)
        try:
            ad_list = self.connection.get_all_addresses(addresses='verbose')
            for ad in ad_list:
                account_name = ""
                adline = ""
                match = re.findall('\(arn:*.*\)', ad.instance_id)
                if match:
                    try:
                        match = match[0]
                        account_id = match.split(':')[4]
                        account_name = self.connection.get_all_accounts(account_id=account_id)[0]['account_name']
                    except:pass
                if ad.region:
                    region = ad.region.name
                adline = "| " + str(ad.public_ip ).ljust(address_width) + " | " + str(ad.instance_id).ljust(info_width) + \
                       " | " + str(account_name).ljust(account_width)  + " | " + str(region) + "\n"
                buf += adline
                if len(adline) > longest:
                    longest = len(adline)
        except Exception, e:
            tb = get_traceback()
            buf = str(tb) + "\n ERROR in show_all_addresses_verbose:" + str(e)
        for x in xrange(0,longest):
            line += "-"
        line += "\n"
        buf = "\n" + line + header + line + buf + line
        if not display:
            return buf
        self.log.info(buf)


    def allocate_address(self, domain=None):
        """
        Allocate an address for the current user

        :return: boto.ec2.address object allocated
        """
        try:
            self.log.debug("Attempting to allocate an address...")
            address = self.connection.allocate_address(domain=domain)
        except Exception, e:
            tb = get_traceback()
            err_msg = red('{0}\nUnable to allocate address, err: {1}'.format(tb, e))
            self.log.critical(str(err_msg))
            raise e
        self.log.debug("Allocated " + str(address))
        return address

    def associate_address(self, instance_id=None, public_ip=None,
                          allocation_id=None, network_interface_id=None,
                          private_ip_address=None, allow_reassociation=False,
                          dry_run=False, timeout=75, refresh_ssh=True):

        address = None
        instance = None
        if isinstance(instance_id, basestring):
            instance = self.get_instances(idstring=instance_id)[0]
        elif isinstance(instance_id, Instance):
            instance = instance_id
            instance_id = instance_id.id
        else:
            raise ValueError('associate_address(). Unknown type for instance:"{0}/{1}'
                             .format(instance_id, type(instance_id)))

        if isinstance(public_ip, Address):
            address = public_ip
            public_ip =  getattr(public_ip, 'public_ip', public_ip)
        elif isinstance(public_ip, basestring):
            address = self.connection.get_all_addresses(addresses=[public_ip])[0]

        allocation_id = getattr(address, 'allocation_id', None)
        old_ip = str(instance.ip_address)
        self.log.debug("Attemtping to associate {0} with {1}".format(public_ip, instance_id))
        self.show_addresses(addresses=address)
        try:
            self.connection.associate_address(instance_id=instance_id,
                                              public_ip=public_ip,
                                              allocation_id=allocation_id,
                                              network_interface_id=network_interface_id,
                                              private_ip_address=private_ip_address,
                                              allow_reassociation=allow_reassociation)
        except Exception, e:
            self.log.critical("{0}\nUnable to associate address: {1} with instance: {2}"
                                 .format(get_traceback(), public_ip, instance.id))
            raise e

        start = time.time()
        elapsed = 0
        ### Ensure address object holds correct instance value
        while not address.instance_id:
            if elapsed > timeout:
                raise Exception('Address:"{0}" never associated with instance: "{1}"'
                                .format(public_ip, instance_id))
            self.log.debug('Address {0} not attached to {1}. Attached to:"{2}"'
                           .format(str(address), instance.id, address.instance_id))
            self.log.debug('Sleeping for 5 seconds before re-checking association...')
            time.sleep(5)
            address = self.connection.get_all_addresses(addresses=[public_ip])[0]
            elapsed = int(time.time()-start)

        poll_count = 15
        ### Ensure instance gets correct address
        while str(instance.ip_address) not in str(address.public_ip):
            if elapsed > timeout:
                raise Exception('Address:"{0}" did not associate with instance:{1} after: {2} '
                                'seconds'.format(public_ip, instance_id, elapsed))
            self.log.debug('Instance {0} has IP {1} attached instead of {2}'
                           .format(instance.id, instance.ip_address, address.public_ip) )
            time.sleep(5)
            instance.update()
            elapsed = int(time.time()-start)
            self.log.debug('Associated IP successfully old_ip: "{0}", new_ip: "{1}"'
                           .format(old_ip, instance.ip_address))
        self.log.debug('Address: {0} associated with instance:{1}.'
                       .format(address.public_ip, instance.ip_address))
        if refresh_ssh:
            if isinstance(instance, EuInstance) or isinstance(instance, WinInstance):
                time.sleep(5)
                instance.update()
                self.log.debug('Refreshing EuInstance: {0} ssh connection to associated addr: {1}'
                               .format(instance.id, instance.ip_address))
                instance.connect_to_instance()
            else:
                self.log.debug('WARNING: associate_address called with refresh_ssh set to '
                               'true, but instance is not EuInstance type:'+str(instance.id))
        self.log.debug('Associate address:{0} instance:{1} success'.format(public_ip, instance_id))
        self.show_addresses(addresses=address)


    def disassociate_address_from_instance(self, instance, timeout=75):
        """
        Disassociate address from instance and ensure that it no longer holds the IP

        :param instance: An instance that has an IP allocated
        :param timeout: Time in seconds to wait for address to disassociate
        :raise:
        """
        self.log.debug("disassociate_address_from_instance: instance.ip_address:" +
                   str(instance.ip_address) + " instance:" + str(instance))
        ip=str(instance.ip_address)
        address = self.connection.get_all_addresses(addresses=[instance.ip_address])[0]
        self.show_addresses(address)
        
        start = time.time()
        elapsed = 0
      
        address = self.connection.get_all_addresses(addresses=[address.public_ip])[0]
        ### Ensure address object hold correct instance value
        while address.instance_id and not re.match(instance.id, str(address.instance_id)):
            self.log.debug('Address {0} not attached to Instance "{1}" but rather Instance "{2}" after {3} seconds'.format(str(address), instance.id, address.instance_id, str(elapsed)) )
            if elapsed > timeout:
                raise Exception('Address ' + str(address) + ' never associated with instance after '+str(elapsed)+' seconds')
            address = self.connection.get_all_addresses(addresses=[address.public_ip])[0]
            time.sleep(5)
            elapsed = int(time.time()-start)
            
        
        self.log.debug("Attemtping to disassociate " + str(address) + " from " + str(instance.id))
        address.disassociate()
        
        start = time.time()
        ### Ensure instance gets correct address
        ### When private addressing is enabled the pub address should be equal to the priv address
        ### Otherwise we want to the pub address to be anything but its current and not the priv address
        while (not instance.private_addressing and instance.ip_address != address.public_ip and instance.ip_address != address.private_ip_address) or \
                (instance.private_addressing and instance.ip_address == instance.private_ip_address):
            self.log.debug('Instance {0} has IP "{1}" still using address "{2}" after {3} seconds'.format(instance.id, instance.ip_address, address.public_ip, str(elapsed)) )
            if elapsed > timeout:
                raise Exception('Address ' + str(address) + ' never disassociated with instance after '+str(elapsed)+' seconds')
            instance.update()
            time.sleep(5)
            elapsed = int(time.time()-start)
            address = self.connection.get_all_addresses(addresses=[address.public_ip])[0]
        address = self.connection.get_all_addresses(address.public_ip)
        self.show_addresses(address)
        self.log.debug("Disassociated IP successfully")

    def release_address(self, address):
        """
        Release all addresses or a particular IP

        :param address: Address object to release
        :raise: Exception when the address does not release
        """
        try:
            self.log.debug("Releasing address: " + str(address))
            address.release()
        except Exception, e:
            raise Exception("Failed to release the address: " + str(address) + ": " +  str(e))


    def check_device(self, device_path):
        """
        Used with instance connections. Checks if a device at a certain path exists

        :param device_path: Path to check
        :return: bool, if device was found
        """
        return self.found("ls -1 " + device_path, device_path)

    @printinfo
    def get_volumes(self, 
                    volume_id="vol-", 
                    status=None, 
                    attached_instance=None, 
                    attached_dev=None, 
                    snapid=None, 
                    zone=None,
                    filters=None,
                    minsize=1, 
                    maxsize=None,
                    md5=None, 
                    eof=False):
        """
        Return list of volumes that matches the criteria. Criteria options to be matched:

        :param volume_id: string present within volume id
        :param status: examples: 'in-use', 'creating', 'available'
        :param attached_instance: instance id example 'i-1234abcd'
        :param attached_dev: example '/dev/sdf'
        :param snapid: snapshot volume was created from example 'snap-1234abcd'
        :param zone: zone of volume example 'PARTI00'
        :param minsize: minimum size of volume to be matched
        :param maxsize: maximum size of volume to be matched
        :param eof: exception on failure to find volume, else returns empty list
        :return: List of volumes matching the filters provided
        :raise:
        """
        retlist = []
        if (attached_instance is not None) or (attached_dev is not None):
            status='in-use'
        volumes = self.connection.get_all_volumes(filters=filters)
        for volume in volumes:
            if not hasattr(volume,'md5'):
                volume = EuVolume.make_euvol_from_vol(volume, tester=self)
            if not re.match(volume_id, volume.id):
                continue
            if (snapid is not None) and (volume.snapshot_id != snapid):
                continue
            if (zone is not None) and (volume.zone != zone):
                continue
            if (status is not None) and (volume.status != status):
                continue
            if (md5 is not None) and hasattr(volume,'md5') and (volume.md5 != md5):
                continue
            if volume.attach_data is not None:
                if (attached_instance is not None) and ( volume.attach_data.instance_id != attached_instance):
                    continue
                if (attached_dev is not None) and (volume.attach_data.device != attached_dev):
                    continue
            if volume.size <  minsize:
                continue
            if maxsize is not None and volume.size > maxsize:
                continue
            if not hasattr(volume,'md5'):
                volume = EuVolume.make_euvol_from_vol(volume)
            retlist.append(volume)
        if eof and retlist == []:
            raise EC2ResourceNotFoundException("Unable to find matching volume")
        else:
            return retlist

    def get_volume(self,
                   volume_id="vol-",
                   status=None,
                   attached_instance=None,
                   attached_dev=None,
                   snapid=None,
                   zone=None,
                   minsize=1,
                   maxsize=None,
                   eof=True):
        """
        Return first volume that matches the criteria.

        :param volume_id: string present within volume id
        :param status: examples: 'in-use', 'creating', 'available'
        :param attached_instance: instance id example 'i-1234abcd'
        :param attached_dev: example '/dev/sdf'
        :param snapid: snapshot volume was created from example 'snap-1234abcd'
        :param zone: zone of volume example 'PARTI00'
        :param minsize: minimum size of volume to be matched
        :param maxsize: maximum size of volume to be matched
        :param eof: exception on failure to find volume, else returns None
        :return: List of volumes matching the filters provided
        :raise:
        """
        vol = None
        try:
            vol = self.get_volumes(volume_id=volume_id, status=status, attached_instance=attached_instance,
                                   attached_dev=attached_dev, snapid=snapid, zone=zone, minsize=minsize,
                                   maxsize=maxsize, eof=eof)[0]

        except Exception, e:
            if eof:
                raise e
        return vol

    @printinfo
    def run_instance(self,
                     image=None,
                     keypair=None,
                     group="default",
                     name=None,
                     type=None,
                     zone=None,
                     min=1,
                     max=1,
                     user_data=None,
                     private_addressing=False,
                     username="root",
                     password=None,
                     is_reachable=True,
                     monitoring_enabled=False,
                     timeout=600):
        """
        Run instance/s and wait for them to go to the running state

        :param image: Image object to use, default is pick the first emi found in the system
        :param keypair: Keypair name to use for the instances, defaults to none
        :param group: Security group name to apply to this set of instnaces, defaults to none
        :param type: VM type to use for these instances, defaults to m1.small
        :param zone: Availability zone to run these instances
        :param min: Minimum instnaces to launch, default 1
        :param max: Maxiumum instances to launch, default 1
        :param user_data: User-data string to pass to instance
        :param private_addressing: Runs an instance with only private IP address
        :param username: username to use when connecting via ssh
        :param password: password to use when connecting via ssh
        :param is_reachable: Instance can be reached on its public IP (Default=True)
        :param timeout: Time in seconds for instance to enter running state
        :return: Reservation object
        :raise:
        """
        if image is None:
            image = self.get_emi()
        if not isinstance(image, Image):
            image = self.get_emi(emi=str(image))
        if image is None:
            raise Exception("emi is None. run_instance could not auto find an emi?")
        if not user_data:
            user_data = self.enable_root_user_data
        if private_addressing is True:
            addressing_type = "private"
            is_reachable= False
        else:
            addressing_type = None
        #In the case a keypair object was passed instead of the keypair name
        if keypair:
            if isinstance(keypair, KeyPair):
                keypair = keypair.name

        if monitoring_enabled :
            enabled=True
        else:
            enabled=False
        start = time.time()
        
        self.log.debug( "Attempting to run "+ str(image.root_device_type)  +" image " + str(image) + " in group " + str(group))
        reservation = image.run(key_name=keypair,security_groups=[group],instance_type=type, placement=zone,
                                min_count=min, max_count=max, user_data=user_data, addressing_type=addressing_type,
                                monitoring_enabled=enabled)
        self.test_resources["instances"].append(reservation)
        
        if (len(reservation.instances) < min) or (len(reservation.instances) > max):
            fail = "Reservation:"+str(reservation.id)+" returned "+str(len(reservation.instances))+\
                   " instances, not within min("+str(min)+") and max("+str(max)+")"
        
        try:
            self.wait_for_reservation(reservation,timeout=timeout)
        except Exception, e:
            self.log.debug(get_traceback())
            self.log.critical("An instance did not enter proper running state in " + str(reservation) )
            self.log.critical("Terminatng instances in " + str(reservation))
            self.terminate_instances(reservation)
            raise Exception("Instances in " + str(reservation) + " did not enter proper state")
        
        for instance in reservation.instances:
            if instance.state != "running":
                self.log.critical("Instance " + instance.id + " now in " + instance.state  + " state  in zone: "  + instance.placement )
            else:
                self.log.debug( "Instance " + instance.id + " now in " + instance.state  + " state  in zone: "  + instance.placement )
            #    
            # check to see if public and private DNS names and IP addresses are the same
            #
            if (instance.ip_address == instance.private_ip_address) or \
                    (instance.ip_address == instance.private_ip_address) and \
                    ( private_addressing is False ):
                self.log.debug(str(instance) + " got Public IP: " + str(instance.ip_address)  + " Private IP: " +
                           str(instance.private_ip_address) + " Public DNS Name: " + str(instance.public_dns_name) +
                           " Private DNS Name: " + str(instance.private_dns_name))
                self.log.critical("Instance " + instance.id + " has he same public and private IPs of " + str(instance.ip_address))
            else:
                self.log.debug(str(instance) + " got Public IP: " + str(instance.ip_address)  + " Private IP: " +
                           str(instance.private_ip_address) + " Public DNS Name: " + str(instance.public_dns_name) +
                           " Private DNS Name: " + str(instance.private_dns_name))

            if not private_addressing:
                try:
                    self.wait_for_valid_ip(instance)
                except Exception, e:
                    tb = get_traceback()
                    ip_err = str(tb)  + "\nWARNING in wait_for_valid_ip: "+str(e)
                    self.log.debug(ip_err)
                    self.terminate_instances(reservation)
                    raise Exception("Reservation " +  str(reservation) + " has been terminated because instance " +
                                    str(instance) + " did not receive a valid IP")

            if is_reachable:
                ping(instance.ip_address, 20)

        ## Add name tag
        if name:
            self.create_tags([reservation.instances], {"Name:": name})
                
        #calculate remaining time to wait for establishing an ssh session/euinstance     
        timeout -= int(time.time() - start)
        #if we can establish an SSH session convert the instances to the test class euinstance for access to instance specific test methods
        if is_reachable:
            self.log.debug("Converting " + str(reservation) + " into euinstances")
            return self.convert_reservation_to_euinstance(reservation, username=username, password=password, private_addressing=private_addressing,
                                                          keyname=keypair, timeout=timeout)
        else:
            return reservation
        
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
                        eu_instance = EuInstance.make_euinstance_from_instance(
                            instance, self,
                            keypair=keypair,
                            password=password,
                            username=username,
                            do_ssh_connect=False,
                            timeout=timeout,
                            private_addressing=private_addressing,
                            reservation=reservation,
                            cmdstart=cmdstart)
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
    

    def create_network_interface_collection(self,
                                            eni=None,
                                            subnet_id=None,
                                            zone=None,
                                            device_index=None,
                                            associate_public_ip_address=None,
                                            eip=None,
                                            auto_eip=False,
                                            groups=None,
                                            eip_domain=None,
                                            description='Nephoria Test ENI',
                                            network_interface_collection=None):
        """
        Helper method for create network interfaces.
        :param eni: Existing Net Interface obj or id. If provided a new ENI will not be created.
        :param subnet_id: subnet or subnet.id, if not provided the method will attempt to look
                          for the default subnet in the zone provided.
        :param zone: zone, used to look up the subnet to be used.
        :param device_index: the device index to be used. If None this default to 0, or if a
                              network_infc_collection is provided this will use the next
                              available index.
        :param associate_public_ip_address: Used to request a public ip from the subnet.
                                            The cloud may reject this request if the dev index is
                                            not 0, and/or there a more than 1 interfaces in the
                                            network itfc collection.
        :param eip: An elastic ip obj or id to be associated with this ENI
        :param auto_eip: Bool, will attempt to allocate and associate an EIP with this ENI
        :param groups: list of security groups for this ENI
        :param eip_domain: domain for this ENI
        :param description: description for this ENI
        :param network_interface_collection: boto NetworkInterfaceCollection() object. If provided
                                             this eni will be appended to the collection
        :return: boto NetworkInterfaceSpecification() obj
        """
        # If the subnet was not provided attempt to find the default subnet.
        if device_index is None:
            if network_interface_collection:
                device_index = len(network_interface_collection)
            else:
                device_index = 0
        if isinstance(eni, basestring):
            eni = self.connection.get_all_network_interfaces([eni])
            if not eni:
                raise ValueError('Could not retrieve existing eni:"{0}" from system'.format(eni))
            eni = eni[0]
        if not eni:
            subnet = None
            if subnet_id:
                if isinstance(subnet, Subnet):
                    subnet = subnet_id
                elif isinstance(subnet_id, basestring):
                    subnets = self.get_all_subnets(subnet_id, zone=zone)
                    if subnets:
                        subnet = subnets[0]
                    else:
                        raise ValueError('Subnet: "{0}" not found using zone filter:"{1}" during '
                                         'create_eni'.format(subnet_id, zone))
                else:
                    raise ValueError('Unknown type for subnet_id: "{0}/{1}"'.format(subnet_id,
                                                                                    type(subnet_id)))
            else:
                self.log.debug('create_network_interface: No subnet provided, fetching default...')
                subnets = self.get_default_subnets(zone=zone)
                if subnets:
                    subnet = subnets[0]
            if not subnet:
                raise ValueError('Subnet not found (Either not provided, '
                                 'and/or default not found. Zone filter:"{0}")'.format(zone))
            subnet_id = subnet.id
            groups = groups or []
            security_group_ids = []
            # sanitize the groups param
            for group in groups:
                if isinstance(group, basestring):
                    security_group_ids.append(group)
                else:
                    security_group_ids.append(group.id)
            eni = self.connection.create_network_interface(subnet_id=subnet_id,
                                                           groups=security_group_ids,
                                                           description=description)
        # If an EIP was provided or requested associate it with the ENI now...
        if eip or auto_eip:
            if not eip:
                eip = self.allocate_address(domain=eip_domain)
            if not isinstance(eip, basestring):
                eip = eip.allocation_id
            assoc = self.connection.associate_address(allocation_id=eip,
                                                      network_interface_id=eni.id)
        # Create the interface specification
        interface = NetworkInterfaceSpecification(device_index=device_index,
                                                  network_interface_id=eni.id,
                                                  delete_on_termination=True,
                                                  associate_public_ip_address=associate_public_ip_address,
                                                  description=description)
        network_interface_collection = network_interface_collection or NetworkInterfaceCollection()
        network_interface_collection.append(interface)
        return network_interface_collection


    def show_network_interfaces(self, enis=None, printmethod=None, printme=True):
        id_h = 'ID'
        aid_h = 'ATTACH_ID'
        public_h = 'PUB IP'
        groups_h = 'SEC GRPS'
        subnet_h = 'SUBNET'
        vpc_h = 'VPC'
        priv_h = 'PRIV IPS'
        attach_h = 'ATTACHMENT'
        index_h = '#'
        dot_h = "DOT"
        inst_h = 'INST ID'
        status_h = 'STATUS'
        enis = enis or self.connection.get_all_network_interfaces()
        if isinstance(enis, basestring):
            enis = self.connection.get_all_network_interfaces(network_interface_ids=[enis])
        if isinstance(enis, list):
            fetch_list = []
            eni_list = []
            for eni in enis:
                if isinstance(eni, basestring):
                    fetch_list.append(eni)
                else:
                    eni_list.append(eni)
            if fetch_list:
                eni_list += self.connection.get_all_network_interfaces(
                    network_interface_ids=fetch_list)
            enis = eni_list
        pt = PrettyTable([id_h, public_h, vpc_h, subnet_h, groups_h, priv_h,
                          aid_h, inst_h, index_h, status_h, dot_h])
        pt.hrules = 1
        pt.padding_width = 0
        pt.max_width[groups_h] = 12
        pt.max_width[priv_h] = 16
        pt.align = 'l'
        for eni in enis:
            groups = "".join(x.id for x in (eni.groups or []))
            private_ips = ""
            for pi in (eni.private_ip_addresses or []):
                if pi.primary:
                    primary = "P"
                else:
                    primary = ""
                private_ips += "{0} {1}".format(primary, pi.private_ip_address).ljust(
                    pt.max_width[priv_h])
            attachment = ""
            instance_id = ""
            device_index = ""
            attach_status = ""
            dot = ""
            if eni.attachment:
                att = eni.attachment
                attachment = att.id
                instance_id = att.instance_id
                device_index = att.device_index
                attach_status = att.status
                if att.delete_on_termination:
                    dot = "T"
                else:
                    dot = "F"
            pt.add_row([eni.id, getattr(eni, 'publicIp', None), eni.vpc_id, eni.subnet_id, groups,
                        private_ips, attachment, instance_id, device_index, attach_status, dot])
        if printme:
            printmethod = printmethod or self.log.info
            printmethod("\n{0}\n".format(pt))
        else:
            return pt


    def wait_for_instances_block_dev_mapping(self,
                                             instances,
                                             poll_interval=1,
                                             timeout=60):
        waiting = copy.copy(instances)
        elapsed = 0
        good = []
        failed = []
        start = time.time()
        self.log.debug('wait_for_instance_block_dev_mapping started...')
        while waiting and (elapsed < timeout):
            elapsed = time.time() - start
            for instance in waiting:
                instance.update()
                for failed_state in ['terminated', 'stopped','stopping']:
                    if instance.state == failed_state:
                        failed.append(instance)
                        if instance in waiting:
                            waiting.remove(instance)
                if instance.root_device_type == 'ebs':
                    if instance.block_device_mapping and instance.block_device_mapping.current_value:
                        self.log.debug('Instance block device mapping is populated:'+str(instance.id))
                        self.update_resources_with_volumes_from_instance_block_device_mapping(instance)
                        good.append(instance)
                else:
                    good.append(instance)
                    self.print_block_device_map(instance.block_device_mapping)
            for instance in good:
                if instance in waiting:
                    waiting.remove(instance)
            if waiting:
                if not int(elapsed)%10:
                    for instance in waiting:
                        self.log.debug('Waiting for instance block device mapping to be populated:'+str(instance.id))
                time.sleep(poll_interval)
        failed.extend(waiting)
        if failed:
            err_buf = 'Instances failed to populate block dev mapping after '+str(elapsed)+'/'+str(timeout)+' seconds: '
            for instance in failed:
                err_buf += str(instance.id)+', current state:'+str(instance.state)+', '
            raise Exception(err_buf)
        self.log.debug('wait_for_instance_block_dev_mapping done. elapsed:'+str(elapsed))


    def update_resources_with_volumes_from_instance_block_device_mapping(self, instance):
        for device_name in instance.block_device_mapping:
            device = instance.block_device_mapping.get(device_name)
            if device.volume_id:
                try:
                    volume = self.get_volume(volume_id=device.volume_id)
                    if not volume in self.test_resources['volumes']:
                        self.test_resources['volumes'].append(volume)
                except Exception, e:
                    tb = get_traceback()
                    self.log.debug("\n" + str(tb) + "\nError trying to retrieve volume:" + str(device.volume_id) +
                               ' from instance:' + str(instance.id) + " block dev map, err:" + str(e))


    @printinfo 
    def monitor_euinstances_to_running(self, instances, poll_interval=10, timeout=480):
        """
        Monitor a list of instances to running state
        :param instances:
        :param poll_interval:
        :param timeout:
        :return: list of instanecs which successfully transitioned to running state
        :raise Exception:
        """
        timeout = int(timeout)
        if not isinstance(instances, types.ListType):
            instances = [instances]
        self.log.debug("("+str(len(instances))+") Monitor_instances_to_running starting...")
        ip_err = ""
        #Wait for instances to go to running state...
        self.monitor_euinstances_to_state(instances,
                                          failstates=['stopped', 'terminated','shutting-down'],
                                          timeout=timeout)
        #Wait for instances in list to get valid ips, check for duplicates, etc...
        try:
            self.wait_for_valid_ip(instances, timeout=timeout)
        except Exception, e:
            tb = get_traceback()
            ip_err = str(tb)  + "\nWARNING in wait_for_valid_ip: "+str(e)
            self.log.debug(ip_err)
        #Now attempt to connect to instances if connect flag is set in the instance...
        waiting = copy.copy(instances)
        good = []
        elapsed = 0
        start = time.time()
        self.log.debug("Instances in running state and wait_for_valid_ip complete, "
                          "attempting connections...")
        while waiting and (elapsed < timeout):
            self.log.debug("Checking "+str(len(waiting))+" instance ssh connections...")
            elapsed = int(time.time()-start)
            for instance in waiting:
                self.log.debug('Checking instance:'+str(instance.id)+" ...")
                if instance.auto_connect:
                    try:
                        if isinstance(instance, WinInstance):
                            #First try checking the RDP and WINRM ports for access...
                            self.log.debug(
                                'Do Security group rules allow winrm from this test machine:' +
                                 str(self.does_instance_sec_group_allow(instance,
                                                                        protocol='tcp',
                                                                        port=instance.winrm_port)))
                            self.log.debug(
                                'Do Security group rules allow winrm from this test machine:' +
                                str(self.does_instance_sec_group_allow(instance,
                                                                       protocol='tcp',
                                                                       port=instance.rdp_port)))
                            instance.poll_for_ports_status(timeout=1)
                            instance.connect_to_instance(timeout=15)
                            self.log.debug("Connected to instance:"+str(instance.id))
                            good.append(instance)
                        else:
                            #  First try ping
                            self.log.debug(
                                'Do Security group rules allow ping from this test machine:' +
                                 str(self.does_instance_sec_group_allow(instance,
                                                                        protocol='icmp',
                                                                        port=0)))
                            ping(instance.ip_address, 2)
                            #  now try to connect ssh or winrm
                            allow = "None"
                            try:
                                allow=str(self.does_instance_sec_group_allow(instance,
                                                                             protocol='tcp',
                                                                             port=22))
                            except:
                                pass
                            self.log.debug('Do Security group rules allow ssh from this '
                                              'test machine:' + str(allow))
                            instance.connect_to_instance(timeout=15)
                            self.log.debug("Connected to instance:"+str(instance.id))
                            good.append(instance)
                    except :
                        elapsed = int(time.time()-start)
                        err = ("instance {0} auto-connect. Time remaining before timeout:'{1}'. "
                               "ERROR:\n{2}".format(instance.id, (int(timeout)-int(elapsed)),
                                                    get_traceback()))
                        self.log.warn(err)
                        pass
                else:
                    good.append(instance)
            for instance in good:
                if instance in waiting:
                    waiting.remove(instance)
            elapsed = int(time.time()-start)
            if waiting and (elapsed < timeout):
                time.sleep(poll_interval)
            else:
                break
                
        if waiting:
            buf = "Following Errors occurred while waiting for instances:\n"
            buf += 'Errors while waiting for valid ip:'+ ip_err + "\n"
            buf += "Timed out waiting:'" + str(elapsed) + "/" + str(timeout) + \
                   "' to connect to the following instances:\n"
            for instance in waiting:
                buf += str(instance.id)+":"+str(instance.ip_address)+","
            raise RuntimeError(buf)
        self.show_instances(good)
        return good

    @printinfo
    def does_instance_sec_group_allow(self,
                                      instance,
                                      src_addr=None,
                                      src_group=None,
                                      protocol='tcp',
                                      port=22):
        if src_group:
            assert isinstance(src_group,SecurityGroup) , \
                'src_group({0}) not of type SecurityGroup obj'.format(src_group)
        s = None
        # self.log.debug("does_instance_sec_group_allow:"+str(instance.id)+" src_addr:"+str(src_addr))
        try:
            if not src_group and not src_addr:
                #Use the local test machine's addr
                if not self.local_machine_source_ip:
                    # Try to get the outgoing addr used to connect to this instance
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,socket.IPPROTO_UDP)
                    s.connect((instance.ip_address,1))
                    # set the tester's global source_ip, assuming it can re-used (at least until
                    # another method sets it to None again)
                    self.local_machine_source_ip = s.getsockname()[0]
                if self.local_machine_source_ip == "0.0.0.0":
                    raise Exception('Test machine source ip detected:' +
                                    str(self.local_machine_source_ip) +
                                    ', tester may need ec2_source_ip set manually')
                src_addr = self.local_machine_source_ip
            if src_addr:
                self.log.debug('Using src_addr:'+str(src_addr))
            elif src_group:
                self.log.debug('Using src_addr:'+str(src_addr))
            else:
                raise ValueError('Was not able to find local src ip')
            groups = self.get_instance_security_groups(instance)
            for group in groups:
                if self.does_sec_group_allow(group,
                                             src_addr=src_addr,
                                             src_group=src_group,
                                             protocol=protocol,
                                             port=port):
                    self.log.debug("Sec allows from test source addr: " +
                               str(src_addr) + ", src_group:" +
                               str(src_group) + ", protocol:" +
                               str(protocol) + ", port:" + str(port))
                    #Security group allows from the src/proto/port
                    return True
            #Security group does not allow from the src/proto/port
            return False
        except Exception, e:
            self.log.warning("{0}\nError in sec group check{1}".format(get_traceback(), e))
            raise e
        finally:
            if s:
                s.close()

    def get_security_group(self, name=None, id=None, vpc_id=None, verbose=None):
        """
         Adding this as both a convienence to the user to separate euare groups
         from security groups
        """
        # To allow easy updating of a group (since group.update() is not implemented at this time),
        # handle SecurityGroup arg type for either kwargs...
        if verbose is None:
            verbose = self._use_verbose_requests
        if not name and not id:
                raise ValueError('get_security_group needs either a name or an id')
        if verbose:
            names = ['verbose']
        else:
            names = []
        group_id = None
        group_name = None
        for group in [name, id]:
            if not group:
                continue
            ids = None
            if isinstance(group, SecurityGroup) or isinstance(id, BotoGroup):
                group_id = group.id
                group_name = group.name
                vpc_id = group.vpc_id
            elif re.match('^sg-\w{8}$',str(group).strip()):
                group_id = group
            elif isinstance(group, basestring):
                group_name = group
            else:
                raise ValueError('Could not find or format group arg for revoke. group:"{0}:{1}"'
                                 .format(group, type(group)))
            if group_id:
                break

        if group_id:
            ids = [group_id]
        if group_name:
            names.append(group_name)
        filters = {}
        if vpc_id:
            filters={'VpcId':vpc_id}
        groups = self.connection.get_all_security_groups(groupnames=names, group_ids=ids,
                                                         filters=filters)
        for group in groups:
            if not group_id or (group_id and group.id == group_id):
                if not group_name or (group_name and group.name == group_name):
                    self.log.debug('Found matching security group for name:' + str(name) +
                                   ' and id:' + str(id))
                    return group
        self.log.debug('No matching security group found for name:'+str(name)+' and id:'+str(id))
        return None
        
    @printinfo                    
    def does_sec_group_allow(self, group, src_addr=None, src_group=None,
                             protocol='tcp', port=22):
        """
        Test whether a security group will allow traffic from a specific 'src' ip address to
        a specific 'port' using a specific 'protocol'
        :param group: Security group obj to use in lookup
        :param src_addr: Source address to lookup against sec group rule(s)
        :param src_group: Boto sec group to use in auth check
        :param protocol: Protocol to lookup sec group rule against
        :param port: Network port to lookup sec group rule against
        """
        if src_group:
            assert isinstance(src_group, SecurityGroup)
        port = int(port)
        protocol = str(protocol).strip().lower()
        self.log.debug('Security group:' + str(group.name) + ", src ip:" +
                   str(src_addr) + ", src_group:" + str(src_group) +
                   ", proto:" + str(protocol) + ", port:" + str(port))
        group = self.get_security_group(id=group.id, name=group.name)
        for rule in group.rules:
            g_buf =""
            if str(rule.ip_protocol).strip().lower() == protocol:
                for grant in rule.grants:
                    g_buf += str(grant)+","
                self.log.debug("rule#{0}: ports:{1}-{2}, grants:{3}"
                           .format(str(group.rules.index(rule)),
                                   str(rule.from_port),
                                   str(rule.to_port),
                                   str(g_buf)))
                if rule.to_port is None:
                    to_port = -1
                else:
                    to_port= int(rule.to_port)
                if rule.from_port is  None:
                    from_port = -1
                else:
                    from_port = int(rule.from_port)

                if (to_port == 0 ) or (to_port == -1) or \
                        (port >= from_port and port <= to_port):
                    for grant in rule.grants:
                        if src_addr and grant.cidr_ip:
                            if is_address_in_network(src_addr, str(grant)):
                                self.log.debug('sec_group DOES allow: group:"{0}"'
                                           ', src:"{1}", proto:"{2}", port:"{3}"'
                                           .format(group.name,
                                                   src_addr,
                                                   protocol,
                                                   port))
                                return True
                        if src_group:
                            src_group_id = str(src_group.name) + \
                                           "-" + (src_group.owner_id)
                            if (src_group.id == grant.group_id ) or \
                                    ( grant.group_id == src_group_id ):
                                self.log.debug('sec_group DOES allow: group:"{0}"'
                                           ', src_group:"{1}"/"{2}", '
                                           'proto:"{3}", ''port:"{4}"'
                                           .format(group.name,
                                                   src_group.id,
                                                   src_group.name,
                                                   protocol,
                                                   port))
                                return True

        self.log.debug('sec_group:"{0}" DOES NOT allow from: src_ip:"{1}", '
                   'src_group:"{2}", proto:"{3}", port:"{4}"'
                   .format(group.name, src_addr, src_group, protocol, port))
        return False
                    
    def get_instance_security_groups(self,instance):
        """
        Definition: Look up and return all security groups this instance is referencing.

        :param instance: instance or euinstance object to
        :return:
        """
        secgroups = []
        groups = []
        if hasattr(instance, 'security_groups') and instance.security_groups:
            return instance.security_groups

        if hasattr(instance, 'groups') and instance.groups:
            groups = instance.groups
        else:
            if hasattr(instance, 'reservation') and instance.reservation:
                res = instance.reservation
            else:
                res = self.get_reservation_for_instance(instance)
            groups = res.groups
        for group in groups:
            secgroups.extend(self.connection.get_all_security_groups(
                groupnames=[str(group.name)]))
        return secgroups
    
    def get_reservation_for_instance(self, instance):
        """
        Definition: Lookup and return reservation obj for this instance

        :param instance: boto instance or euinstance obj to use for lookup
        :return: :raise:
        """
        if hasattr(self, 'get_all_reservations'):
            res = self.connection.get_all_reservations(instance_ids=instance.id)
            if res and isinstance(res, types.ListType):
                return res[0]
        for res in self.connection.get_all_instances():
            for inst in res.instances:
                if inst.id == instance.id:
                    if hasattr(instance,'reservation'):
                        instance.reservation = res
                    return res
        raise Exception('No reservation found for instance:' + str(instance.id))
    
    @printinfo    
    def monitor_euinstances_to_state(self,
                                     instance_list,
                                     state='running',
                                     min=None,
                                     poll_interval=10,
                                     failstates=[],
                                     timeout=120,
                                     eof=True):
        """

        :param instance_list: list of instances to monitor
        :param state: state to monitor to, expected state
        :param min: int min count of instances that need to succeed otherwise except out
        :param poll_interval: int number of seconds between polls for instance status
        :param timeout: time to wait before this method is considered to have failed
        :param eof: boolean to indicate whether or not to exit on first failure
        :return list of instances
        """
        self.log.debug('(' + str(len(instance_list)) + ") monitor_instances_to_state: '" + str(state) + "' starting....")
        monitor = []
        for instance in instance_list:
            if not isinstance(instance, EuInstance) and not isinstance(instance, WinInstance):
                instance = self.convert_instance_to_euinstance(instance, auto_connect=False)
            monitor.append(instance)
        good = []
        failed = []
        elapsed = 0
        start = time.time()
        failmsg = None
        pollinterval = 10
        failmsg = ""
        #If no min allowed successful instance count is given, set it to the length of the list provdied. 
        if min is None:
            min = len(instance_list)
        while monitor and elapsed < timeout:
            elapsed = int(time.time() - start)
            self.log.debug("\n------>Waiting for remaining "+str(len(monitor))+"/"+str(len(instance_list))+
                       " instances to go to state:"+str(state)+', elapsed:('+str(elapsed)+'/'+str(timeout)+")...")
            for instance in monitor:
                try:
                    instance.update()
                    bdm_root_vol_status = None
                    bdm_root_vol_id = None
                    if instance.root_device_type == 'ebs':
                        if not instance.bdm_root_vol:
                            try:
                                instance.bdm_root_vol = self.get_volume(volume_id = instance.block_device_mapping.get(instance.root_device_name).volume_id)
                                bdm_root_vol_id = instance.bdm_root_vol.id
                                bdm_root_vol_status = instance.bdm_root_vol.status
                            except: pass
                        else:
                            instance.bdm_root_vol.update()
                            bdm_root_vol_id = instance.bdm_root_vol.id
                            bdm_root_vol_status = instance.bdm_root_vol.status
                        if instance.laststate:
                            #fail fast on ebs backed instances that go into stopped stated unintentionally
                            if state != "stopped" and ( instance.laststate == 'pending' and instance.state == "stopped"):
                                raise Exception("Instance:"+str(instance.id)+" illegal state transition from "
                                                +str(instance.laststate)+" to "+str(instance.state))
                    dbgmsg = ("Intended state:" + str(state)+": "+str(instance.id)+' Current state:'+str(instance.state)+', type:'+
                              str(instance.root_device_type) + ', backing volume:'+str(bdm_root_vol_id)+' status:'+
                              str(bdm_root_vol_status)+", elapsed:"+ str(elapsed)+"/"+str(timeout))
                    if instance.state == state:
                        self.log.debug("SUCCESS "+ dbgmsg)
                        #This instance is in the correct state, remove from monitor list
                        good.append(instance)
                    else:
                        for failed_state in failstates:
                            if instance.state == failed_state:
                                raise Exception('FAILED STATE:'+ dbgmsg )

                    self.log.debug("WAITING for "+dbgmsg)
                except Exception, e:
                    failed.append(instance)
                    tb = get_traceback()
                    self.log.debug('FAILED: Instance:'+str(instance.id)+",err:"+str(e)+"\n"+str(tb))
                    if eof:
                        self.log.debug("EOF set to True, monitor_euinstances_to_state ending...")
                        raise e
                    if len(instance_list) - len(failed) > min:
                        self.log.debug('Failed instances has exceeded allowed minimum('+str(min)+") monitor_euinstances_to_state ending...")
                        raise e
                    else:
                        failmsg += str(e)+"\n"
                        
            #remove good instances from list to monitor
            for instance in good + failed:
                if instance in monitor:
                    monitor.remove(instance)
                    
            if monitor:
                time.sleep(poll_interval)
                
        self.show_instances(instance_list)
        if monitor:
            failmsg = "Some instances did not go to state:"+str(state)+' within timeout:'+str(timeout)+"\nFailed:"
            for instance in monitor:
                failed.append(instance)
                failmsg += str(instance.id)+","
            if eof:
                raise Exception(failmsg)
            if len(instance_list) - len(failed) > min:
                self.log.debug('Failed instances has exceeded allowed minimum('+str(min)+") monitor_euinstances_to_state ending...")
                raise Exception(failmsg)
            else:
                self.log.debug(failmsg)


    @printinfo
    def wait_for_valid_ip(self, instances, regex="0.0.0.0", poll_interval=10, timeout = 60):
        """
        Wait for instance public DNS name to clear from regex

        :param instances:
        :param private_addressing: boolean for whether instance has private addressing enabled
        :param poll_interval:
        :param instance: instance object to check
        :param timeout: Time in seconds to wait for IP to change
        :return: True on success
        :raise: Exception if IP stays at 0.0.0.0
        """
        #self.log.debug("wait_for_valid_ip: Monitoring instances for valid ips...")
        if not isinstance(instances, types.ListType):
            monitoring = [instances]
        else:
            monitoring = copy.copy(instances)
        elapsed = 0
        good = []
        start = time.time()
        zeros = re.compile(regex)
        while monitoring and (elapsed <= timeout):
            elapsed = int(time.time()- start)
            for instance in monitoring:
                instance.update()
                if hasattr(instance, 'ip_address') and instance.ip_address and \
                        (zeros.search(str(instance.ip_address)) or zeros.search(str(instance.private_ip_address))):
                    # Either public or private ip was still not populated
                    self.log.debug(str(instance.id)+": WAITING for public ip. Current:"+str(instance.ip_address)+
                               ", elapsed:"+str(elapsed)+"/"+str(timeout))
                else:
                    self.log.debug(str(instance.id)+": FOUND public ip. Current:"+str(instance.ip_address)+
                               ", elapsed:"+str(elapsed)+"/"+str(timeout))
                    good.append(instance)
            #clean up list outside of loop
            for instance in good:
                if instance in monitoring:
                    monitoring.remove(instance)
            if monitoring:
                time.sleep(poll_interval)
        if monitoring:
            buf = "Instances timed out waiting for a valid IP, elapsed:"+str(elapsed)+"/"+str(timeout)+"\n"
            for instance in instances:
                buf += "Instance: "+str(instance.id)+", public ip: "+str(instance.ip_address)+", private ip: "+str(instance.private_ip_address)+"\n"
            raise Exception(buf)
        self.check_system_for_dup_ip(instances=good)
        self.log.debug('Wait_for_valid_ip done')
                
    def check_system_for_dup_ip(self, instances=None):
        """
        Check system for instances with conflicting duplicate IPs.
        Will raise exception at end of iterating through all running, pending, or starting instances with info
        as to which instances and IPs conflict.
        If a list of instances is provided, all other conflicting IPS will be ignored and will only raise an exception
        for conflicts with the provided instance 'inst'

        :param instances: optional list, or subset of instances to use in duplicate search.
        """
        errbuf = ""
        publist = {}
        privlist = {}
        self.log.debug('Check_system_for_dup_ip starting...')
        reslist = self.connection.get_all_instances()
        for res in reslist:
            self.log.debug("Checking reservation: "+str(res.id))
            for instance in res.instances:
                self.log.debug('Checking instance '+str(instance.id).ljust(20)+', state:'+str(instance.state).ljust(20)+
                           ' pubip:'+str(instance.ip_address).ljust(20)+
                           ' privip:'+str(instance.private_ip_address).ljust(20))
                if instance.state == 'running' or instance.state == 'pending' or instance.state == 'starting':
                    if instance.ip_address != '0.0.0.0':
                        if instance.ip_address in publist:
                            errbuf += "PUBLIC:"+str(instance.id)+"/"+str(instance.state)+"="+\
                                      str(instance.ip_address)+" vs: "+\
                                      str(publist[instance.ip_address])+"\n"
                            if instances and (instance in instances):
                                raise Exception("PUBLIC:"+str(instance.id)+"/"+str(instance.state)+"="+
                                                str(instance.ip_address)+" vs: "+
                                                str(publist[instance.ip_address]))
                        else:
                            publist[instance.ip_address] = str(instance.id+"/"+instance.state)
                    if instance.private_ip_address != '0.0.0.0':
                        if instance.private_ip_address in privlist:
                            errbuf += "PRIVATE:"+str(instance.id)+"/"+str(instance.state)+"="+\
                                      str(instance.private_ip_address)+" vs: "+\
                                      str(privlist[instance.private_ip_address])+"\n"
                            if instances and (instance in instances):
                                raise Exception("PRIVATE:"+str(instance.id)+"/"+str(instance.state)+"="+
                                                str(instance.private_ip_address)+" vs: "+
                                                str(privlist[instance.private_ip_address]))
                        else:
                            privlist[instance.private_ip_address] = str(instance.id+"/"+instance.state)
        if not instances and errbuf:
            raise Exception("DUPLICATE IPs FOUND:"+errbuf)
        self.log.debug("Done with check_system_for_dup_ip")
        

    def convert_reservation_to_euinstance(self,
                                          reservation,
                                          username=None,
                                          password=None,
                                          keyname=None,
                                          private_addressing=False,
                                          timeout=60):
        """
        Convert all instances in an entire reservation into nephoria.euinstance.Euinstance objects.

        :param reservation: reservation object to use in conversion
        :param username: SSH user name of instance
        :param password: SSH password
        :param keyname: Private key file to use when connecting to the instance
        :param timeout: Time in seconds to wait for successful SSH connection
        :return:
        """
        euinstance_list = []
        keypair = None
        if keyname is not None:
                keypair = self.get_keypair(keyname)
        auto_connect = True
        if private_addressing:
            auto_connect = False
        for instance in reservation.instances:
            if keypair is not None or password is not None:
                try:
                    euinstance_list.append(
                        self.convert_instance_to_euinstance(instance,
                                                            keypair=keypair,
                                                            username = username,
                                                            password=password,
                                                            timeout=timeout,
                                                            auto_connect=auto_connect))
                except Exception, e:
                    self.log.debug(get_traceback())
                    euinstance_list.append(instance)
                    self.get_console_output(instance)
                    raise RuntimeError("Unable to create Euinstance from " + str(instance) +
                                       ": " + str(e))
            else:
                euinstance_list.append(instance)
        reservation.instances = euinstance_list
        return reservation

    def convert_instance_to_euinstance(self, instance, keypair=None,
                                       username=None, password=None,
                                       reservation=None, auto_connect=True,
                                       timeout=120):
        if isinstance(instance, basestring):
            ins = self.get_instances(idstring=instance)
            if ins:
                instance = ins[0]
            else:
                self.log.error('Could not find instance by id: ' + str(instance))
                return None
        if instance.platform == 'windows':
            username = username or 'Administrator'
            instance = WinInstance.make_euinstance_from_instance(
                instance,
                self,
                keypair=keypair,
                username = username,
                password=password,
                reservation=reservation,
                auto_connect=auto_connect,
                timeout=timeout)
        else:
            username = username or 'root'
            instance = EuInstance.make_euinstance_from_instance(instance, self,
                                                                keypair=keypair,
                                                                password=password,
                                                                username=username,
                                                                do_ssh_connect=auto_connect,
                                                                timeout=timeout,
                                                                reservation=reservation)
        if 'instances' in self.test_resources:
            for x in xrange(0, len(self.test_resources['instances'])):
                ins = self.test_resources['instances'][x]
                if ins.id == instance.id:
                     self.test_resources['instances'][x] = instance
        return instance



    def get_console_output(self, instance, dry_run=False, debug=True):
        """
        Retrieve console output from an instance

        :param instance:  Instance ID or Instance object
        :return: string
        :raise: Exception on failure to get console output
        """
        self.log.debug("Attempting to get console output from: " + str(instance))
        if isinstance(instance, Instance):
            instance = instance.id
        output = self.connection.get_console_output(instance_id=instance, dry_run=dry_run)
        if debug:
            self.log.debug(output.output)
        return output

    def get_zone_names(self):
        """
        Return a list of availability zone names.

        :return: list of zone names
        """
        zone_objects = self.connection.get_all_zones()
        zone_names = []
        for zone in zone_objects:
            zone_names.append(zone.name)
        return zone_names


    def get_zones(self, zone_name=None):
        zones = self.connection.get_all_zones(zones=zone_name)
        if not zones:
            return zones
        zone_names = ['verbose']
        if zone_name:
            zone_names.append(zone_name)
        verbose_zones = self.connection.get_all_zones(zones=zone_names)
        if len(zones) >= verbose_zones:
            self.log.warning('Failed to fetch zones with verbose option, '
                             'non-eucalyptus administrative account users may not be authorized '
                             'for this request. No vm slot availability info will be provided')
            return zones
        # the user had verbose zone information, parse it and add it to the zones.
        ret_list = []
        current_zone = None
        headers = []
        for zone in verbose_zones:
            z_name = str(zone.name)
            if not str(z_name).startswith("|-"):
                if current_zone:
                    ret_list.append(current_zone)
                current_zone = zone
                setattr(current_zone, 'available_vm_slots', {})
                order = 0
                continue
            elif current_zone:
                z_name = z_name.lstrip('|-').strip()
                if re.search('vm types', z_name):
                    # this is a header
                    headers = str(zone.state).replace("/", "").split()
                else:
                    # this is a vm_type
                    vm_dict = {'order': order}
                    info = str(zone.state).replace("/", "").split()
                    for x in xrange(0, len(info)):
                        vm_dict[headers[x]] = int(info[x])
                    current_zone.available_vm_slots[z_name] = vm_dict
                    order += 1
        if current_zone:
            ret_list.append(current_zone)
        return ret_list

    def get_available_vm_slots(self, vmtype, zone_name):
        zone = self.get_zones(zone_name=zone_name)[0]
        if not getattr(zone, 'available_vm_slots', None):
            raise EucaAdminRequired()
        vm_info = zone.available_vm_slots.get(vmtype)
        return int(vm_info.get('free'))

    def show_zone_availability(self, zone_name=None, print_me=True):
        zones = self.get_zones(zone_name=zone_name)
        main_pt = PrettyTable(['HEADER'])
        main_pt.max_width = 120
        main_pt.align = 'l'
        main_pt.header = False
        main_pt.border = False
        order_header = str('#').ljust(3)
        info_headers = ['VMTYPE'.ljust(16), 'FREE/MAX'.ljust(16), 'RAM'.ljust(10),
                        'CPU'.ljust(10), 'DISK'.ljust(10), order_header]

        if not zones:
            main_pt.add_row(['No zones to show using zone_name:' + str(zone_name)])
        for zone in zones:
            main_pt.add_row(
                [markup("ZONE: {0} AVAILABILE VM SLOTS:".format(zone.name),
                        markups=[1, 4, 33]).ljust(110)])
            if not hasattr(zone, 'available_vm_slots'):
                main_pt.add_row(['No zone info available, and/or available to this user'])
            else:
                info_pt = PrettyTable(info_headers)
                info_pt.align = "l"
                for vmtype, info_dict in zone.available_vm_slots.iteritems():
                    info_pt.add_row([vmtype,
                                     "{0}/{1}".format(info_dict.get('free'),
                                                      info_dict.get('max')),
                                     info_dict.get('ram'),
                                     info_dict.get('cpu'),
                                     info_dict.get('disk'),
                                     info_dict.get('order')])
                main_pt.add_row(["{0}\n".format(info_pt.get_string(sortby=order_header,
                                                                   fields=info_headers[:-1]))])
        if not print_me:
            return main_pt
        else:
            self.log.info("\n{0}\n".format(main_pt))




 
    @printinfo
    def get_instances(self,
                      idstring=None,
                      state=None,
                      reservation=None,
                      rootdevtype=None,
                      zone=None,
                      key=None,
                      pubip=None,
                      privip=None,
                      ramdisk=None,
                      kernel=None,
                      image_id=None,
                      verbose=None,
                      filters=None):
        """
        Return a list of instances matching the filters provided.

        :param state: str of desired state
        :param idstring: instance-id string
        :param reservation:  reservation-id
        :param rootdevtype: 'instance-store' or 'ebs'
        :param zone: Availablity zone
        :param key: Keypair the instance was launched with
        :param pubip: Instance public IP
        :param privip: Instance private IP
        :param ramdisk: Ramdisk ID string
        :param kernel: Kernel ID string
        :param image_id: Image ID string
        :param filters: dict filters
        :return: list of instances
        """
        ilist = []
        if verbose is None:
            verbose = self._use_verbose_requests
        if idstring:
            if isinstance(idstring, list):
                instance_ids = idstring
            else:
                instance_ids = [str(idstring)]
            if verbose:
                    instance_ids.append('verbose')
        else:
            if verbose:
                idstring = 'verbose'
            instance_ids = idstring
        
        reservations = self.connection.get_all_instances(instance_ids=instance_ids, filters=filters)
        for res in reservations:
            if ( reservation is None ) or (re.search(str(reservation), str(res.id))):
                for i in res.instances:
                    #if (idstring is not None) and (not re.search(idstring, i.id)) :
                    #   continue
                    if (state is not None) and (i.state != state):
                        continue
                    if (rootdevtype is not None) and (i.root_device_type != rootdevtype):
                        continue
                    if (zone is not None) and (i.placement != zone ):
                        continue
                    if (key is not None) and (i.key_name != key):
                        continue
                    if (pubip is not None) and (i.ip_address != pubip):
                        continue
                    if (privip is not None) and (i.private_ip_address != privip):
                        continue
                    if (ramdisk is not None) and (i.ramdisk != ramdisk):
                        continue
                    if (kernel is not None) and (i.kernel != kernel):
                        continue
                    if (image_id is not None) and (i.image_id != image_id):
                        continue
                    i.reservation = res
                    ilist.append(i)
        return ilist

        
    
    def get_connectable_euinstances(self,path=None,username=None, password=None, connect=True):
        """
        Convenience method, returns a list of all running instances, for the current creduser
        for which there are local keys at 'path'

        :param path: Path to look for private keys
        :param username: username to use if path is not pfassed
        :param password: password to use if path is not passed
        :param connect: bool, Whether to create an ssh connection to the instances
        :return:
        """
        try:
            euinstances = []
            keys = self.get_all_current_local_keys(path=path) or []
            for keypair in keys:
                self.log.debug('Looking for instances using keypair:'+keypair.name)
                instances = self.get_instances(state='running',key=keypair.name) or []
                for instance in instances:
                    if not connect:
                        keypair=None
                        euinstances.append(instance)
                    else:
                        euinstances.append(
                            self.convert_instance_to_euinstance(instance,
                                                                username=username,
                                                                password=password,
                                                                keypair=keypair ))
            return euinstances
        except Exception, e:
            traceback.print_exc()
            self.log.debug("Failed to find a pre-existing instance we can connect to:"+str(e))
            pass
    
    
    def get_all_attributes(self, obj, debug=True):
        """
        Get a formatted list of all the key pair values pertaining to the object 'obj'

        :param obj: Object to extract information from
        :param debug: Print key value pairs
        :return: Buffer of key value pairs
        """
        buf=""
        alist = sorted(obj.__dict__)
        for item in alist:
            if debug:
                print str(item)+" = "+str(obj.__dict__[item])
            buf += str(item)+" = "+str(obj.__dict__[item])+"\n"
        return buf
    

    def terminate_instances(self, reservation=None, dry_run=False, verbose=None, timeout=480):
        """
        Terminate instances in the system

        :param reservation: Reservation object to terminate all instances in, default is to terminate all instances
        :raise: Exception when instance does not reach terminated state
        """
        ### If a reservation is not passed then kill all instances
        aggregate_result = False
        instance_list = []
        monitor_list = []
        if verbose is None:
            verbose = self._use_verbose_requests
        if reservation and not isinstance(reservation, types.ListType):
            if isinstance(reservation, Reservation):
                instance_list = reservation.instances or []
            elif isinstance(reservation, Instance):
                instance_list.append(reservation)
            else:
                raise Exception('Unknown type:' + str(type(reservation)) + ', for reservation passed to terminate_instances')
        else:
            if reservation is None:
                if verbose:
                    reservation = self.connection.get_all_instances('verbose')
                else:
                    reservation = self.connection.get_all_instances()
            #first send terminate for all instances
            for res in reservation:
                if isinstance(res, basestring) and str(res).startswith('i'):
                    instance = self.get_instances(idstring=res)
                    if not instance:
                        raise ValueError('Instance not found by id:' + str(res))
                    instance_list += instance
                elif isinstance(res, Reservation):
                    instance_list.extend(res.instances)
                elif isinstance(res, Instance):
                    instance_list.append(res)
                else:
                    raise Exception('Need type instance or reservation in terminate_instances. type:' + str(type(res)))
        ids = []
        for instance in instance_list:
            ids.append(instance.id)
        self.log.debug('Sending terminate for "{0}"'
                       .format(", ".join(str(x.id) for x in instance_list)))
        self.connection.terminate_instances(instance_ids=ids, dry_run=dry_run)
        for instance in instance_list:
            try:
               instance.update()
               if instance.state != 'terminated':
                    monitor_list.append(instance)
               else:
                    self.log.debug('Instance: ' + str(instance.id) + ' in terminated state:' + str(instance.state))
            except EC2ResponseError, e:
                if e.status == 400:
                    pass
                else:
                    raise e
        try:
            self.show_instances(euinstance_list=monitor_list)
        except:
            pass
        try:
            self.monitor_euinstances_to_state(instance_list=monitor_list, state='terminated', timeout=timeout)
            aggregate_result = True
        except Exception, e:
            tb =  traceback.format_exc()
            self.log.debug(str(tb) + '\nCaught Exception in monitoring instances to terminated state:' + str(e))

        return aggregate_result
    
    def stop_instances(self, instances, force=False, dry_run=False, monitor=True, timeout=480):
        """
        Stop all instances in a reservation

        :param instances: boto.ec2.reservation object
        :raise: Exception when instance does not reach stopped state
        """
        instance_ids = []
        instance_objs = []
        instance_list = []
        if not instances:
            raise ValueError('stop_instances, bad value for instances: "{0}"'.format(instances))
        if isinstance(instances, Reservation):
            instance_ids = instances.instances
            for id in instance_ids:
                instance_obj =  self.get_instances(idstring=id)
                if not instance_obj:
                        raise ValueError('Instance not found by id:' + str(id))
                instance_objs.append(instance_obj[0])
        else:
            if not isinstance(instances, list):
                instance_list = [instances]
            else:
                instance_list = instances
            for instance in instance_list:
                if not isinstance(instance, Instance):
                    instance_obj =  self.get_instances(idstring=instance)
                    if not instance_obj:
                            raise ValueError('Instance not found by id:' + str(instance))
                    instance_objs.append(instance_obj[0])
                    instance_ids.append(instance)
                else:
                    instance_ids.append(instance.id)
                    instance_objs.append(instance_obj)

        self.log.debug('Sending stop for instances:"{0}"'.format(", ".join(instance_list)))
        ret = self.stop_instances(instances=instance_ids, force=force, dry_run=dry_run)
        if monitor:
            self.monitor_euinstances_to_state(instance_list=instance_objs, state='stopped',
                                              timeout=timeout)
        return ret
    
    def start_instances(self, instances, dry_run=False, monitor=True, timeout=480):
        """
        Start all instances in a reservation

        :param reservation: boto.ec2.reservation object or list of instances
        :raise: Exception when instance does not reach running state
        """
        instance_ids = []
        instance_objs = []
        instance_list = []
        if not instances:
            raise ValueError('start_instances, bad value for instances: "{0}"'.format(instances))
        if isinstance(instances, Reservation):
            instance_ids = instances.instances
            for id in instance_ids:
                instance_obj =  self.get_instances(idstring=id)
                if not instance_obj:
                        raise ValueError('Instance not found by id:' + str(id))
                instance_objs.append(instance_obj[0])
        else:
            if not isinstance(instances, list):
                instance_list = [instances]
            else:
                instance_list = instances
            for instance in instance_list:
                if not isinstance(instance, Instance):
                    instance_obj =  self.get_instances(idstring=instance)
                    if not instance_obj:
                            raise ValueError('Instance not found by id:' + str(instance))
                    instance_objs.append(instance_obj[0])
                    instance_ids.append(instance)
                else:
                    instance_ids.append(instance.id)
                    instance_objs.append(instance)

        self.log.debug('Sending start for instances:"{0}"'.format(", ".join(instance_list)))
        ret = self.start_instances(instances=instance_ids, dry_run=dry_run)
        if monitor:
            self.monitor_euinstances_to_state(instance_list=instance_objs, state='running',
                                              timeout=timeout)
        return ret

    def start_bundle_instance_task( self,
                                    instance,
                                    bucket_name = None,
                                    prefix = None,
                                    ):
        """
        REQUIRED PARAMETERS
        :rtype : BundleInstanceTask
        :param instance: boto instance to bundle
        :param bucket_name: Name of the bucket to upload. Default='win+ramdom'
        :param prefix:  The prefix for the image file name:Default='windows-bun + emi + random.'
        :param access_key:  String, Access Key ID of the owner of the bucket
        :param secret_key:  String, Secret key used to sign the upload policy
        :return : bundle task object

        """

        if not bucket_name:
            # Count images already registered with this instance id for concurrent nephoria_unit_tests
            try:
                id_count = len(self.get_images(location=instance.id))
            except:
                id_count = 0
            bucket_name =  str(instance.id) + "-" \
                           + str(id_count)
        prefix = prefix or 'bundleof-' + str(instance.id)
        s3_upload_policy = self.generate_default_s3_upload_policy(bucket_name,prefix)
        bundle_task = self.connection.bundle_instance(instance.id, bucket_name, prefix,
                                                      s3_upload_policy)
        self.print_bundle_task(bundle_task)
        return bundle_task



    def print_bundle_task(self,bundle, header=True, footer=True, printout=True):

        """
        Prints formatted output of bundle task attributes.
        :param bundle: BundleInstanceTask object to be printed
        :param header: boolean to print header containing column titles
        :param footer: boolean to print footer containing closing row line
        :param printout: boolean to print output using self.log.debug, else will return a buffer to be printed later.
        :return: string containing formatted output.
        """
        id_len = 15
        instance_id_len = 12
        bucket_len = 36
        prefix_len = 36
        state_len = 15
        start_time_len = 25
        update_time_len = 25
        buf = ""
        line = "-----------------------------------------------------------------------------------------------------" \
               "--------------------------------------------------------------"
        if header:
            buf += str("\n" + line +"\n")
            buf += str('BUNDLE_ID').center(id_len) + '|' \
                   + str('INSTANCE').center(instance_id_len) + '|' \
                   + str('BUCKET').center(bucket_len) + '|' \
                   + str('PREFIX').center(prefix_len) + '|' \
                   + str('STATE').center(state_len) + '|' \
                   + str('START_TIME').center(start_time_len) + '|' \
                   + str('UPDATE_TIME').center(update_time_len) + '\n'
            buf += str(line + "\n")
        buf += str(bundle.id).center(id_len) + '|' \
               + str(bundle.instance_id).center(instance_id_len) + '|' \
               + str(bundle.bucket).center(bucket_len) + '|' \
               + str(bundle.prefix).center(prefix_len) + '|' \
               + str(bundle.state).center(state_len) + '|' \
               + str(bundle.start_time).center(start_time_len) + '|' \
               + str(bundle.update_time).center(update_time_len)
        if footer:
            buf += str("\n" + line)
        if printout:
            self.log.debug(buf)
        return buf


    def bundle_instance_monitor_and_register(self,
                                             instance,
                                             bucket_name=None,
                                             prefix=None,
                                             poll_interval_seconds=20,
                                             timeout_minutes=25):
        """
        Attempts to start a bundle task and monitor it to completion.
        :param instance: boto instance to bundle
        :param bucket_name: Name of the bucket to upload. Default='win+ramdom'
        :param prefix:  The prefix for the image file name:Default='windows-bun + emi + random.'
        :param access_key:  String, Access Key ID of the owner of the bucket
        :param secret_key:  String, Secret key used to sign the upload policy
        :param poll_interval_seconds: Seconds to wait between polling for bundle task status
        :param timeout_minutes: int, minutes to wait before timing out.
        :return : image
        """
        return_dict = {}
        return_dict['manifest'] = None
        return_dict['image'] = None

        bundle_task = self.start_bundle_instance_task(instance,
                                                      bucket_name=bucket_name,
                                                      prefix=prefix,
                                                      )
        self.log.debug("bundle_instance_monitor_and_register: Got bundle task id:" +str(bundle_task.id)
                   + ", now monitor to completed state")
        self.monitor_bundle_tasks(bundle_task.id,
                                  poll_interval_seconds=poll_interval_seconds,
                                  timeout_minutes=timeout_minutes)
        self.log.debug("bundle_instance_monitor_and_register:" + str(bundle_task.id)
                   + " monitored to completed, now get manifest and register...")
        manifest = self.get_manifest_string_from_bundle_task(bundle_task)
        image = self.register_manifest(manifest, virtualization_type=instance.virtualization_type)
        self.log.debug("bundle_instance_monitor_and_register:" + str(bundle_task.id)
                   + ", registered as image:" + str(image.id))
        self.log.debug("bundle_instance_monitor_and_register:" + str(bundle_task.id)
                   + ", now make sure original instance " + (instance.id) + " returns to running state...")
        self.monitor_euinstances_to_state(instance_list=[instance],
                                          state='running',
                                          timeout=600)
        return image


    def get_bundle_task_by_id(self,bundle_task_id):
        bundles = self.connection.get_all_bundle_tasks(bundle_ids=[bundle_task_id])
        if bundles:
            return bundles[0]

    def get_manifest_string_from_bundle_task(self,bundle):

        """
        Create a manifest string from a BundleInstanceTask obj
        :param bundle: BundleInstanceTask
        :return: manifest string
        """
        return str(bundle.bucket) + "/" + str(bundle.prefix) + ".manifest.xml"

    def monitor_bundle_tasks(self, bundle_list, poll_interval_seconds=20, timeout_minutes=25, eof=True):
        """
        Attempts to monitor the state of the bundle task id provided until completed or failed.

        :param bundle_id: string bundle id to poll status for
        :param poll_interval_seconds: sleep period in seconds between polling for bundle task status
        :param timeout_minutes: timeout specified in minutes
        :param eof: boolean, end on first failure otherwise delay error until all bundle tasks have completed or failed
        """
        monitor_list = []
        fail_msg = ""
        if not isinstance(bundle_list, types.ListType):
            bundle_list = [bundle_list]

        for bundle in bundle_list:
            if isinstance(bundle, BundleInstanceTask ):
                monitor_list.append(bundle.id)
            else:
                monitor_list.append(bundle)
        start = time.time()
        elapsed = 0
        timeout = timeout_minutes * 60
        while monitor_list and elapsed < timeout:
            for bundle_id in monitor_list:
                self.log.debug('Waiting for bundle task:' + str(bundle_id) + ' to finish. Elapsed:' + str(elapsed))
                try:
                    bundle_task = self.get_bundle_task_by_id(bundle_id)
                    if bundle_task:
                        self.print_bundle_task(bundle_task)
                    else:
                        self.log.debug(str(bundle_id) + ": Assuming bundle task is complete, fetch came back empty?")
                        monitor_list.remove(bundle_id)
                    if bundle_task.state is None or bundle_task.state == 'none':
                        raise Exception(str(bundle_id) + ": Bundle task state err, state is: '"
                                        + str(bundle_task.state) + "' in monitor")
                    if bundle_task.state == 'failed':
                        raise Exception(str(bundle_id) + ": Bundle task reporting failed state during monitor")
                    if bundle_task.state == 'complete':
                        self.log.debug(str(bundle_id) +":  Bundle task reported state is completed during monitor")
                        monitor_list.remove(bundle_id)
                except Exception, e:
                    fail_msg += 'Monitor_bundle_task ERROR: '+str(e) + "\n"
                    if eof:
                        raise Exception('Monitor_bundle_task ERROR: '+str(e))
                    else:
                        monitor_list.remove(bundle_id)

            time.sleep(poll_interval_seconds)
            elapsed = int(time.time()-start)
        if fail_msg:
            raise Exception(fail_msg)
        return bundle_list



    def register_manifest(self,
                          manifest,
                          root_device_name=None,
                          description=None,
                          architecture=None,
                          virtualization_type=None,
                          platform=None,
                          bdmdev=None,
                          name=None,
                          ramdisk=None,
                          kernel=None):
        """
        Attempts to register the provided manifest and return the image id created by it
        :param manifest: manifest string to register
        :return: : image id string
        """
        image = self.register_image(manifest,
                                    root_device_name=root_device_name,
                                    description=description,
                                    architecture=architecture,
                                    virtualization_type=virtualization_type,
                                    platform=platform,
                                    bdmdev=bdmdev,
                                    name=name,
                                    ramdisk=ramdisk,
                                    kernel=kernel)
        #check to see if really registered by getting image obj to be returned
        try:
            image_obj = self.get_emi(emi=image)
        except Exception, e:
            raise Exception('Failed to retrieve image after registering. Image:' + str(image) + ", err:" + str(e))
        self.log.debug("Registered '" + str(manifest) + "as image:" + str(image))
        return image_obj

    def _register_image_custom_params(self,
                                     name=None,
                                     description=None,
                                     image_location=None,
                                     architecture=None,
                                     kernel_id=None,
                                     ramdisk_id=None,
                                     root_device_name=None,
                                     block_device_map=None,
                                     dry_run=False,
                                     virtualization_type=None,
                                     sriov_net_support=None,
                                     snapshot_id=None,
                                     platform=None,
                                     **custom_params):
        '''
        Register method to allow testing of 'custom_params' dict if provided
        '''
        params = custom_params or {}
        if name:
            params['Name'] = name
        if description:
            params['Description'] = description
        if architecture:
            params['Architecture'] = architecture
        if kernel_id:
            params['KernelId'] = kernel_id
        if ramdisk_id:
            params['RamdiskId'] = ramdisk_id
        if image_location:
            params['ImageLocation'] = image_location
        if platform:
            params['Platform'] = platform
        if root_device_name:
            params['RootDeviceName'] = root_device_name
        if snapshot_id:
            root_vol = BlockDeviceType(snapshot_id=snapshot_id)
            block_device_map = BlockDeviceMapping()
            block_device_map[root_device_name] = root_vol
        if block_device_map:
            block_device_map.ec2_build_list_params(params)
        if dry_run:
            params['DryRun'] = 'true'
        if virtualization_type:
            params['VirtualizationType'] = virtualization_type
        if sriov_net_support:
            params['SriovNetSupport'] = sriov_net_support


        rs = self.connection.get_object('RegisterImage', params,
                                         ResultSet, verb='POST')
        image_id = getattr(rs, 'imageId', None)
        return image_id

    def create_image(self, instance_id, name, description=None, no_reboot=False,
                     block_device_mapping=None, dry_run=False, timeout=600):
        """
        :type instance_id: string
        :param instance_id: the ID of the instance to image.

        :type name: string
        :param name: The name of the new image

        :type description: string
        :param description: An optional human-readable string describing
            the contents and purpose of the AMI.

        :type no_reboot: bool
        :param no_reboot: An optional flag indicating that the
            bundling process should not attempt to shutdown the
            instance before bundling.  If this flag is True, the
            responsibility of maintaining file system integrity is
            left to the owner of the instance.

        :type block_device_mapping: :class:`boto.ec2.blockdevicemapping.BlockDeviceMapping`
        :param block_device_mapping: A BlockDeviceMapping data structure
            describing the EBS volumes associated with the Image.

        :type dry_run: bool
        :param dry_run: Set to True if the operation should not actually run.

        :type timeout: int
        :param timeout: Time to allow image to get to "available" state.

        :raise Exception: On not reaching the correct state or when more than one image is returned
        """
        if isinstance(instance_id, Instance):
            instance_id = instance_id.id
        image_id = self.connection.create_image(instance_id, name=name,
                                                description=description,no_reboot=no_reboot,
                                                block_device_mapping=block_device_mapping,
                                                dry_run=dry_run)
        def get_emi_state():
            images = self.connection.get_all_images(image_ids=[image_id])
            if len(images) == 0:
                raise Exception("Image not found after sending create image request: " + image_id)
            elif len(images) == 1:
                state = images[0].state
                self.log.debug( image_id + " returned state: " + state)
                return state
            else:
                raise Exception("More than one image returned for: " + image_id)
        wait_for_result(get_emi_state, "available", timeout=timeout,poll_wait=20)
        return image_id

    def get_all_conversion_tasks(self, taskid=None):
        params = {}
        if taskid:
            params['ConversionTaskId'] = str(taskid)
        return self.connection.get_list('DescribeConversionTasks',
                                        params,
                                        [('item', ConversionTask),
                                         ('euca:item', ConversionTask)],
                                        verb='POST')

    def get_conversion_task(self, taskid):
        params = {'ConversionTaskId':str(taskid)}
        task = self.connection.get_object('DescribeConversionTasks',
                                           params,
                                           ConversionTask,
                                           verb='POST')
        if not task:
            raise EC2ResourceNotFoundException('"{0}". Conversion task not found'
                                            .format(taskid))
        return task

    def monitor_conversion_tasks(self,
                                 tasks,
                                 states='completed',
                                 time_per_gig=90,
                                 base_timeout=600,
                                 interval=10,
                                 exit_on_failure=False):
        """
        Monitors a list a task or list of tasks. Will monitor each
        task's state to the provided 'state', or until failure, timeout.
        Note: timeout is calculated by size of the largest task multiplied by
              'time_per_gig' added to the 'base_timeout'.
        :param tasks: list of tasks.
        :param state: string representing desired state to monitor to.
                      (pending, active, cancelled, completed, failed)
        :param time_per_gig: time in seconds per largest task size in GB
                             to append to base timeout
        :param base_timeout: base timeout in seconds
        :param interval: seconds between polling tasks
        :param exit_on_failure: Will  monitoring and raise an exception
                                upon first found failure. Otherwise will
                                continue monitoring remaining tasks in list
                                and raise the error when all tasks are
                                complete or timed out.
        """
        err_buf = ""
        monitor_list = []
        if not isinstance(states, types.ListType):
            states = [states]
        #Sanitize provided list...
        if not isinstance(tasks, types.ListType):
            tasks = [tasks]
        for task in tasks:
            if (not isinstance(task,ConversionTask) and
                    isinstance(task,types.StringType)):
                task = self.get_conversion_task(taskid=task)
            monitor_list.append(task)
        checking_list = copy.copy(monitor_list)
        done_list = []
        start = time.time()
        elapsed = 0
        timeout = 0
        for task in checking_list:
            for im in task.importvolumes:
                task_timeout = int(im.volume_size) * int(time_per_gig)
                if task_timeout > timeout:
                    timeout = task_timeout
        timeout += base_timeout
        while checking_list and elapsed < timeout:
            for task in checking_list:
                task.update()
                self.log.debug(task)
                #If the task volume is present add it to the resources list.
                found = False
                for vol in task.volumes:
                    for resvol in self.test_resources['volumes']:
                        if resvol.id == vol.id:
                            found = True
                            break
                    if not found and not vol in self.test_resources['volumes']:
                        self.test_resources['volumes'].append(vol)
                found = False
                if task.instanceid:
                    for resins in self.test_resources['instances']:
                        if resins.id == task.instanceid:
                            found = True
                            break
                        if resins.id == task.instance.reservation.id:
                            found = True
                            break
                    if not found:
                        ins = self.get_instances(idstring=task.instanceid)
                        if ins:
                            ins = ins[0]
                            if not ins in self.test_resources['instances']:
                                self.test_resources['instances'].append(ins)
                #notfound flag is set if task is not found during update()
                if task.notfound:
                    err_msg = 'Task "{0}" not found after elapsed:"{1}"'\
                        .format(task.conversiontaskid, elapsed)
                    err_buf += "\n" + err_msg
                    self.log.debug(err_msg)
                    done_list.append(task)
                    continue
                self.log.debug('Monitoring task:"{0}:{1}", elapsed:'
                           '"{2}/{3}"'
                           .format(task.conversiontaskid,
                                   task.state,
                                   elapsed,
                                   timeout))
                task_state = task.state.lower()
                in_state = False
                #Check state of task against all desired states provided
                for state in states:
                    if task_state == state:
                        in_state = True
                        break
                if in_state:
                    self.log.debug('Task:"{0}" found in desired state:"{1}"'.
                               format(task.conversiontaskid, task.state))
                    done_list.append(task)
                    continue
                # Fail fast for tasks found a final state that doesnt match
                # the desired state provided
                for final_state in ["completed", "cancelled", "failed"]:
                    if re.search(final_state, task_state):
                        err_msg = ('Task "{0}" found in a final state:"{1}" '
                                   'after elapsed:"{2}", msg:"{3}"'
                                   .format(task.conversiontaskid,
                                           task.state,
                                           elapsed,
                                           task.statusmessage))
                        err_buf += "\n" + err_msg
                        self.log.debug(err_msg)
                        done_list.append(task)
                        continue
            try:
                self.print_conversion_task_list(clist=monitor_list)
            except Exception as PE:
                self.log.debug('failed to print conversion task list, err:' +
                    str(PE))
            if exit_on_failure and err_buf:
                break
            for done_task in done_list:
                if done_task in checking_list:
                    checking_list.remove(done_task)
            if checking_list:
                self.log.debug('Waiting for "{0}" remaining tasks to reach '
                           'desired state:"{1}". Sleeping:"{2}"'
                           .format(len(checking_list), state, interval))
                time.sleep(interval)
            elapsed = int(time.time() - start)
        self.print_conversion_task_list(clist=tasks)
        #Any tasks still in checking_list are failures
        for task in checking_list:
            err_buf += ('Monitor complete. Task "{0}:{1}" not in desired '
                        'state "{2}" after elapsed:"{3}"\n'
                        .format(task.conversiontaskid,
                                task.state,
                                state,
                                elapsed))
        if err_buf:
            err_buf = "Exit on first failure set to:" + str(exit_on_failure) \
                      + "\n" + err_buf
            raise Exception('Monitor conversion tasks failures detected:\n'
                            + str(err_buf))

    def print_conversion_task_list(self,
                                   clist=None,
                                   doprint=True,
                                   printmethod=None):
        clist = clist or self.get_all_conversion_tasks()
        printmethod = printmethod or self.log.debug
        taskidlen = 19
        statusmsglen = 24
        availzonelen=14
        volumelen=16
        snaplen=13
        instancelen=13
        imagelen=13
        header = ('TASKID'.center(taskidlen) + " | " +
                  'SNAPSHOTS'.center(snaplen) + " | " +
                  'INSTANCE'.center(instancelen) + " | " +
                  'IMAGE ID'.center(imagelen) + " | " +
                  'ZONE'.center(availzonelen) + " | " +
                  'VOLUMES'.center(volumelen) + " | " +
                  'STATUS MSG'.center(statusmsglen) + " |\n" )
        line = ""
        for x in xrange(0, len(header)):
            line += '-'
        line += "\n"
        buf = "\n" + line + header + line
        for task in clist:
            sizestr = None
            instancestr = "???"
            instancestatus = ""
            imagesize = None
            vollist = []
            volbytes = []
            for importvol in task.importvolumes:
                bytesconverted = importvol.bytesconverted
                volume_id = importvol.volume_id
                if importvol.image:
                    imagesize = long(importvol.image.size)
                if imagesize is not None:
                    sizegb = "%.3f" % float(
                        long(imagesize) / float(1073741824))
                    gbconverted = "%.3f" % float(
                        long(bytesconverted) / float(1073741824))
                    sizestr = ("{0}/{1}gb".format(gbconverted, sizegb))
                vollist.append(str(volume_id))
                volbytes.append(sizestr)
            volumes = ",".join(vollist)
            volbytescon = ",".join(volbytes)
            volstatus = ",".join([str('(' + str(vol.status) + ':' +
                                      str(vol.size) + ')')
                                  for vol in task.volumes]) or "???"
            snaps = ",".join([str(snap.id ) for snap in task.snapshots]) or \
                    "???"
            snapstatus = ",".join([str('(' + snap.status + ')')
                                   for snap in task.snapshots])
            if task.instance:
                instancestr = str(task.instance.id)
                instancestatus = '(' + str(task.instance.state) + ')'
            image_id = task.image_id or "???"
            buf += (str(task.conversiontaskid).center(taskidlen) + " | " +

                    str(snaps).center(snaplen) + " | " +
                    str(instancestr).center(instancelen) + " | " +
                    str(image_id ).center(imagelen) + " | " +
                    str(task.availabilityzone).center(availzonelen) + " | " +
                    str(volumes).center(volumelen) + " | " +
                    str(task.statusmessage[:statusmsglen]).ljust(statusmsglen)
                    + " |\n")
            buf += (str('(' + task.state + ')').center(taskidlen) + " | " +
                    str(snapstatus).center(snaplen) + " | " +
                    str(instancestatus).center(instancelen) + " | " +
                    str('').center(imagelen) + " | " +
                    str('').center(availzonelen) + " | " +
                    str(volstatus).center(volumelen) + " | " +
                    str(task.statusmessage[
                        statusmsglen:(2*statusmsglen)]).ljust(statusmsglen)
                    + " |\n")
            buf += (str('').center(taskidlen) + " | " +
                    str('').center(snaplen) + " | " +
                    str('').center(instancelen) + " | " +
                    str('').center(imagelen) + " | " +
                    str('').center(availzonelen) + " | " +
                    str(volbytescon).center(volumelen) + " | " +
                    str(task.statusmessage[
                        (2*statusmsglen):(3*statusmsglen)]).ljust(statusmsglen)
                    + " |\n")
            buf += line
        if doprint:
            printmethod(buf)
        return buf

    def cancel_conversion_tasks(self, tasks, timeout=180):
        tasks = tasks or self.test_resources['conversion_tasks']
        if not isinstance(tasks, types.ListType):
            tasks = [tasks]
        printbuf = self.print_conversion_task_list(clist=tasks, doprint=False)
        self.log.debug('Cancel Conversion task list...\n' + str(printbuf))
        cancel_tasks = copy.copy(tasks)
        for task in tasks:
            task.update()
            for state in ['canceled', 'failed', 'completed']:
                if task.state == state:
                    cancel_tasks.remove(task)
                    break
        for task in cancel_tasks:
            task.cancel()
        self.monitor_conversion_tasks(tasks=cancel_tasks, states=['canceled'])
        printbuf = self.print_conversion_task_list(clist=tasks, doprint=False)
        self.log.debug('Done with canceling_conversion_tasks...' + str(printbuf))


    def cleanup_conversion_task_resources(self, tasks=None):
        tasks = tasks or self.test_resources.get('conversion_tasks', [])
        if not isinstance(tasks, types.ListType):
            tasks = [tasks]
        error_msg = ""
        try:
            self.cancel_conversion_tasks(tasks)
        except Exception as CE:
                tb = get_traceback()
                self.log.critical('Failed to cancel some tasks:' + str(CE))

        for task in tasks:
            self.log.debug('Attempting to delete all resources associated '
                       'with task: "{0}"'
                       .format(getattr(task, 'id', 'UNKOWN_ID')))
            try:
                assert isinstance(task,ConversionTask)
                task.update()
                try:
                    if task.instance:
                        self.terminate_single_instance(task.instance)
                except Exception, e:
                    tb = get_traceback()
                    error_msg += str(tb) + '\n"{0}":Cleanup_error:"{1}"\n'\
                        .format(task.conversiontaskid, str(e))
                try:
                    if task.image_id:
                        image = self.get_images(emi=task.image_id)
                        if image:
                            self.delete_image(image=image)
                except Exception, e:
                    tb = get_traceback()
                    error_msg += str(tb) + '\n"{0}":Cleanup_error:"{1}"\n'\
                        .format(task.conversiontaskid, str(e))
                try:
                    if task.snapshots:
                        self.delete_snapshots(snapshots=task.snapshots)
                except Exception, e:
                    tb = get_traceback()
                    error_msg += str(tb) + '\n"{0}":Cleanup_error:"{1}"\n'\
                        .format(task.conversiontaskid, str(e))
                try:
                    if task.volumes:
                        self.delete_volumes(volume_list=task.volumes)
                except Exception, e:
                    tb = get_traceback()
                    error_msg += str(tb) + '\n"{0}":Cleanup_error:"{1}"\n'\
                        .format(task.conversiontaskid, str(e))
            except Exception as TE:
                tb = get_traceback()
                error_msg += '{0}\n"{1}" Failed to cleanup task, err:"{1}"'\
                    .format(str(tb), getattr(task, 'id', 'UNKOWN_ID'), str(TE))
        if error_msg:
            raise Exception(error_msg)

    def create_web_servers(self, keypair, group, zone, port=80, count=2, image=None, filename="test-file", cookiename="test-cookie"):
        if not image:
            image = self.get_emi(root_device_type="instance-store", not_location="loadbalancer", not_platform="windows")
        reservation = self.run_instance(image, keypair=keypair, group=group, zone=zone, min=count, max=count)
        self.authorize_group(group=group,port=port)

        ### TODO edit this so that the proper port is open on the apache instance
        for instance in reservation.instances:
            assert isinstance(instance, EuInstance)
            try:
                instance.sys("which apt-get", code=0)
                ## Debian based Linux
                instance.sys("apt-get update", code=0)
                instance.sys("apt-get install -y apache2", code=0)
                instance.sys("echo \"" + instance.id +"\" > /var/www/" + filename)
                instance.sys("echo \"CookieTracking on\" >> /etc/apache2/apache2.conf")
                instance.sys("echo CookieName " + cookiename +" >> /etc/apache2/apache2.conf")
            except sshconnection.CommandExitCodeException, e:
                ### Enterprise Linux
                instance.sys("yum install -y httpd", code=0)
                instance.sys("echo \"" + instance.id +"\" > /var/www/html/" + filename)
                instance.sys("echo \"CookieTracking on\" >> /etc/httpd/conf/httpd.conf")
                instance.sys("echo CookieName " + cookiename +" >> /etc/httpd/conf/httpd.conf")
                instance.sys("service httpd start")
                instance.sys("chkconfig httpd on")
        return (reservation, filename)

    def generate_default_s3_upload_policy(self, bucket, prefix, expiration=24, acl='ec2-bundle-read', encode=True):
        """
        Generates s3 upload policy for bundle instance operation

        :param bucket: bucket string
        :param prefix: prefix string
        :param expiration: int representing hours
        :param acl: acl to be used
        :return: s3 upload encoded policy
        """

        delta = timedelta(hours=expiration)
        expiration_time = (datetime.utcnow() + delta).replace(microsecond=0)
        expiration_str = expiration_time.isoformat()
        
        policy = '{"expiration": "%s",' % expiration_str + \
        '"conditions": [' + \
        '{"bucket": "%s" },' % bucket + \
        '{"acl": "%s" },' % acl + \
        '["starts-with", "$key", "%s"]' % prefix + \
        ']' + \
        '}'

        if encode:
            policy = base64.b64encode(policy)
        return policy



    def sign_policy(self, policy):
        my_hmac = hmac.new(self.connection.aws_secret_access_key, policy, digestmod=hashlib.sha1)
        return base64.b64encode(my_hmac.digest())

    def get_euzones(self, zones=None):
        ret_list = []
        get_zones = []
        if zones is not None:
            if not isinstance(zones, types.ListType):
                zones = [zones]
            for zone in zones:
                if zone:
                    if isinstance(zone, Zone):
                        zone = zone.name
                    get_zones.append(zone)
            myzones = self.connection.get_all_zones(zones=get_zones)
        else:
            myzones = self.connection.get_all_zones()
        for zone in myzones:
            ret_list.append(EuZone.make_euzone_from_zone(zone, self))
        return ret_list


    def get_vm_type_list_from_zone(self, zone):
        euzone = self.get_euzones(zone)[0]
        return euzone.vm_types

    def get_vm_type_from_zone(self,zone, vmtype_name):
        vm_type = None
        type_list = self.get_vm_type_list_from_zone(zone)
        for type in type_list:
            if type.name == vmtype_name:
                vm_type = type
                break
        return vm_type

    def print_block_device_map(self,block_device_map, printmethod=None ):
        printmethod = printmethod or self.log.debug
        buf = '\n'
        device_w = 16
        snap_w = 15
        volume_w = 15
        dot_w = 7
        size_w = 6
        status_w = 7
        ephemeral_name_w = 12
        attach_time_w = 12
        no_device_w = 7
        line = ''
        titles = str('DEVICE').ljust(device_w) + "|" + \
                 str('VOLUME_ID').center(volume_w) + "|" + \
                 str('SNAP_ID').center(snap_w) + "|" + \
                 str('D.O.T.').center(dot_w) + "|" + \
                 str('SIZE').center(size_w) + "|" + \
                 str('EPHEMERAL').center(ephemeral_name_w) + "|" + \
                 str('NO DEV').center(no_device_w) + "|" + \
                 str('ATTACH TM').center(attach_time_w) + "|" + \
                 str('STATUS').center(status_w) + "\n"

        for x in titles:
            if x == '|':
                line += '|'
            else:
                line += "-"
        line = line+"\n"
        header = str('BLOCK DEVICE MAP').center(len(line)) + "\n"
        buf += line + header + line + titles + line
        for device in block_device_map:
            bdm = block_device_map[device]
            buf += str(device).center(device_w) + "|" + \
                   str(bdm.volume_id).center(volume_w) + "|" + \
                   str(bdm.snapshot_id).center(snap_w) + "|" + \
                   str(bdm.delete_on_termination).center(dot_w) + "|" + \
                   str(bdm.size).center(size_w) + "|" + \
                   str(bdm.ephemeral_name).center(ephemeral_name_w) + "|" + \
                   str(bdm.no_device).center(no_device_w) + "|" + \
                   str(bdm.attach_time).center(attach_time_w) + "|" + \
                   str(bdm.status).center(status_w) + "\n"
        buf += line
        printmethod(buf)

    def print_all_vm_types(self,zone=None, debugmethod=None):
        debugmethod = debugmethod or self.log.debug
        buf = "\n"
        if zone:
            zones = [zone]
        else:
            zones = self.connection.get_all_zones()
        for zone in zones:
            buf += "------------------------( " + str(zone) + " )--------------------------------------------\n"
            for vm in self.get_vm_type_list_from_zone(zone):
                vminfo = self.get_all_attributes(vm, debug=False)
                buf +=  "---------------------------------"
                buf += self.get_all_attributes(vm, debug=False)
        debugmethod(buf)

    def monitor_instances(self, instance_ids):
        self.log.debug('Enabling monitoring for instance(s) ' + str(instance_ids))
        self.monitor_instances(instance_ids)

    def unmonitor_instances(self, instance_ids):
        self.log.debug('Disabling monitoring for instance(s) ' + str(instance_ids))
        self.unmonitor_instances(instance_ids)


    def show_images(self, images=None, verbose=False, basic_image=False, printmethod=None):
        printmethod = printmethod or self.log.info
        buf = "\n"
        if not images:
            try:
                images = self.get_images(emi='',basic_image=basic_image, state=None) or []
            except EC2ResourceNotFoundException, nfe:
                printmethod("\nNo images found\n")
                return
        for image in images:
            buf += str(self.show_image(image=image, verbose=verbose, printme=False)) + "\n"
        printmethod(buf)

    def show_image(self, image, verbose=True, printmethod=None,
                   header_markups=[1,4], printme=True):
        if isinstance(image, basestring):
            image = self.get_emi(emi=image, state=None)
            if not image:
                raise EC2ResourceNotFoundException('Image:"{0}" not found'.format(image))
        if not isinstance(image, Image):
            raise ValueError('Unknown type provided for image:"{0}:{1}"'.format(image,
                                                                                type(image)))
        def header(text):
            return markup(text=text, markups=header_markups)

        title =markup("IMAGE ID: {0},    IMAGE NAME:{1}".format(image.id, image.name),
                           markups=[1,94])

        main_pt = PrettyTable([title])
        main_pt.align[title] = 'l'
        main_pt.padding_width = 0
        mainbuf = ""
        if verbose:
            mainbuf += header("IMAGE SUMMARY:\n")
        platform = str(image.platform or "LINUX").upper()
        summary_pt = PrettyTable(["VIRT TYPE", "PUBLIC", "OWNER ID", "KERNEL ID", "RAMDISK ID",
                                  "PLATFORM", "ROOT DEV TYPE", "STATE"])
        summary_pt.padding_width = 0
        row = [image.virtualization_type, image.is_public, image.owner_id, image.kernel_id,
               image.ramdisk_id, platform, image.root_device_type, image.state]
        summary_pt.add_row(row)
        mainbuf += str(summary_pt)
        if verbose:
            mainbuf += header("\n\nIMAGE MANIFEST PATH:\n")
            locpt = PrettyTable(['IMAGE LOCATION:'])
            locpt.add_row([image.location])
            mainbuf += str(locpt) + "\n"
            mainbuf += header("\nIMAGE BLOCK DEVICE MAPPING:")
            if not image.block_device_mapping:
                mainbuf += " N/A\n"
            else:
                mainbuf += "\n" + str(self.show_block_device_map(image.block_device_mapping,
                                                                  printme=False)) + "\n"
            mainbuf += header("\nIMAGE TAGS:\n")
            mainbuf += str(self.show_tags(image.tags, printme=False)) + "\n"
        main_pt.add_row([mainbuf])
        if printme:
            printmethod = printmethod or self.log.info
            printmethod( "\n" + str(main_pt) + "\n")
        else:
            return main_pt

    def show_tags(self, tags, printmethod=None, printme=True):
        if not isinstance(tags, TagSet) and not isinstance(tags, dict):
            if hasattr(tags, 'tags'):
                tags = tags.tags
            else:
                raise ValueError('unknown tags object of type "{0}" passed to show_tags'
                                 .format(type(tags)))
        name_header = markup("TAG NAME")
        value_header = markup("TAG VALUE")
        pt = PrettyTable([name_header, value_header])
        pt.padding_width = 0
        pt.align = 'l'
        pt.hrules = 1
        pt.max_width[name_header] = 20
        pt.max_width[value_header] = 80
        for tag in tags:
            pt.add_row([str(tag), str(tags.get(tag, None))])
        if printme:
            printmethod = printmethod or self.log.info
            printmethod( "\n" + str(pt) + "\n")
        else:
            return pt

    def show_addresses(self, addresses=None, verbose=None, printme=True):
        """
        Print table to debug output showing all addresses available to
        cloud admin using verbose filter
        :param addresses:
        """
        pt = PrettyTable([markup('PUBLIC IP'), markup('ACCOUNT NAME'),
                          markup('REGION'), markup('ADDRESS INFO')])
        pt.align = 'l'
        ad_list = []
        if verbose is None:
            verbose = self._use_verbose_requests
        if verbose:
            get_addresses = ['verbose']
        else:
            get_addresses = None
        try:
            if not addresses:
                ad_list = self.connection.get_all_addresses(addresses=get_addresses)
            else:
                if not isinstance(addresses, list):
                    addresses = [addresses]
                for address in addresses:
                    if isinstance(addresses, basestring):
                        get_addresses.append(address)
                    elif isinstance(address, Address):
                        ad_list.append(address)
                    else:
                        raise ValueError('Show_addresses(). Got unknown address type: {0}:{1}'
                                         .format(address, type(address)))
                if get_addresses:
                    ad_list += self.connection.get_all_addresses(addresses=get_addresses)
                if not ad_list:
                    raise ValueError('Addresses not found for: "{0}"'
                                     .format(",".join(addresses)))
            for ad in ad_list:
                instance_id = ad.instance_id
                public_ip = ad.public_ip
                region = None
                if ad.region:
                    region = ad.region.name
                account_name = ""
                match = re.findall('\(arn:*.*\)', str(instance_id))
                if match:
                    try:
                        match = match[0]
                        account_id = match.split(':')[4]
                        account_name = self.connection.get_all_accounts(account_id=account_id)[0]['account_name']
                        if account_name:
                            account_name = markup(account_name)
                            instance_id = markup(instance_id)
                            public_ip = markup(public_ip)
                            region = markup(region)
                    except:pass
                pt.add_row([public_ip, account_name, region, instance_id])
        except Exception, e:
            tb = get_traceback()
            self.log.critical( str(tb) + "\n ERROR in show_all_addresses_verbose:" + str(e))
        if not printme:
            return pt
        self.log.info("\n" + str(pt) + "\n")

    def show_instance(self, instance, printme=True):
        if not isinstance(instance, EuInstance):
            orig_instance = instance
            if isinstance(instance, str):
                try:
                    instance = self.get_instances(idstring=instance)[0]
                except IndexError: pass
            if isinstance(instance, Instance):
                instance = self.convert_instance_to_euinstance(instance=instance,
                                                               auto_connect=False)
            else:
                raise ValueError('Unknown type for instance: "{0}:{1}"'
                                 .format(orig_instance, type(orig_instance)))
        return instance.show_summary(printme=printme)


    def show_instances(self,
                       euinstance_list=None,
                       state=None,
                       instance_id=None,
                       reservation=None,
                       root_device_type=None,
                       zone=None,
                       key=None,
                       public_ip=None,
                       private_ip=None,
                       ramdisk=None,
                       kernel=None,
                       image_id=None,
                       printme=True
                       ):
        """
        Display or return a table of instances and summary information
        :param euinstance_list: list of euinstance objs, otherwise all instances will be shown
        :param state: filter to be applied if no instance list is provided
        :param instance_id: filter to be applied if no instance list is provided
        :param reservation: filter to be applied if no instance list is provided
        :param root_device_type: filter to be applied if no instance list is provided
        :param zone: filter to be applied if no instance list is provided
        :param key: filter to be applied if no instance list is provided
        :param public_ip: filter to be applied if no instance list is provided
        :param private_ip: filter to be applied if no instance list is provided
        :param ramdisk: filter to be applied if no instance list is provided
        :param kernel: filter to be applied if no instance list is provided
        :param image_id: filter to be applied if no instance list is provided
        :param printme: boolean flag, if True will print the table with self.log.debug, else will
                        return the PrettyTable obj

        :returns: None if printme is True, else will return the PrettyTable obj
        """
        plist = []
        if not euinstance_list:
            euinstance_list = []
            instances = self.get_instances(state=state,
                                           idstring=instance_id,
                                           reservation=reservation,
                                           rootdevtype=root_device_type,
                                           zone=zone,
                                           key=key,
                                           pubip=public_ip,
                                           privip=private_ip,
                                           ramdisk=ramdisk,
                                           kernel=kernel,
                                           image_id=image_id)
            for instance in instances:
                if instance:
                    instance_res = getattr(instance, 'reservation', None)
                    euinstance_list.append(self.convert_instance_to_euinstance(
                        instance, reservation=instance_res, auto_connect=False))
        if not euinstance_list:
            self.log.debug('No instances to print')
            return
        for instance in euinstance_list:
            if not isinstance(instance,EuInstance) and not isinstance(instance, WinInstance):
                instance = self.convert_instance_to_euinstance(instance, auto_connect=False)
            plist.append(instance)
        first = plist.pop(0)
        # Build upon a table created from a euinstance class obj
        maintable = first.printself(printme=False)
        maintable.hrules = 1
        count = 0
        # The first row of the table returned from a euinstance.printself() is a sudo header
        new_header = maintable._rows[0]
        for instance in plist:
            count += 1
            if not count % 5:
                # Add a header every 5th row to make the tables easier to read
                maintable.add_row(new_header)
            try:
                pt = instance.printself(printme=False)
            except Exception as PE:
                self.log.error('{0}\nFailed in instance.printself, type:{1}'.format(get_traceback(), type(instance)))
                raise PE
            if pt._rows:
                maintable.add_row(pt._rows[1])
            # Adjust the table's column widths to allow the largest entries
            for key in pt._max_width:
                pt_max = pt._max_width[key] or 0
                max = maintable._max_width.get(key, 0)
                if pt_max > max:
                    maintable._max_width[key] = pt_max
        if printme:
            self.log.info("\n"+str(maintable)+"\n")
        else:
            return maintable

    def show_bundle_task(self,bundle, header=True, footer=True, printout=True):

        """
        Prints formatted output of bundle task attributes.
        :param bundle: BundleInstanceTask object to be printed
        :param header: boolean to print header containing column titles
        :param footer: boolean to print footer containing closing row line
        :param printout: boolean to print output using self.log.debug, else will return a buffer to be printed later.
        :return: string containing formatted output.
        """
        id_len = 15
        instance_id_len = 12
        bucket_len = 36
        prefix_len = 36
        state_len = 15
        start_time_len = 25
        update_time_len = 25
        buf = ""
        line = "-----------------------------------------------------------------------------------------------------" \
               "--------------------------------------------------------------"
        if header:
            buf += str("\n" + line +"\n")
            buf += str('BUNDLE_ID').center(id_len) + '|' \
                   + str('INSTANCE').center(instance_id_len) + '|' \
                   + str('BUCKET').center(bucket_len) + '|' \
                   + str('PREFIX').center(prefix_len) + '|' \
                   + str('STATE').center(state_len) + '|' \
                   + str('START_TIME').center(start_time_len) + '|' \
                   + str('UPDATE_TIME').center(update_time_len) + '\n'
            buf += str(line + "\n")
        buf += str(bundle.id).center(id_len) + '|' \
               + str(bundle.instance_id).center(instance_id_len) + '|' \
               + str(bundle.bucket).center(bucket_len) + '|' \
               + str(bundle.prefix).center(prefix_len) + '|' \
               + str(bundle.state).center(state_len) + '|' \
               + str(bundle.start_time).center(start_time_len) + '|' \
               + str(bundle.update_time).center(update_time_len)
        if footer:
            buf += str("\n" + line)
        if printout:
            self.log.info(buf)
        return buf

    def show_conversion_task_list(self,
                                   clist=None,
                                   doprint=True,
                                   printmethod=None):
        clist = clist or self.get_all_conversion_tasks()
        printmethod = printmethod or self.log.info
        taskidlen = 19
        statusmsglen = 24
        availzonelen=14
        volumelen=16
        snaplen=13
        instancelen=13
        imagelen=13
        header = ('TASKID'.center(taskidlen) + " | " +
                  'SNAPSHOTS'.center(snaplen) + " | " +
                  'INSTANCE'.center(instancelen) + " | " +
                  'IMAGE ID'.center(imagelen) + " | " +
                  'ZONE'.center(availzonelen) + " | " +
                  'VOLUMES'.center(volumelen) + " | " +
                  'STATUS MSG'.center(statusmsglen) + " |\n" )
        line = ""
        for x in xrange(0, len(header)):
            line += '-'
        line += "\n"
        buf = "\n" + line + header + line
        for task in clist:
            sizestr = None
            instancestr = "???"
            instancestatus = ""
            imagesize = None
            vollist = []
            volbytes = []
            for importvol in task.importvolumes:
                bytesconverted = importvol.bytesconverted
                volume_id = importvol.volume_id
                if importvol.image:
                    imagesize = long(importvol.image.size)
                if imagesize is not None:
                    sizegb = "%.3f" % float(
                        long(imagesize) / float(1073741824))
                    gbconverted = "%.3f" % float(
                        long(bytesconverted) / float(1073741824))
                    sizestr = ("{0}/{1}gb".format(gbconverted, sizegb))
                vollist.append(str(volume_id))
                volbytes.append(sizestr)
            volumes = ",".join(vollist)
            volbytescon = ",".join(volbytes)
            volstatus = ",".join([str('(' + str(vol.status) + ':' +
                                      str(vol.size) + ')')
                                  for vol in task.volumes]) or "???"
            snaps = ",".join([str(snap.id ) for snap in task.snapshots]) or \
                    "???"
            snapstatus = ",".join([str('(' + snap.status + ')')
                                   for snap in task.snapshots])
            if task.instance:
                instancestr = str(task.instance.id)
                instancestatus = '(' + str(task.instance.state) + ')'
            image_id = task.image_id or "???"
            buf += (str(task.conversiontaskid).center(taskidlen) + " | " +

                    str(snaps).center(snaplen) + " | " +
                    str(instancestr).center(instancelen) + " | " +
                    str(image_id ).center(imagelen) + " | " +
                    str(task.availabilityzone).center(availzonelen) + " | " +
                    str(volumes).center(volumelen) + " | " +
                    str(task.statusmessage[:statusmsglen]).ljust(statusmsglen)
                    + " |\n")
            buf += (str('(' + task.state + ')').center(taskidlen) + " | " +
                    str(snapstatus).center(snaplen) + " | " +
                    str(instancestatus).center(instancelen) + " | " +
                    str('').center(imagelen) + " | " +
                    str('').center(availzonelen) + " | " +
                    str(volstatus).center(volumelen) + " | " +
                    str(task.statusmessage[
                        statusmsglen:(2*statusmsglen)]).ljust(statusmsglen)
                    + " |\n")
            buf += (str('').center(taskidlen) + " | " +
                    str('').center(snaplen) + " | " +
                    str('').center(instancelen) + " | " +
                    str('').center(imagelen) + " | " +
                    str('').center(availzonelen) + " | " +
                    str(volbytescon).center(volumelen) + " | " +
                    str(task.statusmessage[
                        (2*statusmsglen):(3*statusmsglen)]).ljust(statusmsglen)
                    + " |\n")
            buf += line
        if doprint:
            printmethod(buf)
        else:
            return buf

    def show_block_device_map(self,block_device_map, printmethod=None, printme=True ):
        printmethod = printmethod or self.log.info

        title = 'BLOCK DEVICE MAP'
        main_pt = PrettyTable([title])
        main_pt.align[title] = 'l'
        main_pt.padding_width = 0

        headers = ['DEVICE', 'VOLUME_ID', 'SNAP_ID', 'D.O.T.', 'SIZE', 'EPHEMERAL',
                  'NO DEV', 'ATTACH TM', 'STATUS']
        pt = PrettyTable(headers)
        pt.padding_width = 0

        for device in block_device_map:
            bdm = block_device_map[device]
            row =  [str(device), str(bdm.volume_id), str(bdm.snapshot_id),
                    str(bdm.delete_on_termination), str(bdm.size), str(bdm.ephemeral_name),
                    str(bdm.no_device), str(bdm.attach_time), str(bdm.status)]
            pt.add_row(row)
        main_pt.add_row([str(pt)])
        if printme:
            printmethod("\n" + str(main_pt) + "\n")
        else:
            return main_pt

    def show_vm_types(self, zone=None, debugmethod=None, printme=True):
        debugmethod = debugmethod or self.log.info
        mainpt=PrettyTable([markup('VM TYPES PER ZONE:', [1, 4, 94])])

        mainpt.align = 'l'
        mainpt.padding_width = 0


        if zone:
            zones = [zone]
        else:
            zones = self.get_all_zones()
        for zone in zones:
            buf = "{0}: {1}\n".format(markup('ZONE', [1, 4, 94]), markup(zone))

            pt = PrettyTable([markup('NAME', [1, 4]).ljust(20), markup('CPU', [1, 4]).ljust(7),
                              markup('DISK', [1, 4]).ljust(10), markup('RAM', [1, 4]).ljust(10),
                              markup('FREE', [1, 4]).ljust(10)])
            pt.align = 'l'
            # pt.hrules = 1
            for vm in self.get_vm_type_list_from_zone(zone):
                pt.add_row([markup(vm.name), vm.cpu, vm.disk, vm.ram,
                            "{0}/{1}".format(vm.free, vm.max)])
            buf += str(pt)
            mainpt.add_row([buf])
        if printme:
            debugmethod("\n{0}\n".format(mainpt))
        else:
            return mainpt

    def show_security_groups(self, groups=None, printme=True):
        ret_buf = ""
        groups = groups or self.connection.get_all_security_groups()
        for group in groups:
            ret_buf += "\n" + str(self.show_security_group(group, printme=False))
        if printme:
            self.log.info(ret_buf)
        else:
            return ret_buf


    def show_security_group(self, group, printme=True):
        try:
            from prettytable import PrettyTable, ALL
        except ImportError as IE:
            self.log.debug('No pretty table import failed:' + str(IE))
            return
        group = self.get_security_group(id=group.id)
        if not group:
            raise ValueError('Show sec group failed. Could not fetch group:'
                             + str(group))
        title = markup("Security Group: {0}/{1}, VPC: {2}"
                            .format(group.name, group.id, group.vpc_id))
        maintable = PrettyTable([title])
        table = PrettyTable(["CIDR_IP", "SRC_GRP_NAME",
                             "SRC_GRP_ID", "OWNER_ID", "PORT",
                             "END_PORT", "PROTO"])
        maintable.align["title"] = 'l'
        #table.padding_width = 1
        for rule in group.rules:
            port = rule.from_port
            end_port = rule.to_port
            proto = rule.ip_protocol
            for grant in rule.grants:
                table.add_row([grant.cidr_ip, grant.name,
                               grant.group_id, grant.owner_id, port,
                               end_port, proto])
        table.hrules = ALL
        maintable.add_row([str(table)])
        if printme:
            self.log.info("\n{0}".format(str(maintable)))
        else:
            return maintable

    def show_security_groups_for_instance(self, instance, printmethod=None, printme=True):
        buf = ""
        title = markup("EUCA SECURITY GROUPS FOR INSTANCE:{0}".format(instance.id))
        pt = PrettyTable([title])
        pt.align['title'] = 'l'
        for group in instance.groups:
            buf += str(self.show_security_group(group=group, printme=False))
        pt.add_row([buf])
        if printme:
            printmethod = printmethod or self.log.info
            printmethod('\n{0}\n'.format(pt))
        else:
            return pt

    def show_account_attributes(self, attribute_names=None, printmethod=None, printme=True):
        attrs = self.connection.describe_account_attributes(attribute_names=attribute_names)

        main_pt = PrettyTable([markup('ACCOUNT ATTRIBUTES')])
        pt = PrettyTable([markup('NAME'), markup('VALUE')])
        pt.hrules = ALL
        for attr in attrs:
            pt.add_row([attr.attribute_name, attr.attribute_values])
        main_pt.add_row([str(pt)])
        if printme:
            printmethod = printmethod or self.log.info
            printmethod( "\n" + str(main_pt) + "\n")
        else:
            return main_pt

    def cleanup_test_instances(self, resourcelist=None):
        failmsg = ""
        failcount = 0
        remove_list = []
        # To speed up termination, send terminate to all instances
        # before sending them to the monitor methods
        if resourcelist is None:
            resourcelist = self.test_resources.get('instances', [])
        if not isinstance(resourcelist, list):
            resourcelist = [resourcelist]
        for res in resourcelist:
            try:
                if isinstance(res, Instance):
                    res.terminate()
                if isinstance(res, Reservation):
                    for ins in res.instances:
                        ins.terminate()
            except:
                traceback.print_exc()
                self.log.debug('Ignoring error in instance cleanup '
                               'during termination')
        # Now monitor to terminated state...
        for res in self.test_resources.get('instances', []):
            try:
                self.terminate_instances(res)
                remove_list.append(res)
            except Exception, e:
                tb = get_traceback()
                failcount += 1
                failmsg += str(tb) + "\nError#:"+ str(failcount)+ ":" + str(e)+"\n"
        for res in remove_list:
            self.test_resources["instances"].remove(res)
        if failcount:
            raise CleanTestResourcesException("Failed to clean up all test Instances:\n{0}"
                                              .format(failmsg))

    def cleanup_addresses(self, ips=None):
        """
        :param ips: optional list of ip addresses, else will attempt to delete from test_resources[]

        """
        addresses = ips or self.test_resources.get('addresses', [])
        if not addresses:
            return
        self.log.debug('Attempting to release to the cloud the following IP addresses:')
        while addresses:
            self.release_address(addresses.pop())

    def cleanup_test_snapshots(self,snaps=None, clean_images=False, add_time_per_snap=10,
                               wait_for_valid_state=120, base_timeout=180):
        """
        :param snaps: optional list of snapshots, else will attempt to delete from test_resources[]
        :param clean_images: Boolean, if set will attempt to delete registered images referencing the snapshots first.
                             Images referencing the snapshot may prevent snapshot deletion to protect the image.
        :param add_time_per_snap:  int number of seconds to append to base_timeout per snapshot
        :param wait_for_valid_state: int seconds to wait for snapshot(s) to enter a 'deletable' state
        :param base_timeout: base timeout to use before giving up, and failing operation.
        """
        snaps = snaps or self.test_resources.get('snapshots', [])
        if not snaps:
            return
        self.log.debug('Attempting to clean the following snapshots:')
        self.show_snapshots(snaps)
        if clean_images:
            for snap in snaps:
                for image in self.test_resources.get('images', []):
                    for dev in image.block_device_mapping:
                        if image.block_device_mapping[dev].snapshot_id == snap.id:
                            self.ec2.delete_image(image)
        if snaps:
            return self.delete_snapshots(snaps,
                                         base_timeout=base_timeout,
                                         add_time_per_snap=add_time_per_snap,
                                         wait_for_valid_state=wait_for_valid_state)

    def clean_up_test_volumes(self, volumes=None, min_timeout=180, timeout_per_vol=30):
        """
        Definition: cleanup helper method intended to clean up volumes created
        within a test, after the test has ran.

        :param volumes: optional list of volumes to delete from system, otherwise will use
                        test_resources['volumes']
        """
        euvolumes = []
        detaching = []
        not_exist = []
        volumes = volumes or self.test_resources.get('volumes', [])
        if not volumes:
            self.log.debug('clean_up_test_volumes, no volumes passed to delete')
            return
        self.log.debug('clean_up_test_volumes starting\nVolumes to be deleted:{0}'
                       .format(",".join(str(x) for x in volumes)))
        for vol in volumes:
            try:
                vol = self.get_volume(volume_id=vol.id)
            except:
                self.log.debug("\n{0}:\n{1}\nCould not retrieve volume:{2}, may no longer exist?"
                               .format(markup('Ignoring the following caught Exception', [1, 91]),
                               get_traceback(),
                               vol.id))
                if vol in self.test_resources['volumes']:
                    self.test_resources['volumes'].remove(vol)
                vol = None
            if vol:
                try:
                    vol.update()
                    if not isinstance(vol, EuVolume):
                        vol = EuVolume.make_euvol_from_vol(vol, self)
                    euvolumes.append(vol)
                except:
                    self.log.debug('Ignoring caught Exception:\n{0}'.format(get_traceback()))
        try:
            self.log.debug('Attempting to clean up the following volumes:')
            self.show_volumes(euvolumes)
        except: pass
        self.log.debug('Clean_up_volumes: Detaching any attached volumes to be deleted...')
        for vol in euvolumes:
            try:
                vol.update()
                if vol.status == 'in-use':
                    if vol.attach_data and (vol.attach_data.status != 'detaching' or
                                                    vol.attach_data.status != 'detached'):
                        try:
                            self.log.debug('{0} Sending detach. Status:{1}, attach_data.status:{2}'
                                           .format(vol.id, vol.status, vol.attach_data.status))
                            vol.detach()
                        except EC2ResponseError, be:
                            if 'Volume does not exist' in be.error_message:
                                not_exist.append(vol)
                                self.log.debug(str(vol.id) + ', volume no longer exists')
                            else:
                                raise be
                    detaching.append(vol)
            except:
                self.log.warning(get_traceback())
        #  If the volume was found to no longer exist on the system, remove it from
        #  further monitoring...
        for vol in not_exist:
            if vol in detaching:
                detaching.remove(vol)
            if vol in euvolumes:
                euvolumes.remove(vol)
        self.test_resources['volumes'] = euvolumes
        timeout = min_timeout + (len(volumes) * timeout_per_vol)
        #If detaching wait for detaching to transition to detached...
        if detaching:
            self.monitor_euvolumes_to_status(detaching, status='available',
                                             attached_status=None,timeout=timeout)
        self.log.debug('clean_up_volumes: Deleteing volumes now...')
        self.show_volumes(euvolumes)
        if euvolumes:
            self.delete_volumes(euvolumes, timeout=timeout)

    def get_current_resources(self, verbose=False):
        """
        Return a dictionary with all known resources the system has.
        Optional pass the verbose=True flag to print this info to the logs
        Included resources are: addresses, images, instances, key_pairs, security_groups,
        snapshots, volumes, zones
        """
        current_artifacts = dict()
        current_artifacts["addresses"] = self.connection.get_all_addresses()
        current_artifacts["images"] = self.connection.get_all_images()
        current_artifacts["instances"] = self.connection.get_all_instances()
        current_artifacts["key_pairs"] = self.connection.get_all_key_pairs()
        current_artifacts["security_groups"] = self.connection.get_all_security_groups()
        current_artifacts["snapshots"] = self.connection.get_all_snapshots()
        current_artifacts["volumes"] = self.connection.get_all_volumes()
        current_artifacts["zones"] = self.connection.get_all_zones()
        if verbose:
            self.log.debug("Current resources in the system:\n{0}".format(current_artifacts))
        return current_artifacts


class VolumeStateException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class EC2ResourceNotFoundException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

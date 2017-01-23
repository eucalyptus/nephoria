# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2011, Eucalyptus Systems, Inc.
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
# Author: matt.clark@eucalyptus.com

'''
Created on Mar 7, 2012
@author: clarkmatthew
extension of the boto instance class, with added convenience methods + objects
Add common instance test routines to this class

Sample usage:
    testinstance = EuInstance.make_euinstance_from_instance( nephoria.run_instances()[0] )
    print testinstance.id
    output = testinstance.sys("ls /dev/xd*")
    print output[0]
    nephoria.sys('ping '+testinstance.ip_address )
    testinstance.sys('yum install ntpd')
'''

from boto.ec2.instance import Instance, InstanceState
from boto.ec2.networkinterface import NetworkInterface
from boto.exception import EC2ResponseError
from cloud_admin.systemconnection import SystemConnection
from cloud_utils.log_utils import eulogger, printinfo, markup
from cloud_utils.net_utils import get_network_info_for_cidr, test_port_status
from cloud_utils.net_utils.sshconnection import SshConnection, CommandExitCodeException, \
    CommandTimeoutException
from cloud_utils.system_utils.machine import Machine
from cloud_utils.log_utils import get_traceback, markup, TextStyle, ForegroundColor, red, \
    BackGroundColor
from nephoria.aws.ec2.euvolume import EuVolume
from nephoria.euca.taggedresource import TaggedResource
from nephoria.testcase_utils import wait_for_result
from random import randint
from prettytable import PrettyTable, ALL
from datetime import datetime
import os
import re
import time
import copy
import types
import operator


class EuInstance(Instance, TaggedResource, Machine):
    @classmethod
    def make_euinstance_from_instance(cls, instance, ec2ops, debugmethod=None, keypair=None,
                                      keypath=None, password=None, username="root",
                                      auto_connect=True, verbose=True, timeout=120,
                                      private_addressing=False, reservation=None, cmdstart=None,
                                      try_non_root_exec=False, exec_password=None, ssh_retry=2,
                                      distro=None, distro_ver=None, arch=None, proxy_hostname=None,
                                      proxy_username='root', proxy_password=None,
                                      systemconnection=None,
                                      proxy_keypath=None):

        '''
        Primary constructor for this class. Note: to avoid an ssh session within this method,
        provide keys, username/pass later.
        Arguments:
        instance - mandatory- a Boto instance object used to build this euinstance object
        keypair - optional- a boto keypair object used for creating ssh connection to the instance
        username - optional- string used to create ssh connection as an alternative to keypair
        password - optional- string used to create ssh connection to this instance as an
                   alternative to keypair
        exec_password -optional -string used for su or sudo where prompted for password, will
                      default to 'password'
        auto_connect -optional -boolean, if True will attempt to automatically create an ssh
                     session for this instance
        try_non_root_exec -optional -boolean, if True will attempt to use sudo if available
                          else su -c to execute privileged commands
        timeout - optional- integer used for ssh connection timeout
        debugmethod - optional - method, used for debug output
        verbose - optional - boolean to determine if debug is to be printed using debug()
        retry - optional - integer, ssh connection attempts for non-authentication failures
        '''
        newins = EuInstance(instance.connection)
        newins.__dict__ = instance.__dict__
        newins._package_manager = None
        newins.rootfs_device = "sda"
        newins.block_device_prefix = "sd"
        newins.virtio_blk = False
        newins.bdm_root_vol = None
        newins.attached_vols = []
        newins.scsidevs = []
        newins.ops = None
        newins.log = None
        newins.ssh = None
        newins.laststate = None
        newins.laststatetime = None
        newins.age_at_state = None
        newins.vmtype_info = None
        newins.use_sudo = None
        newins.security_groups = []

        newins.ec2ops = ec2ops
        newins._systemconnection = systemconnection
        newins.debugmethod = debugmethod
        if newins.debugmethod is None:
            newins.log = eulogger.Eulogger(identifier=str(instance.id))
            newins.debugmethod = newins.log.debug

        if (keypair is not None):
            if isinstance(keypair, types.StringTypes):
                keyname = keypair
                keypair = ec2ops.get_keypair(keyname)
            else:
                keyname = keypair.name
            keypath = os.getcwd() + "/" + keyname + ".pem"
        newins.keypair = keypair
        newins.keypath = keypath
        newins.password = password
        newins.username = username
        newins.exec_password = exec_password or password
        newins.verbose = verbose
        newins.timeout = timeout
        newins.retry = ssh_retry
        newins.private_addressing = private_addressing
        newins.reservation = reservation or newins.get_reservation()
        if newins.reservation and newins.state != 'terminated':
            newins.security_groups = newins.ec2ops.get_instance_security_groups(newins)
        else:
            newins.security_groups = None
        newins.laststate = newins.state
        newins.cmdstart = cmdstart
        newins.auto_connect = auto_connect
        newins.set_last_status()
        if newins.state != 'terminated':
            newins.update_vm_type_info()
        if newins.root_device_type == 'ebs' and newins.state != 'terminated':
            try:
                volume = newins.ec2ops.get_volume(
                    volume_id=newins.block_device_mapping.get(newins.root_device_name).volume_id)
                newins.bdm_root_vol = EuVolume.make_euvol_from_vol(volume, volume=newins.ec2ops,
                                                                   ec2ops=newins.ec2ops,
                                                                   cmdstart=newins.cmdstart)
            except:
                pass

        if newins.auto_connect and newins.state == 'running':
            newins.connect_to_instance(timeout=timeout)
        # Allow non-root access to try sudo if available else su -c to execute privileged commands
        newins.try_non_root_exec = try_non_root_exec
        if newins.try_non_root_exec:
            if username.strip() != 'root':
                if newins.has_sudo(newins):
                    newins.use_sudo = True
                else:
                    newins.use_sudo = False
        return newins

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.id == other.id
        return False

    @property
    def ssh(self):
        return self._ssh

    @ssh.setter
    def ssh(self, ssh):
        self._ssh = ssh

    @property
    def keypath(self):
        keypath = getattr(self, '_keypath', None)
        if not keypath and self.keypair or self.key_name:
            keyname = self.key_name or self.keypair.name
            local_keys = self.ec2ops.get_all_current_local_keys(key_name=keyname,
                                                                path='./',
                                                                extension='.pem')
            if local_keys:
                local_key = local_keys[0]
                keypath = os.path.abspath(local_key.name + '.pem')
                self.log.debug('Found local file for ssh keypair, setting keypath to:{0}'
                               .format(keypath))
                setattr(self, '_keypath', keypath)
            else:
                self.log.warning('SSH key file not found in local dir on this machine. If trying'
                                 'to connect either set self.keypath or move sshkey to local dir')
        return keypath

    @keypath.setter
    def keypath(self, keypath):
        if keypath is None or isinstance(keypath, basestring):
            setattr(self, '_keypath', keypath)
        else:
            errmsg = '{0}\nExpected string or None type for keypath, got:{1}/{2}'\
                .format(get_traceback(), keypath, type(keypath))
            self.log.error(errmsg)
            raise ValueError(errmsg)

    @property
    def age(self):
        launchtime = self.ec2ops.get_datetime_from_resource_string(self.launch_time)
        # return the elapsed time in seconds
        return (time.mktime(datetime.utcnow().utctimetuple()) -
                time.mktime(launchtime.utctimetuple()))

    @property
    def systemconnection(self):
        return getattr(self, '_systemconnection', None)

    @systemconnection.setter
    def systemconnection(self, connection):
        if connection is None or isinstance(connection, SystemConnection):
            setattr(self, '_systemconnection', connection)


    def update(self, validate=False, dry_run=False, err_state='terminated', err_code=-1):
        ret = None
        tb = ""
        retries = 2
        for x in xrange(0, retries):
            try:
                # send with validation True, fail later...
                ret = super(EuInstance, self).update(validate=True, dry_run=dry_run)
                break
            except ValueError:
                if validate:
                    raise
                tb = get_traceback()
                self.log.debug('Failed to update instance. Attempt:{0}/{1}'
                           .format(x, retries))
        if not ret:
            failmsg = 'Failed to update instance. Instance may no longer ' \
                      'be present on system"{0}"'.format(self.id)
            self.log.debug('{0}\n{1}'.format(tb, failmsg))
            self.log.debug('{0} setting fake state to:"{1}"'.format(self.id,
                                                                err_state))
            state = InstanceState(name=err_state, code=err_code)
            self._state = state
            ret = self.state
        self.set_last_status()
        return ret

    def set_last_status(self, status=None):
        self.laststate = self.state
        self.laststatetime = time.time()
        self.age_at_state = self.ec2ops.get_instance_time_launched(self)
        # Also record age from user's perspective, ie when they issued the run instance
        # request (if this is available)
        if hasattr(self, "cmdstart") and self.cmdstart:
            self.age_from_run_cmd = "{0:.2f}".format(time.time() - self.cmdstart)
        else:
            self.age_from_run_cmd = None

    def get_line(self, length):
        line = ""
        for x in xrange(0, int(length)):
            line += "-"
        return "\n" + line + "\n"

    def printself(self, title=True, footer=True, printmethod=None, printme=True):

        def state_markup(state):
            # Markup instance state...
            if state == 'running':
                return markup(state, markups=[1, 92])
            if state == 'terminated':
                return markup(state, markups=[1, 97])
            if state == 'shutting-down':
                return markup(state, markups=[1, 95])
            if state == 'pending':
                return markup(state, markups=[1, 93])
            if state == 'stopped':
                return markup(state, markups=[1, 91])
            else:
                return markup(state, markups=[1, 91])

        def multi_line(lines):
            # Utility method for creating multi line table entries...
            buf = ""
            maxlen = 0
            for line in lines:
                if len(line) + 2 > maxlen:
                    maxlen = len(line) + 2
            for line in lines:
                buf += str(line).ljust(maxlen) + "\n"
            buf = buf.rstrip()
            return (buf, maxlen)

        bdmvol = self.root_device_type
        if self.bdm_root_vol:
            bdmvol += ":" + self.bdm_root_vol.id
        reservation_id = None
        if self.reservation:
            reservation_id = self.reservation.id
            owner_id = self.reservation.owner_id
        else:
            owner_id = "???"
        # Create a multi line field for instance's run info
        idlist = [markup("{0} {1}".format('ID:', self.id), markups=[1, 4, 94]),
                  "{0} {1}".format(markup('TYPE:'), self.instance_type),
                  "{0} {1}".format(markup('RES:'), reservation_id),
                  "{0}".format(markup("ACCOUNT ID:")), owner_id]
        id_string, idlen = multi_line(idlist)
        try:
            emi = self.ec2ops.get_emi(self.image_id)
            emi_name = str(emi.name[0:18]) + ".."
        except:
            emi_name = ""
        # Create a multi line field for the instance's image info
        virt_type = 'PV'
        if self.virtualization_type == 'hvm':
            virt_type = 'HVM'
        emi_string, emilen = multi_line(
            [markup("{0} {1}".format('EMI:', self.image_id)),
             "{0} {1}".format(markup('OS:'), self.platform or 'linux'),
             "{0} {1}".format(markup('VIRT:'), virt_type),
             "{0}".format(markup('IMAGE NAME:')),
             emi_name])

        # Create a multi line field for the instance's state info
        if self.age:
            age = int(self.age)
        else:
            age = "??"
        state_string, state_len = multi_line(["STATE: " + state_markup(self.laststate),
                                              "{0} {1}".format(markup('AGE:'), age),
                                              "{0} {1}".format(markup("ZONE:"), self.placement),
                                              markup('ROOTDEV:'), bdmvol])
        # Create the primary table called pt...
        netinfo = 'INSTANCE NETWORK INFO:'
        idheader = 'INSTANCE ID'
        imageheader = 'INSTANCE IMAGE'
        stateheader = 'INSTANCE STATE'
        pt = PrettyTable([idheader, imageheader, stateheader, netinfo])
        pt.align[netinfo] = 'l'
        pt.valign[netinfo] = 'm'
        pt.align[idheader] = 'l'
        pt.align[imageheader] = 'l'
        pt.align[stateheader] = 'l'
        pt.max_width[idheader] = idlen
        pt.max_width[imageheader] = emilen
        pt.max_width[stateheader] = state_len
        pt.padding_width = 0
        pt.hrules = ALL
        # PrettyTable headers do not work with ascii markups, so make a sudo header
        new_header = []
        for field in pt._field_names:
            new_header.append(markup(field, markups=[1, 4]))
        pt.add_row(new_header)
        pt.header = False
        # Create a subtable 'netpt' to summarize and format the networking portion...
        # Set the maxwidth of each column so the tables line up when showing multiple instances
        vpc_col = ('VPC', 4)
        subnet_col = ('SUBNET', 6)
        if self.vpc_id:
            vpc_col = ('VPC', 12)
            subnet_col = ('SUBNET', 15)
        secgrp_col = ('SEC GRPS', 11)
        privaddr_col = ('P', 1)
        privip_col = ('PRIV IP', 15)
        pubip_col = ('PUB IP', 15)
        net_cols = [vpc_col, subnet_col, secgrp_col, privaddr_col, privip_col, pubip_col]
        # Get the Max width of the main tables network summary column...
        # Start with 2 to account for beginning and end column borders
        netinfo_width = 2
        netinfo_header = []
        for col in net_cols:
            netinfo_width += col[1] + 1
            netinfo_header.append(col[0])
        pt.max_width[netinfo] = netinfo_width
        netpt = PrettyTable([vpc_col[0], subnet_col[0], secgrp_col[0], privaddr_col[0],
                             privip_col[0], pubip_col[0]])
        netpt.padding_width = 0
        netpt.vrules = ALL
        for col in net_cols:
            netpt.max_width[col[0]] = col[1]
        sec_grps = []
        for grp in self.groups:
            sec_grps.append(str(grp.id))
        sec_grps = " ".join(sec_grps)
        private_addressing = "N"
        if self.private_addressing:
            private_addressing = "Y"
        netpt.add_row([str(self.vpc_id).center(vpc_col[1]),
                       str(self.subnet_id).center(subnet_col[1]),
                       str(sec_grps).center(secgrp_col[1]),
                       str(private_addressing).center(privaddr_col[1]),
                       str(self.private_ip_address).center(privip_col[1]),
                       str(self.ip_address).center(pubip_col[1])])
        # To squeeze a potentially long keyname under the network summary table, get the length
        # and format this column to allow for wrapping a keyname under the table...
        # netbuf = netpt.get_string()
        netbuf = "{0}:{1} {2}:{3}\n".format(markup("NODE"),
                                            self.tags.get('euca:node', "???").ljust(16),
                                            markup("KEYPAIR"), self.key_name)
        netbuf +=  "\n".join(netpt.get_string().splitlines()[0:-1])
        # Create the row in the main table...
        pt.add_row([id_string, emi_string, state_string, netbuf])
        if printme:
            printmethod = printmethod or self.log.debug
            printmethod("\n" + str(pt) + "\n")
        return pt

    def show_summary(self, printmethod=None, printme=True):
        def header(text):
            return markup(text=text, markups=[1, 4, 94])

        reservation_id = None
        if self.reservation:
            reservation_id = self.reservation.id
        title = header('INSTANCE SUMMARY:"{0}", STATE:"{1}", PUB:"{2}", PRIV:"{3}'
                       .format(self.id, self.state, self.ip_address, self.private_ip_address))
        main_pt = PrettyTable([title])
        main_pt.align[title] = 'l'
        main_pt.padding_width = 0
        mainbuf = header("SUMMARY:\n")
        summary_pt = PrettyTable(['ID', 'RESERVATION', 'AGE', 'VMTYPE', 'CLUSTER', 'VIRT TYPE',
                                  'REGION', 'KEY'])
        summary_pt.padding_width = 0
        summary_pt.add_row([self.id, reservation_id, self.age, self.instance_type,
                            self.placement, self.virtualization_type, self.region, self.key_name])
        mainbuf += str(summary_pt) + "\n"
        mainbuf += header('\nINSTANCE NETWORK INFO:\n')
        netpt = PrettyTable(['VPC', 'SUBNET', 'PRIV ONLY', 'PRIV DNS', 'PUB DNS'])
        netpt.padding_width = 0
        netpt.add_row([self.vpc_id, self.subnet_id, self.private_addressing,
                       self.private_dns_name, self.public_dns_name])
        mainbuf += str(netpt) + "\n"
        mainbuf += header("\nINSTANCE ENI TABLE:\n")
        mainbuf += str(self.show_enis(printme=False)) + "\n"
        mainbuf += header("\nINSTANCE SECURITY GROUPS:\n")
        mainbuf += str(self.ec2ops.show_security_groups_for_instance(self, printme=False)) + "\n"
        mainbuf += header("\nINSTANCE IMAGE:\n")
        image = self.ec2ops.get_emi(self.image_id)
        mainbuf += str(self.ec2ops.show_image(image=image, printme=False)) + "\n"
        mainbuf += header("\nINSTANCE BLOCK DEVICE MAPPING:\n")
        mainbuf += str(self.ec2ops.show_block_device_map(self.block_device_mapping,
                                                         printme=False))
        main_pt.add_row([mainbuf])
        if printme:
            printmethod = printmethod or self.log.info
            printmethod("\n" + str(main_pt) + "\n")
        return main_pt

    def show_enis(self, printme=True):
        buf = ""
        try:
            self.update()
        except Exception as UE:
            self.log.warning('{0}\nError while updating instance:{1}'.format(get_traceback(), UE))
        for eni in self.interfaces:
            if isinstance(eni, NetworkInterface):
                dev_index = 'NA'
                if eni.attachment:
                    dev_index = "Index:{0}".format(eni.attachment.device_index)
                attached_status = "?"
                if eni.attachment:
                    dot = eni.attachment.delete_on_termination
                    attached_status = eni.attachment.status
                title = " {0}, DESC:{1}, STATUS:{2} ({3})"\
                    .format(markup("{0}, {1}".format(dev_index, eni.id),
                                   markups=[TextStyle.BOLD, ForegroundColor.BLUE,
                                            BackGroundColor.BG_WHITE]),
                            eni.description, eni.status, attached_status)
                enipt = PrettyTable([title])
                enipt.align[title] = 'l'
                enipt.padding_width = 0
                enipt.horizontal_char = "="
                eni_info_pt = PrettyTable(['key', 'value'])
                eni_info_pt.header = False
                key_len = 8
                val_len = 22
                eni_info_pt.max_width['value'] = 22
                eni_info_pt.padding_width = 1
                eni_info_pt.border = False
                eni_info_pt.align = 'l'
                dot = "?"
                if eni.attachment:
                    dot = eni.attachment.delete_on_termination
                eni_info_pt.add_row(['ID:'.ljust(key_len), str(eni.id).ljust(val_len)])
                eni_info_pt.add_row(['VPC:', getattr(eni, 'vpc_id', None)])
                eni_info_pt.add_row(['SUBNET:', getattr(eni, 'subnet_id', None)])
                eni_info_pt.add_row(['CHECK SRC/DST', getattr(eni, 'source_dest_check', None)])
                region =  getattr(eni, 'region', None)
                if region:
                    region = region.name
                eni_info_pt.add_row(['REGION:', str(region)])
                eni_info_pt.add_row(['OWNER:', getattr(eni, 'owner_id', None)])
                pt = PrettyTable(['ENI INFO', 'PRIV_IPS (Primary)', 'PUB IP', 'MAC ADDR', 'DOT'])
                pt.align = 'l'
                pt.padding_width = 1
                pt.vertical_char = '.'
                pt.max_width['ENI'] = 16
                if eni.private_ip_addresses:
                    private_ips = ",".join(str("{0} ({1})"
                                               .format(x.private_ip_address,
                                                       "P" if x.primary else "").center(20))
                                           for x in eni.private_ip_addresses)
                else:
                    private_ips = None

                pt.add_row([str(eni_info_pt),
                            str(private_ips).ljust(20),
                            str(getattr(eni, 'publicIp', None)).ljust(16),
                            str(getattr(eni, 'mac_address', None)).ljust(12),
                            str(dot).ljust(5)])
                enipt.add_row([(str(pt))])
                sec_group_buf = "Security Groups For ENI {0}:".format(eni.id)
                if eni.groups:
                    sec_group_buf += self.ec2ops.show_security_groups(eni.groups, printme=False)
                else:
                    sec_group_buf += "\nNO SECURITY GROUPS FOR THIS ENI "
                enipt.add_row([sec_group_buf])
                buf += "\n{0}\n".format(enipt)
        if printme:
            self.log.info(buf)
        else:
            return buf

    def reset_ssh_connection(self, timeout=None):
        timeout = int(timeout or self.timeout or 0)
        self.log.debug('reset_ssh_connection for:' + str(self.id))
        if ((self.keypath is not None) or
                ((self.username is not None) and (self.password is not None))):
            if self.ssh is not None:
                self.ssh.close()
            self.log.debug('Connecting ssh ' + str(self.id))
            self.ssh = SshConnection(self.ip_address,
                                     keypair=self.keypair,
                                     keypath=self.keypath,
                                     password=self.password,
                                     username=self.username,
                                     timeout=timeout,
                                     banner_timeout=timeout,
                                     retry=self.retry,
                                     logger=self.log,
                                     verbose=self.verbose)
        else:
            self.log.debug("keypath or username/password need to be populated "
                       "for ssh connection")

    def get_reservation(self):
        res = None
        try:
            res = self.ec2ops.get_reservation_for_instance(self)
        except Exception, e:
            self.update()
            self.log.debug('Could not get reservation for instance in state:' +
                       str(self.state) + ", err:" + str(e))
        return res

    def connect_to_instance(self, connect_timeout=15, timeout=120):
        '''
        Attempts to connect to an instance via ssh.
        param connect_timeout: optional. SshConnection timeout in seconds  used per connection
                               attempt. Default 30
        param timeout: optional. Overall time in seconds to wait for all connections
                       before failure
        '''
        self.log.info("Attempting to reconnect_to_instance:" + self.id)
        traceback = None
        attempts = 0
        connect_timeout = int(connect_timeout or 0)
        timeout = int(timeout or 0)
        if ((self.keypath is not None) or
                ((self.username is not None) and (self.password is not None))):
            start = time.time()
            elapsed = 0
            if self.ssh is not None:
                self.ssh.close()
            self.ssh = None
            while not self.ssh and (elapsed <= timeout):
                attempts += 1
                elapsed = int(time.time() - start)
                try:
                    self.update()
                    if self.state != 'running':
                        try:
                            self.log.error('connect_to_instance: instance not in running state. '
                                              'State:{0}'
                                              .format(self.state))
                        except:
                            pass
                        break
                    self.reset_ssh_connection(timeout=connect_timeout)
                    self.log.debug('Try some sys...')
                    self.sys("")
                    self.log.info("SSH Connection Succeeded")
                    break
                except Exception, se:
                    elapsed = int(time.time() - start)
                    traceback = get_traceback()
                    self.log.warn('Caught exception attempting to reconnect '
                               'ssh: {0}'.format(se))
                    self.log.debug('connect_to_instance: Attempts:' +
                               str(attempts) + ', elapsed:' + str(elapsed) +
                               '/' + str(timeout))
                    time.sleep(5)
                    pass
            elapsed = int(time.time() - start)
            if self.ssh is None:
                if traceback:
                    self.log.error('Failed SSH Connection after elapsed:{0}.\n'
                                      'Exception caught during final connect attempt:\n{1}'
                                      .format(elapsed, traceback))
                self.get_connection_debug()
                raise RuntimeError(str(self.id) +
                                   ":Failed establishing ssh connection to "
                                   "instance, elapsed:" + str(elapsed) +
                                   "/" + str(timeout))
            self.set_rootfs_device()
        else:
            self.log.debug("keypath or username/password need to be populated "
                       "for ssh connection")

    def get_connection_debug(self, systemconnection=None):
        # Add network debug/diag info here...
        # First show arp cache from local machine
        # todo Consider getting info from relevant euca components:
        # - iptables info
        # - route info
        # - instance xml
        systemconnection = systemconnection or self.systemconnection
        self.log.debug(markup('Dumping Connection debug info for Instance:"{0}, pub:{1}, '
                                      'priv:{2}"'
                                      .format(self.id, self.ip_address, self.private_ip_address),
                   markups=[1, 4, 95]))
        try:
            # Show local ARP info...
            arp_out = "\nLocal ARP cache for instance ip: " \
                      + str(self.ip_address) + "\n"
            arp_fd = os.popen('arp ' + str(self.ip_address))
            for line in arp_fd:
                arp_out += line
            self.log.debug(arp_out)
        except Exception as AE:
            self.log.debug('Failed to get arp info:' + str(AE))
        self.get_cloud_init_info_from_console()
        # For classic modes, check nodes for conflicts.
        #tbd - Add checks for vpc backends if a vpc backend is available.
        if not self.vpc_id and systemconnection:
            my_node = None
            try:
                my_node = systemconnection.get_hosts_for_node_controllers(instanceid=self.id)[0]
                self.log.debug('Ip addrs for node:"{0}" which is hosting:"{1}"...'
                               .format(my_node.hostname, self.id))
                my_node.sys('ip addr list')
            except Exception as NE:
                self.log.debug('Was unable to gather debug for the node hosting this VM, err: {0}'
                           .format(NE))
                pass
            try:
                self.log.debug('Checking other nodes for possible conflicts...')
                nodes = systemconnection.get_hosts_for_node_controllers()
                if my_node and (my_node in nodes):
                    nodes.remove(my_node)

                for node in nodes:
                    try:
                        self.log.debug('Node "NOT" hosting instance:"{0}"...'.format(self.id))
                        node.sys('ip addr list')
                    except:
                        pass
            except Exception as IPL:
                self.log.debug('Failed gathering ip addr list debug info from all nodes, err: "{0}"'
                           .format(IPL))
                pass
        self.log.debug(markup('DONE Dumping Connection debug info for Instance:"{0}"'
                                      .format(self.id), markups=[1, 4, 95]))

    def get_cloud_init_info_from_console(self):
        ret_buf = ""
        try:
            c_output = self.connection.get_console_output(self.id)
            if c_output:
                output = c_output.output
                ci_lines = []
                if not isinstance(output, list):
                    output = str(output).splitlines()
                for line in output:
                    if re.search('ci-info|cloud-init|WARNING|ERROR|CRITICAL', line):
                        ci_lines.append(line)
                for x in ci_lines:
                    self.log.debug("Console ci-info '{0}':".format(x))
                    ret_buf += x + "\n"
        except Exception as CE:
            self.log.error('{0}Failed to get console output:{1}'
                              .format(get_traceback(), str(CE)))
        return ret_buf

    def has_sudo(self):
        try:
            # Run ssh command directly from ssh interface not local sys()
            self.ssh.sys('which sudo', code=0)
            return True
        except CommandExitCodeException, se:
            self.log.debug('Could not find sudo on remote machine:' +
                       str(self.ip_address))
        return False

    def sys(self, cmd, verbose=True, code=None, try_non_root_exec=None,
            enable_debug=False, timeout=120):
        '''
        Issues a command against the ssh connection to this instance
        Returns a list of the lines from stdout+stderr as a result of the command
        cmd - mandatory - string, the command to be executed
        verbose - optional - boolean flag to enable debug
        timeout - optional - command timeout in seconds
        '''
        if (self.ssh is None):
            raise Exception("{0}: Euinstance ssh connection is None".format(self.id))
        if self.username != 'root' and try_non_root_exec:
            if self.use_sudo:
                results = self.sys_with_sudo(cmd,
                                             verbose=verbose,
                                             code=code,
                                             enable_debug=enable_debug,
                                             timeout=timeout)
                for content in results:
                    if content.startswith("sudo"):
                        results.remove(content)
                        break
                return results
            else:
                return self.sys_with_su(cmd,
                                        verbose=verbose,
                                        code=code,
                                        enable_debug=enable_debug,
                                        timeout=timeout)

        return self.ssh.sys(cmd, verbose=verbose, code=code, timeout=timeout)

    def sys_with_su(self, cmd, verbose=True, enable_debug=False, code=None,
                    prompt='^Password:', username='root', password=None, retry=0,
                    timeout=120):
        password = password or self.exec_password
        out = self.cmd_with_su(cmd,
                               username=username,
                               password=password,
                               prompt=prompt,
                               verbose=verbose,
                               enable_debug=enable_debug,
                               timeout=timeout,
                               retry=retry,
                               listformat=True)
        output = out['output']
        if code is not None:
            if out['status'] != code:
                self.log.debug(output)
                raise CommandExitCodeException(
                    'Cmd:' + str(cmd) + ' failed with status code:' +
                    str(out['status']) + ", output:" + str(output))
        return output

    def cmd_with_su(self,
                    cmd,
                    verbose=True,
                    prompt="^Password:",
                    username='root',
                    password=None,
                    listformat=False,
                    cb=None,
                    cbargs=[],
                    get_pty=True,
                    timeout=120,
                    retry=0,
                    enable_debug=False):
        password = password or self.exec_password
        cmd = 'su ' + str(username) + ' -c "' + str(cmd) + '"'
        return self.cmd_expect_password(cmd,
                                        password=password,
                                        prompt=prompt,
                                        verbose=verbose,
                                        enable_debug=enable_debug,
                                        timeout=timeout,
                                        listformat=listformat,
                                        cb=cb,
                                        cbargs=cbargs,
                                        get_pty=get_pty,
                                        retry=retry)

    def sys_with_sudo(self, cmd, verbose=True, enable_debug=False,
                      prompt='^\[sudo\] password', code=None,
                      password=None, retry=0, timeout=120):
        password = password or self.exec_password
        out = self.cmd_with_sudo(cmd,
                                 password=password,
                                 enable_debug=enable_debug,
                                 prompt=prompt,
                                 verbose=verbose,
                                 timeout=timeout,
                                 retry=retry,
                                 listformat=True)
        output = out['output']
        if code is not None:
            if out['status'] != code:
                self.log.debug(output)
                raise CommandExitCodeException(
                    'Cmd:' + str(cmd) + ' failed with status code:' +
                    str(out['status']) + ", output:" + str(output))
        return output

    def cmd_with_sudo(self,
                      cmd,
                      verbose=True,
                      enable_debug=False,
                      prompt="^\[sudo\] password",
                      password=None,
                      listformat=False,
                      cb=None,
                      cbargs=[],
                      get_pty=True,
                      timeout=120,
                      retry=0):
        password = password or self.exec_password
        if re.search("'", cmd):
            delim = '"'
        else:
            delim = "'"

        cmd = "sudo sh -c " + delim + str(cmd) + delim
        return self.cmd_expect_password(cmd,
                                        password=password,
                                        prompt=prompt,
                                        verbose=verbose,
                                        timeout=timeout,
                                        listformat=listformat,
                                        enable_debug=enable_debug,
                                        cb=cb,
                                        cbargs=cbargs,
                                        get_pty=get_pty,
                                        retry=retry)

    def cmd_expect_password(self,
                            cmd,
                            verbose=None,
                            enable_debug=False,
                            prompt='password',
                            password=None,
                            timeout=120,
                            listformat=False,
                            cb=None,
                            cbargs=[],
                            get_pty=True,
                            retry=0):

        if (self.ssh is None):
            raise Exception("Euinstance ssh connection is None")
        password = password or self.exec_password
        return self.ssh.cmd(cmd,
                            verbose=verbose,
                            timeout=timeout,
                            listformat=listformat,
                            cb=self.ssh.expect_password_cb,
                            cbargs=[password,
                                    prompt,
                                    cb,
                                    cbargs,
                                    retry,
                                    0,
                                    enable_debug],
                            get_pty=get_pty)

    '''
    def start_interactive_ssh(self, timeout=180):
        return self.ssh.start_interactive(timeout=timeout)
    '''

    def cmd(self, cmd, verbose=None, enable_debug=False,
            try_non_root_exec=None, timeout=120, listformat=False,
            cb=None, cbargs=[], get_pty=True, net_namespace=None):
        """
        Runs a command 'cmd' within an ssh connection.
        Upon success returns dict representing outcome of the command.

        Returns dict:
            ['cmd'] - The command which was executed
            ['output'] - The std out/err from the executed command
            ['status'] - The exitcode of the command. Note in the case a call back fires, this
                         exitcode is unreliable.
            ['cbfired']  - Boolean to indicate whether or not the provided callback fired
                          (ie returned False)
            ['elapsed'] - Time elapsed waiting for command loop to end.
        Arguments:
        :param cmd: - mandatory - string representing the command to be run  against the remote
                     ssh session
        :param verbose: - optional - will default to global setting, can be set per cmd() as
                          well here
        :param timeout: - optional - integer used to timeout the overall cmd() operation in case
                          of remote blocking
        :param listformat: - optional - boolean, if set returns output as list of lines, else a
                            single buffer/string
        :param cb: - optional - callback, method that can be used to handle output as it's
                        rx'd instead of waiting for the cmd to finish and return buffer.
                        Called like: cb(ssh_cmd_out_buffer, *cbargs)
                        Must accept string buffer, and return an integer to be used as cmd status.
                        Must return type 'sshconnection.SshCbReturn'
                        If cb returns stop, recv loop will end, and channel will be closed.
                        if cb settimer is > 0, timer timeout will be adjusted for this time
                        if cb statuscode is != -1 cmd status will return with this value
                        if cb nextargs is set, the next time cb is called these args will be
                        passed instead of cbargs
        :param cbargs: - optional - list of arguments to be appended to output buffer and
                         passed to cb

        """
        if net_namespace is not None:
            cmd = 'ip netns exec {0} {1}'.format(net_namespace, cmd)
        if (self.ssh is None):
            raise Exception("{0}: Euinstance ssh connection is None".format(self.id))
        if try_non_root_exec is None:
            try_non_root_exec = self.try_non_root_exec
        if self.username != 'root' and try_non_root_exec:
            if self.use_sudo:
                return self.cmd_with_sudo(cmd, verbose=verbose, timeout=timeout,
                                          enable_debug=enable_debug, listformat=listformat,
                                          cb=cb, cbargs=cbargs, get_pty=get_pty)
            else:
                return self.cmd_with_su(cmd, verbose=verbose, timeout=timeout,
                                        enable_debug=enable_debug, listformat=listformat,
                                        cb=cb, cbargs=cbargs, get_pty=get_pty)
        return self.ssh.cmd(cmd, verbose=verbose, timeout=timeout, listformat=listformat,
                            cb=cb, cbargs=cbargs, get_pty=get_pty)

    def found(self, command, regex, verbose=True):
        """ Returns a Boolean of whether the result of the command contains the regex"""
        result = self.sys(command, verbose=verbose  )
        for line in result:
            found = re.search(regex, line)
            if found:
                return True
        return False

    def get_dev_dir(self, match=None):
        '''
        Attempts to return a list of devices in /dev which match the given grep criteria
        By default will attempt to match self.block_device_prefix if populated, otherwise will
        try to match sd,vd, and xd device prefixes.
        returns a list of matching dev names.
        match - optional - string used in grep search of /dev dir on instance
        '''
        retlist = []
        if match is None:
            match = '^sd\|^vd\|^xd\|^xvd'
        out = self.sys("ls -1 /dev/ | grep '" + str(match) + "'")
        for line in out:
            retlist.append(line.strip())
        return retlist

    def attach_volume(self, volume, dev=None, timeout=180, write_len=32, md5_len=None,
                      overwrite=False):
        '''
        Method used to attach a volume to an instance and track it's use by that instance
        required - euvolume - the euvolume object being attached
        required - tester - the eucaops/nephoria object/connection for this cloud
        optional - dev - string to specify the dev path to 'request' when attaching the volume to
        optional - timeout - integer- time allowed before failing
        optional - overwrite - flag to indicate whether to overwrite head data of a non-zero
                              filled volume upon attach for md5
        '''
        if not isinstance(volume, EuVolume):
            volume = EuVolume.make_euvol_from_vol(volume)
        return self.attach_euvolume(volume, dev=dev, timeout=timeout, write_len=write_len,
                                    md5_len=md5_len, overwrite=overwrite)

    def attach_euvolume(self, euvolume, dev=None, srcdev='/dev/zero', write_len=32, md5_len=None,
                        timeout=180, gb_timeout=120, overwrite=False):
        '''
        Method used to attach a volume to an instance and track it's use by that instance
        required - euvolume - the euvolume object being attached
        required - tester - the eucaops/nephoria object/connection for this cloud
        optional - dev - string to specify the dev path to 'request' when attaching the volume to
        optional - timeout - integer- time allowed before failing
        optional - overwrite - flag to indicate whether to overwrite head data of a non-zero
                  filled volume upon attach for md5
        optional - write_len - int length in bytes to write signature into volume upon attach
        optional - md5_len - int length in bytes to read for md5 of volume upon attach
        optional - gb_timeout -int time to allow per gb to be written to volume
        '''
        if not isinstance(euvolume, EuVolume):
            raise Exception("Volume needs to be of type euvolume, try attach_volume() instead?")

        self.log.debug("Attempting to attach volume:" + str(euvolume.id) + " to instance:" +
                   str(self.id) + " to dev:" + str(dev))
        md5_len = md5_len or write_len
        # grab a snapshot of our devices before attach for comparison purposes
        dev_list_before = self.get_dev_dir()
        dev_list_after = []
        attached_dev = None
        start = time.time()
        elapsed = 0
        if dev is None:
            # update our block device prefix, detect if virtio is now in use
            self.set_block_device_prefix()
            dev = self.get_free_scsi_dev()
        if (self.ec2ops.attach_volume(self, euvolume, dev, pause=10, timeout=timeout)):
            if euvolume.attach_data.device != dev:
                raise Exception('Attached device:' + str(euvolume.attach_data.device) +
                                ", does not equal requested dev:" + str(dev))
            # Find device this volume is using on guest...
            euvolume.guestdev = None
            while (not euvolume.guestdev and elapsed < timeout):
                self.log.debug("Checking for volume attachment on guest, elapsed time(" +
                           str(elapsed) + ")")
                dev_list_after = self.get_dev_dir()
                self.log.debug("dev_list_after:" + " ".join(dev_list_after))
                diff = list(set(dev_list_after) - set(dev_list_before))
                if len(diff) > 0:
                    devlist = str(diff[0]).split('/')
                    attached_dev = '/dev/' + devlist[len(devlist) - 1]
                    euvolume.guestdev = attached_dev.strip()
                    self.log.debug(
                        "Volume:" + str(euvolume.id) + " guest device:" + str(euvolume.guestdev))
                    self.attached_vols.append(euvolume)
                    self.log.debug(euvolume.id + " Requested dev:" +
                               str(euvolume.attach_data.device) +
                               ", attached to guest device:" + str(euvolume.guestdev))
                    break
                elapsed = int(time.time() - start)
                time.sleep(2)
            if not euvolume.guestdev or not attached_dev:
                raise Exception('Device not found on guest after ' + str(elapsed) + ' seconds')
            self.log.debug(str(euvolume.id) + "Found attached to guest at dev:" +
                       str(euvolume.guestdev) + ', after elapsed:' + str(elapsed))
        else:
            self.log.debug('Failed to attach volume:' + str(euvolume.id) + ' to instance:' + self.id)
            raise Exception('Failed to attach volume:' + str(euvolume.id) +
                            ' to instance:' + self.id)
        if (attached_dev is None):
            self.log.debug("List after\n" + " ".join(dev_list_after))
            raise Exception('Volume:' + str(euvolume.id) + ' attached, but not found on guest' +
                            str(self.id) + ' after ' + str(elapsed) + ' seconds?')

        def try_to_write_to_disk():
            # Check to see if this volume has unique data in the head otherwise write some
            # and md5 it
            try:
                self.vol_write_random_data_get_md5(euvolume, srcdev=srcdev, length=write_len,
                                                   md5_len=md5_len, timepergig=gb_timeout,
                                                   overwrite=overwrite)
                return True
            except:
                self.log.debug("\n" + str(get_traceback()) +
                           "\nError caught in try_to_write_to_disk")
                return False

        wait_for_result(try_to_write_to_disk, True)
        self.log.debug('Success attaching volume:' + str(euvolume.id) + ' to instance:' + self.id +
                   ', cloud dev:' + str(euvolume.attach_data.device) + ', attached dev:' +
                   str(attached_dev))
        return attached_dev

    def detach_euvolume(self, euvolume, waitfordev=True, timeout=180):
        '''
        Method used to detach detach a volume to an instance and track it's use by that instance
        required - euvolume - the euvolume object being deattached
        waitfordev - boolean to indicate whether or no to poll guest instance for local device
                     to be removed
        optional - timeout - integer seconds to wait before timing out waiting for the
                   volume to detach
        '''
        start = time.time()
        elapsed = 0
        for vol in self.attached_vols:
            if vol.id == euvolume.id:
                dev = vol.guestdev
                if (self.ec2ops.detach_volume(euvolume, timeout=timeout)):
                    if waitfordev:
                        self.log.debug("Wait for device:" + str(dev) + " to be removed on guest...")
                        while (elapsed < timeout):
                            try:
                                # check to see if device is still present on guest
                                self.assertFilePresent(dev)
                            except Exception, e:
                                # if device is not present remove it
                                self.attached_vols.remove(vol)
                                return True
                            time.sleep(10)
                            elapsed = int(time.time() - start)
                            self.log.debug("Waiting for device '" + str(dev) +
                                       "' on guest to be removed. Elapsed:" + str(elapsed))
                        # one last check, in case dev has changed.
                        self.log.debug("Device " + str(dev) + " still present on " + str(self.id) +
                                   " checking sync state...")
                        if self.get_dev_md5(dev, euvolume.md5len) == euvolume.md5:
                            raise Exception("Volume(" + str(vol.id) + ") detached, but device(" +
                                            str(dev) + ") still present on (" + str(self.id) + ")")
                        else:
                            # assume the cloud has successfully released the device,
                            # guest may have not
                            self.log.debug(str(self.id) + 'previously attached device for vol(' +
                                       str(euvolume.id) + ') no longer matches md5')
                            return True
                    else:
                        self.attached_vols.remove(vol)
                        return True

                else:
                    raise Exception("Volume(" + str(vol.id) + ") failed to detach from device(" +
                                    str(dev) + ") on (" + str(self.id) + ")")
        raise Exception("Detach Volume(" + str(euvolume.id) + ") not found on (" + str(self.id) +
                        ")")

    def get_metadata(self, element_path, prefix='latest/meta-data/', timeout=10, staticmode=False):
        """
        Return the lines of metadata from the element path provided
        If i can reach the metadata service ip use it to get metadata otherwise try
        the clc directly
        """
        try:
            return self.sys("curl http://169.254.169.254/" + str(prefix) + str(element_path),
                            code=0, timeout=timeout)
        except CommandTimeoutException as se:
            if staticmode:
                return self.sys("curl http://" + self.ec2ops.get_ec2_ip() + ":8773/" +
                                str(prefix) + str(element_path), code=0)
            else:
                raise (se)

    def set_block_device_prefix(self):
        return self.set_rootfs_device()

    def set_rootfs_device(self):
        self.rootfs_device = "sda"
        self.block_device_prefix = "sd"
        self.virtio_blk = False
        try:
            self.sys("ls /dev/vda", code=0)
            self.rootfs_device = "vda"
            self.block_device_prefix = "vd"
            self.virtio_blk = True
            return
        except:
            pass
        try:
            self.sys("ls /dev/xvda", code=0)
            self.rootfs_device = "xvda"
            self.block_device_prefix = "xvd"
            self.virtio_blk = False
            return
        except:
            pass
        try:
            self.sys("ls /dev/sda", code=0)
            self.rootfs_device = "sda"
            self.block_device_prefix = "sd"
            self.virtio_blk = False
            return
        except:
            pass


    def terminate(self, dry_run=False):
        errors = ""
        try:
            if self.log:
                self.log.close()
        except Exception as LE:
            errors = "{0}\n{1}\n".format(get_traceback(), LE)
        try:
            if self.ssh:
                self.ssh.connection.close()
                self.ssh.close()
        except Exception as SE:
            errors = "{0}\n{1}\n".format(get_traceback(), SE)
        if errors:
            self.log.error('{0}\n{1}Error closing instances fds'.format(errors, self.id))
        try:
            super(EuInstance, self).terminate(dry_run=dry_run)
        except EC2ResponseError as ERE:
            if ERE.status == 400 and ERE.reason == 'InvalidInstanceID.NotFound':
                self.log.debug('Caught 400 during terminate(). Assuming instance has already been '
                               'terminated and removed from system: "{0}"'.format(ERE))

    def terminate_and_verify(self, verify_vols=True, verify_eni=True,
                             volto=180, timeout=300, poll_interval=10):
        '''
        Attempts to terminate the instance and verify delete on terminate state of an ebs root
        block dev if any. If flagged will attempt to verify the correct
        state of any volumes attached during the terminate operation.

        :type verify_vols: boolean
        :param verify_vols: boolean used to flag whether or not to check for correct volume
                            state after terminate

        :type volto: integer
        :param volto: timeout used for time in seconds to wait for volumes to detach and become
                      available after terminating the instnace

        :type timeout: integer
        :param timeout: timeout in seconds when waiting for an instance to go to terminated state.
        '''
        self.update()
        all_vols = []
        enis = self.interfaces
        err_buff = ""
        elapsed = 0
        if verify_vols:
            # Check that local obj's attached volume state matches cloud's, mainly to alert
            # to errors in test script...
            self.log.debug('Checking euinstance attached volumes states are in sync with clouds')
            for vol in self.attached_vols:
                try:
                    self.verify_attached_vol_cloud_status(vol)
                except Exception, e:
                    err_buff += "ERROR: Unsynced volumes found prior to issuing terminate, " \
                                "check test code:"
                    err_buff += '\n' + str(self.id) + \
                                ':Caught exception verifying attached status for:' + \
                                str(vol.id) + ", Error:" + str(e)
        if verify_vols:
            all_vols = self.ec2ops.get_volumes(attached_instance=self.id)
            for device in self.block_device_mapping:
                dev_map = self.block_device_mapping[device]
                self.log.debug(str(self.id) + ", has volume:" + str(dev_map.volume_id) +
                           " mapped at device:" + str(device))
                for volume in all_vols:
                    if volume.id == dev_map.volume_id:
                        volume.delete_on_termination = dev_map.delete_on_termination
        self.terminate()
        self.ec2ops.wait_for_instance(self, state='terminated', timeout=timeout)
        if verify_vols:
            start = time.time()
            while all_vols and elapsed < volto:
                elapsed = int(time.time() - start)
                loop_vols = copy.copy(all_vols)
                for vol in loop_vols:
                    vol_status = 'available'
                    fail_fast_status = 'deleted'
                    if hasattr(vol, 'delete_on_termination'):
                        if vol.delete_on_termination:
                            vol_status = 'deleted'
                            fail_fast_status = 'available'
                        self.log.debug('volume:' + str(vol.id) + "/" + str(vol.status) +
                                   ", from BDM, D.O.T.:" + str(vol.delete_on_termination) +
                                   ", waiting on status:" + str(vol_status) + ", elapsed:" +
                                   str(elapsed) + "/" + str(volto))
                    else:
                        self.log.debug('volume:' + str(vol.id) + "/" + str(vol.status) +
                                   ", was attached, waiting on status:" +
                                   str(vol_status) + ", elapsed:" + str(elapsed) + "/" + str(volto))
                    vol.expected_status = vol_status
                    vol.update()
                    # If volume has reached it's intended status or
                    # the volume is no longer on the system and it's intended status is 'deleted'
                    if vol.status == vol_status or \
                            (not self.ec2ops.get_volume(volume_id=vol.id, eof=False) and
                             vol_status == 'deleted'):
                        self.log.debug(str(self.id) + ' terminated, ' + str(vol.id) +
                                   "/" + str(vol.status) + ": volume entered expected state:" +
                                   str(vol_status))
                        all_vols.remove(vol)
                        if vol in self.attached_vols:
                            self.attached_vols.remove(vol)
                    if vol.status == fail_fast_status and elapsed >= 30:
                        self.log.debug('Incorrect status for volume:' + str(vol.id) + ', status:' +
                                   str(vol.status))
                        all_vols.remove(vol)
                        err_buff += "\n" + str(self.id) + ":" + str(vol.id) + \
                                    " Volume incorrect status:" + str(vol.status) + \
                                    ", expected status:" + str(vol.expected_status) + \
                                    ", elapsed:" + str(elapsed)
                if all_vols:
                    time.sleep(poll_interval)
            for vol in all_vols:
                err_buff += "\n" + str(self.id) + ":" + str(vol.id) + \
                            " Volume timeout on current status:" + str(vol.status) + \
                            ", expected status:" + str(vol.expected_status) + \
                            ", elapsed:" + str(elapsed)
        if verify_eni:
            self.log.debug('Checking previously attached ENI status post instance terminate...')
            good_enis = []
            start = time.time()
            elapsed = 0
            attempts = 0
            last_errors = ""
            # Set the dot flag in the main eni obj, in case the attachment disappears...
            for eni in enis:
                eni.dot = eni.attachment.delete_on_termination
            def eni_check(eni):
                """
                Perform Post termination checks on ENI...
                """
                self.log.debug('Checking ENI:{0} status post {1} termination. '
                               'Status:{2}, Attachment-Status:{3}'
                               .format(eni, self.id, getattr(eni, 'status', None),
                                       getattr(getattr(eni, 'attachment', None), 'status', None)))
                # Check delete on terminate attribute we applied beforehand...
                dot = eni.dot
                try:
                    eni.update()
                except EC2ResponseError as EE:
                    if int(EE.status) == 400 and EE.reason == 'InvalidNetworkInterfaceID.NotFound':
                        if eni.dot:
                            self.log.debug('{0} was properly deleted per "delete_on_terminate" '
                                           'flag'.format(eni.id))
                            eni.status = 'deleted'
                            eni.attachment = None
                        else:
                            self.log.error("{0} not found on update, and delete on terminate flag"
                                           "was not set?".format(eni.id))
                            raise EE
                if eni.status != 'deleted':
                    if eni.status != 'available':
                        raise ValueError('{0} status != "available" post {1} termination'
                                         .format(eni.id, self.id))
                    if eni.attachment:
                        if eni.attachment.instance_id != self.id:
                            if eni.dot:
                                raise ValueError('ENI {0} should have been "deleted on '
                                                 'termination" of {1} but is now attached to {2}'
                                                 .format(eni.id, self.id,
                                                         eni.attachment.instance_id))
                        raise ValueError('{0} attachment is still present post termination of {1},'
                                         ' eni status:{2}'.format(eni.id,
                                                                  self.id,
                                                                  getattr(eni, 'status', None)))
                    else:
                        if eni.dot:
                            raise ValueError('ENI {0} "delete_on_terminate" flag was set but '
                                             'ENI is still present post {1} termination'
                                             .format(eni.id, self.id))
                self.log.debug('SUCCESS: ENI:{0} entered correct state post {1} termination. '
                               'Status:{2}, Attachment-Status:{3}'
                               .format(eni, self.id, getattr(eni, 'status', None),
                                       getattr(getattr(eni, 'attachment', None), 'status', None)))

            eni = None
            # Poll ENI status until all ENIs are good, or the timeout is reached...
            while len(good_enis) < len(enis) and elapsed < timeout:
                last_errors = ""
                elapsed = int(time.time() - start)
                attempts += 1
                for eni in enis:
                    if eni in good_enis:
                        continue
                    else:
                        try:
                            eni_check(eni)
                            good_enis.append(eni)
                        except Exception as E:
                            self.log.debug(get_traceback())
                            msg = 'ENI:{0}, ERROR: "{1}"\n'.format(eni.id, E)
                            self.log.debug(msg)
                            last_errors += msg
                if last_errors:
                    self.log.debug('Waiting on {0} ENIs to enter proper status post {1} terminate. '
                                   'Attempts: {2} Elapsed:{3}.\nLatest ENI errors:\n{4}'
                                   .format(len(enis) - len(good_enis), self.id, attempts, elapsed,
                                           last_errors))
                    try:
                        self.log.debug(self.show_enis(printme=False))
                    except Exception as SE:
                        self.log.warning('{0}\nIGNORING ERROR in show_enis() attempt:{1}'
                                         .format(get_traceback(), SE))
                    time.sleep(2)
            # Check to see if all the ENIs were considered 'good'...
            if len(good_enis) != len(enis):
                self.log.error('Elapsed:{0}, Good ENIs:"{1}", TOTAL ENIS:"{2}"'.
                               format(elapsed, good_enis, enis))
                err_buff += '\nENI Errors detected post terminate after elapsed:{0}/{1}. ' \
                            'Errors:"{1}"'.format(elapsed, timeout, last_errors)

        # Report the sum of errors if any...
        if err_buff:
            self.log.error("{0}, errors found during instance terminate_and_verify:\n{1}"
                            .format(self.id,err_buff))
            raise RuntimeError("{0}, errors found during instance terminate_and_verify:\n{1}"
                               .format(self.id,err_buff))

    def get_guestdevs_inuse_by_vols(self):
        retlist = []
        for vol in self.attached_vols:
            retlist.append(vol.guestdev)
        return retlist

    def get_free_scsi_dev(self, prefix=None, maxdevs=100):
        '''
        The volume attach command requires a cloud level device name that is not currently
        associated with a volume
        Note: This is the device name from the clouds perspective, not necessarily the guest's
        This method attempts to find a free device name to use in the command
        optional - prefix - string, pre-pended to the the device search string
        optional - maxdevs - number use to specify the max device names to iterate over.
                   Some virt envs have a limit of 16 devs.
        '''
        d = 'e'
        in_use_cloud = ""
        in_use_guest = ""
        dev = None
        if prefix is None:
            prefix = self.block_device_prefix
        cloudlist = self.ec2ops.get_volumes(attached_instance=self.id)

        for x in xrange(0, maxdevs):
            inuse = False
            # double up the letter identifier to avoid exceeding z
            if d == 'z':
                prefix = prefix + 'e'
            dev = "/dev/" + prefix + str(d)
            for avol in self.attached_vols:
                if avol.attach_data.device == dev:
                    inuse = True
                    in_use_guest += str(avol.id) + ", "
                    continue
            # Check to see if the cloud has a conflict with this device name...
            for vol in cloudlist:
                try:
                    vol.update()
                except EC2ResponseError as ER:
                    if ER.status == 400:
                        continue
                if (vol.attach_data is not None) and (vol.attach_data.device == dev):
                    inuse = True
                    in_use_cloud += str(vol.id) + ", "
                    continue
            if inuse is False:
                self.log.debug("Instance:" + str(self.id) + " returning available cloud scsi dev:" +
                           str(dev))
                return str(dev)
            else:
                d = chr(ord('e') + x)  # increment the letter we append to the device string prefix
                dev = None
        if dev is None:
            raise Exception("Could not find a free scsi dev on instance:" + self.id +
                            ", maxdevs:" + str(maxdevs) + "\nCloud_devs:" + str(in_use_cloud) +
                            "\nGuest_devs:" + str(in_use_guest))

    def zero_fill_volume(self, euvolume):
        '''
        zero fills the given euvolume with,returns dd's data/time stat
        '''
        voldev = euvolume.guestdev.strip()
        self.assertFilePresent(voldev)
        fillcmd = "dd if=/dev/zero of=" + str(voldev) + "; sync"
        return self.time_dd(fillcmd)

    @printinfo
    def random_fill_volume(self, euvolume, srcdev=None, length=None, timepergig=120):
        '''
        Attempts to fill the entire given euvolume with unique non-zero data.
        The srcdev is read from in a set size, and then used to write to the euvolume to
        populate it. The file helps with both speed up the copy in the urandom case, and adds
        both some level of randomness another src device as well as allows smaller src devs to be
        used to fill larger euvolumes by repeatedly reading into the copy.
        :param euvolume: the attached euvolume object to write data to
        :param srcdev: the source device to copy data from
        :param length: the number of bytes to copy into the euvolume
        :returns dd's data/time stat
        '''
        mb = 1048576
        gb = 1073741824
        fsize = 4096
        if euvolume not in self.attached_vols:
            raise Exception(self.id + " Did not find this in instance's attached list. "
                                      "Can not write to this euvolume")

        voldev = euvolume.guestdev.strip()
        self.assertFilePresent(voldev)
        if srcdev:
            self.assertFilePresent(srcdev)
        randsrc = None

        if self.found('ls /dev/urandom', 'urandom'):
            randsrc = '/dev/urandom'
        else:
            # look for the another large device we can read from in random size increments
            randsrc = "/dev/" + str(self.sys("ls -1 /dev | grep 'da$'")[0]).strip()
            fsize = randint(1048576, 10485760)
        if srcdev is None:
            srcdev = randsrc
        if not length:
            timeout = int(euvolume.size) * timepergig
        else:
            timeout = timepergig * ((length / gb) or 1)
        # write the volume id into the volume for starters
        ddcmd = 'echo "{0} $(head -c 1000 {1})" | dd of={2}'.format(euvolume.id, randsrc, voldev)
        dd_res_for_id = self.dd_monitor(ddcmd=ddcmd, timeout=timeout, sync=False)
        if length is not None:
            len_remaining = length - int(dd_res_for_id['dd_bytes'])
            self.log.debug('length remaining to write after adding volumeid:' + str(len_remaining))
            if len_remaining <= 0:
                self.sys('sync')
                return dd_res_for_id
            ddbs = 1024
            if len_remaining < ddbs:
                ddbs = len_remaining
            return self.dd_monitor(ddif=str(srcdev),
                                   ddof=str(voldev),
                                   ddbs=ddbs,
                                   ddbytes=len_remaining,
                                   ddseek=int(dd_res_for_id['dd_bytes']),
                                   timeout=timeout)
        else:
            length = self.get_blockdev_size_in_bytes(voldev)
            len_remaining = length - int(dd_res_for_id['dd_bytes'])
            self.log.debug('length remaining to write after adding volumeid:' + str(len_remaining))
            if len_remaining <= 0:
                self.sys('sync')
                return dd_res_for_id
            return self.dd_monitor(ddif=str(srcdev),
                                   ddof=str(voldev),
                                   ddbs=fsize,
                                   ddbytes=len_remaining,
                                   ddseek=int(dd_res_for_id['dd_bytes']),
                                   timeout=timeout)

    def time_dd(self, ddcmd, timeout=120, poll_interval=1, tmpfile=None):
        '''
        Added for legacy support, use dd_monitor instead) Executes dd command on instance,
        parses and returns stats on dd outcome
        '''
        return self.dd_monitor(ddcmd=ddcmd, poll_interval=poll_interval, tmpfile=tmpfile)

    def vol_write_random_data_get_md5(self, euvolume, srcdev=None, length=32, md5_len=None,
                                      timepergig=120, overwrite=False):
        '''
        Attempts to copy some amount of data into an attached volume, and return the md5sum of
        that volume.
        A brief check of the first 32 bytes is performed to see if this volume has pre-existing
        non-zero filled data.
        If pre-existing data is found, and the overwrite flag is not set then the write is not
        performed.
        Returns string with MD5 checksum calculated on 'length' bytes from the head of the device.
        volume - mandatory - boto volume object of the attached volume
        srcdev - optional - string, the file to copy into the volume
        timepergig - optional - the time in seconds per gig, used to estimate an adequate
                    timeout period
        overwrite - optional - boolean. write to volume regardless of whether existing data
                    is found
        '''
        md5_len = md5_len or length
        voldev = euvolume.guestdev.strip()
        if not isinstance(euvolume, EuVolume):
            raise Exception('EuVolume() type not passed to vol_write_random_data_get_md5, '
                            'got type:' + str(type(euvolume)))
        if not voldev:
            raise Exception('Guest device not populated for euvolume:' + str(euvolume.id) +
                            ', euvolume.guestdev:' + str(euvolume.guestdev) +
                            ', voldev:' + str(voldev))
        # Check to see if there's existing data that we should avoid overwriting
        # When length is None fallback to checking for existing data in just the first 10MB
        check_length = length
        if length is None:
            check_length = 10000000
        if overwrite or (int(self.sys('head -c ' + str(check_length) + ' ' + str(voldev) +
                                      ' | xargs -0 printf %s | wc -c')[0]) == 0):

            wrote = self.random_fill_volume(euvolume, srcdev=srcdev, length=length,
                                            timepergig=timepergig)
            # length = dd_dict['dd_bytes']
        else:
            self.log.debug("Volume has existing data, skipping random data fill")
        # Calculate checksum of euvolume attached device for given length
        md5 = self.md5_attached_euvolume(euvolume, timepergig=timepergig, length=md5_len)
        self.log.debug("Filled Volume:" + euvolume.id + " dev:" + voldev + " md5:" + md5)
        euvolume.md5 = md5
        euvolume.md5len = length
        return md5

    def md5_attached_euvolume(self, euvolume, timepergig=120, length=None, updatevol=True):
        '''
        Calculates an md5sum of the first 'length' bytes of the dev representing the attached
        euvolume.
        By default will use the md5len stored within the euvolume. The euvolume will be updated
        with the resulting checksum and length.
        Returns the md5 checksum
        euvolume - mandatory - euvolume object used to calc checksum against
        timepergig - optional - number of seconds used per gig in volume size used in
                     calcuating timeout
        length - optional - number bytes to read from the head of the device file used in md5 calc
        updatevol - optional - boolean used to update the euvolume data or not
        '''
        if length is None:
            length = euvolume.md5len
        try:
            voldev = euvolume.guestdev
            timeout = euvolume.size * timepergig
            md5 = self.get_dev_md5(voldev, length, timeout)
            self.log.debug("Got MD5 for Volume:" + euvolume.id + " dev:" + voldev + " md5:" + md5)
            if updatevol:
                euvolume.md5 = md5
                euvolume.md5len = length
        except Exception, e:
            tb = get_traceback()
            print str(tb)
            raise Exception(str(self.id) + ": Failed to md5 attached volume: " + str(e))
        euvolume.md5 = md5
        euvolume.md5len = length
        euvolume.create_tags({euvolume.tag_md5_key:md5, euvolume.tag_md5len_key: length})
        return md5

    def get_dev_md5(self, devpath, length, timeout=60):
        self.assertFilePresent(devpath)
        if not length:
            md5 = str(self.sys("md5sum " + devpath,
                               timeout=timeout, code=0)[0]).split(' ')[0].strip()
        else:
            md5 = str(self.sys("head -c " + str(length) + " " + str(devpath) +
                               " | md5sum", timeout=timeout, code=0 )[0]).split(' ')[0].strip()
        return md5

    def reboot_instance_and_verify(self,
                                   waitconnect=30,
                                   timeout=360,
                                   connect=True,
                                   checkvolstatus=False,
                                   pad=5):
        '''
        Attempts to reboot an instance and verify it's state post reboot.
        waitconnect-optional-integer representing seconds to wait before attempting to
                    connect to instance after reboot
        timeout-optional-integer, seconds. If a connection has failed, this timer is used to
                determine a retry
        onnect- optional - boolean to indicate whether an ssh session should be established once
                the expected state has been reached
        checkvolstatus - optional -boolean to be used to check volume status post start up
        '''
        msg = ""
        newuptime = None
        attempt = 0

        def get_safe_uptime():
            uptime = None
            try:
                uptime = self.get_uptime()
            except:
                pass
            return uptime

        self.log.debug('Attempting to reboot instance:' + str(self.id) +
                   ', check attached volume state first')
        uptime = wait_for_result(get_safe_uptime, None, oper=operator.ne)
        elapsed = 0
        start = time.time()
        if checkvolstatus:
            # update the md5sums per volume before reboot
            bad_vols = self.get_unsynced_volumes()
            if bad_vols != []:
                for bv in bad_vols:
                    self.log.debug(str(self.id) + 'Unsynced volume found:' + str(bv.id))
                raise Exception(str(self.id) + "Could not reboot using checkvolstatus flag due to "
                                               "unsync'd volumes")
        self.log.debug('Rebooting now...')
        self.reboot()
        time.sleep(waitconnect)
        timeout = timeout - int(time.time() - start)
        while elapsed < timeout:
            newuptime = None
            retry_start = time.time()
            try:
                self.connect_to_instance(timeout=timeout)
                # Wait for the system to provide a valid response for uptime,
                # early connections may not
                newuptime = wait_for_result(get_safe_uptime, None, oper=operator.ne)
            except:
                pass

            elapsed = int(time.time() - start)
            # Check to see if new uptime is at least 'pad' less than before reboot
            if (newuptime is None) or (newuptime > uptime):
                err_msg = "Instance uptime does not represent a reboot. Orig:" + str(uptime) + \
                          ", New:" + str(newuptime) + ", elapsed:" + str(elapsed) + \
                          ", elapsed:" + str(elapsed) + "/" + str(timeout)
                if elapsed > timeout:
                    raise Exception(err_msg)
                else:
                    self.log.debug(err_msg)
                    pause_time = 10 - (time.time() - retry_start)
                    if pause_time > 0:
                        time.sleep(int(pause_time))
            else:
                self.log.debug("Instance uptime indicates a reboot. Orig:" + str(uptime) +
                           ", New:" + str(newuptime) + ", elapsed:" + str(elapsed))
                break
        if checkvolstatus:
            badvols = self.get_unsynced_volumes()
            if badvols != []:
                for vol in badvols:
                    msg = msg + "\nVolume:" + vol.id + " Local Dev:" + vol.guestdev
                raise Exception("Missing volumes post reboot:" + str(msg) + "\n")
        self.log.debug(self.id + " reboot_instance_and_verify Success")

    def get_uptime(self, retries=10, interval=10):
        start = time.time()
        for x in xrange(0, retries):
            try:
                uptime = int(self.sys('cat /proc/uptime', code=0)[0].split()[0].split('.')[0])
                return uptime
                break
            except Exception, E:
                self.log.debug('Error getting uptime attempt:{0}/{1}, err:{2}'
                           .format(x, retries, E))
                self.log.debug('Waiting {0} seconds before checking uptime...'
                           .format(interval))
                time.sleep(interval)
        raise RuntimeError('{0}: Could not get uptime from instance after '
                           'elapsed:{1}'
                           .format(self.id, int(time.time() - start)))

    def attach_euvolume_list(self, list, intervoldelay=0, timepervol=120, md5len=32):
        '''
        Attempts to attach a list of euvolumes. Due to limitations with KVM and detecting
        the location/device name of the volume as attached on the guest, MD5 sums are used...
        -If volumes contain an md5 will wait intervoldelay seconds
        before attempting to attach the next volume in the list.
        -If the next volume in the list does not have an MD5, the next volume will not be
         attached until this volume is detected and an md5sum is populated in the euvolume.

        :param list: List of volumes to be attached, if volumes are not of type
                     euvolume they will be converted
        :param intervoldelay : integer representing seconds between each volume attach attempt
        :param timepervol: time to wait for volume to attach before failing
        :param md5len: length from head of block device to read when calculating md5

        '''
        for euvol in list:
            if not isinstance(euvol, EuVolume):  # or not euvol.md5:
                list[list.index(euvol)] = EuVolume.make_euvol_from_vol(euvol, self.ec2ops)
        for euvol in list:
            dev = self.get_free_scsi_dev()
            if euvol.md5:
                # Monitor volume to attached, dont write/read head for md5 use existing.
                # Check md5 sum later in get_unsynced_volumes.
                if (self.ec2ops.attach_volume(self, euvol, dev, pause=10, timeout=timepervol)):
                    self.attached_vols.append(euvol)
                else:
                    raise Exception('attach_euvolume_list: {0} Test Failed to attach volume:{1}'
                                    .format(self.id, euvol.id))
            else:
                # monitor volume to attached and write unique string to head and record it's md5sum
                self.attach_euvolume(euvol, dev, timeout=timepervol)
            if intervoldelay:
                time.sleep(intervoldelay)
        start = time.time()
        elapsed = 0
        badvols = self.get_unsynced_volumes(list, md5length=md5len, timepervol=timepervol,
                                            check_md5=True)
        if badvols:
            buf = ""
            for bv in badvols:
                buf += str(bv.id) + ","
            raise Exception("Volume(s) were not found on guest:" + str(buf))

    def get_unsynced_volumes(self, euvol_list=None, md5length=32, timepervol=90, min_polls=2,
                             check_md5=False):
        '''
        Description: Returns list of volumes which are:
        -in a state the cloud believes the vol is no longer attached
        -the attached device has changed, or is not found.
        If all euvols are shown as attached to this instance, and the last known local dev is
        present and/or a local device is found with matching md5 checksum
        then the list will return 'None' as all volumes are successfully attached and
        state is in sync.
        By default this method will iterate through all the known euvolumes attached to
        this euinstance.
        A subset can be provided in the list argument 'euvol_list'.
        Returns a list of euvolumes for which a corresponding guest device could not be found,
        or the cloud no longer believes is attached.

        :param euvol_list: - optional - euvolume object list. Defaults to all self.attached_vols
        :param md5length: - optional - defaults to the length given in each euvolume. Used to
                            calc md5 checksum of devices
        :param timerpervolume: -optional - time to wait for device to appear, per volume before
                                failing
        :param min_polls: - optional - minimum iterations to check guest devs before failing,
                            despite timeout
        :param check_md5: - optional - find devices by md5 comparision. Default is to only perform
                            this check when virtio_blk is in use.
        '''
        bad_list = []
        vol_list = []
        checked_vdevs = []
        poll_count = 0
        dev_list = self.get_dev_dir()
        found = False

        if euvol_list is not None:
            vol_list.extend(euvol_list)
        else:
            vol_list = self.attached_vols
        self.log.debug("Checking for volumes whos state is not in sync with our instance's "
                   "test state...")
        for vol in vol_list:
            # First see if the cloud believes this volume is still attached.
            try:
                self.log.debug("Checking volume:" + str(vol.id))
                if (vol.attach_data.instance_id == self.id):  # Verify the cloud status is
                    # Still attached to this instance
                    self.log.debug("Cloud beleives volume:" + str(vol.id) + " is attached to:" +
                               str(self.id) + ", check for guest dev...")
                    found = False
                    elapsed = 0
                    start = time.time()
                    checked_vdevs = []
                    # loop here for timepervol in case were waiting for a volume to appear in
                    # the guest. ie attaching
                    while (not found) and ((elapsed <= timepervol) or (poll_count < min_polls)):
                        try:
                            poll_count += 1
                            # Ugly... :-(
                            # handle virtio and non virtio cases differently (KVM case needs
                            # improvement here).
                            if self.virtio_blk or check_md5:
                                self.log.debug('Checking any new devs for md5:' + str(vol.md5))
                                # Do some detective work to see what device name the previously
                                # attached volume is using
                                devlist = self.get_dev_dir()
                                for vdev in devlist:
                                    vdev = "/dev/" + str(vdev)

                                    # If we've already checked the md5 on this dev no need
                                    # to re-check it.
                                    if vdev not in checked_vdevs:
                                        self.log.debug('Checking ' + str(vdev) +
                                                   " for match against euvolume:" + str(vol.id))
                                        md5 = self.get_dev_md5(vdev, vol.md5len)
                                        self.log.debug('comparing ' + str(md5) + ' vs ' + str(vol.md5))
                                        if md5 == vol.md5:
                                            self.log.debug('Found match at dev:' + str(vdev))
                                            found = True
                                            if (vol.guestdev != vdev):
                                                self.log.debug(
                                                    "(" + str(vol.id) + ")Found dev match. "
                                                    "Guest dev changed! Updating from "
                                                    "previous:'" + str(vol.guestdev) +
                                                    "' to:'" + str(vdev) + "'")
                                            else:
                                                self.log.debug("(" + str(vol.id) +
                                                           ")Found dev match. Previous "
                                                           "dev:'" + str(vol.guestdev) +
                                                           "', Current dev:'" + str(vdev) + "'")
                                            vol.guestdev = vdev
                                        # add to list of devices we've already checked.
                                        checked_vdevs.append(vdev)
                                    if found:
                                        break
                            else:
                                # Not using virtio_blk assume the device will be the same
                                self.assertFilePresent(vol.guestdev.strip())
                                self.log.debug("(" + str(vol.id) +
                                           ")Found local/volume match dev:" +
                                           vol.guestdev.strip())
                                found = True
                        except:
                            pass
                        if found:
                            break
                        self.log.debug('Local device for volume:' + str(vol.id) +
                                   ' not found. Sleeping and checking again...')
                        time.sleep(10)
                        elapsed = int(time.time() - start)
                    if not found:
                        bad_list.append(vol)
                        self.log.debug("(" + str(vol.id) + ")volume.guestdev:" + str(vol.guestdev) +
                                   ", dev not found on guest? Elapsed:" + str(elapsed))
                else:
                    self.log.debug("(" + str(vol.id) + ")Error, Volume.attach_data.instance_id:(" +
                               str(vol.attach_data.instance_id) + ") != (" + str(self.id) + ")")
                    bad_list.append(vol)
            except Exception, e:
                self.log.debug("Volume:" + str(vol.id) + " is no longer attached to this "
                           "instance:" + str(self.id) + ", error:" + str(e))
                bad_list.append(vol)
                pass
        return bad_list

    def find_blockdev_by_md5(self, md5=None, md5len=None, euvolume=None,
                             add_to_attached_list=False):
        guestdev = None

        md5 = md5 or euvolume.md5
        md5len = md5len or euvolume.md5len
        if euvolume:
            pt = self.ec2ops.show_volumes([euvolume], printme=False)
            self.log.debug("Attempting to find block dev by md5. vol:{1}, md5:{1}. md5:{2}\n{3}\n"
                           .format(euvolume.id, md5, md5len, pt))

        vdevs = self.get_dev_dir()
        # if the euvolume has a guest dev, try that first
        if getattr(euvolume, 'guestdev', None):
            for vdev in vdevs:
                if str(euvolume.guestdev).endswith(vdev):
                    vdevs.remove(vdev)
                    vdevs.insert(0, vdev)
        for vdev in vdevs:
            vdev = '/dev/' + str(vdev).replace('/dev/', '')
            self.log.debug('Checking ' + str(vdev) + " for a matching block device")
            block_md5 = self.get_dev_md5(vdev, md5len)
            self.log.debug('comparing dev' + str(vdev) + ': ' + str(block_md5) + ' vs vol:' + str(md5))
            if block_md5 == md5:
                self.log.debug('Found match at dev:' + str(vdev))
                if (euvolume):
                    if (euvolume.guestdev != vdev):
                        self.log.debug("(" + str(euvolume.id) +
                                   ")Found dev match. Guest dev changed! "
                                   "Updating from previous:'" + str(euvolume.guestdev) +
                                   "' to:'" + str(vdev) + "'")
                    else:
                        self.log.debug("(" + str(euvolume.id) + ")Found dev match. Previous dev:'" +
                                   str(euvolume.guestdev) + "', Current dev:'" + str(vdev) + "'")
                    euvolume.guestdev = vdev
                guestdev = vdev
                break
        if add_to_attached_list:
            if euvolume not in self.attached_vols:
                euvolume.md5 = md5
                euvolume.md5len = md5len
                self.attached_vols.append(euvolume)
        return guestdev

    def verify_attached_vol_cloud_status(self, euvolume):
        '''
        Confirm that the cloud is showing the state for this euvolume as attached to this instance
        '''
        try:
            euvolume = self.ec2ops.get_volume(volume_id=euvolume.id)
        except Exception, e:
            self.log.debug("Error in verify_attached_vol_status, try running init_volume_list first")
            raise Exception("Failed to get volume in get_attached_vol_cloud_status, err:" + str(e))
        if euvolume.attach_data.instance_id != self.id:
            self.log.debug("Error in verify_attached_vol_status, try running init_volume_list first")
            raise Exception("(" + str(self.id) + ")Cloud status for vol(" + str(euvolume.id) +
                            " = not attached to this instance ")

    def init_volume_list(self, reattach=False, detach=True, timeout=300):
        '''
        This should be used when first creating a euinstance from an instance to insure the
        euinstance volume state is in sync with the cloud, mainly
        for the case where a euinstance is made from a pre-existing and in-use instance.
        Method to detect volumes which the cloud believes this guest is using, and attempt to
        match up the cloud dev with the local guest dev.
        In the case the local dev can not be found the volume will be detached. If the local
        device is found a euvolume object is created and appended
        the local attached_vols list. To confirm local state with the cloud state, the
        options 'reattach', or 'detach' can be used.

        '''
        self.attached_vols = []
        cloudlist = []

        # Make sure the volumes we think our attached are in a known good state
        badvols = self.get_unsynced_volumes()

        for badvol in badvols:
            try:
                self.detach_euvolume(badvol, timeout=timeout)
            except Exception, e:
                raise Exception("Error in sync_volume_list attempting to detach badvol:" +
                                str(badvol.id) + ". Err:" + str(e))

        cloudlist = self.ec2ops.ec2.get_all_volumes()
        found = False
        for vol in cloudlist:
            # check to see if the volume is attached to us, but is not involved with the
            #  bdm for this instance
            found = False
            if (vol.attach_data.instance_id == self.id) and not \
                    (self.root_device_type == 'ebs' and self.bdm_root_vol.id != vol.id):
                for avol in self.attached_vols:
                    if avol.id == vol.id:
                        self.log.debug("Volume" + vol.id + " found attached")
                        found = True
                        break
                if not found:
                    dev = vol.attach_data.device
                    try:
                        self.assertFilePresent(dev)
                        if not detach:
                            evol = EuVolume.make_euvol_from_vol(vol)
                            evol.guestdev = dev
                            self.attached_vols.append(evol)
                        else:
                            self.ec2ops.detach_volume(vol, timeout=timeout)
                    except Exception, e:
                        if reattach or detach:
                            self.ec2ops.detach_volume(vol, timeout=timeout)
                        if reattach:
                            dev = self.get_free_scsi_dev()
                            self.attach_volume(self, self, vol, dev)

    def stop_instance_and_verify(self, timeout=200, state='stopped', failstate='terminated',
                                 check_vols=True, check_enis=True):
        '''
        Attempts to stop instance and verify the state has gone to stopped state
        timeout -optional-time to wait on instance to go to state 'state' before failing
        state -optional-the expected state to signify success, default is stopped
        failstate -optional-a state transition that indicates failure, default is terminated
        '''
        self.log.debug(self.id + " Attempting to stop instance...")
        start = time.time()
        elapsed = 0
        self.stop()
        while (elapsed < timeout):
            time.sleep(2)
            self.update()
            if self.state == state:
                break
            if self.state == failstate:
                raise Exception(str(self.id) + " instance went to state:" + str(self.state) +
                                " while stopping")
            elapsed = int(time.time() - start)
            if elapsed % 10 == 0:
                self.log.debug(str(self.id) + " wait for stop, in state:" + str(self.state) +
                           ",time remaining:" + str(elapsed) + "/" + str(timeout))
        if self.state != state:
            raise Exception(self.id + " state: " + str(self.state) + " expected:" + str(state) +
                            ", after elapsed:" + str(elapsed))
        if check_vols:
            for volume in self.attached_vols:
                volume.update
                if volume.status != 'in-use':
                    raise Exception(str(self.id) + ', Volume ' + str(volume.id) + ':' +
                                    str(volume.status) +
                                    ' state did not remain in-use during stop')
        if check_enis:
            self.check_eni_attachments(local_dev_timeout=timeout)
        self.log.debug(self.id + " stop_instance_and_verify Success")

    def start_instance_and_verify(self, timeout=300, state='running', failstates=['terminated'],
                                  failfasttime=30, connect=True, checkvolstatus=True,
                                  check_enis=True):
        '''
        Attempts to start instance and verify state, and reconnects ssh session
        timeout -optional-time to wait on instance to go to state 'state' before failing
        state -optional-the expected state to signify success, default is running
        failstate -optional-a state transition that indicates failure, default is terminated
        connect- optional - boolean to indicate whether an ssh session should be established
                 once the expected state has been reached
        checkvolstatus - optional -boolean to be used to check volume status post start up
        '''
        self.log.debug(self.id + " Attempting to start instance...")
        if checkvolstatus:
            for volume in self.attached_vols:
                volume.update
                if checkvolstatus:
                    if volume.status != 'in-use':
                        raise Exception(str(self.id) + ', Volume ' + str(volume.id) + ':' +
                                        str(volume.status) +
                                        ' state did not remain in-use during stop')
        self.log.debug("\n" + str(self.id) + ": Printing Instance 'attached_vol' list:\n")
        self.ec2ops.show_volumes(self.attached_vols)
        msg = ""
        start = time.time()
        elapsed = 0
        self.update()
        # Add fail fast states...
        if self.state == 'stopped':
            failstates.extend(['stopped', 'stopping'])
        self.start()

        while (elapsed < timeout):
            elapsed = int(time.time() - start)
            self.update()
            self.log.debug(str(self.id) + " wait for start, in state:" + str(self.state) +
                       ",time remaining:" + str(elapsed) + "/" + str(timeout))
            if self.state == state:
                break
            if elapsed >= failfasttime:
                for failstate in failstates:
                    if self.state == failstate:
                        raise Exception(str(self.id) + " instance went to state:" +
                                        str(self.state) + " while starting")
            time.sleep(10)
        if self.state != state:
            raise Exception(
                self.id + " not in " + str(state) + " state after elapsed:" + str(elapsed))
        else:
            self.log.debug(self.id + " went to state:" + str(state))
            if connect:
                self.connect_to_instance(timeout=timeout)
            if checkvolstatus:
                badvols = self.get_unsynced_volumes(check_md5=True)
                if badvols != []:
                    for vol in badvols:
                        msg = msg + "\nVolume:" + vol.id + " Local Dev:" + vol.guestdev
                    raise Exception("Missing volumes post reboot:" + str(msg) + "\n")
            if check_enis:
                self.check_eni_attachments(local_dev_timeout=timeout)
        self.log.debug(self.id + " start_instance_and_verify Success")

    def mount_attached_volume(self,
                              volume,
                              mkfs_cmd="mkfs.ext3",
                              force_mkfs=False,
                              mountdir="/mnt",
                              name=None):
        """
        Attempts to mount a block device associated with an attached volume.
        Attempts to mkfs, and mkdir for mount if needed.

        :param volume: euvolume obj
        :param mkfs_cmd: string representing mkfs cmd, defaults to 'mkfs.ext3'
        :param mountdir: dir to mount, defaults to '/mnt'
        :param name: name of dir create within mountdir to mount volume, defaults to volume's id
        :return: string representing path to volume's mounted dir
        """
        dev = volume.guestdev
        name = name or volume.id
        mountdir = mountdir.rstrip("/") + "/"
        if not dev:
            raise Exception(str(volume.id) + ': Volume guest device was not set, is this '
                                             'volume attached?')
        mounted_dir = self.get_volume_mounted_dir(volume)
        if mounted_dir:
            return mounted_dir
        if force_mkfs:
            self.sys(mkfs_cmd + " -F " + dev, code=0)
        else:
            try:
                self.sys('blkid -o value -s TYPE ' + str(dev) + '*', code=0)
            except:
                self.sys(mkfs_cmd + " " + dev, code=0)
        mount_point = mountdir + name
        try:
            self.assertFilePresent(mount_point)
        except:
            self.sys('mkdir -p ' + mount_point, code=0)
        self.sys('mount ' + dev + ' ' + mount_point, code=0)
        return mount_point

    def get_volume_mounted_dir(self, volume):
        """
        Attempts to fetch the dir/mount point for a given block-guestdev or a euvolume
        that contains attached guestdev information.

        :param volume: attached euvolume
        :param guestdev: local block device path
        :return: string representing path to mounted dir, or None if not found
        """
        mount_dir = None
        guestdev = volume.guestdev
        if not guestdev:
            raise Exception('No guest device found or provided for to check for mounted state')
        try:
            mount_dir = self.sys('mount | grep ' + str(guestdev), code=0)[0].split()[2]
        except Exception, e:
            self.log.debug('Mount point for ' + str(guestdev) + 'not found:' + str(e))
            return mount_dir
        return mount_dir

    def update_vm_type_info(self):
        self.vmtype_info = self.ec2ops.get_vm_type_info(self.instance_type)
        return self.vmtype_info

    def get_ephemeral_dev(self):
        """
        Attempts to find the block device path on this instance

        :return: string representing path to ephemeral block device
        """
        ephem_name = None
        dev_prefixs = ['s', 'v', 'xd', 'xvd']
        if not self.root_device_type == 'ebs':
            try:
                self.assertFilePresent('/dev/' + str(self.rootfs_device))
                return self.rootfs_device
            except:
                ephem_name = 'da'
        else:
            ephem_name = 'db'
        devs = self.get_dev_dir()
        for prefix in dev_prefixs:
            if str(prefix + ephem_name) in devs:
                return str('/dev/' + prefix + ephem_name)
        raise Exception('Could not find ephemeral device?')

    def get_blockdev_size_in_bytes(self, devpath):
        bytes = self.sys('blockdev --getsize64 ' + str(devpath), code=0)[0]
        return int(bytes)

    def check_ephemeral_against_vmtype(self):
        gb = 1073741824

        size = self.vmtype_info.disk
        ephemeral_dev = self.get_ephemeral_dev()
        block_size = self.get_blockdev_size_in_bytes(ephemeral_dev)
        gbs = block_size / gb
        self.log.debug("Ephemeral check: ephem_dev:{0}, bytes: {1}, gbs:{2}, vmtype size:{3}"
                   .format(ephemeral_dev, block_size, gbs, size))
        if int(gbs) != int(size):
            raise Exception("Ephemeral check failed. {0} Blocksize:{1} gb ({2} bytes) != vmtype "
                            "size:{3} gb".format(ephemeral_dev, gbs, block_size, size))
        else:
            self.log.debug('check_ephemeral_against_vmtype, passed')
        return ephemeral_dev

    def get_memtotal_in_mb(self):
        kb_to_mb = 1024
        return long(self.sys('cat /proc/meminfo | grep MemTotal', code=0)[0].split()[1]) / kb_to_mb

    def check_ram_against_vmtype(self, pad=32):
        total_ram = self.get_memtotal_in_mb()
        self.log.debug("Ram check: vm_ram: {0}mb vs memtotal: {1}mb. Diff:{2}mb, pad:{3}mb"
                   .format(self.vmtype_info.ram,
                           total_ram,
                           (self.vmtype_info.ram - total_ram),
                           pad))
        if not ((self.vmtype_info.ram - total_ram) <= pad):
            raise Exception('Ram check failed. vm_ram:' + str(self.vmtype_info.ram) +
                            " vs memtotal:" + str(total_ram) +
                            ". Diff is greater than allowed pad:" + str(pad) + "mb")
        else:
            self.log.debug('check_ram_against_vmtype, passed')

    def get_guest_dev_for_block_device_map_device(self, md5, md5len, map_device):
        '''
        Finds a device in the block device mapping and attempts to locate which guest device
        the volume is using based upon the provided md5 sum, and length in bytes that were
        read in to create  the checksum. If found the volume
        is appended to the local list of attached volumes and the md5 checksum and len are set
        in the volume for later test use.
        returns the guest device if found.
        '''
        self.log.debug('Attempting to find block device for mapped device name:' + str(map_device) +
                   ', md5:' + str(md5) +
                   ', md5len:' + str(md5len))
        dbg_buf = "\nInstance 'attached_vol' list:\n"
        for vol in self.attached_vols:
            dbg_buf += "Volume:" + str(vol.id) + ", md5:" + str(vol.md5) + ", md5len" + \
                       str(vol.md5len) + "\n"
        self.log.debug(dbg_buf)
        mapped_device = self.block_device_mapping.get(map_device)
        volume_id = mapped_device.volume_id
        volume = self.ec2ops.get_volume(volume_id=volume_id)
        if volume.attach_data.device != map_device:
            raise Exception('mapped device name:' + str(mapped_device) +
                            ', does not match attached device name:' +
                            str(volume.attach_data.device))
        local_dev = self.find_blockdev_by_md5(md5=md5, md5len=md5len)
        if not local_dev:
            raise Exception('dev:' + str(map_device) + ', vol:' + str(volume_id) +
                            ' - Could not find a device matching md5:' +
                            str(md5) + ", len:" + str(md5len))
        self.log.debug('Recording volume:' + str(volume.id) +
                   ' md5 info in volume, and adding to attached list')
        if not local_dev:
            raise Exception('Could not find mapped device:' + str(map_device) +
                            ', using md5:' + str(md5) + ', md5len' + str(md5len))
        volume.guestdev = local_dev
        volume.md5 = md5
        volume.md5len = md5len
        if volume not in self.attached_vols:
            self.attached_vols.append(volume)
        return local_dev

    def check_instance_meta_data_for_block_device_mapping(self, root_dev=None, bdm=None):
        '''
        Checks current instances meta data against a provided block device map & root_dev, or
        against the current values of the instance; self.block_device_mapping &
        self.root_device_name
        '''
        self.ec2ops.show_block_device_map(self.block_device_mapping)
        meta_dev_names = self.get_metadata('block-device-mapping')
        meta_devices = {}
        root_dev = root_dev or self.root_device_name
        root_dev = os.path.basename(root_dev)
        orig_bdm = bdm or self.block_device_mapping
        bdm = copy.copy(orig_bdm)

        if root_dev in bdm:
            bdm.pop(root_dev)
        if '/dev/' + root_dev in bdm:
            bdm.pop('/dev/' + root_dev)

        for device in meta_dev_names:
            # Check root device meta data against the root device, else add to dict for
            # comparison against block dev map
            if device == 'ami' or device == 'emi' or device == 'root':
                meta_device = self.get_metadata('block-device-mapping/' + str(device))
                if not meta_device:
                    raise Exception('Device: {0} metadata response:{1}'
                                    .format(device, meta_device))
                if root_dev not in meta_device and '/dev/' + str(root_dev) not in meta_device:
                    raise Exception('Meta data "block-device-mapping/' + str(device) +
                                    '", root dev:' +
                                    str(root_dev) + ' not in ' + str(meta_device))
            else:
                meta_devices[device] = self.get_metadata('block-device-mapping/' + str(device))[0]

        for device in bdm:
            found = False
            device_map = bdm[device]
            if device_map.no_device:
                continue
            else:
                if device_map.ephemeral_name:
                    dev_name_prefix = 'ephemeral'
                else:
                    dev_name_prefix = 'ebs'
                for meta_dev in meta_devices:
                    self.log.debug('looking for device:{0}, dev_name_prefix:{1}, meta dev:{2}'
                               .format(device, dev_name_prefix, meta_dev))
                    if str(meta_dev).startswith(dev_name_prefix):
                        if os.path.basename(meta_devices.get(meta_dev)) == \
                                os.path.basename(device):
                            self.log.debug('Found meta data match for block device:' + str(device) +
                                       " for meta name: " + str(meta_dev))
                            meta_devices.pop(meta_dev)
                            found = True
                            break
                if not found:
                    raise Exception('No meta data found for block dev map device:' + str(device))
        if meta_devices:
            err_buf = "({0})The following devices were found in meta data, " \
                      "but not in the instance's " \
                      "block dev mapping:".format(self.id)
            for meta_dev in meta_devices:
                err_buf += "\n'Metadata block device name: '" + str(meta_dev) + \
                           "' --> Metadata device value:'" + \
                           str(meta_devices.get(meta_dev)) + "' (Not found in Instance's BDM)"
            raise Exception(err_buf)

    def get_network_device_info(self, name=None, prefix='/sys/class/net/'):
        ret = {}
        ipv4_info = self.get_network_ipv4_info()
        # Pipe to grep here just to disable auto color ascii markups in the output...
        dev_names = self.sys('ls -1 {0} | grep .'.format(prefix), code=0)
        for dev_name in dev_names:
            attempt = 0
            good = False
            max_attempts = 3
            while attempt < max_attempts and not good:
                self.log.debug('Attempting to fetch info for device {0}'.format(dev_name))
                attempt += 1
                try:
                    dev = {}
                    dev_name = str(dev_name).strip()
                    if name and dev_name != name:
                        continue
                    dev_ipv4_info = ipv4_info.get(dev_name) or {}
                    dev['local_ip'] = dev_ipv4_info.get('ip', None)
                    dev['local_cidr'] = dev_ipv4_info.get('network_cidr', None)

                    dev_path = os.path.join(prefix, dev_name)

                    # Get MAC address...
                    mac_path = os.path.join(dev_path, 'address')
                    mac_addr = self.sys('cat {0}'.format(mac_path), code=0) or [""]
                    mac_addr = mac_addr[0]
                    search = re.search("^\w\w:\w\w:\w\w:\w\w:\w\w:\w\w$", mac_addr.strip())
                    if search:
                        dev['address'] = search.group()
                    else:
                        self.log.warning('Failed to parse MAC info for:{0}'.format(dev_name))
                        dev['address'] = None
                    dev['eni_index'] = None
                    dev['eni'] = None
                    dev['eni_private_ips'] = None
                    dev['eni_public_ip'] = None
                    if dev['address']:
                        for interface in self.interfaces:
                            if interface.mac_address == dev['address']:
                                dev['eni'] = interface.id
                                dev['eni_private_ips'] = [str(x.private_ip_address) for x in
                                                          interface.private_ip_addresses]
                                dev['eni_public_ip'] = getattr(interface, 'publicIp', None)
                                if interface.attachment:
                                    dev['eni_index'] = interface.attachment.device_index
                    # Get the operation state...
                    oper_path = os.path.join(dev_path, 'operstate')
                    try:
                        dev['operstate'] = (self.sys('cat {0}'.format(oper_path), code=0,
                                                     timeout=2) or [None])[0]
                    except (CommandTimeoutException, CommandExitCodeException) as TE:
                        self.log.debug(TE)
                        dev['operstate'] = None
                    ret[dev_name] = dev
                    good = True
                except Exception as E:
                    self.log.debug('{0}\nError while gathering device info for:{1}, Err:"{2}"'
                                     .format(get_traceback(), dev_name, E))
                    if attempt >= max_attempts:
                        raise
                    time.sleep(1.5)
        macs = [x.get('address') for x in ret.values()]
        for interface in self.interfaces:
            if interface.mac_address not in macs:
                self.log.warning(red('ENI:{0} MAC:{1} not found on instance at this time'
                                     .format(interface.id, interface.mac_address)))
        return ret

    def get_network_local_device_for_eni(self, eni):
        if isinstance(eni, basestring):
            enis = self.connection.get_all_network_interfaces([eni])
            if not enis:
                raise ValueError('Could not fetch ENI for {0}'.format(eni))
            eni = enis[0]
        net_info = self.get_network_device_info()
        for dev, info in net_info.iteritems():
            if eni.mac_address and eni.mac_address == info.get('address', None):
                info['dev_name'] = dev
                return info
        return None

    def show_network_device_info(self, dev_name=None, dev_info=None,  printme=True,
                                 printmethod=None):
        dev_info = dev_info or self.get_network_device_info(name=dev_name)
        if not dev_info:
            self.log.debug('No network devices found, name:{0}?'.format(dev_name))
            return None
        headers = ['dev_name']
        # Build the headers dynamically from the device dictionary...
        for dev, value in dev_info.iteritems():
            for header, info in value.iteritems():
                if header not in headers:
                    headers.append(header)
        # Create the table...
        pt = PrettyTable(headers)
        pt.align = 'l'
        for dev, dev_info in dev_info.iteritems():
            dev_info['dev_name']  = dev
            row = []
            for header in headers:
                if header in dev_info:
                    row.append(dev_info[header])
                else:
                    row.append('???')
            pt.add_row(row)
        if not printme:
            return pt
        else:
            printmethod = printmethod or self.log.info
            printmethod("\n{0}\n".format(pt))

    def check_eni_attachments(self, verbose=True, local_dev_timeout=60):
        """
        Checks all eni attached ENI using the list currenntly in self.interfaces.
        If local_dev_timeout is not None then the local guest is polled for a device with
        matching mac address until found or timeout is reached.

        Args:
            local_dev_timeout: The time to wait for the device to show up on the guest before
                               erroring out. If this timeout is None, this check is not performed.

        Returns: list of updated eni objs

        """
        if verbose:
            self.show_enis()
        enis = []
        for eni in self.interfaces:
            enis.append(self.check_eni_attachment(eni, local_dev_timeout=local_dev_timeout))
        return enis


    def attach_eni(self, eni, index=None, check_only=False, local_dev_timeout=60):
        """
        Attaches an ENI to this instance and peforms basic validation on the attachment.
        Checks the attachment info,  device index in the response for the ENI and instance, etc.
        Checks the local guest, polls waiting for the device to show up.
        Args:
            eni: eni id, or boto obj.
            index: Device index to provide in the attach request. If 'None' this method will
                   attempt to provide a free index value.
            check_only: Boolean, will send an attach request but instead will run the attachment
                        checks.
            local_dev_timeout: The time to wait for the device to show up on the guest before
                               erroring out. If this timeout is None, this check is not performed.

        Returns: eni
        """
        self.log.debug('Starting checks for attachment of ENI:{0}'.format(eni))
        if isinstance(eni, basestring):
            enis = self.connection.get_all_network_interfaces([str(eni)])
            if not enis:
                raise ValueError('Could not fetch ENI for provided value:{0}'.format(eni))
            eni = enis[0]
            self.log.debug('Found ENI: {0}'.format(eni.id))
        self.update()
        eni.update()
        self.ec2ops.show_network_interfaces(eni)
        pre_attach_net_devs = self.get_network_interfaces().keys()
        indexes = []
        for interface in self.interfaces:
            if interface.attachment:
                indexes.append(int(interface.attachment.device_index))
        indx = None
        for indx in xrange(0, 500):
            if indx not in indexes:
                break
            else:
                indx = None
        if indx is None:
            raise ValueError('Could not find free network device index on this instance?')
        self.log.debug('Devices on guest before ENI:{0} attach:"{1}"'.format(eni.id,
                                                                             pre_attach_net_devs))
        if check_only:
            self.log.debug('check_only: {0}, not sending attach request...')
        else:
            self.log.debug('Sending attach request now for ENI:{0}'.format(eni.id))
            eni.attach(self.id, indx)
            eni.update()
        return self.check_eni_attachment(eni, index=indx, local_dev_timeout=local_dev_timeout)


    def check_eni_attachment(self, eni, index=None, api_timeout=60, eni_status='in-use',
                             attachment_status='attached', local_dev_timeout=60):
        """
        Checks a give ENI for the proper attribute status.
        If local_dev_timeout is not None then the local guest is polled for a device with
        matching mac address until found or timeout is reached.
        Args:
            eni: an eni id or eni obj to check
            index: The expected attachment index for this eni, by default this is derived
                   from the local self.interfaces information.
            api_timeout: int. Time to wait for attributes in the response related to the
                         eni, instance, etc. to report the correct status before timing out.
            local_dev_timeout: The time to wait for the device to show up on the guest before
                               erroring out. If this timeout is None, this check is not performed.

        Returns: update eni obj

        """
        if isinstance(eni, basestring):
            enis = self.connection.get_all_network_interfaces([str(eni)])
            if not enis:
                raise ValueError('Could not fetch ENI for provided value:{0}'.format(eni))
            eni = enis[0]
            self.log.debug('Found ENI: {0}'.format(eni.id))
        self.update()
        eni.update()
        if not eni.attachment:
            raise ValueError('ENI:{0} does not have attachment data after update()'.format(eni.id))
        indx = index or eni.attachment.device_index
        start = time.time()
        elapsed = 0
        attempts = 0
        api_is_good = False
        last_error = None
        while elapsed < api_timeout and not api_is_good:
            elapsed = int(time.time() - start)
            attempts += 1
            try:
                if eni.id not in [str(x.id) for x in self.interfaces]:
                    raise ValueError('ENI:{0} not found in instance:{1} interfaces:"{2}"'
                                     .format(eni.id, self.id,
                                             ", ".join([str(x.id) for x in self.interfaces])))
                for i in self.interfaces:
                    if i.id == eni.id:
                        break
                if int(i.attachment.device_index) != indx:
                    raise ValueError('Device index:"{0}" of eni in local instances does not match '
                                     'requested:"{1}" value.'.format(i.id. indx))
                if eni.status != eni_status:
                    raise ValueError('ENI status "{0}" != "{1}"'.format(eni.status, eni_status))
                if eni.attachment.id != i.attachment.id:
                    raise ValueError('ENI attachment id: {0} != self.interfaces.attachment.id:{1}'
                                     .format(eni.attachment.id, i.attachment.id))
                if not eni.attachment:
                    raise ValueError('ENI attachment info is empty after updating ENI info post '
                                     'attachment')
                if eni.attachment.instance_id != self.id:
                    raise ValueError('ENI attachment data instance_id:"{0}" does not show proper '
                                     'instance id:{1}'.format(eni.attachment.instance_id, self.id))
                if int(eni.attachment.device_index) != indx:
                    raise ValueError('ENI attachment device index:"{0}" does match requested '
                                    'index:"{1}"'.format(eni.attachment.device_index, indx))
                if eni.attachment.status != attachment_status:
                    raise ValueError('ENI attachment.status: "{0}" != "{1}"'
                                     .format(eni.attachment.status, attachment_status))
                api_is_good = True
                break
            except ValueError as VE:
                last_error = str(VE)
                self.log.debug('{0}\nERROR:"{1}", attempts:{2}, elapsed:{3}'
                               .format(get_traceback(), VE, attempts, elapsed))
                time.sleep(2)
                eni.update()
                self.update()
        if not api_is_good:
            raise ValueError('ERRORS after elapsed:{0}:"{1}"'.format(elapsed,
                                                                     last_error or "UNKNOWN?"))
        else:
            self.log.debug('System is showing ENI:{0} attached'.format(eni.id))
        if local_dev_timeout is None or not self.ssh or self.state != 'running':
            self.log.debug('local_dev_timeout or self.ssh is None, not waiting for device to'
                           ' appear on guest')
            return (eni, None)
        self.log.debug(' Moving on to guest checks...')
        start = time.time()
        elapsed = 0
        attempts = 0
        dev_found = False
        dev = None
        while elapsed < local_dev_timeout and not dev_found:
            elapsed = int(time.time() - start)
            attempts += 1
            net_devs = self.get_network_device_info()
            for dev, info in net_devs.iteritems():
                if info.get('address') == eni.mac_address:
                    break
                else:
                    dev = None


            if not dev:
                eth_info = ", ".join(["{0}:{1}"
                                     .format(x, y.get('address')) for x, y in net_devs.iteritems()])
                self.log.debug('Found Net DEVS:"{0}"'.format(eth_info))
                self.log.debug('Still waiting for local device to appear for ENI:{0},'
                               ' attempts:{1}, elapsed:{2}/{3}'.format(eni.id, attempts, elapsed,
                                                                   local_dev_timeout))
                time.sleep(5)
            else:
                self.log.debug('Found device:{0} for ENI:{1} attachment:{2}'
                               .format(dev, eni.id, eni.attachment.id))
                return eni
        raise RuntimeError('Network device for ENI:{0} did not appear on guest after '
                           'attempts:{1}, elapsed{2}/{3}'.format(eni.id, attempts, elapsed,
                                                             local_dev_timeout))


    def detach_eni(self, eni,  api_timeout=180, ignore_missing=True, local_dev_timeout=60):
        """
        Attempts to detach the provided ENI from this instance.
        Checks to see if this eni is indeed attached and found in self.instances first.
        If 'local_dev' is provided, this method will wait for that device to disappear from the
        guest. If 'local_dev' is not  provided, the method will look for the tag containing
        {attachment.id: local_dev}, otherwise this method will check the current local
        network devices and attempts to wait for single device to disappear.
        If local_dev_timeout is None, this check is skipped.
        Args:
            eni: eni id, or boto eni object to detach
            api_timeout: int. Time to wait for attributes in the response related to the
                         eni, instance, etc. to report the correct status before timing out.
            ignore_missing: bool, if True will not raise error if eni is not reported as
                            attached to this instance.
            local_dev_timeout: Time to wait for the local guest device to disappear after detaching
                               the ENI before raising an error. If local_dev_timeout is None,
                               the checks for local devices are skipped.

        Returns: The updated detached ENI

        """
        if isinstance(eni, basestring):
            enis = self.connection.get_all_network_interfaces([eni])
            if not enis:
                raise ValueError('Could not fetch ENI for provided value:{0}'.format(eni))
            eni = enis[0]
        self.update()
        eni.update()
        attachment_id = eni.attachment.id

        if eni.id not in [str(x.id) for x in self.interfaces]:
            msg = ('ENI:{0} not found as attached in {1}.interfaces:"{2}"'
                             .format(eni.id, self.id,
                                     ", ".join([str(x.id) for x in self.interfaces])))
            if ignore_missing:
                self.log.warning(msg)
                return eni
            else:
                raise ValueError(msg)
        if not eni.attachment or eni.attachment.instance_id != self.id:
            raise ValueError('{0}.instances has the eni in the list of attached ENI, but the ENI '
                             'attachment.instance_id:{1} != {2}'
                             .format(self.id, eni.attachment.instance_id, self.id))
        if self.ssh and local_dev_timeout is not None and self.state == 'running':
            try:
                pre_detach_net_devices = self.get_network_interfaces().keys()
                self.log.debug('Devices on this instance before ENI:{0} detach:"{1}"'
                               .format(eni.id, pre_detach_net_devices))
            except:
                pass
        self.log.debug('sending {0} detach now...'.format(eni.id))
        eni.detach()
        eni.update()
        self.update()
        start = time.time()
        elapsed = 0
        attempts = 0
        api_is_good = False
        last_error = None
        while elapsed < api_timeout and not api_is_good:
            elapsed = int(time.time() - start)
            attempts += 1
            try:
                dot = None
                try:
                    if eni.attachment:
                        dot = eni.attachment.delete_on_termination
                    eni.update(validate=True)
                except EC2ResponseError as EE:
                    if EE.status == 400 and EE.reason == 'InvalidNetworkInterfaceID.NotFound':
                        if dot or dot is None:
                            api_is_good = True
                        else:
                            raise RuntimeError('ENI:{0} not found after detach, and '
                                               'delete on terminate == {1}'.format(eni.id, dot))
                if not api_is_good and eni.attachment and eni.attachment.instance_id == self.id:
                    raise ValueError('ENI:{0} attachment data still shows it is attached to this '
                                     'instance:{1}'.format(eni.id, eni.attachment.instance_id))
                if not api_is_good and eni.status != 'available' and not eni.attachment:
                    raise ValueError('ENI:{0} is no longer attached and eni.status:"{1}" != '
                                     '"available"'.format(eni.id, eni.status))
                if eni.id in [str(x.id) for x in self.interfaces]:
                    raise ValueError('ENI:{0} still present in self.interfaces'.format(eni.id))
                api_is_good = True
                break
            except ValueError as VE:
                last_error = str(VE)
                self.log.debug('{0}\nDETACH WARNING:"{1}", attempts:{2}, elapsed:{3}/{4}'
                               .format(get_traceback(), VE, attempts, elapsed, api_timeout))
                time.sleep(3)
                # Fetch the eni obj in case the update() method is not reliable
                enis = self.connection.get_all_network_interfaces([eni.id])
                if not enis:
                    raise ValueError('Could not fetch updated ENI:{0}'.format(eni.id))
                eni = enis[0]
                self.update()
                self.ec2ops.show_network_interfaces(eni)
        if not api_is_good:
            raise ValueError('ERRORS after elapsed:{0}/{1}:"{2}"'.format(elapsed, api_timeout,
                                                                         last_error or "UNKNOWN?"))
        else:
            self.log.debug('System is showing ENI:{0} detached. Moving on to guest checks...'
                           .format(eni.id))
        if local_dev_timeout is None or not self.ssh or self.state != 'running':
            self.log.debug('local_dev_timeout or self.ssh is None. Skipping local device '
                           'checks on ENI:{0} detach'.format(eni.id))
            return eni
        start = time.time()
        elapsed = 0
        attempts = 0
        dev_found = True

        while elapsed < local_dev_timeout and dev_found:
            elapsed = int(time.time() - start)
            attempts += 1
            dev = None
            info = None
            net_devs = self.get_network_device_info()
            for dev, info in net_devs.iteritems():
                if info.get('address') == eni.mac_address:
                    break
                else:
                    dev = None
            if not dev:
                eth_info = ", ".join(["{0}:{1}"
                                     .format(x, y.get('address')) for x, y in net_devs.iteritems()])
                self.log.debug('Found Net DEVS:"{0}"'.format(eth_info))
                self.log.debug('Device is no longer found on guest for detached ENI:{0},'
                               ' attempts:{1}, elapsed:{2}'.format(eni.id, attempts, elapsed))
                return eni
            else:
                self.log.debug('Still waiting. Found device:{0} for detached ENI:{1} '
                               'attachment:{2}'.format(dev, eni.id, eni.attachment.id))
                time.sleep(5)
        raise RuntimeError('Network device for ENI:{0} still on guest after detach. '
                           'attempts:{1}, elapsed{2}'.format(eni.id, attempts, elapsed))


    def detach_all_enis(self, exclude_indexes=None, local_dev_timeout=60):
        """
        Attempts to detach all enis which are not included in the exlude_indexes list.
        If exclude_indexes is None, the primary or ENI at index 0 will be excluded.
        Args:
            exclude_indexes: list of eni device indexes to exclude
            local_dev_timeout: time to wait for local device to be removed. If this value is None
                               the checks for the local/guest device will be skipped.

        """
        if exclude_indexes is None:
            exclude_indexes = [0]
        elif not isinstance(exclude_indexes, list):
            exclude_indexes = [exclude_indexes]
        self.update()
        for eni in self.interfaces:
            if int(eni.attachment.device_index) not in exclude_indexes:
                self.detach_eni(eni=eni, local_dev_timeout=local_dev_timeout)
            else:
                self.log.debug('Skipping eni:{0} as device index:{1} is in the exclude list:{2}'
                               .format(eni.id, eni.attachment.device_index, exclude_indexes))
        self.log.debug('Done detaching all non-primary index ENIs from this instance')

    def sync_enis_etc_sysconfig(self, prefix='eth'):
        """
        Helper method to sync the guests networking services with 1 or more cloud ENIs.
        This method should setup local device for each ENI including; ip addresses, rules and
        routes in a RHEL/CENTOS based system using sysconfig.
        (For DEBIAN/UBUNTU systems see 'sync_enis_etc_default')
        Args:
            prefix: string, default network dev name ie: eth, em, etc..
        """
        enis = self.ec2ops.connection.get_all_network_interfaces(
            filters={'attachment.instance-id': self.id})
        # Make sure we can fetch the subnet for each eni first...
        subnets = {}
        for eni in enis:
            subnet = self.ec2ops.get_subnet(eni.subnet_id)
            subnets[subnet.id] = subnet
        # set dev to index mapping
        index_mapping = []
        for eni in enis:
            if not index_mapping:
                index_mapping.append(eni)
            else:
                placed = False
                for imap in index_mapping:
                    if eni.attachment.device_index < imap.attachment.device_index:
                        index_mapping.insert(index_mapping.index(imap) + 1, eni)
                        placed = True
                        break
                if not placed:
                    index_mapping.append(eni)
        for eni in index_mapping:
            eni.local_dev_index = index_mapping.index(eni)
        # Get network devices on the guest
        devs = self.get_network_interfaces().keys() or []
        if "{0}0".format(prefix) not in devs:
            raise ValueError('Dev {0} not found in host devs:"{1}"'.format("{0}0".format(prefix),
                                                                           ",".join(devs)))
        # First force the default gateway to be device at index 0...
        network_file_path = ' /etc/sysconfig/network'
        new_buf = "GATEWAYDEV={0}0\n".format(prefix)
        # If the file exists replace or add the GATEWAYDEV value in it...
        if self.is_present(network_file_path):
            lines = self.sys('cat {0}'.format(network_file_path), code=0)
            for line in lines:
                if not re.search('GATEWAYDEV', line):
                    new_buf += str(line) + "\n"
        self.log.debug('Attempting to update gw info in: {0}:\n{1}'
                       .format(network_file_path, new_buf))
        backup_network_file_path = "{0}_backup".format(network_file_path).strip()
        temp_network_file_path = "{0}_temp".format(network_file_path).strip()
        f = None
        # Create a backup of the existing file...
        if self.is_present(backup_network_file_path):
            self.sys('rm -f {0}'.format(backup_network_file_path))
        self.sys('cp {0} {1}'.format(network_file_path, backup_network_file_path))
        # Write the new contents from new_buf into a temporary file to be swapped in to protect
        # from errors during write.
        self.ssh.open_sftp()
        try:
            f = self.open_remote_file(temp_network_file_path, 'w+')
            f.write(new_buf)
            f.flush()
        except Exception as FE:
            self.log.error('Error attempting to write to file:"{0}"'
                           .format(temp_network_file_path))
            raise
        finally:
            if f:
                f.close()
        # Finally swap in the temp file and overwrite the working copy.
        self.sys('mv {0} {1}'.format(temp_network_file_path, network_file_path), code=0)
        self.debug('Finished writing: {0}'.format(network_file_path))

        # Add interface ifcfg files for all interfaces other than the non-primary ENI...
        eni_ifcfg_files = ['/etc/sysconfig/network-scripts/ifcfg-{0}0'.format(prefix)]
        for eni in enis:
            if eni.attachment.device_index != 0:
                dev_name = '{0}{1}'.format(prefix, eni.local_dev_index)
                if dev_name not in devs:
                    raise ValueError(
                        'Dev {0} not found in host devs:"{1}"'.format(dev_name, ",".join(devs)))
                net_script= ('DEVICE="{0}"\nBOOTPROTO="dhcp"\nONBOOT="yes"\n'
                             'TYPE="Ethernet"\nUSERCTL="yes"\nPEERDNS="yes"\nIPV6INIT="no"\n'
                             'PERSISTENT_DHCLIENT="1"'.format(dev_name))
                if_file = '/etc/sysconfig/network-scripts/ifcfg-{0}'.format(dev_name).strip()
                f = None
                self.log.debug('Attempting to write network-script for: {0}'.format(if_file))
                try:
                    f = self.open_remote_file(if_file, 'w')
                    f.write(net_script)
                    f.flush()
                    eni_ifcfg_files.append(if_file)
                finally:
                    if f:
                        f.close()
        # Add interface route files for all interfaces other than the non-primary ENI...
        eni_route_files = ['/etc/sysconfig/network-scripts/route-{0}0'.format(prefix)]
        for eni in enis:
            if eni.attachment.device_index != 0:
                dev_name = '{0}{1}'.format(prefix, eni.local_dev_index)
                if dev_name not in devs:
                    raise ValueError(
                        'Dev {0} not found in host devs:"{1}"'.format(dev_name, ",".join(devs)))
                subnet = subnets.get(eni.subnet_id)
                self.log.debug('Getting route info for subnet:')
                self.ec2ops.show_subnet(subnet)
                net_info = get_network_info_for_cidr(subnet.cidr_block)
                buf = "Network Info for subnet: {0}\n".format(subnet.id)
                for key, value in net_info.iteritems():
                    buf += "{0}:\t{1}\n".format(key, value)
                self.log.debug(buf)
                # todo find out what to use for the gateway here...
                # Assume the gateway is the first available address...
                gw = net_info.get('network').split('.')
                last_octet = gw.pop()
                last_octet = int(last_octet) + 1
                gw.append(last_octet)
                gw = ".".join(str(x) for x in gw)

                route_script = ("default via {0} dev {1} table 123{2}\n"
                                "{3} dev {1} src {3} table {2}\n"
                                .format(gw, dev_name, eni.local_dev_index, subnet.cidr_block,
                                        eni.private_ip_address))
                self.log.debug('Route info for eni: {0}, dev:{1}\n{2}'.format(eni.id, dev_name,
                                                                              route_script))
                route_file = '/etc/sysconfig/network-scripts/route-{0}'.format(dev_name).strip()
                f = None
                self.log.debug('Attempting to write network-script for: {0}'.format(route_file))
                try:
                    f = self.open_remote_file(route_file, 'w+')
                    f.write(route_script)
                    f.flush()
                    eni_route_files.append(route_file)
                finally:
                    if f:
                        f.close()
        # Add interface rule files for all interfaces other than the non-primary ENI....
        eni_rule_files = ['/etc/sysconfig/network-scripts/rule-{0}0'.format(prefix)]
        for eni in enis:
            if eni.attachment.device_index != 0:
                attachment = eni.attachment
                dev_name = '{0}{1}'.format(prefix, eni.local_dev_index)
                if dev_name not in devs:
                    raise ValueError(
                        'Dev {0} not found in host devs:"{1}"'.format(dev_name, ",".join(devs)))
                rule_script = "from {0}/32 table {1}\n".format(eni.private_ip_address,
                                                               eni.local_dev_index)
                rule_file = '/etc/sysconfig/network-scripts/route-{0}'.format(dev_name).strip()
                f = None
                self.log.debug('Attempting to write network-script for: {0}'.format(rule_file))
                try:
                    f = self.open_remote_file(rule_file, 'w+')
                    f.write(rule_script)
                    f.flush()
                    eni_route_files.append(rule_file)
                finally:
                    if f:
                        f.close()
        # Helper method to remove any non-primary interface scripts no longer in use by an ENI
        def remove_old_scripts(existing_list, current_eni_list):
            for existing_script in existing_list:
                existing_script = existing_script.strip()
                found = False
                for eni_file_name in current_eni_list:
                    if re.search('^{0}$'.format(existing_script), eni_file_name) or \
                            re.search('{0}\.\d+$'.format(eni_file_name), existing_script):
                        found = True
                        break
                if not found:
                    if self.is_file(existing_script):
                        self.log.debug('No corresponding ENI found. Removing file:"{0}"'
                                       .format(existing_script))
                        self.sys('rm -f {0}'.format(existing_script))

        # Remove any old files, files for detached ENIs, etc..
        existing_ifcfg_files = self.sys('ls /etc/sysconfig/network-scripts/ | grep "^ifcfg-{0}"'
                                        .format(prefix))
        remove_old_scripts(existing_ifcfg_files, eni_ifcfg_files)
        existing_route_files = self.sys('ls /etc/sysconfig/network-scripts/ | grep "^route-{0}"'
                                        .format(prefix))
        remove_old_scripts(existing_route_files, eni_route_files)
        existing_rule_files = self.sys('ls /etc/sysconfig/network-scripts/ | grep "^rule-{0}"'
                                       .format(prefix))
        remove_old_scripts(existing_rule_files, eni_rule_files)
        # Now restart the network service to make use of the config and scripts created...
        self.log.info('Restarting network service for instance:{0}'.format(self.id))
        self.sys('service network restart')
        for x in range(20):
            try:
                test_port_status(self.ip_address, port=22)
                break
            except Exception as PE:
                self.log.debug('{0}, Test Port Status. {1}:{2}. Elapsed:{3}. Result: {4}'
                               .format(self.id, self.ip_address, 22, x, PE))
                time.sleep(1)
        # Finally refresh the ssh connection in case it was lost in the network restart...
        self.log.debug('Attempting to refresh ssh connection after syncing ENIs...')
        self.refresh_ssh()

    def sync_enis_etc_default(self, prefix='eth'):
        # For debian/ubuntu based systems
        raise NotImplementedError('This method needs to be implemented')

    def sync_enis_static_ip_config(self, exclude_indexes=None, timeout=30):
        """
        Attempts to assign ip addresses to interfaces using ifconfig.
        By default will exclude device index '0'.
        Args:
            exclude_indexes: list of device indexes (integers) to exclude. By default (None) the
            method will exclude device index 0.

        """
        errors = ""
        if exclude_indexes is None:
            exclude_indexes = [0]
        elif exclude_indexes and not isinstance(exclude_indexes, list):
            exclude_indexes = [exclude_indexes]
        self.update()
        for eni in self.interfaces:
            if int(eni.attachment.device_index) in exclude_indexes:
                self.log.debug('Skipping IP config for ENI:{0} at device_index:{1}'
                               .format(eni.id, eni.attachment.device_index))
                continue
            else:
                try:
                    for attempt in xrange(0, 3):
                        dev_info = self.get_network_local_device_for_eni(eni)
                        if not dev_info:
                            time.sleep(2)
                        else:
                            break
                    if not dev_info:
                        raise RuntimeError('Local dev not found for eni:{0}'.format(eni.id))
                    dev_name = dev_info.get('dev_name')
                    subnet = self.ec2ops.get_subnet(eni.subnet_id)
                    cidr_mask = subnet.cidr_block.split('/')[1]
                    ip_cidr = "{0}/{1}".format(eni.private_ip_address, cidr_mask)
                    self.sys('ifconfig {0} up'.format(dev_name), code=0)
                    self.sys('ifconfig {0} {1}'.format(dev_name, ip_cidr), code=0)
                except Exception as E:
                    self.show_network_device_info()
                    error = 'Error syncing IP info for ENI:{0}, ' \
                            'ERROR:"{1}"\n'.format(eni.id, E)
                    self.log.error(red("{0}\n{1}".format(get_traceback(), error)))
                    raise E
                # Now wait for device IP info to appear...
                error = None
                start = time.time()
                elapsed = 0
                attempts = 0
                while elapsed < timeout:
                    attempts += 1
                    elapsed = int(time.time() - start)
                    error = None
                    try:
                        new_ip_info = self.get_network_ipv4_info(cache_interval=0)
                        if not dev_name in new_ip_info:
                            raise ValueError('IP info not found for dev:{0} on VM:{1}'
                                             .format(dev_name, self.id))
                        guest_ip = new_ip_info[dev_name].get('ipcidr')
                        if guest_ip != ip_cidr:
                            raise ValueError('Guest IP:"{0}" != ENIs IP Private IP:{2} '
                                             'applying changes on guest. Attempts:{3}, Elapsed:{4}'
                                             .format(guest_ip, eni.id, ip_cidr, attempts, elapsed))
                        break
                    except Exception as E:
                        self.show_network_device_info()
                        error = 'Attempt:{0}, Elapsed:{1}/{2}, Error waiting for IP info to ' \
                                'sync for ENI:{3}, ERROR:"{4}"\n'.format(attempts, elapsed,
                                                                         timeout, eni.id, E)
                        self.log.warning("{0}\n{1}".format(get_traceback(), error))
                        time.sleep(5)
                if error:
                    self.log.warning(red(error))
                    errors += error
        if errors:
            raise RuntimeError('Errors detected while attempting to configure guest net devices'
                               'with cloud ENI info. Errors:{0}'.format(errors))
        self.show_network_device_info()
        self.log.debug('Done with syncing ENI ip info with static config')













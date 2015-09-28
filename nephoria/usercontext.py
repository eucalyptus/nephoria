#!/usr/bin/python
# -*- coding: utf-8 -*-
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

from logging import INFO, DEBUG
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_admin.access.autocreds import AutoCreds
from nephoria.aws.iam.iamops import IAMops
from nephoria.aws.s3.s3ops import S3ops
from nephoria.aws.ec2.ec2ops import EC2ops
from nephoria.aws.elb.elbops import ELBops
from nephoria.aws.sts.stsops import STSops
from nephoria.aws.cloudformation.cfnops import CFNops
from nephoria.aws.cloudwatch.cwops import CWops
from nephoria.aws.autoscaling.asops import ASops

class UserContext(AutoCreds):

    # This map is used for context lookups...
    CLASS_MAP = {IAMops.__name__: 'iam',
                 S3ops.__name__: 's3',
                 EC2ops.__name__: 'ec2',
                 ELBops.__name__: 'elb',
                 STSops.__name__: 'sts',
                 CWops.__name__: 'cloudwatch',
                 CFNops.__name__: 'cloudformation',
                 ASops.__name__: 'autoscaling'}

    def __init__(self,  aws_access_key=None, aws_secret_key=None, aws_account_name=None,
                 aws_user_name=None, context_mgr=None, credpath=None, string=None,
                 machine=None, keysdir=None, logger=None, service_connection=None,
                 eucarc=None, existing_certs=False, boto_debug=0, log_level=DEBUG):

        super(UserContext, self).__init__(aws_access_key=aws_access_key,
                                          aws_secret_key=aws_secret_key,
                                          aws_account_name=aws_account_name,
                                          aws_user_name=aws_user_name,
                                          credpath=credpath, string=string,
                                          machine=machine, keysdir=keysdir,
                                          logger=logger, loglevel=log_level,
                                          existing_certs=existing_certs,
                                          service_connection=service_connection,
                                          auto_create=False)
        self._connections = {}
        self._previous_context = None
        self._user_info = {}

        self.context_mgr = context_mgr
        # Logging setup
        if not logger:
            logger = Eulogger(str(self), stdout_level=log_level)
        self.log = logger
        self.log.debug = self.log.debug
        self.critical = self.log.critical
        self.info = self.log.info
        if eucarc:
            for key, value in eucarc.__dict__.iteritems():
                setattr(self, key, value)
        elif not (self.aws_access_key and aws_secret_key and self.serviceconnection):
            self.auto_find_credentials(assume_admin=False)
        if service_connection:
            self.update_attrs_from_cloud_services()
        self._test_resources = {}
        self._connection_kwargs = {'eucarc': self, 
                                   'context_mgr': self.context_mgr,
                                   'boto_debug': boto_debug,
                                   'user_context': self,
                                   'log_level': log_level}
        self.log.identifier = str(self)
        self.log.debug('Successfully created User Context')

    ##########################################################################################
    #   User/Account Properties, Attributes, Methods, etc..
    ##########################################################################################

    def __enter__(self):
        self._previous_context = self.context_mgr.current_user_context
        self.context_mgr.set_current_user_context(self)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.context_mgr.set_current_user_context(self._previous_context)

    def __repr__(self):
        account_name = ""
        user_name = ""
        account_id = ""
        try:
            account_name = self.account_name
            user_name = self.user_name
            account_id = self.account_id
            if account_name:
                account_name = ":{0}".format(account_name)
            if user_name:
                user_name = ":{0}".format(user_name)

        except:
            pass
        return "{0}:{1}{2}{3}".format(self.__class__.__name__, account_id,
                                      account_name, user_name)

    @property
    def test_resources(self):
        resource_dict = {}
        for key, value in self._connections.iteritems():
            resource_dict[key] = getattr(value, 'test_resources', {})
        return resource_dict

    @property
    def user_info(self):
        if not self._user_info:
            if self.account_name == 'eucalyptus' and self.user_name == 'admin':
                delegate_account = self.account_id
            else:
                delegate_account = None
            self._user_info = self.iam.get_user_info(delegate_account=delegate_account)
        return self._user_info

    @property
    def user_name(self):
        if not self._user_name:
            self._user_name = self.user_info.get('user_name', None)
        return self._user_name

    @property
    def user_id(self):
        return self.user_info.get('user_id', None)

    @property
    def account_name(self):
        if not self._account_name:
            account_names = self.iam.get_account_aliases(delegate_account=self.account_id)
            if account_names:
                self._account_name = account_names[0]
        return self._account_name

    @property
    def account_id(self):
        if not self._account_id:
            account = self.iam.get_account(account_name=self.account_name)
            self._account_id = account.get('account_id', None)
        return self._account_id

    ##########################################################################################
    #   CLOUD SERVICE CONNECTIONS
    ##########################################################################################

    @property
    def iam(self):
        ops_class = IAMops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def s3(self):
        ops_class = S3ops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def ec2(self):
        ops_class = EC2ops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def elb(self):
        ops_class = ELBops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def sts(self):
        ops_class = STSops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def autoscaling(self):
        ops_class = ASops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def cloudwatch(self):
        ops_class = CWops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def cloudformation(self):
        ops_class = CFNops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]


    ##########################################################################################
    #   TEST CLEAN UP METHODS
    ##########################################################################################

    def cleanup_artifacts(self,
                          instances=True,
                          snapshots=True,
                          volumes=True,
                          load_balancers=True,
                          ip_addresses=True,
                          auto_scaling_groups=True,
                          launch_configurations=True,
                          iam_accounts=True,
                          keypairs=True):
        """
        Description: Attempts to remove artifacts created during and through this nephoria's lifespan.
        """
        failmsg = ""
        failcount = 0
        self.log.debug("Starting cleanup of artifacts")
        if auto_scaling_groups and self.test_resources["auto-scaling-groups"]:
            try:
                self.autoscaling.cleanup_autoscaling_groups()
            except Exception, e:
                tb = self.get_traceback()
                failcount +=1
                failmsg += str(tb) + "\nError#:"+ str(failcount)+ ":" + str(e)+"\n"
        if instances:
            remove_list = []
            instances = []
            # To speed up termination, send terminate to all instances
            # before sending them to the monitor methods
            for res in self.test_resources["reservations"]:
                try:
                    if isinstance(res, Instance):
                        res.terminate()
                    if isinstance(res, Reservation):
                        for ins in res.instances:
                            ins.terminate()
                except:
                    traceback.print_exc()
                    self.log.debug('ignoring error in instance cleanup '
                               'during termination')
            # Now monitor to terminated state...
            for res in self.test_resources["reservations"]:
                try:
                    self.ec2.terminate_instances(res)
                    remove_list.append(res)
                except Exception, e:
                    tb = self.get_traceback()
                    failcount +=1
                    failmsg += str(tb) + "\nError#:"+ str(failcount)+ ":" + str(e)+"\n"
            for res in remove_list:
                self.test_resources["reservations"].remove(res)
        if ip_addresses:
            try:
                self.cleanup_addresses()
            except Exception, e:
                tb = self.get_traceback()
                failcount +=1
                failmsg += str(tb) + "\nError#:"+ str(failcount)+ ":" + str(e)+"\n"
        if volumes:
            try:
                self.clean_up_test_volumes(timeout_per_vol=60)
                self.test_resources['volumes']=[]
            except Exception, e:
                tb = self.get_traceback()
                failcount +=1
                failmsg += str(tb) + "\nError#:"+ str(failcount)+ ":" + str(e)+"\n"
        if snapshots:
            try:
                self.cleanup_test_snapshots()
            except Exception, e:
                tb = self.get_traceback()
                failcount +=1
                failmsg += str(tb) + "\nError#:" + str(failcount)+ ":" + str(e)+"\n"
        if load_balancers and self.test_resources["load_balancers"]:
            try:
                self.cleanup_load_balancers()
            except Exception, e:
                tb = self.get_traceback()
                failcount += 1
                failmsg += str(tb) + "\nError#:" + str(failcount) + ":" + str(e)+"\n"

        if launch_configurations and self.test_resources["launch-configurations"]:
            try:
                self.autoscaling.cleanup_launch_configs()
            except Exception, e:
                tb = self.get_traceback()
                failcount += 1
                failmsg += str(tb) + "\nError#:" + str(failcount) + ":" + str(e)+"\n"

        for key, array in self.test_resources.iteritems():
            for item in array:
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
                    tb = self.get_traceback()
                    failcount += 1
                    failmsg += str(tb) + "\nUnable to delete item: " + str(item) + "\n" + str(e)+"\n"
        if failmsg:
            failmsg += "\nFound " + str(failcount) + " number of errors while cleaning up. See above"
            raise Exception(failmsg)
        if launch_configurations and self.test_resources["launch-configurations"]:
            try:
                self.autoscaling.cleanup_launch_configs()
            except Exception, e:
                tb = self.get_traceback()
                failcount +=1
                failmsg += str(tb) + "\nError#:"+ str(failcount)+ ":" + str(e)+"\n"
        if iam_accounts and self.test_resources["iam_accounts"]:
            try:
                for account_name in self.test_resources["iam_accounts"]:
                    self.iam.delete_account(account_name=account_name, recursive=True)
            except: pass

    def cleanup_load_balancers(self, lbs=None):
        """
        :param lbs: optional list of load balancers, otherwise it will attempt to delete from test_resources[]
        """
        if lbs:
            self.elb.delete_load_balancers(lbs)
        else:
            try:
                self.elb.delete_load_balancers(self.test_resources['load_balancers'])
            except KeyError:
                self.log.debug("No loadbalancers to delete")

    def cleanup_addresses(self, ips=None):
        """
        :param ips: optional list of ip addresses, else will attempt to delete from test_resources[]

        """
        addresses = ips or self.test_resources['addresses']
        if not addresses:
            return

        self.log.debug('Attempting to release to the cloud the following IP addresses:')

        while addresses:
            self.ec2.release_address(addresses.pop())


    def cleanup_test_snapshots(self,snaps=None, clean_images=False, add_time_per_snap=10, wait_for_valid_state=120, base_timeout=180):
        """
        :param snaps: optional list of snapshots, else will attempt to delete from test_resources[]
        :param clean_images: Boolean, if set will attempt to delete registered images referencing the snapshots first.
                             Images referencing the snapshot may prevent snapshot deletion to protect the image.
        :param add_time_per_snap:  int number of seconds to append to base_timeout per snapshot
        :param wait_for_valid_state: int seconds to wait for snapshot(s) to enter a 'deletable' state
        :param base_timeout: base timeout to use before giving up, and failing operation.
        """
        snaps = snaps or self.test_resources['snapshots']
        if not snaps:
            return
        self.log.debug('Attempting to clean the following snapshots:')
        self.ec2.show_snapshots(snaps)
        if clean_images:
            for snap in snaps:
                for image in self.test_resources['images']:
                    for dev in image.block_device_mapping:
                        if image.block_device_mapping[dev].snapshot_id == snap.id:
                            self.ec2.delete_image(image)
        if snaps:
            return self.ec2.delete_snapshots(snaps,
                                        base_timeout=base_timeout,
                                        add_time_per_snap=add_time_per_snap,
                                        wait_for_valid_state=wait_for_valid_state)

    def clean_up_test_volumes(self, volumes=None, min_timeout=180, timeout_per_vol=30):
        """
        Definition: cleaup helper method intended to clean up volumes created within a test, after the test has ran.

        :param volumes: optional list of volumes to delete from system, otherwise will use test_resources['volumes']
        """
        euvolumes = []
        detaching = []
        not_exist = []
        line = '\n----------------------------------------------------------------------------------------------------\n'

        volumes = volumes or self.test_resources['volumes']
        if not volumes:
            self.log.debug('clean_up_test_volumes, no volumes passed to delete')
            return
        self.log.debug('clean_up_test_volumes starting\nVolumes to be deleted:' + ",".join(str(x) for x in volumes))

        for vol in volumes:
            try:
                vol = self.ec2.get_volume(volume_id=vol.id)
            except:
                tb = self.get_traceback()
                self.log.debug("\n" + line + " Ignoring caught Exception:\n" + str(tb) + "\n"+ str(vol.id) +
                           ', Could not retrieve volume, may no longer exist?' + line)
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
                    tb = self.get_traceback()
                    self.log.debug('Ignoring caught Exception: \n' + str(tb))
        try:
            self.log.debug('Attempting to clean up the following volumes:')
            self.ec2.show_volumes(euvolumes)
        except: pass
        self.log.debug('Clean_up_volumes: Detaching any attached volumes to be deleted...')
        for vol in euvolumes:
            try:
                vol.update()
                if vol.status == 'in-use':
                    if vol.attach_data and (vol.attach_data.status != 'detaching' or vol.attach_data.status != 'detached'):
                        try:
                            self.log.debug(str(vol.id) + ', Sending detach. Status:' +str(vol.status) +
                                       ', attach_data.status:' + str(vol.attach_data.status))
                            vol.detach()
                        except EC2ResponseError, be:
                            if 'Volume does not exist' in be.error_message:
                                not_exist.append(vol)
                                self.log.debug(str(vol.id) + ', volume no longer exists')
                            else:
                                raise be
                    detaching.append(vol)
            except:
                print self.get_traceback()
        #If the volume was found to no longer exist on the system, remove it from further monitoring...
        for vol in not_exist:
            if vol in detaching:
                detaching.remove(vol)
            if vol in euvolumes:
                euvolumes.remove(vol)
        self.test_resources['volumes'] = euvolumes
        timeout = min_timeout + (len(volumes) * timeout_per_vol)
        #If detaching wait for detaching to transition to detached...
        if detaching:
            self.ec2.monitor_euvolumes_to_status(detaching, status='available', attached_status=None,timeout=timeout)
        self.log.debug('clean_up_volumes: Deleteing volumes now...')
        self.ec2.show_volumes(euvolumes)
        if euvolumes:
            self.ec2.delete_volumes(euvolumes, timeout=timeout)

    def get_current_resources(self,verbose=False):
        """
        Return a dictionary with all known resources the system has. Optional pass the verbose=True flag to print this info to the logs
           Included resources are: addresses, images, instances, key_pairs, security_groups, snapshots, volumes, zones
        """
        current_artifacts = dict()
        current_artifacts["addresses"] = self.ec2.get_all_addresses()
        current_artifacts["images"] = self.ec2.get_all_images()
        current_artifacts["instances"] = self.ec2.get_all_instances()
        current_artifacts["key_pairs"] = self.ec2.get_all_key_pairs()
        current_artifacts["security_groups"] = self.ec2.get_all_security_groups()
        current_artifacts["snapshots"] = self.ec2.get_all_snapshots()
        current_artifacts["volumes"] = self.ec2.get_all_volumes()
        current_artifacts["zones"] = self.ec2.get_all_zones()

        if verbose:
            self.log.debug("Current resources in the system:\n" + str(current_artifacts))
        return current_artifacts


# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2016, Eucalyptus Systems, Inc.
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

import os

from botocore.exceptions import ClientError

from nephoria.baseops.boto3baseops import Boto3BaseOps


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

    def create_keypair(self, key_name, key_dir=None, save_to_local=True):
        """
        Creates a key pair and saves the key pair into a local directory.

        Args:
            key_name: name of the key pair
            key_dir: where the key is saved during the test
            save_to_local: if set to True, this method writes the key pair to a file in key_dir

        Returns:
            returns key pair if successfully created
        """
        if not key_dir:
            key_dir = os.getcwd()
        self.log.debug('Creating key {0}'.format(key_name))
        try:
            k = self.connection.create_key_pair(KeyName=key_name)
        except ClientError, e:
            raise Exception(e.message)
        key_file = '{0}/{1}.pem'.format(key_dir, k.key_name)

        if save_to_local:
            with open(key_file, 'w') as key_material:
                key_material.write(k.key_material)
            self.log.debug("Saved key pair at '{0}'".format(key_file))
        try:
            ret_key = self.connection.KeyPair(key_name)
            ret_key.load()
            self.log.debug("Successfully created keypair '{0}'".format(k.key_name, key_file))
            return ret_key
        except ClientError, e:
            raise Exception(e.message)

    def delete_keypair(self, key_name, delete_local=False, key_dir=None):
        """
        Deletes key pair and tests if the key pair's removed.

        Args:
            key_name: name of the key pair to delete
            delete_local: if set to True, if deletes the local file from key_dir
            key_dir: deletes the key pair from key_dir, if delete_local is set to True

        Returns:
            Returns True on success.
        """
        if not key_dir:
            key_dir = os.getcwd()
        k = self.connection.KeyPair(key_name)
        self.log.debug("Deleting key '{0}'".format(key_name))
        try:
            k.load()
            k.delete()
        except ClientError, e:
            raise Exception(e.message)
        try:
            k.reload()
        except:
            return True
                        

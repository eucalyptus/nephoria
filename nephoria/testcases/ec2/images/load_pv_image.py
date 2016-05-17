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

from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcases.euca2ools.euca2ools_image_utils import Euca2oolsImageUtils
from nephoria.testcontroller import TestController
from nephoria.usercontext import UserContext
from nephoria.aws.ec2.ec2ops import EC2ResourceNotFoundException
import copy
import os
import time


class Load_Pv_Image(CliTestRunner):

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['test_account'] = {
         'args': ['--test-account'],
         'kwargs': {"help": "Cloud account name to use",
                    "default": "eucalyptus"}}

    _DEFAULT_CLI_ARGS['kernel_image_url'] = {
        'args': ['--kernel-image-url'],
        'kwargs': { 'default': None,
                    'help': 'URL containing the kernel image to be downloaded to the worker '
                            'machine and used in the pv image' }}

    _DEFAULT_CLI_ARGS['kernelfilepath'] = {
        'args': ['--kernelfilepath'],
        'kwargs': { 'default': None,
                    'help': 'An existing file path on the worker machine containing the '
                            'kernel disk image to use' }}

    _DEFAULT_CLI_ARGS['ramdisk_image_url'] = {
        'args': ['--ramdisk-image-url'],
        'kwargs': { 'default': None,
                    'help': 'URL containing the initrd image to be downloaded to the worker '
                            'machine and used in the pv image' }}

    _DEFAULT_CLI_ARGS['ramdiskfilepath'] = {
        'args': ['--ramdiskfilepath'],
        'kwargs': { 'default': None,
                    'help': 'An existing file path on the worker machine containing the '
                            'ramdisk image to use' }}

    _DEFAULT_CLI_ARGS['disk_image_url'] = {
        'args': ['--disk-image-url'],
        'kwargs': { 'default': None,
                    'help': 'URL containing the image to be downloaded to the worker machine '
                            'and used for the pv disk image' }}

    _DEFAULT_CLI_ARGS['diskfilepath'] = {
        'args': ['--diskfilepath'],
        'kwargs': { 'default': None,
                    'help': 'An existing file path on the worker machine containing the '
                            'image to use' }}

    _DEFAULT_CLI_ARGS['workerip'] = {
        'args': ['--workerip'],
        'kwargs': { 'dest': 'worker_machine',
                    'default': None,
                    'help': 'The ip/hostname of the machine that the operation will be'
                            ' performed on' }}

    _DEFAULT_CLI_ARGS['worker_username'] = {
        'args': ['--worker-username'],
        'kwargs': { 'dest': 'worker_username',
                    'default': 'root',
                    'help': 'The username of the machine that the operation will be '
                            'performed on' }}

    _DEFAULT_CLI_ARGS['worker_password'] = {
        'args': ['--worker-password'],
        'kwargs': { 'dest': 'worker_password',
                    'default': None,
                    'help': 'The password of the machine that the operation will be '
                            'performed on' }}

    _DEFAULT_CLI_ARGS['worker_keypath'] = {
        'args': ['--worker-keypath'],
        'kwargs': { 'dest': 'worker_keypath',
                    'default': None,
                    'help': 'The ssh keypath of the machine that the operation will be'
                            ' performed on' }}

    _DEFAULT_CLI_ARGS['destpath'] = {
        'args': ['--destpath'],
        'kwargs': { 'default': '/disk1/storage',
                    'help': 'The path on the workip that this operation will be performed on' }}

    _DEFAULT_CLI_ARGS['urlpass'] = {
        'args': ['--urlpass'],
        'kwargs': { 'dest': 'wget_password',
                    'default': None,
                    'help': 'Password needed to retrieve remote url' }}

    _DEFAULT_CLI_ARGS['urluser'] = {
        'args': ['--urluser'],
        'kwargs': { 'dest': 'wget_user',
                    'default': None,
                    'help': 'Username needed to retrieve remote url' }}

    _DEFAULT_CLI_ARGS['interbundletime'] = {
        'args': ['--interbundletime'],
        'kwargs': { 'dest': 'inter_bundle_timeout',
                    'default': 120,
                    'help': 'Inter-bundle timeout' }}

    _DEFAULT_CLI_ARGS['bucket'] = {
        'args': ['--bucket'],
        'kwargs': { 'dest': 'bucketname',
                    'default': None,
                    'help': 'bucketname' }}

    _DEFAULT_CLI_ARGS['overwrite'] = {
        'args': ['--overwrite'],
        'kwargs': { 'action': 'store_true',
                    'default': False,
                    'help': 'Will overwrite files in matching work dir on worker '
                            'machine if found' }}

    _DEFAULT_CLI_ARGS['no_existing_images'] = {
        'args': ['--no-existing-images'],
        'kwargs': { 'action': 'store_true',
                    'default': False,
                    'help': 'If set this will not use existing images found on the '
                            'system sharing the same image name(s) for kernel(eki) and '
                            'ramdisk(eri) images when building the final image(EMI' }}

    _DEFAULT_CLI_ARGS['time_per_gig'] = {
        'args': ['--time-per-gig'],
        'kwargs': { 'default': 300,
                    'help': 'Time allowed per image size in GB before timing out.' }}

    _DEFAULT_CLI_ARGS['remove_created_images'] = {
        'args': ['--remove-created-images'],
        'kwargs': { 'action': 'store_true',
                    'default': False,
                    'help': 'Flag if set will attempt to deregisteri mages this test created' }}


    def post_init(self, *args, **kwargs):
        self._emi = None
        self.eki = None
        self.eri = None
        self.created_image = None
        self._user = None
        self._tc = None
        self._image_utils = None

        if not self.args.test_list and self.args.emi:
            if (not self.args.disk_image_url and not self.args.diskfilepath) or \
                    (self.args.disk_image_url and self.args.diskfilepath):
                raise ValueError('Must provide "either" a url (image_url) to a disk image or the '
                                 'file path to an existing image on the worker '
                                 'machine (imagefilepath)')
            if (not self.args.kernel_image_url and not self.args.kernelfilepath) or \
                    (self.args.kernel_image_url and self.args.kernelfilepath):
                raise ValueError('Must provide "either" a url (kernel_image_url) to a kernel '
                                 'image or the file path to an existing image on the worker '
                                 'machine (kernelfilepath)')
            if (not self.args.ramdisk_image_url and not self.args.ramdiskfilepath) or \
                    (self.args.ramdisk_image_url and self.args.ramdiskfilepath):
                raise ValueError('Must provide "either" a url (ramdisk_image_url) to a '
                                 'ramdisk image or the file path to an existing image on the worker '
                                 'machine (ramdiskfilepath)')


        self.args.worker_password = self.args.worker_password or self.args.password
        self.args.worker_keypath = self.args.worker_keypath
        self.args.virtualization_type = 'paravirtual'

    @property
    def emi(self):
        if not self._emi:
            if self.args.emi:
                self._emi = self.user.ec2.get_emi(self.args.emi, state=None)
        return self._emi

    @emi.setter
    def emi(self, emi):
        if isinstance(emi, basestring):
            emi = self.user.ec2.get_emi(emi, state=None)
        self._emi = emi


    @property
    def tc(self):
        tc = getattr(self, '__tc', None)
        if not tc:
            tc = TestController(self.args.clc,
                                environment_file=self.args.environment_file,
                                password=self.args.password,
                                clouduser_name=self.args.test_user,
                                clouduser_account=self.args.test_account,
                                log_level=self.args.log_level)
            setattr(self, '__tc', tc)
        return tc

    @property
    def image_utils(self):
        iu = getattr(self, '_image_utils', None)
        if iu is None:
            # Create an ImageUtils helper from the arguments provided in this testcase...
            setattr(self.args, 'worker_machine', self.tc.sysadmin.clc_machine)
            setattr(self.args, 'user_context', self.user)
            iu = self.do_with_args(Euca2oolsImageUtils)
            setattr(self, '_image_utils', iu)
        return iu

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

    def test1_do_kernel_image(self):
        """
        Description:
        Registers a kernel image with the cloud for use in creating an EMI.
        Attempts to either use an existing file path or download from a URL (whichever has been
        provided by the user) to a 'worker machine'. The worker machine will default to the CLC if
        another host is not provided.
        The image is bundled, uploaded and registered using euca2ools on the worker machine.
        """
        size = None
        image_utils = self.image_utils
        kernelfilepath = self.args.kernelfilepath
        kernel_image_url = self.args.kernel_image_url
        filename = os.path.basename(kernelfilepath or kernel_image_url)
        imagename = filename[0:20] + '_by_eutester'
        try:
            image = self.user.ec2.get_emi(emi='ki', filters={'name':imagename})
        except EC2ResourceNotFoundException:
            image = None
        if image:
            if self.args.no_existing_images:
                x = 0
                while True:
                    try:
                         x += 1
                         newname = "{0}_{1}".format(imagename, x)
                         self.user.ec2.get_emi(emi='ki', filters={'name':newname})
                    except EC2ResourceNotFoundException:
                        imagename = newname
                        break
            else:
                self.status('Found existing EKI image:"{0}" with name: "{1}"'
                            .format(image.id, image.name))
                self.eki = image
                self.user.ec2.show_image(self.eki,verbose=True)
                return self.eki
        if not kernelfilepath:
            destpath = self.args.destpath
            size, kernelfilepath = image_utils.wget_image(image_url=kernel_image_url,
                                                          destpath=destpath)
        manifest = image_utils.euca2ools_bundle_image(path=kernelfilepath,
                                                      destination=self.args.destpath)
        upmanifest = image_utils.euca2ools_upload_bundle(manifest=manifest,
                                                         bucketname=imagename + '_eutester_pv')
        eki = image_utils.euca2ools_register(manifest = upmanifest, name= imagename)
        # Make sure this image can be retrieved from the system...
        image = self.user.ec2.get_emi(eki, state=None)
        assert image.id == eki, 'Image retrieved from system did not match the test image id. ' \
                                'Fix the test?'
        # Add some tags to inform the cloud admin/users where this image came from...
        image.add_tag(key='Created by eutester load_pv_image test')
        if size is not None:
            image.add_tag(key='size', value=str(size))
        if kernel_image_url:
            image.add_tag(key='source', value=kernel_image_url)
        image.update()
        self.eki = image
        self.user.ec2.show_image(self.eki, verbose=True)
        return self.eki

    def test2_do_ramdisk_image(self):
        """
        Description:
        Registers a ramdisk image with the cloud for use in creating an EMI.
        Attempts to either use an existing file path or download from a URL (whichever has been
        provided by the user) to a 'worker machine'. The worker machine will default to the CLC if
        another host is not provided.
        The image is bundled, uploaded and registered using euca2ools on the worker machine.
        """
        size = None
        image_utils = self.image_utils
        ramdisk_image_url = self.args.ramdisk_image_url
        ramdiskfilepath = self.args.ramdiskfilepath
        filename =  os.path.basename(ramdiskfilepath or ramdisk_image_url)
        imagename =filename[0:20] + '_by_eutester'
        try:
            image = self.user.ec2.get_emi(emi='ri', filters={'name':imagename})
        except EC2ResourceNotFoundException:
            image = None
        if image:
            if self.args.no_existing_images:
                x = 0
                while True:
                    try:
                         x += 1
                         newname = "{0}_{1}".format(imagename, x)
                         self.user.ec2.get_emi(emi='ri', filters={'name':newname})
                    except EC2ResourceNotFoundException:
                        imagename = newname
                        break
            else:
                self.status('Found existing ERI image:"{0}" with name: "{1}"'
                            .format(image.id, image.name))
                self.eri = image
                self.user.ec2.show_image(self.eri,verbose=True)
                return self.eri
        if not ramdiskfilepath:
            destpath = self.args.destpath
            size, ramdiskfilepath = image_utils.wget_image(image_url=ramdisk_image_url,
                                                           destpath=destpath)
        manifest = image_utils.euca2ools_bundle_image(path=ramdiskfilepath,
                                                      destination=self.args.destpath)
        upmanifest = image_utils.euca2ools_upload_bundle(manifest=manifest,
                                                         bucketname=imagename + '_eutester_pv')
        eri = image_utils.euca2ools_register(manifest = upmanifest, name= imagename)
        # Make sure this image can be retrieved from the system...
        image = self.user.ec2.get_emi(eri, state=None)
        assert image.id == eri, 'Image retrieved from system did not match the test image id. ' \
                                'Fix the test?'
        # Add some tags to inform the cloud admin/users where this image came from...
        image.add_tag(key='Created by eutester load_pv_image test')
        if size is not None:
            image.add_tag(key='size', value=str(size))
        if ramdisk_image_url:
            image.add_tag(key='source', value=ramdisk_image_url)
        image.update()
        self.eri = image
        self.user.ec2.show_image(self.eri, verbose=True)
        return self.eri

    def test3_do_image(self):
        """
        Description:
        Registers an image with the cloud using the ERI, and EKI found or created by this test.
        Attempts to either use an existing file path or download from a URL (whichever has been
        provided by the user) to a 'worker machine'. The worker machine will default to the CLC if
        another host is not provided.
        The image is bundled, uploaded and registered using euca2ools on the worker machine.
        """
        size = None
        image_utils = self.image_utils
        diskfilepath = self.args.diskfilepath
        disk_image_url = self.args.disk_image_url
        filename = os.path.basename(diskfilepath or disk_image_url)
        imagename = filename[0:20] + '_by_eutester'
        if not diskfilepath:
            destpath = self.args.destpath
            size, diskfilepath = image_utils.wget_image(image_url=disk_image_url,
                                                        destpath=destpath)
        try:
            self.user.ec2.get_emi(emi='', filters={'name':imagename}, state=None)
        except EC2ResourceNotFoundException:
            pass
        else:
            # imagename is already taken.
            # Always create a new EMI, so make sure we increment the image name...
            x = 0
            while True:
                try:
                     x += 1
                     newname = "{0}_{1}".format(imagename, x)
                     self.user.ec2.get_emi(emi='', filters={'name':newname})
                     self.log.debug('image name:"{0}" is already in use...'.format(newname))
                except EC2ResourceNotFoundException:
                    imagename = newname
                    self.log.debug('Found an unused image name. Using name:"{0}"'.format(imagename))
                    break
        manifest = image_utils.euca2ools_bundle_image(path=diskfilepath,
                                                      destination=self.args.destpath)
        upmanifest = image_utils.euca2ools_upload_bundle(manifest=manifest,
                                                         bucketname=imagename + '_eutester_pv')
        emi = image_utils.euca2ools_register(manifest = upmanifest,
                                                  name= imagename,
                                                  kernel=self.eki.id,
                                                  ramdisk=self.eri.id,
                                                  description='"created by eutester '
                                                              'load_pv_image test"',
                                                  virtualization_type='paravirtual',
                                                  arch='x86_64'
                                                  )
        # Make sure this image can be retrieved from the system...
        image = self.user.ec2.get_emi(emi, state=None)
        assert image.id == emi, 'Image retrieved from system did not match the test image id. ' \
                                'Fix the test?'
        # Add some tags to inform the cloud admin/users where this image came from...
        image.add_tag(key='eutester-created', value='Created by eutester load_pv_image test')
        if size is not None:
            image.add_tag(key='size', value=str(size))
        if disk_image_url:
            image.add_tag(key='source', value=disk_image_url)
        image.update()
        self.emi = image
        self.user.ec2.show_image(self.emi, verbose=True)
        return self.emi

    def test4_make_image_public(self):
        """
        Description:
        Attempts to set the launch permissions to ALL, making the image public.
        """
        emi_id = self.emi or self.args.emi
        if not emi_id:
            raise SkipTestException('No emi found or provided')
        if not isinstance(emi_id, basestring):
            emi_id = emi_id.id
        emi = self.user.ec2.get_emi(emi_id, state=None)
        emi.set_launch_permissions(group_names=['all'])
        emi.update()
        self.user.ec2.show_image(emi)

    def show_images(self):
        '''
        Attempts to fetch the EMI, EKI, and ERI created by this test and display them in table
        format to the user.
        '''
        self.log.debug('\nCreate the following Image(s)...\n')
        images = []
        if self.emi:
            self.emi.update()
            images.append(self.emi)
        if self.eri:
            self.eri.update()
            images.append(self.eri)
        if self.eki:
            self.eki.update()
            images.append(self.eki)
        if not images:
            self.log.debug('No IMAGES were created?')
        else:
            self.user.ec2.show_images(images=images, verbose=True)
        if not self.emi and self.eri and self.eki:
            self.user.ec2.critical('\nTEST FAILED: Could not find all images (EMI, ERI, EKI)')

    def test5_run_new_pv_image(self):
        """
        Description:
        Attempts to run an instance from the newly created PV image.
        Will attempt to ping/ssh into the instance once running and execute the 'uptime' command.
        """
        emi = self.emi
        if not emi:
            raise SkipTestException('No emi found or provided')
        if isinstance(emi, basestring):
            emi = self.user.ec2.get_emi(emi, state=None)
        self.reservation = None
        ### Add and authorize a group for the instance
        self.group = self.user.ec2.add_group('load_pv_image_test')
        self.user.ec2.authorize_group(self.group, port=22, protocol='tcp')
        self.user.ec2.authorize_group(self.group,  protocol='icmp', port=-1)
        ### Generate a keypair for the instance
        localkeys = self.user.ec2.get_all_current_local_keys()
        if localkeys:
            self.keypair = localkeys[0]
            self.keypair_name = self.keypair.name
        else:
            self.keypair_name = "load_pv_test_keypair" + str(int(time.time()))
            self.keypair = self.user.ec2.get_keypair(key_name=self.keypair_name)
        try:
            size = int(self.emi.tags.get('size', 0)) * int(self.args.time_per_gig)
            timeout = size or 300
            instance = self.user.ec2.run_image(image=emi, keypair=self.keypair,
                                             group=self.group, timeout=timeout)[0]
            instance.sys('uptime', code=0)
            self.status("Run new PV image PASSED")
        finally:
            emi.update()
            self.log.debug('Image states after run attempt:')
            self.show_images()

    def clean_method(self):
        """
        Description:
        Attempts to clean up resources/artifacts created during this test.
        This method will not clean up the images created in this
        test. Will attempt to delete/terminate instances, keypairs, etc..
        """
        pass

if __name__ == "__main__":
    testcase = Load_Pv_Image()
    # Create a single testcase to wrap and run the image creation tasks.
    result = testcase.run()
    if result:
        testcase.log.error('TEST FAILED WITH RESULT:{0}'.format(result))
    else:
        testcase.status('TEST PASSED')
    exit(result)



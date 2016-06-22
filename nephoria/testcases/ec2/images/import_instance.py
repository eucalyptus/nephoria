#!/usr/bin/python
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
#!/usr/bin/env python
from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcases.euca2ools.euca2ools_image_utils import Euca2oolsImageUtils
from nephoria.usercontext import UserContext
from nephoria.testcontroller import TestController
from cloud_utils.log_utils import get_traceback
from cloud_utils.system_utils import local
from cloud_utils.net_utils.sshconnection import CommandExitCodeException
from boto.s3.bucket import Bucket
from boto.ec2.keypair import KeyPair
from boto.exception import S3ResponseError
import copy
from nephoria.aws.ec2.conversiontask import ConversionTask
from subprocess import CalledProcessError
from urllib2 import Request, urlopen, URLError
from base64 import b64decode
import os
import time
import types


class ImportInstanceTests(CliTestRunner):
    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)
    _DEFAULT_CLI_ARGS['url'] = {
        'args': ['--url'],
        'kwargs': {'default': None,
                   'help': 'URL containing remote image to create import instance task from'}}

    _DEFAULT_CLI_ARGS['instanceuser'] = {
        'args': ['--instance-user'],
        'kwargs': {'dest': 'instance_user',
                   'default': None,
                   'help': 'Username used for ssh or winrm login ie: Linux:root '
                           'Windows:Administrator'}}

    _DEFAULT_CLI_ARGS['workerip'] = {
        'args': ['--workerip'],
        'kwargs': {'dest': 'worker_machine',
                   'default': None,
                   'help': 'The ip/hostname of the machine that the operation will be performed '
                           'on'}}

    _DEFAULT_CLI_ARGS['worker_username'] = {
        'args': ['--worker-username'],
        'kwargs': {'dest': 'worker_username',
                   'default': 'root',
                   'help': 'The username of the machine that the operation will be performed on'}}

    _DEFAULT_CLI_ARGS['worker_password'] = {
        'args': ['--worker-password'],
        'kwargs': {'dest': 'worker_password',
                   'default': None,
                   'help': 'The password of the machine that the operation will be performed on'}}

    _DEFAULT_CLI_ARGS['worker_keypath'] = {
        'args': ['--worker-keypath'],
        'kwargs': {'dest': 'worker_keypath',
                   'default': None,
                   'help': 'The ssh keypath of the machine that the operation will be performed '
                           'on'}}

    _DEFAULT_CLI_ARGS['destpath'] = {
        'args': ['--destpath'],
        'kwargs': {'default': '/disk1/storage',
                   'help': 'The path on the workip that this operation will be performed on'}}

    _DEFAULT_CLI_ARGS['imagelocation'] = {
        'args': ['--imagelocation'],
        'kwargs': {'default': None,
                   'help': 'The file path on the worker of a pre-existing image to import'}}

    _DEFAULT_CLI_ARGS['urlpass'] = {
        'args': ['--urlpass'],
        'kwargs': {'dest': 'wget_password',
                   'default': None,
                   'help': 'Password needed to retrieve remote url'}}

    _DEFAULT_CLI_ARGS['urluser'] = {
        'args': ['--urluser'],
        'kwargs': {'dest': 'wget_user',
                   'default': None,
                   'help': 'Username needed to retrieve remote url'}}

    _DEFAULT_CLI_ARGS['gigtime'] = {
        'args': ['--gigtime'],
        'kwargs': {'dest': 'time_per_gig',
                   'default': 300,
                   'help': 'Time allowed per gig size of image to be used'}}

    _DEFAULT_CLI_ARGS['virtualization_type'] = {
        'args': ['--virtualization-type'],
        'kwargs': {'default': 'hvm',
                   'help': 'virtualization type hvm or pv'}}

    _DEFAULT_CLI_ARGS['bucket'] = {
        'args': ['--bucket'],
        'kwargs': {'dest': 'bucketname',
                   'default': None,
                   'help': 'bucket name to be used for import task'}}

    _DEFAULT_CLI_ARGS['arch'] = {
        'args': ['--arch'],
        'kwargs': {'dest': 'arch',
                   'default': "x86_64",
                   'help': 'Image architecture ie:x86_64'}}

    _DEFAULT_CLI_ARGS['imageformat'] = {
        'args': ['--imageformat'],
        'kwargs': {'dest': 'imageformat',
                   'default': 'raw',
                   'help': 'image format for import task. ie vmdk raw vhd'}}

    _DEFAULT_CLI_ARGS['platform'] = {
        'args': ['--platform'],
        'kwargs': {'dest': 'platform',
                   'default': "Linux",
                   'help': 'Linux or Windows'}}

    _DEFAULT_CLI_ARGS['uploaded_manifest'] = {
        'args': ['--uploaded-manifest'],
        'kwargs': {'dest': 'upload_manifest',
                   'default': None,
                   'help': 'bucket/prefix location of manifest to register'}}

    _DEFAULT_CLI_ARGS['bundle_manifest'] = {
        'args': ['--bundle-manifest'],
        'kwargs': {'dest': 'bundle_manifest',
                   'default': None,
                   'help': 'file path on worker to bundle manifest to upload'}}

    _DEFAULT_CLI_ARGS['overwrite'] = {
        'args': ['--overwrite'],
        'kwargs': {'action': 'store_true',
                   'default': False,
                   'help': 'Will overwrite files in matching work dir on worker machine if found'}}

    _DEFAULT_CLI_ARGS['time_per_gig'] = {
        'args': ['--time-per-gig'],
        'kwargs': {'default': 100,
                   'help': 'Time allowed (in addition to base timeout) per image size in GB '
                           'before timing out task. Default:100 seconds'}}

    _DEFAULT_CLI_ARGS['base_timeout'] = {
        'args': ['--base-timeout'],
        'kwargs': {'default': 600,
                   'help': 'Base timeout value prior to adding time per gig of image size'}}

    _DEFAULT_CLI_ARGS['task_user_data'] = {
        'args': ['--task-user-data'],
        'kwargs': {'default': '#cloud-config\ndisable_root: false',
                   'help': 'user data to provide to import instance task request'}}

    _DEFAULT_CLI_ARGS['no_clean_on_exit'] = {
        'args': ['--no-clean-on-exit'],
        'kwargs': {'action': 'store_true',
                   'default': False,
                   'help': 'Disable cleanup method upon exit to leave test resources behind'}}

    del _DEFAULT_CLI_ARGS['emi']


    def post_init(self):
        """
        cli_test_runner method which runs after __init__()
        """
        self.args.worker_password = self.args.worker_password or self.args.password
        self.args.worker_keypath = self.args.worker_keypath
        # Format platform case sensitive arg.
        if str(self.args.platform).upper().strip() == "WINDOWS":
            self.args.platform = "Windows"
        elif str(self.args.platform).upper().strip() == "LINUX":
            self.args.platform = "Linux"
        if self.args.instance_user is None:
            if self.args.platform == "Windows":
                self.args.instance_user = 'Administrator'
            else:
                self.args.instance_user = 'root'
        self.latest_task_dict = None
        self._user = None
        self._tc = None
        self._image_utils = None
        self._bucket = None
        self._group = None
        self._imagelocation = None
        self._keypair = None
        self._created_keypairs = []
        self._zone = None
        self.args_check = None
        self.current_task = None


    @property
    def imagelocation(self):
        if not self._imagelocation:
            self._imagelocation = self.get_source_volume_image()
        return self._imagelocation

    @property
    def tc(self):
        if not self._tc:
            if not self.args.clc:
                self.log.error('Must provide --clc flag to run this test')
                raise ValueError('Must provide --clc flag to run this test')
            try:
                self._tc = TestController(hostname=self.args.clc,
                                    environment_file=self.args.environment_file,
                                    password=self.args.password,
                                    clouduser_name=self.args.test_user,
                                    clouduser_account=self.args.test_account,
                                    log_level=self.args.log_level)
            except Exception as E:
                self.log.error("{0}\nError creating TestController obj:{1}"
                               .format(get_traceback(), E))
                raise E
        return self._tc

    @property
    def created_image(self):
        task = (self.latest_task_dict or {}).get('task', None)
        return getattr(task, 'id', None)

    @property
    def worker_password(self):
        wp = self.args.worker_password or self.args.password
        return wp


    @property
    def worker_keypath(self):
        wk = self.args.worker_keypath or self.args.keypair
        return wk


    @property
    def image_utils(self):
        iu = getattr(self, '_image_utils', None)
        if iu is None:
            # Create an ImageUtils helper from the arguments provided in this testcase...
            setattr(self.args, 'worker_machine', self.tc.sysadmin.clc_machine)
            setattr(self.args, 'user_context', self.user)
            setattr(self.args, 'test_controller', self.tc)
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


    def check_url(self, url=None):
        retries = 12
        retry_delay = 10
        req = Request(self.args.image_url)
        url = url or self.args.image_url
        for x in range(retries + 1):
            try:
                response = urlopen(req)
                self.log.debug('URL: "{0}" is valid and reachable!'.format(url))
            except URLError, e:
                if x < retries:
                    if hasattr(e, 'reason'):
                        self.log.debug('Retrying to resolve "{0}", and got: "{1}"'
                                       .format(url, e.reason))
                    elif hasattr(e, 'code'):
                        self.log.debug('Retrying to resolve "{0}", and got: "{1}"'
                                       .format(url, e.code))
                    time.sleep(retry_delay)
                    continue
                else:
                    if hasattr(e, 'reason'):
                        raise AssertionError('INVALID URL: "{0}", "{1}"'
                                             .format(url, e.reason))
                    elif hasattr(e, 'code'):
                        raise AssertionError('INVALID REQUEST: "{0}", "{1}"'
                                             .format(url, e.code))
            break

    @property
    def bucket(self):
        if not self._bucket:
            bucketname = self.args.bucketname
            if not bucketname:
                if self.imagelocation or self.args.url:
                    location = self.imagelocation or self.args.url
                    image_name = os.path.basename(location)[0:15]
                else:
                    image_name = str(self.args.platform or 'test')
                bucketname = 'eutester_import_' + str(image_name)
            self._bucket = self.user.s3.create_bucket(bucketname)
        return self._bucket

    @bucket.setter
    def bucket(self, value=None):
        if value is None or isinstance(value, Bucket):
            self._bucket = value
        elif isinstance(value, basestring):
            user = self.user
            assert isinstance(user, UserContext)
            try:
                self._bucket = self.user.s3.get_bucket(value)
            except S3ResponseError as SE:
                self.log.error('Error fetching bucket:"{0}", err:"{1}"'.format(value, SE))
                raise SE
        else:
            raise ValueError('Unknown type for bucket: "{0}/{1}"'.format(value, type(value)))


    @classmethod
    def assertEquals(cls, x, y):
        assert x == y, str(x) + ' is not equal to ' + str(y)

    @property
    def keyname(self):
        return self.keypair.name

    @property
    def groupname(self):
        return self.group.name

    @property
    def group(self):
        if not self._group:
            self._group = self._get_security_group()
        return self._group

    @group.setter
    def group(self, group):
        if group is None:
            self._group = group
        else:
            if isinstance(group, basestring):
                group_name = group
            else:
                group_name = group.name
            try:
                self._group = self._get_security_group(group_name=group_name)
            except Exception as E:
                self.log.error("{0}\nError setting up security group, err:{1}"
                               .format(get_traceback(), E))
                raise E

    def _get_security_group(self, group_name=None):
        group_name = group_name or 'import_instance_test_group'
        user = self.user
        group = user.ec2.add_group(group_name=group_name)
        #authorize group for ssh and icmp
        user.ec2.authorize_group(group, protocol='tcp', port=22)
        user.ec2.authorize_group(group, protocol='icmp', port='-1')
        if self.args.platform == 'Windows':
            user.ec2.authorize_group(group, protocol='tcp', port='3389')
            user.ec2.authorize_group(group, protocol='tcp', port='80')
            user.ec2.authorize_group(group, protocol='tcp', port='443')
            user.ec2.authorize_group(group, protocol='tcp', port='5985')
            user.ec2.authorize_group(group, protocol='tcp', port='5986')
        return group

    @property
    def keypair(self):
        if not self._keypair:
            try:
                self._keypair = self.user.ec2.create_keypair_and_localcert(
                    "{0}_key_{1}".format(self.name, time.time()))
                self._created_keypairs.append(self._keypair)
            except Exception, ke:
                self.log.error("Failed to find/create a keypair, error:" + str(ke))
                raise ke
        return self._keypair

    @keypair.setter
    def keypair(self, keypair):
        if keypair is None or isinstance(keypair, KeyPair):
            self._keypair = keypair
        else:
            raise ValueError('keypair must be of type None or boto Keypair, got:"{0}/{1}"'
                             .format(keypair, type(keypair)))
    @property
    def zone(self):
        if not self._zone:
            if self.args.zone:
                self._zone = self.args.zone
            else:
                zones = self.tc.admin.ec2.get_zone_names()
                if not zones:
                    raise RuntimeError('Could not find any zones to use in this test')
                self._zone = zones[0]
        return self._zone

    @zone.setter
    def zone(self, zone):
        if zone is None or isinstance(zone, basestring):
            self._zone = zone
        else:
            raise ValueError('Zone must be of type None or String, got: "{0}/{1}"'
                             .format(zone, type(zone)))

    def get_source_volume_image(self, url=None, img_utils=None):
        url = url or self.args.url
        img_utils = img_utils or self.image_utils
        if self.args.imagelocation:
            imagelocation = self.args.imagelocation
        else:
            assert isinstance(img_utils, Euca2oolsImageUtils)
            worker = img_utils.worker_machine
            src_img = os.path.basename(url)
            src_img = os.path.join(self.args.destpath, src_img)
            try:
                #Looking for existing file at destpath
                worker.sys('ls ' + src_img, code=0)
            except CommandExitCodeException:
                #File not found at destpath download it...
                worker.wget_remote_image(url=url, dest_file_name=src_img)
            imagelocation = src_img
        return imagelocation

    

    def test1_basic_create_import_instance(self,
                                          base_timout=None,
                                          time_per_gig=None):
        '''
        Definition: Attempts to run, monitor and validate the outcome of a
        basic import instance task.
        Will test the following:

        ## TASK CHECKS:
        -Euca2ools import task request
        -Will monitor task and describe task responses until complete, or a
         given timeout is reached.
        -Upon completion will validate task status

        ## TASK INSTANCE CHECKS:
        -Instance status
        -Will Monitor instance to running, then attempt to ping and ssh.
        -Instance params (security group, key, zone, etc)
        -Will request the instance from the system to confirm it is visible
        to this account, etc..

        ## TASK VOLUME CHECKS:
        -Volume status as created and available post task
        -Request the volume from the system to confirm it is visible to this
        account, etc..
        -Volume Params are correct, size, zone, etc per task request

        ## TASK SNAPSHOT CHECKS:
        -Snapshot status completed
        -Verify the owner id is the same as the account id that made the task
        request

        ## TASK IMAGE CHECKS:
        -Verify the image is not public
        -Verify the image state is 'available'
        -Verify the image owner id is the same as the account id that made the
        task request.
        '''
        self.log.info('Attempting euca-import-instance...')
        try:
            self.user.iam.show_user_summary()
            self.user.show()
        except:
            pass
        base_timout = base_timout or self.args.base_timeout
        time_per_gig = time_per_gig or self.args.time_per_gig
        img_utils = self.image_utils
        user = self.user
        assert isinstance(img_utils, Euca2oolsImageUtils)
        params = {'import_file':self.imagelocation,
                  'bucket':self.bucket.name,
                  'zone':self.zone,
                  'format':self.args.imageformat,
                  'instance_type':self.args.vmtype,
                  'arch':self.args.arch,
                  'keypair':self.keyname,
                  'group':self.groupname,
                  'platform':self.args.platform,
                  'user_context': self.user,
                  'user_data':self.args.task_user_data}
        taskid = img_utils.euca2ools_import_instance(**params)
        task = user.ec2.get_conversion_task(taskid=taskid)
        assert isinstance(task,ConversionTask)
        self.current_task = task
        user.ec2.monitor_conversion_tasks(task,
                                        base_timeout=base_timout,
                                        time_per_gig=time_per_gig)

        # Make sure the task returns an instance, check that the instance for
        # proper run state and param use.
        if not task.instanceid:
            raise RuntimeError('Instance ID not found after task completed, '
                               'status msg:' + str(task.statusmessage))
        inst = user.ec2.get_instances(idstring=task.instanceid)
        if inst:
            inst = inst[0]
            username = self.args.instance_user
            euinst = user.ec2.convert_instance_to_euinstance(instance=inst,
                                                             keypair=self.keypair,
                                                             username=username,
                                                             systemconnection=self.tc.sysadmin,
                                                             auto_connect=False)
            user.ec2.monitor_euinstances_to_running(euinst)
            if euinst.platform == 'windows':
                euinst.connect_to_instance(wait_for_boot=180, timeout=300)
            else:
                euinst.connect_to_instance()
        else:
            raise RuntimeError('Instance:"{0}" not found from task:"{1}"'
                            .format(task.instanceid, task.id))
        if not task.image_id:
            raise RuntimeError('Image Id not found after task completed, '
                               'status msg:' + str(task.statusmessage))
        emi = user.ec2.get_emi(emi=task.image_id)
        self.assertEquals(emi.owner_id, user.account_id)
        for snap in task.snapshots:
            self.assertEquals(snap.owner_id, user.account_id)

        self.latest_task_dict = {'params': params,
                                 'task': task,
                                 'instance': euinst}
        return self.latest_task_dict

    def test2_validate_params_against_task(self):
        if not self.latest_task_dict:
            raise RuntimeError('Dict for latest task not found to validate?')
        params = self.latest_task_dict['params']
        task = self.latest_task_dict['task']
        return self.validate_params_against_task(params=params, task=task)

    def test3_make_image_public(self):
        if not self.latest_task_dict:
            raise RuntimeError('Dict for latest task not found to validate?')
        task = self.latest_task_dict['task']
        emi = self.user.ec2.get_emi(emi=task.image_id)
        emi.set_launch_permissions(group_names=['all'])
        self.log.info('\n---------------------------\n'
                      'MADE PUBLIC EMI: {0}'
                      '\n---------------------------'.format(emi.id))

    def test4_tag_image(self):
        if not self.latest_task_dict:
            raise RuntimeError('Dict for latest task not found to validate?')
        task = self.latest_task_dict['task']
        emi = self.user.ec2.get_emi(emi=task.image_id)
        try:
            if self.args.url:
                emi.add_tag('source', value=(str(self.args.url)))
            emi.add_tag('eutester-created', value="import-instance-test")
        except Exception, te:
            self.log.debug('Could not add tags to image:' + str(emi.id) +
                       ", err:" + str(te))

    def validate_params_against_task(self, params, task):
        assert isinstance(params, types.DictionaryType)
        assert isinstance(task, ConversionTask)
        err_msg = ""
        try:
            if params.has_key('bucket'):
                self.log.debug('Checking task for bucket...')
                #todo put bucket checks here
        except Exception as e:
            self.log.error('Error checking task bucket:\n"{0}'.format(get_traceback()))
            err_msg += str(e) + "\n"

        try:
            if params.has_key('zone'):
                zone = params['zone']
                self.log.debug('Checking task for zone params:' + str(zone))
                self.assertEquals(zone, task.availabilityzone)
                for volume in task.volumes:
                    self.assertEquals(volume.zone, zone)
                    self.assertEquals(task.instance.placement, zone)
        except Exception as e:
            self.log.error('Error checking task zone:\n"{0}'.format(get_traceback()))
            err_msg += str(e) + "\n"

        try:
            if params.has_key('size'):
                size = params['size']
                self.log.debug('Checking task for size params:' + str(size))
                self.assertEquals(zone, task.availabilityzone)
                for im_volume in task.importvolumes:
                    self.assertEquals(str(im_volume.volume.size), str(size))
        except Exception as e:
            self.log.error('Error checking task size:\n"{0}'.format(get_traceback()))
            err_msg += str(e) + "\n"

        try:
            if params.has_key('format'):
                image_format = params['format']
                self.log.debug('Checking task for format:' + str(image_format))
                for volume in task.importvolumes:
                        self.assertEquals(str(volume.image.format).upper(),
                                          str(image_format).upper())
        except Exception as e:
            self.log.error('Error checking task format:\n"{0}'.format(get_traceback()))
            err_msg += str(e) + "\n"

        try:
            if params.has_key('instance_type'):
                instance_type = params['instance_type']
                self.log.debug('Checking task for instance_type:' + str(instance_type))
                self.assertEquals(task.instance.instance_type, instance_type)
        except Exception as e:
            self.log.error('Error checking task instance-type:\n"{0}'.format(get_traceback()))
            err_msg += str(e) + "\n"

        try:
            if params.has_key('arch'):
                arch = params['arch']
                self.log.debug('Checking task for arch:' + str(arch))
                emi = self.user.ec2.get_emi(emi=task.image_id)
                self.assertEquals(emi.architecture, arch)
        except Exception as e:
            self.log.error('Error checking task arch:\n"{0}'.format(get_traceback()))
            err_msg += str(e) + "\n"

        try:
            if params.has_key('keypair'):
                keypair = params['keypair']
                self.log.debug('Checking task for keypair:' + str(keypair))
                self.assertEquals(keypair, task.instance.key_name)
        except Exception as e:
            self.log.error('Error checking task keypair:\n"{0}'.format(get_traceback()))
            err_msg += str(e) + "\n"

        try:
            if params.has_key('group'):
                group = params['group']
                self.log.debug('Checking task for group:' + str(group))
                ins = self.user.ec2.convert_instance_to_euinstance(
                    task.instance, systemconnection=self.tc.sysadmin, auto_connect=False)
                groups = self.user.ec2.get_instance_security_groups(ins)
                sec_group = groups[0]
                self.assertEquals(sec_group.name, group)
        except Exception as e:
            self.log.error('Error checking task group:\n"{0}'.format(get_traceback()))
            err_msg += str(e) + "\n"

        try:
            if params.has_key('platform'):
                platform = params['platform']
                self.log.debug('Checking task for platform: ' + str(platform))
                platform = str(platform).lower()
                if platform == 'linux':
                    platform = None
                self.assertEquals(platform, task.instance.platform)
        except Exception as e:
            self.log.error('Error checking task platform:\n"{0}'.format(get_traceback()))
            err_msg += str(e) + "\n"

        try:
            if hasattr(task, 'instanceid') and task.instanceid and \
                    params.has_key('user_data') and params['user_data'] is not None:
                user_data = params['user_data']
                self.log.debug('Checking task for user_data: ' + str(user_data))
                ins_attr = self.user.ec2.connection.get_instance_attribute(
                    task.instanceid, 'userData')
                if 'userData' in ins_attr:
                    ins_user_data = b64decode(ins_attr['userData'])
                else:
                    ins_user_data = None
                self.assertEquals(user_data, ins_user_data)
        except Exception as e:
            self.log.error('Error checking task user-data:\n"{0}'.format(get_traceback()))
            err_msg += str(e) + "\n"

        if err_msg:
            raise Exception("Failures in param validation detected:n\n"
                            + str(err_msg))

    def clean_method(self):
        if self.args.no_clean_on_exit:
            self.log.info('"no_clean_on_exit" set. Skipping Clean method')
            return
        task = self.current_task
        err_buf = ""
        if not task:
            return
        try:
            if task.instance:
                self.user.ec2.terminate_single_instance(task.instance)
        except Exception as E:
            msg = 'Error terminating task instance, err: {0}'.format(E)
            err_buf += msg + "\n"
            self.log.error("{0}\n{1}".format(get_traceback(), msg))
        try:
            if task.volumes:
                self.user.ec2.delete_volumes(task.volumes)
        except Exception as E:
            msg = 'Error deleting task volumes, err: {0}'.format(E)
            err_buf += msg + "\n"
            self.log.error("{0}\n{1}".format(get_traceback(), msg))
        try:
            for keypair in self._created_keypairs:
                self.user.ec2.delete_keypair(keypair)
        except Exception as E:
            msg = 'Error deleting keypair, err: {0}'.format(E)
            err_buf += msg + "\n"
            self.log.error("{0}\n{1}".format(get_traceback(), msg))
        try:
            if self._group:
                self.user.ec2.delete_group(self._group)
        except Exception as E:
            msg = 'Error deleting security group, err: {0}'.format(E)
            err_buf += msg + "\n"
            self.log.error("{0}\n{1}".format(get_traceback(), msg))
        if err_buf:
            raise RuntimeError(err_buf)
        else:
            self.log.info('Clean method completed')




if __name__ == "__main__":
    test = ImportInstanceTests()
    result = test.run()
    if test.created_image:
        test.log.info('\n---------------------------\nCreated EMI:{0}\n'
                      '---------------------------'.format(test.created_image))
    exit(result)





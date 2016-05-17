#!/usr/bin/env python
from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcases.euca2ools.euca2ools_image_utils import Euca2oolsImageUtils
from nephoria.usercontext import UserContext
from nephoria.testcontroller import TestController
import copy
import time
from urllib2 import Request, urlopen, URLError




class LoadHvmImage(CliTestRunner):

    #####################################################################################
    # Example of how to edit, add, remove the pre-baked cli arguments provided in the base
    # CliTestRunner class...
    #####################################################################################

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)


    _DEFAULT_CLI_ARGS['filepath'] = {
        'args': ['--filepath'],
        'kwargs': {'dest': 'filepath',
                   'help': 'File path to create EMI from',
                   'default': None}}

    _DEFAULT_CLI_ARGS['instance_timeout'] = {
        'args': ['--instance-timeout'],
        'kwargs': {'help': 'Time to wait for an instance to run',
                   'default': 300,
                   'type': int}}

    _DEFAULT_CLI_ARGS['workerip'] = {
        'args': ['--workerip'],
        'kwargs': {'dest': 'worker_machine',
                   'help': 'The ip/hostname of the machine that the operation will be '
                           'performed on',
                   'default': None}}

    _DEFAULT_CLI_ARGS['worker_username'] = {
        'args': ['--worker-username'],
        'kwargs': {'dest': 'worker_username',
                   'help': 'The username of the machine that the operation will be performed on, '
                           'default:"root"',
                   'default': 'root'}}

    _DEFAULT_CLI_ARGS['worker_password'] = {
        'args': ['--worker-password'],
        'kwargs': {'dest': 'worker_password',
                   'help': 'The password of the machine that the operation will be performed on',
                   'default': None}}

    _DEFAULT_CLI_ARGS['worker_keypath'] = {
        'args': ['--worker-keypath'],
        'kwargs': {'dest':'worker_keypath',
                   'help': 'The ssh keypath of the machine that the operation will be '
                           'performed on',
                   'default': None}}

    _DEFAULT_CLI_ARGS['destpath'] = {
        'args': ['--destpath'],
        'kwargs': {'help': 'The path on the workip, that this operation will be performed on',
                   'default': '/disk1/storage'}}

    _DEFAULT_CLI_ARGS['urlpass'] = {
        'args': ['--urlpass'],
        'kwargs': {'dest': 'wget_password',
                   'help': 'Password needed to retrieve remote url',
                   'default': None}}

    _DEFAULT_CLI_ARGS['wget_user'] = {
        'args': ['--wget-user'],
        'kwargs': {'dest': 'wget_user',
                   'help': 'Username needed to retrieve remote url',
                   'default': None}}

    _DEFAULT_CLI_ARGS['image_url'] = {
        'args': ['--image-url'],
        'kwargs': {'help': 'URL containing remote windows image to create EMI from',
                   'default': None}}

    _DEFAULT_CLI_ARGS['gigtime'] = {
        'args': ['--gigtime'],
        'kwargs': {'dest': 'time_per_gig',
                   'help': 'Time allowed per gig size of image to be used',
                   'default': 300}}

    _DEFAULT_CLI_ARGS['interbundletime'] = {
        'args': ['--interbundletime'],
        'kwargs': {'dest': 'inter_bundle_timeout',
                   'help': 'Inter-bundle timeout',
                   'default': 120}}

    _DEFAULT_CLI_ARGS['virtualization_type'] = {
        'args': ['--virtualization-type'],
        'kwargs': {'help': 'virtualization type, hvm or pv',
                   'default': 'hvm'}}

    _DEFAULT_CLI_ARGS['bucketname'] = {
        'args': ['--bucket'],
        'kwargs': {'dest': 'bucketname',
                   'help': 'bucketname',
                   'default': None}}

    _DEFAULT_CLI_ARGS['platform'] = {
        'args': ['--platform'],
        'kwargs': {'help': '"Linux" or "Windows", default: "linux"' ,
                   'default': None}}

    _DEFAULT_CLI_ARGS['uploaded_manifest'] = {
        'args': ['--uploaded-manifest'],
        'kwargs': {'help': 'bucket/prefix location of manifest to register',
                   'default': None}}

    _DEFAULT_CLI_ARGS['bundle_manifest'] = {
        'args': ['--bundle_manifest'],
        'kwargs': {'help': 'file path on worker to bundle manifest to upload',
                   'default': None}}

    _DEFAULT_CLI_ARGS['overwrite'] = {
        'args': ['--overwrite'],
        'kwargs': {'help': 'Will overwrite files in matching work dir on worker machine if found',
                   'action': 'store_true',
                   'default': False}}

    _DEFAULT_CLI_ARGS['time_per_gig'] = {
        'args': ['--time_per_gig'],
        'kwargs': {'help': 'Time allowed per image size in GB before timing out',
                   'default': 300}}

    _DEFAULT_CLI_ARGS['cloud_account'] = {
        'args': ['--account'],
        'kwargs': {'help': 'cloud account to be used in this test',
                   'default': None}}


    def post_init(self):
        self.created_image = None
        self._user = None
        self._tc = None
        self._image_utils = None
        self.args_check = None

    @property
    def tc(self):
        tc = getattr(self, '__tc', None)
        if not tc:
            tc = TestController(hostname=self.args.clc,
                                environment_file=self.args.environment_file,
                                password=self.args.password,
                                clouduser_name=self.args.test_user,
                                clouduser_account=self.args.test_account,
                                log_level=self.args.log_level)
            setattr(self, '__tc', tc)
        return tc


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

    def make_image_public(self, emi):
        emi = emi or self.created_image
        emi.set_launch_permissions(group_names=['all'])
        self.log.info('\n---------------------------\n'
                      'MADE PUBLIC EMI: {0}'
                      '\n---------------------------'.format(emi))

    def test1_check_args(self):
        """
        Checks the provided testcase arguments to make sure they are valid.
        Attempts to validate an image 'url' if provided.
        """
        self.args_check = False
        if not self.args.uploaded_manifest and not self.args.bundle_manifest:
            if (not self.args.image_url and not self.args.filepath) or \
                    (self.args.image_url and self.args.filepath):
                raise Exception('If manifest not provided, either a URL or FILE path '
                                'is required to create image')
            if self.args.image_url:
                self.check_url()
        self.args_check = True

    def test2_create_emi(self):
        """
        Attempts to create an HVM image/EMI from the provided arguments within the cloud
        """
        self.status('Attempting to create emi with the following user:')
        self.user.iam.show_user_summary()
        if self.args_check == False:
            raise SkipTestException('ARGS check failed, skipping create emi test')
        self.image_utils.user_context = self.user
        self.created_image = self.do_with_args(self.image_utils.create_emi)
        self.log.info('\n---------------------------\n'
                      'Created EMI: {0}'
                      '\n---------------------------'.format(self.created_image))

    def test3_make_image_public(self):
        """
        Attempts to make an image public.
        By default will use the image EMI created within the test.
        If an 'emi' ID was provided to the test it will instead use that image/EMI id.
        :return:
        """
        emi = self.created_image or self.args.emi
        if not emi:
            raise SkipTestException('Skipping test. No EMI created or provided to make public')
        self.make_image_public(emi=emi)

    def test4_tag_image(self):
        emi = self.created_image
        if not emi:
            raise SkipTestException('Skipping test. No EMI created to make public')
        if not isinstance(emi, basestring):
            emi = emi.id
        self.user.ec2.create_tags([emi],
                                  {'Nephoria Test Image: {0}'.format(time.asctime()):'',
                                   'URL': self.args.image_url})

    def clean_method(self):
        pass

if __name__ == "__main__":
    test =LoadHvmImage()
    result = test.run()
    if test.created_image:
        test.log.info('\n---------------------------\nCreated EMI:{0}\n'
                      '---------------------------'.format(test.created_image))
    exit(result)




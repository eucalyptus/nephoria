
'''
This test case class is intended to help test functions and features related to block device mapping for ebs backed
instances. The test attempts to create a base ebs-backed image created from a remote url downloaded and written to a
volume within this cloud. A snapshot of this volume, and md5sum are taken for use throughout the different test
iterations. In addition a 2nd volume is filled with some amount of random/unique data before a 2nd snapshot and md5sum
of it are created and used through the test as well.
This test class attempts to test the different block device attributes and verify them through the different stages
of the vm/guest.

'''
from cloud_utils.log_utils import get_traceback, red
from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcontroller import TestController
from boto.ec2.group import Group
from boto.ec2.instance import Instance
from boto.ec2.volume import Volume
from boto.ec2.snapshot import Snapshot

from boto.ec2.blockdevicemapping import BlockDeviceMapping, BlockDeviceType
import time
import types
import httplib
import copy
import math
import re



class FixedBlockDeviceMapping(BlockDeviceMapping):
    # Originally a Temporary class until boto fixes this upstream.
    # 'nodevice' param is formatted incorrectly, should not prefix with 'Ebs' before 'NoDevice'.
    # As of 3/14 this appears to be fixed, although now euca may be requiring the nodevice param
    # to be populated with a boolean, and Boto is sending an empty string. See: EUCA-10649

    def _build_list_params(self, params, prefix=''):
        i = 1
        for dev_name in self:
            pre = '%s.%d' % (prefix, i)
            params['%s.DeviceName' % pre] = dev_name
            block_dev = self[dev_name]
            if block_dev.ephemeral_name:
                params['%s.VirtualName' % pre] = block_dev.ephemeral_name
            else:
                if block_dev.no_device:
                    params['%s.NoDevice' % pre] = 'true'
                else:
                    if block_dev.snapshot_id:
                        params['%s.Ebs.SnapshotId' % pre] = block_dev.snapshot_id
                    if block_dev.size:
                        params['%s.Ebs.VolumeSize' % pre] = block_dev.size
                    if block_dev.delete_on_termination:
                        params['%s.Ebs.DeleteOnTermination' % pre] = 'true'
                    else:
                        params['%s.Ebs.DeleteOnTermination' % pre] = 'false'
                    if block_dev.volume_type:
                        params['%s.Ebs.VolumeType' % pre] = block_dev.volume_type
                    if block_dev.iops is not None:
                        params['%s.Ebs.Iops' % pre] = block_dev.iops
                    # The encrypted flag (even if False) cannot be specified for the root EBS
                    # volume.
                    if block_dev.encrypted is not None:
                        if block_dev.encrypted:
                            params['%s.Ebs.Encrypted' % pre] = 'true'
                        else:
                            params['%s.Ebs.Encrypted' % pre] = 'false'

            i += 1

    def build_list_params(self, params, prefix=''):
        return self._build_list_params(params=params, prefix=prefix)

class Block_Device_Mapping_Tests(CliTestRunner):
    #Define the bytes per gig
    gig = 1073741824

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['use_previous'] = \
        {'args': ['--use-previous'],
         'kwargs': {'help': 'Use existing volumes, snapshots and images from a previous '
                          'Block_Device_Mapping_Test run',
                    'default': False,
                    'action': 'store_true'}}

    _DEFAULT_CLI_ARGS['url'] = {
        'args': ['--url'],
        'kwargs': {'help': "URL containing remote BFEBS image to create emi from",
                   'default': None,
                   'required': True}}

    _DEFAULT_CLI_ARGS['instance_password'] = {
        'args': ['--instance-password'],
        'kwargs': {'help': "Optional instance ssh password",
                   'default': None}}

    def post_init(self, *args, **kwargs):
        self.url = self.args.url
        self._emi = None
        self._user = None
        self._tc = None
        self._zone = None
        self._group = None
        self._test_id = None
        self._keypairname = None
        self._keypair = None

        self._base_test_snapshot = None
        self._base_test_volume = None
        self._current_test_instance = None
        self._build_image_volume = None
        self._build_image_snapshot = None

        self.test_resources = {}
        self.reservation = None
        self.instance = None
        self.volumes = []
        self.image_bytes = None
        self.image_gigs = None
        self.build_image_volume = None
        self.build_image_volume_tag_name = 'block_dev_map_tests_build_image_volume'
        self.build_image_snapshot = None
        self.build_image_snapshot_tag_name = 'block_dev_map_tests_build_image_snapshot'
        self.block_device_map = None
        self.base_test_volume = None
        self.base_test_volume_tag_name = 'block_dev_map_tests_base_test_volume'
        self.base_test_snapshot = None
        self.base_test_snapshot_tag_name = 'block_dev_map_tests_base_test_snap'
        self.test_image1 = None
        self.test_image1_tag_name = 'block_dev_map_tests_image1'
        self.test_image2 = None
        self.test_image2_tag_name = 'block_dev_map_tests_image2'
        self.test_image3 = None
        self.test_image3_tag_name = 'block_dev_map_tests_image3'
        self.test_image4 = None
        self.test_image4_tag_name = 'block_dev_map_tests_image4'
        self.snapshots = []
        self.images = []
        self.instance_password = self.args.instance_password
        self.groupname = "{0}_{1}".format(self.__class__.__name__, int(time.time()))

    @property
    def tc(self):
        tc = getattr(self, '_tc', None)
        if not tc:
            tc = TestController(self.args.clc,
                                password=self.args.password,
                                clouduser_name=self.args.test_user,
                                clouduser_account=self.args.test_account,
                                log_level=self.args.log_level)
            setattr(self, '_tc', tc)
        return tc

    @property
    def my_test_id(self):
        if not self._test_id:
            self._test_id = "{0}:{1}".format(self.__class__.__name__, int(time.time()))
        return self._test_id

    @property
    def zone(self):
        if not self._zone:
            if self.args.zone:
                self._zone = str(self.args.zone)
            else:
                zonelist = self.user.ec2.get_zone_names()
                if not zonelist:
                    msg = "Could not discover an availability zone to perform tests in. Please " \
                          "specify zone"
                    self.log.error("{0}\n{1}".format(get_traceback(), msg))
                    raise RuntimeError(None)
                self._zone = zonelist[0]
        return self._zone

    @property
    def group(self):
        group = getattr(self, '_group', None)
        if not group:
            group = self.user.ec2.add_group("{0}_group".format(self.__class__.__name__))
            self.user.ec2.authorize_group(group, port=22, protocol='tcp')
            self.user.ec2.authorize_group(group, protocol='icmp', port=-1)
            self.user.ec2.show_security_group(group)
            setattr(self, '_group', group)
        return group

    @group.setter
    def group(self, value):
        if value is None or isinstance(value, Group):
            setattr(self, '_group', value)
        else:
            raise ValueError('Can not set security group to type:"{0}/{1}"'
                             .format(value, type(value)))

    @property
    def keypair_name(self):
        keyname = getattr(self, '_keypairname', None)
        if not keyname:
            keyname = "{0}_{1}".format(self.__class__.__name__, int(time.time()))
            setattr(self, '_keypairname', keyname)
        return keyname

    @property
    def keypair(self):
        key = getattr(self, '_keypair', None)
        if not key:
            key = self.user.ec2.get_keypair(key_name=self.keypair_name)
            setattr(self, '_keypair', key)
        return key

    @property
    def emi(self):
        emi = getattr(self, '_emi', None)
        if not emi:
            try:
                if self.args.emi:
                    emi = self.user.ec2.get_emi(emi=self.args.emi)
                else:
                    try:
                        emi = self.user.ec2.get_emi(basic_image=True,
                                                    root_device_type='instance-store')
                    except Exception as E:
                        self.log.warn(red('Error fetching a basic test image, will try any image next. '
                                      'Error:{0}'.format(E)))
                    #emi = self.user.ec2.get_emi()
                setattr(self, '_emi', emi)
            except Exception as E:
                self.log.error("{0}\nFailed to fetch EMI:{1}".format(get_traceback(), E))
                raise E
        return emi

    @emi.setter
    def emi(self, value):
        setattr(self, '_emi', value)

    @property
    def user(self):
        user = getattr(self, '_user', None)
        if not user:
            try:
                user = self.tc.get_user_by_name(aws_account_name=self.args.test_account,
                                                aws_user_name=self.args.test_user)
            except:
                user = self.tc.create_user_using_cloudadmin(aws_account_name=self.args.test_account,
                                                            aws_user_name=self.args.test_user)
            setattr(self, '_user', user)
        return user

    @property
    def base_test_snapshot(self):
        if not self._base_test_snapshot:
            self.test0_setup_bfebs_instance_volume_and_snapshots_from_url()
        return self._base_test_snapshot

    @base_test_snapshot.setter
    def base_test_snapshot(self, snapshot):
        if snapshot is None or isinstance(snapshot, Snapshot):
            self._build_image_snapshot = snapshot
        else:
            msg = "{0}Unsupported type for base_image_snapshot. Must be of type None or " \
                  "boto.Volume. Got: {1}/{2}".format(get_traceback(), snapshot, type(snapshot))
            self.log.error(msg)
            raise ValueError(msg)

    @property
    def base_test_volume(self):
        if not self._base_test_volume:
            self._base_test_volume = self.user.ec2.create_volumes(self.zone, size=1,
                                                                  monitor_to_state=None)[0]
            self.user.ec2.create_tags(self.base_test_volume.id, {self.my_test_id: ''})
            self._base_test_volume.add_tag(self.base_test_volume_tag_name)
            self.user.ec2.monitor_created_euvolumes_to_state(volumes=[self._base_test_volume])
        return self._base_test_volume

    @base_test_volume.setter
    def base_test_volume(self, volume):
        if volume is None or isinstance(volume, Volume):
            self._build_image_volume = volume
        else:
            msg = "{0}Unsupported type for base_test_volume. Must be of type None or " \
                  "boto.Volume. Got: {1}/{2}".format(get_traceback(), volume, type(volume))
            self.log.error(msg)
            raise ValueError(msg)

    @property
    def current_test_instance(self):
        if not self._current_test_instance:
            self.status('Attempting to launch helper instance...')
            self._current_test_instance = self.user.ec2.run_image(self.emi,
                                                                  keypair=self.keypair.name,
                                                                  vmtype=self.args.vmtype,
                                                                  group=self.group.id,
                                                                  zone=self.zone)[0]
            self.user.ec2.create_tags(self._current_test_instance.id, {self.my_test_id: ''})
        return self._current_test_instance

    @current_test_instance.setter
    def current_test_instance(self, instance):
        if instance is None or isinstance(instance, Instance):
            self._current_test_instance = instance
        else:
            msg = "{0}Unsupported type for test_instance. Must be of type None or " \
                  "boto.Instance. Got: {1}/{2}".format(get_traceback(), instance, type(instance))
            self.log.error(msg)
            raise ValueError(msg)

    @property
    def build_image_volume(self):
        if not self._build_image_volume:
            self.status('create test volume(s)...')
            self._build_image_volume = self.user.ec2.create_volumes(self.zone,
                                                                    size=self.image_gigs,
                                                                    monitor_to_state=None)[0]
            self.user.ec2.create_tags(self.build_image_volume.id, {self.my_test_id: ''})
            self.build_image_volume.add_tag(self.build_image_volume_tag_name)
            self.user.ec2.monitor_created_euvolumes_to_state(volumes=[self._build_image_volume])
        return self._build_image_volume

    @build_image_volume.setter
    def build_image_volume(self, volume):
        if volume is None or isinstance(volume, Volume):
            self._build_image_volume = volume
        else:
            msg = "{0}Unsupported type for build_image_volume. Must be of type None or " \
                  "boto.Volume. Got: {1}/{2}".format(get_traceback(), volume, type(volume))
            self.log.error(msg)
            raise ValueError(msg)

    @property
    def build_image_snapshot(self):
        if not self._build_image_snapshot:
            self.test0_setup_bfebs_instance_volume_and_snapshots_from_url()
        return self._build_image_snapshot

    @build_image_snapshot.setter
    def build_image_snapshot(self, snapshot):
        if snapshot is None or isinstance(snapshot, Snapshot):
            self._build_image_snapshot = snapshot
        else:
            msg = "{0}Unsupported type for build_image_snapshot. Must be of type None or " \
                  "boto.Volume. Got: {1}/{2}".format(get_traceback(), snapshot, type(snapshot))
            self.log.error(msg)
            raise ValueError(msg)


    def clean_method(self):
        '''
        Definition:
        Clean up test artifacts leaving behind the images and snapshots created during this test
        '''
        #leave the base test, and snapshot behind for future use. To remove these,
        # the images they are associated with will need to be deleted as well.
        id_list = []
        delete_list = []
        error_count = 0
        for snap in self.test_resources.get('snapshots', []):
            if self.base_test_snapshot and re.search( snap.id, self.base_test_snapshot.id):
                self.log.debug('Removing base_test_snapshot from test_resources list so not deleted')
            elif self.build_image_snapshot and re.search(snap.id, self.build_image_snapshot.id):
                self.log.debug('Removing build_image_snapshot from test_resources list so not deleted')
            else:
                delete_list.append(snap)
        self.test_resources['snapshots'] = delete_list
        errors = ""
        try:
            self.user.ec2.delete_snapshots(self.test_resources.get('snapshots',[]))
        except Exception as E:
            error_count += 1
            self.log.error("{0}\n{1}".format(get_traceback(), E))
            errors += "{0}\n".format(E)

        try:
            instances = self.user.ec2.get_instances(filters={'tag-key': self.my_test_id})
            if instances:
                self.user.ec2.terminate_instances(instances)
        except Exception as E:
            error_count += 1
            self.log.error("{0}\n{1}".format(get_traceback(), E))
            errors += "{0}\n".format(E)
        try:
            volumes = self.user.ec2.get_volumes(filters={'tag-key': self.my_test_id})
            if volumes:
                self.user.ec2.delete_volumes(volumes)
        except Exception as E:
            error_count += 1
            self.log.error("{0}\n{1}".format(get_traceback(), E))
            errors += "{0}\n".format(E)
        try:
            if self.keypair:
                self.user.ec2.delete_keypair(self.keypair)
        except Exception as E:
            error_count += 1
            self.log.error("{0}\n{1}".format(get_traceback(), E))
            errors += "{0}\n".format(E)
        if errors:
            self.log.error(red('{0} Errors during cleanup Method: {1}'.format(error_count,
                                                                              errors)))
            raise RuntimeError('{0} Errors during cleanup Method: {1}'.format(error_count,
                                                                              errors))
        else:
            self.log.debug('Clean method complete')

    def get_remote_file_size_via_http(self, url=None):
        url = url or self.url
        #Get the remote file size from the http header of the url given
        try:
            url = url.replace('http://','')
            host = url.split('/')[0]
            path = url.replace(host,'')
            self.log.debug("get_remote_file, host("+host+") path("+path+")")
            conn=httplib.HTTPConnection(host)
            conn.request("HEAD", path)
            res=conn.getresponse()
            image_bytes = int(res.getheader('content-length'))
            self.log.debug("content-length:"+str(self.image_bytes))
            conn.close()
        except Exception, e:
            self.log.debug("Failed to get remote file size...")
            raise e
        self.status('URL:' + str(url) + "\ncontent-length:" + str(image_bytes))
        return image_bytes


    def get_existing_test_snapshot_by_tag_key(self, tagkey):
        snapshots = self.user.ec2.get_snapshots(filters={'tag-key':str(tagkey)})
        for snapshot in snapshots:
            if 'md5' in snapshot.tags and 'md5len' in snapshot.tags:
                return snapshot
        return None

    def get_existing_test_volume_by_tag_key(self, tagkey):
        volumes = self.user.ec2.get_volumes(filters={'tag-key':str(tagkey)})
        for volume in volumes:
            if 'md5' in volume.tags and 'md5len' in volume.tags:
                return volume
        return None

    def get_existing_test_image_by_tag_key(self, tagkey):
        try:
            return self.user.ec2.get_emi(filters={'tag-key':str(tagkey)})
        except:
            return None



    def test0_setup_bfebs_instance_volume_and_snapshots_from_url(self, url=None,
                                                                 create_test_vol=True,
                                                                 time_per_gig=100):
        if self.args.use_previous:
            self.try_existing_resources_else_create_them()

        url = url or self.url
        volumes = []
        self.image_bytes = self.get_remote_file_size_via_http(url=url)
        self.image_gigs = int(math.ceil(float(self.image_bytes)/self.gig) or 1)
        curl_timeout= self.image_gigs * time_per_gig

        instance = self.current_test_instance
        #self.status('Attempting to launch helper instance...')
        #instance = self.user.ec2.run_image(self.emi,
        #                                      keypair=self.keypair.name,
        #                                      vmtype=self.args.vmtype,
        #                                      group=self.group.id,
        #                                      zone=self.zone)[0]
        #self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        #self.current_test_instance = instance

        #self.status('create test volume(s)...')
        #self.build_image_volume = self.user.ec2.create_volumes(self.zone, size = self.image_gigs,
        #                                                       monitor_to_state=None)[0]
        #self.user.ec2.create_tags(self.build_image_volume.id, {self.my_test_id: ''})
        #volumes.append(self.build_image_volume)
        #self.build_image_volume.add_tag(self.build_image_volume_tag_name)

        #if create_test_vol:
        #    self.base_test_volume = self.user.ec2.create_volumes(self.zone, size = 1,
        #                                                         monitor_to_state=None )[0]
        #    self.user.ec2.create_tags(self.base_test_volume.id, {self.my_test_id: ''})
        #    volumes.append(self.base_test_volume)
        #    self.base_test_volume.add_tag(self.base_test_volume_tag_name)
        #self.user.ec2.monitor_created_euvolumes_to_state(volumes=volumes)
        self.status("Copy the remote bfebs image into a volume and create snapshot from it...")
        instance.attach_volume(self.build_image_volume)
        instance.sys("curl "+url+" > "+ self.build_image_volume.guestdev+" && sync",
                     timeout=curl_timeout)
        instance.md5_attached_euvolume(self.build_image_volume)
        self._build_image_snapshot = self.user.ec2.create_snapshots(
            volume=self.build_image_volume)[0]
        self.user.ec2.create_tags(self.build_image_snapshot.id, {self.my_test_id: ''})
        #update test resources with tags...
        self.build_image_snapshot.add_tag(self.build_image_snapshot_tag_name)
        self.build_image_snapshot.add_tag('md5',self.build_image_volume.md5)
        self.build_image_snapshot.add_tag('md5len',self.build_image_volume.md5len)
        self.build_image_snapshot.add_tag('src_url', str(url))
        self.build_image_volume.add_tag('src_url', str(url))
        self.build_image_volume.add_tag('md5', self.build_image_volume.md5)
        self.build_image_volume.add_tag('md5len', self.build_image_volume.md5len)

        self.status('Done creating BFEBS build_image_snapshot and volume and md5ing volume')
        if create_test_vol:
            self.status('Attaching test volume, writing random data into it and gathering md5...')
            instance.attach_volume(self.base_test_volume)
            instance.vol_write_random_data_get_md5(self.base_test_volume, overwrite=True)
            self._base_test_snapshot = self.user.ec2.create_snapshots(
                volume=self.base_test_volume)[0]
            self.user.ec2.create_tags(self.base_test_snapshot.id, {self.my_test_id: ''})
            self.base_test_snapshot.add_tag(self.base_test_snapshot_tag_name)
            self.base_test_volume.add_tag('md5', self.base_test_volume.md5)
            self.base_test_volume.add_tag('md5len', self.base_test_volume.md5len)
            self.base_test_snapshot.add_tag('md5', self.base_test_volume.md5)
            self.base_test_snapshot.add_tag('md5len', self.base_test_volume.md5len)
        instance.terminate_and_verify()
        return self.build_image_snapshot

    def add_block_device_types_to_mapping(self,
                                        device_name,
                                        ephemeral_name=None,
                                        snapshot_id=None,
                                        size=None,
                                        no_device=False,
                                        delete_on_terminate=True,
                                        block_device_map=None):
        block_device_map = block_device_map or FixedBlockDeviceMapping()
        block_dev_type = BlockDeviceType()
        block_dev_type.delete_on_termination = delete_on_terminate
        block_dev_type.no_device = no_device
        block_dev_type.size = size

        if snapshot_id:
            if isinstance(snapshot_id, types.StringTypes):
                snapshot_id = snapshot_id
            else:
                snapshot_id = snapshot_id.id
            block_dev_type.snapshot_id = snapshot_id
        elif ephemeral_name:
            block_dev_type.ephemeral_name = ephemeral_name

        block_device_map[device_name] = block_dev_type
        return block_device_map

    def create_bfebs_image(self,
                           snapshot,
                           root_device_name = '/dev/sda',
                           name=None,
                           delete_on_terminate=True,
                           size=None,
                           block_device_map=None):
        if isinstance(snapshot, types.StringTypes):
            snapshot_id = snapshot
        else:
            snapshot_id = snapshot.id
        image_id = self.user.ec2.register_snapshot_by_id(snap_id=snapshot_id,
                                                        root_device_name=root_device_name,
                                                        size=size,
                                                        dot=delete_on_terminate,
                                                        name=name,
                                                        block_device_map=block_device_map
                                                        )
        self.user.ec2.create_tags(image_id, {self.my_test_id: ''})
        new_image = self.user.ec2.get_emi(emi=image_id)
        self.images.append(new_image)
        return new_image


    def populate_self_from_existing_test_resources(self,build_image=True, base_test=True):
        if build_image:
            self.build_image_snapshot = self.get_existing_test_snapshot_by_tag_key(
                tagkey=self.build_image_snapshot_tag_name)
            if self.build_image_snapshot:
                self.build_image_snapshot.eutest_volume_md5 = \
                    self.build_image_snapshot.tags.get('md5')
                self.build_image_snapshot.eutest_volume_md5len = \
                    int(self.build_image_snapshot.tags.get('md5len'))
            self.build_image_volume = self.get_existing_test_volume_by_tag_key(
                tagkey=self.build_image_volume_tag_name)
            if self.build_image_volume:
                self.build_image_volume.md5 = self.build_image_volume.tags.get('md5')
                self.build_image_volume.md5len = int(self.build_image_volume.tags.get('md5len'))
        if base_test:
            self.base_test_snapshot = self.get_existing_test_snapshot_by_tag_key(
                tagkey=self.base_test_snapshot_tag_name)
            if self.base_test_snapshot:
                self.base_test_snapshot.eutest_volume_md5 = self.base_test_snapshot.tags.get('md5')
                self.base_test_snapshot.eutest_volume_md5len = \
                    int(self.base_test_snapshot.tags.get('md5len'))
            self.base_test_volume = self.get_existing_test_volume_by_tag_key(
                self.base_test_volume_tag_name)
            if self.base_test_volume:
                self.base_test_volume.md5 = self.base_test_volume.tags.get('md5')
                self.base_test_volume.md5len = int(self.base_test_volume.tags.get('md5len'))
        self.test_image1 = self.get_existing_test_image_by_tag_key(self.test_image1_tag_name)
        self.test_image2 = self.get_existing_test_image_by_tag_key(self.test_image2_tag_name)
        self.test_image3 = self.get_existing_test_image_by_tag_key(self.test_image3_tag_name)
        self.test_image4 = self.get_existing_test_image_by_tag_key(self.test_image4_tag_name)


    def try_existing_resources_else_create_them(self, url=None):
        self.populate_self_from_existing_test_resources()
        if not self.build_image_snapshot or not self.base_test_snapshot:
            self.log.debug('\nPopulate instances from existing missing all or some of the '
                           'required resources:' +
                       '\nbuild_image_volume:' + str(self.build_image_volume) +
                       '\nbuild_image_snapshot(required):' + str(self.build_image_snapshot) +
                       '\nbase_test_snapshot(required):' + str(self.base_test_snapshot) +
                       '\nbase_test_volume:' + str(self.base_test_volume) + "\n")
            self.log.debug('Building missing resources now...')
            url = url or self.url
            if not url:
                raise Exception('URL to bfebs image is needed to build snapshot test resource')
            self.test0_setup_bfebs_instance_volume_and_snapshots_from_url(url=url)
        if not self.build_image_volume:
            self.build_test_volume = self.user.ec2.create_volume(zone=self.zone, snapshot=self.build_image_snapshot)
            self.user.ec2.create_tags(self.build_test_volume.id, {self.my_test_id: ''})
            self.build_image_volume.md5 = self.build_image_snapshot.md5=self.build_image_snapshot.eutest_volume_md5
            self.build_image_volume.md5len = self.build_image_snapshot.eutest_volume_md5len
            self.build_image_volume.add_tag('md5', self.build_image_volume.md5)
            self.build_image_volume.add_tag('md5len', self.build_image_volume.md5len)
        if not self.base_test_volume:
            self.status('Creating base_test_volume from base_test_snapshot: ')
            self.base_test_volume = self.user.ec2.create_volume(zone=self.zone, snapshot=self.base_test_snapshot)
            self.user.ec2.create_tags(self.base_test_volume.id, {self.my_test_id: ''})
            self.base_test_volume.md5 = self.base_test_snapshot.md5=self.build_image_snapshot.eutest_volume_md5
            self.base_test_volume.md5len = self.base_test_snapshot.eutest_volume_md5len
            self.base_test_volume.add_tag('md5', self.base_test_volume.md5)
            self.base_test_volume.add_tag('md5len', self.base_test_volume.md5len)

    def find_volume_on_euinstance(self, euinstance, map_device_name, md5=None, md5len=None, euvolume=None, ):
        '''
        Find block devices on guest by the MD5 sum of the volume(s) they were created from.
        Will attempt to find euvolumes on an instance 'if' the euvolume(s) have md5sums to use for
        comparison on the guest's dev dir.
        '''
        md5 = md5 or euvolume.md5
        md5len = md5len or euvolume.md5len
        return euinstance.get_guest_dev_for_block_device_map_device(md5=md5,md5len=md5len,map_device=map_device_name)

        #return euinstance.find_blockdev_by_md5(md5=euvolume.md5, md5len=euvolume.md5len)


    def test1_register_n_run_bfebs_image_w_dot_is_true(self):
        '''
        Will test running a default bfebs image. Additional tests here:
        -will verify a portion of the root device's md5sum against the original volume's/snapshot's
        -will verify delete on terminate set to True, will expect backing volume to be deleted
        -will attempt to verify volume states through stopping and restarting the instance
        -will attempt to verify instance meta data for the block device map in use
        -will look for 'no' ephemeral
        '''
        errmsg = ""
        if not self.build_image_snapshot:
            raise SkipTestException('Build Image Snapshot is None, check logs for related failures')
        image_name = self.test_image1_tag_name + "_" + str(self.build_image_snapshot.id)
        image = self.create_bfebs_image(snapshot=self.build_image_snapshot, name=image_name, delete_on_terminate=True)
        if not image.block_device_mapping.get(image.root_device_name).delete_on_termination:
            raise Exception('Expected DOT is True, instead image delete on termination set to:' +
                            str(image.block_device_mapping.get(image.root_device_name.delete_on_termination)))
        self.status('Created image:'+str(image.id)+', now running instance from it...')
        self.user.ec2.show_block_device_map(image.block_device_mapping)
        self.test_image1 = image
        self.test_image1.add_tag(self.test_image1_tag_name)
        instance = self.user.ec2.run_image(image=image, keypair=self.keypair, group=self.group)[0]
        self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        try:
            self.current_test_instance = instance
            self.status('Resulting in the instance block device map:')
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Checking instance devices for md5sums which match original volume/snapshots...')
            self.find_volume_on_euinstance(instance,
                                           instance.root_device_name,
                                           md5=self.build_image_snapshot.eutest_volume_md5,
                                           md5len=self.build_image_snapshot.eutest_volume_md5len)
            self.status('Checking instance for to make sure ephemeral is not present...')
            try:
                instance.get_ephemeral_dev()
            except:
                self.log.debug('Ephemeral was not found, passing...')
            else:
                raise Exception('Ephemeral device found, but none provided?')
            self.status('Check block device mapping meta data...')
            instance.check_instance_meta_data_for_block_device_mapping()
            self.status('Stopping instance:' + str(instance.id))
            instance.stop_instance_and_verify()
            self.status('Restarting instance:' + str(instance.id))
            instance.start_instance_and_verify(checkvolstatus=True)
            self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            instance.terminate_and_verify()
            if errmsg:
                raise Exception(errmsg)


    def test2_register_n_run_bfebs_image_w_dot_is_false(self):
        '''
        Will test running a default bfebs image. Additional tests here:
        -will verify a portion of the root device's md5sum against the original volume's/snapshot's
        -will verify delete on terminate set to True, will expect backing volume to remain and become available.
        -will look for 'no' ephemeral
        '''
        errmsg = ""
        if not self.build_image_snapshot:
            raise SkipTestException('Build Image Snapshot is None, check logs for related failures')
        image_name = self.test_image2_tag_name + "_" + str(self.build_image_snapshot.id)
        image = self.create_bfebs_image(snapshot=self.build_image_snapshot, name=image_name,
                                        delete_on_terminate=False)
        if image.block_device_mapping.get(image.root_device_name).delete_on_termination:
            raise Exception('Expected DOT is False, instead image delete on termination set to:' +
                            str(image.block_device_mapping.get(image.root_device_name.delete_on_termination)))
        self.status('Created image:'+str(image.id)+', now running instance from it...')
        self.user.ec2.show_block_device_map(image.block_device_mapping)
        self.test_image2 = image
        self.test_image2.add_tag(self.test_image2_tag_name)
        instance = self.user.ec2.run_image(image=image, keypair=self.keypair, group=self.group)[0]
        self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        try:
            self.current_test_instance = instance
            self.status('Resulting in the instance block device map:')
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Checking instance devices for md5sums which match original volume/snapshots...')
            self.find_volume_on_euinstance(instance,
                                           instance.root_device_name,
                                           md5=self.build_image_snapshot.eutest_volume_md5,
                                           md5len=self.build_image_snapshot.eutest_volume_md5len)
            self.status('Checking instance for to make sure ephemeral is not present...')
            try:
                instance.get_ephemeral_dev()
            except:
                self.log.debug('Ephemeral was not found, passing...')
            else:
                raise Exception('Ephemeral device found, but none provided?')
            self.status('Check block device mapping meta data...')
            instance.check_instance_meta_data_for_block_device_mapping()
            self.status('Stopping instance:' + str(instance.id))
            instance.stop_instance_and_verify()
            self.status('Restarting instance:' + str(instance.id))
            instance.start_instance_and_verify(checkvolstatus=True)
            self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            instance.terminate_and_verify()
            if errmsg:
                raise Exception(errmsg)


    def test3_register_n_run_bfebs_image_w_ephemeral_map_snap_map_and_ebsvol_map_dot_is_true(self):
        '''
        Will test running a default bfebs image registered w/ the following mapped devices, delete on terminate for
        all devices is true:
        1)the snapshot containing the original bfebs image
        2)the base test snapshot created by this testcase
        3)an empty volume
        Additional tests here:
        -will verify a portion of the root device's md5sum against the original volume's/snapshot's
        -will verify a portion of the test snapshot's md5sum against the guest's device
        -will verify the presence and size of the ephemeral disk
        -will attempt to verify the presence and size of empty volume's device (by process of elimination)
        -will attempt to verify the empty volume's requested size against the size of the block dev on guest
        -will attempt to verify volume states through stopping and restarting the instance
        -will attempt to verify instance meta data for the block device map in use
        -will verify delete on terminate set to True, and all volumes are deleted post instance termination
        '''
        errmsg = ""
        image_name = self.test_image3_tag_name + "_" + str(self.build_image_snapshot.id)
        bdm_emptyvol_dev = '/dev/vdd'
        bdm_snapshot_dev = '/dev/vdc'
        bdm_ephemeral_dev = '/dev/vdb'
        bdm_ephemeral_name = 'ephemeral0'
        bdm_emptyvol_size = 2

        if not self.build_image_snapshot:
            raise SkipTestException('Build Image Snapshot is None, check logs for related failures')
        if not self.base_test_snapshot:
            raise SkipTestException('Base Test Snapshot is None, check logs for related failures')

        self.status('Creating image with block device mapping...')
        bdm = self.add_block_device_types_to_mapping(snapshot_id=self.base_test_snapshot.id,
                                               device_name=bdm_snapshot_dev,
                                               delete_on_terminate=True)
        self.add_block_device_types_to_mapping(size = bdm_emptyvol_size,
                                               device_name = bdm_emptyvol_dev,
                                               delete_on_terminate=True,
                                               block_device_map=bdm)
        #add ephemeral dev separately to use later for bug work around...
        eph_dev = BlockDeviceType()
        eph_dev.device_name=bdm_ephemeral_dev
        eph_dev.ephemeral_name=bdm_ephemeral_name
        bdm[bdm_ephemeral_dev] = eph_dev
        self.user.ec2.show_block_device_map(bdm)
        image = self.create_bfebs_image(snapshot=self.build_image_snapshot,
                                        block_device_map=bdm,
                                        name=image_name,
                                        delete_on_terminate=True)
        self.user.ec2.show_block_device_map(image.block_device_mapping)
        self.test_image3 = image
        self.test_image3.add_tag(self.test_image3_tag_name)
        self.status('Created image:'+str(image.id)+', now running instance from it...')
        instance = self.user.ec2.run_image(image=image,keypair=self.keypair, group=self.group)[0]
        self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        try:
            self.current_test_instance = instance
            self.status('Resulting in the instance block device map:')
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Checking instance devices for md5sums which match original volume/snapshots.\nThis step will also' +
                         'record the volume id, md5 and guest device within the instance for later stop, start, and detach' +
                         'operations...')
            self.status('Getting guest device for root device...')
            guest_root_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.build_image_snapshot.eutest_volume_md5,
                                                                                md5len=self.build_image_snapshot.eutest_volume_md5len,
                                                                                map_device=instance.root_device_name)
            self.status('Getting guest device for snapshot device...')
            guest_snap_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.base_test_snapshot.eutest_volume_md5,
                                                                                md5len=self.base_test_snapshot.eutest_volume_md5len,
                                                                                map_device=bdm_snapshot_dev)
            self.status('Checking instance for ephemeral disk and size...')
            guest_ephemeral_dev = instance.check_ephemeral_against_vmtype()
            self.status("Ephemeral verified, Attempting to find guest's device empty volume by process of elimination...")
            remaining_devs=self.find_remaining_devices(instance,[guest_root_dev, guest_snap_dev, guest_ephemeral_dev])
            if len(remaining_devs) != 1:
                raise Exception('Could not find empty vol dev from remaining devs on guest:' + str(",").join(remaining_devs))
            guest_emptyvol_device = '/dev/' + str(remaining_devs[0]).replace('/dev/','')
            self.status('Found empty volume on guest device:'+ str(guest_emptyvol_device)+', checking for proper size...')
            vol_size = instance.get_blockdev_size_in_bytes(guest_emptyvol_device) / self.gig
            if vol_size != bdm_emptyvol_size:
                raise Exception('Block device size on guest:' + str(vol_size) +
                                ", does not match requested size:" + str(bdm_emptyvol_size))
            self.status('Found empty volume device on guest, writing random  data and storing md5 prior to stop/start tests...')
            empty_vol = self.user.ec2.get_volume(instance.block_device_mapping.get(bdm_emptyvol_dev).volume_id)
            empty_vol.guestdev = guest_emptyvol_device
            if not empty_vol in instance.attached_vols:
                instance.attached_vols.append(empty_vol)
            instance.vol_write_random_data_get_md5(empty_vol)
            self.status('Check block device mapping meta data...')
            #Temp work around for existing bug where ephemeral is not reported...
            meta_bdm = instance.block_device_mapping
            if not meta_bdm.has_key(bdm_ephemeral_dev):
                self.resulterr('Ephemeral disk not reported in instance block dev mapping: see euca-6048')
                meta_bdm[bdm_ephemeral_dev] = eph_dev
            instance.check_instance_meta_data_for_block_device_mapping(root_dev=image.root_device_name, bdm=meta_bdm)
            self.status('Stopping instance:' + str(instance.id))
            instance.stop_instance_and_verify()
            self.status('Restarting instance:' + str(instance.id))
            instance.start_instance_and_verify(checkvolstatus=True)
            self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            instance.terminate_and_verify()
            if errmsg:
                raise Exception(errmsg)

    def test4_register_n_run_bfebs_image_w_ephemeral_map_snap_map_and_ebsvol_map_dot_is_false(self):
        '''
        Will test running a default bfebs image registered w/ the following mapped devices, delete on terminate for
        all devices is False:
        1)the snapshot containing the original bfebs image
        2)the base test snapshot created by this testcase
        3)an empty volume
        Additional tests here:
        -will verify a portion of the root device's md5sum against the original volume's/snapshot's
        -will verify a portion of the test snapshot's md5sum against the guest's device
        -will verify the presence and size of the ephemeral disk
        -will attempt to verify the presence and size of empty volume's device (by process of elimination)
        -will attempt to verify the empty volume's requested size against the size of the block dev on guest
        -will attempt to verify volume states through stopping and restarting the instance
        -will attempt to verify instance meta data for the block device map in use
        -will verify delete on terminate set to False, and all volumes are not deleted post instance termination
        '''
        errmsg = ""
        image_name = self.test_image4_tag_name + "_" + str(self.build_image_snapshot.id)
        bdm_emptyvol_dev = '/dev/vdd'
        bdm_snapshot_dev = '/dev/vdc'
        bdm_ephemeral_dev = '/dev/vdb'
        bdm_ephemeral_name = 'ephemeral0'
        bdm_emptyvol_size = 2

        self.status('Creating image with block device mapping...')
        bdm = self.add_block_device_types_to_mapping(snapshot_id=self.base_test_snapshot.id,
                                               device_name=bdm_snapshot_dev,
                                               delete_on_terminate=False)
        self.add_block_device_types_to_mapping(device_name = bdm_emptyvol_dev,
                                               size = bdm_emptyvol_size,
                                               delete_on_terminate=False,
                                               block_device_map=bdm)
        #add ephemeral dev separately to use later for bug work around...
        eph_dev = BlockDeviceType()
        eph_dev.device_name=bdm_ephemeral_dev
        eph_dev.ephemeral_name=bdm_ephemeral_name
        bdm[bdm_ephemeral_dev] = eph_dev
        self.user.ec2.show_block_device_map(bdm)
        image = self.create_bfebs_image(snapshot=self.build_image_snapshot,
                                        block_device_map=bdm,
                                        name=image_name,
                                        delete_on_terminate=False)
        self.user.ec2.show_block_device_map(image.block_device_mapping)
        self.test_image4 = image
        self.test_image4.add_tag(self.test_image4_tag_name)
        self.status('Created image:'+str(image.id)+', now running instance from it...')
        instance = self.user.ec2.run_image(image=image, keypair=self.keypair, group=self.group)[0]
        self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        try:
            self.current_test_instance = instance
            self.status('Resulting in the instance block device map:')
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Checking instance devices for md5sums which match original volume/snapshots.\nThis step will also \
                         record the volume id, md5 and guest device within the instance for later stop, start, and detach \
                         operations...')
            guest_root_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.build_image_snapshot.eutest_volume_md5,
                                                                                md5len=self.build_image_snapshot.eutest_volume_md5len,
                                                                                map_device=instance.root_device_name)
            guest_snap_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.base_test_snapshot.eutest_volume_md5,
                                                                                md5len=self.base_test_snapshot.eutest_volume_md5len,
                                                                                map_device=bdm_snapshot_dev)
            self.status('Checking instance for ephemeral disk and size...')
            guest_ephemeral_dev = instance.check_ephemeral_against_vmtype()
            self.status("Attempting to find guest's device empty volume by process of elimination...")
            remaining_devs=self.find_remaining_devices(instance,[guest_root_dev, guest_snap_dev, guest_ephemeral_dev])
            if len(remaining_devs) != 1:
                raise Exception('Could not find empty vol dev from remaining devs on guest:' + str(",").join(remaining_devs))
            guest_emptyvol_device = '/dev/' + str(remaining_devs[0]).replace('/dev/','')
            self.status('Found empty volume on guest device:'+ str(guest_emptyvol_device)+', checking for proper size...')
            vol_size = instance.get_blockdev_size_in_bytes(guest_emptyvol_device) / self.gig
            if vol_size != bdm_emptyvol_size:
                raise Exception('Block device size on guest:' + str(vol_size) +
                                ", does not match requested size:" + str(bdm_emptyvol_size))
            self.status('Found empty volume device on guest, writing random  data and storing md5 prior to stop/start tests...')
            empty_vol = self.user.ec2.get_volume(instance.block_device_mapping.get(bdm_emptyvol_dev).volume_id)
            empty_vol.guestdev = guest_emptyvol_device
            if not empty_vol in instance.attached_vols:
                instance.attached_vols.append(empty_vol)
            instance.vol_write_random_data_get_md5(empty_vol)

            self.status('Check block device mapping meta data...')
            #Temp work around for existing bug where ephemeral is not reported...
            meta_bdm = instance.block_device_mapping
            if not meta_bdm.has_key(bdm_ephemeral_dev):
                self.resulterr('Ephemeral disk not reported in instance block dev mapping: see euca-6048')
                meta_bdm[bdm_ephemeral_dev] = eph_dev
            instance.check_instance_meta_data_for_block_device_mapping(root_dev=image.root_device_name, bdm=meta_bdm)
            self.status('Stopping instance:' + str(instance.id))
            instance.stop_instance_and_verify()
            self.status('Restarting instance:' + str(instance.id))
            instance.start_instance_and_verify(checkvolstatus=True)
            self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            instance.terminate_and_verify()
            if errmsg:
                raise Exception(errmsg)


    def test5_run_time_image1_overwrite_root_vol_size_and_set_dot_to_false(self):
        '''
        Will test running a default bfebs image registered w/ the following mapped devices, delete on terminate for
        all devices is False:
        1)the snapshot containing the original bfebs image

        At run time the following block device map attributes will be over written by:
        -root device size increased by 1g
        -delete on terminate flag set from True to False

        Additional tests here:
        -will verify a portion of the root device's md5sum against the original volume's/snapshot's
        -will verify that the guest's block dev representing the root dev is the new size provided
        -will verify an ephemeral disk is not provided
        -will attempt to verify volume states through stopping and restarting the instance
        -will attempt to verify instance meta data for the block device map in use
        -will verify delete on terminate set to False, and all volumes are not deleted post instance termination
        '''
        errmsg = ""
        image = self.test_image1
        #Add 1 to current root device size...
        bdm_rootsnap_size = image.block_device_mapping.get(image.root_device_name).size + 1
        #Get opposite of DOT value...
        dot_value = (not image.block_device_mapping.get(image.root_device_name).delete_on_termination)
        self.status('Using image:' +str(self.test_image1.id)+ ", root dev size set to:" +
                     str(bdm_rootsnap_size) + " and dot to false at run time...")
        self.status('Original Image block device map:')
        self.user.ec2.show_block_device_map(image.block_device_mapping)
        bdm = self.add_block_device_types_to_mapping(device_name=image.root_device_name,
                                                     size=bdm_rootsnap_size,
                                                     delete_on_terminate=dot_value)
        self.status('Applying the following block device map:')
        self.user.ec2.show_block_device_map(bdm)
        instance = self.user.ec2.run_image(image=image,block_device_map=bdm, keypair=self.keypair,
                                           group=self.group)[0]
        self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        try:
            self.current_test_instance = instance
            self.status('Resulting in the instance block device map:')
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Checking instance devices for md5sums which match original volume/snapshots.\nThis step will also \
                         record the volume id, md5 and guest device within the instance for later stop, start, and detach \
                         operations...')
            self.status('Checking device(s) size(s) on guest vs requested in bdm...')
            guest_root_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.build_image_snapshot.eutest_volume_md5,
                                                                                md5len=self.build_image_snapshot.eutest_volume_md5len,
                                                                                map_device=instance.root_device_name)
            self.status('Checking device(s) size(s) on guest vs requested in bdm...')
            root_dev_size = instance.get_blockdev_size_in_bytes(guest_root_dev) / self.gig
            if root_dev_size != bdm_rootsnap_size:
                raise Exception('Root device size on guest:' + str(root_dev_size) +
                                ' !=  requested size' + str(bdm_rootsnap_size) +
                                ", original size in image:" + str(image.block_device_mapping.get(image.root_device_name).size))
            self.status('Checking instance for to make sure ephemeral is not present...')
            try:
                instance.get_ephemeral_dev()
            except:
                self.log.debug('Ephemeral was not found, passing...')
            else:
                raise Exception('Ephemeral device found, but none provided?')
            self.status('Check block device mapping meta data...')
            instance.check_instance_meta_data_for_block_device_mapping(root_dev=image.root_device_name, bdm=bdm)
            self.status('Stopping instance:' + str(instance.id))
            instance.stop_instance_and_verify()
            self.status('Restarting instance:' + str(instance.id))
            instance.start_instance_and_verify(checkvolstatus=True)
            self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            instance.terminate_and_verify()
            if errmsg:
                raise Exception(errmsg)


    def test6_run_time_image1_add_ephemeral_map_snap_map_emptyvol_map_at_run_time_dot_true(self):
        '''
        Will test running a default bfebs image registered w/ the following mapped devices, delete on terminate for
        all devices is False:
        1)the snapshot containing the original bfebs image

        At run time the following block devices will be applied per map:
        1) Single ephemeral disk, size of vm type disk
        2) Single volume created from the local base_test_snapshot - size altered by +1 gig
        3) Single empty volume

        Additional tests here:
        -will verify a portion of the root device's md5sum against the original volume's/snapshot's
        -will verify a portion of the test snapshot's md5sum against the guest's device and size of disk
        -will verify the presence and size of the ephemeral disk
        -will attempt to verify the presence and size of empty volume's device (by process of elimination)
        -will attempt to verify the empty volume's requested size against the size of the block dev on guest
        -will attempt to verify volume states through stopping and restarting the instance
        -will attempt to verify instance meta data for the block device map in use
        -will verify delete on terminate set to True, and all volumes are deleted post instance termination
        '''
        errmsg = ""
        image = self.test_image1
        bdm_emptyvol_dev = '/dev/vdd'
        bdm_snapshot_dev = '/dev/vdc'
        bdm_ephemeral_dev = '/dev/vdb'
        bdm_ephemeral_name = 'ephemeral0'
        bdm_rootsnap_size = image.block_device_mapping.get(image.root_device_name).size
        bdm_emptyvol_size = 1
        bdm_snap_size = self.base_test_snapshot.volume_size + 1

        self.status('Using image:' +str(self.test_image1.id)+ ", ephemeral, and snapshot ebs devices added at run time..")
        self.status('Original Image block device map:')
        self.user.ec2.show_block_device_map(image.block_device_mapping)
        bdm = self.add_block_device_types_to_mapping(snapshot_id=self.base_test_snapshot.id,
                                               size = bdm_snap_size,
                                               device_name=bdm_snapshot_dev,
                                               delete_on_terminate=False)
        self.add_block_device_types_to_mapping(device_name = bdm_emptyvol_dev,
                                               size = bdm_emptyvol_size,
                                               delete_on_terminate=False,
                                               block_device_map=bdm)
        #add ephemeral dev separately to use later for bug work around...
        eph_dev = BlockDeviceType()
        eph_dev.device_name=bdm_ephemeral_dev
        eph_dev.ephemeral_name=bdm_ephemeral_name
        bdm[bdm_ephemeral_dev] = eph_dev
        self.status('Applying the following block device map:')
        self.user.ec2.show_block_device_map(bdm)
        instance = self.user.ec2.run_image(image=image,block_device_map=bdm, keypair=self.keypair,
                                           group=self.group)[0]
        self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        try:
            self.current_test_instance = instance
            self.status('Resulting in the instance block device map:')
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Checking instance for ephemeral disk and size...')
            guest_ephemeral_dev = instance.check_ephemeral_against_vmtype()
            self.status('Checking instance devices for md5sums which match original volume/snapshots.\nThis step will also \
                         record the volume id, md5 and guest device within the instance for later stop, start, and detach \
                         operations...')
            self.status('Checking device(s) size(s) on guest vs requested in bdm...')
            guest_root_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.build_image_snapshot.eutest_volume_md5,
                                                                                md5len=self.build_image_snapshot.eutest_volume_md5len,
                                                                                map_device=instance.root_device_name)
            root_dev_size = instance.get_blockdev_size_in_bytes(guest_root_dev) / self.gig
            if root_dev_size != bdm_rootsnap_size:
                raise Exception('Root device size on guest:' + str(root_dev_size) +
                                ' !=  requested size' + str(bdm_rootsnap_size) +
                                ", original size in image:" + str(image.block_device_mapping.get(image.root_device_name).size))

            #Volume from snapshot checks...
            guest_snap_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.base_test_snapshot.eutest_volume_md5,
                                                                                md5len=self.base_test_snapshot.eutest_volume_md5len,
                                                                                map_device=bdm_snapshot_dev)
            guest_snapvol_size = instance.get_blockdev_size_in_bytes(guest_snap_dev) / self.gig
            if guest_snapvol_size != bdm_snap_size:
                raise Exception('Volume size on guest:'+ str(guest_snapvol_size)+' != ' + str(bdm_snap_size) +
                                ', the size requested for bdm snap:' + str(self.base_test_snapshot.id))

            #Empty vol checks...
            self.status("Attempting to find guest's device empty volume by process of elimination...")
            remaining_devs=self.find_remaining_devices(instance,[guest_root_dev, guest_snap_dev, guest_ephemeral_dev])
            if len(remaining_devs) != 1:
                raise Exception('Could not find empty vol dev from remaining devs on guest:' + str(",").join(remaining_devs))
            guest_emptyvol_device = '/dev/' + str(remaining_devs[0]).replace('/dev/','')
            self.status('Found empty volume on guest device:'+ str(guest_emptyvol_device)+', checking for proper size...')
            vol_size = instance.get_blockdev_size_in_bytes(guest_emptyvol_device) / self.gig
            if vol_size != bdm_emptyvol_size:
                raise Exception('Block device size on guest:' + str(vol_size) +
                                ", does not match requested size:" + str(bdm_emptyvol_size))
            self.status('Found empty volume device on guest, writing random  data and storing md5 prior to stop/start tests...')
            empty_vol = self.user.ec2.get_volume(instance.block_device_mapping.get(bdm_emptyvol_dev).volume_id)
            empty_vol.guestdev = guest_emptyvol_device
            if not empty_vol in instance.attached_vols:
                instance.attached_vols.append(empty_vol)
            instance.vol_write_random_data_get_md5(empty_vol)

            self.status('Check block device mapping meta data...')
            #Temp work around for existing bug where ephemeral is not reported...
            meta_bdm = instance.block_device_mapping
            if not meta_bdm.has_key(bdm_ephemeral_dev):
                self.resulterr('Ephemeral disk not reported in instance block dev mapping: see euca-6048')
                meta_bdm[bdm_ephemeral_dev] = eph_dev
            instance.check_instance_meta_data_for_block_device_mapping(root_dev=image.root_device_name, bdm=meta_bdm)
            self.status('Stopping instance:' + str(instance.id))
            instance.stop_instance_and_verify()
            self.status('Restarting instance:' + str(instance.id))
            instance.start_instance_and_verify(checkvolstatus=True)
            self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            instance.terminate_and_verify()
            if errmsg:
                raise Exception(errmsg)

    def test7_run_time_image3_overwrite_all_non_root_w_no_device(self):
        errmsg = ""
        image = self.test_image3
        bdm_emptyvol_dev = '/dev/vdd'
        bdm_snapshot_dev = '/dev/vdc'
        bdm_ephemeral_dev = '/dev/vdb'
        self.status('Original Image block device map:')
        self.user.ec2.show_block_device_map(image.block_device_mapping)
        bdm = self.add_block_device_types_to_mapping(device_name=bdm_ephemeral_dev,
                                                     no_device=True)
        self.add_block_device_types_to_mapping(device_name=bdm_snapshot_dev,
                                               no_device=True,
                                               block_device_map=bdm)
        self.add_block_device_types_to_mapping(device_name = bdm_emptyvol_dev,
                                               no_device=True,
                                               block_device_map=bdm)
        self.status('Applying the following block device map:')
        self.user.ec2.show_block_device_map(bdm)
        instance = self.user.ec2.run_image(image=image,block_device_map=bdm, keypair=self.keypair,
                                           group=self.group)[0]
        self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        self.status('Resulting in the instance block device map:')
        self.user.ec2.show_block_device_map(instance.block_device_mapping)
        self.status('Checking instance, confirming lack of ephemeral disk...')
        try:
            instance.get_ephemeral_dev()
        except:
            self.log.debug('Ephemeral was not found, passing...')
        else:
            raise Exception('Ephemeral device found, but was over written with no_device?')
        guest_root_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.build_image_snapshot.eutest_volume_md5,
                                                                            md5len=self.build_image_snapshot.eutest_volume_md5len,
                                                                            map_device=instance.root_device_name)
        self.status('Checking for any non-root block devices...')
        remaining_devs = self.find_remaining_devices(instance=instance, known_dev_list=[guest_root_dev])
        if remaining_devs:
            raise Exception('Found additional unknown block devices on guest, expected all to be removed:' +
                            str(',').join(remaining_devs))
        self.status('Check block device mapping meta data...')
        instance.check_instance_meta_data_for_block_device_mapping()
        try:
            self.status('Stopping instance:' + str(instance.id))
            instance.stop_instance_and_verify()
            self.status('Restarting instance:' + str(instance.id))
            instance.start_instance_and_verify(checkvolstatus=True)
            self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            instance.terminate_and_verify()
            if errmsg:
                raise Exception(errmsg)

    def test8_run_time_image4_overwrite_misc_attributes_and_mixed_dot_at_run_time(self):
        errmsg = ""
        image = self.test_image4
        bdm_emptyvol_dev = '/dev/vdd'
        bdm_snapshot_dev = '/dev/vdc'
        bdm_ephemeral_dev = '/dev/vdb'
        bdm_emptyvol_size = image.block_device_mapping.get(bdm_emptyvol_dev).size + 1
        bdm_emptyvol_dot =  (not image.block_device_mapping.get(bdm_emptyvol_dev).delete_on_termination)
        bdm_snapshot_size = image.block_device_mapping.get(bdm_snapshot_dev).size + 1
        bdm_root_size = image.block_device_mapping.get(image.root_device_name).size + 1
        bdm_dot_value = (not image.block_device_mapping.get(image.root_device_name).delete_on_termination)
        self.status('Original Image block device map:')
        self.user.ec2.show_block_device_map(image.block_device_mapping)
        bdm = self.add_block_device_types_to_mapping(device_name=image.root_device_name,
                                                           size=bdm_root_size,
                                                           delete_on_terminate=bdm_dot_value)
        self.add_block_device_types_to_mapping(snapshot_id=self.base_test_snapshot.id,
                                               device_name=bdm_snapshot_dev,
                                               delete_on_terminate=False,
                                               size = bdm_snapshot_size,
                                               block_device_map=bdm)
        self.add_block_device_types_to_mapping(device_name = bdm_emptyvol_dev,
                                               size = bdm_emptyvol_size,
                                               delete_on_terminate=bdm_emptyvol_dot,
                                               block_device_map=bdm)
        self.status('Applying the following block device map:')
        self.user.ec2.show_block_device_map(bdm)
        instance = self.user.ec2.run_image(image=image,block_device_map=bdm, keypair=self.keypair,
                                           group=self.group)[0]
        self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        try:
            self.current_test_instance = instance
            self.status('Resulting in the instance block device map:')
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Checking instance for ephemeral disk and size...')
            guest_ephemeral_dev = instance.check_ephemeral_against_vmtype()

            self.status('Checking instance devices for md5sums which match original volume/snapshots.\nThis step will also \
                         record the volume id, md5 and guest device within the instance for later stop, start, and detach \
                         operations...')
            self.status('Checking device(s) size(s) on guest vs requested in bdm...')
            guest_root_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.build_image_snapshot.eutest_volume_md5,
                                                                                md5len=self.build_image_snapshot.eutest_volume_md5len,
                                                                                map_device=instance.root_device_name)
            guest_root_size = instance.get_blockdev_size_in_bytes(guest_root_dev) / self.gig
            if guest_root_size != bdm_root_size:
                raise Exception('Root volume size on guest:'+ str(guest_root_size)+', != ' + str(bdm_root_size) +
                                ' the size requested for root in bdm')

            guest_snap_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.base_test_snapshot.eutest_volume_md5,
                                                                                md5len=self.base_test_snapshot.eutest_volume_md5len,
                                                                                map_device=bdm_snapshot_dev)
            guest_snapvol_size = instance.get_blockdev_size_in_bytes(guest_snap_dev) / self.gig
            if guest_snapvol_size != bdm_snapshot_size:
                raise Exception('Volume size on guest:'+ str(guest_snapvol_size)+' != ' + str(bdm_snapshot_size) +
                                ', the size requested for bdm snap:' + str(self.base_test_snapshot.id))

            self.status("Attempting to find guest's device empty volume by process of elimination...")
            remaining_devs=self.find_remaining_devices(instance,[guest_root_dev, guest_snap_dev, guest_ephemeral_dev])
            if len(remaining_devs) != 1:
                raise Exception('Could not find empty vol dev from remaining devs on guest:' + str(",").join(remaining_devs))
            guest_emptyvol_device = '/dev/' + str(remaining_devs[0]).replace('/dev/','')
            self.status('Found empty volume on guest device:'+ str(guest_emptyvol_device)+', checking for proper size...')
            guest_emptyvol_size = instance.get_blockdev_size_in_bytes(guest_emptyvol_device) / self.gig
            if guest_emptyvol_size != bdm_emptyvol_size:
                raise Exception('Block device size on guest:' + str(guest_emptyvol_size) +
                                ", does not match requested size:" + str(bdm_emptyvol_size))
            self.status('Found empty volume device on guest, writing random  data and storing md5 prior to stop/start tests...')
            empty_vol = self.user.ec2.get_volume(instance.block_device_mapping.get(bdm_emptyvol_dev).volume_id)
            empty_vol.guestdev = guest_emptyvol_device
            if not empty_vol in instance.attached_vols:
                instance.attached_vols.append(empty_vol)
            instance.vol_write_random_data_get_md5(empty_vol)
            self.status('Check block device mapping meta data...')
            #Temp work around for existing bug where ephemeral is not reported...
            meta_bdm = instance.block_device_mapping
            if not meta_bdm.has_key(bdm_ephemeral_dev):
                self.resulterr('Ephemeral disk not reported in instance block dev mapping: see euca-6048')
                eph_dev = BlockDeviceType()
                eph_dev.device_name=bdm_ephemeral_dev
                eph_dev.ephemeral_name='ephemeral0'
                meta_bdm[bdm_ephemeral_dev] = eph_dev
            instance.check_instance_meta_data_for_block_device_mapping(root_dev=image.root_device_name, bdm=meta_bdm)

            self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            instance.terminate_and_verify()
            if errmsg:
                raise Exception(errmsg)


    def test9_run_time_image1_add_snap_map_attach_a_vol_to_running_instance(self):
        '''
        Will test running a default bfebs image registered w/ the following mapped devices, delete on terminate for
        all devices is False:
        1)the snapshot containing the original bfebs image

        At run time the following block devices will be applied per map:
        1) Single volume created from the local base_test_snapshot - size altered by +1 gig

        Post running:
        1) Attach the base_test_volume

        Additional tests here:
        -will verify attach, detach, reattach of single volume to instance in running state
        -will verify stop, start, terminate, etc of root vol, run time bdm vol, and volume attached during running state
        -will verify a portion of the root device's md5sum against the original volume's/snapshot's
        -will verify a portion of the test snapshot's md5sum against the guest's device and size of disk
        -will attempt to verify volume states through stopping and restarting the instance
        -will attempt to verify instance meta data for the block device map in use
        -will verify delete on terminate set to True, and all volumes are deleted post instance termination
        '''
        errmsg = ""
        image = self.test_image1
        bdm_emptyvol_dev = '/dev/vdd'
        bdm_snapshot_dev = '/dev/vdc'
        bdm_ephemeral_dev = '/dev/vdb'
        bdm_ephemeral_name = 'ephemeral0'
        bdm_root_size = image.block_device_mapping.get(image.root_device_name).size
        bdm_emptyvol_size = 1
        bdm_snap_size = self.base_test_snapshot.volume_size + 1


        self.status('Using image:' +str(self.test_image1.id)+ ", ephemeral, and snapshot ebs devices added at run time..")
        self.status('Original Image block device map:')
        self.user.ec2.show_block_device_map(image.block_device_mapping)
        bdm = self.add_block_device_types_to_mapping(snapshot_id=self.base_test_snapshot.id,
                                                     device_name=bdm_snapshot_dev,
                                                     size=bdm_snap_size,
                                                     delete_on_terminate=True)

        #add ephemeral dev separately to use later for bug work around...
        eph_dev = BlockDeviceType()
        eph_dev.device_name=bdm_ephemeral_dev
        eph_dev.ephemeral_name=bdm_ephemeral_name
        bdm[bdm_ephemeral_dev] = eph_dev
        self.status('Applying the following block device map:')
        self.user.ec2.show_block_device_map(bdm)
        instance = self.user.ec2.run_image(image=image,block_device_map=bdm, keypair=self.keypair,
                                           group=self.group)[0]
        self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        try:
            self.current_test_instance = instance
            self.status('Resulting in the instance block device map:')
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Checking instance for to make sure ephemeral is present...')
            instance.get_ephemeral_dev()

            self.status('Checking instance devices for md5sums which match original volume/snapshots.\nThis step will also \
                         record the volume id, md5 and guest device within the instance for later stop, start, and detach \
                         operations...')
            self.status('Getting guest dev for bdm root device...')
            guest_root_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.build_image_snapshot.eutest_volume_md5,
                                                                                md5len=self.build_image_snapshot.eutest_volume_md5len,
                                                                                map_device=instance.root_device_name)
            self.status('Checking guest root device size against bdm')
            guest_root_size = instance.get_blockdev_size_in_bytes(guest_root_dev) / self.gig
            if guest_root_size != bdm_root_size:
                raise Exception('Root volume size on guest:'+ str(guest_root_size)+', != ' + str(bdm_root_size) +
                                ' the size requested for root in bdm')
            self.status('Getting guest device for bdm base test snapshot...')
            guest_snap_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.base_test_snapshot.eutest_volume_md5,
                                                                                md5len=self.base_test_snapshot.eutest_volume_md5len,
                                                                                map_device=bdm_snapshot_dev)
            self.status('Checking size on guest for base test snapshot...')
            guest_snapvol_size = instance.get_blockdev_size_in_bytes(guest_snap_dev) / self.gig
            if guest_snapvol_size != bdm_snap_size:
                raise Exception('Volume size on guest:'+ str(guest_snapvol_size)+' != ' + str(bdm_snap_size) +
                                ', the size requested for bdm snap:' + str(self.base_test_snapshot.id))
            #Grab the current block device map before attaching any volumes, use this for meta data testing later.
            #Temp work around for existing bug where ephemeral is not reported...
            meta_bdm = instance.block_device_mapping
            if not meta_bdm.has_key(bdm_ephemeral_dev):
                self.resulterr('Ephemeral disk not reported in instance block dev mapping: see euca-6048')
                meta_bdm[bdm_ephemeral_dev] = eph_dev
            new_vol = self.user.ec2.create_volume(zone=self.zone,size=1, timepergig=180)
            self.user.ec2.create_tags(new_vol.id, {self.my_test_id: ''})
            self.status('Attaching new test volume to this running instance...')
            instance.attach_euvolume(new_vol, timeout=120, overwrite=False)
            self.status('Block dev map after attaching volume to running instance:')
            instance.update()
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Detaching the recently attached volume from instance...')
            instance.detach_euvolume(new_vol)
            self.status('Block dev map after detaching volume from instance...')
            instance.update()
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Attaching the same test volume to this running instance for remainder of test...')
            instance.attach_euvolume(new_vol, timeout=120, overwrite=True)
            self.status('Block dev map after re-attaching volume to running instance:')
            instance.update()
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Check block device mapping meta data...')
            instance.check_instance_meta_data_for_block_device_mapping(root_dev=image.root_device_name, bdm=meta_bdm)
            self.status('Stopping instance:' + str(instance.id))
            instance.stop_instance_and_verify()
            self.status('Restarting instance:' + str(instance.id))
            instance.start_instance_and_verify(checkvolstatus=True)
            self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            if instance:
                instance.terminate_and_verify()
            if errmsg:
                raise Exception(errmsg)


    def test10_misc_exceed_max_vol_size_storage_property_per_block_dev_map(self):
        '''
        Attempts to set the maxvolumesizeingb storage property to a value that will be exceeded by the size of the ebs
        volume(s) requested in the image block device mapping, as well as mapping provided at run time. This test
        will fail if this operation is permitted.
        '''
        errmsg = ""
        bdm_snapshot_dev = '/dev/vdc'
        bdm_snap_size = 6
        prop_name = "{0}.storage.maxvolumesizeingb".format(self.zone)
        maxprop = self.tc.sysadmin.get_property(prop_name)
        orig_maxsize = maxprop.value
        try:
            maxprop.modify_value(1)
            image = self.test_image1
            self.status('Using image:' +str(self.test_image1.id)+ ", ephemeral, and snapshot ebs devices added at run time..")
            self.status('Original Image block device map:')
            self.user.ec2.show_block_device_map(image.block_device_mapping)
            bdm = self.add_block_device_types_to_mapping(snapshot_id=self.base_test_snapshot.id,
                                                         device_name=bdm_snapshot_dev,
                                                         size=bdm_snap_size,
                                                         delete_on_terminate=True)
            self.status('Applying the following block device map:')
            self.user.ec2.show_block_device_map(bdm)
            try:
                instance = self.user.ec2.run_image(image=image,block_device_map=bdm,
                                                   keypair=self.keypair, group=self.group)[0]
                self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
                self.current_test_instance = instance
            except:
                self.status('Instance failed, did not exceed properties correctly. Passing')
            else:
                try:
                    instance.terminate_and_verify()
                except:pass
                raise Exception('Instance did not fail, storage property "maxvolumesizeingb" may have been exceeded')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            maxprop.modify_value(orig_maxsize)
            if errmsg:
                raise Exception(errmsg)

    def test11_misc_exceed_max_total_storage_property_per_block_dev_map(self):
        '''
        Attempts to set maxvolumesizeingb storage property to a value that is than exceeded per the ebs volumes
        requested in the block device mapping of the image and and run time. Test will fail if this operation is
        permitted
        '''
        errmsg = ""
        bdm_snapshot_dev = '/dev/vdc'
        bdm_snap_size = 6
        prop_name = "{0}.storage.maxtotalvolumesizeingb".format(self.zone)
        maxtotal_prop = self.tc.sysadmin.get_property(prop_name)
        orig_maxtotal = maxtotal_prop.value
        try:
            maxtotal_prop.modify_value(5)
            image = self.test_image1
            self.status('Using image:' +str(self.test_image1.id)+ ", ephemeral, and snapshot ebs devices added at run time..")
            self.status('Original Image block device map:')
            self.user.ec2.show_block_device_map(image.block_device_mapping)
            bdm = self.add_block_device_types_to_mapping(snapshot_id=self.base_test_snapshot.id,
                                                         device_name=bdm_snapshot_dev,
                                                         size=bdm_snap_size,
                                                         delete_on_terminate=True)
            self.status('Applying the following block device map:')
            self.user.ec2.show_block_device_map(bdm)
            try:
                instance = self.user.ec2.run_image(image=image,block_device_map=bdm,
                                                   keypair=self.keypair, group=self.group)[0]
                self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
                self.current_test_instance = instance
            except:
                self.status('Instance failed, did not exceed properties correctly. Passing')
            else:
                try:
                    instance.terminate_and_verify()
                except:pass
                raise Exception('Instance did not fail, storage property "maxtotalvolumesizeingb" may have been exceeded')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            maxtotal_prop.modify_value(orig_maxtotal)
            if errmsg:
                raise Exception(errmsg)

    def test12_misc_run_image1_check_attached_volume_states_during_stop_start(
            self, can_detach_block_dev_map=False):
        '''
        Attempts to run test bfebs image#1 and test the following:
        -Add an additional ebs block device in the map built from the base test snapshot
        -Verify the root device is present and in bdm and by checksum on the guest
        -Verify the root device's size specified in the bdm is also the size which appears on the running guest
        -Verify the additional ebs device is present and in bdm and by checksum on the guest
        -Verify the additional ebs device's size specified in the bdm is also the size which appears on the running guest
        -Verify instance meta data for block device mapping
        -Attach a volume while instance is in running state, verify device on guest
        -Stop the instance and verify the instance goes to stopped state correctly
        -While in the stopped state monitor all volumes attached to instance for 60 seconds to confirm correct state
        -Monitor instance for 60 seconds to verify it remains in correct stopped state
        -Attempt to detach volume while instance is in stopped state
        -Start instance and verify all volumes are attached, check guest for devices by checksum


        '''
        errmsg = ""
        image = self.test_image1
        instance = None
        bdm_snapshot_dev = '/dev/vdc'
        bdm_snap_size = self.base_test_snapshot.volume_size
        bdm_root_size = image.block_device_mapping.get(image.root_device_name).size
        try:
            self.status('Original Image block device map:')
            self.user.ec2.show_block_device_map(image.block_device_mapping)
            bdm = self.add_block_device_types_to_mapping(snapshot_id=self.base_test_snapshot.id,
                                                         device_name=bdm_snapshot_dev,
                                                         size=bdm_snap_size,
                                                         delete_on_terminate=True)
            self.status('Applying the following block device map:')
            self.user.ec2.show_block_device_map(bdm)
            self.status('Running instance with previously displayed block device mapping...')
            instance = self.user.ec2.run_image(image=image,
                                             block_device_map=bdm,
                                             keypair=self.keypair,
                                             password=self.instance_password,
                                             group=self.group)[0]
            self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
            self.current_test_instance = instance
            self.status('Instance now running. Resulting in the instance block device map:')
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Checking instance devices for md5sums which match original volume/snapshots.\nThis step will also \
                         record the volume id, md5 and guest device within the instance for later stop, start, and detach \
                         operations...')
            self.status('Getting guest device for block dev map root device...')
            guest_root_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.build_image_snapshot.eutest_volume_md5,
                                                                                md5len=self.build_image_snapshot.eutest_volume_md5len,
                                                                                map_device=instance.root_device_name)
            self.status('Checking device(s) size(s) on guest vs requested in bdm for root device ...')
            root_dev_size = instance.get_blockdev_size_in_bytes(guest_root_dev) / self.gig
            if root_dev_size != bdm_root_size:
                raise Exception('Root device size on guest:' + str(root_dev_size) +
                                ' !=  requested size' + str(bdm_root_size) +
                                ", original size in image:" + str(bdm_root_size))
            self.status('Getting guest device for block dev map, device using base test snapshot...')
            guest_snap_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.base_test_snapshot.eutest_volume_md5,
                                                                                md5len=self.base_test_snapshot.eutest_volume_md5len,
                                                                                map_device=bdm_snapshot_dev)
            self.status('Checking device(s) size(s) on guest vs requested in bdm for base test snapshot ...')
            guest_snapvol_size = instance.get_blockdev_size_in_bytes(guest_snap_dev) / self.gig
            if guest_snapvol_size != bdm_snap_size:
                raise Exception('Volume size on guest:'+ str(guest_snapvol_size)+' != ' + str(bdm_snap_size) +
                                ', the size requested for bdm snap:' + str(self.base_test_snapshot.id))
            #Get block device map before attaching volumes to use for meta data test later...
            meta_bdm = instance.block_device_mapping
            self.status('Attaching the base test volume to this running instance...')
            instance.attach_euvolume(self.base_test_volume, timeout=120, overwrite=False)
            self.status('Block dev map after attaching volume to running instance:')
            instance.update()
            self.status('Check block device mapping meta data...')
            instance.check_instance_meta_data_for_block_device_mapping(root_dev=image.root_device_name, bdm=meta_bdm)
            self.status('Stopping instance:' + str(instance.id))
            instance.stop_instance_and_verify()
            self.status('Monitor attached volumes for 1 minute make sure status remains in-use...')
            start = time.time()
            elapsed = 0
            errmsg = ''
            while elapsed < 60:
                elapsed = int(time.time()- start)
                for vol in instance.attached_vols:
                    vol.update()
                    if vol.status != 'in-use':
                        err = str(vol.id)+", state is not in-use while instance:" + str(instance.id) \
                                  + ' is stopped, elapsed:' +str(elapsed) + "\n"
                        self.log.debug(err)
                        errmsg += err
                    if instance.state != 'stopped':
                        err  = str(instance.id) + " instance state: " + str(instance.state) \
                                  + " no longer in stopped state, elapsed:" + str(elapsed) + "\n"
                        self.log.debug(err)
                        errmsg += err
                    self.user.ec2.show_volumes(instance.attached_vols)
                time.sleep(10)
            self.status('Attempt to detach volume which was attached after running instance while in stopped state...')
            instance.detach_euvolume(self.base_test_volume,timeout=180)
            try:
                self.status('Attempt to detach volume from block dev map...')

            except Exception, e:
                err = ('Could not detach bdm volume:' + str(self.base_test_volume.id)
                       + " from stopped instance:" + str(instance.id) + ", err:"+ str(e)) + '\n'
                if can_detach_block_dev_map:
                    errmsg += err
                else:
                    self.log.debug('WARNING' + err + "\n" +
                               'can_detach_block_dev_map not set, may not be supported in this release')

            self.status('Restarting instance:' + str(instance.id))
            instance.start_instance_and_verify(checkvolstatus=True)
            self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' +str(e)
            self.endfailure(errmsg)

        finally:
            if instance:
                instance.terminate_and_verify()
            if errmsg:
                raise Exception(errmsg)

    def test13_misc_run_image1_terminate_during_stopped_verify_volume_dot(self):
        '''
        Attempts to run an instance with it's:
        - root device DOT (delete on termination) flag set to True
        - add another volume in the BDM with the DOT flag set to False
        - verifies that the 2nd non-root volume is present on the guest
        - stops the guest
        - terminates the guest in the stop state
        - verifies the volume states match the DOT states. The root volume should be deleted, the 2nd should be available
        '''
        self.status('Running test image1 w/ dot flag set to true and BDM volume with DOT set to false...')
        image = self.test_image1
        bdm_snapshot_dev = '/dev/vdc'
        self.status('Original Image block device map:')
        self.user.ec2.show_block_device_map(image.block_device_mapping)
        bdm = self.add_block_device_types_to_mapping(snapshot_id=self.base_test_snapshot.id,
                                                     device_name=bdm_snapshot_dev,
                                                     delete_on_terminate=False)
        self.status('Applying the following block device map:')
        self.user.ec2.show_block_device_map(bdm)
        self.status('Running instance with previously displayed block device mapping...')
        instance = self.user.ec2.run_image(image=image,block_device_map=bdm,
                                           keypair=self.keypair, group=self.group)[0]
        self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
        self.current_test_instance = instance
        self.status('Checking instance for attached BDM volume created from base test snapshot')
        guest_snap_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.base_test_snapshot.eutest_volume_md5,
                                                                            md5len=self.base_test_snapshot.eutest_volume_md5len,
                                                                            map_device=bdm_snapshot_dev)
        self.status('Stopping instance...')
        instance.stop_instance_and_verify()
        self.status('Terminating instance and verifying correct volume states for both BDM volumes root + ' +
                    str(bdm_snapshot_dev))
        instance.terminate_and_verify()

    def test14_misc_run_image1_with_multiple_bdm_terminate_in_stopped_state(self, can_detach_block_dev_map=False):
        '''
        Attempts to run test bfebs image#1 and test the following:
        -Add an additional ebs block device in the map built from the base test snapshot
        -Verify the root device is present and in bdm and by checksum on the guest
        -Verify the root device's size specified in the bdm is also the size which appears on the running guest
        -Verify the additional ebs device is present and in bdm and by checksum on the guest
        -Verify the additional ebs device's size specified in the bdm is also the size which appears on the running guest
        -Verify instance meta data for block device mapping
        -Attach a volume while instance is in running state, verify device on guest
        -Stop the instance and verify the instance goes to stopped state correctly
        -While in the stopped terminate the instance
        -Verify all volumes enter their correct Delete On Terminate states

        '''
        errmsg = ""
        instance = None
        image = self.test_image1
        bdm_snapshot_dev = '/dev/vdc'
        bdm_snap_size = self.base_test_snapshot.volume_size
        bdm_root_size = image.block_device_mapping.get(image.root_device_name).size
        try:
            self.status('Original Image block device map:')
            self.user.ec2.show_block_device_map(image.block_device_mapping)
            bdm = self.add_block_device_types_to_mapping(snapshot_id=self.base_test_snapshot.id,
                                                         device_name=bdm_snapshot_dev,
                                                         size=bdm_snap_size,
                                                         delete_on_terminate=True)
            self.status('Applying the following block device map:')
            self.user.ec2.show_block_device_map(bdm)
            self.status('Running instance with previously displayed block device mapping...')
            instance = self.user.ec2.run_image(image=image,
                                             block_device_map=bdm,
                                             keypair=self.keypair,
                                             password=self.instance_password,
                                             group=self.group)[0]
            self.user.ec2.create_tags(instance.id, {self.my_test_id: ''})
            self.current_test_instance = instance
            self.status('Instance now running. Resulting in the instance block device map:')
            self.user.ec2.show_block_device_map(instance.block_device_mapping)
            self.status('Checking instance devices for md5sums which match original volume/snapshots.\nThis step will also \
                         record the volume id, md5 and guest device within the instance for later stop, start, and detach \
                         operations...')
            self.status('Getting guest device for block dev map root device...')
            guest_root_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.build_image_snapshot.eutest_volume_md5,
                                                                                md5len=self.build_image_snapshot.eutest_volume_md5len,
                                                                                map_device=instance.root_device_name)
            self.status('Checking device(s) size(s) on guest vs requested in bdm for root device ...')
            root_dev_size = instance.get_blockdev_size_in_bytes(guest_root_dev) / self.gig
            if root_dev_size != bdm_root_size:
                raise Exception('Root device size on guest:' + str(root_dev_size) +
                                ' !=  requested size' + str(bdm_root_size) +
                                ", original size in image:" + str(bdm_root_size))
            self.status('Getting guest device for block dev map, device using base test snapshot...')
            guest_snap_dev = instance.get_guest_dev_for_block_device_map_device(md5=self.base_test_snapshot.eutest_volume_md5,
                                                                                md5len=self.base_test_snapshot.eutest_volume_md5len,
                                                                                map_device=bdm_snapshot_dev)
            self.status('Checking device(s) size(s) on guest vs requested in bdm for base test snapshot ...')
            guest_snapvol_size = instance.get_blockdev_size_in_bytes(guest_snap_dev) / self.gig
            if guest_snapvol_size != bdm_snap_size:
                raise Exception('Volume size on guest:'+ str(guest_snapvol_size)+' != ' + str(bdm_snap_size) +
                                ', the size requested for bdm snap:' + str(self.base_test_snapshot.id))
                #Get block device map before attaching volumes to use for meta data test later...
            meta_bdm = instance.block_device_mapping
            self.status('Attaching the base test volume to this running instance...')
            instance.attach_euvolume(self.base_test_volume, timeout=120, overwrite=False)
            self.status('Block dev map after attaching volume to running instance:')
            instance.update()
            self.status('Check block device mapping meta data...')
            instance.check_instance_meta_data_for_block_device_mapping(root_dev=image.root_device_name, bdm=meta_bdm)
            self.status('Stopping instance:' + str(instance.id))
            instance.stop_instance_and_verify()
            self.status('Monitor attached volumes for 1 minute make sure status remains in-use...')
            start = time.time()
            elapsed = 0
            errmsg = ''
        except Exception, e:
            tb = get_traceback()
            errmsg = str(tb) + '\nTest Failed, err:' + str(e)
            self.endfailure(errmsg)

        finally:
            try:
                if instance:
                    self.status('Terminating instance, checking for delete on termination status for ebs block devs...')
                    instance.terminate_and_verify()
            except Exception, tv:
                tb = get_traceback()
                errmsg = errmsg + "\n" + str(tb) + "\nError during terminate and verify:" + str(tv)
            if errmsg:
                raise Exception(errmsg)

    def find_remaining_devices(self,instance,known_dev_list):
        self.log.debug('Looking for remaining devices after known devs:' +str(',').join(known_dev_list))
        dev_dir = instance.get_dev_dir()
        remove_devs = []
        for dev in dev_dir:
            dev_string = '/dev/' + str(dev).replace('/dev/','')
            for known_dev in known_dev_list:
                #Remove all disk partitions
                if dev_string.startswith(known_dev):
                    self.log.debug(str(dev)+': Eliminating known dev:' +str(dev_string)+ ' from possible remaining devices')
                    if not dev in remove_devs:
                        remove_devs.append(dev)
                    continue
        for dev in remove_devs:
            self.log.debug('Removing dev:'+str(dev))
            dev_dir.remove(dev)
        self.log.debug('Returning list of possible remaining/unknown devices:' + str(',').join(dev_dir))
        return dev_dir

if __name__ == "__main__":
    test = Block_Device_Mapping_Tests()
    result = test.run()
    exit(result)

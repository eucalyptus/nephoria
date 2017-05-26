#!/usr/bin/env python
import random

from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcontroller import TestController
import copy
import time


class LoadBfebsImage(CliTestRunner):

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['image_url'] = {'args': ['--image-url'],
                                      'kwargs': {'help': 'URL of the image',
                                                 'default': None}
                                      }
    def post_init(self):
        self.created_image = None

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
    def user(self):
        user = getattr(self, '__user', None)
        if not user:
            try:
                user = self.tc.get_user_by_name(aws_account_name=self.args.test_account,
                                                aws_user_name=self.args.test_user)
            except:
                user = self.tc.create_user_using_cloudadmin(aws_account_name=self.args.test_account,
                                                            aws_user_name=self.args.test_user)
            setattr(self, '__user', user)
        return user

    @property
    def emi(self):
        emi = getattr(self, '__emi', None)
        if not emi:
            if self.args.emi:
                emi = self.user.ec2.get_emi(emi=self.args.emi)
            else:
                try:
                    emi = self.user.ec2.get_emi()
                except:
                    pass
                if not emi:
                    emi = self.user.ec2.get_emi()
            setattr(self, '__emi', emi)
        return emi

    @emi.setter
    def emi(self, value):
        setattr(self, '__emi', value)

    @property
    def keypair_name(self):
        keyname = getattr(self, '__keypairname', None)
        if not keyname:
            keyname = "{0}_{1}".format(self.__class__.__name__, int(time.time()))
        return keyname

    @property
    def keypair(self):
        key = getattr(self, '__keypair', None)
        if not key:
            key = self.user.ec2.get_keypair(key_name=self.keypair_name)
            setattr(self, '__keypair', key)
        return key

    @property
    def group(self):
        group = getattr(self, '__group', None)
        if not group:
            group = self.user.ec2.add_group("{0}_group".format(self.__class__.__name__))
            self.user.ec2.authorize_group(group, port=22, protocol='tcp')
            self.user.ec2.authorize_group(group,  protocol='icmp', port=-1)
            self.user.ec2.show_security_group(group)
            setattr(self, '__group', group)
        return group

    @group.setter
    def group(self, value):
        setattr(self, '__group', value)

    def make_image_public(self, emi=None):
        emi = emi or self.created_image
        if emi and isinstance(emi, basestring):
            emi = self.user.ec2.get_emi(emi)
        emi.set_launch_permissions(group_names=['all'])
        self.log.info('\n---------------------------\n'
                      'MADE PUBLIC EMI: {0}'
                      '\n---------------------------'.format(emi))

    def test1_build_ebs_backed_image_in_vm(self):
        """
        Attempts to run the number of instances provided by the vm_count param
        """
        self.log.debug(type(self.args.image_url))
        if not self.args.image_url:
            raise Exception("No image url passed to run BFEBS tests")

        zone = self.args.zone
        zones = self.user.ec2.get_zone_names() or []
        if not zone:
            zone = zones[random.randint(0, len(zones) - 1)]
        else:
            if zone not in zones:
                raise ValueError('Requested Zone: {0} not found in available zones:"{1}"'
                                 .format(zone, ", ".join(zones)))
        instances = self.user.ec2.run_image(image=self.emi, keypair=self.keypair,
                                            zone=zone, group=self.group)
        for instance in instances:
            self.tc.test_resources['_instances'].append(instance)
            volume_1 = self.user.ec2.create_volume(zone=zone, size=3)
            self.tc.test_resources['_volumes'].append(volume_1)
            volume_device = instance.attach_volume(volume_1)
            instance.sys("curl " + self.args.image_url + " > " + volume_device, timeout=800, code=0)
            snapshot = self.user.ec2.create_snapshot(volume_1.id)
            self.created_image = self.user.ec2.register_snapshot(snapshot)
        self.user.ec2.terminate_instances(instances)

    def test2_make_image_public(self):
        """
        Attempts to make an image public.
        By default will use the image EMI created within the test.
        If an 'emi' ID was provided to the test it will instead use that image/EMI id.
        :return:
        """
        emi = self.created_image
        if not emi:
            raise SkipTestException('Skipping test. No EMI created or provided to make public')
        self.make_image_public(emi=emi)

    def test3_tag_image(self):
        emi = self.created_image
        if not emi:
            raise SkipTestException('Skipping test. No EMI created to make public')
        if not isinstance(emi, basestring):
            emi = emi.id
        self.user.ec2.create_tags([emi],
                                  {'Nephoria Test Image: {0}'.format(time.asctime()):'',
                                   'URL': self.args.image_url})

    def clean_method(self):
        if self.tc.test_resources['_instances']:
            instances = self.tc.test_resources['_instances']
            self.log.debug("***************")
            self.log.debug(self.tc.test_resources)
            self.log.debug(type(self.tc.test_resources['_instances']))
            self.log.debug("***************")
            self.tc.admin.ec2.terminate_instances(instances)
        if self.tc.test_resources['_volumes']:
            volumes = self.tc.test_resources['_volumes']
            for v in volumes:
                v.delete()


if __name__ == "__main__":
    test = LoadBfebsImage()
    result = test.run()
    exit(result)


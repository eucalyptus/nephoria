#!/usr/bin/env python
from nephoria.testcase_utils import wait_for_result
from nephoria.testcase_utils.cli_test_runner import CliTestRunner
from nephoria.testcontroller import TestController
import copy
import time


class InstanceMigration(CliTestRunner):

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

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
    def emi(self):
        emi = getattr(self, '__emi', None)
        if not emi:
            if self.args.emi:
                emi = self.tc.admin.ec2.get_emi(emi=self.args.emi)
            else:
                try:
                    emi = self.tc.admin.ec2.get_emi(location='cirros')
                except:
                    pass
                if not emi:
                    emi = self.tc.admin.ec2.get_emi()
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
            key = self.tc.admin.ec2.get_keypair(key_name=self.keypair_name)
            setattr(self, '__keypair', key)
        return key

    @property
    def group(self):
        group = getattr(self, '__group', None)
        if not group:
            group = self.tc.admin.ec2.add_group("{0}_group".format(self.__class__.__name__))
            self.tc.admin.ec2.authorize_group(group, port=22, protocol='tcp')
            self.tc.admin.ec2.authorize_group(group, protocol='icmp', port=-1)
            self.tc.admin.ec2.show_security_group(group)
            setattr(self, '__group', group)
        return group

    @group.setter
    def group(self, value):
        setattr(self, '__group', value)

    def helper_get_nc_for_instance(self, t_instance, zone):
        ret_node = None
        nodes = self.tc.sysadmin.get_all_node_controller_services(partition=zone.name)
        for node in nodes:
            for ins in node.instances:
                # Instance and Euinstance are not comparable
                if ins.id == t_instance.id:
                    return node
        return ret_node

    def test_instance_migration_basic(self, emi=None, volume=False):
        """
        Test Coverage:
            a) Runs an instance and migrates the instance using euserve-migrate-instances
            b) Verifies the instance is migrated to a new node and accessible
        """

        zones = self.tc.sysadmin.get_all_clusters()
        if not emi:
            emi = self.emi

        for zone in zones:
            if len(zone.node_controller_services) < 2:
                self.log.debug("Not enough Node Controllers found in cluster to continue instance migration testing.")
                continue
            euinstances = self.tc.admin.ec2.run_image(image=emi, keypair=self.keypair, group=self.group, zone=zone.name)
            self.tc.test_resources['_instances'].append(euinstances[0])
            test_instance = euinstances[0]

            volume_device = None
            if volume:
                euvol = self.tc.admin.ec2.create_volume(zone=zone.name)
                self.tc.test_resources['_volumes'].append(euvol)
                volume_device = test_instance.attach_euvolume(euvol)
            source_node = self.helper_get_nc_for_instance(test_instance, zone)
            try:
                self.tc.sysadmin.migrate_instances(instance_id=test_instance.id)
            except Exception, e:
                raise e

            def wait_for_new_nc():
                dest_node = self.helper_get_nc_for_instance(test_instance, zone)
                return source_node.hostname == dest_node.hostname

            wait_for_result(wait_for_new_nc, False, timeout=600, poll_wait=30)
            # TODO write a validate instance function
            self.tc.admin.ec2.monitor_euinstances_to_running(test_instance)

            if volume_device:
                test_instance.sys("ls " + volume_device, code=0)

    def test_instance_migration_with_volume(self):
        self.test_instance_migration_basic(volume=True)

    def test_ebs_backed_instance_migration(self):
        ebs_emi = self.tc.admin.ec2.get_emi(root_device_type="ebs")
        self.test_instance_migration_basic(emi=ebs_emi)

    def test_ebs_instance_migration_with_volume(self):
        ebs_emi = self.tc.admin.ec2.get_emi(root_device_type="ebs")
        self.test_instance_migration_basic(emi=ebs_emi, volume=True)

    def clean_method(self):
        # instances = getattr(self, 'instances', [])
        instances = self.tc.test_resources['_instances']
        volumes = self.tc.test_resources['_volumes']
        keypair = getattr(self, '__keypair', None)
        self.tc.admin.ec2.terminate_instances(instances)
        for v in volumes:
            v.delete()
        if keypair:
            self.tc.admin.ec2.delete_keypair(self.keypair)

if __name__ == "__main__":
    test = InstanceMigration()
    result = test.run()
    exit(result)




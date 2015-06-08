
import os
from prettytable import PrettyTable
import re
import stat
import time
import types
from xml.dom.minidom import parseString

from cloud_utils.net_utils.sshconnection import CommandExitCodeException, \
    CommandTimeoutException, SshCbReturn
from cloud_admin.hosts.helpers import EucaMachineHelpers
from cloud_utils.log_utils import get_traceback, markup


##################################################################################################
#               The Node Controller 'Machine' or 'Host' helper methods...                        #
##################################################################################################


class NodeControllerHelpers(EucaMachineHelpers):
    """
    Represents a machine hosting the node controller service.
    """
    @property
    def node_controller_service(self):
        for service in self.services:
            if service.type == 'node':
                return service
        return None

    def get_last_capacity_status(self):
        """
        Attempts to find and parse the last reported status line from nc.log
        Sample line:
        returning status=enabled cores=30/32 mem=7538/8050 disk=47/57
        """
        last = getattr(self, '__capacity_status', None)
        if last:
            if (time.time() - last.get('updated')) <= 5:
                return last
        ret = {"status": None,
               'updated': 0,
               'cores': None,
               'cores_total': None,
               'mem': None,
               'mem_total': None,
               'disk': None,
               'disk_total': None}
        if str(self.eucahost.eucalyptus_conf.LOGLEVEL).lower() not in ['debug', 'trace']:
            self.log.debug('Cant fetch capacity status from node with loglevel: DEBUG < "{0}"'
                           .format(self.eucahost.eucalyptus_conf.LOG_LEVEL))
            return ret
        euca_path = self.eucahost.get_eucalyptus_home() or ""
        nclog = os.path.join(euca_path, 'var/log/eucalyptus/nc.log')
        try:
            out = self.sys('tac {0} | grep -m1 "returning status="'.format(nclog), code=0,
                           listformat=False)
            if out:
                timestamp = re.search("^(\d+-\d+-\d+\s+\d+:\d+:\d+)\s", out)
                if timestamp:
                    ret['timestamp'] = timestamp.group(1)
                else:
                    ret['timestamp'] = 'unknown'
                for val in ['status', 'cores', 'mem', 'disk']:
                    search = "{0}=(\S+)".format(val)
                    grp = re.search(search, out)
                    if grp:
                        if val == 'status':
                            ret[val] = grp.group(1)
                        else:
                            cur, tot = grp.group(1).split('/')
                            ret[val] = int(cur)
                            ret[val + "_total"] = int(tot)
            ret['updated'] = time.time()
            setattr(self, '__capacity_status', ret)
        except CommandExitCodeException as CE:
            self.log.warn('{0}\nError fetching nc status:"{1}"'.format(get_traceback(), str(CE)))
        return ret

    def get_vm_availability(self):
        av = self.get_last_capacity_status()
        ret = []
        if not av:
            return ret
        for key, value in av.iteritems():
            if value is None:
                self.log.warn('Cant get vm availability due to None value: {0}={1}'
                              .format(key, value))
                return ret
        vm_types = self.eucahost.connection.ec2_connection.get_all_instance_types()
        for t in vm_types:

            disk_max = av.get('disk_total') / int(t.disk)
            mem_max = av.get('mem_total') / int(t.memory)
            cpu_max = av.get('cores_total') / int(t.cores)
            t.total = min(mem_max, disk_max, cpu_max)
            # Dont add vmtypes this node/host can never service...
            if not t.total:
                continue
            mem_cur = av.get('mem') / int(t.memory)
            disk_cur = av.get('disk') / int(t.disk)
            cpu_cur = av.get('cores') / int(t.cores)
            t.current = min([mem_cur, disk_cur, cpu_cur])
            ret.append(t)
        return ret

    def show_availability_for_node(self, printmethod=None, print_table=True):
        printmethod = printmethod or self.eucahost.log.info
        vmtypes = self.get_vm_availability()
        cap = self.get_last_capacity_status()
        main_pt = PrettyTable([markup('("{0}"\'s VM AVAILABILITY @ {1})')
                                   .format(self.eucahost.hostname, cap.get('timestamp'))])
        main_pt.border = 0
        main_pt.align = 'l'
        cpu_hdr = markup('CPU({0}/{1})'.format(cap.get('cores'), cap.get('cores_total')))
        mem_hdr = markup('MEM({0}/{1})'.format(cap.get('mem'), cap.get('mem_total')))
        disk_hdr = markup('DISK({0}/{1})'.format(cap.get('disk'), cap.get('disk_total')))
        vm_hdr = markup('VMTYPE')
        av_hdr = markup('AVAIL')
        pt = PrettyTable([vm_hdr, av_hdr, cpu_hdr, mem_hdr, disk_hdr])
        pt.align = 'l'
        pt.align[cpu_hdr] = 'c'
        pt.align[av_hdr] = 'c'
        pt.border = 1
        pt.vrules = 2
        pt.hrules = 0
        pt.padding_width = 0
        for t in vmtypes:
            pt.add_row([t.name, "{0} / {1}".format(t.current, t.total), t.cores, t.memory, t.disk])
        main_pt.add_row([pt])
        if print_table:
            printmethod("\n{0}\n".format(main_pt))
        else:
            return main_pt

    def get_hypervisor_from_euca_conf(self):
        """
            Attempts to find HYPERVISOR value in <eucalytpus home>/etc/eucalyptus.conf

            :return: string representing hypervisor type if found
            """
        return getattr(self.eucalyptus_conf, 'HYPERVISOR', None)

    def get_local_nc_service_state(self):
        service_state = None
        if self.ssh:
            try:
                if self.distro is not "vmware":
                    self.sys("service eucalyptus-nc status", code=0)
                    service_state = 'running'
                else:
                    # Todo add vmware service query here...
                    service_state = 'unknown'
            except CommandExitCodeException:
                service_state = 'not_running'
            except Exception, E:
                self.debug('Could not get service state from node:"{0}", err:"{1}"'
                           .format(self.hostname), str(E))
        else:
            self.critical("No ssh connection for node controller:'{0}'".format(self.hostname))
        self.service_state = service_state
        return service_state

    def get_virsh_list(self):
        """
        Return a dict of virsh list domains.
        dict should have dict['id'], dict['name'], dict['state']

        """
        instance_list = []
        if self.eucahost:
            keys = []
            output = self.eucahost.sys('virsh list', code=0)
            if len(output) > 1:
                keys = str(output[0]).strip().lower().split()
                for line in output[2:]:
                    line = line.strip()
                    if line == "":
                        continue
                    domain_line = line.split()
                    instance_list.append(
                        {keys[0]: domain_line[0],
                         keys[1]: domain_line[1],
                         keys[2]: domain_line[2]})
        return instance_list

    def tail_instance_console(self,
                              instance,
                              max_lines=None,
                              timeout=30,
                              idle_timeout=30,
                              print_method=None):
        '''


        '''
        if timeout < idle_timeout:
            idle_timeout = timeout
        if not isinstance(instance, types.StringTypes):
            instance = instance.id
        console_path = self.get_instance_console_path(instance)
        start_time = time.time()
        lines_read = 0
        print_method = print_method or self.debug
        prefix = str(instance) + " Console Output:"
        try:
            self.eucahost.cmd('tail -F ' + str(console_path),
                             verbose=False,
                             cb=self.remote_tail_monitor_cb,
                             cbargs=[instance,
                                     max_lines,
                                     lines_read,
                                     start_time,
                                     timeout,
                                     print_method,
                                     prefix,
                                     idle_timeout],
                             timeout=idle_timeout)
        except CommandTimeoutException, cte:
            self.debug('Idle timeout fired while tailing console: ' + str(cte))

    def remote_tail_monitor_cb(self,
                               buf,
                               instance_id,
                               max_lines,
                               lines_read,
                               start_time,
                               timeout,
                               print_method,
                               prefix,
                               idle_timeout):
        ret = SshCbReturn(stop=False, settimer=idle_timeout)
        return_buf = ""
        now = time.time()
        if (timeout and (now - start_time) >= timeout) or (max_lines and lines_read >= max_lines):
            ret.statuscode = 0
            ret.stop = True
        try:
            for line in str(buf).splitlines():
                lines_read += 1
                print_method(str(prefix) + str(line))
        except Exception, e:
            return_buf = "Error in remote_tail_monitor:" + str(e)
            ret.statuscode = 69
            ret.stop = True
        finally:
            ret.buf = return_buf
            ret.nextargs = [instance_id, max_lines, lines_read, start_time, timeout]
            return ret

    def get_instance_multipath_dev_info_for_instance_ebs_volume(self, instance, volume):
        if not isinstance(instance, types.StringTypes):
            instance = instance.id
        if isinstance(volume, types.StringTypes):
            volume = self.tester.get_volume(volume_id=volume)
        if volume.attach_data and volume.attach_data.instance_id == instance:
            dev = volume.attach_data.device
        else:
            raise Exception(str(volume.id) + 'Vol not attached to instance: ' + str(instance))
        return self.get_instance_multipath_dev_info_for_instance_block_dev(instance, dev)

    def get_instance_multipath_dev_info_for_instance_block_dev(self, instance, ebs_block_dev,
                                                               verbose=False):
        if not isinstance(instance, types.StringTypes):
            instance = instance.id
        mpath_dev = self.get_instance_multipath_dev_for_instance_block_dev(instance, ebs_block_dev)
        mpath_dev_info = self.eucahost.sys(
            'multipath -ll ' + str(mpath_dev) + " | sed 's/[[:cntrl:]]//g' ",
            verbose=verbose, code=0)
        return mpath_dev_info

    def get_instance_multipath_dev_for_instance_ebs_volume(self, instance, volume):
        if not isinstance(instance, types.StringTypes):
            instance = instance.id
        if isinstance(volume, types.StringTypes):
            volume = self.tester.get_volume(volume_id=volume)

    def get_instance_multipath_dev_for_instance_block_dev(self, instance, ebs_block_dev,
                                                          verbose=False):
        mpath_dev = None
        ebs_block_dev = os.path.basename(ebs_block_dev)
        if not isinstance(instance, types.StringTypes):
            instance = instance.id
        dm_dev = self.get_instance_block_disk_dev_on_node(instance, ebs_block_dev)
        sym_links = self.eucahost.sys('udevadm info --name ' + str(dm_dev) + ' --query symlink',
                                     verbose=verbose, code=0)[0]
        for path in str(sym_links).split():
            if str(path).startswith('mapper/'):
                mpath_dev = path.split('/')[1]
                break
        return mpath_dev

    def get_instance_block_disk_dev_on_node(self, instance, block_dev):
        block_dev = os.path.basename(block_dev)
        if not isinstance(instance, types.StringTypes):
            instance = instance.id
        paths = self.get_instance_block_disk_source_paths(instance)
        sym_link = paths[block_dev]
        real_dev = self.eucahost.sys('readlink -e ' + sym_link, verbose=False, code=0)[0]
        fs_stat = self.eucahost.get_file_stat(real_dev)
        if stat.S_ISBLK(fs_stat.st_mode):
            return real_dev
        else:
            raise (str(instance) + ", dev:" + str(
                block_dev) + ',Error, device on node is not block type :' + str(real_dev))

    def get_instance_block_disk_source_paths(self, instance, target_dev=None):
        '''
        Returns dict mapping target dev to source path dev/file on NC
        Example return dict: {'vdb':'/NodeDiskPath/dev/sde'}
        '''
        ret_dict = {}
        if target_dev:
            target_dev = os.path.basename(target_dev)
        if not isinstance(instance, types.StringTypes):
            instance = instance.id
        disk_doms = self.get_instance_block_disk_xml_dom_list(instance_id=instance)
        for disk in disk_doms:
            source_dev = disk.getElementsByTagName('source')[0].attributes.get('dev').nodeValue
            target_bus = disk.getElementsByTagName('target')[0].attributes.get('dev').nodeValue
            if not target_dev or target_dev == target_bus:
                ret_dict[target_bus] = str(source_dev)
        return ret_dict

    def get_instance_console_path(self, instance_id):
        if not isinstance(instance_id, types.StringTypes):
            instance = instance_id.id
        dev_dom = self.get_instance_device_xml_dom(instance_id=instance_id)
        console_dom = dev_dom.getElementsByTagName('console')[0]
        return console_dom.getElementsByTagName('source')[0].attributes.get('path').nodeValue

    def get_instance_device_xml_dom(self, instance_id):
        if not isinstance(instance_id, types.StringTypes):
            instance = instance_id.id
        dom = self.get_instance_xml_dom(instance_id)
        return dom.getElementsByTagName('devices')[0]

    def get_instance_block_disk_xml_dom_list(self, instance_id):
        if not isinstance(instance_id, types.StringTypes):
            instance = instance_id.id
        dev_dom = self.get_instance_xml_dom(instance_id)
        return dev_dom.getElementsByTagName('disk')

    def get_instance_xml_dom(self, instance_id):
        if not isinstance(instance_id, types.StringTypes):
            instance = instance_id.id
        output = self.get_instance_xml_text(instance_id)
        dom_xml = parseString(output)
        return dom_xml.getElementsByTagName('domain')[0]

    def get_instance_xml_text(self, instance_id):
        if not isinstance(instance_id, types.StringTypes):
            instance = instance_id.id
        return self.eucahost.sys('virsh dumpxml ' + str(instance_id), listformat=False,
                                verbose=False, code=0)

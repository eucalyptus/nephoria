
import copy
import logging
import os.path
import yaml
from cloud_admin.access.autocreds import AutoCreds
from cloud_admin.services.adminapi import AdminApi
from cloud_admin.hosts.eucahost import EucaHost
from cloud_utils.system_utils.machine import Machine
from cloud_utils.log_utils.eulogger import Eulogger


class SystemConnection(AdminApi):

    def __init__(self,
                 hostname,
                 username='root',
                 password=None,
                 keypath=None,
                 proxy_hostname=None,
                 proxy_username='root',
                 proxy_password=None,
                 proxy_keypath=None,
                 config_yml=None,
                 config_qa=None,
                 credpath=None,
                 aws_access_key=None,
                 aws_secret_key=None,
                 log_level='DEBUG',
                 boto_debug_level=0,
                 euca_user='admin',
                 euca_account='eucalyptus',
                 ):
        self.clc_connect_kwargs = {
            'hostname': hostname,
            'username': username,
            'password': password,
            'keypath': keypath,
            'proxy_hostname': proxy_hostname,
            'proxy_username': proxy_username,
            'proxy_password': proxy_password,
            'proxy_keypath': proxy_keypath
        }
        self._clc_machine = None
        self.hostname = hostname
        self.config_qa = config_qa
        self.config_yml = config_yml
        # self._aws_access_key = aws_access_key
        # self._aws_secret_key = aws_secret_key
        self._eucahosts = {}
        self._credpath = credpath
        self.log = Eulogger(identifier=self.__class__.__name__, stdout_level=log_level)
        self.creds = AutoCreds(credpath=self._credpath,
                                aws_access_key=aws_access_key,
                                aws_secret_key=aws_secret_key,
                                aws_account_name=euca_account,
                                aws_user_name=euca_user,
                                logger=self.log,
                                **self.clc_connect_kwargs)
        super(SystemConnection, self).__init__(hostname=hostname,
                                                aws_secret_key=self.creds.aws_secret_key,
                                                aws_access_key=self.creds.aws_access_key,
                                                logger=self.log,
                                                boto_debug_level=boto_debug_level)

    def set_loglevel(self, level, parent=False):
        """
        wrapper for log.setLevel, accept int or string.
        Levels can be found in logging class. At the time this was written they are:
        CRITICAL:50
        DEBUG:10
        ERROR:40
        FATAL:50
        INFO:20
        NOTSET:0
        WARN:30
        WARNING:30
        """
        level = level or logging.NOTSET
        if not isinstance(level, int) and not isinstance(level, basestring):
            raise ValueError('set_loglevel. Level must be of type int or string, got: "{0}/{1}"'
                             .format(level, type(level)))
        if isinstance(level, basestring):
            level = getattr(logging, str(level).upper())
        return self.log.set_parentloglevel(level)


    @property
    def clc_machine(self):
        if not self._clc_machine:
            if self.clc_connect_kwargs['hostname']:
                if self.eucahosts[self.clc_connect_kwargs['hostname']]:
                    self._clc_machine = self.eucahosts[self.clc_connect_kwargs['hostname']]
                else:
                    self._clc_machine = Machine(**self.clc_connect_kwargs)
                    self.eucahosts[self.clc_connect_kwargs['hostname']] = self._clc_machine
        return self._clc_machine

    @property
    def eucahosts(self):
        if not self._eucahosts:
            self._eucahosts = self._update_host_list()
        return self._eucahosts

    def _update_host_list(self):
        machines = self.get_all_machine_mappings()
        connect_kwargs = copy.copy(self.clc_connect_kwargs)
        if 'hostname' in connect_kwargs:
            connect_kwargs.pop('hostname')
        for ip, services in machines.iteritems():
            self._eucahosts[ip] = EucaHost(hostname=ip, services=services, **connect_kwargs)
        return self._eucahosts

    def get_hosts_by_service_type(self, servicetype):
        ret_list = []
        for ip, host in self.eucahosts.iteritems():
            for service in host.services:
                if service.type == servicetype:
                    ret_list.append(host)
        return ret_list

    def get_clc_host(self):
        clc = None
        clcs = self.get_hosts_by_service_type(servicetype='eucalyptus')
        if clcs:
            clc = clcs[0]
        return clc

    def get_node_hosts(self, partition=None, instanceid=None):
        ncs = self.get_hosts_by_service_type(servicetype='node')
        if not partition and not instanceid:
            return ncs
        retlist = []
        for nc in ncs:
            if instanceid:
                for instance in nc.instances:
                    if instance == instanceid:
                        return [nc]
            if nc.partition == partition:
                retlist.append(nc)
        return retlist

    def get_cluster_controller_hosts(self, partition=None):
        ccs = self.get_hosts_by_service_type(servicetype='cluster')
        if not partition:
            return ccs
        retlist = []
        for cc in ccs:
            if cc.partition == partition:
                retlist.append(cc)
        return retlist

    def get_storage_controller_hosts(self, partition=None):
        scs = self.get_hosts_by_service_type(servicetype='storage')
        if not partition:
            return scs
        retlist = []
        for sc in scs:
            if sc.partition == partition:
                retlist.append(sc)
        return retlist

    def get_cloud_summary_string(self):
        ret = ""
        for ip, host in self.eucahosts.iteritems():
            ret += "{0}\n".format(host.summary_string)
        return ret

    def build_machine_dict_from_config(cls):
        raise NotImplementedError()

    def build_machine_dict_from_cloud_services(self):
        raise NotImplementedError('not yet implemented')


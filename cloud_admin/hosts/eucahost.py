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

import inspect
import os
from prettytable import PrettyTable
import re
from cloud_utils.net_utils.sshconnection import CommandExitCodeException
from cloud_utils.system_utils.machine import Machine
from cloud_utils.log_utils import markup
from cloud_admin.hosts.eucalyptusconf import EucalyptusConf
from cloud_admin.hosts.helpers.helpernamespace import HelperNamespace


class EucaHost(Machine):

    def __init__(self, connection, hostname, services, helper_classes=None, **kwargs):
        self.connection=connection
        self._eucalyptus_repo_file = None
        self._eucalyptus_enterprise_repo_file = None
        self._euca2ools_repo_file = None
        self.euca_source = None
        self.components = {}
        services = services or []
        if not isinstance(services, list):
            services = [services]
        self.services = services
        kwargs['hostname'] = hostname
        super(EucaHost, self).__init__(**kwargs)
        self.helpers = HelperNamespace(self)

    def machine_setup(self):
        """
        Used as a callback for extending this class without super().__init__()
        """
        pass

    def show(self):
        return self.connection.show_hosts(hosts=self)

    @property
    def euca_service_codes(self):
        """
        A list of the abbreviations/codes any service has defined. ie: SC, CC, CLC, NC, etc..
        """
        ret = []
        for serv in self.services:
            if serv.service_code not in ret:
                ret.append(serv.service_code)
        return ret

    @property
    def _identifier(self):
        return str("{0}:({1})".format(self.hostname, self.euca_service_codes))

    @property
    def partitions(self):
        partitions = []
        for serv in self.services:
            if serv.type in ['node', 'cluster', 'storage']:
                if serv.partition not in partitions:
                    partitions.append(serv.partition)
        if not partitions:
            return 'euca'
        return ",".join(partitions)

    @property
    def summary_string(self):
        """
        A string representing the legacy format for representing a cloud host/machine:
        ie: "1.1.1.1 centos 6.6 x86_64 PARTI01 [CC SC]"
        """
        try:
            return "{0} {1} {2} {3} {4} {5}".format(
                self.hostname,
                self.distro,
                self.distro_ver,
                self.arch,
                self.partitions,
                '[{0}]'.format(" ".join(str(x) for x in self.euca_service_codes)))
        except Exception as E:
            return str(E)

    @property
    def eucalyptus_conf(self):
        """
        A Namespace representing the keys/values found in the eucalyptus.conf file found on
        this machine.
        """
        if not self._config:
            self._config = self.get_eucalyptus_conf()
        return self._config

    @eucalyptus_conf.setter
    def eucalyptus_conf(self, new_config):
        self._config = new_config

    @property
    def eucalyptus_repo_file(self):
        """
        RepoFile Namespace representing the key values repo info contained in a file where the
        baseurl matches the current url in use for the package name.
        """
        if not self._eucalyptus_repo_file:
            self._eucalyptus_repo_file = self.package_manager.get_repo_file_by_baseurl(
                url=self.get_eucalyptus_repo_url())
        return self._eucalyptus_repo_file

    @property
    def eucalyptus_enterprise_repo_file(self):
        """
        RepoFile Namespace representing the key values repo info contained in a file where the
        baseurl matches the current url in use for the package name.
        """
        if not self._eucalyptus_enterprise_repo_file:
            self._eucalyptus_enterprise_repo_file = self.package_manager.get_repo_file_by_baseurl(
                url=self.get_eucalyptus_enterprise_repo_url())
        return self._eucalyptus_enterprise_repo_file

    @property
    def euca2ools_repo_file(self):
        """
        RepoFile Namespace representing the key values repo info contained in a file where the
        baseurl matches the current url in use for the package name.
        """
        if not self._euca2ools_repo_file:
            self._euca2ools_repo_file = self.package_manager.get_repo_file_by_baseurl(
                url=self.get_euca2ools_repo_url())
        return self._euca2ools_repo_file

    def get_installed_eucalyptus_packages(self, searchstring='euca'):
        return self.package_manager.get_installed_packages(searchstring=searchstring)

    def get_available_eucalyptus_packages(self, searchstring='eucalyptus'):
        cmd = ('yum search eucalyptus -q  2> /dev/null | grep -e "{0}" | grep -iv error | '
               "awk '{print $1}'".format(searchstring))
        return self.sys(cmd, code=0)

    def get_eucalyptus_repo_url(self):
        """
        Attempts to return the url in use for this package
        """
        return self.package_manager.get_url_for_package('eucalyptus')

    def get_eucalyptus_enterprise_repo_url(self):
        """
        Attempts to return the url in use for this package
        """
        return self.package_manager.get_url_for_package('eucalyptus-enterprise')

    def get_euca2ools_repo_url(self):
        """
        Attempts to return the url in use for this package
        """
        return self.package_manager.get_url_for_package('euca2ools')

    def get_euca_process_summary(self):
        ret = {}
        for service in self.services:
            if service.type == 'cluster':
                ret['eucalytus-cc'] = self.get_pid_info(self.get_eucalyptus_cc_pid())
            elif service.type == 'node':
                ret['eucalyptus-nc'] = self.get_pid_info(self.get_eucalyptus_nc_pid())
            else:
                if not 'eucalyptus' in ret:
                    ret['eucalyptus'] = self.get_pid_info(self.get_eucalyptus_cloud_pid())
        eucanetd_pid = self.get_eucanetd_service_pid()
        if eucanetd_pid:
            ret['eucanetd'] = self.get_pid_info(eucanetd_pid)
        ret.update(self.helpers.midonet.get_midonet_process_summary())
        return ret

    def show_euca_process_summary(self, printmethod=None, print_table=True):
        printmethod = printmethod or self.log.info
        ps_sum = self.get_euca_process_summary()
        serv_hdr = markup('HOST SERVICE', [1, 4])
        pt = PrettyTable([serv_hdr,
                          markup('COMMAND', [1, 4]),
                          markup('%CPU', [1, 4]),
                          markup('%MEM', [1, 4]),
                          markup('PS_UPTIME', [1, 4])])
        pt.align = 'l'
        pt.align[serv_hdr] = 'r'
        pt.border = 0
        for service, command_dict in ps_sum.iteritems():
            pt.add_row([markup(service + ":", [1, 32]), "", "", "", ""])
            for command, info in command_dict.iteritems():
                pt.add_row(["  --->", command, info.get('%CPU', None),
                            info.get('%MEM', None), info.get('ELAPSED', None)])
        if print_table:
            printmethod("\n{0}\n".format(pt))
        else:
            return pt

    def get_eucanetd_service_pid(self):
        ret = None
        try:
            path = os.path.join(self.get_eucalyptus_home(), 'var/run/eucalyptus/eucanetd.pid')
            out = self.sys('cat {0}'.format(path), code=0)
        except CommandExitCodeException:
            return None
        else:
            for line in out:
                match = re.search('^\s*(\d+)\s*$', line)
                if match:
                    ret = int(match.group(1))
        return ret

    def get_eucalyptus_service_pid(self, eucalyptus_service):
        """
        Returns the process id or pid of the eucalyptus service running on this machine.
        Will return None if not found,
        which may indicate the process is not running or not intended to run on this machine.

        :param eucalyptus_service: eucalyptus-cloud, eucalyptus-cc, eucalyptus-nc
        :return: string representing pid
        """
        pid = None
        paths = ["/var/run/eucalyptus/", "/opt/eucalyptus/var/run/eucalyptus/"]
        for path in paths:
            try:
                pid = int(self.sys('cat ' + path + str(eucalyptus_service), code=0)[0].strip())
                break
            except (CommandExitCodeException, IndexError):
                pass
        if pid is None:
            self.log.debug("Pid not found at paths: ".join(paths))
        return pid

    def get_eucalyptus_cloud_pid(self):
        """
        :return: Returns the process id for eucalyptus-cloud running on this machine, or
        None if not found.
        """
        return self.get_eucalyptus_service_pid('eucalyptus-cloud.pid')

    def get_eucalyptus_nc_pid(self):
        """
        :return: Returns the process id for eucalyptus-nc running on this machine, or
        None if not found.
        """
        return self.get_eucalyptus_service_pid('eucalyptus-nc.pid')

    def get_eucalyptus_cc_pid(self):
        """
        :return: Returns the process id for eucalyptus-cc running on this machine, or
         None if not found.
        """
        return self.get_eucalyptus_service_pid('eucalyptus-cc.pid')

    def get_uptime(self):
        return int(self.sys('cat /proc/uptime', code=0)[0].split()[1].split('.')[0])

    def get_eucalyptus_cloud_process_uptime(self):
        """
        Attempts to look up the elapsed running time of the PID associated with the
         eucalyptus-cloud process/service.
        :return: (int) elapsed time in seconds this PID has been running
        """
        pid = self.get_eucalyptus_cloud_pid()
        return self.get_elapsed_seconds_since_pid_started(pid)

    def get_eucalyptus_cc_process_uptime(self):
        """
        Attempts to look up the elapsed running time of the PID associated with the
        eucalyptus-cc process/service.
        :return: (int) elapsed time in seconds this PID has been running
        """
        pid = self.get_eucalyptus_cc_pid()
        return self.get_elapsed_seconds_since_pid_started(pid)

    def get_eucalyptus_nc_process_uptime(self):
        """
        Attempts to look up the elapsed running time of the PID associated with the
        eucalyptus-nc process/service.
        :return: (int) elapsed time in seconds this PID has been running
        """
        pid = self.get_eucalyptus_nc_pid()
        return self.get_elapsed_seconds_since_pid_started(pid)

    def get_eucalyptus_cloud_is_running_status(self):
        """
        Checks eucalyptus-cloud service status
        :return: boolean, True if running False if not.
        """
        return self.get_service_is_running_status('eucalyptus-cloud')

    def get_eucalyptus_cc_is_running_status(self):
        """
        Checks eucalyptus-cc service status
        :return: boolean, True if running False if not.
        """
        return self.get_service_is_running_status('eucalyptus-cc')

    def get_eucalyptus_nc_is_running_status(self):
        """
        Checks eucalyptus-nc service status
        :return: boolean, True if running False if not.
        """
        return self.get_service_is_running_status('eucalyptus-nc')

    def get_eucalyptus_version(self, versionpath="/etc/eucalyptus/eucalyptus-version"):
        """
        :param versionpath: path to version file
        :return: eucalyptus version string
        """
        try:
            return self.sys('cat ' + versionpath, code=0)[0]
        except CommandExitCodeException:
            return self.sys('cat /opt/eucalyptus' + versionpath, code=0)[0]

    def get_euca2ools_version(self, brief=True):
        try:
            out = self.sys('euca-version', code=0)
            for line in out:
                if re.search("^euca2ools", line):
                    split = line.split()
                    if not brief:
                        return " ".join(split[1:])
                    return split[1]
        except CommandExitCodeException as CE:
            self.log.debug('Failed to fetch euca2ools version, err:"{0}"'.format(str(CE)))
        return None

    @staticmethod
    def _get_eucalyptus_home(machine):
        """
        A poor attempt to find the Eucalyptus installation path, ie: '/', or '/opt/eucalyptus'
        """
        out = machine.sys('env | grep EUCALYPTUS') or []
        for line in out:
            match = re.match("^EUCALYPTUS=(\S*)", line)
            if match:
                return match.group(1)
        if machine.is_dir('/opt/eucalyptus'):
            return '/opt/eucalyptus'
        out = machine.sys('ls /usr/sbin/ | grep eucalyptus')
        if out:
            return '/'
        if hasattr(machine, 'eucalyptus_conf') and machine.eucalyptus_conf.EUCALYPTUS:
            return machine.eucalyptus_conf.EUCALYPTUS
        return "/"

    def get_eucalyptus_home(self):
        """
        A poor attempt to find the Eucalyptus installation path, ie: '/', or '/opt/eucalyptus'
        """
        return self._get_eucalyptus_home(self)

    def get_eucalyptus_conf(self, eof=False, basepaths=None, verbose=False):
        """
        Attempts to read and return the eucalyptus.conf file on this machine into a
        Eucalyptusconf namespace obj.
        :param eof: bool, raise an exception on failure otherwise ignore and return None
        :param basepaths: list of strings representing the paths to look for 'eucalyptus.conf'
        :param verbose: log additional information
        :returns Eucalyptusconf obj or None
        """
        if basepaths is None:
            basepaths = ["/", "/opt/eucalyptus"]
        elif not isinstance(basepaths, list):
            basepaths = [basepaths]
        config = None
        out = None
        message = ""
        eucalyptus_conf = None
        for path in basepaths:
            try:
                eucalyptus_conf_path = os.path.join(str(path), '/etc/eucalyptus/eucalyptus.conf')
                out = self.sys('cat {0}'.format(eucalyptus_conf_path), code=0,
                               verbose=verbose)
                if verbose:
                    self.log.debug('Found eucalyptus.conf at path: "{0}"'
                                   .format(eucalyptus_conf_path))
                self.eucalyptus_conf_path = eucalyptus_conf_path
                break
            except CommandExitCodeException as CE:
                # File was not found, not readable, etc at this path
                message += str(CE) + "\n"
                pass
        if not out:
            paths_string = ", ".join(str(x) for x in basepaths)
            err = 'eucalyptus.conf not found on this system at paths:"{0}"\n{1}'\
                .format(paths_string, message)
            if eof:
                raise RuntimeError(err)
            else:
                self.log.debug(err)
        else:
            try:
                eucalyptus_conf = EucalyptusConf(lines=out)
                self.eucalyptus_conf = eucalyptus_conf
            except Exception, e:
                out = 'Error while trying to create EucalyptusConf():' + str(e)
                self.log.warn(out)
                if eof:
                    raise
        return eucalyptus_conf

    def __str__(self):
        return "{0}:{1}".format(self.__class__.__name__, self.hostname)

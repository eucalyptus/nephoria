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

from eutester.utils.file_utils.euconfig EuConfig
from eutester.utils.machine import Machine



class EucaHost(Machine):

    def machine_setup(self):
        self.euca_source = None
        self.components = {}

    @property
    def config(self):
        if not self._config:
            self._config = self.get_eucalyptus_conf()
        return self._config

    @config.setter
    def config(self, new_config):
        self._config = new_config

    @property
    def eucalyptus_conf(self):
        if hasattr(self.config, 'eucalyptus_conf'):
            return self.config.eucalyptus_conf
        return None

    def get_eucalyptus_service_pid(self, eucalyptus_service):
        """
        Returns the process id or pid of the eucalyptus service running on this machine. Will return None if not found,
        which may indicate the process is not running or not intended to run on this machine.

        :param eucalyptus_service: eucalyptus-cloud, eucalyptus-cc, eucalyptus-nc
        :return: string representing pid
        """
        pid = None
        paths = ["/var/run/eucalyptus/","/opt/eucalyptus/var/run/eucalyptus/"]
        for path in paths:
            try:
                pid = int(self.sys('cat ' + path + str(eucalyptus_service), code=0)[0].strip())
                break
            except: pass
        if pid is None:
            self.debug("Pid not found at paths: ".join(paths))
        return pid

    def get_eucalyptus_cloud_pid(self):
        """
        :return: Returns the process id for eucalyptus-cloud running on this machine, or None if not found.
        """
        return self.get_eucalyptus_service_pid('eucalyptus-cloud.pid')

    def get_eucalyptus_nc_pid(self):
        """
        :return: Returns the process id for eucalyptus-nc running on this machine, or None if not found.
        """
        return self.get_eucalyptus_service_pid('eucalyptus-nc.pid')

    def get_eucalyptus_cc_pid(self):
        """
        :return: Returns the process id for eucalyptus-cc running on this machine, or None if not found.
        """
        return self.get_eucalyptus_service_pid('eucalyptus-cc.pid')

    def get_uptime(self):
        return int(self.sys('cat /proc/uptime', code=0)[0].split()[1].split('.')[0])

    def get_eucalyptus_cloud_process_uptime(self):
        """
        Attempts to look up the elapsed running time of the PID associated with the eucalyptus-cloud process/service.
        :return: (int) elapsed time in seconds this PID has been running
        """
        pid = self.get_eucalyptus_cloud_pid()
        return self.get_elapsed_seconds_since_pid_started(pid)

    def get_eucalyptus_cc_process_uptime(self):
        """
        Attempts to look up the elapsed running time of the PID associated with the eucalyptus-cc process/service.
        :return: (int) elapsed time in seconds this PID has been running
        """
        pid = self.get_eucalyptus_cc_pid()
        return self.get_elapsed_seconds_since_pid_started(pid)

    def get_eucalyptus_nc_process_uptime(self):
        """
        Attempts to look up the elapsed running time of the PID associated with the eucalyptus-nc process/service.
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

    def get_eucalyptus_version(self,versionpath="/etc/eucalyptus/eucalyptus-version"):
        """

        :param versionpath: path to version file
        :return: eucalyptus version string
        """
        try:
            return self.sys('cat ' + versionpath, code=0)[0]
        except Exception, e:
            return self.sys('cat /opt/eucalyptus' + versionpath, code=0)[0]

    def get_eucalyptus_conf(self,eof=False, basepaths=[ "/" , "/opt/eucalyptus" ], verbose=False):
        out = None
        config = None
        use_path = None
        for path in basepaths:
            try:
                self.sys('ls '+ str(path) + '/etc/eucalyptus/eucalyptus.conf', code=0,
                         verbose=verbose)
                use_path = path + '/etc/eucalyptus/eucalyptus.conf'
                break
            except:
                pass
        if not use_path:
            out = 'eucalyptus.conf not found on this system'
            if eof:
                raise Exception(out)
            else:
                self.debug(out)
        else:
            try:
                config = EuConfig(filename=use_path, ssh=self.ssh,
                                  default_section_name='eucalyptus_conf')
            except Exception, e:
                out = 'Error while trying to create euconfig from eucalyptus_conf:' + str(e)
                if eof:
                    raise Exception(out)
                else:
                    self.debug(out)
        return config


    def __str__(self):
        s  = "+++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
        s += "+" + "Hostname:" + str(self.hostname) + "\n"
        s += "+" + "Distro: " + str(self.distro) +"\n"
        s += "+" + "Distro Version: " +  str(self.distro_ver) +"\n"
        s += "+" + "Components: " +   str(self.components) +"\n"
        s += "+++++++++++++++++++++++++++++++++++++++++++++++++++++"
        return s


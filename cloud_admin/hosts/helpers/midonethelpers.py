
import re
from cloud_admin.hosts.helpers import EucaMachineHelpers
from cloud_utils.net_utils.sshconnection import CommandExitCodeException
from cloud_utils.log_utils import get_traceback


class MidonetHelpers(EucaMachineHelpers):
    _mid_get_connection = None

    """
    Helper methods for machines hosting Midonet Services.
    """

    def get_pid_info(self, pid):
        return self.eucahost.get_pid_info(pid=pid)

    def get_midonet_process_summary(self, force_mido=False, force_zoo=False, force_cass=False,
                                    force_tom=False):
        """
        Returns a

        """
        ret = {}
        mido_pid = self.get_midolman_service_pid()
        zookeeper_pid = self.get_zookeeper_pid()
        cassandra_pid = self.get_cassandra_pid()
        tomcat_pid = self.get_tomcat_pid()
        if mido_pid or force_mido:
            ret['midolman'] = self.get_pid_info(mido_pid)
        if zookeeper_pid or force_zoo:
            ret['zookeeper'] = self.get_pid_info(zookeeper_pid)
        if cassandra_pid or force_cass:
            ret['cassandra'] = self.get_pid_info(cassandra_pid)
        if tomcat_pid or force_tom:
            ret['tomcat'] = self.get_pid_info(tomcat_pid)
        return ret

    def get_midolman_service_pid(self):
        ret = None
        try:
            out = self.sys('status midolman', code=0)
        except CommandExitCodeException:
            return None
        else:
            for line in out:
                match = re.search('^\s*midolman*.*process\s+(\d+)\s*$', line)
                if match:
                    ret = int(match.group(1))
        return ret

    def get_cassandra_pid(self):
        try:
            out = self.sys('cat /var/run/cassandra/cassandra.pid', code=0)
            if out:
                match = re.match("^(\d+)$", out[0])
                if match:
                    return int(match.group(1))
        except CommandExitCodeException:
            return None

    def get_zookeeper_pid(self):
        for path in ['/var/lib/zookeeper/data/zookeeper_server.pid',
                     '/var/run/zookeeper/zookeeper*.pid']:
            try:
                out = self.sys("cat {0}".format(path), code=0)
                if out:
                    match = re.match("^(\d+)$", out[0])
                    if match:
                        return int(match.group(1))
            except CommandExitCodeException:
                pass
        return None

    def get_tomcat_pid(self):
        try:
            out = self.sys('cat /var/run/tomcat.pid', code=0)
            if out:
                match = re.match("^(\d+)$", out[0])
                if match:
                    return int(match.group(1))
        except CommandExitCodeException:
            return None

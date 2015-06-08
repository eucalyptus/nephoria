

import select
import threading
import time
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import get_traceback
from cloud_utils.log_utils import printinfo, markup
from cloud_utils.file_utils import render_file_template
from cloud_utils.net_utils.sshconnection import (
    CommandExitCodeException,
    SshCbReturn,
    SshConnection
)
import re
import os
from prettytable import PrettyTable
import sys
import tempfile
from repoutils import Yum, Apt


class Machine(object):

    def __init__(self,
                 hostname,
                 username="root",
                 password=None,
                 keypath=None,
                 proxy_hostname=None,
                 proxy_username='root',
                 proxy_password=None,
                 proxy_keypath=None,
                 do_ssh_connect=True,
                 distro=None,
                 distro_ver=None,
                 arch=None,
                 timeout=120,
                 ssh_retry=2,
                 logger=None,
                 verbose=True):
        """
        A basic (primarily Linux) Machine interface. This interface is intended to provide a
        base set of utilities for working with a Linux machine in a Cloud system environment.
        The class is intended to be built upon adding more pointed utlities for VMs,
        Cloud components, etc..
        By default init() will attempt to create an sshconnection using the parameters provided.
        The primary method for interacting with the ssh session will be the machine.sys() method.
        Most utiltiy methods within this class are wrapping the sys() method and issuing common
        linux commands on the remote machine.

        :param hostname: The hostname or IP of the machine
        :param username: The ssh username used to for ssh login
        :param password: The password associate with 'username'
        :param keypath:  The path to an ssh key to be used, (defaults to the usual local key dirs)
        :param proxy_hostname: (optional) A ssh proxy hostname or ip
        :param proxy_username: (optional) Proxy username for ssh login
        :param proxy_password: (optional) Proxy password associated with proxy username
        :param proxy_keypath: (optional) ssh key path, otherwise will try the default ssh dir(s)
        :param do_ssh_connect: (optional) bool, if True will attempt an ssh connection.
        :param distro: (optional), string for distro name, otherwise will try to find it
        :param distro_ver: (optional) string for distro version, otherwise will try to find it
        :param arch: (optional) string for arch type, otherwise will try to find it
        :param timeout: (optional) time in seconds to allow for ssh connection to complete
        :param ssh_retry: (optional) int, number of ssh connection attempts
        :param debugmethod: (optional) A method used for writing debug information
        :param verbose: bool option to enable/disable some verbose logging
        """
        self._arch = arch
        self._ssh = None
        self._sftp = None
        self._distroname = distro
        self._distrover = distro_ver
        self._repo_utils = None
        self._package_manager = None
        self._config = None
        self._free_stats = {}
        self._cpu_stats = {}
        self._sys_stats_interval = 5
        self.hostname = hostname
        self.arch = arch
        self._do_ssh_connect = do_ssh_connect
        self.username = username
        self.password = password
        self.verbose = verbose
        if logger is None:
            logger = Eulogger(identifier=self._identifier)
        self.log = logger
        self.ssh_connect_kwargs = {'host': self.hostname,
                                   'username': self.username,
                                   'password': self.password,
                                   'keypath': keypath,
                                   'proxy': proxy_hostname,
                                   'proxy_username': proxy_username,
                                   'proxy_password': proxy_password,
                                   'proxy_keypath': proxy_keypath,
                                   'timeout': timeout,
                                   'retry': ssh_retry,
                                   'debugmethod': self.log.debug,
                                   'verbose': self.verbose
                                   }
        self.log_threads = {}
        self.log_buffers = {}
        self.log_active = {}
        self.wget_last_status = 0
        self.machine_setup()

    def machine_setup(self):
        # For custom implementations
        pass

    def __repr__(self):
        return "{0}:{1}".format(self.__class__.__name__, self.hostname)

    @property
    def _identifier(self):
        return str(self.hostname or self.__class__)

    #############################################################################################
    #                       Debug Utilities                                                     #
    #############################################################################################

    def debug(self, msg):
        """
        Note: Should use self.log.debug instead.
        Used to print debug, defaults to print() but over ridden by self.debugmethod if not None
        msg - mandatory -string, message to be printed
        """
        if self.verbose is True:
            self.log.debug(msg)

    def poll_log(self, log_file="/var/log/messages"):
        self.log.debug("Starting to poll " + log_file)
        self.log_channel = self.ssh.connection.invoke_shell()
        self.log_channel.send("tail -f " + log_file + " \n")
        # Begin polling channel for any new data
        while self.log_active[log_file]:
            # CLOUD LOG
            rl, wl, xl = select.select([self.log_channel], [], [], 0.0)
            if len(rl) > 0:
                self.log_buffers[log_file] += self.log_channel.recv(1024)
            time.sleep(1)

    def start_log(self, log_file="/var/log/messages"):
        """Start thread to poll logs"""
        thread = threading.Thread(target=self.poll_log, args=log_file)
        thread.daemon = True
        self.log_threads[log_file] = thread.start()
        self.log_active[log_file] = True

    def stop_log(self, log_file="/var/log/messages"):
        """Terminate thread that is polling logs"""
        self.log_active[log_file] = False

    def save_log(self, log_file, path="logs"):
        """Save log buffer for log_file to the path to a file"""
        if not os.path.exists(path):
            os.mkdir(path)
        FILE = open(path + '/' + log_file, "w")
        FILE.writelines(self.log_buffers[log_file])
        FILE.close()

    def save_all_logs(self, path="logs"):
        """Save log buffers to a file"""
        for log_file in self.log_buffers.keys():
            self.save_log(log_file, path)

    def dump_netfail_info(self,ip=None, mac=None, pass1=None, pass2=None, showpass=True,
                          taillength=50, net_namespace=None):
        """
        Debug method to provide potentially helpful info from current machine when debugging connectivity issues.
        """
        self.debug('Attempting to dump network information, args: ip:' + str(ip)
                   + ' mac:' + str(mac)
                   + ' pass1:' + self.get_masked_pass(pass1,show=True)
                   + ' pass2:' + self.get_masked_pass(pass2,show=True))
        self.ping_cmd(ip,verbose=True, net_namespace=net_namespace,count=1)
        ns_list = self.sys('ip netns list')
        if net_namespace in ns_list:
            self.sys('arp -a', net_namespace=net_namespace)
            self.sys('ifconfig', net_namespace=net_namespace)
            self.sys('netstat -rn', net_namespace=net_namespace)
        self.sys('arp -a')
        self.sys('dmesg | tail -'+str(taillength))
        self.sys('cat /var/log/messages | tail -'+str(taillength))

    def get_masked_pass(self, pwd, firstlast=True, charcount=True, show=False):
        '''
        format password for printing
        options:
        pwd - string- the text password to format
        firstlast -boolean - show the first and last characters in pwd
        charcount -boolean - print a "*" for each char in pwd, otherwise return fixed
                   string '**hidden**'
        show - boolean - convert pwd to str() and return it in plain text
        '''
        ret = ""
        if pwd is None:
            return ""
        if show is True:
            return str(pwd)
        if charcount is False:
            return "**hidden**"
        for x in xrange(0, len(pwd)):
            if (x == 0 or x == len(pwd)) and firstlast:
                ret = ret + pwd[x]
            else:
                ret += "*"

    #############################################################################################
    #                         Package Management                                                #
    #############################################################################################

    @property
    def package_manager(self):
        if not self._package_manager:
            self._package_manager = self._get_package_manager()
        return self._package_manager

    @package_manager.setter
    def package_manager(self, new_package_manager):
        self._package_manager = new_package_manager

    def _get_distro_info_from_machine(self, verbose=False):
        """
        Ubuntu 14.04.2
        CentOS release 6.6 (Final)
        """
        if not self.ssh:
            raise Exception('Need SSH connection to retrieve distribution info from machine')
        try:
            out = self.sys('cat /etc/issue', listformat=False, code=0, verbose=verbose)
        except CommandExitCodeException, CE:
            self.log.debug('Failed to fetch /etc/issue from machine:"{0}", err:"{1}"'
                           .format(self.hostname, str(CE)))
            out = None
        if out:
            try:
                self.distro = str(re.match("^\w+", out).group()).strip().lower()
                self.distro_ver = str(re.search("\s(\d+[\d, .]*)\s", out).group()).strip().lower()
            except Exception, DE:
                self.log.debug('Could not parse distro info from machine, err:' + str(DE))
        self.distro = self.distro or "UNKNOWN"
        self.distro_ver = self.distro_ver or "UNKNOWN"
        return (self.distro, self.distro_ver)

    def _get_package_manager(self, verbose=False):
        """
        Attempts to create a package manager obj based upon the detected package manager
        type.
        """
        try:
            self.sys('which yum', code=0)
            self.package_manager = Yum(self)
            return self.package_manager
        except CommandExitCodeException:
            try:
                self.sys('which apt', code=0, verbose=verbose)
                self.package_manager = Apt(self)
                return self.package_manager
            except CommandExitCodeException:
                pass
        raise RuntimeError('Unable to determine package manager for machine:{0}'
                           .format(self.hostname))

    def upgrade(self, package=None, nogpg=False):
        self.package_manager.upgrade(package, nogpg=nogpg)

    def add_repo(self, url, name="test-repo"):
        self.package_manager.add_repo(url, name)

    def install(self, package, nogpg=False, timeout=300):
        self.package_manager.install(package, nogpg=nogpg)

    def update_repos(self):
        self.package_manager.update_repos()

    def get_package_info(self):
        self.package_manager.get_package_info()

    def get_installed_packages(self):
        self.package_manager.get_installed_packages()

    #############################################################################################
    #                       Network Utilties                                                    #
    #############################################################################################

    @property
    def ssh(self):
        if not self._ssh:
            if self._do_ssh_connect:
                self._ssh = SshConnection(**self.ssh_connect_kwargs)
        return self._ssh

    @ssh.setter
    def ssh(self, newssh):
        self._ssh = newssh

    @property
    def sftp(self):
        if not self._sftp:
            self._sftp = self.ssh.connection.open_sftp()
        return self._sftp

    @sftp.setter
    def sftp(self, newsftp):
        self._sftp = newsftp

    def refresh_ssh(self):
        self.ssh.refresh_connection()

    def start_interactive_ssh(self, timeout=180):
        """
        start a very basic interactive ssh session with this machine
        """
        return self.ssh.start_interactive(timeout=timeout)

    def refresh_connection(self):
        '''
        Attempt to restart/re-create a the machine's ssh connection
        '''
        self.ssh.refresh_connection()

    def interrupt_network(self, time=120, interface=None):
        '''
        Bounce a network interface on the remote machine.
        Used for test purposes
        '''
        defaults = ['eth1', 'em1']
        if not interface:
            for interface in defaults:
                try:
                    self.sys('ifconfig {0}'.format(interface), code=0)
                    break
                except CommandExitCodeException:
                    interface = None
                    pass
        if not interface:
            raise ValueError('interrupt_network. No interface provided, and defaults({0}) '
                             'not found on system'.format(", ".join(str(x) for x in defaults)))
        try:
            self.sys("ifdown " + interface + " && sleep " + str(time) + " && ifup " + interface,
                     timeout=3)
        except:
            pass

    def sys(self, cmd, verbose=True, timeout=120, listformat=True, code=None, net_namespace=None):
        '''
        Issues a command against the ssh connection to this instance
        Returns a list of the lines from stdout+stderr as a result of the command
        '''
        if net_namespace is not None:
            cmd = 'ip netns exec {0} {1}'.format(net_namespace, cmd)
        return self.ssh.sys(cmd, verbose=verbose, timeout=timeout,listformat=listformat, code=code)

    def cmd(self, cmd, verbose=True, timeout=120, listformat=False, net_namespace=None,
            cb=None, cbargs=[]):
        '''
        Issues a command against the ssh connection to this instance
        returns dict containing:
            ['cmd'] - The command which was executed
            ['output'] - The std out/err from the executed command
            ['status'] - The exit (exitcode) of the command, in the case a call back fires,
                         this status code is unreliable.
            ['cbfired']  - Boolean to indicate whether or not the provided callback fired
                          (ie returned False)
            ['elapsed'] - Time elapsed waiting for command loop to end.
        cmd - mandatory - string, the command to be executed
        verbose - optional - boolean flag to enable debug
        timeout - optional - command timeout in seconds
        listformat -optional - specifies returned output in list of lines, or single string buffer
        net_namespace - optional - issue command in the network namespace provided.
        cb - optional - call back function, accepting string buffer, returning true false see s
                        shconnection for more info
        '''
        if net_namespace is not None:
            cmd = 'ip netns exec {0} {1}'.format(net_namespace, cmd)
        if (self.ssh is not None):
            return self.ssh.cmd(cmd, verbose=verbose, timeout=timeout, listformat=listformat,
                                cb=cb, cbargs=cbargs)
        else:
            raise Exception("Euinstance ssh connection is None")

    def sys_until_found(self, cmd, regex, verbose=True, timeout=120, listformat=True,
                        net_namespace=None):
        '''
        Run a command until output of command satisfies/finds regex or EOF is found.
        returns dict containing:
            ['cmd'] - The command which was executed
            ['output'] - The std out/err from the executed command
            ['status'] - The exit (exitcode) of the command, in the case a call back fires,
                         this status code is unreliable.
            ['cbfired']  - Boolean to indicate whether or not the provided callback fired
                          (ie returned False)
            ['elapsed'] - Time elapsed waiting for command loop to end.
        cmd - mandatory - string, the command to be executed
        regex - mandatory - regex to look for
        verbose - optional - boolean flag to enable debug
        timeout - optional - command timeout in seconds
        listformat -optional - specifies returned output in list of lines, or single string buffer
        '''
        return self.cmd(cmd, verbose=verbose, timeout=timeout, listformat=listformat,
                        net_namespace=net_namespace, cb=self.str_found_cb, cbargs=[regex, verbose])

    def _str_found_cb(self, buf, regex, verbose, search=True):
        """
        Return sshcbreturn type setting stop to True if given regex matches against
        given string buf
        """
        if verbose:
            self.log.debug(str(buf))
        return SshCbReturn(stop=self._str_found(buf, regex=regex, search=search))

    def _str_found(self, buf, regex, search=True):
        """
        Return True if given regex matches against given string
        """
        if search:
            found = re.search(regex, buf)
        else:
            found = re.match(regex, buf)
        if found:
            return True
        else:
            return False

    def wget_remote_image(self,
                          url,
                          path=None,
                          dest_file_name=None,
                          user=None,
                          password=None,
                          retryconn=True,
                          timeout=300):
        """
        Wrapper, monitor and display for a remote wget session issued on this machine obj.

        :param url: url to wget
        :param path: wget's -P param
        :param dest_file_name: wget's -O param for destination
        :param user: user for wget auth if needed
        :param password: password for wget auth if needed
        :param retryconn: wget's bool used include --retry-connrefused param
        :param timeout: the overall timeout for the wget command being executed on this machine
        :raise RuntimeError upon wget failure/error.
        """
        self.log.debug('wget_remote_image, url:' + str(url) + ", path:" + str(path))
        cmd = 'wget '
        if path:
            cmd = cmd + " -P " + str(path)
        if dest_file_name:
            cmd = cmd + " -O " + str(dest_file_name)
        if user:
            cmd = cmd + " --user " + str(user)
        if password:
            cmd = cmd + " --password " + str(password)
        if retryconn:
            cmd += ' --retry-connrefused '
        cmd = cmd + ' ' + str(url)
        self.log.debug('wget_remote_image cmd: ' + str(cmd))
        ret = self.cmd(cmd, timeout=timeout, cb=self.wget_status_cb)
        if ret['status'] != 0:
            raise RuntimeError('wget_remote_image failed with status:' + str(ret['status']))
        self.log.debug('wget_remote_image succeeded')

    def wget_status_cb(self, buf):
        """
        Callback to be used to provide real time status during a remote wget session
        """
        ret = SshCbReturn(stop=False)
        try:
            buf = buf.strip()
            val = buf.split()[0]
            if val != self.wget_last_status:
                if re.match('^\d+\%', buf):
                    sys.stdout.write("\r\x1b[K" + str(buf))
                    sys.stdout.flush()
                    self.wget_last_status = val
                else:
                    print buf
        except Exception, e:
            pass
        finally:
            return ret

    def ping_check(self,host, verbose=True, net_namespace=None):
        """
        Wrapper for ICMP ping requests/checks.
        :param host: remote host to ping from this machine obj
        :param verbose: log additional output from this ping command(s)
        :param net_namespace: the Linux network namespace on this machine obj to run ping from.
        :raises RuntimeError if ping fails.
        """
        out = self.ping_cmd(host, verbose=verbose, net_namespace=net_namespace)
        self.debug('Ping attempt to host:'+str(host)+", status code:"+str(out['status']))
        if out['status'] != 0:
            raise RuntimeError('Ping returned error:'+str(out['status'])+' to host:'+str(host))

    def ping_cmd(self, host, count=2, pingtimeout=10, commandtimeout=120, listformat=False,
                 verbose=True, net_namespace=None):

        """
        Wrapper for the ping command to be executed on this machine obj

        :param host: remote host to ping from this machine obj
        :param count: number of ping attempts to be provided to ping command.
        :param pingtimeout: timeout param to be provided to 'ping' command for it's timeout
        :param commandtimeout: Time to wait for the ssh command issuing ping to complete
        :param listformat: bool, if true provides a list of lines, else a single string buffer
        :param verbose: log additional output from this ping command(s)
        :param net_namespace: the Linux network namespace on this machine obj to run ping from.
        :return: the response from the ping command(s)
        """
        cmd = 'ping -c ' +str(count)+' -t '+str(pingtimeout)
        if verbose:
            cmd += ' -v '
        cmd = cmd + ' '+ str(host)
        self.debug('cmd: {0}'.format(cmd))
        out = self.cmd(cmd, verbose=verbose, timeout=commandtimeout, listformat=listformat,
                       net_namespace=net_namespace)
        self.debug('out: {0}'.format(out))
        if verbose:
            #print all returned attributes from ping command dict
            for item in sorted(out):
                self.debug(str(item)+" = "+str(out[item]) )
        return out

    ###############################################################################################
    #                           OS/System Utilties                                                #
    ###############################################################################################

    @property
    def _mem_info(self):
        # Returns a dict of free mem stats from this machine obj.
        # results are cached for '_sys_stats_interval' seconds.
        # to force an update set '_free_stats' to None before fetching.
        if not self._free_stats.get('stats', None) or \
        (time.time() - self._free_stats.get('last_updated', 0) > self._sys_stats_interval):
            header = []

            def newstats(total, used, free):
                return  {'total': total,
                          'used': used,
                          'free': free}

            free_stats = {}
            try:
                out = self.sys('free -m', code=0, verbose=False)
                for line in out:
                    line = str(line).lower().split()
                    if not header:
                        if 'total' in line:
                            header = ['title'] + line
                    else:
                        for memtype in ['mem', 'swap']:
                            if "{0}:".format(memtype) in line:
                                free_stats[memtype] = newstats(
                                    total=line[header.index('total')],
                                    used=line[header.index('used')],
                                    free=line[header.index('free')])
                                break
                free_stats['last_updated'] = time.time()
            except Exception as CE:
                self.log.warn('{0}\n{1}\nFailed to update mem stats:"{2}"'
                              .format("\n".join(out or []), get_traceback(), CE))
            self._free_stats['stats'] = free_stats

        return self._free_stats.get('stats', {})

    @property
    def arch(self):
        # Marchine arch (ie x86_64)
        if not self._arch:
            self._get_arch_info_from_machine()
        return self._arch

    @arch.setter
    def arch(self, value):
        # Marchine arch (ie x86_64)
        self._arch = value

    @property
    def distro(self):
        # Linux Distribution information
        if not self._distroname:
            distro, ver = self._get_distro_info_from_machine()
            self._distroname = distro
            self._distrover = ver
        return self._distroname

    @distro.setter
    def distro(self, new_distro):
        # Linux Distribution information
        self._distroname = new_distro

    @property
    def distro_ver(self):
        # Linux Distribution information
        if not self._distrover:
            distro, ver = self._get_distro_info_from_machine()
            self._distroname = distro
            self._distrover = ver
        return self._distrover

    @distro_ver.setter
    def distro_ver(self, new_distro):
        # Linux Distribution information
        self._distrover = new_distro

    def _get_arch_info_from_machine(self, verbose=False):
        '''
        Attempt to detect and assign the arch info for this machine
        '''
        try:
            arch = self.sys('uname -p', code=0, verbose=verbose)[0]
            self._arch = arch
            return arch
        except Exception, UE:
            self.log.debug('Failed to get arch info from:"{0}", err:"{1}"'
                           .format(self.hostname, str(UE)))
        return None

    def get_free_mem(self):
        val = self._mem_info.get('mem', {}).get('free', None)
        if val is not None:
            val = int(val)
        return val

    def get_total_mem(self):
        val = self._mem_info.get('mem', {}).get('total', None)
        if val is not None:
            val = int(val)
        return val

    def get_used_mem(self):
        val = self._mem_info.get('mem', {}).get('used', None)
        if val is not None:
            val = int(val)
        return val

    def get_swap_used(self):
        val = self._mem_info.get('swap', {}).get('used', None)
        if val is not None:
            val = int(val)
        return val

    def get_uptime(self):
        # fetch uptime of remote machine from proc uptime
        return int(self.sys('cat /proc/uptime', code=0)[0].split()[1].split('.')[0])

    def mkfs(self, partition, type="ext3"):
        self.sys("mkfs." + type + " -F " + partition)

    def mount(self, device, path):
        self.sys("mount " + device + " " + path)

    def show_sys_info(self, mem=True, cpu=True, disk=True, print_method=None, print_table=True):
        print_method = print_method or self.log.info
        sys_pt = PrettyTable(['name', 'value', 'percent'])
        sys_pt.header = False
        sys_pt.border = 0
        sys_pt.align = 'l'
        sys_pt.padding_width = 0
        if mem:
            sys_pt.add_row([markup("Mem:", [1, 4]), "", ""])
            free = self.get_free_mem() or 0
            used = self.get_used_mem() or 0
            total = self.get_total_mem() or 0
            swap = self.get_swap_used() or 0
            per_used = "{0:.1f}".format((used / float(total)) * 100)
            per_free = "{0:.1f}".format((free / float(total)) * 100)
            per_swap = "{0:.1f}".format((swap / float(total)) * 100)
            sys_pt.add_row([" Used:", "{0}".format(used), "{0}%".format(per_used)])
            sys_pt.add_row([" Free:", "{0}".format(free), "{0}%".format(per_free)])
            sys_pt.add_row([" Swap:", "{0}".format(swap), "{0}%".format(per_swap)])
        if cpu:
            sys_pt.add_row([markup("CPU:", [1, 4]), "", ""])
            cpu_info = self.cpu_info
            all = cpu_info.pop('all', None)
            for cpu in sorted(cpu_info):
                values = cpu_info[cpu]
                sys_pt.add_row([" #{0}:".format(cpu), "{0}%".format(values.get('used', None)), ""])
        if disk:
            sys_pt.add_row([markup("DISK:", [1, 4]), "", ""])
            disk_info = self.get_disk_summary()
            for fs, info in disk_info.iteritems():
                sys_pt.add_row([os.path.basename(fs) + " ", info.get('size'), info.get('use%')])
        if print_table:
            print_method("\n{0}\n".format(sys_pt))
        return sys_pt


    ###############################################################################################
    #                               Process Utils                                                 #
    ###############################################################################################

    @property
    def cpu_info(self):
        # Returns a dict of cpu stats from this machine obj.
        # results are cached for '_sys_stats_interval' seconds.
        # to force an update set '_cpu_stats' to None before fetching.
        if not self._cpu_stats.get('stats', None) or \
        (time.time() - self._cpu_stats.get('last_updated', 0) > self._sys_stats_interval):
            header = []

            def newstats(usr, nice, sys, iowait, idle):
                return  {'usr': usr,
                         'nice': nice,
                         'sys': sys,
                         'iowait': iowait,
                         'idle': idle,
                         'used': 100 - float(idle)}

            cpu_stats = {}
            try:
                out = self.sys('mpstat -P ALL', code=0, verbose=False)
                for line in out:
                    line = str(line).lower().split()
                    if not header:
                        if '%idle' in line:
                            header = line
                    elif line:
                        cpu = line[header.index('cpu')]
                        if cpu != 'all':
                            cpu = int(cpu)
                        cpu_stats[cpu] = newstats(
                            usr=line[header.index('%usr')],
                            nice=line[header.index('%nice')],
                            sys=line[header.index('%sys')],
                            iowait=line[header.index('%iowait')],
                            idle=line[header.index('%idle')])

                self._cpu_stats['last_updated'] = time.time()
            except Exception as CE:
                self.log.warn('{0}\n{1}\nFailed to update cpu stats:"{2}"'
                              .format("\n".join(out or []), get_traceback(), CE))
            self._cpu_stats['stats'] = cpu_stats
        return self._cpu_stats.get('stats', {})

    def get_service_is_running_status(self, service, code=0):
        """
        Checks status of service 'service' on the machine obj.
        :param service: string representing service name
        :return: boolean.
        """
        try:
            self.sys("service " + str(service) + " status", code=0)
            return True
        except CommandExitCodeException:
            return False
        except Exception, e:
            self.log.debug('Could not get "{0}" service state from machine: {1}, err:{2}'
                           .format(service, self.hostname, str(e)))

    def get_elapsed_seconds_since_pid_started(self, pid):
        """
        Attempts to parse ps time elapsed since process/pid has been running and return the
        presented time in elapsed number of seconds.
        :param pid: Process id to get elapsed time from
        :return: Elapsed time in seconds that pid has been running
        """
        seconds_min = 60
        seconds_hour = 3600
        seconds_day = 86400
        elapsed = 0
        try:
            if not pid:
                raise Exception('Empty pid passed to get_elapsed_seconds_since_pid_started')
            cmd = "ps -eo pid,etime | grep " + str(pid) + " | awk '{print $2}'"
            self.log.debug('starting get pid uptime"' + str(cmd) + '"...')
            # expected format: days-HH:MM:SS
            out = self.sys(cmd, code=0)[0]
            out = out.strip()
            if re.search("-", out):
                split_out = out.split("-")
                days = int(split_out[0])
                time_string = split_out[1]
            else:
                days = 0
                time_string = out

            split_time = time_string.split(':')
            # insert a 0 if hours, and minutes are not present.
            for x in xrange(len(split_time), 3):
                split_time.insert(0, 0)

            hours = int(split_time[0] or 0)
            minutes = int(split_time[1] or 0)
            seconds = int(split_time[2] or 0)
            elapsed = seconds + (minutes * seconds_min) + (hours * seconds_hour) + (
                days * seconds_day)
        except Exception, ES:
            self.log.debug('{0}\n"get_elapsed_seconds_since_pid_started" error: "{1}"'
                           .format(get_traceback(), str(ES)))
        return int(elapsed)

    def get_pid_info(self, pid, ps_cols=None):
        ret = {}
        ps_cols = ps_cols or ['etime', 'pcpu', 'pmem']
        if not 'comm' in ps_cols:
            ps_cols.append('comm')
        try:
            out = self.sys('ps -p {0} --ppid {0} -o {1}'.format(pid, ",".join(ps_cols)), code=0)
        except CommandExitCodeException as CE:
            self.log.debug('Error fetching info for pid:{0}, err:"{1}"'.format(pid, str(CE)))
        else:
            if len(out) >= 2:
                header = out[0].split()
                command_index = header.index('COMMAND')
                header.remove('COMMAND')
                for line in out[1:]:
                    values = line.split()
                    command = values.pop(command_index)
                    new_dict = {}
                    for h_name in header:
                        new_dict[h_name] = values[header.index(h_name)]
                    ret[command] = new_dict
        return ret

    def found(self, command, regex, verbose=True):
        """ Returns a Boolean of whether the result of the command contains the regex"""
        result = self.sys(command, verbose=verbose)
        if result is None or result == []:
            return False
        for line in result:
            found = re.search(regex, line)
            if found:
                return True
        return False

    #############################################################################################
    #                       User Related Utils                                                  #
    #############################################################################################

    def get_users(self):
        '''
        Attempts to return a list of normal linux access local to this instance.
        Returns a list of all non-root access found within the uid_min/max range who are
        not marked nologin
        '''
        users = []
        try:
            uid_min = str(self.sys("grep ^UID_MIN /etc/login.defs | awk '{print $2}'")[0]).strip()
            uid_max = str(self.sys("grep ^UID_MAX /etc/login.defs | awk '{print $2}'")[0]).strip()
            try:
                users = str(self.sys("cat /etc/passwd | grep -v nologin | awk -F: '{ if ( $3 >= " +
                                     str(uid_min) + " && $3 <= " + str(uid_max) +
                                     " ) print $0}' ")[0]).split(":")[0]
            except IndexError, ie:
                self.log.debug("No access found, passing exception:" + str(ie))
                pass
            return users
        except Exception, e:
            self.log.debug("Failed to get local access. Err:" + str(e))

    def get_user_password(self, username):
        '''
        Attempts to verify whether or not a user 'username' has a password set or not on
        this instance.
        returns true if a password is detected, else false

        '''
        password = None
        out = self.sys("cat /etc/passwd | grep '^" + str(username) + "'")
        if out != []:
            self.log.debug("pwd out:" + str(out[0]))
            if (str(out[0]).split(":")[1] == "x"):
                out = self.sys("cat /etc/shadow | grep '^" + str(username) + "'")
                if out != []:
                    password = str(out[0]).split(":")[1]
                    if password == "" or re.match("^!+$", password):
                        password = None
        return password

    def get_user_group_info(self, username, index=3):
        '''
        Attempts to return a list of groups for a specific user on this instance.
        index is set at the grouplist by default [3], but can be adjust to include the username,
        password, and group id as well in the list.
        where the parsed string should be in format 'name:password:groupid1:groupid2:groupid3...'
        '''
        groups = []
        out = []
        try:
            out = self.sys("cat /etc/group | grep '^" + str(username) + "'")
            if out != []:
                groups = str(out[0]).strip().split(":")
                # return list starting at group index
                groups = groups[index:len(groups)]
            return groups
        except Exception, e:
            self.log.debug("No group found for user:" + str(username) + ", err:" + str(e))

    ###############################################################################################
    #                       File Related Utils                                                    #
    ###############################################################################################

    def chown(self, user, path):
        self.sys("chwon " + user + ":" + user + " " + path)

    def get_abs_path(self, path):
        out = self.sys('echo "$(cd "$(dirname "{0}")" && pwd)/$(basename "{0}")"'.format(path),
                       code=0)
        if out:
            path = os.path.normpath(str(out[0]).strip())
            path.rstrip('.')
            path.rstrip('/') + "/"
            return path
        return None

    def _file_test(self, testchar, path):
        testchar = str(testchar).rstrip('-')
        try:
            self.sys('[ -{0} {1} ]'.format(testchar, path), code=0)
            return True
        except CommandExitCodeException:
            return False

    def is_file(self, path):
        return self._file_test('f', path)

    def is_dir(self, path):
        return self._file_test('d', path)

    def is_block_dev(self, path):
        return self._file_test('b', path)

    def is_readable(self, path):
        return self._file_test('r', path)

    def is_writeable(self, path):
        return self._file_test('w', path)

    def is_executable(self, path):
        return self._file_test('x', path)

    def is_present(self, filepath):
        return self._file_test('e', filepath)

    def get_file_stat(self, path):
        return self.sftp.lstat(path)

    def get_file_size(self, path):
        return self.sftp.lstat(path).st_size

    def get_file_perms_flag(self, path):
        return self.sftp.lstat(path).FLAG_PERMISSIONS

    def get_file_groupid(self, path):
        return self.sftp.lstat(path).st_gid

    def get_file_userid(self, path):
        return self.sftp.lstat(path).st_uid

    @printinfo
    def dd_monitor(self,
                   ddif=None,
                   ddof=None,
                   ddcount=None,
                   ddbs=1024,
                   ddbytes=None,
                   ddcmd=None,
                   ddseek=None,
                   timeout=300,
                   poll_interval=1,
                   tmpfile=None,
                   sync=True):
        '''
        Executes dd command on instance, monitors and displays ongoing status, and returns
        stats dict for dd outcome
        :type ddif: str
        :param ddif: Interface to read data in from

        :type ddof: str
        :param ddof: Interface to write data to

        :type ddcount: int
        :param ddcount: Number or count of block size (ddbs) to read/write

        :type ddbs: int
        :param ddbs: Block size used for  reads/writes

        :type ddbytes: int
        :param ddbytes: Number of bytes to be roughly r/w (note: used as ddbytes/ddbs = count)

        :type ddcmd: str
        :param ddcmd: String representing a preformed dd comand to be executed and monitored

        :type ddseek: int
        :param ddseek: length of ddof file to seek before writing

        :type timeout: int
        :param timeout: Number of seconds to wait before timing out on dd cmd.

        :type poll_interval: int
        :param poll_interval: Number of seconds to pause between polling dd and updating status

        :type tmpfile: str
        :param tmpfile: temp file used on remote instance to redirect dd's stderr to in order
                        to nohup dd.

        :rtype: dict
        :returns: dict containing dd stats
        '''
        mb = 1048576  # bytes per mb
        gig = 1073741824  # bytes per gig
        # this tmp file will be created on remote instance to write stderr from dd to...
        if not tmpfile:
            tstamp = time.time()
            tmpfile = '/tmp/eutesterddcmd.{0}.{1}'.format(self.hostname, str(int(tstamp))[-4:])
        tmppidfile = tmpfile + ".pid"
        # init return dict
        ret = {
            'dd_records_in': 0,
            'dd_records_out': 0,
            'dd_bytes': 0,
            'dd_mb': 0,
            'dd_gig': 0,
            'dd_elapsed': 0,
            'dd_rate': 0,
            'dd_units': "",
            'dd_full_rec_in': 0,
            'dd_full_rec_out': 0,
            'dd_partial_rec_in': 0,
            'dd_partial_rec_out': 0,
            'test_time': 0,
            'test_rate': 0,
            'ddcmd': ""}
        dd_units = 0
        elapsed = 0
        done = False
        infobuf = None
        outbuf = None
        start = time.time()
        if ddcmd:
            ddcmd = ddcmd
        else:
            if not ddif or not ddof:
                raise Exception('dd_monitor needs ddif and ddof, or a preformed ddcmd string')
            ddbs_str = str(' bs=' + str(ddbs) + ' ') or ""
            if ddcount:
                ddcount_str = str(' count=' + str(ddcount) + ' ')
            elif ddbytes and ddbs:
                ddcount_str = str(' count=' + str((ddbytes / ddbs) or 1) + ' ')
            else:
                ddcount_str = ''
            if ddseek:
                ddseek_str = str(' seek=' + str(ddseek) + ' ')
            else:
                ddseek_str = ''
            ddcmd = str('dd if=' + str(ddif) + ' of=' + str(ddof) + str(ddseek_str) +
                        str(ddbs_str) + str(ddcount_str))
            ret['ddcmd'] = ddcmd

        # Due to the ssh psuedo tty, this is done in an ugly manner to get output of
        # future usr1 signals for dd status updates and allow this to run with nohup in the
        # background. Added sleep so cmd is nohup'd before tty is terminated (maybe?)
        try:
            cmd = 'nohup ' + str(ddcmd) + ' 2> ' + str(tmpfile) + ' & echo $! && sleep 2'
            # Execute dd command and store echo'd pid from output
            try:
                dd_pid = self.sys(cmd, code=0)[0]
            except CommandExitCodeException, se:
                dbg_buf = ""
                file_contents = self.sys('cat ' + str(tmpfile))
                if file_contents:
                    dbg_buf = "\n".join(file_contents)
                raise Exception('Failed dd cmd:"' + str(cmd) + '", tmpfile contents:\n' +
                                str(dbg_buf))

            # Form the table headers for printing dd status...
            linediv = '\n---------------------------------------------------------------' \
                      '-------------------------------------------------------------\n'
            databuf = str('BYTES').ljust(15)
            databuf += '|' + str('MBs').center(15)
            databuf += '|' + str('GIGs').center(8)

            timebuf = '|' + str('DD TIME').center(10)
            timebuf += '|' + str('TEST TIME').center(10)

            ratebuf = '|' + str('DD RATE').center(12)
            ratebuf += '|' + str('TEST RATE').center(12)

            recbuf = '|' + str('REC_IN').center(18)
            recbuf += '|' + str('REC_OUT').center(18)

            info_header = str('DD DATA INFO').ljust(len(databuf))
            info_header += '|' + str('DD TIME INFO').center(len(timebuf) - 1)
            info_header += '|' + str('DD RATE INFO').center(len(ratebuf) - 1)
            info_header += '|' + str('DD RECORDS FULL/PARTIAL INFO').center(len(recbuf) - 1)

            buf = linediv
            buf += info_header
            buf += linediv
            buf += databuf + timebuf + ratebuf + recbuf
            buf += linediv
            sys.stdout.write(buf)
            sys.stdout.flush()
            dd_exit_code = -1
            # Keep getting and printing dd status until done...
            while not done and (elapsed < timeout):
                # send sig usr1 to have dd process dump status to stderr redirected to tmpfile
                output = self.cmd('kill -USR1 ' + str(dd_pid), verbose=False)
                cmdstatus = int(output['status'])
                if cmdstatus != 0:
                    done = True
                    cmdout = self.cmd('wait {0}'.format(dd_pid), verbose=False)
                    dd_exit_code = int(cmdout['status'])
                    # if the command returned error, process is done
                    out = self.sys('cat ' + str(tmpfile) + "; rm -f " + str(tmpfile), code=0,
                                   verbose=False)
                else:
                    # if the above command didn't error out then dd ps is still running,
                    # grab status from tmpfile, and clear it
                    out = self.sys('cat ' + str(tmpfile) + " && echo '' > " + str(tmpfile) +
                                   ' 2>&1 > /dev/null', code=0, verbose=False)
                for line in out:
                    line = str(line)
                    try:
                        if re.search('records in', line):
                            ret['dd_records_in'] = str(line.split()[0]).strip()
                            ret['dd_full_rec_in'] = \
                                str(ret['dd_records_in'].split("+")[0].strip())
                            # dd_full_rec_in = int(dd_full_rec_in)
                            ret['dd_partial_rec_in'] = \
                                str(ret['dd_records_in'].split("+")[1].strip())
                            # dd_partial_rec_in = int(dd_partial_rec_in)
                        elif re.search('records out', line):
                            ret['dd_records_out'] = str(line.split()[0]).strip()
                            ret['dd_full_rec_out'] = \
                                str(ret['dd_records_out'].split("+")[0].strip())
                            # dd_ful_rec_out = int(dd_full_rec_out)
                            ret['dd_partial_rec_out'] = str(ret['dd_records_out'].split("+")[1]
                                                            .strip())
                            # dd_partial_rec_out = int(dd_partial_rec_out)
                        elif re.search('copied', line):
                            # 123456789 bytes (123 MB) copied, 12.34 s, 123.45 MB/s
                            summary = line.split()
                            ret['dd_bytes'] = int(summary[0])
                            ret['dd_mb'] = float("{0:.2f}".format(ret['dd_bytes'] / float(mb)))
                            ret['dd_gig'] = float("{0:.2f}".format(ret['dd_bytes'] / float(gig)))
                            ret['dd_elapsed'] = float(summary[5])
                            ret['dd_rate'] = float(summary[7])
                            ret['dd_units'] = str(summary[8])
                    except Exception, e:
                        # catch any exception in the data parsing and show it as info/debug later
                        tb = get_traceback()
                        infobuf = '\n\nCaught exception while processing line:"' + str(line) + '"'
                        infobuf += '\n' + str(tb) + "\n" + str(e) + '\n'
                elapsed = float(time.time() - start)
                ret['test_rate'] = float("{0:.2f}".format(ret['dd_mb'] / elapsed))
                ret['test_time'] = "{0:.4f}".format(elapsed)
                # Create and format the status output buffer, then print it...
                buf = str(ret['dd_bytes']).ljust(15)
                buf += '|' + str(ret['dd_mb']).center(15)
                buf += '|' + str(ret['dd_gig']).center(8)
                buf += '|' + str(ret['dd_elapsed']).center(10)
                buf += '|' + str(ret['test_time']).center(10)
                buf += '|' + str(str(ret['dd_rate']) + " " + str(ret['dd_units'])).center(12)
                buf += '|' + str(str(ret['test_rate']) + " " + str('MB/s')).center(12)
                buf += '|' + str("F:" + str(ret['dd_full_rec_in']) + " P:" +
                                 str(ret['dd_partial_rec_in'])).center(18)
                buf += '|' + str("F:" + str(ret['dd_full_rec_out']) + " P:" +
                                 str(ret['dd_partial_rec_out'])).center(18)
                sys.stdout.write("\r\x1b[K" + str(buf))
                sys.stdout.flush()
                time.sleep(poll_interval)
            sys.stdout.write(linediv)
            sys.stdout.flush()
            elapsed = int(time.time() - start)
            if not done:
                # Attempt to kill dd process...
                self.sys('kill ' + str(dd_pid))
                raise RuntimeError('dd_monitor timed out before dd cmd completed, elapsed:{0}/{1}'
                                   .format(str(elapsed), str(timeout)))
            else:
                # sync to ensure writes to dev
                if sync:
                    self.sys('sync', code=0)
                    elapsed = int(time.time() - start)
            # if we have any info from exceptions caught during parsing, print that here...
            if infobuf:
                print infobuf
            # format last output for debug in case of errors
            if out:
                outbuf = "\n".join(out)
            # Check for exit code of dd command, 127 may indicate dd process ended before wait pid,
            # use additional checks below to determine a failure when 127 is returned.
            if dd_exit_code != 127 and dd_exit_code != 0:
                raise CommandExitCodeException('dd cmd failed with exit code:' + str(dd_exit_code))
            # if we didn't transfer any bytes of data, assume the cmd failed and wrote to stderr
            # now in outbuf...
            if not ret['dd_full_rec_out'] and not ret['dd_partial_rec_out']:
                raise CommandExitCodeException('Did not transfer any data using dd cmd:' +
                                               str(ddcmd) + "\nstderr: " + str(outbuf))
            if ((ret['dd_full_rec_in'] != ret['dd_full_rec_out']) or
                    (ret['dd_partial_rec_out'] != ret['dd_partial_rec_in'])):
                raise CommandExitCodeException('dd in records do not match out records in '
                                               'transfer')
            self.log.debug('Done with dd, copied:{0} bytes, {1} fullrecords, {2} partrecords - '
                           'over elapsed:{3}'.format(ret['dd_bytes'],
                                                     ret['dd_full_rec_out'],
                                                     ret['dd_partial_rec_out'],
                                                     elapsed))
            self.sys('rm -f ' + str(tmpfile))
            self.sys('rm -f ' + str(tmppidfile))
        except:
            self.sys('rm -f ' + str(tmpfile))
            raise
        return ret

    def get_disk_summary(self, dfargs=None, verbose=False):
        ret = {}
        if dfargs is None:
            dfargs = "-h"
        df_info = self.get_df_info(path="", dfargs=dfargs, verbose=verbose)
        for df in df_info:
            fs = df.pop('filesystem')
            ret[fs] = df
        return ret

    def get_df_info(self, path=None, dfargs=None, verbose=False):
        """
        Return df's output in dict format for a given path.
        If path is not given will give the df info for the current working dir used in the ssh
        session this command is executed in (ie: /home/user or /root).
        path - optional -string, used to specifiy path to use in df command. Default is PWD of
                         ssh shelled command
        verbose - optional -boolean, used to specify whether or debug is printed during
                            this command.
        Example:
            dirpath = '/disk1/storage'
            dfout = self.get_df_info_at_path(path=dirpath)
            available_space = dfout['available']
            mounted_on = dfout['mounted']
            filesystem = dfout['filesystem']
        """
        ret = []
        if path is None:
            path = '${PWD}'
        if dfargs is None:
            dfargs = ""
        else:
            if isinstance(dfargs, list):
                dfargs = " ".join(dfargs)
        cmd = 'df -P {0} {1}'.format(dfargs, path)
        if verbose:
            self.log.debug('get_df_info_at_path cmd:' + str(cmd))
        output = self.sys(cmd, code=0, verbose=verbose)
        # Get the presented fields from commands output,
        # Convert to lowercase, use this as our dict keys

        def add_underscore(grp):
            word = grp.group(0)

            return str(word).replace(" ", "_")
        field_line = str(re.sub('[A-Z]\w*(\s+)[a-z]\w*', add_underscore, output[0]))
        fields = field_line.lower().split()
        for line in output[1:]:
            line = str(line).lower().split()
            fs_dict = {}
            for field in fields:
                fs_dict[field] = line[fields.index(field)]
            ret.append(fs_dict)
        return ret

    def get_available(self, path, unit=1):
        """
        Return df output's available field. By default this is KB.
        path - optional -string.
        unit - optional -integer used to divide return value.
               Can be used to convert KB to MB, GB, TB, etc..
        """
        size = int(self.get_df_info_at_path(path=path)['available'])
        return size / unit

    def assertFilePresent(self, filepath):
        '''
        Method to check for the presence of a file at 'filepath' on the instance
        filepath - mandatory - string, the filepath to verify
        '''
        filepath = str(filepath).strip()
        out = self.cmd("ls " + filepath)['status']
        self.log.debug('exit code:' + str(out))
        if out != 0:
            raise Exception("File:" + filepath + " not found on instance:" + self.id)
        self.log.debug('File ' + filepath + ' is present on ' + self.id)

    #############################################################################################
    #                   Misc Utilities
    #############################################################################################

    def put_templated_file(self, local_src, remote_dest, **kwargs):
        '''
        jinja file template aid
        '''
        tmp = tempfile.mktemp()
        try:
            render_file_template(local_src, tmp, **kwargs)
            self.ssh.sftp_put(tmp, remote_dest)
        finally:
            os.remove(tmp)

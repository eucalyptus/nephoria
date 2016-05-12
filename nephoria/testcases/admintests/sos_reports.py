#!/usr/bin/env python

from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from cloud_utils.log_utils import get_traceback, red, ForegroundColor, BackGroundColor, markup
from cloud_utils.net_utils.remote_commands import RemoteCommands
from nephoria.testcontroller import TestController
import copy
import time
import os


class SOSReports(CliTestRunner):

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['ticket_number'] = {
        'args': ['--ticket-number'],
        'kwargs': {'dest': 'ticket_number',
                   'help': 'Issue, bug, ticket number or identifier to use (defaults to time)',
                   'default': None}}
    _DEFAULT_CLI_ARGS['timeout'] = {
        'args': ['--timeout'],
        'kwargs': {'dest': 'timeout',
                   'help': 'Timeout for the sos gathering operation',
                   'default': 1200}}

    _DEFAULT_CLI_ARGS['remote_dir'] = {
        'args': ['--remote-dir'],
        'kwargs': {'dest': 'remote_dir',
                   'help': 'Directory on remote host(s)',
                   'default': '/root/'}}

    _DEFAULT_CLI_ARGS['local_dir'] = {
        'args': ['--local-dir'],
        'kwargs': {'dest': 'local_dir',
                   'help': 'Local directory to use for gathering sos reports',
                   'default': ''}}

    _DEFAULT_CLI_ARGS['package_url'] = {
        'args': ['--package-url'],
        'kwargs': {'dest': 'package_url',
                   'help': 'Url to use for eucalyptus sos plugin package',
                   'default': "http://downloads.eucalyptus.com/software/tools/centos/6/x86_64/"
                              "eucalyptus-sos-plugins-0.1.5-0.el6.noarch.rpm"}}

    def post_init(self, *args, **kwargs):
        self.start_time = int(time.time())
        self.ticket_number = self.args.ticket_number or self.start_time
        self.remote_dir = os.path.join(self.args.remote_dir,
                                       'euca-sosreport-{0}'.format(self.ticket_number))


    @property
    def tc(self):
        tc = getattr(self, '__tc', None)
        if not tc:
            tc = TestController(hostname=self.args.clc,
                                environment_file=self.args.environment_file,
                                password=self.args.password,
                                log_level=self.args.log_level)
            setattr(self, '__tc', tc)
        return tc

    @property
    def rc(self):
        rc = getattr(self, '__rc', None)
        if not rc:
            rc = RemoteCommands(ips=self.tc.sysadmin.eucahosts.keys(),
                            username='root',
                            password=self.args.password)
            setattr(self, '__rc', rc)
        return rc

    def clean_method(self):
        pass

    def test1_install_sos_and_plugins(self):
        """
        Attempts to install the SOS and Eucalyptus-sos-plugins on each machine in the cloud.
        """
        rc = self.rc
        rc.results = {}
        rc.run_remote_commands(command='yum install sos eucalyptus-sos-plugins -y --nogpg')
        rc.show_results()


    def test2_run(self):
        """
        Attempts to run SOS on each host in the cloud to create and gather SOS reports.
        """
        command = "mkdir -p " + self.remote_dir
        command += "; sosreport --batch --tmp-dir {0} --ticket-number {1} "\
            .format(self.remote_dir, self.ticket_number)
        rc = self.rc
        rc.results = {}
        rc.run_remote_commands(command=command)
        rc.show_results()

    def test3_download(self):
        """
        Attempts to download the SOS reports from each host in the cloud and store in a local
        directory
        """
        error_msg = ""
        count = 0
        err_count = 0
        host_count = len(self.tc.sysadmin.eucahosts)
        for ip, host in self.tc.sysadmin.eucahosts.iteritems():
            try:
                remote_tarball_path = host.sys("ls -1 {0}/*.xz | grep {1}"
                                               .format(self.remote_dir, self.ticket_number),
                                               code=0)[0]
                tarball_name = os.path.basename(remote_tarball_path)
                local_name = "{0}.{1}{2}".format(ip.replace('.', '_'), self.ticket_number,
                                                 tarball_name.split(str(self.ticket_number))[1])
                local_tarball_path = os.path.join(self.args.local_dir, local_name)
                self.log.debug("Downloading file to: " + local_tarball_path)
                host.ssh.sftp_get(localfilepath=local_tarball_path,
                                  remotefilepath=remote_tarball_path)
            except Exception, e:
                err_count += 1
                msg = '\nError Downloading from: {0}. Error:"{0}"\n'.format(ip, e)
                self.log.error("{0}\n{1}".format(get_traceback(), msg))
                error_msg += msg
            else:
                count += 1
                self.log.info(markup('Downloaded SOS report {0}/{1} to:{2}'
                                     .format(count, host_count, local_tarball_path),
                                     markups=[ForegroundColor.WHITE, BackGroundColor.BG_GREEN]))
        if error_msg:
            self.log.error(red(error_msg))
            raise Exception('Error during download on {0}/{1} hosts'.format(err_count, host_count))


if __name__ == "__main__":
    test =SOSReports()
    result = test.run()
    exit(result)
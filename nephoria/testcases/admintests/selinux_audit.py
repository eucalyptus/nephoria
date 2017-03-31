#!/usr/bin/env python

from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from cloud_utils.log_utils import get_traceback, red, ForegroundColor, BackGroundColor, markup
from cloud_utils.net_utils.remote_commands import RemoteCommands
from cloud_utils.net_utils.sshconnection import SshConnection
from nephoria.testcontroller import TestController
import copy
import re
import time
import os


class SeLinuxAudit(CliTestRunner):

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)


    _DEFAULT_CLI_ARGS['timeout'] = {
        'args': ['--timeout'],
        'kwargs': {'dest': 'timeout',
                   'help': 'Timeout for the audit gathering operation',
                   'default': 1200}}

    _DEFAULT_CLI_ARGS['start_hours'] = {
        'args': ['--start-hours'],
        'kwargs': {'dest': 'start_hours',
                   'help': 'Number of hours ago to use as start time for ausearch. '
                           'Will inspect logs from start_hours ago and newer. A value of 0 will'
                           'prevent this argument from being presented to ausearch ',
                   'default': 4}}

    _DEFAULT_CLI_ARGS['search_args'] = {
        'args': ['--search-args'],
        'kwargs': {'dest': 'search_args',
                   'help': 'Arguments to be fed to ausearch command. If --start is provided here'
                           'then this will override this scripts --start-hours value',
                   'default': " -m avc,user_avc "}}

    _DEFAULT_CLI_ARGS['ip_list'] = {
        'args': ['--ip-list'],
        'kwargs': {'dest': 'ip_list',
                   'help': 'Comma separated list of ips or hostnames to gather sos reports from',
                   'default': None }}


    def post_init(self, *args, **kwargs):
        # Some helper code to provide a start date to ausearch as well as checks to see
        # if the user has provided this arg else where, or told us not to provide it.
        start_hours = 0
        if self.args.search_args is None:
            self.search_args = " "
        else:
            self.search_args = str(self.args.search_args)
        if self.search_args and re.search('-s', self.search_args):
            self.start_time = " "
        else:
            try:
                start_hours = int(self.args.start_hours)
            except:
                self.args.start_hours = self.args.start_hours or 0
                self.start_time = "--start {0}" .format(self.args.start_hours)
            else:
                if not start_hours:
                    self.start_time = " "
                else:
                    start = time.time() - (60*60*start_hours)
                    ts = time.localtime(start)
                    self.start_time = " --start {0}/{1}/{2} {3}:{4}:{5} ".format(ts.tm_mon,
                                                                               ts.tm_mday,
                                                                               ts.tm_year,
                                                                               ts.tm_hour,
                                                                               ts.tm_min,
                                                                               ts.tm_sec)
        self._ip_list = []


    def _scrub_ip_list(self, value):
        value = value or []
        ip_list = []
        if isinstance(value, basestring):
            value = value.split(',')
        if not isinstance(value, list):
            self.log.error(red('ip_list must be a list of IPs or comma separated string of IPs'))
            raise ValueError('ip_list must be a list of IPs or comma separated string of IPs')
        for ip in value:
            ip_list.append(str(ip).strip())
        return ip_list


    @property
    def ip_list(self):
        if not self._ip_list:
            ip_list = self.args.ip_list or self.tc.sysadmin.eucahosts.keys()
            self._ip_list = self._scrub_ip_list(ip_list)
        return self._ip_list

    @ip_list.setter
    def ip_list(self, value):
        self._ip_list = self._scrub_ip_list(value)

    @property
    def tc(self):
        tc = getattr(self, '__tc', None)
        if not tc:
            self.log.debug('Attempting to create TestController...')
            tc = TestController(hostname=self.args.clc,
                                environment_file=self.args.environment_file,
                                password=self.args.password,
                                timeout=self.args.timeout,
                                log_level=self.args.log_level)
            setattr(self, '__tc', tc)
        return tc

    @property
    def rc(self):
        rc = getattr(self, '__rc', None)
        if not rc:
            ip_list = self.ip_list
            self.log.debug('Attempting to create remote command driver with ip list: {0}'
                           .format(ip_list))
            rc = RemoteCommands(ips=self.ip_list,
                                username='root',
                                password=self.args.password,
                                timeout=600)
            setattr(self, '__rc', rc)
        return rc

    def clean_method(self):
        pass


    def test0_install_audit_utils(self):
        """
        Attempts to install the audit utils
        """

        rc = self.rc
        rc.results = {}
        cmd = "yum install policycoreutils-python -y --nogpg"
        self.log.debug('Running "{0}" on ips:{1}'.format(cmd, rc.ips))
        rc.run_remote_commands(command=cmd)
        rc.show_results()
        failed = 0
        for host, result in rc.results.iteritems():
            if result.get('status') != 0:
                failed += 1

        if failed:
            raise RuntimeError('{0}/{1} hosts had errors during run cmd:"{2}"'
                               .format(failed, len(rc.ips), cmd))

    def test1_gather_ausearch(self):
        """
        Attempts to gather ausearch information for the provided time period.
        If there is output from this command the test raises a runtime error as this may
        need selinux policy attention.
        """

        rc = self.rc
        rc.results = {}
        cmd = 'ausearch {0} {1} --success no'.format(self.start_time, self.search_args)
        self.log.debug('Running "{0}" on ips:{1}'.format(cmd, rc.ips))
        rc.run_remote_commands(command=cmd)
        rc.show_results(expected_status=1)
        failed = 0
        for host, result in rc.results.iteritems():
            if result.get('status') != 1:
                failed += 1
            if result.get('output'):
                res = "".join(result.get('output')).strip()
                if not (res == "" or "Nothing to do" in res or "<no matches>" in res):
                    failed += 1

        if failed:
            raise RuntimeError('{0}/{1} hosts either failed to run command or returned '
                               'output for cmd:"{2}"'
                               .format(failed, len(rc.ips), cmd))

    def test2_gather_audit2allow(self):
        """
        Attempts to gather audit2allow information for the provided time period.
        If there is output from this command the test raises a runtime error as this may
        need selinux policy attention.
        """

        rc = self.rc
        rc.results = {}
        cmd = 'ausearch {0} {1} --success no '.format(self.start_time, self.search_args)
        self.log.debug('Running "{0}" on ips:{1}'.format(cmd, rc.ips))
        rc.run_remote_commands(command=cmd)
        rc.show_results(expected_status=1)
        failed = 0
        for host, result in rc.results.iteritems():
            if result.get('status') != 1:
                failed += 1
            if result.get('output'):
                res = "".join(result.get('output')).strip()
                if not (res == "" or "Nothing to do" in res or "<no matches>" in res):
                    failed += 1

        if failed:
            raise RuntimeError('{0}/{1} hosts either failed to run command or returned '
                               'output for cmd:"{2}"'
                               .format(failed, len(rc.ips), cmd))

    def test3_gather_audit2why(self):
        """
        Attempts to gather audit2allow information for the provided time period.
        If there is output from this command the test raises a runtime error as this may
        need selinux policy attention.
        """

        rc = self.rc
        rc.results = {}
        cmd = 'ausearch {0} {1} --success no '.format(self.start_time, self.search_args)
        self.log.debug('Running "{0}" on ips:{1}'.format(cmd, rc.ips))
        rc.run_remote_commands(command=cmd)
        rc.show_results(expected_status=1)
        failed = 0
        for host, result in rc.results.iteritems():
            if result.get('status') != 1:
                failed += 1
            if result.get('output'):
                 res = "".join(result.get('output')).strip()
                 if not (res == "" or "Nothing to do" in res or  "<no matches>" in res):
                    failed += 1

        if failed:
            raise RuntimeError('{0}/{1} hosts either failed to run command or returned '
                               'output for cmd:"{2}"'
                               .format(failed, len(rc.ips), cmd))




if __name__ == "__main__":
    test = SeLinuxAudit()
    result = test.run()
    exit(result)
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
# Author: vic.iglesias@eucalyptus.com

import re
import time
from argparse import Namespace
from cloud_utils.net_utils.sshconnection import CommandExitCodeException
from cloud_utils.log_utils import markup


class RepoUtils:
    def __init__(self, machine, package_manager="yum"):
        self.package_manager = None
        if package_manager is "yum":
            self.package_manager = Yum(machine)
        if package_manager is "apt":
            self.package_manager = Apt(machine)


class Package:
    name = None
    version = None


class PackageManager:
    name = None
    machine = None
    repo_url_cache = {}

    def install(self, package):
        raise NotImplementedError("Method not implemented for package manager " + str(self.name))

    def upgrade(self, package=None):
        raise NotImplementedError("Method not implemented for package manager " + str(self.name))

    def add_repo(self, url, name=None):
        raise NotImplementedError("Method not implemented for package manager " + str(self.name))

    def update_repos(self):
        raise NotImplementedError("Method not implemented for package manager " + str(self.name))

    def get_package_info(self, package_name):
        raise NotImplementedError("Method not implemented for package manager " + str(self.name))

    def get_installed_packages(self, searchstring=None):
        raise NotImplementedError("Method not implemented for package manager " + str(self.name))

    def get_url_for_package(self, package_name):
        raise NotImplementedError("Method not implemented for package manager " + str(self.name))

    def get_repo_file(self, filepath, filters=None):
        raise NotImplementedError("Method not implemented for package manager " + str(self.name))

    def get_repo_file_by_baseurl(self, url, repopath=None, cleanurl=True, filters=None):
        raise NotImplementedError("Method not implemented for package manager " + str(self.name))

    def get_repo_file_for_package(self, packagename, repopath=None, filters=None):
        raise NotImplementedError("Method not implemented for package manager " + str(self.name))


class Yum(PackageManager):
    def __init__(self, machine):
        self.machine = machine
        self.name = "yum"

    def install(self, package, nogpg=False):
        gpg_flag = ""
        if nogpg:
            gpg_flag = "--nogpg"

        return self.machine.sys("yum install -y " + gpg_flag + " " + package, code=0)

    def upgrade(self, package=None, nogpg=False):
        gpg_flag = ""
        if nogpg:
            gpg_flag = "--nogpg"
        if not package:
            package = ""
        return self.machine.sys("yum upgrade -y " + gpg_flag + " " + package, timeout=480)

    def get_package_info(self, package_name):
        return self.machine.sys('yum info {0}'.format(package_name), code=0)

    def get_url_for_package(self, package_name):
        if package_name in self.repo_url_cache:
            if (time.time() - self.repo_url_cache[package_name]['updated']) <= 10:
                return self.repo_url_cache[package_name]['url']
        out = self.machine.sys('yumdownloader --urls eucalyptus -q', code=0)
        for line in out:
            match = re.match("^(http*.*.rpm)$", line)
            if match:
                line = match.group(1)
                self.repo_url_cache[package_name] = {'updated': time.time(),
                                                     'url': line}
                return line
        self.machine.log.error(markup('URL not found for local package:"{0}"'
                                      .format(package_name), markups=[1, 31]))

    def get_repo_file_for_package(self, packagename, repopath=None, filters=None):
        """
        Attempts to find a file containing repo info at 'repopath', by matching the in use
        package url to the baseurl entries of files at 'repopath' and return a dict
        of the key=value info found.
        :param packagename: string, name of package to use in search
        :param repopath: dir to search for files
        :param filters: list of strings.  Will match a subset of the keys found and only return
                        those keys matching a filter.
        :returns namespace obj with repo info or None upon error, file not found, etc..
        """
        url = self.get_url_for_package(packagename)
        return self. get_repo_file_by_baseurl(url=url, repopath=repopath, filters=filters)

    def get_repo_file_by_baseurl(self, url, repopath=None, cleanurl=True, filters=None):
        """
        Attempts to find a file containing repo info at 'repopath' by matching the provided 'url'
        to the 'baseurl' entries, and return a namespace obj with info
        of the key=value info found.
        :param url: string, baseurl to search repo files for
        :param repopath: dir to search for files
        :param cleanurl: bool, attempts to format an url to a typical baseurl
        :param filters: list of strings.  Will match a subset of the keys found and only return
                        those keys matching a filter.
        :returns namespace with repo info or None upon error, file not found, etc..
        """
        if repopath is None:
            repopath = '/etc/yum.repos.d/*'
        if cleanurl:
            try:
                match = re.match('^(http://\S+/x86_64)', url)
                if match:
                    url = match.group(1)
            except:
                pass
        try:
            out = self.machine.sys('grep "{0}" {1} -l'.format(url, repopath), code=0)
        except CommandExitCodeException as CE:
            self.machine.log.error(markup('Could not find repo for url:"{0}", err:"{1}"'
                                   .format(url, str(CE)), markups=[1, 31]))
            return None
        if out:
            filepath = out[0]
            if re.search('^{0}'.format(repopath), filepath):
                return self.get_repo_file(filepath, filters=filters)
        return None

    def get_repo_file(self, filepath, filters=None):
        """
        Read in repo key=value info from a file at 'filepath'.
        :param filepath: string, filepath containing repo info on remote machine
        :param filters: list of strings.  Will match a subset of the keys found and only return
                        those keys matching a filter.
        :returns namespace obj with repo info or None.
        """
        filter_values = filters or []
        values = {'filepath': filepath}
        try:
            out = self.machine.sys('cat {0}'.format(filepath), code=0)
        except CommandExitCodeException as CE:
            self.machine.log.error(markup('Failed to read repo_file at:"{0}", err:"{1}"'
                                   .format(filepath, str(CE)), markups=[1, 31]))
            return None
        for line in out:
            valname = None
            value = None
            if not line:
                continue
            valmatch = re.search('\s*(\w.*)\s*=\s*(\w.*)\s*$', line)
            if valmatch:
                valname = valmatch.group(1)
                value = valmatch.group(2)
            else:
                namematch = re.search('^\s*\[\s*(\S*)\s*\]\s*$', line)
                if namematch:
                    valname = 'repo_name'
                    value = namematch.group(1)
            if valname and value is not None:
                values[valname] = value
        if not values:
            self.machine.log.error(markup('No values parsed from:"{0}"'
                                          .format(filepath), markups=[1, 31]))
            return None
        if not filters:
            return RepoFile(**values)
        ret = RepoFile()
        for name in filters:
            if name in values:
                setattr(ret, name, values[name])
        return ret

    def add_repo(self, url, name=None):
        if name is None:
            name = "new-repo-" + str(int(time.time()))
        repo_file = "/etc/yum.repos.d/" + name + ".repo"
        self.machine.sys("echo '[%s]' > %s" % (name, repo_file))
        self.machine.sys("echo 'name=%s' >> %s" % (name, repo_file))
        self.machine.sys("echo 'baseurl=%s' >> %s" % (url, repo_file))
        self.machine.sys("echo -e 'enabled=1\ngpgcheck=0' >> %s " % repo_file)
        return self.update_repos()

    def update_repos(self):
        return self.machine.sys("yum clean all")

    def get_installed_packages(self, searchstring=None):
        if searchstring:
            searchstring = " | grep {0}".format(searchstring)
        else:
            searchstring = ""
        cmd = "yum list installed {0}".format(searchstring)
        return self.machine.sys(cmd, code=0)


class Apt(PackageManager):
    def __init__(self, machine):
        self.machine = machine
        self.name = "apt"
        self.apt_options = "-o Dpkg::Options::='--force-confold' -y --force-yes "

    def install(self, package, timeout=300):
        return self.machine.sys("export DEBIAN_FRONTEND=noninteractive; apt-get install %s %s" % (
            self.apt_options, str(package)), timeout=timeout, code=0)

    def upgrade(self, package=None):
        if package is None:
            package = ""
        return self.machine.sys("export DEBIAN_FRONTEND=noninteractive; apt-get "
                                "dist-upgrade %s %s " % (self.apt_options, str(package)))

    def get_package_info(self, package_name):
        return self.machine.sys('apt-cache show {0}'.format(package_name), code=0)

    def add_repo(self, url, name=None):
        if name is None:
            name = "new-repo-" + str(int(time.time()))
        repo_file = "/etc/apt/sources.list.d/" + name
        self.machine.sys("echo %s >> %s " % (url, repo_file))
        return self.update_repos()

    def update_repos(self):
        return self.machine.sys("apt-get update")


class RepoFile(Namespace):
    def __init__(self, **kwargs):
        self.baseurl = None
        self.enabled = None
        self.filepath = None
        self.gpgcheck = None
        self.gpgkey = None
        self.metadata_expire = None
        self.name = None
        self.repo_name = None
        self.sslverify = None
        super(RepoFile, self).__init__(**kwargs)

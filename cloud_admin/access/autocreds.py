"""
AutoCreds is a convenience class which attempt to provide utilities for reading in
credentials data from multiple sources.
The auto_create flag (set to True by default) attempts  to automatically produce credentials
based upon the information provided to this AutoCreds obj.
        - If any ssh connect arguments (outside of hostname) are provided then only the remote
        machine tried for existing creds at 'self._credpath'.
        - If credpath was provided the local file system will first be tried for existing
        credentials
        - If aws access and secret keys were provided allong with hostname, will attempt to
        derivce service credpaths from the Eucalyptus Admin api.
        -Finally if a hostname was provided an ssh attempt will be made (with any other
         connection kwargs provided)to fetch from the remote system as well.
         If password or keypath was not provided, this assumes keys have been sync'd between the
         localhost and the remote machine.
        Upon the first successful discovery of credentials, the local obj is populated with
        eucarc attributes and returns.

Some examples:
In [7]: from cloud_admin.access.autocreds import AutoCreds

# From a remote machine..
In [8]: creds = AutoCreds(credpath='', hostname='10.111.5.156', password='foobar')
In [9]: creds.ec2_url
Out[9]: 'http://10.111.5.156:8773/services/compute'

# From a local filepath:
In [11]: creds = AutoCreds(credpath='eucarc-10.111.5.156-eucalyptus-admin/eucarc')
In [12]: creds.s3_url
Out[12]: 'http://10.111.5.156:8773/services/objectstorage'

# Finally from the Eucalyptus Admin Api...
creds = AutoCreds(aws_access_key=aws_access_key, aws_secret_key=aws_secret_key,
                  hostname='10.111.5.156')

# Access the credential values as attributes of the AutoCreds obj such as:
In [21]: admin_connection = ServiceConnection(host='10.111.5.156',
                                              aws_access_key_id=creds.aws_access_key,
                                              aws_secret_key=creds.aws_secret_key)

# All creds can be fetched in a dict using:
In [22]: creds.get_eucarc_attrs()
Out[22]:
{'aws_access_key': 'AKIAAAI765C6PIO7QMS7',
 'aws_auto_scaling_url': 'http://10.111.5.156:8773/services/AutoScaling',
 'aws_cloudformation_url': 'http://10.111.5.156:8773/services/CloudFormation',
 'aws_cloudwatch_url': 'http://10.111.5.156:8773/services/CloudWatch',
 'aws_credential_file': None,
 'aws_elb_url': 'http://10.111.5.156:8773/services/LoadBalancing',
 'aws_iam_url': 'http://10.111.5.156:8773/services/Euare',
 'aws_secret_key': 'lqi6Bp6hHAIwkXwicRyDKxHDckr2vrnDd7I1xu6d',
 'aws_simpleworkflow_url': 'http://10.111.5.156:8773/services/SimpleWorkflow',
 'ec2_access_key': 'AKIAAAI765C6PIO7QMS7',
 'ec2_account_number': None,
 'ec2_cert': None,
 'ec2_jvm_args': None,
 'ec2_private_key': None,
 'ec2_secret_key': 'lqi6Bp6hHAIwkXwicRyDKxHDckr2vrnDd7I1xu6d',
 'ec2_url': 'http://10.111.5.156:8773/services/compute',
 'ec2_user_id': None,
 'euare_url': 'http://10.111.5.156:8773/services/Euare',
 'eucalyptus_cert': None,
 'eustore_url': 'http://emis.eucalyptus.com/',
 's3_url': 'http://10.111.5.156:8773/services/objectstorage',
 'token_url': 'http://10.111.5.156:8773/services/Tokens'}

 # For easy viewing, they can be shown in table format as well:
In [23]: creds.show()
[2015-05-18 15:47:12,249] [AutoCreds] [DEBUG]:
+------------------------+--------------------------------------------------+
| ec2_account_number     | None                                             |
+------------------------+--------------------------------------------------+
| euare_url              | http://10.111.5.156:8773/services/Euare          |
+------------------------+--------------------------------------------------+
| ec2_user_id            | None                                             |
+------------------------+--------------------------------------------------+
| token_url              | http://10.111.5.156:8773/services/Tokens         |
+------------------------+--------------------------------------------------+
| ec2_url                | http://10.111.5.156:8773/services/compute        |
+------------------------+--------------------------------------------------+
| aws_elb_url            | http://10.111.5.156:8773/services/LoadBalancing  |
+------------------------+--------------------------------------------------+
| aws_cloudformation_url | http://10.111.5.156:8773/services/CloudFormation |
+------------------------+--------------------------------------------------+
| aws_secret_key         | lqi6Bp6hHAIwkXwicRyDKxHDckr2vrnDd7I1xu6d         |
+------------------------+--------------------------------------------------+
| aws_cloudwatch_url     | http://10.111.5.156:8773/services/CloudWatch     |
+------------------------+--------------------------------------------------+
| eucalyptus_cert        | None                                             |
+------------------------+--------------------------------------------------+
| s3_url                 | http://10.111.5.156:8773/services/objectstorage  |
+------------------------+--------------------------------------------------+
| aws_iam_url            | http://10.111.5.156:8773/services/Euare          |
+------------------------+--------------------------------------------------+
| aws_simpleworkflow_url | http://10.111.5.156:8773/services/SimpleWorkflow |
+------------------------+--------------------------------------------------+
| ec2_jvm_args           | None                                             |
+------------------------+--------------------------------------------------+
| ec2_private_key        | None                                             |
+------------------------+--------------------------------------------------+
| ec2_access_key         | AKIAAAI765C6PIO7QMS7                             |
+------------------------+--------------------------------------------------+
| ec2_secret_key         | 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         |
+------------------------+--------------------------------------------------+
| aws_access_key         | AKIAAAI765C6PIO7QMS7                             |
+------------------------+--------------------------------------------------+
| eustore_url            | http://emis.eucalyptus.com/                      |
+------------------------+--------------------------------------------------+
| aws_credential_file    | None                                             |
+------------------------+--------------------------------------------------+
| ec2_cert               | None                                             |
+------------------------+--------------------------------------------------+
| aws_auto_scaling_url   | http://10.111.5.156:8773/services/AutoScaling    |
+------------------------+--------------------------------------------------+
| UNPARSED LINES         | None                                             |
+------------------------+--------------------------------------------------+)
"""
import os.path
import re
from urlparse import urlparse
from cloud_utils.file_utils.eucarc import Eucarc
from cloud_utils.log_utils import get_traceback
from cloud_utils.system_utils.machine import Machine
from cloud_admin.services.serviceconnection import ServiceConnection
from cloud_utils.net_utils.sshconnection import CommandExitCodeException
from cloud_admin.hosts.eucahost import EucaHost


eucarc_to_service_map = {
    "euare_url": 'euare',
    "ec2_url": 'compute',
    "token_url": 'tokens',
    "aws_elb_url": 'loadbalancing',
    "aws_cloudformation_url": 'cloudformation',
    "aws_cloudwatch_url": 'cloudwatch',
    "s3_url": 'objectstorage',
    "aws_iam_url": 'euare',
    "aws_simpleworkflow_url": 'simpleworkflow',
    "aws_auto_scaling_url": 'autoscaling'}


class AutoCreds(Eucarc):
    def __init__(self,
                 auto_create=True,
                 aws_access_key=None,
                 aws_secret_key=None,
                 aws_account_name=None,
                 aws_user_name=None,
                 hostname=None,
                 username='root',
                 password=None,
                 keypath=None,
                 credpath=None,
                 proxy_hostname=None,
                 proxy_username='root',
                 proxy_password=None,
                 proxy_keypath=None,
                 logger=None,
                 eucarc_obj=None):
        super(AutoCreds, self).__init__(logger=logger)
        self._serviceconnection = None
        self._clc_ip = hostname
        self._clc_machine = None
        self._credpath = credpath
        self._account_name = aws_account_name
        self._user_name = aws_user_name
        self.aws_secret_key = aws_secret_key
        self.aws_access_key = aws_access_key
        self.debug = self.log.debug
        self._has_updated_connect_args = False  # used to speed up auto find credentials
        if (username != 'root' or proxy_username != 'root' or password or keypath or
                proxy_hostname or proxy_keypath or proxy_password):
            self._has_updated_connect_args = True
        self._clc_connect_kwargs = {
            'hostname': hostname,
            'username': username,
            'password': password,
            'keypath': keypath,
            'proxy_hostname': proxy_hostname,
            'proxy_username': proxy_username,
            'proxy_password': proxy_password,
            'proxy_keypath': proxy_keypath
        }
        if eucarc_obj:
            self.__dict__.update(eucarc_obj.__dict__)
        if not eucarc_obj and auto_create:
            self.auto_find_credentials()

    @property
    def clc_machine(self):
        if not self._clc_machine:
            self._clc_machine = self.connect_to_clc()
        return self._clc_machine

    @clc_machine.setter
    def clc_machine(self, newclc):
        self._clc_machine = newclc

    @property
    def serviceconnection(self):
        if not self._serviceconnection:
            self._serviceconnection = self._connect_services()
        return self._serviceconnection

    def _connect_services(self):
        if self.aws_secret_key and self.aws_access_key and self._clc_ip:
            self._serviceconnection = ServiceConnection(hostname=self._clc_ip,
                                      aws_access_key=self.aws_access_key,
                                      aws_secret_key=self.aws_secret_key)
        return self._serviceconnection

    def _close_adminpi(self):
        """
        If open, Attempts to close/cleanup the AutoCred's serviceconnection obj
        """
        if self._serviceconnection:
            try:
                self._serviceconnection.close()
                self._serviceconnection = None
            except:
                pass

    def update_attrs_from_cloud_services(self):
        """
        Attempts to update the current eucarc artifacts (service paths) from services
        gathered via the Eucalyptus admin api interface
        :returns dict mapping eucarc common key-values to the discovered service URIs.
        """
        if not self.serviceconnection:
            raise RuntimeError('Can not fetch service paths from cloud without an ServiceConnection '
                               'connection\n This requires: clc_ip, aws_access_key, '
                               'aws_secret_key')
        path_dict = self._get_service_paths_from_serviceconnection(self.serviceconnection)
        if not path_dict.get('ec2_access_key'):
            path_dict['ec2_access_key'] = self.aws_access_key
        if not path_dict.get('ec2_secret_key'):
            path_dict['ec2_secret_key'] = self.aws_secret_key
        self.__dict__.update(path_dict)
        self._close_adminpi()
        return path_dict

    @classmethod
    def _get_service_paths_from_serviceconnection(cls, serviceconnection):
        """
        Reads the Eucalyptus services, maps them to common eucarc key values, and returns
        the dict of the mapping.
        :params serviceconnection: an ServiceConnection obj w/ active connection.
        :returns dict mapping eucarc common key-values to the discovered service URIs.
        """
        assert isinstance(serviceconnection, ServiceConnection)
        services = serviceconnection.get_services()
        ret_dict = {}
        for service in services:
            for key, serv_value in eucarc_to_service_map.iteritems():
                if service.type == serv_value:
                    ret_dict[key] = str(service.uri)
        return ret_dict

    def get_local_eucarc(self, credpath):
        """
        Reads in eucarc contents from a local file path. Checks to make sure the credpath
        given is an existing file, if a dir was provide it will check for a file name 'eucarc'
        in that dir.
        :params credpath: string representing the path to the eucarc file
        :return dict of eucarc read in
        """
        if not str(credpath).endswith('eucarc') and os.path.isdir(credpath):
            credpath = os.path.join(credpath, 'eucarc')
        if os.path.isfile(credpath):
            return self._from_filepath(credpath)
        return None

    def get_remote_eucarc(self, credpath, machine=None):
        """
        Reads in eucarc contents from a remote file path on the provided Machine().
        Checks to make sure the credpath given is an existing file, if a dir was provide it will
        check for a file name 'eucarc' in that dir.
        :params credpath: string representing the path to the eucarc file
        :params machine: Machine() obj
        :returns dict of eucarc read in
        """
        machine = machine or self.clc_machine
        if not str(credpath).endswith('eucarc') and machine.is_dir(credpath):
            credpath = os.path.join(credpath, 'eucarc')
        if machine.is_file(credpath):
            return self._from_filepath(filepath=credpath, sshconnection=machine._ssh)
        return None

    def connect_to_clc(self, connect_kwargs=None):
        """
        Attempts to create a Machine by connecting to the remote host, usually the CLC.
        :params connect_kwargs: Dictionary set of arguments to be provided to Machine().__init__()
        returns machine obj upon success
        """
        connect_kwargs = connect_kwargs or self._clc_connect_kwargs
        machine = Machine(**connect_kwargs)
        self.clc_machine = machine
        return machine

    def auto_find_credentials(self):
        """
        Convenience method which attempts to automatically produce credentials based upon the
        information provided to this AutoCreds obj.
        - If any ssh connect arguments (outside of hostname) are provided then only the remote
        machine tried for existing creds at 'self._credpath'.
        - If credpath was provided the local file system will first be tried for existing
        credentials
        - If aws access and secret keys were provided allong with hostname, will attempt to
        derivce service credpaths from the Eucalyptus Admin api.
        -Finally if a hostname was provided an ssh attempt will be made (with any other
         connection kwargs provided)to fetch from the remote system as well.
         If password or keypath was not provided, this assumes keys have been sync'd between the
         localhost and the remote machine.
        Upon the first successful discovery of credentials, the local obj is populated with
        eucarc attributes and returns.
        """

        def try_local(self):
            if self._credpath:
                try:
                    res = self.get_local_eucarc(credpath=self._credpath)
                    if res:
                        self.debug('Found local creds at: "{0}"'.format(self._credpath))
                        return res
                except IOError:
                    pass

        def try_serviceconnection(self):
            if self.aws_secret_key and self.aws_access_key and self._clc_ip:
                self._connect_services()
                try:
                    res = self.update_attrs_from_cloud_services()
                    if res:
                        self.debug('Derived creds from serviceconnection')
                        return res
                except RuntimeError as RE:
                    self.debug('{0}\nFailed to update creds using serviceconnection, err:"{1}"'
                               .format(get_traceback(), str(RE)))
                    self._close_adminpi()

        def try_remote(self):
            if self._clc_ip and self._credpath:
                try:
                    machine = self.clc_machine or self.connect_to_clc()
                    if machine:
                        try:
                            if not self._keysdir:
                                self._keysdir = machine.get_abs_path(self._credpath)
                        except:
                            pass
                        res = self.get_remote_eucarc(credpath=self._credpath, machine=machine)
                        if res:
                            self.debug('Found remote creds on:"{0}", at path:"{1}"'
                                       .format(self.clc_machine.ssh.host, self._credpath))
                            return res
                except Exception as e:
                    self.debug("{0}\nFailed to fetch creds remotely, err:'{1}'"
                               .format(get_traceback(), str(e)))

        def try_clc_db(self):
            self.debug('trying clc db...')
            if self._clc_ip and self.aws_account_name and self.aws_user_name:
                machine = self.clc_machine or self.connect_to_clc()
                if machine:
                    try:
                        res = self.get_existing_keys_from_clc(account=self.aws_account_name,
                                                              user=self.aws_user_name,
                                                              machine=machine)
                        try:
                            # With keys, try filling in remainder with service urls/attributes
                            # using the admin api interface...
                            res = self.update_attrs_from_cloud_services()
                        except:
                            pass
                        return res
                    except RuntimeError as RE:
                        self.debug('{0}\nFailed to fetch creds from clc db, err:{1}'
                                   .format(get_traceback(), str(RE)))


        default_order = [try_local, try_serviceconnection, try_remote, try_clc_db]
        if self._clc_ip and self._credpath and self._has_updated_connect_args:
            # if any ssh related arguements were provided, assume the user would like
            # to try remote first
            if try_remote(self):
                return
            default_order.remove(try_remote)
            raise ValueError('Could not find "remote" creds with provided information.')
        else:
            for meth in default_order:
                if meth(self):
                    return
            raise ValueError("Could not find path with provided information.")

    def get_existing_keys_from_clc(self, account, user, machine=None, eucahome=None, port=8777,
                                   dbuser='eucalyptus', p12file=None, pkfile=None,
                                   passphrase=None, db=None, pargs=None, verbose=False):
        ret = {}
        db = db or 'eucalyptus_shared'
        pargs = pargs or ""
        machine = machine or self.clc_machine
        passphrase = None or 'eucalyptus'
        eucahome = eucahome or EucaHost._get_eucalyptus_home(machine) or '/'
        EucaP12File = p12file or os.path.join(eucahome, '/var/lib/eucalyptus/keys/euca.p12')
        CloudPKFile = pkfile or os.path.join(eucahome, '/var/lib/eucalyptus/keys/cloud-pk.pem')
        cmd = ("echo -n '{0}' | openssl SHA256  -sign {1} | sha256sum"
               .format(passphrase, CloudPKFile))
        out = machine.sys(cmd, code=0, verbose=verbose)
        if out:
            dbpass = str(out[0]).split()[0]

        dbsel = ("\"select k.auth_access_key_query_id, k.auth_access_key_key, "
                 "a.auth_account_number, a.auth_account_name, c.auth_certificate_pem "
                 "from eucalyptus_auth.auth_access_key k "
                 "join eucalyptus_auth.auth_user u on k.auth_access_key_owning_user=u.id "
                 "join eucalyptus_auth.auth_cert c on c.auth_certificate_owning_user=u.id "
                 "join eucalyptus_auth.auth_group_has_users gu on gu.auth_user_id = u.id "
                 "join eucalyptus_auth.auth_group g on gu.auth_group_id=g.id "
                 "join eucalyptus_auth.auth_account a on g.auth_group_owning_account=a.id "
                 "where a.auth_account_name = '{0}' and g.auth_group_name = '{1}'\";"
                 .format(account, "_" + user))
        dbcmd = ('export PGPASSWORD={0}; psql {1} -A -F "," -h 127.0.0.1 -p {2} -U {3} -d {4} '
                 '-c {5}'.format(dbpass, pargs, port, dbuser, db, dbsel))
        qout = machine.sys(dbcmd, code=0, verbose=verbose)
        if qout:
            try:
                names = qout[0].split(',')
                values = qout[1].split(',')
                ret['AWS_ACCESS_KEY'] = values[names.index('auth_access_key_query_id')]
                ret['AWS_SECRET_KEY'] = values[names.index('auth_access_key_key')]
                ret['EC2_ACCOUNT_NUMBER'] = values[names.index('auth_account_number')]
                ret['EC2_ACCOUNT_NAME'] = values[names.index('auth_account_name')]
                ret['CERT'] = values[names.index('auth_certificate_pem')]
                self.aws_access_key = ret['AWS_ACCESS_KEY']
                self.aws_secret_key = ret['AWS_SECRET_KEY']
                self.ec2_user_id = ret['EC2_ACCOUNT_NUMBER']
                self.ec2_account_number = ret['EC2_ACCOUNT_NUMBER']
                self.ec2_account_name = ret['EC2_ACCOUNT_NAME']
            except Exception as PE:
                self.log.error('Output:\n{0}\nFailed parsing creds lookup output, err:{1}'
                               .format("\n".join(qout), str(PE)))
                raise PE
        return ret

    def create_local_creds(self, local_destdir, machine=None, overwrite=False):
        """
        Attempts to create a local set of files containing the current credential artifacts
        in this AutoCreds obj. The following files will be written to the provided
        'local_destdir' directory:
        - A eucarc file containing the "export key=value" syntax to resolve service urls
          and the location of any credentials related files.
        - Any current attributes with an sftp:// uri will be downloaded to local_destdir. At this
        time the AutoCred eucarc attributes will be updated to represent their now local filepath,
        an the local eucarc written will also reflect the new location.
        :params local_destdir: local directory to write cred files to.
                               Will create if does not exist.
        :params machine: The Machine() obj to download any sftp:// files from
        :params overwrite: bool, if True will overwrite any existing items at 'local_destdir'
        """
        machine = machine or self.clc_machine
        has_sftp_items = False
        local_destdir = os.path.abspath(local_destdir)
        for key, value in self.get_eucarc_attrs().iteritems():
            if re.search('^sftp://', value):
                has_sftp_items = True
        if has_sftp_items:
            if not machine:
                if not self._has_updated_connect_args:
                    self.log.info('Remote machine info has not been provided, '
                                  'skipping remote creds download')
                else:
                    machine = self.connect_to_clc()
            self._download_remote_artifacts(local_destdir=local_destdir, machine=machine,
                                            overwrite=overwrite)
        self.debug('Finished creating new local creds at: {0}'.format(local_destdir))
        # Now write the eucarc file. Any downloaded files should have updated the
        # local euarc attrs replacing the sftp uri with a local file path
        eucarc_path = os.path.join(local_destdir, 'eucarc')
        with open(eucarc_path, 'w') as eucarc:
            eucarc.seek(0)
            for key, value in self.get_eucarc_attrs().iteritems():
                if not re.search('^sftp://', value):
                    eucarc.write("export {0}={1}\n".format(str(key).upper(), value))
            eucarc.flush()
        self.debug('Finished creating new local creds at: {0}'.format(local_destdir))

    def _download_remote_artifacts(self, local_destdir, machine, sftp_prefix='^sftp://',
                                   overwrite=False):
        """
        Attempts to download any eucarc artifacts which current has an sftp:// url.
        To see these values use self.show() or self.get_eucarc_attrs() dict.
        :params local_destdir: Local directory to download the remote files to
        :params machine: remote machine object to download the files from
        :params sftp_prefeix: The search criteria for determining which eucarc artifacts
                              should be downloaded.
        :params overwrite: bool, if True will overwrite any existing items at 'local_destdir'
        returns the local path (string) items were downloaded to upon success
        """
        if not isinstance(machine, Machine):
            raise ValueError('_download_remote_artifacts requires Machine() type. Got:"{0}/{1}"'
                             .format(machine, type(machine)))
        if not isinstance(local_destdir, basestring):
            raise ValueError('_download_remote_artifacts requires string for local_destdir(). '
                             'Got:"{0}/{1}"'.format(local_destdir, type(local_destdir)))
        if not os.path.exists(local_destdir):
            os.makedirs(local_destdir)
        else:
            if not os.path.isdir(local_destdir):
                raise ValueError('Provided local_destdir exists and is not a directory:"{0}"'
                                 .format(local_destdir))
            if not overwrite:
                raise ValueError('local_destdir exists. set "overwrite=True" to write over '
                                 'existing contents: {0}'.format(local_destdir))
        local_destdir = os.path.abspath(local_destdir)
        for key, path in self.get_eucarc_attrs().iteritems():
            if not key.startswith('_') and re.search(sftp_prefix, str(path)):
                urlp = urlparse(path)
                if not self.clc_machine.hostname == urlp.hostname:
                    raise ValueError('sftp uri hostname:{0} does not match current Machines:{1}'
                                     .format(urlp.hostname, machine.hostname))
                artifact_name = os.path.basename(urlp.path)
                localpath = os.path.join(local_destdir, artifact_name)
                machine.sftp.get(remotepath=urlp.path, localpath=localpath)
                setattr(self, key, localpath)
                self.debug('Wrote: {0} to local:{1}'.format(key, localpath))
        return local_destdir

    # Todo Clean up the legacy methods below...

    def _legacy_create_credentials(self, clc, admin_cred_dir, account, user, zipfile='creds.zip'):
        zipfilepath = os.path.join(admin_cred_dir, zipfile)
        output = self.credential_exist_on_remote_machine(zipfilepath)
        if output['status'] == 0:
            self.debug("Found creds file, skipping euca_conf --get-credentials.")
        else:
            cmd_download_creds = str("{0}/usr/sbin/euca_conf --get-credentials {1}/creds.zip "
                                     "--cred-user {2} --cred-account {3}"
                                     .format(self.eucapath, admin_cred_dir, user, account))
            if self.clc.found(cmd_download_creds, "The MySQL server is not responding"):
                raise IOError("Error downloading credentials, looks like CLC was not running")
            if self.clc.found("unzip -o {0}/creds.zip -d {1}"
                              .format(admin_cred_dir, admin_cred_dir),
                              "cannot find zipfile directory"):
                raise IOError("Empty ZIP file returned by CLC")
        return zipfilepath

    def get_active_cert_for_creds(self, credzippath=None, account=None, user=None, update=True,
                                  machine=None):
        if credzippath is None:
            if hasattr(self, 'cred_zipfile') and self.cred_zipfile:
                credzippath = self.cred_zipfile
            elif self.credpath:
                credzippath = self.credpath
            else:
                raise ValueError('cred zip file not provided or set for AutoCred obj')
        machine = machine or self.clc_machine
        account = account or self.account_name
        user = user or self.aws_username
        admin_cred_dir = os.path.dirname(credzippath)
        clc_eucarc = os.path.join(admin_cred_dir, 'eucarc')
        # backward compatibility
        certpath_in_eucarc = machine.sys(". {0} &>/dev/null && "
                                         "echo $EC2_CERT".format(clc_eucarc))
        if certpath_in_eucarc:
            certpath_in_eucarc = certpath_in_eucarc[0]
        self.debug('Current EC2_CERT path for {0}: {1}'.format(clc_eucarc, certpath_in_eucarc))
        if certpath_in_eucarc and self.get_active_id_for_cert(certpath_in_eucarc):
            self.debug("Cert/pk already exist and is active in '" +
                       admin_cred_dir + "/eucarc' file.")
        else:
            # Try to find existing active cert/key on clc first. Check admin_cred_dir then
            # do a recursive search from ssh user's home dir (likely root/)
            self.debug('Attempting to find an active cert for this account on the CLC...')
            certpaths = (self.find_active_cert_and_key_in_dir(dir=admin_cred_dir) or
                         self.find_active_cert_and_key_in_dir())
            self.debug('Found Active cert and key paths')
            if not certpaths:
                # No existing and active certs found, create new ones...
                self.debug('Could not find any existing active certs on clc, '
                           'trying to create new ones...')
                certpaths = self.create_new_user_certs(admin_cred_dir, account, user)
            # Copy cert and key into admin_cred_dir
            certpath = certpaths.get('certpath')
            keypath = certpaths.get('keypath')
            newcertpath = os.path.join(admin_cred_dir, os.path.basename(certpath))
            newkeypath = os.path.join(admin_cred_dir, os.path.basename(keypath))
            self.debug('Using certpath:{0} and keypath:{1} on clc'
                       .format(newcertpath, newkeypath))
            machine.sys('cp {0} {1}'.format(certpath, newcertpath))
            machine.sys('cp {0} {1}'.format(keypath, newkeypath))
            # Update the existing eucarc with new cert and key path info...
            self.debug("Setting cert/pk in '" + admin_cred_dir + "/eucarc'")
            machine.sys("echo 'export EC2_CERT=${EUCA_KEY_DIR}/" + "{0}' >> {1}"
                        .format(os.path.basename(newcertpath), clc_eucarc))
            machine.sys("echo 'export EC2_PRIVATE_KEY=${EUCA_KEY_DIR}/" + "{0}' >> {1}"
                        .format(os.path.basename(newkeypath), clc_eucarc))
            self.debug('updating zip file with new cert, key and eucarc: {0}'
                       .format(credzippath))
            for updatefile in [os.path.basename(newcertpath), os.path.basename(newkeypath),
                               os.path.basename(clc_eucarc)]:
                machine.sys('cd {0} && zip -g {1} {2}'
                            .format(os.path.dirname(credzippath),
                                    os.path.basename(credzippath),
                                    updatefile), code=0)
            return credzippath

    def create_new_user_certs(self, admin_cred_dir, account, user, force_cert_create=False,
                              newcertpath=None, newkeypath=None, machine=None):
        machine = machine or self.clc_machine
        eucarcpath = os.path.join(admin_cred_dir, 'eucarc')
        newcertpath = newcertpath or os.path.join(admin_cred_dir, "euca2-cert.pem")
        newkeypath = newkeypath or os.path.join(admin_cred_dir, "/euca2-pk.pem")
        # admin_certs = machine.sys("source {0} && /usr/bin/euare-userlistcerts | grep -v Active"
        #                           .format(eucarcpath))
        admin_certs = []
        for cert in self.get_active_certs():
            admin_certs.append(cert.get('certificate_id'))
        if len(admin_certs) > 1:
            if force_cert_create:
                self.debug("Found more than one certs, deleting last cert")
                machine.sys(". {0} &>/dev/null && "
                            "/usr/bin/euare-userdelcert -c {1} --user-name {2}"
                            .format(eucarcpath,
                                    admin_certs[admin_certs.pop()],
                                    user),
                            code=0)
            else:
                raise RuntimeWarning('No active certs were found on the clc, and there are 2'
                                     'certs outstanding. Either delete an existing '
                                     'cert or move and active cert into clc root dir.'
                                     'The option "force_cert_create" will "delete" an existing'
                                     'cert automatically and replace it.'
                                     'Warning: deleting existing certs may leave signed'
                                     'objects in cloud unrecoverable.')
        self.debug("Creating a new signing certificate for user '{0}' in account '{1}'."
                   .format(user, account))
        self.debug('New cert name:{0}, keyname:{1}'.format(os.path.basename(newcertpath),
                                                           os.path.basename(newkeypath)))

        machine.sys(". {0} &>/dev/null && "
                    "/usr/bin/euare-usercreatecert --user-name {1} --out {2} --keyout {3}"
                    .format(eucarcpath,
                            user,
                            newcertpath,
                            newkeypath),
                    code=0)
        return {"certpath": newcertpath, "keypath": newkeypath}

    def get_active_certs(self):
        """
        Query system for active certs list
        :returns :list of active cert dicts
        """
        if not hasattr(self, 'euare') or not self.euare:
            self.critical(self.markup('Cant update certs until euare interface '
                                      'is initialized', 91))
            return []
        certs = []
        resp = self.euare.get_all_signing_certs()
        if resp:
            cresp = resp.get('list_signing_certificates_response')
            if cresp:
                lscr = cresp.get('list_signing_certificates_result')
                if lscr:
                    certs = lscr.get('certificates', [])
        return certs

    def get_active_id_for_cert(self, certpath, machine=None):
        """
        Attempt to get the cloud's active id for a certificate at 'certpath' on
        the 'machine' filesystem. Also see is_ec2_cert_active() for validating the current
        cert in use or the body (string buffer) of a cert.
        :param certpath: string representing the certificate path on the machines filesystem
        :param machine: Machine obj which certpath exists on
        :returns :str() certificate id (if cert is found to be active) else None
        """
        if not certpath:
            raise ValueError('No ec2 certpath provided or set for eutester obj')
        machine = machine or self.clc
        self.debug('Verifying cert: "{0}"...'.format(certpath))
        body = str("\n".join(machine.sys('cat {0}'.format(certpath), verbose=False))).strip()
        certs = []
        if body:
            certs = self.get_active_certs()
        for cert in certs:
            if str(cert.get('certificate_body')).strip() == body:
                self.debug('verified certificate with id "{0}" is still valid'
                           .format(cert.get('certificate_id')))
                return cert.get('certificate_id')
        self.debug('Cert: "{0}" is NOT active'.format(certpath or body))
        return None

    def find_active_cert_and_key_in_dir(self, dir="", machine=None, recursive=True):
        """
        Attempts to find an "active" cert and the matching key files in the provided
        directory 'dir' on the provided 'machine' via ssh.
        If recursive is enabled, will attempt a recursive search from the provided directory.
        :param dir: the base dir to search in on the machine provided
        :param machine: a Machine() obj used for ssh search commands
        :param recursive: boolean, if set will attempt to search recursively from the dir provided
        :returns dict w/ values 'certpath' and 'keypath' or {} if not found.
        """
        machine = machine or self.clc_machine
        ret_dict = {}
        if dir and not dir.endswith("/"):
            dir += "/"
        if recursive:
            rec = "r"
        else:
            rec = ""
        certfiles = machine.sys(
            'grep "{0}" -l{1} {2}*.pem'.format('^-*BEGIN CERTIFICATE', rec, dir))
        for f in certfiles:
            if self.get_active_id_for_cert(f, machine=machine):
                dir = os.path.dirname(f)
                keypath = self.get_key_for_cert(certpath=f, keydir=dir, machine=machine)
                if keypath:
                    self.debug('Found existing active cert and key on clc: {0}, {1}'
                               .format(f, keypath))
                    return {'certpath': f, 'keypath': keypath}
        return ret_dict

    def get_key_for_cert(self, certpath, keydir, machine=None, recursive=True):
        """
        Attempts to find a matching key for cert at 'certpath' in the provided directory 'dir'
        on the provided 'machine'.
        If recursive is enabled, will attempt a recursive search from the provided directory.
        :param dir: the base dir to search in on the machine provided
        :param machine: a Machine() obj used for ssh search commands
        :param recursive: boolean, if set will attempt to search recursively from the dir provided
        :returns string representing the path to the key found or None if not found.
        """
        machine = machine or self.clc_machine
        self.debug('Looking for key to go with cert...')
        if keydir and not keydir.endswith("/"):
            keydir += "/"
        if recursive:
            rec = "r"
        else:
            rec = ""
        certmodmd5 = machine.sys('openssl x509 -noout -modulus -in {0}  | md5sum'
                                 .format(certpath))
        if certmodmd5:
            certmodmd5 = str(certmodmd5[0]).strip()
        else:
            return None
        keyfiles = machine.sys('grep "{0}" -lz{1} {2}*.pem'
                               .format("^\-*BEGIN RSA PRIVATE KEY.*\n.*END RSA PRIVATE KEY\-*",
                                       rec, keydir))
        for kf in keyfiles:
            keymodmd5 = machine.sys('openssl rsa -noout -modulus -in {0} | md5sum'.format(kf))
            if keymodmd5:
                keymodmd5 = str(keymodmd5[0]).strip()
            if keymodmd5 == certmodmd5:
                self.debug('Found key {0} for cert {1}'.format(kf, certpath))
                return kf
        return None

    def is_ec2_cert_active(self, certbody=None):
        """
        Attempts to verify if the current self.ec2_cert @ self.ec2_certpath is still active.
        :param certbody
        :returns the cert id if found active, otherwise returns None
        """
        certbody = certbody or self.ec2_cert
        if not certbody:
            raise ValueError('No ec2 cert body provided or set for eutester to check for active')
        if isinstance(certbody, dict):
            checkbody = certbody.get('certificate_body')
            if not checkbody:
                raise ValueError('Invalid certbody provided, did not have "certificate body" attr')
        for cert in self.get_active_certs():
            body = str(cert.get('certificate_body')).strip()
            if body and body == str(certbody).strip():
                return cert.get('certificate_id')
        return None

    def credential_exist_on_remote_machine(self, cred_path, machine=None):
        machine = machine or self.clc_machine
        return machine.ssh.cmd("test -e " + cred_path)

    def download_creds_from_clc(self, admin_cred_dir, zipfile="creds.zip"):

        zipfilepath = os.path.join(admin_cred_dir, zipfile)
        self.debug("Downloading credentials from " + self.clc.hostname + ", path:" + zipfilepath +
                   " to local file: " + str(zipfile))
        self.sftp.get(zipfilepath, zipfilepath)
        unzip_cmd = "unzip -o {0} -d {1}".format(zipfilepath, admin_cred_dir)
        self.debug('Trying unzip cmd: ' + str(unzip_cmd))
        self.local(unzip_cmd)
        # backward compatibility
        cert_exists_in_eucarc = self.found("cat " + admin_cred_dir + "/eucarc", "export EC2_CERT")
        if cert_exists_in_eucarc:
            self.debug("Cert/pk already exist in '" + admin_cred_dir + "/eucarc' file.")
        else:
            self.download_certs_from_clc(admin_cred_dir=admin_cred_dir, update_eucarc=True)

    def download_certs_from_clc(self, admin_cred_dir=None, update_eucarc=True, machine=None):
        machine = machine or self.clc_machine
        admin_cred_dir = admin_cred_dir or self.credpath
        self.debug("Downloading certs from " + self.clc.hostname + ", path:" +
                   admin_cred_dir + "/")
        clc_eucarc = os.path.join(admin_cred_dir, 'eucarc')
        local_eucarc = os.path.join(admin_cred_dir, 'eucarc')
        remotecertpath = machine.sys(". {0} &>/dev/null && "
                                     "echo $EC2_CERT".format(clc_eucarc))
        if remotecertpath:
            remotecertpath = remotecertpath[0]
        remotekeypath = machine.sys(". {0} &>/dev/null && "
                                    "echo $EC2_PRIVATE_KEY".format(clc_eucarc))
        if remotekeypath:
            remotekeypath = remotekeypath[0]
        if not remotecertpath or not remotekeypath:
            self.critical('CERT and KEY paths not provided in {0}'.format(clc_eucarc))
            return {}
        localcertpath = os.path.join(admin_cred_dir, os.path.basename(remotecertpath))
        localkeypath = os.path.join(admin_cred_dir, os.path.basename(remotekeypath))
        self.sftp.get(remotecertpath, localcertpath)
        self.sftp.get(remotekeypath, localkeypath)
        if update_eucarc:
            self.debug("Setting cert/pk in '{0}".format(local_eucarc))
            self.local("echo 'export EC2_CERT=${EUCA_KEY_DIR}/" +
                       str(os.path.basename(localcertpath)) + "' >> " + local_eucarc)
            self.local("echo 'export EC2_PRIVATE_KEY=${EUCA_KEY_DIR}/" +
                       str(os.path.basename(localkeypath)) + "' >> " + local_eucarc)
        return {'certpath': localcertpath, 'keypath': localkeypath}

    def send_creds_to_machine(self, admin_cred_dir, machine, filename='creds.zip'):
        filepath = os.path.join(admin_cred_dir, filename)
        self.debug("Sending credentials to " + machine.hostname)
        localmd5 = None
        remotemd5 = None
        try:
            machine.sys('ls ' + filepath, code=0)
            remotemd5 = self.get_md5_for_file(filepath, machine=machine)
            localmd5 = self.get_md5_for_file(filepath)
        except CommandExitCodeException:
            pass
        if not remotemd5 or (remotemd5 != localmd5):
            machine.sys("mkdir " + admin_cred_dir)
            machine.sftp.put(admin_cred_dir + "/creds.zip", admin_cred_dir + "/creds.zip")
            machine.sys("unzip -o " + admin_cred_dir + "/creds.zip -d " + admin_cred_dir)
        else:
            self.debug("Machine " + machine.hostname + " already has credentials in place not "
                                                       " sending")

    def setup_local_creds_dir(self, admin_cred_dir):
        if not os.path.exists(admin_cred_dir):
            os.mkdir(admin_cred_dir)

    def setup_remote_creds_dir(self, admin_cred_dir):
        self.sys("mkdir " + admin_cred_dir)

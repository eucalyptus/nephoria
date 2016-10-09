

import logging

import yaml
from cloud_admin.systemconnection import SystemConnection
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import get_traceback
from cloud_utils.system_utils.machine import Machine
from nephoria.usercontext import UserContext
from nephoria import __DEFAULT_API_VERSION__
from boto3 import set_stream_logger


def set_boto_logger_level(level='NOTSET', format_string=None):
    """
    Set the global boto loggers levels to 'level'. ie "DEBUG", "INFO", "CRITICAL"
    default is "NOTSET"
    :param level: string matching logging class levels, or integer representing the equiv value
    :param format_string: logging class formatter string
    """
    level = Eulogger.format_log_level(level, 'NOTSET')
    set_stream_logger('boto', level=level, format_string=None)
    set_stream_logger('boto3', level=level, format_string=None)
    set_stream_logger('botocore', level=level, format_string=None)


class SystemConnectionFailure(Exception):
    pass

class TestController(object):
    def __init__(self,
                 hostname=None, username='root', password=None, keypath=None, region=None,
                 domain=None,
                 proxy_hostname=None, proxy_password=None,
                 clouduser_account='nephotest', clouduser_name='sys_admin', clouduser_credpath=None,
                 clouduser_accesskey=None, clouduser_secretkey=None,
                 cloudadmin_credpath=None, cloudadmin_accesskey=None, cloudadmin_secretkey=None,
                 timeout=10, log_level='DEBUG', log_file=None, log_file_level='DEBUG',
                 environment_file=None, https=False, validate_certs=False,
                 cred_depot_hostname=None, cred_depot_username='root', cred_depot_password=None,
                 boto2_api_version=None):

        """

        :param hostname: CLC ssh hostname
        :param username: CLC ssh username
        :param password: CLC ssh password
        :param proxy_hostname: CLC ssh proxy hostname
        :param proxy_password: CLC ssh proxy password
        :param clouduser_account:
        :param clouduser_name:
        :param clouduser_credpath:
        :param clouduser_accesskey:
        :param clouduser_secretkey:
        :param cloudadmin_credpath:
        :param cloudadmin_accesskey:
        :param cloudadmin_secretkey:
        :param timeout:
        """
        if isinstance(log_level, basestring):
            log_level = getattr(logging, log_level.upper(), logging.DEBUG)
        self.log = Eulogger("TESTER:{0}".format(hostname), stdout_level=log_level,
                            logfile=log_file, logfile_level=log_file_level)
        if not hostname and environment_file:
            try:
                component = self.get_component_from_topology(environment_file, 'clc-1')
                hostname = component['clc-1']
            except KeyError:
                component = self.get_component_from_topology(environment_file,
                                                             'clc')
                hostname = component['clc'][0]
        self.log.identifier = "TESTER:{0}".format(hostname)
        self.log = Eulogger("TESTER:{0}".format(hostname), stdout_level=log_level)
        self._region = region
        self._sysadmin = None
        self._cloudadmin = None
        self._test_user = None
        self._cred_depot = None
        self._default_timeout = timeout
        self._domain = domain
        self._https = https
        self._validate_certs = validate_certs
        self._cloud_admin_connection_info = {}
        self._test_user_connection_info = {}
        boto2_api_version = boto2_api_version or __DEFAULT_API_VERSION__
        self._system_connection_info = {'hostname': hostname,
                                        'username': username,
                                        'password': password,
                                        'keypath': keypath,
                                        'proxy_hostname': proxy_hostname,
                                        'proxy_password': proxy_password,
                                        'proxy_username': None,
                                        'config_qa': None,
                                        'credpath': cloudadmin_credpath,
                                        'aws_access_key': cloudadmin_accesskey,
                                        'aws_secret_key': cloudadmin_secretkey,
                                        'log_level': log_level,
                                        'boto_debug_level': 0,
                                        'euca_user': 'admin',
                                        'euca_account': 'eucalyptus',
                                        'https': https,
                                        'domain': domain}

        self._cloud_admin_connection_info = {'aws_account_name': 'eucalyptus',
                                             'aws_user_name': 'admin',
                                             'credpath': cloudadmin_credpath,
                                             'region': self.region,
                                             'domain': self.domain,
                                             'aws_access_key': cloudadmin_accesskey,
                                             'aws_secret_key': cloudadmin_secretkey,
                                             'service_connection': self.sysadmin,
                                             'log_level': log_level,
                                             'validate_certs': validate_certs,
                                             'boto2_api_version': boto2_api_version,
                                             'https': https}

        self._test_user_connection_info = {'aws_account_name': clouduser_account,
                                           'aws_user_name': clouduser_name,
                                           'credpath': clouduser_credpath,
                                           'aws_access_key': clouduser_accesskey,
                                           'aws_secret_key': clouduser_secretkey,
                                           'region': self.region,
                                           'domain': self.domain,
                                           'log_level': log_level,
                                           'validate_certs': validate_certs,
                                           'boto2_api_version': boto2_api_version,
                                           'https': https}

        self._cred_depot_connection_info = {'hostname': cred_depot_hostname,
                                            'username': cred_depot_username,
                                            'password': cred_depot_password or password,
                                            'log_level': log_level}

        # TODO ??
        self.test_resources = \
            {
                '_instances': [],
                '_volumes': []
            }

    def __repr__(self):
        try:
            myrepr = "{0}:{1}(sysadmin+eucalyptus/admin)".format(
                self.__class__.__name__,
                self._system_connection_info.get('hostname', ""))
            return myrepr
        except Exception as E:
            self.log.debug(E)
            return str(self.__class__.__name__)

    @property
    def domain(self):
        if self._domain is None:
            prop_name = 'system.dns.dnsdomain'
            try:
                # First try from the cloud property...
                region_prop = self.sysadmin.get_property(prop_name)
                if region_prop.value:
                    self._domain = region_prop.value
            except Exception as E:
                self.log.error('{0}\nError fetching cloud property:"{1}". Error:"{2}"'
                               .format(get_traceback(), prop_name, E))
        return self._domain or self.region

    @property
    def region(self):
        return self._region

    @region.setter
    def region(self, value):
        if self._region is not None and self._region != value:
            self.log.error('Can not change region once it has been set')
            raise ValueError('Can not change region once it has been set')
        self._cloud_admin_connection_info['region'] = value
        self._test_user_connection_info['region'] = value
        self._region = value

    @property
    def cred_depot(self):
        if not self._cred_depot and self._cred_depot_connection_info.get('hostname'):
            try:
                self._cred_depot = Machine(**self._cred_depot_connection_info)
            except Exception as E:
                self.log.error('{0}\nError connecting to cred depot machine:"{1}"'
                               .format(get_traceback(), E))
                raise E
        return self._cred_depot

    @property
    def sysadmin(self):
        if not self._sysadmin:
            if not self._system_connection_info.get('hostname', None):
                return None
            try:
                self._sysadmin = SystemConnection(**self._system_connection_info)
            except Exception as TE:
                self.log.error('{0}\nCould not create sysadmin interface, timed out: "{1}"'
                                  .format(get_traceback(), TE))
                raise TE
        return self._sysadmin

    @property
    def admin(self):
        if not self._cloudadmin:
            try:
                conn_info = self._cloud_admin_connection_info
                if (conn_info.get('credpath') or
                    (conn_info.get('aws_access_key') and conn_info.get('aws_secret_key'))):
                    if conn_info.get('credpath'):
                        conn_info['machine'] = self.cred_depot
                else:
                    rc_config = self.sysadmin.creds or {}
                    rc_config.domain = self.domain
                    rc_config.region = self.region
                    conn_info['eucarc'] = rc_config
                self._cloudadmin = UserContext(**conn_info)
            except Exception as E:
                self.log.error('{0}\nError creating admin user, err:"{1}"'
                               .format(get_traceback(), E))
                raise E
        return self._cloudadmin

    @property
    def user(self):
        if not self._test_user:
            try:
                self._test_user = self.create_user_using_cloudadmin(
                    **self._test_user_connection_info)
            except Exception as E:
                self.log.error('{0}\nError Creating test user, error:"{1}"'
                               .format(get_traceback(), E))
                raise E
        return self._test_user

    @user.setter
    def user(self, user):
        if user is None:
            self._test_user = None
        if isinstance(user, UserContext):
            self._test_user = user
            return
        raise ValueError('Unsupported type for test_user:"{0}", "{1}"'.format(user, type(user)))

    def reset_connections(self):
        self._sysadmin = None
        self._cloudadmin = None
        self._test_user = None

    def get_user_by_name(self, aws_account_name, aws_user_name,
                         machine=None, service_connection=None, region=None, domain=None,
                         validate_certs=False, path='/',
                         https=None, log_level=None, boto2_api_version=None):
        """
        Fetch an existing cloud user and convert into a usercontext object.
        For checking basic existence of a cloud user, use the iam interface instead.
        """
        boto2_api_version = boto2_api_version or \
                            self._test_user_connection_info.get('boto2_api_version', None)
        try:
            user = self.admin.iam.get_user_info(user_name=aws_user_name,
                                                delegate_account=aws_account_name)
        except Exception:
            self.log.error('Error fetching "account:{0}, user:{1}" has this user been created '
                           'already?'.format(aws_account_name, aws_user_name))
            raise
        if user:
            return self.create_user_using_cloudadmin(aws_account_name=aws_account_name,
                                                     aws_user_name=aws_user_name,
                                                     region=region, domain=domain,
                                                     validate_certs=validate_certs,
                                                     machine=machine,
                                                     service_connection=service_connection,
                                                     path=path, https=https, log_level=log_level,
                                                     boto2_api_version=boto2_api_version)
        else:
            raise ValueError('User info not returned for "account:{0}, user:{1}"'
                             .format(aws_account_name, aws_user_name))


    def create_user_using_cloudadmin(self, aws_account_name=None, aws_user_name='admin',
                                     aws_access_key=None, aws_secret_key=None,
                                     credpath=None, eucarc=None,
                                     machine=None, service_connection=None, path='/',
                                     region=None, domain=None, https=None,
                                     validate_certs=False,
                                     boto2_api_version=None, log_level=None):
        if log_level is None:
            log_level = self.log.stdout_level or 'DEBUG'
        if region is None:
            region = self.region
        if domain is None:
            domain = self.domain
        if https is None:
            https = self._https
        boto2_api_version = boto2_api_version or \
                            self._test_user_connection_info.get('boto2_api_version', None)
        self.log.debug('Attempting to create user with params: account:{0}, name:{1}'
                          'access_key:{2}, secret_key:{3}, credpath:{4}, eucarc:{5}'
                          ', machine:{6}, service_connection:{7}, path:{8}, region:{9},'
                          'loglevel:{10}, https:{11}'
                       .format(aws_account_name, aws_user_name, aws_access_key, aws_secret_key,
                               credpath, eucarc, machine, service_connection, path, region,
                               log_level, https))
        service_connection = service_connection or self.sysadmin
        if eucarc:
            if aws_access_key:
                eucarc.access_key = aws_access_key
            if aws_secret_key:
                eucarc.secret_key = aws_secret_key
            if aws_user_name:
                eucarc.user_name = aws_user_name
            if aws_account_name:
                eucarc.account_name = aws_account_name

            return UserContext(eucarc=eucarc,
                               region=region,
                               domain=domain,
                               service_connection=service_connection,
                               log_level=log_level,
                               https=https,
                               boto2_api_version=boto2_api_version)
        if aws_access_key and aws_secret_key:
            return UserContext(aws_access_key=aws_access_key,
                               aws_secret_key=aws_secret_key,
                               aws_account_name=aws_account_name,
                               aws_user_name=aws_user_name,
                               region=region,
                               domain=domain,
                               service_connection=service_connection,
                               log_level=log_level,
                               boto2_api_version=boto2_api_version,
                               https=https)
        if credpath:
            return UserContext(credpath=credpath,
                               region=region,
                               domain=domain,
                               machine=machine,
                               log_level=log_level,
                               boto2_api_version=boto2_api_version)

        info = self.admin.iam.create_account(account_name=aws_account_name,
                                                  ignore_existing=True)
        if info:
            user = self.admin.iam.create_user(user_name=aws_user_name,
                                              delegate_account=info.get('account_name'),
                                              path=path)
            info.update(user)
        else:
            raise RuntimeError('Failed to create and/or fetch Account:"{0}", for User:"{1}"'
                               .format(aws_account_name, aws_user_name))
        ak = self.admin.iam.get_aws_access_key(user_name=info.get('user_name'),
                                               delegate_account=info.get('account_name'))
        if not ak:
            ak = self.admin.iam.create_access_key(user_name=info.get('user_name'),
                                                  delegate_account=info.get('account_name'))
        try:
            info['access_key_id'] = ak['access_key_id']
        except KeyError:
            err_msg = ('Failed to fetch access key for USER:"{0}", ACCOUNT:"{1}"'
                       .format(aws_user_name, aws_account_name))
            self.log.error('{0}\n{1}'.format(get_traceback(), err_msg))
            raise RuntimeError(err_msg)
        if self.admin.iam.get_all_signing_certs(user_name=info.get('user_name'),
                                                delegate_account=info.get('account_name')):
            certs = True
        else:
            certs = False
        user =  UserContext(aws_access_key=info.get('access_key_id'),
                            aws_secret_key=info.get('secret_access_key'),
                            aws_account_name=info.get('account_name'),
                            aws_user_name=info.get('user_name'),
                            region=region,
                            domain=domain,
                            existing_certs=certs,
                            machine=self.sysadmin.clc_machine,
                            service_connection=self.sysadmin,
                            log_level=log_level,
                            boto2_api_version=boto2_api_version,
                            https=https)
        user._user_info = self.admin.iam.get_user_info(user_name=user.user_name,
                                                       delegate_account=user.account_id)
        return user

    def dump_conn_debug(self, info):
        """
        Helper method to format and display the connection info contained in a specific dict.
        Example: self.dump_conn_debug(self._system_connection_info)
        :param info:  connection dict.
        """
        try:
            self.log.debug(
                    'Connection info:\n{0}'
                    .format("\n".join("{0}:{1}".format(x, y) for x,y in info.iteritems())))
        except Exception as doh:
            self.log.error('{0}\nError attempting to dump connection info:{1}'
                           .format(get_traceback(), doh))


    def set_boto_logger_level(self, level='NOTSET', format_string=None):
        """
        Set the global boto loggers levels to 'level'. ie "DEBUG", "INFO", "CRITICAL"
        default is "NOTSET"
        :param level: string matching logging class levels, or integer representing the equiv value
        :param format_string: logging class formatter string
        """
        return set_boto_logger_level(level=level, format_string=format_string)

    def get_component_from_topology(self, environment_file, component_type=None):
        """
        Reads eucalyptus topology from environment file and returns value of expected component.

        Args:
            environment_file - environment file to extract Eucalyptus topology
            component_type - type of the component that needs to be extracted
        Returns:
            a dict with component_type as key and value from the environment file
        """
        try:
            with open(environment_file) as myenv:
                env_dict = yaml.load(myenv)
        except Exception as EE:
            self.log.error('Failed to read env file:"{0}", err:{1}'.format(environment_file, EE))
            raise EE

        result = env_dict['default_attributes']['eucalyptus']['topology'][component_type]

        return {component_type: result}

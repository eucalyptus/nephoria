
import signal
from cloud_admin.systemconnection import SystemConnection
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import get_traceback
from cloud_utils.system_utils.machine import Machine
from nephoria.usercontext import UserContext
from nephoria.testcase_utils import TimerSeconds, TimeoutError, wait_for_result
from boto3 import set_stream_logger


class SystemConnectionFailure(Exception):
    pass


class TestController(object):
    def __init__(self,
                 hostname=None, username='root', password=None, region=None,
                 proxy_hostname=None, proxy_password=None,
                 clouduser_account='nephotest', clouduser_name='admin', clouduser_credpath=None,
                 clouduser_accesskey=None, clouduser_secretkey=None,
                 cloudadmin_credpath=None, cloudadmin_accesskey=None, cloudadmin_secretkey=None,
                 timeout=10, log_level='DEBUG',
                 cred_depot_hostname=None, cred_depot_username='root', cred_depot_password=None):

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
        self.log = Eulogger("TESTER:{0}".format(hostname), stdout_level=log_level)
        self._region = region
        self._sysadmin = None
        self._cloudadmin = None
        self._test_user = None
        self._cred_depot = None
        self._default_timeout = timeout
        self._cloud_admin_connection_info = {}
        self._test_user_connection_info = {}
        self._system_connection_info = {'hostname': hostname,
                                        'username': username,
                                        'password': password,
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
                                        'euca_account': 'eucalyptus'}

        self._cloud_admin_connection_info = {'account_name': 'eucalyptus',
                                             'user_name': 'admin',
                                             'credpath': cloudadmin_credpath,
                                             'access_key': cloudadmin_accesskey,
                                             'secret_key': cloudadmin_secretkey,
                                             'region': self.region,
                                             'log_level': log_level}

        self._test_user_connection_info = {'aws_account_name': clouduser_account,
                                           'aws_user_name': clouduser_name,
                                           'credpath': clouduser_credpath,
                                           'aws_access_key': clouduser_accesskey,
                                           'aws_secret_key': clouduser_secretkey,
                                           'region': self.region,
                                           'log_level': log_level}
        self._cred_depot_connection_info = {'hostname': cred_depot_hostname,
                                            'username': cred_depot_username,
                                            'password': cred_depot_password or password,
                                            'log_level': log_level}
    def __repr__(self):
        try:
            myrepr = "{0}:{1}({2}:{3},{4}:{5})".format(
                self.__class__.__name__,
                self._system_connection_info.get('hostname', ""),
                self._cloud_admin_connection_info.get('account_name', ""),
                self._cloud_admin_connection_info.get('user_name', ""),
                self._test_user_connection_info.get('aws_account_name', ""),
                self._test_user_connection_info.get('aws_user_name', ""))
            return myrepr
        except Exception as E:
            self.log.debug(E)
            return str(self.__class__.__name__)

    @property
    def region(self):
        if not self._region and self.sysadmin is not None:
            try:
                regions = self.sysadmin.ec2_connection.get_all_regions()
                if not regions:
                    self.log.warning('No Regions found?')
                else:
                    region = regions[0]
                    name = region.name
                    if name:
                        name = str(name)
                    self.region = name
            except Exception as RE:
                self.log.error('{0}.\nError while fetching region info:{0}'.format(get_traceback(),
                                                                                   RE))
        return self._region

    @region.setter
    def region(self, value):
        if self._region is not None and self._region != value:
            raise ValueError('Can not change region once it has been set')
        self._cloud_admin_connection_info['region'] = value
        self._test_user_connection_info['region'] = value
        self._region = value

    @property
    def cred_depot(self):
        if not self._cred_depot and self._cred_depot_connection_info.get('hostname'):
            self._cred_depot = Machine(**self._cred_depot_connection_info)
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
            conn_info = self._cloud_admin_connection_info
            if (conn_info.get('credpath') or
                (conn_info.get('aws_access_key') and conn_info.get('aws_secret_key'))):
                if conn_info.get('credpath'):
                    conn_info['machine'] = self.cred_depot
                self.dump_conn_debug(conn_info)
                self._cloudadmin = UserContext(**conn_info)
            else:
                self._cloudadmin = UserContext(eucarc=self.sysadmin.creds, region=self.region)
        return self._cloudadmin

    @property
    def user(self):
        if not self._test_user:
            self._test_user = self.create_user_using_cloudadmin(**self._test_user_connection_info)
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
                         machine=None, service_connection=None, path='/',
                         log_level=None):
        """
        Fetch an existing cloud user and convert into a usercontext object.
        For checking basic existence of a cloud user, use the iam interface instead.
        """
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
                                                     machine=machine,
                                                     service_connection=service_connection,
                                                     path=path, log_level=log_level)
        else:
            raise ValueError('User info not returned for "account:{0}, user:{1}"'
                             .format(aws_account_name, aws_user_name))



    def create_user_using_cloudadmin(self, aws_account_name=None, aws_user_name='admin',
                                     aws_access_key=None, aws_secret_key=None,
                                     credpath=None, eucarc=None,
                                     machine=None, service_connection=None, path='/',
                                     region=None, log_level=None):
        if log_level is None:
            log_level = self.log.stdout_level or 'DEBUG'
        if region is None:
            region = self.region
        self.log.debug('Attempting to create user with params: account:{0}, name:{1}'
                          'access_key:{2}, secret_key:{3}, credpath:{4}, eucarc:{5}'
                          ', machine:{6}, service_connection:{7}, path:{8}, region:{9},'
                          'loglevel:{10}'
                       .format(aws_account_name, aws_user_name, aws_access_key, aws_secret_key,
                               credpath, eucarc, machine, service_connection, path, region,
                               log_level))
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
                               service_connection=service_connection,
                               log_level=log_level)
        if aws_access_key and aws_secret_key:
            return UserContext(aws_access_key=aws_access_key,
                               aws_secret_key=aws_secret_key,
                               aws_account_name=aws_account_name,
                               aws_user_name=aws_user_name,
                               service_connection=service_connection,
                               log_level=log_level)
        if credpath:
            return UserContext(credpath=credpath,
                               machine=machine,
                               log_level=log_level)

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
                            existing_certs=certs,
                            machine=self.sysadmin.clc_machine,
                            service_connection=self.sysadmin,
                            log_level=log_level)
        user._user_info = self.admin.iam.get_user_info(user_name=user.user_name,
                                                       delegate_account=user.account_id)
        return user

    def dump_conn_debug(self, info):
            try:
                self.log.debug(
                        'Connection info:\n{0}'
                        .format("\n".join("{0}:{1}".format(x, y) for x,y in info.iteritems())))
            except Exception as doh:
                self.log.error('{0}\nError attempting to dump connection info:{1}'
                               .format(get_traceback(), doh))

    def wait_for_result(self, *args, **kwargs):
        return wait_for_result(*args, **kwargs)

    def set_boto_logger_level(self, level='NOTSET', format_string=None):
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


















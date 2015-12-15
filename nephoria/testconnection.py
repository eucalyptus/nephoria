#!/usr/bin/python

from logging import INFO, DEBUG, NOTSET
from boto import set_stream_logger, regioninfo
from boto import __version__ as boto_version
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import markup, get_traceback
from cloud_utils.file_utils.eucarc import Eucarc
from nephoria import CleanTestResourcesException
import re
from urlparse import urlparse


AWSRegionData = {
    'us-east-1': 'us-east-1.amazonaws.com',
    'us-west-1': 'us-west-1.amazonaws.com',
    'us-west-2': 'us-west-2.amazonaws.com',
    'eu-west-1': 'eu-west-1.amazonaws.com',
    'ap-northeast-1': 'ap-northeast-1.amazonaws.com',
    'ap-southeast-1': 'ap-southeast-1.amazonaws.com'}

class TestConnection(object):
    EUCARC_URL_NAME = None
    AWS_REGION_SERVICE_PREFIX = None

    def __init__(self, eucarc=None, credpath=None, service_url=None, context_mgr=None,
                 aws_access_key_id=None, aws_secret_access_key=None,
                 is_secure=False, port=None, host=None, endpoint=None, region=None,
                 boto_debug=0, path=None, validate_certs=None, test_resources=None,
                 logger=None, log_level=None, user_context=None, APIVersion=None,
                 verbose_requests=None):
        if self.EUCARC_URL_NAME is None:
            raise NotImplementedError('EUCARC_URL_NAME not set for this class:"{0}"'
                                      .format(self.__class__.__name__))
        self.service_host = None
        self.service_port = None
        self.service_path = None
        self._original_connection = None
        self.context_mgr = context_mgr
        self.test_resources_clean_methods = {}
        self.test_resources = test_resources or {}
        if boto_debug:
            set_stream_logger('boto')
        if log_level is None:
            log_level = DEBUG
        if not logger:
            context = ""
            if user_context:
                try:
                    context = "({0}:{1})".format(user_context.account_name, user_context.user_name)
                except:
                    pass
            logger = Eulogger("{0}{1}".format(self.__class__.__name__, context),
                              stdout_level=log_level)
        self.log = logger
        self.log.set_stdout_loglevel(log_level)
        if not eucarc:
            if credpath:
                eucarc = Eucarc(filepath=credpath)
            else:
                eucarc = Eucarc()
        self.eucarc = eucarc
        self._try_verbose = verbose_requests
        self._is_secure = is_secure
        if aws_secret_access_key:
            self.eucarc.aws_secret_key = aws_secret_access_key
        if aws_access_key_id:
            self.eucarc.aws_access_key = aws_access_key_id
        self._service_url = service_url
        if not (host or port or path):
            if self.service_url:
                urlp = urlparse(self.service_url)
                host = host or urlp.hostname
                port = port or urlp.port or 8773
                path = path or urlp.path
        self.service_host = host
        self.service_port = port
        self.service_path = path
        self.service_region = self._get_region_info(host=host, endpoint=endpoint,
                                                    region_name=region)
        self._boto_debug = boto_debug
        if validate_certs is None:
            validate_certs = True
            if re.search('2.6', boto_version):
                validate_certs = False

        self._connection_kwargs = {'aws_access_key_id': self.eucarc.aws_access_key,
                                   'aws_secret_access_key': self.eucarc.aws_secret_key,
                                   'is_secure': is_secure,
                                   'port': self.service_port,
                                   'host': self.service_host,
                                   'debug': self.boto_debug,
                                   'region': self.service_region,
                                   'validate_certs': validate_certs,
                                   'path': path}
        self._clean_connection_kwargs()
        if APIVersion:
            self._connection_kwargs['api_version'] = APIVersion,
        # Verify the required params have been set...
        required = []
        for key, value in self._connection_kwargs.iteritems():
            if value is None:
                required.append(key)
        if required:
            raise ValueError('Required Connection parameters were None: "{0}"'
                             .format(", ".join(required)))

    # Experiment to allow setting context for all boto objects created despite the
    # connection they possess. '_connection' is used by the underlying boto connection class(s)
    # to retrieve the http connection from pool or create a new one.
    @property
    def connection(self):
        if self.context_mgr:
            current_context = self.context_mgr.get_connection_context(ops=self)
            if current_context:
                self.log.debug('"{0}":connection, Got a different connection context:"{1}"'
                                  .format(self, current_context))
                return current_context
        return super(TestConnection, self).get_http_connection(*self._connection)

    def get_http_connection(self, *args, **kwargs):
        if self.context_mgr:
            current_context = self.context_mgr.get_current_ops_context(ops=self)
            if current_context:
                self.log.debug('"{0}": get_http_connection, Got a different ops context:"{1}"'
                                  .format(self, current_context))
                return current_context.get_http_connection(*current_context._connection)
        return super(TestConnection, self).get_http_connection(*args, **kwargs)

    @property
    def service_url(self):
        if not self._service_url:
            url = getattr(self.eucarc, self.EUCARC_URL_NAME, None)
            if url:
                self._service_url = url
            else:
                if self._is_secure:
                    prefix = 'https'
                elif self.service_host:
                    prefix = 'http'
                    url = "{0}://{1}:{2}{3}".format(prefix,
                                                self.service_host,
                                                self.service_port or "",
                                                self.service_path or "")
                    return url
        return self._service_url

    @property
    def boto_debug(self):
        if hasattr(self, 'debug'):
            return self.debug
        else:
            return self._boto_debug

    @boto_debug.setter
    def boto_debug(self, level):
        self._boto_debug = level
        self.debug = level

    @property
    def _use_verbose_requests(self):
        if self._try_verbose is None:
            self._try_verbose = False
            if self.eucarc:
                account = getattr(self.eucarc, 'aws_account_name', None)
                user = getattr(self.eucarc, 'aws_user_name', None)
                if account == 'eucalyptus' and user == 'admin':
                    self._try_verbose = True
        return self._try_verbose

    @_use_verbose_requests.setter
    def _use_verbose_requests(self, value):
        if value is None or isinstance(value, bool):
            self._try_verbose = value
            return
        raise ValueError('Only bool or None type supported for "_use_verbose_requests". '
                         'Got: "{0}/{1}"'.format(value, type(value)))

    def _get_region_info(self, host=None, endpoint=None, region_name=None):
        if (host or endpoint or region_name):
            region = regioninfo.RegionInfo()
            if region_name:
                region.name = region_name
                self.log.debug("Check region: " + str(region))
                try:
                    if not endpoint:
                        endpoint_url = AWSRegionData[region_name]
                        if self.AWS_REGION_SERVICE_PREFIX and \
                                not(endpoint_url.startswith(self.AWS_REGION_SERVICE_PREFIX)):
                            endpoint_url = "{0}.{1}".format(self.AWS_REGION_SERVICE_PREFIX,
                                                            endpoint_url)
                        region.endpoint = endpoint_url
                    else:
                        region.endpoint = endpoint
                except KeyError:
                    raise Exception('Unknown region: %s' % region)
            else:
                region.name = host or endpoint
                if endpoint:
                    region.endpoint = endpoint
                elif host:
                    region.endpoint = host
            return region
        return None


    def _clean_connection_kwargs(self):
        classes = self.__class__.__bases__
        for connection_class in classes:
            if connection_class != TestConnection:
                varnames = connection_class.__init__.__func__.func_code.co_varnames
                keys = self._connection_kwargs.keys()
                for key in keys:
                    if key not in varnames:
                        del self._connection_kwargs[key]


    def show_connection_kwargs(self):
        debug_buf = 'Current "{0}" connection kwargs for\n'.format(self.__class__.__name__)
        for key, value in self._connection_kwargs.iteritems():
            debug_buf += "{0}{1}{2}\n".format(str(key).ljust(30), " -> ", value)
        self.log.debug(debug_buf)

    def enable_boto_debug(self, level=DEBUG, format_string=None):
        self.boto_debug=2
        set_stream_logger('boto', level=level, format_string=None)

    def disable_boto_debug(self, level=NOTSET):
        self.boto_debug=0
        set_stream_logger('boto', level=level)

    def setup_resource_trackers(self):
        raise NotImplementedError('ERROR: {0} has not implemented resource tracking method. '
                                  '"test_resources" and "test_resources_clean_methods" should be '
                                  'setup here.'
                                  .format(self.__class__.__name__))

    def clean_all_test_resources(self):
        fault_buf = ""
        for resource_name, resource_list in self.test_resources.iteritems():
            clean_method = self.test_resources_clean_methods.get(resource_name, None)
            if clean_method:
                try:
                    try:
                        clean_method_name = clean_method.__func__.__name__
                    except:
                        clean_method_name = str(clean_method)
                    self.log.debug('Attempting to clean test resources of type:"{0}", '
                                   'method:"{1}", artifacts:"{2}"'
                                   .format(resource_name, clean_method_name, resource_list))
                    clean_method(resource_list)
                except Exception as E:
                    fault_buf += "{0}\n{1}\n".format(get_traceback(),
                                                     markup('Error while attempting to remove '
                                                            'test resource type:"{0}", '
                                                            'error:"{1}"'
                                                            .format(resource_name, E)))
        if fault_buf:
            raise CleanTestResourcesException(fault_buf)


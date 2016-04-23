#!/usr/bin/python

from logging import DEBUG, NOTSET
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import markup, get_traceback
from cloud_utils.file_utils.eucarc import Eucarc
from nephoria import CleanTestResourcesException
from urlparse import urlparse


AWSRegionData = {
    'us-east-1': 'us-east-1.amazonaws.com',
    'us-west-1': 'us-west-1.amazonaws.com',
    'us-west-2': 'us-west-2.amazonaws.com',
    'eu-west-1': 'eu-west-1.amazonaws.com',
    'ap-northeast-1': 'ap-northeast-1.amazonaws.com',
    'ap-southeast-1': 'ap-southeast-1.amazonaws.com'}

class BaseOps(object):
    # The key name this ops class uses to look up it's service url value (ie EC2_URL, S3_URL, etc)
    EUCARC_URL_NAME = None
    # The service prefix used with the region (ie ec2, iam, s3, etc)
    SERVICE_PREFIX = None
    # The underlying class used to connect to the cloud (ie boto.VPCConnection)
    CONNECTION_CLASS = None

    def __init__(self, eucarc=None, credpath=None, service_url=None, aws_access_key_id=None,
                 aws_secret_access_key=None, is_secure=False, port=None, host=None,
                 region=None, connection_debug=0, path=None, validate_certs=True,
                 test_resources=None, logger=None, log_level=None, user_context=None,
                 session=None, api_version=None, verbose_requests=None):
        if self.EUCARC_URL_NAME is None:
            raise NotImplementedError('EUCARC_URL_NAME not set for this class:"{0}"'
                                      .format(self.__class__.__name__))
        if self.SERVICE_PREFIX is None:
            raise NotImplementedError('Service Prefix has not been defined for this class:"{0}"'
                                      .format(self.__class__.__name__))
        init_kwargs = locals()
        init_kwargs.__delitem__('self')
        self._session = session
        self.connection = None
        self.service_host = None
        self.service_port = None
        self.service_path = None
        # Store info about created resources and how to clean/delete them for this ops connection
        self.test_resources_clean_methods = {}
        self.test_resources = test_resources or {}
        # Store the user context for this connection if provided
        self._user_context = user_context
        if not region and self._user_context:
            region = self._user_context.region
        self.service_region = region
        # Create the logger for this ops connection
        if log_level is None:
            log_level = DEBUG
        def get_logger_context():
            host = self.service_host or ""
            context = ""
            try:
                if self._user_context:
                    if self._user_context._user_name and self._user_context._account_name:

                        context = "({0}:{1})".format(self._user_context.user_name,
                                                     self._user_context.account_name)
                    elif self._user_context.access_key:
                        context = "(AK:{0}...)".format(self._user_context.__access_key[5:])
            except Exception as LE:
                print 'error fetching user context: "{0}"'.format(LE)
            if not context:
                if aws_access_key_id:
                    context = "(AK:{0}...)".format(aws_access_key_id[5:])
                else:
                    context = "()"
            return context
        if not logger:
            logger = Eulogger("{0}{1}".format(self.__class__.__name__, get_logger_context()),
                              stdout_level=log_level)
        self.log = logger
        self.log.debug('Creating ops: {0}'.format(self.__class__.__name__))
        self.log.set_stdout_loglevel(log_level)
        # Store the runtime configuration for this ops connection
        if not eucarc:
            if credpath:
                eucarc = Eucarc(filepath=credpath)
            else:
                eucarc = Eucarc()
        self.eucarc = eucarc
        # Set the connection params...
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
        self.service_region = region
        # Build out kwargs used to create service connection/client
        # Pass all the args/kwargs provided at init to the create_connection_kwargs method for the
        # ops class to use to build it's kwargs as needed.
        self._connection_kwargs = self.create_connection_kwargs(**init_kwargs)
        self.connect(verbose=connection_debug)
        # Remaining setup...
        self.setup()

    def __repr__(self):
        return "{0}:{1}:{2}".format(self.__class__.__name__, self.service_region,
                                    self.SERVICE_PREFIX)

    def connect(self, verbose=False,  connection_kwargs=None):
        """
        Verify the required params have been set, and connect the underlying connection class.

        :param verbose: Dump debug output about the connection
        :param connection_kwargs: options dict containing kwargs used when creating the
                                  underlying connection
        """
        if self.CONNECTION_CLASS is None:
            raise NotImplementedError('Connection Class has not been defined for this class:"{0}"'
                                      .format(self.__class__.__name__))
        if connection_kwargs:
            self._connection_kwargs = connection_kwargs
        # Remove and kwargs which are not part of the service connection class creation method
        self._clean_connection_kwargs()
        required = []
        for key, value in self._connection_kwargs.iteritems():
            if value is None:
                required.append(key)
        if required:
            self.show_connection_kwargs(connection_kwargs=connection_kwargs)
            raise ValueError('{0}: Required Connection parameters were None: "{1}"'
                             .format(self.__class__.__name__, ", ".join(required)))
        #### Init connection...
        if verbose:
            self.show_connection_kwargs()
        try:
            # Remove any kwargs that are not applicable to this connection class
            # For example 'region' may not be applicable to services such as 'IAM'
            connection_keys = self._connection_kwargs.keys()
            for ckey in connection_keys:
                if ckey not in self.CONNECTION_CLASS.__init__.__func__.__code__.co_varnames:
                    self.log.debug('Arg "0" not found in "{1}.init()", removing kwarg '
                                   'connection args.'.format(ckey, self.CONNECTION_CLASS.__name__))
                    self._connection_kwargs.__delitem__(ckey)
            self.connection = self.CONNECTION_CLASS(**self._connection_kwargs)
        except:
            self.show_connection_kwargs()
            raise

    def create_connection_kwargs(self, **kwargs):
        self._connection_kwargs = kwargs


    def setup(self):
        self.setup_resource_trackers()

    @property
    def service_name(self):
        return self.SERVICE_PREFIX

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
    def session(self):
        return self._session

    @session.setter
    def session(self, value):
        self._session = value

    def enable_connection_debug(self, level=DEBUG, format_string=None):
        pass

    def disable_connection_debug(self, level=NOTSET):
        pass

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

    def _clean_connection_kwargs(self, connection_kwargs=None, connection_method=None):
        # Remove any kwargs from self_connection_kwargs that are not applicable
        # to self.CONNECTION_CLASS
        if connection_kwargs is None:
            connection_kwargs = self._connection_kwargs or {}
        if connection_method is None:
            connection_method = self.CONNECTION_CLASS.__init__
        varnames = connection_method.__func__.func_code.co_varnames
        keys = connection_kwargs.keys()
        for key in keys:
            if key not in varnames:
                del connection_kwargs[key]
        return connection_kwargs


    def show_connection_kwargs(self, connection_kwargs=None):
        if connection_kwargs is None:
            connection_kwargs = self._connection_kwargs
        print connection_kwargs
        debug_buf = 'Current "{0}" connection kwargs for\n'.format(self.__class__.__name__)
        for key, value in connection_kwargs.iteritems():
            debug_buf += "{0}{1}{2}\n".format(str(key).ljust(30), " -> ", value)
        self.log.debug(debug_buf)


    def setup_resource_trackers(self):
        """
        Allows each ops class to track resources created by this ops class, as well as the
        method(s) to user per resource to type to clean/remove them.
        For example an ec2_ops class may create 'instances' and later can register a 'terminate()'
        method to delete these upon exit.
        """
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



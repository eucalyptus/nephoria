#!/usr/bin/python

import copy
from inspect import isclass
from logging import DEBUG, NOTSET
from boto.regioninfo import RegionInfo
from boto import set_stream_logger
from boto3 import set_stream_logger as b3_set_stream_logger
from boto3.session import Session
from botocore.client import BaseClient
from boto3.resources.base import ServiceResource
from nephoria.baseops import BaseOps, AWSRegionData, NephoriaObject
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import get_traceback, red
import re

class B3Session(object):
    def __init__(self, ops, connection_kwargs=None, access_key=None, secret_key=None, region=None,
                 session=None, client=None, resource=None, verbose=False, auto_connect=True):
        if not isinstance(ops, BaseOps):
            raise ValueError('Unknown type for ops. Expected type:"{0}", got:"{1}/{2}"'
                             .format(BaseOps.__class__.__name__, ops, type(ops)))
        self._active_session = session
        self._client = client
        self._resource = resource
        self._ops = ops
        self._log = self._ops.log
        self._verbose = verbose
        self._access_key = connection_kwargs.get('aws_access_key_id', None) or \
                           self._ops.eucarc.aws_access_key
        self._secret_key = connection_kwargs.get('aws_secret_access_key', None) or \
                           self._ops.eucarc.aws_secret_key
        self._region = connection_kwargs.get('region_name', None) or self._ops.service_region

    @property
    def connection_info(self):
        return self._ops._connection_kwargs

    @property
    def _session(self):
        if not self._active_session:
            self._start_session()
        return self._active_session

    @_session.setter
    def _session(self, new_session):
        if not isinstance(new_session, Session) and new_session is not None:
            raise ValueError('Unknown type for session, got: "{0}/{1}"'.format(new_session,
                                                                               type(new_session)))
        self._active_session = new_session

    @property
    def client(self):
        if not self._client:
            self._connect(resource=False, client=True)
        return self._client

    @client.setter
    def client(self, new_client):
        if not isinstance(new_client, BaseClient) and new_client is not None:
            raise ValueError('Unknown type for client, got: "{0}/{1}"'.format(new_client,
                                                                               type(new_client)))
        self._client = new_client

    @property
    def resource(self):
        if not self._resource:
            self._connect(client=False, resource=True)
        return self._resource

    @resource.setter
    def resource(self, new_resource):
        if not isinstance(new_resource, ServiceResource) and new_resource is not None:
            raise ValueError('Unknown type for resource, got: "{0}/{1}"'.format(new_resource,
                                                                              type(new_resource)))
        self._resource = new_resource

    def _start_session(self, connection_kwargs=None):
        if self._ops._user_context:
            self._session = self._ops._user_context.session
        else:
            try:
                region = self._region
                self._session = Session(aws_access_key_id=self._access_key,
                                        aws_secret_access_key=self._secret_key,
                                        region_name=region)
            except Exception as SE:
                self._log.error(red('{0}\nError creating boto3 {1} session. Error:{2}'
                                    .format(get_traceback(), self.__class__.__name__, SE)))
                raise
        return self._session

    def _connect(self, connection_kwargs=None, client=True, resource=True, verbose=None):

        """
        Verify the required params have been set, and connect the underlying connection class.

        :param verbose: Dump debug output about the connection
        :param connection_kwargs: options dict containing kwargs used when creating the
                                  underlying connection
        """
        if verbose is None:
            verbose = self._verbose
        connection_kwargs = connection_kwargs or self.connection_info
        service_name = connection_kwargs.get('service_name', None) or self._ops.service_name
        session = self._session
        if not session:
            raise RuntimeError('"{0}". Session was not found/created during boto3 connect()'
                               .format(self))
        client_connection_method = None
        if client:
            client_connection_method = session.client

        resource_connection_method = None
        if resource:
            if service_name in session.get_available_resources():
                resource_connection_method = session.resource
            else:
                self._ops.log.debug('No session resource interface available for: "{0}"'
                                    .format(service_name))
        if not resource_connection_method and not client_connection_method:
            self._log.debug('No client or resource interface to create')
            return
        api_version = connection_kwargs.get('boto3_api_version', None)
        if api_version:
            connection_kwargs['api_version'] = api_version
        # Clean up kwargs and create the resource and or client interfaces
        def create_interface(connect_kwargs, connection_method):
            # Remove kwargs which are not part of the service connection class creation method
            check_kwargs = self._ops.get_applicable_kwargs(connection_kwargs=connect_kwargs,
                                                           connection_method=connection_method)

            try:
                # Remove any kwargs that are not applicable to this connection class
                # For example 'region' may not be applicable to services such as 'IAM'
                connection_keys = check_kwargs.keys()
                for ckey in connection_keys:
                    if ckey not in connection_method.__func__.__code__.co_varnames:
                        self._ops.log.debug('Arg "0" not found in method:"{1}()", removing kwarg '
                                           'connection args.'.format(
                            ckey, connection_method.__func__.__name__))
                        check_kwargs.__delitem__(ckey)
                #### Init connection...
                if verbose:
                    self._log.debug('Attempting to create: "{0}" with the following kwargs...'
                                   .format(connection_method))
                    self._ops.show_connection_kwargs(connection_kwargs=check_kwargs)
                return connection_method(**check_kwargs)
            except:
                self._ops.show_connection_kwargs()
                raise
        if client_connection_method:
            self.client = create_interface(connection_kwargs, client_connection_method)
        if resource_connection_method:
            self.resource = create_interface(connection_kwargs, resource_connection_method)


class BotoBaseOps(BaseOps):
    EUCARC_URL_NAME = None
    SERVICE_PREFIX = None
    CONNECTION_CLASS = None

    def create_connection_kwargs(self, **kwargs):
        """
        Create connection kwargs for Boto type connections. See Baseops.__init__(**kwargs)
        for kwargs available
        """
        verbose = kwargs.get('verbose', False)
        region = kwargs.get('region')
        boto2_api_version = kwargs.get('boto2_api_version', None)
        boto3_api_version = kwargs.get('boto3_api_version', None)
        is_secure = kwargs.get('is_secure', True)
        connection_debug = kwargs.get('connection_debug')
        region = self._get_region_info(host=self.service_host,
                                       endpoint=self.service_host,
                                       region_name=region)
        validate_certs = kwargs.get('validate_certs', False)
        # Set port for service...
        service_port = kwargs.get('port', None) or self.service_port
        if not service_port:
            service_port = self.DEFAULT_EUCA_SERVICE_PORT
            for value in [kwargs.get('region'), self.service_host, self.service_url]:
                if re.search('amazonaws.com', str(value)):
                    if not is_secure and re.search('https', (self.service_url or "")):
                        # Use the more secure option between the url and is_secure flag if they
                        # differ..
                        is_secure = True
                    # Handle AWS case...
                    if re.search('iam|sts', self.service_url):
                        is_secure = True
                        self.service_region = None
                        region = None
                    if is_secure:
                        self.log.debug('Setting service port to 443')
                        service_port = 443
                    else:
                        service_port = 80
                    self.service_port =  service_port
                    if kwargs.get('region', None):
                        kwargs['region'] = kwargs['region'].strip('.amazonaws.com')
                    if self.service_region:
                        self.service_region = self.service_region.strip('amazonaws.com')
                    break

        # This needs to be re-visited due to changes in Eucalyptus and Boto regarding certs...
        connection_kwargs = {'service_name': self.SERVICE_PREFIX,
                                   'aws_access_key_id': self.eucarc.aws_access_key,
                                   'aws_secret_access_key': self.eucarc.aws_secret_key,
                                   'is_secure': is_secure,
                                   'use_ssl': is_secure,
                                   'port': service_port,
                                   'host': self.service_host,
                                   'debug': connection_debug,
                                   'region': region,
                                   'region_name': self.service_region,
                                   'verify': validate_certs,
                                   'validate_certs': validate_certs,
                                   'endpoint_url': self.service_url,
                                   'verbose': verbose,
                                   'boto2_api_version': boto2_api_version,
                                   'boto3_api_version': boto3_api_version,
                                   'path': self.service_path}
        return connection_kwargs

    @property
    def connection(self):
        return self.boto2

    @property
    def boto2(self):
        if not self._b2_connection:
            try:
                self._b2_connection = self.boto2_connect(
                    verbose=self._connection_kwargs.get('verbose'),
                    connection_kwargs=self._connection_kwargs)
            except Exception as CE:
                self.log.error(red('{0}\nFailed to create boto2 "{1}" connection. Err:"{2}"'
                                   .format(get_traceback(), self.__class__.__name__, CE)))
                raise
        return self._b2_connection

    @property
    def boto3(self):
        if not self._b3_connection:
            try:
                self._b3_connection = B3Session(ops=self,
                                                connection_kwargs=self._connection_kwargs,
                                                verbose=self._connection_kwargs.get('verbose'))
            except Exception as CE:
                self.log.error(red('{0}\nFailed to create boto3 "{1}" session. Err:"{2}"'
                                   .format(get_traceback(), self.__class__.__name__, CE)))
                raise
        return self._b3_connection


    def enable_boto2_connection_debug(self, level=DEBUG, format_string=None):
        try:
            self.connection.debug = 2
            level = Eulogger.format_log_level(level, 'DEBUG')
            set_stream_logger('boto', level=level, format_string=None)
        except:
            self.log.error('Could not enable debug for: "{0}"'.format(self))
            raise

    def enable_boto3_connection_debug(self, level=DEBUG, format_string=None):
        try:
            level = Eulogger.format_log_level(level, 'DEBUG')
            b3_set_stream_logger('botocore', level=level, format_string=format_string)
        except:
            self.log.error('Could not enable debug for: "{0}"'.format(self))
            raise

    def disable_boto2_connection_debug(self, level=NOTSET):
        try:
            self.connection.debug = 0
            level = Eulogger.format_log_level(level, 'NOTSET')
            set_stream_logger('boto', level=level, format_string=None)
        except:
            self.log.error('Could not disable debug for: "{0}"'.format(self))
            raise

    def disable_boto3_connection_debug(self, level=NOTSET):
        try:
            self.connection.debug = 0
            level = Eulogger.format_log_level(level, 'NOTSET')
            b3_set_stream_logger('botocore', level=level, format_string=None)
        except:
            self.log.error('Could not disable debug for: "{0}"'.format(self))
            raise

    def _get_region_info(self, host=None, endpoint=None, region_name=None):
        self.log.debug("get region info params: host:{0}, endpoint:{1}, "
                       "region_name:{2}".format(host, endpoint, region_name))
        if (host or endpoint or region_name):
            region = RegionInfo()
            if region_name:
                region.name = region_name
                self.log.debug("Check region: " + str(region))
                try:
                    if not endpoint:
                        endpoint_url = AWSRegionData[region_name]
                        if self.SERVICE_PREFIX and \
                                not(endpoint_url.startswith(self.SERVICE_PREFIX)):
                            endpoint_url = "{0}.{1}".format(self.SERVICE_PREFIX,
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

    def boto2_connect(self, verbose=False, connection_kwargs=None):
        """
        Verify the required params have been set, and connect the underlying connection class.

        :param verbose: Dump debug output about the connection
        :param connection_kwargs: options dict containing kwargs used when creating the
                                  underlying connection
        """
        connection_kwargs = copy.copy(connection_kwargs)
        if self.CONNECTION_CLASS is None:
            raise NotImplementedError('Connection Class has not been defined for this class:"{0}"'
                                      .format(self.__class__.__name__))

        api_version = connection_kwargs.get('boto2_api_version', None)
        if api_version:
            connection_kwargs['api_version'] = api_version
        # Remove and kwargs which are not part of the service connection class creation method
        connection_kwargs = self.get_applicable_kwargs(
            connection_kwargs=self._connection_kwargs,
            connection_method=self.CONNECTION_CLASS.__init__)

        required = []
        for key, value in connection_kwargs.iteritems():
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
            connection_keys = connection_kwargs.keys()
            for ckey in connection_keys:
                if ckey not in self.CONNECTION_CLASS.__init__.__func__.__code__.co_varnames:
                    self.log.debug('Arg "0" not found in "{1}.init()", removing kwarg '
                                   'connection args.'.format(ckey, self.CONNECTION_CLASS.__name__))
                    connection_kwargs.__delitem__(ckey)
            return self.CONNECTION_CLASS(**connection_kwargs)
        except:
            self.show_connection_kwargs(connection_kwargs)
            raise

    def map_to_object(self, obj_dict, to_class=None, add_all=True):
        """
        Attempts to convert a dictionary into an object of the provided 'to_class' type
        or Nephoria Object type.

        Args:
            obj_dict: dictionary of values to assign to new object
            to_class: A class to create the new object from.
            add_all: boolean, if True all attributes will be added to the new object, if false
                     only the attributes already present in the class/new object will be used.

        Returns:
            instance/object created from 'to_class'

        """
        if obj_dict is None:
            return None
        to_class = to_class or NephoriaObject
        if not isclass(to_class):
            raise ValueError('Expected a class, but got: "{0}/{1}"'.format(to_class,
                                                                           type(to_class)))

        # Convert camelcase to lower case underscore...
        def convert(name):
            s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
            return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

        # Dict will now have any previous camel case as well as underscore notation.
        keys = obj_dict.keys()
        for key in keys:
            value = obj_dict[key]
            b2name = convert(name=key)
            obj_dict[b2name] = value

        init_kwargs = self.get_applicable_kwargs(obj_dict, to_class.__init__) or {}
        new_obj = to_class(**init_kwargs)
        for key, value in obj_dict.iteritems():
            if key not in init_kwargs:
                if not add_all:
                    if hasattr(new_obj, key):
                        setattr(new_obj, key, value)
                else:
                    setattr(new_obj, key, value)
        return new_obj

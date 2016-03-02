#!/usr/bin/python

from logging import DEBUG, NOTSET
from boto3 import set_stream_logger
from boto3.session import Session
from nephoria.baseops import BaseOps
from cloud_utils.log_utils.eulogger import Eulogger

class Boto3BaseOps(BaseOps):
    #  The key-name used to find the service url in the runtime-config. ie: EC2_URL, IAM_URL, etc
    EUCARC_URL_NAME = None
    #  Service name/prefix. ie: 'ec2', 's3', 'iam', etc..
    SERVICE_PREFIX = None
    #  Do not set connection class for boto3 ops
    CONNECTION_CLASS = None

    def create_connection_kwargs(self, **kwargs):
        """
        Create connection kwargs for Boto type connections. See Baseops.__init__(**kwargs)
        for kwargs available
        """
        region = kwargs.get('region')
        endpoint_url = self.service_url
        verify = kwargs.get('validate_certs', True)
        api_version = kwargs.get('api_version', "")
        use_ssl = kwargs.get('is_secure', False)
        region = region

        self._connection_kwargs = {'service_name': self.SERVICE_PREFIX,
                                   'aws_access_key_id': self.eucarc.aws_access_key,
                                   'aws_secret_access_key': self.eucarc.aws_secret_key,
                                   'use_ssl': use_ssl,
                                   'region_name': region,
                                   'verify': verify,
                                   'endpoint_url': endpoint_url}
        if api_version is not None:
            self._connection_kwargs['api_version'] = api_version

        return self._connection_kwargs

    def enable_connection_debug(self, level=DEBUG, format_string=None):
        try:
            level = Eulogger.format_log_level(level, 'DEBUG')
            set_stream_logger('botocore', level=level, format_string=None)
        except:
            self.log.error('Could not enable debug for: "{0}"'.format(self))
            raise

    def disable_connection_debug(self, level=NOTSET):
        try:
            self.connection.debug = 0
            level = Eulogger.format_log_level(level, 'NOTSET')
            set_stream_logger('botocore', level=level, format_string=None)
        except:
            self.log.error('Could not disable debug for: "{0}"'.format(self))
            raise

    @property
    def session(self):
        if not self._session:
            if self._user_context:
                self._session = self._user_context.session
            else:
                self._session = Session(aws_access_key_id=self.eucarc.aws_access_key,
                                        aws_secret_access_key=self.eucarc.secret_key,
                                        region_name=self.service_region)
        return self._session

    @session.setter
    def session(self, value):
        if value is None or isinstance(value, Session):
            self._session = value
        else:
            raise TypeError('Expected "{0}" type for session, got: "{1}/{2}"'
                            .format(Session.__class__.__name__, value, type(value)))

    def connect(self, verbose=False,  connection_kwargs=None, connection_method=None):
        """
        Verify the required params have been set, and connect the underlying connection class.

        :param verbose: Dump debug output about the connection
        :param connection_kwargs: options dict containing kwargs used when creating the
                                  underlying connection
        """
        if connection_kwargs:
            self._connection_kwargs = connection_kwargs
        session = None
        if connection_method is None and not self.CONNECTION_CLASS:
            session = self.session
            if not session:
                raise RuntimeError('"{0}". Session was not found/created during connect()'
                                   .format(self))
            connection_method = session.resource
        # Remove and kwargs which are not part of the service connection class creation method
        self._clean_connection_kwargs(connection_kwargs=self._connection_kwargs,
                                      connection_method=connection_method)
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
                if ckey not in connection_method.__func__.__code__.co_varnames:
                    self.log.debug('Arg "0" not found in method:"{1}()", removing kwarg '
                                   'connection args.'.format(ckey,
                                                             connection_method.__func__.__name__))
                    self._connection_kwargs.__delitem__(ckey)
            self.connection = connection_method(**self._connection_kwargs)
        except:
            self.show_connection_kwargs()
            raise
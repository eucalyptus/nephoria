#!/usr/bin/python

from logging import DEBUG, NOTSET
from boto.regioninfo import RegionInfo
from boto import set_stream_logger
from boto import __version__ as boto_version
from nephoria.baseops import BaseOps, AWSRegionData
from cloud_utils.log_utils.eulogger import Eulogger
import re

class BotoBaseOps(BaseOps):
    EUCARC_URL_NAME = None
    SERVICE_PREFIX = None
    CONNECTION_CLASS = None

    def create_connection_kwargs(self, **kwargs):
        """
        Create connection kwargs for Boto type connections. See Baseops.__init__(**kwargs)
        for kwargs available
        """
        region = kwargs.get('region')
        service_url = kwargs.get('service_url')
        validate_certs = kwargs.get('validate_certs', None)
        api_version = kwargs.get('api_version', "")
        is_secure = kwargs.get('is_secure', True)
        connection_debug = kwargs.get('connection_debug')
        region = self._get_region_info(host=self.service_host,
                                       endpoint=self.service_host,
                                       region_name=region)

        # This needs to be re-visited due to changes in Eucalyptus and Boto regarding certs...
        if validate_certs is None:
            validate_certs = True
            if re.search('2.6', boto_version):
                validate_certs = False

        self._connection_kwargs = {'service_name': self.SERVICE_PREFIX,
                                   'aws_access_key_id': self.eucarc.aws_access_key,
                                   'aws_secret_access_key': self.eucarc.aws_secret_key,
                                   'is_secure': is_secure,
                                   'use_ssl': is_secure,
                                   'port': self.service_port,
                                   'host': self.service_host,
                                   'debug': connection_debug,
                                   'region': region,
                                   'region_name': self.service_region,
                                   'verify': validate_certs,
                                   'validate_certs': validate_certs,
                                   'endpoint_url': self.service_url,
                                   'path': self.service_path}
        return self._connection_kwargs

    def enable_connection_debug(self, level=DEBUG, format_string=None):
        try:
            self.connection.debug = 2
            level = Eulogger.format_log_level(level, 'DEBUG')
            set_stream_logger('boto', level=level, format_string=None)
        except:
            self.log.error('Could not enable debug for: "{0}"'.format(self))
            raise

    def disable_connection_debug(self, level=NOTSET):
        try:
            self.connection.debug = 0
            level = Eulogger.format_log_level(level, 'NOTSET')
            set_stream_logger('boto', level=level, format_string=None)
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

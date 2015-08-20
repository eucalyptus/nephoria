#!/usr/bin/python

from boto import set_stream_logger, regioninfo
from boto import __version__ as boto_version
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils import net_utils, file_utils, log_utils
from cloud_utils.file_utils.eucarc import Eucarc
import testcase_utils
import re
import os
import random
import time
import string
import operator
import types
from functools import wraps
from urlparse import urlparse

__version__ = '2.0'

AWSRegionData = {
    'us-east-1': 'elasticloadbalancing.us-east-1.amazonaws.com',
    'us-west-1': 'elasticloadbalancing.us-west-1.amazonaws.com',
    'us-west-2': 'elasticloadbalancing.us-west-2.amazonaws.com',
    'eu-west-1': 'elasticloadbalancing.eu-west-1.amazonaws.com',
    'ap-northeast-1': 'elasticloadbalancing.ap-northeast-1.amazonaws.com',
    'ap-southeast-1': 'elasticloadbalancing.ap-southeast-1.amazonaws.com'}

class TestConnection(object):
    EUCARC_URL_NAME=None

    def __init__(self, eucarc=None, credpath=None, service_url=None,
                 aws_access_key_id=None, aws_secret_access_key=None,
                 is_secure=False, port=None, host=None, endpoint=None, region=None,
                 boto_debug=0, path=None, validate_certs=None, test_resources=None, logger=None,
                 APIVersion=None):
        if self.EUCARC_URL_NAME is None:
            raise NotImplementedError('EUCARC_URL_NAME not set for this class:"{0}"'
                                      .format(self.__class__.__name__))
        self.test_resource = test_resources
        self.service_host = None
        self.service_port = None
        self.service_path = None
        if boto_debug:
            set_stream_logger('boto')
        if not logger:
            logger = Eulogger(self.__class__.__name__)
        self.logger = logger
        if not eucarc and credpath:
            eucarc = Eucarc(filepath=credpath)
        self.eucarc = eucarc
        self._is_secure = is_secure
        if aws_secret_access_key:
            self.eucarc.aws_access_key = aws_secret_access_key
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
        self.boto_debug = boto_debug
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

    def _get_region_info(self, host=None, endpoint=None, region_name=None):
        if (host or endpoint or region_name):
            region = regioninfo.RegionInfo()
            if region_name:
                region.name = region_name
                self.logger.debug("Check region: " + str(region))
                try:
                    if not endpoint:
                        region.endpoint = AWSRegionData[region]
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

    def show_connection_kwargs(self):
        debug_buf = 'Current "{0}" connection kwargs for\n'.format(self.__class__.__name__)
        for key, value in self._connection_kwargs.iteritems():
            debug_buf += "{0}{1}{2}\n".format(str(key).ljust(30), " -> ", value)
        self.logger.debug(debug_buf)


def handle_timeout(self, signum, frame):
    raise testcase_utils.TimeoutFunctionException()

def grep(self, string, list):
    """ Remove the strings from the list that do not match the regex string"""
    expr = re.compile(string)
    return filter(expr.search,list)

def render_file_template(src, dest, **kwargs):
    return file_utils.render_file_template(src, dest, **kwargs)

def id_generator(size=6, chars=None):
    """Returns a string of size with random charachters from the chars array.
         size    Size of string to return
         chars   Array of characters to use in generation of the string
    """
    chars = chars or (string.ascii_uppercase + string.ascii_lowercase  + string.digits)
    return ''.join(random.choice(chars) for x in range(size))






    



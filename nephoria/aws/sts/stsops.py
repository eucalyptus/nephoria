# Copyright 2011-2014 Eucalyptus Systems, Inc.
#
# Redistribution and use of this software in source and binary forms,
# with or without modification, are permitted provided that the following
# conditions are met:
#
#   Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
#   Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from nephoria.testconnection import TestConnection
import boto
from boto.ec2.regioninfo import RegionInfo
from boto.sts import STSConnection
EC2RegionData = {
    'us-east-1': 'ec2.us-east-1.amazonaws.com',
    'us-west-1': 'ec2.us-west-1.amazonaws.com',
    'eu-west-1': 'ec2.eu-west-1.amazonaws.com',
    'ap-northeast-1': 'ec2.ap-northeast-1.amazonaws.com',
    'ap-southeast-1': 'ec2.ap-southeast-1.amazonaws.com'}


class STSops(TestConnection, STSConnection):
    AWS_REGION_SERVICE_PREFIX = 'ec2'
    EUCARC_URL_NAME = 'sts_url'
    def __init__(self, eucarc=None, credpath=None, context_mgr=None,
                 aws_access_key_id=None, aws_secret_access_key=None,
                 is_secure=False, port=None, host=None, region=None, endpoint=None,
                 boto_debug=0, path=None, APIVersion=None, validate_certs=None,
                 test_resources=None, logger=None, log_level=None):

        # Init test connection first to sort out base parameters...
        TestConnection.__init__(self,
                                eucarc=eucarc,
                                credpath=credpath,
                                context_mgr=context_mgr,
                                test_resources=test_resources,
                                logger=logger,
                                aws_access_key_id=aws_access_key_id,
                                aws_secret_access_key=aws_secret_access_key,
                                is_secure=is_secure,
                                port=port,
                                host=host,
                                APIVersion=APIVersion,
                                validate_certs=validate_certs,
                                boto_debug=boto_debug,
                                path=path,
                                log_level=log_level)
        if self.boto_debug:
            self.show_connection_kwargs()
        # Init IAM connection...
        try:
            STSConnection.__init__(self, **self._connection_kwargs)
        except:
            self.show_connection_kwargs()
            raise

    def setup_sts_connection(self, endpoint=None, region=None, aws_access_key_id=None, aws_secret_access_key=None,
                             path="/", port=443, is_secure=True, boto_debug=0):
        sts_region = RegionInfo()
        if region:
            self.debug("Check region: " + str(region))
            try:
                if not endpoint:
                    sts_region.endpoint = EC2RegionData[region]
                else:
                    sts_region.endpoint = endpoint
            except KeyError:
                raise Exception('Unknown region: %s' % region)
        else:
            sts_region.name = 'eucalyptus'
            if endpoint:
                sts_region.endpoint = endpoint
            else:
                sts_region.endpoint = self.get_sts_ip()

        try:
            sts_connection_args = {'aws_access_key_id': aws_access_key_id,
                                   'aws_secret_access_key': aws_secret_access_key,
                                   'is_secure': is_secure,
                                   'debug': boto_debug,
                                   'port': port,
                                   'path': path,
                                   'region': sts_region}
            self.debug("Attempting to create STS connection to " + sts_region.endpoint + ':' + str(port) + path)
            self.connection = boto.connect_sts(**sts_connection_args)
        except Exception, e:
            self.critical("Was unable to create STS connection because of exception: " + str(e))

    def get_session_token( self, duration=None ):
        """
        Get a possibly cached session token, if getting a new token request the given duration
        Options:
            duration - The desired duration for the token in seconds (if issued, None for default duration)
        """
        return self.connection.get_session_token( duration )

    def issue_session_token( self, duration=None ):
        """
        Get a newly issued session token with the given (or default) duration
        Options:
            duration - The desired duration for the token in seconds (None for default duration)
        """
        return self.connection.get_session_token( duration, force_new=True )


# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2014, Eucalyptus Systems, Inc.
# All rights reserved.
#
# Redistribution and use of this software in source and binary forms, with or
# without modification, are permitted provided that the following conditions
# are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author: Vic Iglesias vic.iglesias@eucalyptus.com
#
from nephoria import TestConnection
import boto
from boto.ec2.regioninfo import RegionInfo
from boto.cloudformation import CloudFormationConnection

class CFNops(CloudFormationConnection, TestConnection):

    EUCARC_URL_NAME = 'cloudformation_url'
    def __init__(self, eucarc=None, credpath=None,
                 aws_access_key_id=None, aws_secret_access_key=None,
                 is_secure=False, port=None, host=None, region=None, endpoint=None,
                 boto_debug=0, path=None, APIVersion=None, validate_certs=None,
                 test_resources=None, logger=None):

        # Init test connection first to sort out base parameters...
        TestConnection.__init__(self,
                                eucarc=eucarc,
                                credpath=credpath,
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
                                path=path)
        if self.boto_debug:
            self.show_connection_kwargs()
        # Init IAM connection...
        try:
            CloudFormationConnection.__init__(self, **self._connection_kwargs)
        except:
            self.show_connection_kwargs()
            raise

    def setup_cfn_connection(self,
                             endpoint=None,
                             path="/",
                             port=443,
                             region=None,
                             aws_access_key_id=None,
                             aws_secret_access_key=None,
                             is_secure=True,
                             boto_debug=0):
        cfn_region = RegionInfo()
        if region:
            self.debug("Check region: " + str(region))
            try:
                if not endpoint:
                    cfn_region.endpoint = "cloudformation.{0}.amazonaws.com".format(region)
                else:
                    cfn_region.endpoint = endpoint
            except KeyError:
                raise Exception( 'Unknown region: %s' % region)
        else:
            cfn_region.name = 'eucalyptus'
            if endpoint:
                cfn_region.endpoint = endpoint
            else:
                cfn_region.endpoint = self.get_cfn_ip()

        try:
            cfn_connection_args = { 'aws_access_key_id' : aws_access_key_id,
                                    'aws_secret_access_key': aws_secret_access_key,
                                    'is_secure': is_secure,
                                    'debug':boto_debug,
                                    'port' : port,
                                    'path' : path,
                                    'region' : cfn_region}
            self.debug("Attempting to create cloudformation connection to " + self.get_cfn_ip() + ':' + str(port) + path)
            self.connection = boto.connect_cloudformation(**cfn_connection_args)
        except Exception, e:
            self.critical("Was unable to create cloudformation connection because of exception: " + str(e))

    def create_stack(self, stack_name, template_body, template_url=None, parameters=None):
        self.info("Creating stack: {0}".format(stack_name))
        self.connection.create_stack(stack_name, template_body, template_url=template_url, parameters=parameters)

    def delete_stack(self, stack_name):
        self.info("Deleting stack: {0}".format(stack_name))
        self.connection.delete_stack(stack_name)
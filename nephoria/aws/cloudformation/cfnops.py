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
from nephoria.baseops.botobaseops import BotoBaseOps

import boto
from boto.ec2.regioninfo import RegionInfo
from boto.cloudformation import CloudFormationConnection
import time

class CFNops(BotoBaseOps):
    SERVICE_PREFIX = 'cloudformation'
    CONNECTION_CLASS = CloudFormationConnection
    EUCARC_URL_NAME = 'cloudformation_url'

    def create_stack(self, stack_name, template_body, template_url=None, parameters=None,
                     *args, **kwargs):
        self.log.info("Creating stack: {0}".format(stack_name))
        arn = super(CFNops, self).connection.create_stack(stack_name, template_body,
                                                          template_url=template_url,
                                                          parameters=parameters, *args, **kwargs)
        for x in xrange(0, 5):
            stacks = self.connection.describe_stacks(arn)
            if stacks:
                return stacks[0]
            time.sleep(2 * x)

    create_stack.__doc__ = CloudFormationConnection.create_stack.__doc__

    def delete_stack(self, stack_name_or_id, *args, **kwargs):
        self.log.info("Deleting stack: {0}".format(stack_name_or_id))
        return super(CFNops, self).connection.delete_stack(stack_name_or_id, *args, **kwargs)

    delete_stack.__doc__ = CloudFormationConnection.delete_stack.__doc__
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

from boto.cloudformation import CloudFormationConnection
from boto.cloudformation.stack import Stack
from boto.exception import BotoServerError
import time
import json
import os
import re
import urllib
from prettytable import PrettyTable
from nephoria.baseops.botobaseops import BotoBaseOps

class CFNops(BotoBaseOps):
    SERVICE_PREFIX = 'cloudformation'
    CONNECTION_CLASS = CloudFormationConnection
    EUCARC_URL_NAME = 'cloudformation_url'

    def setup_resource_trackers(self):
        ## add test resource trackers and cleanup methods...
        self.test_resources["stacks"] = self.test_resources.get('stacks', [])
        self.test_resources_clean_methods["stacks"] = None

    def create_stack(self, stack_name, template_body, template_url=None, parameters=None,
                     *args, **kwargs):
        self.log.info("Creating stack: {0}".format(stack_name))
        arn = self.connection.create_stack(stack_name, template_body,
                                           template_url=template_url,
                                           parameters=parameters, *args, **kwargs)
        for x in xrange(0, 5):
            stacks = self.connection.describe_stacks(arn)
            if stacks:
                self.test_resources["stacks"].append(stacks[0])
                return stacks[0]
            time.sleep(2 * x)

    create_stack.__doc__ = CloudFormationConnection.create_stack.__doc__

    def validate_template(self, template_body, template_url=None, *args, **kwargs):
        self.log.info("Validating template: {0}".format(template_body))
        return self.connection.validate_template(template_body,
                                                 template_url=template_url,
                                                 *args, **kwargs) 

    validate_template.__doc__ = CloudFormationConnection.validate_template.__doc__

    def delete_stack(self, stack_name_or_id, *args, **kwargs):
        if not isinstance(stack_name_or_id, basestring):
            stack_name_or_id = stack_name_or_id.stack_id
        self.log.info("Deleting stack: {0}".format(stack_name_or_id))
        return self.connection.delete_stack(stack_name_or_id, *args, **kwargs)

    delete_stack.__doc__ = CloudFormationConnection.delete_stack.__doc__

    def delete_all_stacks(self, timeout=360, poll_sleep=10):
        """
        Deletes all stacks.

        Args:
            timeout: default= 60
            poll_sleep: 10 seconds

        Returns: list of stacks, empty list if succeeded

        """
        stacks = self.describe_stacks()
        poll_count = timeout / poll_sleep
        if len(stacks) > 0:
            for i in stacks:
                self.log.debug("Deleting Stack: {0}".format(i))
                self.delete_stack(i)
            for _ in range(poll_count):
                time.sleep(poll_sleep)
                stacks = self.describe_stacks()
                if len(stacks) == 0:
                    break
                for i in stacks:
                    if i in stacks:
                        self.delete_stack(i)
        stacks = self.describe_stacks()
        return stacks

    def describe_stacks(self, stack_names_or_ids=None, *args, **kwargs):
        if stack_names_or_ids and not isinstance(stack_names_or_ids, list):
            stack_names_or_ids = [stack_names_or_ids]
        self.log.info("Describing stack: {0}".format(stack_names_or_ids))
        return self.connection.describe_stacks(stack_names_or_ids, *args, **kwargs)

    describe_stacks.__doc__ = CloudFormationConnection.describe_stacks.__doc__


#!/usr/bin/python
# -*- coding: utf-8 -*-
# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2011, Eucalyptus Systems, Inc.
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



from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.file_utils.eucarc import Eucarc
from nephoria.aws.iam.iamops import IAMops
from nephoria.aws.s3.s3ops import S3ops
from nephoria.aws.ec2.ec2ops import EC2ops
from nephoria.aws.elb.elbops import ELBops
from nephoria.aws.sts.stsops import STSops
from nephoria.aws.cloudformation.cfnops import CFNops
from nephoria.aws.cloudwatch.cwops import CWops
from nephoria.aws.autoscaling.asops import ASops

class UserContext(Eucarc):

    # This map is used for context lookups...
    CLASS_MAP = {IAMops: 'iam',
                 S3ops: 's3',
                 EC2ops: 'ec2',
                 ELBops: 'elb',
                 STSops: 'sts',
                 CWops: 'cloudwatch',
                 CFNops: 'cloudformation',
                 ASops: 'autoscaling'}

    def __init__(self, context_mgr=None, filepath=None, string=None, sshconnection=None,
                 keysdir=None, logger=None):

        super(UserContext, self).__init__(filepath=filepath, string=string,
                                         sshconnection=sshconnection, keysdir=keysdir,
                                         logger=logger)
        self._connections = {}
        self.context_mgr = context_mgr
        # Logging setup
        if not logger:
            logger = Eulogger(self.account_id)
        self.logger = logger
        self.debug = self.logger.debug
        self.critical = self.logger.critical
        self.info = self.logger.info

    def __enter__(self):
        self.testconnection.set_current_user(self)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.testconnection.set_current_user(None)

    @property
    def iam(self):
        ops_class = IAMops
        name = self.CLASS_MAP[ops_class]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self, context_mgr=self.context_mgr)
        return self._connections[name]

    @property
    def s3(self):
        ops_class = S3ops
        name = self.CLASS_MAP[ops_class]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self, context_mgr=self.context_mgr)
        return self._connections[name]

    @property
    def ec2(self):
        ops_class = EC2ops
        name = self.CLASS_MAP[ops_class]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self, context_mgr=self.context_mgr)
        return self._connections[name]

    @property
    def elb(self):
        ops_class = ELBops
        name = self.CLASS_MAP[ops_class]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self, context_mgr=self.context_mgr)
        return self._connections[name]

    @property
    def sts(self):
        ops_class = STSops
        name = self.CLASS_MAP[ops_class]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self, context_mgr=self.context_mgr)
        return self._connections[name]

    @property
    def autoscaling(self):
        ops_class = ASops
        name = self.CLASS_MAP[ops_class]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self, context_mgr=self.context_mgr)
        return self._connections[name]

    @property
    def cloudwatch(self):
        ops_class = CWops
        name = self.CLASS_MAP[ops_class]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self, context_mgr=self.context_mgr)
        return self._connections[name]

    @property
    def cloudformation(self):
        ops_class = CFNops
        name = self.CLASS_MAP[ops_class]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self, context_mgr=self.context_mgr)
        return self._connections[name]



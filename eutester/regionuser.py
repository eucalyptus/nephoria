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
from eutester.aws.iam.iamops import IAMops
from eutester.aws.s3.s3ops import S3ops
from eutester.aws.ec2.ec2ops import EC2ops
from eutester.aws.elb.elbops import ELBops

class RegionUser(Eucarc):
    def __init__(self, testconnection, logger=None, secure=False):
        self.testconnection = testconnection
        self._connections = {}

        # Logging setup
        if not logger:
            logger = Eulogger(name=self.name)
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
        name = 'iam'
        ops_class = IAMops
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self)
        return self._connections[name]

    @property
    def s3(self):
        name = 's3'
        ops_class = S3ops
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self)
        return self._connections[name]

    @property
    def ec2(self):
        name = 'ec2'
        ops_class = ECx`2ops
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self)
        return self._connections[name]

    @property
    def elb(self):
        name = 'elb'
        ops_class = ELBops
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(eucarc=self)
        return self._connections[name]



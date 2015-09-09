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

from logging import INFO, DEBUG
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_admin.access.autocreds import AutoCreds
from nephoria.aws.iam.iamops import IAMops
from nephoria.aws.s3.s3ops import S3ops
from nephoria.aws.ec2.ec2ops import EC2ops
from nephoria.aws.elb.elbops import ELBops
from nephoria.aws.sts.stsops import STSops
from nephoria.aws.cloudformation.cfnops import CFNops
from nephoria.aws.cloudwatch.cwops import CWops
from nephoria.aws.autoscaling.asops import ASops

class UserContext(AutoCreds):

    # This map is used for context lookups...
    CLASS_MAP = {IAMops.__name__: 'iam',
                 S3ops.__name__: 's3',
                 EC2ops.__name__: 'ec2',
                 ELBops.__name__: 'elb',
                 STSops.__name__: 'sts',
                 CWops.__name__: 'cloudwatch',
                 CFNops.__name__: 'cloudformation',
                 ASops.__name__: 'autoscaling'}

    def __init__(self,  aws_access_key=None, aws_secret_key=None, aws_account_name=None,
                 aws_user_name=None, context_mgr=None, credpath=None, string=None,
                 machine=None, keysdir=None, logger=None, service_connection=None,
                 eucarc=None, existing_certs=False, boto_debug=0, log_level=DEBUG):

        super(UserContext, self).__init__(aws_access_key=aws_access_key,
                                          aws_secret_key=aws_secret_key,
                                          aws_account_name=aws_account_name,
                                          aws_user_name=aws_user_name,
                                          credpath=credpath, string=string,
                                          machine=machine, keysdir=keysdir,
                                          logger=logger, loglevel=log_level,
                                          existing_certs=existing_certs,
                                          service_connection=service_connection,
                                          auto_create=False)
        self._connections = {}
        self._previous_context = None
        self._user_info = {}

        self.context_mgr = context_mgr
        # Logging setup
        if not logger:
            logger = Eulogger(self.account_id, stdout_level=log_level)
        self.logger = logger
        self.debug = self.logger.debug
        self.critical = self.logger.critical
        self.info = self.logger.info
        if eucarc:
            for key, value in eucarc.__dict__.iteritems():
                setattr(self, key, value)
        elif not (self.aws_access_key and aws_secret_key and self.serviceconnection):
            self.auto_find_credentials(assume_admin=False)
        if service_connection:
            self.update_attrs_from_cloud_services()
        self._connection_kwargs = {'eucarc': self, 
                                   'context_mgr': self.context_mgr,
                                   'boto_debug': boto_debug,
                                   'user_context': self,
                                   'log_level': log_level}

    def __enter__(self):
        self._previous_context = self.context_mgr.current_user_context
        self.context_mgr.set_current_user_context(self)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.context_mgr.set_current_user_context(self._previous_context)

    def __repr__(self):
        account_name = ""
        user_name = ""
        try:
            account_name = self.account_name
            user_name = self.user_name
            if account_name:
                account_name = "({0})".format(account_name)
            if user_name:
                user_name = "({0})".format(user_name)
        except:
            pass

        return "{0}:{1}{2}{3}".format(self.__class__.__name__, self.account_id,
                                      account_name, user_name)

    @property
    def user_info(self):
        if not self._user_info:
            self._user_info = self.iam.get_user_info(delegate_account=self.account_id)
        return self._user_info

    @property
    def user_name(self):
        if not self._user_name:
            self._user_name = self.user_info.get('user_name', None)
        return self._user_name

    @property
    def user_id(self):
        return self.user_info.get('user_id', None)

    @property
    def account_name(self):
        if not self._account_name:
            account_names = self.iam.get_account_aliases(delegate_account=self.account_id)
            if account_names:
                self._account_name = account_names[0]
        return self._account_name

    @property
    def iam(self):
        ops_class = IAMops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def s3(self):
        ops_class = S3ops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def ec2(self):
        ops_class = EC2ops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def elb(self):
        ops_class = ELBops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def sts(self):
        ops_class = STSops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def autoscaling(self):
        ops_class = ASops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def cloudwatch(self):
        ops_class = CWops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]

    @property
    def cloudformation(self):
        ops_class = CFNops
        name = self.CLASS_MAP[ops_class.__name__]
        if not self._connections.get(name, None):
            self._connections[name] = ops_class(**self._connection_kwargs)
        return self._connections[name]



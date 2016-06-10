#!/usr/bin/env python
import re
from boto.exception import JSONResponseError

from nephoria.testcase_utils.cli_test_runner import CliTestRunner
from nephoria.testcase_utils.cli_test_runner import SkipTestException
from nephoria.testcontroller import TestController
import copy


class GenericTemplateRun(CliTestRunner):

    _CLI_DESCRIPTION = ("Test given Cloudformation template/URL"
                        " against Eucalyptus Cloudformation."
                        )
    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['template_file'] = {
        'args': ['--template-file'],
        'kwargs': {'help': 'file location containing JSON template'}}

    _DEFAULT_CLI_ARGS['template_url'] = {
        'args': ['--template-url'],
        'kwargs': {'help': 'S3 URL for JSON template'}}

    _DEFAULT_CLI_ARGS['template_params'] = {
        'args': ['--template-paramaters'],
        'kwargs': {'help': "key/value parameters to use with stack's template",
                   'nargs': '*'}}

    @property
    def tc(self):
        tc = getattr(self, '__tc', None)
        if not tc:
            tc = TestController(self.args.clc,
                                password=self.args.password,
                                clouduser_name=self.args.test_user,
                                clouduser_account=self.args.test_account,
                                log_level=self.args.log_level)
            setattr(self, '__tc', tc)
        return tc

    @property
    def user(self):
        user = getattr(self, '__user', None)
        if not user:
            try:
                user = self.tc.get_user_by_name(
                                    aws_account_name=self.args.test_account,
                                    aws_user_name=self.args.test_user)
            except:
                user = self.tc.create_user_using_cloudadmin(
                                    aws_account_name=self.args.test_account,
                                    aws_user_name=self.args.test_user)
            setattr(self, '__user', user)
        return user

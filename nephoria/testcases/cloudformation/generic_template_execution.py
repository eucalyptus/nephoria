#!/usr/bin/env python
import re
from boto.exception import BotoServerError

from nephoria.testcase_utils.cli_test_runner import CliTestRunner
from nephoria.testcase_utils.cli_test_runner import SkipTestException
from nephoria.testcontroller import TestController
import copy
import os.path


class GenericTemplateRun(CliTestRunner):

    _CLI_DESCRIPTION = ("Test given Cloudformation template/URL"
                        " against Eucalyptus Cloudformation."
                        )
    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['template_file'] = {
        'args': ['--template-file'],
        'kwargs': {'dest': 'template_file',
                   'help': 'file location containing JSON template',
                   'default': None}}

    _DEFAULT_CLI_ARGS['template_url'] = {
        'args': ['--template-url'],
        'kwargs': {'dest': 'template_url',
                   'help': 'S3 URL for JSON template',
                   'default': None}}

    _DEFAULT_CLI_ARGS['template_params'] = {
        'args': ['--template-paramaters'],
        'kwargs': {
                   'dest': 'template_params',
                   'help': "key/value parameters to use with stack's template",
                   'nargs': '*',
                   'default': None}}

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

    def test_validate_template(self):
        """
        Test Coverage:
            - validate provided template
        """
        self.log.debug("Validating Cloudformation Template.")
        """
        Confirm the following:
            - if --template-file or --template-url is used.
            - if --template-file is used, confirm file exists.
            - if --template-file is used, use it; if not, use
              --template-url
        """
        if self.args.template_file is None and self.args.template_url is None:
            raise ValueError("Please pass either template-file/template-url.")
        if self.args.template_file and os.path.exists(self.args.template_file) is False:
            raise ValueError("File passed for template-file does not exist.")
        if self.args.template_file:
            temp = open(self.args.template_file)
            temp_body = temp.read()
            temp.close()
            import ipdb; ipdb.set_trace()
            try:
                self.tc.user.cloudformation.validate_template(
                                                   template_body=temp_body)
                self.log.debug("Template is valid.")
            except BotoServerError as e:
                self.log.error("Error validating template: " + e.error_message)
                raise e
        else:
            url = self.args.template_url
            try:
                self.tc.user.cloudformation.validate_template(
                                                   template_url=url)
                self.log.debug("Template is valid.")
            except BotoServerError as e:
                self.log.error("Error validating template: " + e.error_message)
                raise e

if __name__ == "__main__":
    test = GenericTemplateRun()
    result = test.run()
    exit(result)

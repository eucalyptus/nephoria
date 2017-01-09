#!/usr/bin/env python
import re
from boto.exception import BotoServerError

from nephoria.testcase_utils.cli_test_runner import CliTestRunner
from nephoria.testcase_utils.cli_test_runner import SkipTestException
from nephoria.testcontroller import TestController
import copy
import time
import random
import os.path


class BasicMessagesTests(CliTestRunner):
    _CLI_DESCRIPTION = ("Test SQS messages basics. "
                        "This script utilizes the following "
                        "SQS API calls: "
                        "SnedMessage, SendMessageBatch, ReceiveMessage, "
                        "DeleteMesage, DeleteMessageBatch, "
                        "ChangeMessageVisibility and "
                        "ChangeMessageVisibilityBatch."
                        )
    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['queue_name'] = {
        'args': ['--queue-name'],
        'kwargs': {'dest': 'queue_name',
                   'help': 'Name of the SQS Queue',
                   'default': None}}

    _DEFAULT_CLI_ARGS['domain'] = {
        'args': ['--domain'],
        'kwargs': {'dest': 'domain_name',
                   'help': '(Optional) AWS/Eucalyptus Domain',
                   'default': None}}

    _DEFAULT_CLI_ARGS['boto_loglevel'] = {
        'args': ['--boto-loglevel'],
        'kwargs': {'dest': 'boto_loglevel',
                   'help': ("Set debugging log level for "
                            "all boto/boto3 API calls. "
                            "Default is NOTSET."),
                   'choices': ['CRITICAL', 'ERROR', 'WARNING',
                               'INFO', 'DEBUG', 'NOTSET'],
                   'default': 'NOTSET'}}

    @property
    def tc(self):
        tc = getattr(self, '__tc', None)
        if not tc:
            if (
                self.args.secret_key and
                self.args.access_key
               ):
                tc = TestController(clouduser_accesskey=self.args.access_key,
                                    clouduser_secretkey=self.args.secret_key,
                                    clouduser_name=self.args.test_user,
                                    clouduser_account=self.args.test_account,
                                    region=self.args.region,
                                    domain=self.args.domain_name)
            else:
                tc = TestController(self.args.clc,
                                    password=self.args.password,
                                    clouduser_name=self.args.test_user,
                                    clouduser_account=self.args.test_account,
                                    log_level=self.args.log_level)

            setattr(self, '__tc', tc)
            self.tc.set_boto_logger_level(level=self.args.boto_loglevel)
            self.tc.user.sqs.enable_boto2_connection_debug(
                level=self.args.boto_loglevel)
        return tc

    @property
    def user(self):
        user = getattr(self, '__user', None)
        if not user:
            try:
                user = self.tc.get_user_by_name(
                                    region=self.args.region,
                                    domain=self.args.domain_name,
                                    aws_account_name=self.args.test_account,
                                    aws_user_name=self.args.test_user)
            except:
                user = self.tc.create_user_using_cloudadmin(
                                    aws_account_name=self.args.test_account,
                                    aws_user_name=self.args.test_user)
            setattr(self, '__user', user)
        return user

    @property
    def queue_name(self):
        """
        Make sure queue name is set.  If queue name not passed,
        generate queue name.
        """
        queue_name = getattr(self, '__queue_name', None)
        if (
               self.args.queue_name and
               not queue_name
           ):
            queue_name = self.args.queue_name
        elif not queue_name:
            queue_name = "nephoria-queue-" + str(int(time.time()))

        setattr(self, '__queue_name', queue_name)
        return queue_name

    def test_create_queue_message(self):
        """
        Test Coverage:
            - create standard queue
            - send a message to the queue
        """
        self.log.debug("Creating SQS Queue for messages..")
        try:
            test_queue = self.tc.user.sqs.connection.create_queue(
                                           queue_name=self.queue_name)
            self.log.debug("Created SQS Queue " +
                           str(test_queue.name) +
                           " successfully.")
        except BotoServerError as e:
            self.log.error("Error creating queue: " + e.error_message)
            raise e

        try:
            self.tc.user.sqs.connection.send_message(queue,
                                                     "This is a test",
                                                     delay_seconds=0)
            self.log.debug("Added message to SQS queue " +
                           str(queue.name) + ".")
        except BotoServerError as e:
            self.log.error("Unable to write message to queue " +
                           str(self.queue_name))
            raise e
        try:
            attributes = self.tc.user.sqs.connection.get_queue_attributes(
                                    queue)
        except BotoServerError as e:
            self.log.error("Error obtaining attributes for SQS queue: " +
                           str(self.queue_name))
            raise e

        self.log.debug("Confirm ApproximateNumberOfMessages attribute " +
                       "is equal to zero for queue " +
                       str(self.queue_name))
        if int(attributes['ApproximateNumberOfMessages']) == 1:
            self.log.debug("Queue " + str(self.queue_name) +
                           "contains the message")
            break
        else:
            raise RuntimeError("Queue " + str(self.queue_name) +
                               " does not contain the message.")

    def clean_method(self):
        """
        Grab information about the queue just created,
        purge all messages, then delete the queue.
        """
        self.log.debug("Get SQS queue created for test..")
        try:
            queue = self.tc.user.sqs.connection.get_queue(
                                        queue_name=self.queue_name)
        except BotoServerError as e:
            self.log.error("The following queue was not located: " +
                           str(self.queue_name))
            raise e
        """
        Purging a queue can take up to 1 minute, therefore
        we need to check the queue for up to a minute leveraging
        decorrelated jitter exponential backoff for each request.
        if the ApproximateNumberOfMessages attributes doesn't equal
        zero at the end of the minute interval, raise an error
        """
        timeout = int(time.time()) + 60*int(1)
        while True:
            try:
                attributes = self.tc.user.sqs.connection.get_queue_attributes(
                                        queue)
            except BotoServerError as e:
                self.log.error("Error obtaining attributes for SQS queue: " +
                               str(self.queue_name))
                raise e

            self.log.debug("Confirm ApproximateNumberOfMessages attribute " +
                           "is equal to zero for queue " +
                           str(self.queue_name))
            if int(attributes['ApproximateNumberOfMessages']) == 0:
                self.log.debug("Queue " + str(self.queue_name) +
                               " was purged.")
                break
            elif int(time.time()) > timeout:
                raise RuntimeError("Queue " + str(self.queue_name) +
                                   " within the minute timeframe.")
            sleep_time = min(int(timeout),
                             random.uniform(2, 2*3))
            self.log.debug("Sleep " + str(sleep_time) +
                           " seconds before next request..")
            time.sleep(sleep_time)

        self.log.debug("Deleting the following queue: " +
                       str(queue.name))
        try:
            self.tc.user.sqs.connection.delete_queue(
                queue)
        except BotoServerError as e:
            self.log.error("Failed to delete queue " +
                           str(queue.name))
            raise e

if __name__ == "__main__":
    test = BasicMessagesTests()
    result = test.run()
    exit(result)

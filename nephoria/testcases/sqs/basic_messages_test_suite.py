#!/usr/bin/env python
import re
from boto.exception import BotoServerError
from boto.sqs.message import Message

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

    @property
    def messages(self):
        """
        Create a structure to contain all messages
        used throughout the test suite
        """
        messages = getattr(self, '__messages', None)
        if not messages:
            messages = []
        setattr(self, '__messages', messages)
        return messages

    def test_create_queue_message(self):
        """
        Test Coverage:
            - send a message to the queue
        """
        self.log.debug("Creating SQS Queue for messages..")
        try:
            queue = self.tc.user.sqs.connection.create_queue(
                                           queue_name=self.queue_name)
            self.log.debug("Created SQS Queue " +
                           str(queue.name) +
                           " successfully.")
        except BotoServerError as e:
            self.log.error("Error creating queue: " + e.error_message)
            raise e

        try:
            message = self.tc.user.sqs.connection.send_message(queue,
                                                               "Nephoria Test",
                                                               delay_seconds=0)
            self.log.debug("Added message to SQS queue " +
                           str(queue.name) + ".")
            """
            Store message to be used in verification in
            test_receive_delete_message() method
            """
            self.messages.append(message.id)
        except BotoServerError as e:
            self.log.error("Unable to write message to queue " +
                           str(queue.name))
            raise e

    def test_receive_delete_message(self):
        """
        Test Coverage:
            - confirm queue has message
            - retrieve message, confirm contents, then delete message
              from queue
        """
        self.log.debug("Get SQS queue created for test..")
        try:
            queue = self.tc.user.sqs.connection.get_queue(
                                        queue_name=self.queue_name)
            self.log.debug("Located SQS queue " +
                           str(queue.name))
        except BotoServerError as e:
            self.log.error("The following queue was not located: " +
                           str(self.queue_name))
            raise e
        """
        Check to see if message is recognized
        as being stored in the queue
        """
        try:
            attributes = self.tc.user.sqs.connection.get_queue_attributes(
                                    queue)
        except BotoServerError as e:
            self.log.error("Error obtaining attributes for SQS queue: " +
                           str(queue.name))
            raise e

        self.log.debug("Confirm ApproximateNumberOfMessages attribute " +
                       "is equal to zero for queue " +
                       str(queue.name))
        if int(attributes['ApproximateNumberOfMessages']) == 1:
            self.log.debug("Queue " + str(queue.name) +
                           "contains the message")
        else:
            raise RuntimeError("Queue " + str(queue.name) +
                               " does not contain the message.")
        """
        Retrieve message from queue and confirm contents
        match original message
        """
        try:
            messages = self.tc.user.sqs.connection.receive_message(queue)
        except BotoServerError as e:
            self.log.error("Error obtaining message from SQS queue: " +
                           str(queue.name))
            raise e
        for message in messages:
            """
            Confirm the initial message is in the queue,
            and display relevant content
            """
            self.log.debug("Verify if message retrieved from " +
                           "queue " + str(queue.name) +
                           " matches original message..")
            self.log.debug("Verify message ID")
            assert message.id in self.messages, \
                ("Message ID doesn't match original")
            self.log.debug("Verify message body")
            assert re.match("Nephoria Test",
                            message.get_body()), \
                ("Message body doesn't match original")
            """
            After verifying the message,
            delete the message from the queue
            """
            try:
                result = self.tc.user.sqs.connection.delete_message(
                            queue,
                            message)
            except BotoServerError as e:
                self.log.error("Failed to delete message from " +
                               "queue " + str(queue.name))
                raise e
            else:
                if result:
                    self.log.debug("Message deleted from queue " +
                                   str(queue.name))
                    self.messages.remove(message.id)
                else:
                    self.log.error("Failed to delete message from " +
                                   "queue " + str(queue.name))

    def test_receive_delete_multiple_messages(self):
        """
        Test Coverage:
            - send batch messages
            - delete batch messages
        """
        self.log.debug("Get SQS queue created for test..")
        try:
            queue = self.tc.user.sqs.connection.get_queue(
                                        queue_name=self.queue_name)
            self.log.debug("Located SQS queue " +
                           str(queue.name))
        except BotoServerError as e:
            self.log.error("The following queue was not located: " +
                           str(self.queue_name))
            raise e
        # Create batch messages
        batch_messages = [(x, 'This is message %d' % x, 0) for x in range(1, 11)]
        try:
            results = self.tc.user.sqs.connection.send_message_batch(
                                    queue,
                                    batch_messages)
            self.log.debug("Added batch messages to SQS queue " +
                           str(queue.name) + ".")
        except BotoServerError as e:
            self.log.error("Unable to send messages in batch request " +
                           "to queue " + str(queue.name))
            raise e
        else:
            self.log.debug("Verify all messeages were sent to the queue")
            assert len(results.results) == 10, \
                ("Not all messages were sent.")
        """
        Create a list of all the messages in
        the queue in order to delete them.
        """
        while True:
            try:
                message = self.tc.user.sqs.connection.receive_message(
                                            queue)
                self.log.debug("Grabbing message from SQS queue " +
                               str(queue.name))
            except BotoServerError as e:
                self.log.error("Unable to retrieve message from queue " +
                               str(queue.name))
                raise e
            else:
                if len(message) == 1:
                    self.messages.append(message[0])
                else:
                    break
        # Delete messages in batch
        try:
            delete_results = self.tc.user.sqs.connection.delete_message_batch(
                                            queue,
                                            self.messages)
            self.log.debug("Deleted messages in batch request.")
        except BotoServerError as e:
            self.log.error("Unable to delete messages in batch request " +
                           "to queue " + str(queue.name))
            raise e
        else:
            self.log.debug("Verify delete response to confirm messages " +
                           "were deleted")
            assert len(delete_results.results) == 10, \
                ("Not all messages were deleted.")

    def clean_method(self):
        """
        Grab queue to purge all messages,
        then delete the queue.
        """
        self.log.debug("Get SQS queue created for test..")
        try:
            queue = self.tc.user.sqs.connection.get_queue(
                                        queue_name=self.queue_name)
            self.log.debug("Located SQS queue " +
                           str(queue.name))
        except BotoServerError as e:
            self.log.error("The following queue was not located: " +
                           str(self.queue_name))
            raise e

        try:
            self.tc.user.sqs.connection.purge_queue(
                queue)
        except BotoServerError as e:
            self.log.error("Error when purging queue " +
                           str(queue.name))
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
                               str(queue.name))
                raise e

            self.log.debug("Confirm ApproximateNumberOfMessages attribute " +
                           "is equal to zero for queue " +
                           str(queue.name))
            if int(attributes['ApproximateNumberOfMessages']) == 0:
                self.log.debug("Queue " + str(queue.name) +
                               " was purged.")
                break
            elif int(time.time()) > timeout:
                raise RuntimeError("Queue " + str(queue.name) +
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

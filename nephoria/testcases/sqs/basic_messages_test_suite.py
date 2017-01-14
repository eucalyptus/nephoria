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
        Make sure queue name is set. Each test will
        generate queue name.
        """
        queue_name = getattr(self, '__queue_name', None)
        queue_name = "nephoria-queue-" + str(int(round(
                                            time.time() * 10000)))
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
            - create queue
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
        except BotoServerError as e:
            self.log.error("Unable to write message to queue " +
                           str(queue.name))
            raise e

    def test_receive_delete_message(self):
        """
        Test Coverage:
            - create queue
            - send message to queue
            - retrieve message, confirm contents, then delete message
              from queue
        """
        self.log.debug("Create SQS queue for test..")
        try:
            queue = self.tc.user.sqs.connection.create_queue(
                                           queue_name=self.queue_name)
            self.log.debug("Created SQS Queue " +
                           str(queue.name) +
                           " successfully.")
        except BotoServerError as e:
            self.log.error("Error creating queue: " + e.error_message)
            raise e

        self.log.debug("Send message to queue " + str(queue.name))
        try:
            message = self.tc.user.sqs.connection.send_message(queue,
                                                               "Nephoria Test",
                                                               delay_seconds=0)
            self.log.debug("Added message to SQS queue " +
                           str(queue.name) + ".")
            """
            Store message to be used in verification in
            later in test
            """
            self.messages.append(message.id)
        except BotoServerError as e:
            self.log.error("Unable to write message to queue " +
                           str(queue.name))
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
            messages = self.tc.user.sqs.connection.receive_message(
                                        queue,
                                        attributes='All')
        except BotoServerError as e:
            self.log.error("Error obtaining message from SQS queue: " +
                           str(queue.name))
            raise e
        for message in messages:
            """
            Confirm the initial message is in the queue,
            display relevant content and message attributes
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
            self.log.debug("Verify ApproximateFirstReceiveTimestamp " +
                           "attribute")
            assert message.attributes['ApproximateFirstReceiveTimestamp'], \
                ("ApproximateFirstReceiveTimestamp attribute " +
                 "not present")
            self.log.debug("Verify ApproximateReceiveCount " +
                           "attribute")
            assert message.attributes['ApproximateReceiveCount'], \
                ("ApproximateReceiveCount attribute " +
                 "not present")
            self.log.debug("Verify SenderId " +
                           "attribute")
            assert message.attributes['SenderId'], \
                ("SenderId attribute " +
                 "not present")
            self.log.debug("Verify SentTimestamp " +
                           "attribute")
            assert message.attributes['SentTimestamp'], \
                ("SentTimestamp attribute " +
                 "not present")
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

    def test_change_message_visibility(self):
        """
        Test Coverage:
            - create queue
            - send message to queue
            - change message visibility, then receive message
            - change message visibility that results
              in the message not being accessible, even
              if VisibilityTimeout has been reached (negative test)
        """
        self.log.debug("Create SQS queue for test..")
        try:
            queue = self.tc.user.sqs.connection.create_queue(
                                           queue_name=self.queue_name)
            self.log.debug("Created SQS Queue " +
                           str(queue.name) +
                           " successfully.")
        except BotoServerError as e:
            self.log.error("Error creating queue: " + e.error_message)
            raise e

        """
        Change visibility timeout to a minute for queue to give more
        flexibility for positive/negative tests
        """
        try:
            queue.set_timeout(60)
            self.log.debug("Set queue visibility timeout to 60 seconds")
        except BotoServerError as e:
            self.log.error("Error setting queue visibility timeout: " +
                           e.error_message)
            raise e
        # Confirm timeout has been set to 60 seconds
        try:
            queue_timeout = queue.get_timeout()
            self.log.debug("Get queue visibility timeout...")
        except BotoServerError as e:
            self.log.error("Error getting queue visibility timeout: " +
                           e.error_message)
            raise e
        else:
            if queue_timeout != 60:
                self.log.error("Queue timeout not set to 60 seconds.")
                raise ValueError("Queue timeout not set to 60 seconds")
            else:
                self.log.debug("Queue timeout set to 60 seconds")

        self.log.info("Test message visibility")
        self.log.debug("Send message to queue " + str(queue.name))
        try:
            message = self.tc.user.sqs.connection.send_message(queue,
                                                               "Nephoria Test",
                                                               delay_seconds=0)
            self.log.debug("Added message to SQS queue " +
                           str(queue.name) + ".")
        except BotoServerError as e:
            self.log.error("Unable to write message to queue " +
                           str(queue.name))
            raise e
        """
        Receive message from queue, then change
        visibility timeout of message
        """
        try:
            messages = self.tc.user.sqs.connection.receive_message(
                                        queue,
                                        attributes='All')
            self.log.debug("Received message successfully from " +
                           "queue " + str(queue.name))
        except BotoServerError as e:
            self.log.error("Error obtaining message from SQS queue: " +
                           str(queue.name))
            raise e
        # Define visibility timeouts
        timeout = 15
        sec_timeout = 10
        for message in messages:
            try:
                self.tc.user.sqs.connection.change_message_visibility(
                                        queue,
                                        message.receipt_handle,
                                        timeout)
                self.log.debug("Changed message visibility timeout " +
                               "to " + str(timeout) + " seconds..")
                self.messages.append(message.id)
            except BotoServerError as e:
                self.log.error("Unable to change message visibility " +
                               "timeout in queue " + str(queue.name))
                raise e
        """
        Wait seconds in timeout value, then try to re-receive the message.
        Compare the messages to confirm they are the same.
        """
        self.log.debug("Sleep for " + str(timeout) + " seconds..")
        time.sleep(timeout)
        try:
            sec_messages = self.tc.user.sqs.connection.receive_message(
                                        queue,
                                        attributes='All')
            self.log.debug("Received message successfully from " +
                           "queue " + str(queue.name))
        except BotoServerError as e:
            self.log.error("Error obtaining message from SQS queue: " +
                           str(queue.name))
            raise e

        for message in sec_messages:
            """
            Confirm message received matches
            the message received earlier
            """
            self.log.debug("Verify message ID")
            assert message.id in self.messages, \
                ("Message ID doesn't match original")
            self.messages.remove(message.id)
            """
            - Negative test -
            Sleep for original timeout,  
            change message timeout, however
            set the timeout to 10 seconds
            """
            self.log.info("Negative test for message visibility")
            self.log.debug("Sleep for " + str(timeout) + " seconds..")
            time.sleep(timeout)
            try:
                self.tc.user.sqs.connection.change_message_visibility(
                                        queue,
                                        message.receipt_handle,
                                        sec_timeout)
                self.log.debug("Changed message visibility timeout " +
                               "to " + str(sec_timeout) + " seconds..")
            except BotoServerError as e:
                self.log.error("Unable to change message visibility " +
                               "timeout in queue " + str(queue.name))
                raise e
        """
        Sleep for the new timeout value, then
        try to receive messages; this should work.
        Sleep for 5 seconds, then receive messages again;
        this should fail
        """
        self.log.debug("Sleep for " + str(sec_timeout) + " seconds..")
        time.sleep(sec_timeout)
        try:
            thrd_messages = self.tc.user.sqs.connection.receive_message(
                                        queue,
                                        attributes='All')
            self.log.debug("Received message successfully with new " +
                           "timeout")
        except BotoServerError as e:
                self.log.error("Unable to receive message " +
                               "from queue " + str(queue.name))
                raise e
        self.log.debug("Sleep for 5 seconds..")
        time.sleep(5)
        try:
            fourth_messages = self.tc.user.sqs.connection.receive_message(
                                        queue,
                                        attributes='All')
        except BotoServerError as e:
            self.log.error("Error obtaining message from SQS queue: " +
                           str(queue.name) + ". This is expected " +
                           "behavior: {0}".format(e.error_message))
            pass
        else:
            if len(fourth_messages) > 0:
                self.log.error("Received message successfully from " +
                               "queue " + str(queue.name) + "." +
                               " This should have failed.")
                raise ValueError("Messages should not have been returned")
            else:
                self.log.debug("Confirm no messages are returned.")
                pass

    def test_change_message_visibility_batch(self):
        pass

    def test_receive_delete_messages_batch(self):
        """
        Test Coverage:
            - create queue
            - send batch messages to queue
            - delete batch messages in queue
        """
        self.log.debug("Create SQS queue for test..")
        try:
            queue = self.tc.user.sqs.connection.create_queue(
                                           queue_name=self.queue_name)
            self.log.debug("Created SQS Queue " +
                           str(queue.name) +
                           " successfully.")
        except BotoServerError as e:
            self.log.error("Error creating queue: " + e.error_message)
            raise e
        # Create batch messages
        batch_messages = [(x, 'Message %d' % x, 0) for x in range(1, 11)]
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
        self.log.debug("Get all SQS queues created for tests..")
        try:
            queues = self.tc.user.sqs.connection.get_all_queues(
                                        prefix='nephoria')
            self.log.debug("Located all SQS queues..")
        except BotoServerError as e:
            self.log.error("Could not obtain all SQS queues")
            raise e

        for queue in queues:
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
                    attrs = self.tc.user.sqs.connection.get_queue_attributes(
                                            queue)
                except BotoServerError as e:
                    self.log.error("Error obtaining attrs for SQS queue: " +
                                   str(queue.name))
                    raise e

                self.log.debug("Confirm ApproximateNumberOfMessages " +
                               "is equal to zero for queue " +
                               str(queue.name))
                if int(attrs['ApproximateNumberOfMessages']) == 0:
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

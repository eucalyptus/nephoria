#!/usr/bin/env python
import re
from boto.exception import S3ResponseError

from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcontroller import TestController
import copy
import time


class RunInstances(CliTestRunner):

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

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
                user = self.tc.get_user_by_name(aws_account_name=self.args.test_account,
                                                aws_user_name=self.args.test_user)
            except:
                user = self.tc.create_user_using_cloudadmin(aws_account_name=self.args.test_account,
                                                            aws_user_name=self.args.test_user)
            setattr(self, '__user', user)
        return user

    @property
    def bucket_prefix(self):
        bucket_prefix = getattr(self, '__bucket_prefix', None)
        if not bucket_prefix:
            bucket_prefix = "nephoria-bucket-test-suite-" + str(int(time.time()))
        return bucket_prefix

    @bucket_prefix.setter
    def bucket_prefix(self, value):
        setattr(self, '__bucket_prefix', value)

    def test_bucket_get_put_delete(self):
        test_bucket = self.bucket_prefix + "-simple-test-bucket"
        bucket = self.tc.user.s3.create_bucket(test_bucket)
        self.tc.user.s3.delete_bucket(test_bucket)

    def test_negative_basic(self):
        """
        Test Coverage:
            - create bucket with empty-string name
            - invalid bucket names
        """
        self.log.debug("Trying to create bucket with empty-string name.")
        try:
            null_bucket_name = ""
            bucket_obj = self.tc.user.s3.create_bucket(null_bucket_name)
            if bucket_obj:
                raise("Should have caught exception for creating bucket with empty-string name.")
        except S3ResponseError as e:
            assert (e.status == 405), 'Expected response status code to be 405, actual status code is ' + str(e.status)
            assert (
            re.search("MethodNotAllowed", e.code)), "Incorrect exception returned when creating bucket with null name."

        self.log.debug("Testing an invalid bucket names, calls should fail.")

        def test_creating_bucket_invalid_names(bad_bucket):
            should_fail = False
            try:
                bucket = self.tc.user.s3.create_bucket(bad_bucket)
                should_fail = True
                try:
                    self.tc.user.s3.delete_bucket(bucket)
                except:
                    self.log.debug("Exception deleting bad bucket, shouldn't be here anyway. Test WILL fail")
            except Exception as e:
                self.log.debug("Correctly caught the exception for bucket name '" + bad_bucket + "' Reason: " + e.reason)
            if should_fail:
                raise("Should have caught exception for bad bucket name: " + bad_bucket)

        # with the EUCA-8864 fix, a new property 'objectstorage.bucket_naming_restrictions'
        # has been introduced, now 'bucket..123', 'bucket.' are actually valid bucket names
        # when using 'extended' naming convention.
        # http://docs.aws.amazon.com/AmazonS3/latest/dev/BucketRestrictions.html
        # when DNS is not being used, for now buckets can be created with bucket
        # names like '/bucket123', 'bucket123/', see EUCA-8863
        # TODO check what bucket naming convention is being used for the test
        for bad_bucket in ["bucket&123", "bucket*123"]:
            test_creating_bucket_invalid_names(self.bucket_prefix + bad_bucket)

    def clean_method(self):
        pass


if __name__ == "__main__":
    test = RunInstances()
    result = test.run()
    exit(result)


#!/usr/bin/env python

#
###########################################
#                                         #
#   objectstorage/S3 CORS Test Cases      #
#                                         #
###########################################

#Author: Lincoln Thomas <lincoln.thomas@hpe.com>

import re
import copy
import time

from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcontroller import TestController

import boto
from boto.exception import S3ResponseError
from boto.exception import BotoServerError
from boto.exception import S3CreateError

import boto.s3
from boto.s3.bucket import Bucket
from boto.s3.cors import CORSConfiguration, CORSRule

import requests
from requests.models import Response
import httplib2

class CorsTestSuite(CliTestRunner):
    
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
            bucket_prefix = "nephoria-cors-test-suite-" + str(int(time.time()))
        return bucket_prefix

    @bucket_prefix.setter
    def bucket_prefix(self, value):
        setattr(self, '__bucket_prefix', value)

    def set_cors_config(self, bucket):
        '''
        Set up a CORS config on the given bucket.
        '''
        self.log.debug("Setting a CORS config")
        bucket_cors_set = CORSConfiguration()

        bucket_allowed_methods = ['GET']
        bucket_allowed_origins = ['*']
        bucket_cors_set.add_rule(bucket_allowed_methods, 
                                 bucket_allowed_origins)

        bucket_allowed_methods = ['PUT', 'POST', 'DELETE']
        bucket_allowed_origins = ['https', 'http://*.example1.com', 'http://www.example2.com']
        bucket_allowed_headers = ['*']
        bucket_cors_set.add_rule(bucket_allowed_methods, 
                                 bucket_allowed_origins, 
                                 allowed_header=bucket_allowed_headers)

        bucket_rule_id = "Nephoria Rule ID"
        bucket_allowed_methods = ['GET']
        bucket_allowed_origins = ['*']
        bucket_allowed_headers = ['*']
        bucket_max_age_seconds = 3000
        bucket_expose_headers = ["x-amz-server-side-encryption", 
                                 "x-amz-request-id", 
                                 "x-amz-id-2"]
        bucket_cors_set.add_rule(bucket_allowed_methods, 
                                 bucket_allowed_origins, 
                                 bucket_rule_id,
                                 bucket_allowed_headers, 
                                 bucket_max_age_seconds,
                                 bucket_expose_headers)

        bucket.set_cors(bucket_cors_set)
        return bucket_cors_set

    def test_cors_config_mgmt(self):
        '''
        Method: Tests setting, getting,validating, and deleting the CORS config on a bucket.
        '''
        
        bucket_name="-cors-config-test-bucket"
        self.buckets_used = set()
        test_bucket=self.bucket_prefix + bucket_name
        self.buckets_used.add(test_bucket)
        self.log.info("Starting CORS config management tests")
        try :
            self.log.debug("Creating bucket " + test_bucket)
            bucket = self.tc.user.s3.create_bucket(test_bucket)                
            if bucket == None:
                self.tc.user.s3.delete_bucket(test_bucket)
                raise AssertionError(test_bucket + "No bucket object returned by create_bucket")
        except (S3ResponseError, S3CreateError) as e:
            raise AssertionError(test_bucket + " create caused exception: " + str(e))
        
        # Get the CORS config (none yet). 
        # Should get 404 Not Found, with "NoSuchCORSConfiguration" in the body.
        try :    
            self.log.debug("Getting (empty) CORS config")
            bucket.get_cors()
            self.tc.user.s3.delete_bucket(test_bucket)
            raise AssertionError("Did not get the expected S3ResponseError getting CORS config where none exists.")
        except S3ResponseError as e:
            if (e.status == 404 and e.reason == "Not Found" and e.code == "NoSuchCORSConfiguration"):
                self.log.debug("Caught expected S3ResponseError with expected contents, " + 
                               "getting CORS config when none exists yet.")
            else:
                self.tc.user.s3.delete_bucket(test_bucket)
                self.fail("Caught S3ResponseError getting CORS config when none exists yet," +
                          "but exception contents were unexpected: " + str(e))

        try :
            bucket_cors_set = self.set_cors_config(bucket)
        except S3ResponseError as e:
            self.tc.user.s3.delete_bucket(test_bucket)
            raise AssertionError("Caught S3ResponseError setting CORS config: " + str(e))
                    
        # Get the CORS config. Should get the config we just set.
        try :    
            self.log.debug("Getting the CORS config we just set")
            bucket_cors_retrieved = bucket.get_cors()
            #LPT always true??
            assert (bucket_cors_retrieved.to_xml() == bucket_cors_set.to_xml(), 
                'Bucket CORS config: Expected ' + bucket_cors_set.to_xml() + 
                ', Retrieved ' + bucket_cors_retrieved.to_xml())
        except S3ResponseError as e:
            self.tc.user.s3.delete_bucket(test_bucket)
            raise AssertionError("Caught S3ResponseError getting CORS config, after setting it successfully: " + str(e))

        # Delete the CORS config and bucket, unless the caller says not to.
        try :    
            self.log.debug("Deleting the CORS config")
            bucket.delete_cors()
        except S3ResponseError as e:
            self.tc.user.s3.delete_bucket(test_bucket)
            raise AssertionError("Caught S3ResponseError deleting CORS config, after setting and validating it successfully: " + str(e))

        # Get the CORS config (none anymore). 
        # Should get 404 Not Found, with "NoSuchCORSConfiguration" in the body.
        try :    
            self.log.debug("Getting (empty again) CORS config")
            bucket.get_cors()
            self.tc.user.s3.delete_bucket(test_bucket)
            raise AssertionError("Did not get the expected S3ResponseError getting CORS config after being deleted.")
        except S3ResponseError as e:
            self.tc.user.s3.delete_bucket(test_bucket)
            if (e.status == 404 and e.reason == "Not Found" and e.code == "NoSuchCORSConfiguration"):
                self.log.debug("Caught expected S3ResponseError with expected contents, " + 
                               "getting CORS config after being deleted.")
            else:
                raise AssertionError("Caught S3ResponseError getting CORS config after being deleted," +
                                     "but exception contents were unexpected: " + str(e))

    def test_cors_preflight_requests(self):
        '''
        Method: Tests sending various preflight OPTIONS requests,
        and validating the preflight responses against the CORS config.
        '''

        def send_preflight(bucket, headers=None):
            """
            Sends a CORS preflight request with the CORS request headers,
            and returns the response with any CORS response headers.
            """
            response = bucket.connection.make_request('OPTIONS', bucket.name,
                                                    headers=headers)
            if response.status == 200:
                return True
            else:
                # There's nothing in the body on a successful CORS response,
                # so we only need it to report errors.
                body = response.read()
                raise bucket.connection.provider.storage_response_error(
                    response.status, response.reason, body)

        # Test code starts here
        bucket_name="-cors-preflight-test-bucket"
        self.buckets_used = set()
        test_bucket=self.bucket_prefix + bucket_name
        self.buckets_used.add(test_bucket)
        self.log.info("Starting CORS preflight OPTIONS request tests")
        try :
            self.log.debug("Creating bucket " + test_bucket)
            bucket = self.tc.user.s3.create_bucket(test_bucket)
            if bucket == None:
                self.tc.user.s3.delete_bucket(test_bucket)
                raise AssertionError(test_bucket + "No bucket object returned by create_bucket")
        except (S3ResponseError, S3CreateError) as e:
            raise AssertionError(test_bucket + " create caused exception: " + str(e))

        try :
            self.set_cors_config(bucket)
        except S3ResponseError as e:
            self.tc.user.s3.delete_bucket(test_bucket)
            raise AssertionError("Caught S3ResponseError setting CORS config: " + str(e))
                    
        self.log.debug("Sending a preflight without any extra headers")
        try:
            preflight_response = send_preflight(bucket)
#LPT verify this after similar test below
            raise AssertionError("Did not get the expected exception! Status is %d, Reason is '%s', Code is '%s', Message is '%s'", 
                                 preflight_response.stssssatus, preflight_response.reason, preflight_response.code, preflight_response.body)
        except S3ResponseError as e:
            #self.log.debug("Status is %d, Reason is '%s', Code is '%s', Message is '%s'", e.status, e.reason, e.code, e.message)
            if (e.status == 400 and 
                e.reason == 'Bad Request' and
                e.code == 'BadRequest' and 
                e.message == 'Insufficient information. Origin request header needed.'):
                self.log.debug("Caught expected S3ResponseError: " + str(e))

        self.log.debug("Sending a preflight with Method but no Origin")
        try:
            preflight_response = send_preflight(bucket, headers={'Access-Control-Request-Method': 'GET'})
#LPT verify this after similar test below
            raise AssertionError("Did not get the expected exception! Status is %d, Reason is '%s', Code is '%s', Message is '%s'", 
                                 preflight_response.stssssatus, preflight_response.reason, preflight_response.code, preflight_response.body)
        except S3ResponseError as e:
            #self.log.debug("Status is %d, Reason is '%s', Code is '%s', Message is '%s'", e.status, e.reason, e.code, e.message)
            if (e.status == 400 and 
                e.reason == 'Bad Request' and
                e.code == 'BadRequest' and 
                e.message == 'Insufficient information. Origin request header needed.'):
                self.log.debug("Caught expected S3ResponseError: " + str(e))
       
        self.log.debug("Sending a preflight with Origin but no Method")
        try:
            preflight_response = send_preflight(bucket, headers={'Origin': 'http://www.example1.com'})
#LPT verify this after similar test below
            raise AssertionError("Did not get the expected exception! Status is %d, Reason is '%s', Code is '%s', Message is '%s'", 
                                 preflight_response.stssssatus, preflight_response.reason, preflight_response.code, preflight_response.body)
        except S3ResponseError as e:
            #self.log.debug("Status is %d, Reason is '%s', Code is '%s', Message is '%s'", e.status, e.reason, e.code, e.message)
            if (e.status == 400 and 
                e.reason == 'Bad Request' and
                e.code == 'BadRequest' and 
                e.message == 'Invalid Access-Control-Request-Method: null'):
                self.log.debug("Caught expected S3ResponseError: " + str(e))

        self.log.debug("Sending a preflight with Origin but bad Method")
        try:
            preflight_response = send_preflight(bucket, headers={'Origin': 'http://www.example1.com',
                                                                 'Access-Control-Request-Method': 'OPTIONS'})
#LPT verify this after similar test below
            raise AssertionError("Did not get the expected exception! Status is %d, Reason is '%s', Code is '%s', Message is '%s'", 
                                 preflight_response.stssssatus, preflight_response.reason, preflight_response.code, preflight_response.body)
        except S3ResponseError as e:
            #self.log.debug("Status is %d, Reason is '%s', Code is '%s', Message is '%s'", e.status, e.reason, e.code, e.message)
            if (e.status == 400 and 
                e.reason == 'Bad Request' and
                e.code == 'BadRequest' and 
                e.message == 'Invalid Access-Control-Request-Method: OPTIONS'):
                self.log.debug("Caught expected S3ResponseError: " + str(e))
       

        
    def clean_method(self):
        '''This is the teardown method'''
        #Delete the testing bucket if it is left-over
        self.log.info("Deleting the buckets used for testing")
        # Can't iterate over a list if we're deleting from it as we iterate, so make a copy
        buckets_used = self.buckets_used.copy() 
        for bucket_name in buckets_used:
            try:
                self.log.debug("Checking for bucket " + bucket_name + " for possible deletion")
                self.tc.user.s3.get_bucket(bucket_name)
            except S3ResponseError as e:
                self.log.debug("Caught S3ResponseError checking for bucket" + bucket_name + ", assuming already deleted: " + str(e))
                continue
            try:
                self.log.debug("Found bucket exists, deleting it")
                self.tc.user.s3.delete_bucket(bucket_name)
            except S3ResponseError as e:
                raise AssertionError("Caught S3ResponseError deleting bucket" + bucket_name + ": " + str(e))
        return
          
if __name__ == "__main__":
    test = CorsTestSuite()
# To run a subset of tests, use the --test-list cmd-line param, with a comma-separated
# list of tests. The clean_method() will run regardless.
    result = test.run()
    exit(result)

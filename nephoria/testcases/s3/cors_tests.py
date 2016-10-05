#!/usr/bin/env python

#
###########################################
#                                         #
#   objectstorage/S3 CORS Test Cases      #
#                                         #
###########################################

#Author: Lincoln Thomas <lincoln.thomas@hpe.com>

import copy
import time

from nephoria.testcase_utils.cli_test_runner import CliTestRunner
from nephoria.testcontroller import TestController

from boto.exception import S3ResponseError
from boto.exception import S3CreateError

from boto.s3.cors import CORSConfiguration

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
        bucket_cors_set = CORSConfiguration()

        bucket_rule_id = "Rule 1: Origin example1 can write, with all headers allowed"
        bucket_allowed_origins = ('http://www.example1.com')
        bucket_allowed_methods = ('PUT', 'POST', 'DELETE')
        bucket_allowed_headers = ('*')
        bucket_cors_set.add_rule(bucket_allowed_methods, 
                                 bucket_allowed_origins,
                                 bucket_rule_id,
                                 bucket_allowed_headers)

        bucket_rule_id = "Rule 2: Origin example2 can GET only"
        bucket_allowed_origins = ('http://www.example2.com')
        bucket_allowed_methods = ('GET')
        bucket_cors_set.add_rule(bucket_allowed_methods, 
                                 bucket_allowed_origins,
                                 bucket_rule_id)

        bucket_rule_id = "Rule 3: Any origin can HEAD"
        bucket_allowed_origins = ('*')
        bucket_allowed_methods = ('HEAD')
        bucket_cors_set.add_rule(bucket_allowed_methods, 
                                 bucket_allowed_origins,
                                 bucket_rule_id)

        bucket_rule_id = "Rule 4: Either of these wildcarded origins can do any method, "
        "can cache the response for 50 minutes, "
        "can only send request headers that begin x-amz- or Content-, "
        "and can expose the listed ExposeHeaders to clients."
        bucket_allowed_origins = ('http://www.corstest*.com', 'http://*.sample.com')
        bucket_allowed_methods = ('GET', 'HEAD', 'PUT', 'POST', 'DELETE')
        bucket_allowed_headers = ('x-amz-*', 'Content-*')
        bucket_max_age_seconds = 3000
        bucket_expose_headers = ("x-amz-server-side-encryption", 
                                 "x-amz-request-id", 
                                 "x-amz-id-2")
        bucket_cors_set.add_rule(bucket_allowed_methods, 
                                 bucket_allowed_origins, 
                                 bucket_rule_id,
                                 bucket_allowed_headers, 
                                 bucket_max_age_seconds,
                                 bucket_expose_headers)

        bucket.set_cors(bucket_cors_set)

        # Uncomment the below to make set-vs-retrieved configs different,
        # to test the comparison test code.
#         bucket_cors_set.add_rule(bucket_allowed_methods, 
#                                  bucket_allowed_origins, 
#                                  bucket_rule_id,
#                                  bucket_allowed_headers, 
#                                  bucket_max_age_seconds,
#                                  bucket_expose_headers)
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

        self.log.debug("Creating bucket " + test_bucket)
        try:
            bucket = self.tc.user.s3.create_bucket(test_bucket)
        except (S3ResponseError, S3CreateError) as e:
            raise AssertionError(test_bucket + " create caused exception: " + str(e))
        else:
            if bucket == None:
                raise AssertionError(test_bucket + "No bucket object returned by create_bucket")

        self.log.debug("Getting (empty) CORS config")
        try:    
            bucket.get_cors()
        except S3ResponseError as e:
            if (e.status == 404 and e.reason == "Not Found" and e.code == "NoSuchCORSConfiguration"):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError("Did not get the expected S3ResponseError getting CORS config where none exists.")

        self.log.debug("Setting CORS config on " + test_bucket)
        try:
            bucket_cors_set = self.set_cors_config(bucket)
        except S3ResponseError as e:
            raise AssertionError("Caught S3ResponseError setting CORS config: " + str(e))
                    
        self.log.debug("Getting the CORS config we just set")
        try:    
            bucket_cors_retrieved = bucket.get_cors()
        except S3ResponseError as e:
            raise AssertionError("Caught S3ResponseError getting CORS config, after setting it successfully: " + str(e))

        assert bucket_cors_retrieved.to_xml() == bucket_cors_set.to_xml(), (
            'Bucket CORS config retrieved is not the same as what we set.' +
            '\n---------- Expected:\n' + 
            bucket_cors_set.to_xml() +
            '\n---------- Retrieved:\n' + 
            bucket_cors_retrieved.to_xml())

        self.log.debug("Deleting the CORS config")
        try:    
            bucket.delete_cors()
        except S3ResponseError as e:
            raise AssertionError("Caught S3ResponseError deleting CORS config, after setting and validating it successfully: " + str(e))

        self.log.debug("Getting (empty again) CORS config")
        try:    
            bucket.get_cors()
        except S3ResponseError as e:
            if (e.status == 404 and e.reason == "Not Found" and e.code == "NoSuchCORSConfiguration"):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError("Did not get the expected S3ResponseError getting CORS config after being deleted.")


    def test_cors_preflight_requests(self):
        '''
        Method: Tests sending various preflight OPTIONS requests,
        and validating the preflight responses against the CORS config.
        '''

        def send_preflight(bucket, key_name='', headers=None):
            """
            Sends a CORS preflight request with the CORS request headers,
            and returns the response with any CORS response headers.
            """
            response = bucket.connection.make_request('OPTIONS', bucket.name, key_name,
                                                    headers=headers)
            if response.status == 200:
                return response
            else:
                # There's nothing in the body on a successful CORS response,
                # so we only need it to report errors.
                body = response.read()
                raise bucket.connection.provider.storage_response_error(
                    response.status, response.reason, body)

        def preflight_invalid(preflight_response):
            return ("Preflight response invalid: Status is %d, Reason is '%s', "
                    "Message is:\n%s\nBody is:\n%s" % 
                    (preflight_response.status, preflight_response.reason, 
                    preflight_response.msg, preflight_response.read()))
                  
        def preflight_non_exception(preflight_response):
            return ("Did not get the expected exception. " +
                    preflight_invalid(preflight_response))
            
        # Test code starts here
        bucket_name="-cors-preflight-test-bucket"
        self.buckets_used = set()
        test_bucket=self.bucket_prefix + bucket_name
        self.buckets_used.add(test_bucket)
        self.log.info("Starting CORS preflight OPTIONS request tests")

        self.log.debug("Creating bucket " + test_bucket)
        try:
            bucket = self.tc.user.s3.create_bucket(test_bucket)
        except (S3ResponseError, S3CreateError) as e:
            raise AssertionError(test_bucket + " create caused exception: " + str(e))
        else:
            if bucket == None:
                raise AssertionError(test_bucket + "No bucket object returned by create_bucket")

        # Create a key name but don't actually create an object.
        # The key will be ignored by the server for an preflight OPTIONS request.
        dummy_key_name = "no_such_object"
        
        self.log.debug("Testing preflights with no CORS config")
        
        self.log.debug("Sending a preflight without any extra headers")
        try:
            # Target for all tests below is the object, not the bucket, unless specified.
            # Target for this test is the bucket, not the object.
            preflight_response = send_preflight(bucket)
        except S3ResponseError as e:
            if (e.status == 400 and 
                e.reason == 'Bad Request' and
                e.code == 'BadRequest' and 
                e.message == 'Insufficient information. Origin request header needed.'):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError(preflight_non_exception(preflight_response))

        self.log.debug("Sending a preflight with Origin but bad Method")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name, 
                                                headers={'Origin': 'http://www.example1.com',
                                                         'Access-Control-Request-Method': 'BLAH'})
        except S3ResponseError as e:
            if (e.status == 400 and 
                e.reason == 'Bad Request' and
                e.code == 'BadRequest' and 
                e.message == 'Invalid Access-Control-Request-Method: BLAH'):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError(preflight_non_exception(preflight_response))

        self.log.debug("Sending a preflight with Origin and valid Method")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name,
                                                headers={'Origin': 'http://www.example1.com',
                                                         'Access-Control-Request-Method': 'POST'})
        except S3ResponseError as e:
            if (e.status == 403 and 
                e.reason == 'Forbidden' and
                e.code == 'AccessForbidden' and 
                e.message == 'CORSResponse: CORS is not enabled for this bucket.'):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError(preflight_non_exception(preflight_response))

        self.log.debug("Setting CORS config on " + test_bucket)
        try:
            self.set_cors_config(bucket)
        except S3ResponseError as e:
            raise AssertionError("Caught S3ResponseError setting CORS config: " + str(e))
                    
        self.log.debug("Testing preflights with CORS config in place")
        
        self.log.debug("Sending a preflight without any extra headers")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name)
        except S3ResponseError as e:
            if (e.status == 400 and 
                e.reason == 'Bad Request' and
                e.code == 'BadRequest' and 
                e.message == 'Insufficient information. Origin request header needed.'):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError(preflight_non_exception(preflight_response))

        self.log.debug("Sending a preflight with Method but no Origin")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name,
                                                headers={'Access-Control-Request-Method': 'GET'})
        except S3ResponseError as e:
            if (e.status == 400 and 
                e.reason == 'Bad Request' and
                e.code == 'BadRequest' and 
                e.message == 'Insufficient information. Origin request header needed.'):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError(preflight_non_exception(preflight_response))

        self.log.debug("Sending a preflight with Origin but no Method")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name,
                                                headers={'Origin': 'http://www.example1.com'})
        except S3ResponseError as e:
            if (e.status == 400 and 
                e.reason == 'Bad Request' and
                e.code == 'BadRequest' and 
                e.message == 'Invalid Access-Control-Request-Method: null'):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError(preflight_non_exception(preflight_response))

        self.log.debug("Sending a preflight with Origin but unsupported Method (OPTIONS)")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name, 
                                                headers={'Origin': 'http://www.example1.com',
                                                         'Access-Control-Request-Method': 'OPTIONS'})
        except S3ResponseError as e:
            if (e.status == 400 and 
                e.reason == 'Bad Request' and
                e.code == 'BadRequest' and 
                e.message == 'Invalid Access-Control-Request-Method: OPTIONS'):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError(preflight_non_exception(preflight_response))

        self.log.debug("Sending a preflight with matching Origin example1 and Method")
        try:
            # Target for this test is the bucket, not the object.
            preflight_response = send_preflight(bucket, 
                                                headers={'Origin': 'http://www.example1.com',
                                                         'Access-Control-Request-Method': 'POST'})
        except S3ResponseError as e:
            raise AssertionError("Caught S3ResponseError: " + str(e))
        else:
            if (preflight_response.status == 200 and
                preflight_response.reason == 'OK' and
                preflight_response.getheader('Access-Control-Allow-Origin') == 'http://www.example1.com' and
                preflight_response.getheader('Access-Control-Allow-Methods') == 'PUT, POST, DELETE' and
                preflight_response.getheader('Access-Control-Allow-Credentials') == 'true' and
                preflight_response.getheader('Vary') == 'Origin, Access-Control-Request-Headers, Access-Control-Request-Method' and
                preflight_response.getheader('Content-Length') == '0'):
                self.log.debug("Extra CORS headers valid")
            else:
                raise AssertionError(preflight_invalid(preflight_response))

        self.log.debug("Sending a preflight with matching Origin example2 and Method")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name, 
                                                headers={'Origin': 'http://www.example2.com',
                                                         'Access-Control-Request-Method': 'GET'})
        except S3ResponseError as e:
            raise AssertionError("Caught S3ResponseError: " + str(e))
        else:
            if (preflight_response.status == 200 and
                preflight_response.reason == 'OK' and
                preflight_response.getheader('Access-Control-Allow-Origin') == 'http://www.example2.com' and
                preflight_response.getheader('Access-Control-Allow-Methods') == 'GET' and
                preflight_response.getheader('Access-Control-Allow-Credentials') == 'true' and
                preflight_response.getheader('Vary') == 'Origin, Access-Control-Request-Headers, Access-Control-Request-Method' and
                preflight_response.getheader('Content-Length') == '0'):
                self.log.debug("Extra CORS headers valid")
            else:
                raise AssertionError(preflight_invalid(preflight_response))

        self.log.debug("Sending a preflight with matching Origin (any origin) and Method HEAD")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name, 
                                                headers={'Origin': 'http://www.mycorssite1.com',
                                                         'Access-Control-Request-Method': 'HEAD'})
        except S3ResponseError as e:
            raise AssertionError("Caught S3ResponseError: " + str(e))
        else:
            if (preflight_response.status == 200 and
                preflight_response.reason == 'OK' and
                preflight_response.getheader('Access-Control-Allow-Origin') == '*' and
                preflight_response.getheader('Access-Control-Allow-Methods') == 'HEAD' and
                preflight_response.getheader('Access-Control-Allow-Credentials') == None and
                preflight_response.getheader('Vary') == 'Origin, Access-Control-Request-Headers, Access-Control-Request-Method' and
                preflight_response.getheader('Content-Length') == '0'):
                self.log.debug("Extra CORS headers valid")
            else:
                raise AssertionError(preflight_invalid(preflight_response))

        self.log.debug("Sending a preflight with matching Origin (sample.com with no port defined)")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name, 
                                                headers={'Origin': 'http://this.sample.com',
                                                         'Access-Control-Request-Method': 'DELETE'})
        except S3ResponseError as e:
            raise AssertionError("Caught S3ResponseError: " + str(e))
        else:
            if (preflight_response.status == 200 and
                preflight_response.reason == 'OK' and
                preflight_response.getheader('Access-Control-Allow-Origin') == 'http://this.sample.com' and
                preflight_response.getheader('Access-Control-Allow-Methods') == 'GET, HEAD, PUT, POST, DELETE' and
                preflight_response.getheader('Access-Control-Expose-Headers') == 'x-amz-server-side-encryption, x-amz-request-id, x-amz-id-2' and
                preflight_response.getheader('Access-Control-Max-Age') == '3000' and
                preflight_response.getheader('Access-Control-Allow-Credentials') == 'true' and
                preflight_response.getheader('Vary') == 'Origin, Access-Control-Request-Headers, Access-Control-Request-Method' and
                preflight_response.getheader('Content-Length') == '0'):
                self.log.debug("Extra CORS headers valid")
            else:
                raise AssertionError(preflight_invalid(preflight_response))

        self.log.debug("Sending a preflight with non-matching Origin (sample.com with port 80)")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name, 
                                                headers={'Origin': 'http://this.sample.com:80',
                                                         'Access-Control-Request-Method': 'DELETE'})
        except S3ResponseError as e:
            if (e.status == 403 and 
                e.reason == 'Forbidden' and
                e.code == 'AccessForbidden' and 
                e.message == 'CORSResponse: This CORS request is not allowed. '
                'This is usually because the evaluation of Origin, request method / '
                'Access-Control-Request-Method or Access-Control-Request-Headers are '
                "not whitelisted by the resource's CORS spec."):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError(preflight_non_exception(preflight_response))

        self.log.debug("Sending a preflight with matching Origin corstest and 2 good Request Headers")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name, 
                                                headers={'Origin': 'http://www.corstest.com',
                                                         'Access-Control-Request-Method': 'DELETE',
                                                         'Access-Control-Request-Headers': 'x-amz-date,Content-Length'})
        except S3ResponseError as e:
            raise AssertionError("Caught S3ResponseError: " + str(e))
        else:
            if (preflight_response.status == 200 and
                preflight_response.reason == 'OK' and
                preflight_response.getheader('Access-Control-Allow-Origin') == 'http://www.corstest.com' and
                preflight_response.getheader('Access-Control-Allow-Methods') == 'GET, HEAD, PUT, POST, DELETE' and
                preflight_response.getheader('Access-Control-Allow-Headers') == 'x-amz-date, Content-Length' and
                preflight_response.getheader('Access-Control-Expose-Headers') == 'x-amz-server-side-encryption, x-amz-request-id, x-amz-id-2' and
                preflight_response.getheader('Access-Control-Max-Age') == '3000' and
                preflight_response.getheader('Access-Control-Allow-Credentials') == 'true' and
                preflight_response.getheader('Vary') == 'Origin, Access-Control-Request-Headers, Access-Control-Request-Method' and
                preflight_response.getheader('Content-Length') == '0'):
                self.log.debug("Extra CORS headers valid")
            else:
                raise AssertionError(preflight_invalid(preflight_response))

        self.log.debug("Sending a preflight with matching Origin corstest1.company.com and 2 good Request Headers")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name, 
                                                headers={'Origin': 'http://www.corstest1.company.com',
                                                         'Access-Control-Request-Method': 'DELETE',
                                                         'Access-Control-Request-Headers': 'x-amz-date,Content-Length'})
        except S3ResponseError as e:
            raise AssertionError("Caught S3ResponseError: " + str(e))
        else:
            if (preflight_response.status == 200 and
                preflight_response.reason == 'OK' and
                preflight_response.getheader('Access-Control-Allow-Origin') == 'http://www.corstest1.company.com' and
                preflight_response.getheader('Access-Control-Allow-Methods') == 'GET, HEAD, PUT, POST, DELETE' and
                preflight_response.getheader('Access-Control-Allow-Headers') == 'x-amz-date, Content-Length' and
                preflight_response.getheader('Access-Control-Expose-Headers') == 'x-amz-server-side-encryption, x-amz-request-id, x-amz-id-2' and
                preflight_response.getheader('Access-Control-Max-Age') == '3000' and
                preflight_response.getheader('Access-Control-Allow-Credentials') == 'true' and
                preflight_response.getheader('Vary') == 'Origin, Access-Control-Request-Headers, Access-Control-Request-Method' and
                preflight_response.getheader('Content-Length') == '0'):
                self.log.debug("Extra CORS headers valid")
            else:
                raise AssertionError(preflight_invalid(preflight_response))

        self.log.debug("Sending a preflight with matching Origin corstest1.company.com with 1 good and 1 bad Request Header")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name, 
                                                headers={'Origin': 'http://www.corstest1.company.com',
                                                         'Access-Control-Request-Method': 'DELETE',
                                                         'Access-Control-Request-Headers': 'x-amz-date,Date'})
        except S3ResponseError as e:
            if (e.status == 403 and 
                e.reason == 'Forbidden' and
                e.code == 'AccessForbidden' and 
                e.message == 'CORSResponse: This CORS request is not allowed. '
                'This is usually because the evaluation of Origin, request method / '
                'Access-Control-Request-Method or Access-Control-Request-Headers are '
                "not whitelisted by the resource's CORS spec."):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError(preflight_non_exception(preflight_response))

        self.log.debug("Sending a preflight with no matching Origin/Method combination")
        try:
            preflight_response = send_preflight(bucket, dummy_key_name, 
                                                headers={'Origin': 'http://www.mycorssite1.com',
                                                         'Access-Control-Request-Method': 'GET'})
        except S3ResponseError as e:
            if (e.status == 403 and 
                e.reason == 'Forbidden' and
                e.code == 'AccessForbidden' and 
                e.message == 'CORSResponse: This CORS request is not allowed. '
                'This is usually because the evaluation of Origin, request method / '
                'Access-Control-Request-Method or Access-Control-Request-Headers are '
                "not whitelisted by the resource's CORS spec."):
                self.log.debug("Caught expected S3ResponseError with expected contents.")
            else:
                raise AssertionError("Caught S3ResponseError but exception contents were unexpected: " + str(e))
        else:
            raise AssertionError(preflight_non_exception(preflight_response))


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

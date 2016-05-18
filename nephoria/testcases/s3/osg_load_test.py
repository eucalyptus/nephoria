#!/usr/bin/env python
from __future__ import division

import hashlib
import logging
from cStringIO import StringIO
import re
import tempfile

import os

import datetime
from concurrent.futures.thread import ThreadPoolExecutor
from math import ceil

from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
from nephoria.testcontroller import TestController
import copy
import time


class OSGConcurrentTests(CliTestRunner):

    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)

    _DEFAULT_CLI_ARGS['buckets'] = {
        'args': ['--buckets'],
        'kwargs': {'dest': 'buckets', 'help': 'Number of buckets', 'default': 5, 'type': int}
    }

    _DEFAULT_CLI_ARGS['objects'] = {
        'args': ['--objects'],
        'kwargs': {'dest': 'objects', 'help': 'Number of objects', 'default': 5, 'type': int}
    }

    _DEFAULT_CLI_ARGS['threads'] = {
        'args': ['--threads'],
        'kwargs': {'dest': 'threads', 'help': 'Number of threads', 'default': 3, 'type': int}
    }

    _DEFAULT_CLI_ARGS['object_size'] = {
        'args': ['--object-size'],
        'kwargs': {'dest': 'object_size', 'help': 'Size of the objects to upload', 'default': 5, 'type': int}
    }

    _DEFAULT_CLI_ARGS['mpu_threshold'] = {
        'args': ['--mpu-threshold'],
        'kwargs': {'dest': 'mpu_threshold', 'default': 5120, 'type': int,
                   'help': 'Multipart upload is used when the object size is bigger than the mpu-threshold'
                           'value in Kilobyte. Any value less than 5120KB will result single file upload. '
                           'Default value is used when not passed as an argument.'}
    }

    bucket_list = []
    temp_files = []


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

    def create_file(self, size_in_kb, file_name="nephoria-object"):
        temp_file = tempfile.NamedTemporaryFile(mode='w+b', prefix=file_name)
        self.temp_files.append(temp_file)
        temp_file.write(os.urandom(1024 * size_in_kb))
        return temp_file.name

    def get_object(self, bucket, key_name, meta=True):
        """
        Writes the object to a temp file and returns the meta info of the object e.g hash, name.
        Returns the downloaded object when meta is set to False.
        """
        # self.log.debug("Getting object '" + key_name + "'")
        ret_key = bucket.get_key(key_name)
        temp_object = tempfile.NamedTemporaryFile(mode="w+b", prefix="eutester-mpu")
        self.temp_files.append(temp_object)
        ret_key.get_contents_to_file(temp_object)
        if meta:
            return {'name': temp_object.name, 'hash': self.get_hash(temp_object.name)}
        return temp_object

    def get_hash(self, file_path):
        return hashlib.md5(self.get_content(file_path)).hexdigest()

    def get_content(self, file_path):
        with open(file_path) as file_to_check:
            data = file_to_check.read()
        return data

    def single_upload(self, bucket, key_name, file_path):
        key = bucket.new_key(key_name)
        key.set_contents_from_filename(file_path)
        self.log.debug("Uploaded key '" + key_name + "' to bucket '" + bucket.name + "'")
        return key

    def multipart_upload(self, bucket, key_name, eufile):
        part_size = 1024 * self.args.mpu_threshold
        eufile.seek(0, os.SEEK_END)
        eufile_size = eufile.tell()
        num_parts = int(ceil(eufile_size / part_size))

        mpu = bucket.initiate_multipart_upload(key_name)
        self.log.debug("Initiated MPU. Using MPU Id: " + mpu.id)

        for i in range(num_parts):
            start = part_size * i
            file_part = open(eufile.name, 'rb')
            file_part.seek(start)
            data = file_part.read(part_size)
            file_part.close()
            mpu.upload_part_from_file(StringIO(data), i + 1)
            self.log.debug("Uploaded part " + str(i + 1) + " of '" + key_name + "' to bucket '" + bucket.name + "'")
        self.log.debug("Completing multipart upload of '" + key_name + "' to bucket '" +
                   bucket.name + "'" + " using mpu id: " + mpu.id)
        mpu.complete_upload()
        self.log.debug("Completed multipart upload of '" + key_name + "' to bucket '" + bucket.name + "'")

    def put_get_check(self, bucket_name, key_name, eu_file):
        """
        PUT objects, GET objects and then verify objects with object hash
        5MB is a hard-coded limit for MPU in OSG
        """
        bucket = self.tc.admin.s3.get_bucket_by_name(bucket_name)
        if (os.path.getsize(eu_file.name) > (5 * 1024 * 1024)) and (self.args.mpu_threshold >= (5 * 1024)):
            self.multipart_upload(bucket, key_name, eu_file)
        else:
            upload_time = self.time_to_exec(self.single_upload, bucket, key_name, eu_file.name)
            with open('osg_perf.log', 'a') as f:
                f.write('PUT\t' + str(upload_time['time']) + '\n')

        get_time = self.time_to_exec(self.get_object, bucket, key_name)
        with open('osg_perf.log', 'a') as f:
            f.write('GET\t' + str(get_time['time']) + '\n')
        ret_object_meta = get_time['output']
        local_object_hash = self.get_hash(eu_file.name)

        # self.log.debug("Matching local and remote hashes of object: " + eu_file.name)
        # self.log.debug("Remote object: " + ret_object_meta['hash'])
        # self.log.debug("Local object:  " + local_object_hash)
        if ret_object_meta['hash'] != local_object_hash:
            # self.log.debug("return_object hash: " + ret_object_meta['hash'])
            # self.log.debug("local_object hash: " + local_object_hash)
            # self.log.debug("Uploaded content and downloaded content are not same.")
            return False
        return True

    def time_to_exec(self, method, *args, **kwargs):
        start_time = time.time()
        method_name = method.__name__
        try:
            result = method(*args, **kwargs)
        except Exception as e:
            end_time = time.time()
            total_time = end_time - start_time
            self.log.error("Failed to run method: " + method_name)
            self.log.error(e.message)
        else:
            end_time = time.time()
            total_time = end_time - start_time
        return {'time': total_time, 'output': result}

    def create_buckets(self, num):
        for i in range(num):
            bucket_name = self.bucket_prefix + '-' + str(i)
            self.log.debug('creating bucket: ' + bucket_name)
            self.bucket_list.append(bucket_name)
            bucket = self.tc.admin.s3.connection.create_bucket(bucket_name)

        self.log.debug(self.tc.admin.s3.connection.get_all_buckets())

    def test_concurrent_upload(self):
        with open('osg_perf.log', 'w') as f:
            f.write(str('OPS\t\tTime') + '\n')
            f.write(str('---\t\t----') + '\n')
        self.log.debug("Creating buckets..")
        self.create_buckets(self.args.buckets)

        self.log.debug("Creating object of " + str(self.args.object_size) + "KB")
        eu_file = open(self.create_file(self.args.object_size))

        thread_pool = []
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for i in range(self.args.buckets):
                for j in range(self.args.objects):
                    thread_pool.append(executor.submit(self.put_get_check, bucket_name=self.bucket_list[i],
                                                       key_name=eu_file.name + '-' + str(j), eu_file=eu_file))

        for tp in thread_pool:
            try:
                if not tp.result():
                    self.log.error("[CRITICAL] failed upload in thread")
            except Exception as e:
                self.log.error("Found exception in thread-pool: " + e.message)

    def clear_bucket(self, bucket_name):
        bucket = self.tc.admin.s3.get_bucket_by_name(bucket_name)
        for key in bucket:
            self.log.debug('deleting key: ' + key.name)
            delete_time = self.time_to_exec(key.delete)
            with open('osg_perf.log', 'a') as f:
                f.write('DEL\t' + str(delete_time['time']) + '\n')

    def clean_method(self):
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for bucket_name in self.bucket_list:
                executor.submit(self.clear_bucket, bucket_name)

        for bucket_name in self.bucket_list:
            self.tc.admin.s3.connection.delete_bucket(bucket_name)
        for tf in self.temp_files:
            tf.close()

if __name__ == "__main__":
    test = OSGConcurrentTests()
    result = test.run()
    exit(result)

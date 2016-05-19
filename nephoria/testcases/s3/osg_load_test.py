#!/usr/bin/env python
from __future__ import division

from cStringIO import StringIO
import tempfile

import os
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
    total_put_latency = 0
    total_get_latency = 0
    total_del_latency = 0

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
            bucket_prefix = "nephoria-bucket-" + str(int(time.time()))
        return bucket_prefix

    @bucket_prefix.setter
    def bucket_prefix(self, value):
        setattr(self, '__bucket_prefix', value)

    def create_file(self, size_in_kb, file_name="nephoria-object"):
        temp_file = tempfile.NamedTemporaryFile(mode='w+b', prefix=file_name)
        self.temp_files.append(temp_file)
        temp_file.write(os.urandom(1024 * size_in_kb))
        return temp_file.name

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
                f.write('PUT\t' + str(upload_time) + '\n')
        return True

    def time_to_exec(self, method, *args, **kwargs):
        start_time = time.time()
        method_name = method.__name__
        try:
            result = method(*args, **kwargs)
        except Exception as e:
            self.log.error(e)
            end_time = time.time()
            total_time = end_time - start_time
            self.log.error("Failed to run method: " + method_name)
        else:
            end_time = time.time()
            total_time = end_time - start_time
        return total_time

    def create_buckets(self, num):
        for i in range(num):
            bucket_name = self.bucket_prefix + '-' + str(i)
            self.log.debug('creating bucket: ' + bucket_name)
            self.bucket_list.append(bucket_name)
            bucket = self.tc.admin.s3.connection.create_bucket(bucket_name)

        self.log.debug(self.tc.admin.s3.connection.get_all_buckets())

    def get_content(self, key):
        self.log.debug("Getting content as string for: " + key.name)
        content = key.get_contents_as_string()



    def put_objects(self, bucket_name, key_name, eu_file=None):
        """
        Args:
            bucket_name: existing bucket_name to put objects
            key_name: name of the key
            eu_file: file to put into bucket
        """
        bucket = self.tc.admin.s3.get_bucket_by_name(bucket_name)

        if (os.path.getsize(eu_file.name) > (5 * 1024 * 1024)) and (self.args.mpu_threshold >= (5 * 1024)):
            self.multipart_upload(bucket, key_name, eu_file)
        else:
            upload_time = self.time_to_exec(self.single_upload, bucket, key_name, eu_file.name)
            self.total_put_latency = self.total_put_latency + upload_time
            with open('osg_perf.log', 'a') as f:
                f.write('PUT\t\t' + str(upload_time) + '\n')
            return True

    def test1_concurrent_upload(self):
        with open('osg_perf.log', 'w') as f:
            f.write(str('OPS\t\t   Time   ') + '\n')
            f.write(str('---\t\t----------') + '\n')
        self.log.debug("Creating buckets..")
        self.create_buckets(self.args.buckets)

        self.log.debug("Creating object of " + str(self.args.object_size) + "KB")
        eu_file = open(self.create_file(self.args.object_size))

        thread_pool = []
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for bucket_name in self.bucket_list:
                for k in range(self.args.objects):
                    thread_pool.append(executor.submit(self.put_objects,
                                                       bucket_name=bucket_name,
                                                       key_name=eu_file.name + '-' + str(k),
                                                       eu_file=eu_file))
        lock_time = 2
        self.log.debug("len(thread_pool): " + str(len(thread_pool)))
        while len(thread_pool) < (self.args.buckets * self.args.objects):
            self.log.debug("len(thread_pool): " + str(len(thread_pool)))
            self.log.warning("Uncanny lock, sleeping for " + str(lock_time) + " seconds.")
            time.sleep(lock_time)

        for tp in thread_pool:
            try:
                if not tp.result():
                    self.log.error("[CRITICAL] failed upload in thread")
            except Exception as e:
                self.log.error("Found exception in thread-pool: " + e.message)

    def get_objects(self, key):
        download_time = self.time_to_exec(self.get_content, key)
        self.total_get_latency = self.total_get_latency + download_time
        with open('osg_perf.log', 'a') as f:
            f.write('GET\t\t' + str(download_time) + '\n')

    def test2_get_objects(self):
        get_thread_pool = []
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for bucket_name in self.bucket_list:
                bucket = self.tc.admin.s3.get_bucket_by_name(bucket_name)
                max_keys = 10
                keys = bucket.get_all_keys(max_keys=max_keys)
                for key in keys:
                    get_thread_pool.append(executor.submit(self.get_objects, key))
                while keys.next_marker:
                    self.log.debug("found keys.next_marker: " + keys.next_marker)
                    keys = bucket.get_all_keys(marker=keys.next_marker)
                    for key in keys:
                        get_thread_pool.append(executor.submit(self.get_objects, key))
        self.log.debug("len(get_thread_pool): " + str(len(get_thread_pool)))

        lock_time = 2
        while len(get_thread_pool) < (self.args.buckets * self.args.objects):
            self.log.debug("len(get_thread_pool): " + str(len(get_thread_pool)))
            self.log.warning("Uncanny lock, sleeping for " + str(lock_time) + " seconds.")
            time.sleep(lock_time)

    def delete_key(self, key):
        self.log.debug('deleting key: ' + key.name)
        delete_time = self.time_to_exec(key.delete)
        self.total_del_latency = self.total_del_latency + delete_time
        with open('osg_perf.log', 'a') as f:
            f.write('DEL\t\t' + str(delete_time) + '\n')
        return True

    def test3_delete_objects(self):
        clean_thread_pool = []

        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for bucket_name in self.bucket_list:
                bucket = self.tc.admin.s3.get_bucket_by_name(bucket_name)
                max_keys = 10
                keys = bucket.get_all_keys(max_keys=max_keys)
                for key in keys:
                    clean_thread_pool.append(executor.submit(self.delete_key, key))
                while keys.next_marker:
                    self.log.debug("found keys.next_marker: " + keys.next_marker)
                    keys = bucket.get_all_keys(marker=keys.next_marker)
                    for key in keys:
                        clean_thread_pool.append(executor.submit(self.delete_key, key))

        self.log.debug("len(clean_thread_pool): " + str(len(clean_thread_pool)))
        lock_time = 2
        while len(clean_thread_pool) < (self.args.buckets * self.args.objects):
            self.log.debug("len(clean_thread_pool): " + str(len(clean_thread_pool)))
            self.log.warning("Uncanny lock, sleeping for " + str(2) + " seconds.")
            time.sleep(lock_time)

        for ctp in clean_thread_pool:
            try:
                if not ctp.result():
                    self.log.error("[CRITICAL] failed delete in thread")
            except Exception as e:
                self.log.error("Found exception in clean_thread_pool: " + e.message)

        for bucket_name in self.bucket_list:
            self.tc.admin.s3.connection.delete_bucket(bucket_name)
        for tf in self.temp_files:
            tf.close()

    def test4_calculate_average_latency(self):
        with open('osg_perf.log', 'a') as f:
            f.write('\n\n')
            f.write('  Average Latency  ' + '\n')
            f.write('-------------------' + '\n')
        avg_put = self.total_put_latency / (self.args.objects * self.args.buckets)
        with open('osg_perf.log', 'a') as f:
            f.write('Avg PUT\t\t' + str(avg_put) + '\n')
        avg_get = self.total_get_latency / (self.args.objects * self.args.buckets)
        with open('osg_perf.log', 'a') as f:
            f.write('Avg GET\t\t' + str(avg_get) + '\n')
        avg_del = self.total_del_latency / (self.args.objects * self.args.buckets)
        with open('osg_perf.log', 'a') as f:
            f.write('Avg DEL\t\t' + str(avg_del) + '\n')

    def clean_method(self):
        pass

if __name__ == "__main__":
    test = OSGConcurrentTests()
    test_result = test.run()
    exit(test_result)

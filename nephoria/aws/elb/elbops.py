# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2014, Eucalyptus Systems, Inc.
# All rights reserved.
#
# Redistribution and use of this software in source and binary forms, with or
# without modification, are permitted provided that the following conditions
# are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import re
import copy
import time
from boto.ec2.regioninfo import RegionInfo
import boto
from concurrent.futures import ThreadPoolExecutor
import urllib2
import cookielib
import requests
from nephoria.baseops.botobaseops import BotoBaseOps
from boto.ec2.elb import ELBConnection
from boto.ec2.elb.listener import Listener
from boto.ec2.elb.healthcheck import HealthCheck
from os.path import join


class ELBops(BotoBaseOps):
    SERVICE_PREFIX = 'elasticloadbalancing'
    EUCARC_URL_NAME = 'elb_url'
    CONNECTION_CLASS = ELBConnection

    def setup_resource_trackers(self):
        """
        Setup keys in the test_resources hash in order to track artifacts created
        """
        self.test_resources["load_balancers"] = []
        self.test_resources_clean_methods["load_balanceers"] = self.cleanup_load_balancers

    def create_listener(self, load_balancer_port=80, protocol="HTTP", instance_port=80, load_balancer=None):
        self.log.debug(
            "Creating ELB Listener for protocol " + protocol + " and port " + str(load_balancer_port) + "->" + str(
                instance_port))
        listner = Listener(load_balancer=load_balancer,
                           protocol=protocol,
                           load_balancer_port=load_balancer_port,
                           instance_port=instance_port)
        return listner

    def create_healthcheck(self, target="HTTP:80/instance-name", interval=5, timeout=2, healthy_threshold=2,
                           unhealthy_threshold=10):
        self.log.debug("Creating healthcheck: " + target + " interval=" + str(interval) + " timeout=" + str(timeout) +
                   " healthy threshold=" + str(healthy_threshold) + " unhealthy threshold=" + str(unhealthy_threshold))
        healthcheck = HealthCheck(target=target,
                                  timeout=timeout,
                                  interval=interval,
                                  healthy_threshold=healthy_threshold,
                                  unhealthy_threshold=unhealthy_threshold)
        return healthcheck

    def generate_http_requests(self, url, count=100, worker_threads=20):
        self.log.debug("Generating {0} http requests against {1}".format(count, url))
        jar = cookielib.FileCookieJar("cookies")
        handler = urllib2.HTTPCookieProcessor(jar)
        opener = urllib2.build_opener(handler)
        urllib2.install_opener(opener)
        response_futures = []
        with ThreadPoolExecutor(max_workers=worker_threads) as executor:
            for _ in range(count):
                response_futures.append(executor.submit(requests.get, url))

        responses = []
        for response in response_futures:
            http_response = response.result()
            try:
                http_error_code = http_response.status_code
                if http_error_code == 200:
                    result = "{0}".format(http_response.content.rstrip())
                    self.log.debug("Request response: " + result)
                    responses.append(result)
                else:
                    raise Exception("Error code " + http_error_code + " found when sending " +
                                    str(worker_threads) + " concurrent requests to " + url)
            finally:
                http_response.close()
        return responses

    def register_lb_instances(self, name, instances, timeout=360, poll_count=15):
        inst_ids = [inst.id for inst in instances]
        self.log.debug("Registering instances {0} with lb {1}".format(inst_ids, name))
        self.register_instances(name, inst_ids)
        poll_sleep = timeout / poll_count
        for _ in range(poll_count):
            self.log.debug("Checking instance health for {0}".format(inst_ids))
            inst_states = self.describe_instance_health(name, instances=inst_ids)
            states = [state.state for state in inst_states]
            if not states or 'OutOfService' in states:
                time.sleep(poll_sleep)
            elif 'InService' in states:
                self.log.debug("Instances {0} for lb {1} are InService".format(inst_ids, name))
                return
            else:
                # This should never happen
                pass
        raise Exception("Instances {0} failed to enter InService state before timeout".format(inst_ids))

    def create_load_balancer(self, zones, name="test", load_balancer_port=80, instances=None):
        self.log.debug("Creating load balancer: " + name + " on port " + str(load_balancer_port))
        listener = self.create_listener(load_balancer_port=load_balancer_port)
        super(ELBops, self).create_load_balancer(name, zones=zones, listeners=[listener])

        healthcheck = self.create_healthcheck()
        self.configure_health_check(name, healthcheck)

        if instances:
            self.register_instances(name, instances)

        ### Validate the creation of the load balancer
        lbs = self.get_all_load_balancers(load_balancer_names=[name])
        if not "load_balancers" in self.test_resources:
            self.test_resources["load_balancers"] = []

        if len(lbs) == 1:
            self.test_resources["load_balancers"].append(lbs[0])
            return lbs[0]
        else:
            raise Exception("Unable to retrieve load balancer after creation")

    def delete_load_balancers(self, lbs, timeout=60):
        for lb in lbs:
            self.delete_load_balancer(lb, timeout)

    def delete_load_balancer(self, lb, timeout=60, poll_sleep=10):
        self.log.debug("Deleting Loadbalancer: {0}".format(lb.name))
        self.delete_load_balancer(lb.name)
        poll_count = timeout / poll_sleep
        for _ in range(poll_count):
            lbs = self.get_all_load_balancers(load_balancer_names=[lb.name])
            if lb in lbs:
                time.sleep(poll_sleep)
        if lb in self.test_resources["load_balancers"]:
            self.test_resources["load_balancers"].remove(lb)

    def create_app_cookie_stickiness_policy(self, name, lb_name, policy_name):
        self.log.debug("Create app cookie stickiness policy: " + str(policy_name))
        self.create_app_cookie_stickiness_policy(name=name,
                                                     lb_name=lb_name,
                                                     policy_name=policy_name)

    def create_lb_cookie_stickiness_policy(self, cookie_expiration_period, lb_name, policy_name):
        self.log.debug("Create lb cookie stickiness policy: " + str(policy_name))
        self.create_lb_cookie_stickiness_policy(cookie_expiration_period=cookie_expiration_period,
                                                    lb_name=lb_name,
                                                    policy_name=policy_name)

    def create_lb_policy(self, lb_name, policy_name, policy_type, policy_attributes):
        self.log.debug("Create lb policy: " + str(policy_name))
        self.create_lb_policy(lb_name=lb_name,
                                  policy_name=policy_name,
                                  policy_type=policy_type,
                                  policy_attributes=policy_attributes)

    def set_lb_policy(self, lb_name, lb_port, policy_name=None):
        self.log.debug("Set policy " + str(policy_name) + " for " + lb_name)
        self.set_lb_policies_of_listener(lb_name=lb_name,
                                             lb_port=lb_port,
                                             policies=policy_name)

    def delete_lb_policy(self, lb_name, policy_name):
        self.log.debug("Deleting lb policy " + str(policy_name) + " from " + str(lb_name))
        self.delete_lb_policy(lb_name=lb_name,
                                  policy_name=policy_name)

    def describe_lb_policies(self, lb):
        lbs = self.get_all_load_balancers(load_balancer_names=[lb])
        return lbs[0].policies

    def add_lb_listener(self, lb_name, listener):
        self.log.debug("adding listener")
        self.create_load_balancer_listeners(name=lb_name, listeners=[listener])

    def remove_lb_listener(self, lb_name, port):
        self.log.debug("removing listener")
        self.delete_load_balancer_listeners(name=lb_name, ports=[port])

    def add_server_cert(self, cert_name, cert_dir="./cloudtests/cloud_user/elb/test_data",
                        cert_file="ssl_server_certs_basics.crt",
                        key_file="ssl_server_certs_basics.pem"):
        cert_body = open(join(cert_dir, cert_file)).read()
        cert_key = open(join(cert_dir, key_file)).read()
        self.upload_server_cert(cert_name=cert_name, cert_body=cert_body, private_key=cert_key)
        
    def cleanup_load_balancers(self, lbs=None):
        """
        :param lbs: optional list of load balancers, otherwise it will attempt to delete from test_resources[]
        """
        if lbs:
            self.delete_load_balancers(lbs)
        else:
            try:
                self.delete_load_balancers(self.test_resources.get('load_balancers', []))
            except KeyError:
                self.log.debug("No loadbalancers to delete")
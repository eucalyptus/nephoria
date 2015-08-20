# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2011, Eucalyptus Systems, Inc.
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
import time
from cloud_admin.systemconnection import SystemConnection

 
class EuserviceManager(SystemConnection):

        
    def __init__(self, tester):

        ### Make sure i have the right connection to make first contact with euca-describe-services
        self.tester = tester
        self.debug = tester.debug
            
    def start_all(self):
        raise NotImplementedError('Need to implement start_all method')
    
    def modify_process(self, euservice, command): 
        raise NotImplementedError('Need to implement modify_process method')
    
    def stop(self, euservice):
        if re.search("cluster", euservice.type):
            self.modify_process(euservice, "cleanstop")
        else:
            self.modify_process(euservice, "stop")
        euservice.running = False
        
    def start(self, euservice):
        if euservice.type == 'cluster':
            if euservice.machine.get_eucalyptus_cc_is_running_status():
                euservice.running = True
                return
        else:
            if euservice.machine.get_eucalyptus_cloud_is_running_status():
                euservice.running = True
                return
        self.modify_process(euservice, "start")

        
    def wait_for_service(self, euservice, state = "ENABLED", states=None,attempt_both = True, timeout=600):
        interval = 20
        poll_count = timeout / interval
        while (poll_count > 0):
            matching_services = []
            try:
                matching_services = self.get(euservice.type, euservice.partition, attempt_both)
                for service in matching_services:
                    if states:
                        for state in states:
                            if re.search(state, service.state):
                                return service
                    else:
                        if re.search(state, service.state):
                            return service
            except Exception, e:
                self.tester.debug("Caught " + str(e) + " when trying to get services. Retrying in " + str(interval) + "s")
            poll_count -= 1
            self.tester.sleep(interval)
                
        if poll_count is 0:
            self.tester.fail("Service: " + euservice.name + " did not enter "  + state + " state")
            raise Exception("Service: " + euservice.name + " did not enter "  + state + " state")
        
    def all_services_operational(self):
        self.debug('all_services_operational starting...')
        all_services_to_check = self.get_all_services()
        self.print_services_list(all_services_to_check)
        while all_services_to_check:
            ha_counterpart = None
            service = all_services_to_check.pop()
            self.debug('Checking for operational state of services type:' + str(service.type))
            for serv in all_services_to_check:
                if not serv.isActiveActive() and serv.type == service.type and serv.partition == service.partition:
                    ha_counterpart = serv
                    break
            if ha_counterpart:
                all_services_to_check.remove(ha_counterpart)
                self.wait_for_service(service,"ENABLED")
                self.wait_for_service(service,"DISABLED")
            else:
                self.wait_for_service(service,"ENABLED")

    def wait_for_all_services_operational(self, timeout=600):
        '''
        Attempts to wait for a core set of eutester monitored services on the cloud and/or specified in the
        config file to transition to ENABLED. In the HA case will look for both an ENABLED and DISABLED service.
        '''
        start = time.time()
        elapsed = 0
        while elapsed < timeout:
            self.debug("wait_for_all_services_operational, elapsed: " + str(elapsed) + "/" + str(timeout))
            elapsed = int(time.time() - start)
            try:
                self.print_services_list()
                self.all_services_operational()
                self.debug('All services were detected as operational')
                return
            except Exception, e:
                tb = self.tester.get_traceback()
                elapsed = int(time.time() - start )
                error = tb + "\n Error waiting for all services operational, elapsed: " + \
                        str(elapsed) + "/" + str(timeout) + ", error:" + str(e)
                if elapsed < timeout:
                    self.debug(error)
                else:
                    raise Exception(error)
            time.sleep(15)









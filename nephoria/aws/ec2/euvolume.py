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
# Author: matt.clark@eucalyptus.com
'''
Created on Mar 7, 2012
@author: clarkmatthew
Place holder for volume test specific convenience methods+objects to extend boto's volume class

'''
import re
from boto.ec2.volume import Volume
from boto.exception import EC2ResponseError
import time
from nephoria.euca.taggedresource import TaggedResource
from cloud_utils.log_utils import eulogger
from datetime import datetime, timedelta
from prettytable import PrettyTable



class EuVolume(Volume, TaggedResource):
    # Define test tag key names...
    tag_md5_key = 'md5'
    tag_md5len_key = 'md5len'
    tag_source_snapshot_id = 'source_snapshot_id'
    tag_source_volume_zone = 'source_volume_zone'
    tag_source_volume_id = 'source_volume_id'
    tag_source_volume_size = 'source_volume_size'
    tag_source_volume_md5 = 'source_volume_md5'
    tag_source_volume_md5_len = 'source_volume_md5_len'
    tag_source_volume_timestatmp = 'source_volume_timestamp'
    tag_instance_id_key = 'instance_id'
    tag_guestdev_key = 'guestdev'

    '''
    Note: Different hypervisors will honor the requested cloud dev differently, so the requested device can not 
    be relied up as the device it attached to on the guest 'guestdev'
    '''

        
    @classmethod
    def make_euvol_from_vol(cls, volume, ec2ops=None, cmdstart=None):
        newvol = EuVolume(volume.connection)
        newvol.__dict__ = volume.__dict__
        newvol._log = None
        newvol.md5 = None
        newvol.md5len = None
        # the guest device name in use by this attached volume
        newvol.guestdev = ""
        # the device name given to the cloud as a request to be used.
        newvol.clouddev = ""
        newvol.update_from_volume_tags()
        newvol.init_tag_attrs()
        newvol.ec2ops = ec2ops
        #if newvol.md5len is None:
        #    newvol.md5len = 1024
        newvol.eutest_failmsg = None
        newvol.eutest_laststatus = newvol.status
        newvol.eutest_ageatstatus = 0 
        newvol.eutest_cmdstart = cmdstart or newvol.get_volume_time_created(volume)
        newvol.eutest_createorder = None
        newvol.eutest_cmdtime = None
        newvol.eutest_attached_instance_id = None
        if newvol.tags.has_key(newvol.tag_md5_key):
            newvol.md5 = newvol.tags[newvol.tag_md5_key]
        if newvol.tags.has_key(newvol.tag_md5len_key):
            newvol.md5len = newvol.tags[newvol.tag_md5len_key]
        newvol.set_attached_status()

        return newvol

    def __repr__(self):
        return "{0}:{1}".format(self.__class__.__name__, getattr(self, 'id', None))

    def init_tag_attrs(self):
        for key, value in vars(self.__class__).iteritems():
            if str(key).startswith('tag_'):
                if not hasattr(self, value):
                    setattr(self, value, None)


    @property
    def log(self):
        if not self._log:
            self._log = eulogger.Eulogger(identifier=str(self.id))
        return self._log


    def create_tags_dict(self):
        ret_dict = {}
        clsattrs = vars(self.__class__)
        for key, value in clsattrs.iteritems():
            if str(key).startswith('tag_'):
                ret_dict[value] = getattr(self, value, "")
        return ret_dict


    def update_from_volume_tags(self, tags=None):
        tags = tags or self.tags.iteritems()
        for key, value in tags:
            setattr(self, key, value)

    def update_volume_tags_from_local_values(self):
        self.create_tags(self.create_tags_dict())


    # imported from ec2ops
    def get_volume_time_created(self, volume):
        """
        Get the seconds elapsed since the volume was created.

        :type volume: boto volume object
        :param volume: The volume used to calculate the elapsed time since created.

        :rtype: integer
        :returns: The number of seconds elapsed since this volume was created.
        """
        last_status = volume.status
        try:
            volume.update()
        except EC2ResponseError as ER:
            if ER.status == 400 and last_status in ['deleted', 'deleting']:
                self.status = 'deleted'
                self.attach_data = None
            else:
                raise ER
        #get timestamp from attach_data
        create_time = self.get_datetime_from_resource_string(volume.create_time)
        #return the elapsed time in seconds
        return time.mktime(datetime.utcnow().utctimetuple()) - time.mktime(create_time.utctimetuple())

    # imported from ec2ops
    @staticmethod
    def get_datetime_from_resource_string(timestamp,
                                          time_format="%Y %m %d %H %M %S"):
        """
        Convert a typical resource timestamp to datetime time_struct.

        :type timestamp: string
        :param timestamp: Timestamp held within specific boto resource objects.
                          Example timestamp format: 2012-09-19T21:24:03.864Z

        :rtype: time_struct
        :returns: The time_struct representation of the timestamp provided.
        """
        t = re.findall('\w+',str(timestamp).replace('T',' '))
        #remove milliseconds from list...
        t.pop()
        #create a time_struct out of our list
        return datetime.strptime(" ".join(t), time_format)

    def update(self):
        last_status = self.status
        ret = last_status
        try:
            ret = super(EuVolume, self).update()
            if (self.tags.has_key(self.tag_md5_key) and
                    (self.md5 != self.tags[self.tag_md5_key])) or \
                    (self.tags.has_key(self.tag_md5len_key) and
                         (self.md5len != self.tags[self.tag_md5len_key])):
                self.update_volume_attach_info_tags()
        except EC2ResponseError as ER:
            if ER.status == 400 and last_status in ['deleted', 'deleting']:
                self.status = 'deleted'
                self.attach_data =  None
            else:
                raise ER
        self.set_last_status()
        return ret


    def set_last_status(self,status=None):
        self.eutest_laststatus = status or self.status
        self.eutest_laststatustime = time.time()
        self.set_attached_status()
        self.eutest_ageatstatus = "{0:.2f}".format(time.time() - self.eutest_cmdstart)

    def set_attached_status(self):
        if self.attach_data:
            self.eutest_attached_status = self.attach_data.status
            self.eutest_attached_instance_id = self.attach_data.instance_id
            if self.tags.has_key(self.tag_instance_id_key) and self.tags[self.tag_instance_id_key] != self.eutest_attached_instance_id:
                self.remove_tag(self.tag_instance_id_key)
                self.remove_tag(self.tag_guestdev_key)
            else:
                if not self.guestdev and self.tags.has_key(self.tag_guestdev_key):
                    self.guestdev = self.tags[self.tag_guestdev_key]
        else:
            self.eutest_attached_status = None
            self.eutest_attached_instance_id = None

    def printself(self, printmethod=None, printme=True):
        pt = PrettyTable(['VOL_ID', 'ORDER', 'TESTSTATUS', 'AGE', 'SIZE',
                          'SRC_SNAP', 'MD5/(LEN)', 'ZONE', 'INSTANCE'])
        pt.padding_width=0
        instance_id = None
        if self.attach_data:
           instance_id = self.attach_data.instance_id
        pt.add_row([self.id, self.eutest_createorder, self.eutest_laststatus or self.status,
                    self.eutest_ageatstatus, self.size, self.snapshot_id,
                    "{0}/({1})".format(self.md5, self.md5len), self.zone, instance_id])
        if printme:
            printmethod = printmethod or self.debug
            printmethod(str(pt))
        else:
            return pt

    def update_volume_attach_info_tags(self, md5=None, md5len=None, instance_id=None, guestdev=None):
        md5 = md5 or self.md5
        md5len = md5len or self.md5len
        self.add_tag(self.tag_md5_key, md5)
        self.add_tag(self.tag_md5len_key, md5len)
        if self.status == 'in-use' and hasattr(self,'attach_data') and self.attach_data:
            instance_id = instance_id or self.eutest_attached_instance_id
            guestdev = guestdev or self.guestdev
            self.add_tag(self.tag_instance_id_key, instance_id)
            self.add_tag(self.tag_guestdev_key, guestdev)
        else:
            self.set_volume_detached_tags()


    def set_volume_detached_tags(self):
        self.remove_tag(self.tag_instance_id_key)
        self.remove_tag(self.tag_guestdev_key)
    
        
        
        
        
        
        

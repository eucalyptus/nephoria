

from nephoria.testcontroller import TestController
import json
class ebs_tag(object):
    def __init__(self, md5=None, source_zone=None, source_volume=None, source_volume_size=None,
                 source_volume_md5=None, source_volume_timestamp=None):
        self.md5 = md5
        self.source_zone = source_zone
        self.source_volume = source_volume
        self.source_volume_size = source_volume_size
        self.source_volume_md5 = source_volume_md5
        self.source_volume_timestamp = source_volume_timestamp

    def to_dict(self):
        return {'md5':self.md5,
                'source_zone': self.source_zone,
                'source_volume': self.source_volume,
                'source_volume_size': self.source_volume_size,
                'source_volume_md5': self.source_volume_md5,
                'source_volume_timestamp': self.source_volume_timestamp}

    def from_tag(self, tag):
        pass

    def from_json_string(self, tag):



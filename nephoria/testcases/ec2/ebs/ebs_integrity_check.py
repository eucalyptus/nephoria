

from nephoria.testcontroller import TestController
from boto.ec2.volume import Volume
import json
class EBSTestTag(object):
    def __init__(self, volume, md5=None, source_zone=None, source_volume=None,
                 source_volume_size=None, source_volume_md5=None, source_volume_timestamp=None):
        if not isinstance(volume, Volume):
            raise ValueError('"{0}".__init__() expected type:{1}, got:"{2}/{3}"'
                             .format(self.__class__.__name__, Volume, volume, type(volume)))
        self.volume = volume
        self.md5 = md5
        self.source_zone = source_zone
        self.source_volume = source_volume
        self.source_volume_size = source_volume_size
        self.source_volume_md5 = source_volume_md5
        self.source_volume_timestamp = source_volume_timestamp

    def __repr__(self):
        return "{0}:{1}".format(self.__class__.__name__, self.volume.id)

    def to_dict(self):
        return {'md5':self.md5,
                'source_zone': self.source_zone,
                'source_volume': self.source_volume,
                'source_volume_size': self.source_volume_size,
                'source_volume_md5': self.source_volume_md5,
                'source_volume_timestamp': self.source_volume_timestamp}

    def update_from_volume_tags(self, tags=None):
        tags = tags or self.tags
        for key, value in tags:
            setattr(self, key, value)

    def update_volume_tags_from_local_values(self):
        self.volume.create_tags(vars(self))



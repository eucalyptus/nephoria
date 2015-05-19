

"""
system-properties:
      one.storage.scpaths: 10.107.2.1
      one.storage.chapuser: euca-one
      one.storage.sanpassword: zoomzoom
      one.storage.sanuser: root
      one.storage.ncpaths: 10.107.2.1
      one.storage.sanhost: 10.109.2.1
      two.storage.scpaths: 10.107.2.1
      two.storage.chapuser: euca-one
      two.storage.sanpassword: zoomzoom
      two.storage.sanuser: root
      two.storage.ncpaths: 10.107.2.1
      two.storage.sanhost: 10.109.2.1
      www.http_port: '9999'
"""

from cloud_admin.topo import BaseBuilder


class SysPropBuilder(BaseBuilder):

    def __init__(self, builder):
        pass


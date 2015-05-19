

"""
topology:
      clusters:
        one:
          cc-1: 10.111.1.61
          nodes: 10.111.1.175 10.111.5.88
          storage-backend: netapp
          sc-1: 10.111.1.61
        two:
          cc-1: 10.111.1.135
          nodes: 10.111.5.101 10.111.5.151
          storage-backend: netapp
          sc-1: 10.111.1.135
      clc-1: 10.111.1.41
      walrus: 10.111.1.41
      user-facing:
      - 10.111.1.41
"""

from cloud_admin.topo import BaseBuilder


class TopoBuilder(BaseBuilder):
    pass

class ClusterBuilder(BaseBuilder):


    def




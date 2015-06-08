from cloud_admin.hosts.helpers.dns_helpers import DnsHelpers
from cloud_admin.hosts.helpers.nc_helpers import NodeControllerHelpers
from cloud_admin.hosts.helpers.cc_helpers import ClusterControllerHelpers
from cloud_admin.hosts.helpers.clc_helpers import CloudControllerHelpers
from cloud_admin.hosts.helpers.sc_helpers import StorageControllerHelpers
from cloud_admin.hosts.helpers.midonethelpers import MidonetHelpers
from cloud_admin.hosts.helpers.osg_helpers import ObjectStorageGatewayHelpers


class HelperNamespace(object):

    def __init__(self, eucahost):
        self._eucahost = eucahost
        self.dns = DnsHelpers(eucahost)
        self.cloud_controller = CloudControllerHelpers(eucahost)
        self.cluster_controller = ClusterControllerHelpers(eucahost)
        self.midonet = MidonetHelpers(eucahost)
        self.node_controller = NodeControllerHelpers(eucahost)
        self.storage_controller = StorageControllerHelpers(eucahost)
        self.osg = ObjectStorageGatewayHelpers(eucahost)







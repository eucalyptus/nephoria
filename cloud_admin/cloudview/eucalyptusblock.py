

"""
Sample configuration (in yaml)...

eucalyptus:
    default-img-url: http://images.walrus.qa:8773/precise-server-cloudimg-amd64-disk1.img
    install-load-balancer: 'true'
    install-imaging-worker: 'true'
    network:
      private-interface: br0
      public-interface: br0
      bridge-interface: br0
      bridged-nic: em1
      config-json:
        InstanceDnsServers:
        - 10.111.1.41
        Mido:
          EucanetdHost: c-06.qa1.eucalyptus-systems.com
          GatewayHost: c-06.qa1.eucalyptus-systems.com
          GatewayIP: 10.116.129.41
          GatewayInterface: em1.116
          PublicGatewayIP: 10.116.133.173
          PublicNetworkCidr: 10.116.128.0/17
        Mode: VPCMIDO
        PublicIps:
        - 10.116.45.1-10.116.45.254
      mode: VPCMIDO
    nc:
      max-cores: 32
      cache-size: 40000
    init-script-url: http://git.qa1/qa-repos/eucalele/raw/master/scripts/network-interfaces.sh
    post-script-url: http://git.qa1/qa-repos/eucalele/raw/master/scripts/midonet_post.sh
    log-level: DEBUG
    eucalyptus-repo: http://packages.release.eucalyptus-systems.com/yum/tags/eucalyptus-devel/centos/6/x86_64/
    enterprise-repo: http://packages.release.eucalyptus-systems.com/yum/tags/enterprise-devel/centos/6/x86_64/
    euca2ools-repo: http://packages.release.eucalyptus-systems.com/yum/tags/euca2ools-devel/centos/6/x86_64/
    yum-options: "--nogpg"
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

from cloud_admin.cloudview import ConfigBlock
from cloud_admin.cloudview import Namespace
from cloud_admin.services import EucaNotFoundException

class EucalyptusBlock(ConfigBlock):
    def build_active_config(self):
        #Add the topology configuration
        self.topology = TopologyBlock(self._connection)
        self.topology.build_active_config()

        #Add the node controller configuration
        self.nc = NodeControllerBlock(self._connection)
        self.nc.build_active_config()

        # Add Eucalyptus system properties
        system_properties = SystemPropertiesBlock(self._connection)
        system_properties.build_active_config()
        setattr(self, 'system-properties', system_properties)


class TopologyBlock(ConfigBlock):

    def build_active_config(self):

        # Add the Cluster configuration block
        self.clusters = ClustersBlock(self._connection)
        self.clusters.build_active_config()

        # Add the CLC info
        clc_count = 0
        for clc in self._connection.get_all_cloud_controller_services():
            clc_count += 1
            setattr(self, 'clc-{0}'.format(clc_count), clc.ip_addr)

        # Add the Walrus info
        walrus = self._connection.get_all_walrus_backend_services()
        if walrus:
            self.walrus = walrus[0].ip_addr

        # Add the UFS info
        ufs = self._connection.get_all_unified_frontend_services()
        ufs_ips = []
        for service in ufs:
            ufs_ips.append(service.ip_addr)
        setattr(self,'user-facing', ufs_ips)


class ClustersBlock(ConfigBlock):

    def build_active_config(self):
        # Add top level 'clusters' block
        # clusters:
        self.clusters = Namespace()

        for cluster in self._connection.get_all_clusters():
            # Create a Namespace object to hold the cluster config block
            # clusters:
            #   one:
            new_cluster = Namespace()
            setattr(self.clusters, cluster.name, new_cluster)
            # Assign attrs to this cluster...
            # clusters:
            #   <cluster.name>:
            #       <cc.name>: <cc.ip>
            #       <sc.name>: <sc.ip>
            for cc in cluster.cluster_controller_services:
                setattr(new_cluster, cc.name, cc.ip_addr)
            for sc in cluster.storage_controller_services:
                setattr(new_cluster, sc.name, sc.ip_addr)
            try:
                prop = cluster.get_cluster_property('storage.blockstoragemanager')
                new_cluster.storage_backend = prop.value
            except EucaNotFoundException as NFE:
                new_cluster.storage_backend = str(NFE)
                pass
            new_cluster.nodes = " ".join(str(x.ip_addr) for x in cluster.node_controller_services)


class SystemPropertiesBlock(ConfigBlock):

    def build_active_config(self):
        for prop in self._connection.get_properties():
            setattr(self, prop.name, prop.value)


class NodeControllerBlock(ConfigBlock):

    def build_active_config(self):
        maxcores = {}
        cachesize = {}
        for node in self._connection.get_node_hosts():
            if maxcores.get(node.eucalyptus_conf.MAX_CORES) is not None:
                maxcores[node.eucalyptus_conf.MAX_CORES].append(node.hostname)
            else:
                maxcores[node.eucalyptus_conf.MAX_CORES] = [node.hostname]
            if cachesize.get(node.eucalyptus_conf.NC_CACHE_SIZE) is not None:
                cachesize[node.eucalyptus_conf.NC_CACHE_SIZE].append(node.hostname)
            else:
                cachesize[node.eucalyptus_conf.NC_CACHE_SIZE] = [node.hostname]
        if len(maxcores.keys()) == 1:
            maxcores = maxcores.keys()[0]
        setattr(self, 'max-cores', maxcores)

        if len(cachesize.keys()) == 1:
            cachesize = cachesize.keys()[0]
        setattr(self, 'cache-size', cachesize)





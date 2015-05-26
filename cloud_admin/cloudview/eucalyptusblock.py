

"""
###############################################################################################
#  This module intends to provide tools to discover and build configuration blocks representing
#  the current state of a cloud deployment.
#  These Config blocks or manifests should help provide utility with systems like
#  Calyptos, and other Eucalyptus Deployment and diagnostic tools.
##############################################################################################
"""


import json
import re
import sys
from cloud_admin.cloudview import ConfigBlock
from cloud_admin.cloudview import Namespace
from cloud_admin.services import EucaNotFoundException
from cloud_utils.log_utils import markup


def get_values_from_hosts(hostdict, host_method_name=None, host_attr_chain=[],
                          **host_method_kwargs):
    """
    Convenience method to traverse multiple hosts and collect values by calling the same
    method on each host, or by gathering and comparing the same attribute name per each host.
    :param hostdict: dict in form {'hostname1': eucahostobj1, 'hostname2': eucahostobj2}
    :param host_method_name: a Method local to the eucahost obj, ie: eucahostobj.get_stuff()
    :param host_attr_chain: a list of attrs names(strings) local to the host obj, ie for:
                            host.__class__.__name__  is host_attr_chain=['__class___', '__name__']
    :param host_method_kwargs: dict of key=value args to be used with host_method_name()
    :returns: a string if all hosts contain the same value, otherwise will return a dict in the
              format {'host': value} to show which hosts have which value(s).
    """
    value_dict = {}
    if (not host_method_name and not host_attr_chain) or (host_method_name and host_attr_chain):
        raise ValueError('Must provide either host_method_name "or" host_attr, got:{0},{1}'
                         .format(host_method_name, host_attr_chain))

    def debug(msg, host=None, err=False):
        if host and hasattr(host, 'debug'):
            host.debug(msg)
        elif err:
            print sys.stderr, msg
        else:
            print msg
    lookup = host_method_name or ".".join(host_attr_chain)

    for ip, host in hostdict.iteritems():
        # Traverse attrs to retrieve the end value...
        if host_attr_chain:
            obj = host
            for attr in host_attr_chain:
                try:
                    obj = getattr(obj, attr)
                except AttributeError as AE:
                    obj = None
                    errmsg = markup('{0}:{1}'.format(host, str(AE)), [1, 31])
                    debug(errmsg, host, err=True)
            value = obj
        # Use the host method...
        elif host_method_name:
            method = getattr(host, host_method_name, None)
            if method:
                value = method(**host_method_kwargs)
        debug(markup('Got value for host: "{0}.{1}" = "{2}"'
                     .format(ip, lookup, value), [1, 94]), host)
        if value_dict.get(value) is not None:
            value_dict[value].append(ip)
        else:
            value_dict[value] = [ip]
    # If we have more than one key entry in a dict, then one of the hosts
    # had a different value.
    # In this case produce a dict for the final value. This will at least show which hosts
    # have different values, and can be considered for a format change in the config
    # If these values end up being empty strings then don't create (empty attributes)

    if len(value_dict.keys()) == 1:
            value_dict = value_dict.keys()[0]
    if value_dict:
        return value_dict


class EucalyptusBlock(ConfigBlock):
    """
    ##############################################################################################
    #                            Eucalyptus Cloud Config Block
    # This is the main block for building the Eucalyptus portion of a config block.
    # Sample output of this config block:
    #
    #     eucalyptus:
    #     default-img-url: http://images.walrus.qa:8773/precise-server-cloudimg-amd64-disk1.img
    #     install-load-balancer: 'true'
    #     install-imaging-worker: 'true'
    #     network:
    #       private-interface: br0
    #       public-interface: br0
    #       bridge-interface: br0
    #       bridged-nic: em1
    #       config-json:
    #         InstanceDnsServers:
    #         - 10.111.1.41
    #         Mido:
    #           EucanetdHost: c-06.qa1.eucalyptus-systems.com
    #           GatewayHost: c-06.qa1.eucalyptus-systems.com
    #           GatewayIP: 10.116.129.41
    #           GatewayInterface: em1.116
    #           PublicGatewayIP: 10.116.133.173
    #           PublicNetworkCidr: 10.116.128.0/17
    #         Mode: VPCMIDO
    #         PublicIps:
    #         - 10.116.45.1-10.116.45.254
    #       mode: VPCMIDO
    #     nc:
    #       max-cores: 32
    #       cache-size: 40000
    #     init-script-url: http://git.qa1/qa-repos/eucalele/raw/master/scripts/network-int.sh
    #     post-script-url: http://git.qa1/qa-repos/eucalele/raw/master/scripts/midonet_post.sh
    #     log-level: DEBUG
    #     eucalyptus-repo: http://packages.release.eucalyptus-systems.com/yum/tags/6/x86_64/
    #     enterprise-repo: http://packages.release.eucalyptus-systems.com/yum/tags/6/x86_64/
    #     euca2ools-repo: http://packages.release.eucalyptus-systems.com/yum/tags//6/x86_64/
    #     yum-options: "--nogpg"
    #     topology:
    #       clusters:
    #         one:
    #           cc-1: 10.111.1.61
    #           nodes: 10.111.1.175 10.111.5.88
    #           storage-backend: netapp
    #           sc-1: 10.111.1.61
    #         two:
    #           cc-1: 10.111.1.135
    #           nodes: 10.111.5.101 10.111.5.151
    #           storage-backend: netapp
    #           sc-1: 10.111.1.135
    #       clc-1: 10.111.1.41
    #       walrus: 10.111.1.41
    #       user-facing:
    #       - 10.111.1.41
    #     system-properties:
    #       one.storage.scpaths: 10.107.2.1
    #       one.storage.chapuser: euca-one
    #       one.storage.sanpassword: zoomzoom
    #       one.storage.sanuser: root
    #       one.storage.ncpaths: 10.107.2.1
    #       one.storage.sanhost: 10.109.2.1
    #       two.storage.scpaths: 10.107.2.1
    #       two.storage.chapuser: euca-one
    #       two.storage.sanpassword: zoomzoom
    #       two.storage.sanuser: root
    #       two.storage.ncpaths: 10.107.2.1
    #       two.storage.sanhost: 10.109.2.1
    #       www.http_port: '9999'
    #
    ##############################################################################################
    """

    def build_active_config(self, do_topology=True, do_node_config=True, do_props=True,
                            do_repo_urls=True, do_network=True, do_service_images=True,
                            do_euca_conf_gen=True, do_cc_config=True, do_yum_options=True):
        if do_topology:
            # Discover and add the topology configuration
            self.topology = TopologyBlock(self._connection)
            self.topology.build_active_config()

        if do_node_config:
            # Discover and add the node controller configuration
            self.nc = NodeControllerBlock(self._connection)
            self.nc.build_active_config()

        if do_cc_config:
            self.cc = ClusterControllerBlock(self._connection)
            self.cc.build_active_config()

        if do_props:
            # Discover and add the current Eucalyptus system properties
            system_properties = SystemPropertiesBlock(self._connection)
            system_properties.build_active_config()
            setattr(self, 'system-properties', system_properties)

        if do_repo_urls:
            # Discover and add the current eucalyptus repo URLs
            self.discover_repo_urls()

        if do_yum_options:
            # Discover and add the global yum options supported in deployment
            self.discover_yum_options()

        if do_network:
            # Discover and add the current network config
            self.network = NetworkConfigBlock(self._connection)
            self.network.build_active_config()

        if do_service_images:
            # Discover and add the service image config
            self.discover_service_image_config()

        if do_euca_conf_gen:
            self.discover_euca_conf_general()

    def discover_service_image_config(self):
        pass

    def discover_repo_urls(self):
        """
        Attempt to query each machine and build the Eucalyptus repo attributes...
            eucalyptus-repo: http://...
            enterprise-repo: http://...
            euca2ools-repo: http://...
        If every machine returns the same values repo urls, then the single url string will be
        used. If more than one url is in use by the machines then a dict showing 'host:'url'
        mapping will used to provide more info as to the location of the machines with each url.

        """
        repo_map = {'eucalyptus-repo': ['eucalyptus_repo_file', 'baseurl'],
                    'eucalyptus-enterprise-repo': ['eucalyptus_enterprise_repo_file', 'baseurl'],
                    'euca2ools-repo': ['euca2ools_repo_file', 'baseurl']}

        for localname, attrchain in repo_map.iteritems():
            value = get_values_from_hosts(self._connection.eucahosts, host_attr_chain=attrchain)
            if value:
                try:
                    baseurl = re.match('^(http://\S+/x86_64)', value)
                    if baseurl:
                        value = baseurl.group(1)
                except:
                    pass
                setattr(self, localname, value)

    def discover_yum_options(self):
        """
        Iterate over all hosts and all managed eucalyptus repos, to pick out supported
        yum options (currently only 'gpgcheck'). If any of the euca managed repos on any hosts
        differs from the others, report the dict to help sort out who/what is different.
        Else return the single value they all share.
        """
        opt_map = {'yum-options': ['eucalyptus_repo_file', 'gpgcheck'],
                   'yum-options': ['eucalyptus_enterprise_repo_file', 'gpgcheck'],
                   'yum-options': ['euca2ools_repo_file', 'gpgcheck']}
        opt_dict = {}
        for localname, attrchain in opt_map.iteritems():
            value = get_values_from_hosts(self._connection.eucahosts, host_attr_chain=attrchain)
            opt_dict[attrchain[0]] = value
        # if all the values are the same return the single value...
        if len(set(opt_dict.values())) == 1:
            value = opt_dict.values().pop()
        else:
            # some repo, or host has a different value so return the dict...
            value = {'gpgcheck': opt_dict}
        if value and value != '0':
            value = "--nogpg"
        setattr(self, localname, value)

    def discover_euca_conf_general(self):
        """
        Attempt to query each machine and build the eucalyptus.conf general attributes...
        If every machine returns the same values, then the single string value will be
        used. If more than one value is in use by the machines then a dict showing 'host:'value'
        mapping will used to provide more info as to the location of the machines with each value.
        """
        config_map = {'cloud-opts': 'CLOUD_OPTS',
                      'eucalyptus_conf': 'LOG_LEVEL',
                      'home-directory': 'EUCALYPTUS',
                      'user': 'EUCA_USER'}

        for localname, confname in config_map.iteritems():
            value = get_values_from_hosts(
                hostdict=self._connection.eucahosts,
                host_attr_chain=['eucalyptus_conf', '{0}'.format(confname)])
            if value:
                setattr(self, localname, value)


class TopologyBlock(ConfigBlock):
    """
    ###############################################################################################
    #                            Cloud Topology Config Block
    #
    #  Sample output from this config block:
    #
    #     topology:
    #       clc-1: 10.111.5.156
    #       clusters:
    #         clusters:
    #           one:
    #             nodes: 10.111.5.151
    #             one-cc-1: 10.111.5.180
    #             one-sc-1: 10.111.5.180
    #           two:
    #             nodes: 10.111.5.85
    #             two-cc-1: 10.111.1.116
    #             two-sc-1: 10.111.1.116
    #         storage-backend: netapp
    #       user-facing:
    #       - 10.111.5.156
    #       walrus: 10.111.5.156
    #
    ###############################################################################################
    """
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
        setattr(self, 'user-facing', ufs_ips)


class ClustersBlock(ConfigBlock):
    """
    ##############################################################################################
    #                               Cluster Config Block
    #
    #  Sample output from this config block:
    #     clusters:
    #       one:
    #         nodes: 10.111.5.151
    #         one-cc-1: 10.111.5.180
    #         one-sc-1: 10.111.5.180
    #       two:
    #         nodes: 10.111.5.85
    #         two-cc-1: 10.111.1.116
    #         two-sc-1: 10.111.1.116
    #       storage-backend: threepar
    #
    ##############################################################################################
    """
    def build_active_config(self):
        for cluster in self._connection.get_all_clusters():
            # Create a Namespace object to hold the cluster config block
            # clusters:
            #   one:
            new_cluster = Namespace()
            setattr(self, cluster.name, new_cluster)
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
                setattr(self, 'storage-backend', prop.value)
            except EucaNotFoundException as NFE:
                new_cluster.storage_backend = str(NFE)
                pass
            new_cluster.nodes = " ".join(str(x.ip_addr) for x in cluster.node_controller_services)


class SystemPropertiesBlock(ConfigBlock):
    """
    ##############################################################################################
    #                          System Properties Config Block
    #
    # Sample output from this config block:
    #
    #    system-properties:
    #      ...
    #       ...
    #       two.storage.chapuser: euca-one
    #       two.storage.sanpassword: secretpassword
    #       two.storage.sanuser: root
    #       two.storage.ncpaths: 10.107.2.1
    #       two.storage.sanhost: 10.109.2.1
    #       www.http_port: '9999'
    #       ...
    #       ...
    #
    ##############################################################################################
    """
    def build_active_config(self):
        for prop in self._connection.get_properties():
            setattr(self, prop.name, prop.value)


class NodeControllerBlock(ConfigBlock):
    """
    ##############################################################################################
    #                        Node 'Controllers' Config Block
    #  Sample output from this config block:
    #
    #    nc:
    #      hypervisor: kvm
    #      instance-path: /var/lib/eucalyptus/instances
    #      max-cores: '32'
    #      port: '8775'
    #      service-path: axis2/services/EucalyptusNC
    #
    ##############################################################################################
    """
    def build_active_config(self):
        confmap = {'max-cores': ['eucalyptus_conf', 'MAX_CORES'],
                   'cachesize': ['eucalyptus_conf', 'NC_CACHE_SIZE'],
                   'service-path': ['eucalyptus_conf', 'NC_SERVICE'],
                   'port': ['eucalyptus_conf', 'NC_PORT'],
                   'work-size': ['eucalyptus_conf', 'NC_WORK_SIZE'],
                   'hypervisor': ['eucalyptus_conf', 'HYPERVISOR'],
                   'work-size': ['eucalyptus_conf', 'NC_WORK_SIZE'],
                   'instance-path': ['eucalyptus_conf', 'INSTANCE_PATH']}
        for localname, confname in confmap.iteritems():
            value = get_values_from_hosts(hostdict=self._connection.eucahosts,
                                          host_attr_chain=confname)
            if value:
                setattr(self, localname, value)


class ClusterControllerBlock(ConfigBlock):
    """
    ##############################################################################################
    #                               Cluster 'Controllers' Config Block
    #  Sample output from this config block:
    #
    #  cc:
    #    port: '8774'
    #    scheduling-policy: ROUNDROBIN
    #
    ##############################################################################################
    """
    def build_active_config(self):
        confmap = {'port': ['eucalyptus_conf', 'CC_PORT'],
                   'scheduling-policy': ['eucalyptus_conf', 'SCHEDPOLICY']}
        for localname, confname in confmap.iteritems():
            value = get_values_from_hosts(hostdict=self._connection.eucahosts,
                                          host_attr_chain=confname)
            if value:
                setattr(self, localname, value)


class NetworkConfigBlock(ConfigBlock):
    """
    ##############################################################################################
    #                      Cloud Network Config Block
    #
    #  Sample output from this config block:
    #    network:
    #      bridge-interface: br0
    #      config-json:
    #        InstanceDnsServers:
    #        - 10.111.5.156
    #        Mido:
    #          EucanetdHost: g-12-04.qa1.eucalyptus-systems.com
    #          GatewayHost: g-12-04.qa1.eucalyptus-systems.com
    #          GatewayIP: 10.116.133.156
    #          GatewayInterface: em1.116
    #          PublicGatewayIP: 10.116.133.173
    #          PublicNetworkCidr: 10.116.128.0/17
    #        Mode: VPCMIDO
    #        PublicIps:
    #        - 10.116.156.0-10.116.156.254
    #
    ##############################################################################################
    """
    def build_active_config(self):
        interface_map = {'private-interface': 'VNET_PRIVINTERFACE',
                         'public-interface': 'VNET_PUBINTERFACE',
                         'bridge-interface': 'VNET_BRIDGE',
                         'dhcp-daemon': 'VNET_DHCPDAEMON',
                         'mode': 'VNET_MODE',
                         'public-ips': 'VNET_PUBLICIPS',
                         'subnet': 'VNET_SUBNET',
                         'netmask': 'VNET_NETMASK',
                         'addresses-per-net': 'VNET_ADDRSPERNET',
                         'dns-server': 'VNET_DNS',
                         'broadcast': 'VNET_BROADCAST',
                         'router': 'VNET_ROUTER',
                         'domain-name': 'VNET_DOMAINNAME',
                         'metadata-use-private-ip': 'METADATA_USE_VM_PRIVATE',
                         'metadata-ip': 'METADATA_IP',
                         'nc-router': 'NC_ROUTER',
                         'disable-tunneling': 'DISABLE_TUNNELING'}
        for localname, confname in interface_map.iteritems():
            value = get_values_from_hosts(
                hostdict=self._connection.eucahosts,
                host_attr_chain=['eucalyptus_conf', '{0}'.format(confname)])
            if value:
                setattr(self, localname, value)
        net_json_prop = self._connection.get_property('cloud.network.network_configuration')
        network_config = None
        if net_json_prop.value:
            network_config = json.loads(net_json_prop.value)
        network_config = Namespace(**network_config)
        setattr(self, 'config-json', network_config)

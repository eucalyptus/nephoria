
### Cloud admin modules:

##### access:
    Utility odules help Administer Cloud Users, Accounts, Credentials Administrative modules

##### backends:
    Cloud backend modules. This may include backend modules for:
        - Block storage modules for the backing HW or SW (ie SAN, DAS, Ceph, etc)
        - Network modules (ie: Network HW, SDN component interfaces, etc. )
        - Hypervisor modules (ie: vmware api, etc)
        - Object Storage modules (ie: Riak, etc)

##### hosts:
    Host machine modules. Utilities for the machines which host cloud services.
    This may include:
        - Eucalyptus Host machine modules and service specific machine helper modules. These will
          be primarily for Linux machines which are hosting the Eucalyptus services.
        - Utlities to manage the host machines.

##### services:
    Eucalyptus specific modules. Utilities to handle cloud services requests, and responses.
    This may include:
        - Eucalyptus Administrative Services
        - Eucalyptus Administrative Properties
        - Eucalyptus Administrative API

##### cloudview
    Eucalyptus Cloud topology utilities.
    This may include:
        - Utilities to help manage, monitor, debug a given topology.
        - Utilities to help deploy, configure, etc..
        - Utilities to help discovery, and create representations of a given topology
         in code and in different text or graphical formats.


#### Example using the systemconnection interface:


First create the systemconnection interface. By default Ssh credentials, and/or Eucalyptus
credentials are combined to provide both machine and service level utilities from a single
connection interface.
- See 'services' and the 'adminapi' module for the Eucalyptus services, and
  properties interface.
- See 'hosts' for the utilities that involve interacting with the underlying machines hosting
  the Eucalyptus services.
- See cloud_view for the utilities that help produce configuration blocks (or manifests) of the
  existing Cloud, it's configuration and topology.

```
In [1]: from cloud_admin.systemconnection import SystemConnection

In [2]: sc = SystemConnection('10.111.5.156', password='foobar')
```

#### Accessing the Eucalyptus services...

Some examples of how the Eucalyptus services, and properties can be queried, modified, etc..
Use show commands during development to help debug and create sytemconnection scripts...

```
In [3]: sc.sho
sc.show_cloud_controllers       sc.show_components_summary      sc.show_objectstorage_gateways  sc.show_service_types           sc.show_storage_controllers
sc.show_cluster_controllers     sc.show_machine_mappings        sc.show_properties              sc.show_service_types_verbose   sc.show_walrus_backends
sc.show_clusters                sc.show_nodes                   sc.show_properties_narrow       sc.show_services

In [3]: sc.show_nodes()
[2015-05-26 12:55:09,848][INFO][SystemConnection]:
+----+------------+-------+-----------------------------------------------------------+
|ZONE| NODE NAME  | STATE |                         INSTANCES                         |
+----+------------+-------+-----------------------------------------------------------+
|one |10.111.5.151|ENABLED|                                                           |
+----+------------+-------+-----------------------------------------------------------+
|two |10.111.5.85 |ENABLED|  i-44274273(running,       m1.small,    instance-store  ) |
|    |            |       |  i-51475876(running,       m1.small,    instance-store  ) |
|    |            |       |  i-3fea5ffe(running,       m1.small,    instance-store  ) |
+----+------------+-------+-----------------------------------------------------------+


In [4]: sc.show_cluster_controllers()
[2015-05-26 12:55:25,097][INFO][SystemConnection]:
+------------+--------+-------+-------+
|HOSTNAME    |NAME    |CLUSTER|STATE  |
+------------+--------+-------+-------+
|10.111.5.180|one-cc-1|one    |ENABLED|
|10.111.1.116|two-cc-1|two    |ENABLED|
+------------+--------+-------+-------+


In [5]: sc.show_properties('www')
[2015-05-26 12:55:37,965][INFO][SystemConnection]:
+-------------------+----------------------------------------+---------------------------------+
|PROPERTY NAME      |PROPERTY VALUE                          |DESCRIPTION                      |
+-------------------+----------------------------------------+---------------------------------+
|www.httpproxyhost  |                                        |Http Proxy Host                  |
+-------------------+----------------------------------------+---------------------------------+
|www.httpproxyport  |                                        |Http Proxy Port                  |
+-------------------+----------------------------------------+---------------------------------+
|www.https_ciphers  |RSA:DSS:ECDSA:+RC4:+3DES:TLS_EMPTY_RENEG|SSL ciphers for HTTPS listener.  |
|                   |OTIATION_INFO_SCSV:!NULL:!EXPORT:!EXPORT|                                 |
|                   |1024:!MD5:!DES                          |                                 |
+-------------------+----------------------------------------+---------------------------------+
|www.https_port     |8443                                    |Listen to HTTPs on this port.    |
+-------------------+----------------------------------------+---------------------------------+
|www.https_protocols|SSLv2Hello,TLSv1,TLSv1.1,TLSv1.2        |SSL protocols for HTTPS listener.|
+-------------------+----------------------------------------+---------------------------------+

```

#### Accessing the Host machines

Combine Eucalyptus services with their underlying machines hosting the services.
These are accessed as 'hosts' through the systemconnection interface...

```

In [6]: sc.show_machine_mappings()
[2015-05-26 13:00:16,919][INFO][SystemConnection]:
+--------------------+-----------------------------------------------------------------------------+
| MACHINE            | SERVICES                                                                    |
+--------------------+-----------------------------------------------------------------------------+
|                    |   TYPE              NAME                               STATE      CLUSTER   |
| 10.111.5.156       |   eucalyptus        10.111.5.156                       ENABLED              |
|                    |   user-api          API_10.111.5.156                   ENABLED              |
|                    |   autoscaling       API_10.111.5.156.autoscaling       ENABLED              |
|                    |   cloudformation    API_10.111.5.156.cloudformation    ENABLED              |
|                    |   cloudwatch        API_10.111.5.156.cloudwatch        ENABLED              |
|                    |   compute           API_10.111.5.156.compute           ENABLED              |
|                    |   euare             API_10.111.5.156.euare             ENABLED              |
|                    |   identity          API_10.111.5.156.identity          ENABLED              |
|                    |   imaging           API_10.111.5.156.imaging           ENABLED              |
|                    |   loadbalancing     API_10.111.5.156.loadbalancing     ENABLED              |
|                    |   objectstorage     API_10.111.5.156.objectstorage     ENABLED              |
|                    |   objectstorage     API_10.111.5.156.objectstorage     ENABLED              |
|                    |   simpleworkflow    API_10.111.5.156.simpleworkflow    ENABLED              |
|                    |   tokens            API_10.111.5.156.tokens            ENABLED              |
|                    |   objectstorage     API_10.111.5.156.objectstorage     ENABLED              |
|                    |   objectstorage     API_10.111.5.156.objectstorage     ENABLED              |
|                    |   walrusbackend     walrus-1                           ENABLED              |
|                    |                                                                             |
+--------------------+-----------------------------------------------------------------------------+
|                    |   TYPE              NAME                               STATE      CLUSTER   |
| 10.111.5.151       |   node              10.111.5.151                       ENABLED      one     |
|                    |                                                                             |
+--------------------+-----------------------------------------------------------------------------+
|                    |   TYPE              NAME                               STATE      CLUSTER   |
| 10.111.5.85        |   node              10.111.5.85                        ENABLED      two     |
|                    |                                                                             |
|                    | INSTANCES                                                                   |
|                    | i-44274273(running),     m1.small,    instance-store                        |
|                    | i-51475876(running),     m1.small,    instance-store                        |
|                    | i-3fea5ffe(running),     m1.small,    instance-store                        |
|                    |                                                                             |
+--------------------+-----------------------------------------------------------------------------+
|                    |   TYPE              NAME                               STATE      CLUSTER   |
| 10.111.5.180       |   storage           one-sc-1                           ENABLED      one     |
|                    |   cluster           one-cc-1                           ENABLED      one     |
|                    |                                                                             |
+--------------------+-----------------------------------------------------------------------------+
|                    |   TYPE              NAME                               STATE      CLUSTER   |
| 10.111.1.116       |   storage           two-sc-1                           ENABLED      two     |
|                    |   cluster           two-cc-1                           ENABLED      two     |
|                    |                                                                             |
+--------------------+-----------------------------------------------------------------------------+

```

##### Some sample utilities with an indidual host, hosting the Eucalyptus Node controller service...

````

In [7]: nodes = sc.get_hosts_for
sc.get_hosts_for_cloud_controllers    sc.get_hosts_for_storage_controllers  sc.get_hosts_for_walrus
sc.get_hosts_for_node_controllers     sc.get_hosts_for_ufs

In [7]: nodes = sc.get_hosts_for_node_controllers()

In [8]: nodes
Out[8]: [EucaHost:10.111.5.151, EucaHost:10.111.5.85]

In [9]: nc = sc.get_hosts_for_node_controllers()[0]

In [10]: nc.euc
nc.euca2ools_repo_file              nc.euca_nc_helpers                  nc.euca_service_codes               nc.euca_ws_helpers                  nc.eucalyptus_repo_file
nc.euca_cc_helpers                  nc.euca_osg_helpers                 nc.euca_source                      nc.eucalyptus_conf
nc.euca_clc_helpers                 nc.euca_sc_helpers                  nc.euca_ufs_helpers                 nc.eucalyptus_enterprise_repo_file

In [10]: nc.eucalyptus_conf.
nc.eucalyptus_conf.CC_PORT                  nc.eucalyptus_conf.METADATA_IP              nc.eucalyptus_conf.USE_VIRTIO_NET           nc.eucalyptus_conf.VNET_PRIVINTERFACE
nc.eucalyptus_conf.CLOUD_OPTS               nc.eucalyptus_conf.METADATA_USE_VM_PRIVATE  nc.eucalyptus_conf.USE_VIRTIO_ROOT          nc.eucalyptus_conf.VNET_PUBINTERFACE
nc.eucalyptus_conf.DISABLE_TUNNELING        nc.eucalyptus_conf.NC_CACHE_SIZE            nc.eucalyptus_conf.VNET_ADDRSPERNET         nc.eucalyptus_conf.VNET_PUBLICIPS
nc.eucalyptus_conf.EUCALYPTUS               nc.eucalyptus_conf.NC_PORT                  nc.eucalyptus_conf.VNET_BRIDGE              nc.eucalyptus_conf.VNET_ROUTER
nc.eucalyptus_conf.EUCA_USER                nc.eucalyptus_conf.NC_ROUTER                nc.eucalyptus_conf.VNET_BROADCAST           nc.eucalyptus_conf.VNET_SUBNET
nc.eucalyptus_conf.HYPERVISOR               nc.eucalyptus_conf.NC_SERVICE               nc.eucalyptus_conf.VNET_DHCPDAEMON          nc.eucalyptus_conf.set_defaults
nc.eucalyptus_conf.INSTANCE_PATH            nc.eucalyptus_conf.NC_WORK_SIZE             nc.eucalyptus_conf.VNET_DNS                 nc.eucalyptus_conf.unparsedlines
nc.eucalyptus_conf.LOGLEVEL                 nc.eucalyptus_conf.NODES                    nc.eucalyptus_conf.VNET_DOMAINNAME          nc.eucalyptus_conf.update_from_string
nc.eucalyptus_conf.LOG_LEVEL                nc.eucalyptus_conf.SCHEDPOLICY              nc.eucalyptus_conf.VNET_MODE
nc.eucalyptus_conf.MAX_CORES                nc.eucalyptus_conf.USE_VIRTIO_DISK          nc.eucalyptus_conf.VNET_NETMASK

In [10]: print nc.eucalyptus_conf.MAX_CORES
32


In [11]: print nc.eucalyptus_repo_file
RepoFile(baseurl='http://packages.release.eucalyptus-systems.com/yum/tags/eucalyptus-4.1/centos/6/x86_64/', enabled='1', filepath='/etc/yum.repos.d/eucalyptus-release.repo', gpgcheck='1', gpgkey='http://www.eucalyptus.com/sites/all/files/c1240596-eucalyptus-release-key.pub', metadata_expire='1', name='Eucalyptus Package Repo', repo_name='eucalyptus-release', sslverify='true')


In [12]: repo_info = nc.eucalyptus_repo_file


In [13]: repo_info.
repo_info.baseurl          repo_info.filepath         repo_info.gpgkey           repo_info.name             repo_info.sslverify
repo_info.enabled          repo_info.gpgcheck         repo_info.metadata_expire  repo_info.repo_name

In [13]: print repo_info.baseurl
http://packages.release.eucalyptus-systems.com/yum/tags/eucalyptus-4.1/centos/6/x86_64/


In [14]: print repo_info.gpgcheck
1

```

##### Hosts can be interacted with via ssh via the sys interface...

```

In [15]: nc.sys('free', code=0)
Out[15]:
['             total       used       free     shared    buffers     cached',
 'Mem:       7254904    6322152     932752        328     191872    4085884',
 '-/+ buffers/cache:    2044396    5210508',
 'Swap:      7372796       1868    7370928']

```

#####  ...or for real time debugging, start an interactive shell

```
In [16]: nc.start_interactive_ssh()
Opened channel, starting interactive mode...
Last login: Tue May 26 12:59:47 2015 from euca-vpn-10-5-1-70.eucalyptus-systems.com
[root@g-08-09 ~]# uptime
 13:11:19 up 13 days, 14:58,  1 user,  load average: 0.00, 0.00, 0.00
[root@g-08-09 ~]# exit
logout

In [17]:
```

##### Get General information about the hosts, their services, processes, etc..

```

In [18]: print nc.distro + " : " + nc.distro_ver
centos : 6.6

In [19]: nc.get_eucalyptus
nc.get_eucalyptus_cc_is_running_status     nc.get_eucalyptus_cloud_pid                nc.get_eucalyptus_home                     nc.get_eucalyptus_repo_url
nc.get_eucalyptus_cc_pid                   nc.get_eucalyptus_cloud_process_uptime     nc.get_eucalyptus_nc_is_running_status     nc.get_eucalyptus_service_pid
nc.get_eucalyptus_cc_process_uptime        nc.get_eucalyptus_conf                     nc.get_eucalyptus_nc_pid                   nc.get_eucalyptus_version
nc.get_eucalyptus_cloud_is_running_status  nc.get_eucalyptus_enterprise_repo_url      nc.get_eucalyptus_nc_process_uptime


In [19]: nc.get_eucalyptus_nc_process_uptime()
Out[19]: 1175397

In [20]: nc.get_eucalyptus_nc_pid()
Out[20]: 28046

In [22]: nc.get_eucalyptus_version()
Out[22]: '4.2.0'

In [23]: nc.get_eucalyptus_repo_url()
Out[23]: 'http://packages.release.eucalyptus-systems.com/yum/tags/eucalyptus-4.1/centos/6/x86_64//eucalyptus-4.1.1-0.0.23208.94.20150522git0116314.el6.x86_64.rpm'


```
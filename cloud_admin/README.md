
### Cloud admin modules:

##### access:
    Utility modules related to Cloud Account's and cloud user's access to a cloud.
    Fetching/creating cloud credentials, Account, users, policies, etc..

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
- See 'services' and the 'serviceconnection' module for the Eucalyptus services, and
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

### Get Host Summary Information:

```
In [1]: from cloud_admin.systemconnection import SystemConnection
In [2]: sc = SystemConnection('10.111.5.105', password='foobar', log_level='info')
In [3]: sc.show_hosts()
In [3]: sc.show_hosts()
[2015-05-31 09:08:12,811][INFO][SystemConnection]:
+--------------------------+-----------------------------------------------------------------------------+
| MACHINE INFO             | EUCALYPTUS SERVICES                                                         |
+--------------------------+-----------------------------------------------------------------------------+
|         HOST:            |   TYPE              NAME                               STATE      CLUSTER   |
| 10.111.5.156             |   eucalyptus        10.111.5.156                       ENABLED              |
|     Ver::4.2.0           |   user-api          API_10.111.5.156                   ENABLED              |
| Mem:                     |   autoscaling       API_10.111.5.156.autoscaling       ENABLED              |
|  Used:       6957  0.98% |   cloudformation    API_10.111.5.156.cloudformation    ENABLED              |
|  Free:       127   0.02% |   cloudwatch        API_10.111.5.156.cloudwatch        ENABLED              |
|  Swap:       535   0.08% |   compute           API_10.111.5.156.compute           ENABLED              |
| CPU:                     |   euare             API_10.111.5.156.euare             ENABLED              |
|  #0:         10.66%      |   identity          API_10.111.5.156.identity          ENABLED              |
|  #1:         9.43%       |   imaging           API_10.111.5.156.imaging           ENABLED              |
|  #2:         10.41%      |   loadbalancing     API_10.111.5.156.loadbalancing     ENABLED              |
|  #3:         9.47%       |   objectstorage     API_10.111.5.156.objectstorage     ENABLED              |
| DISK:                    |   simpleworkflow    API_10.111.5.156.simpleworkflow    ENABLED              |
| md0          244m  15%   |   tokens            API_10.111.5.156.tokens            ENABLED              |
| vg01-lv_root 196g  6%    |   walrusbackend     walrus-1                           ENABLED              |
| tmpfs        3.5g  0%    |                                                                             |
|                          |  EUCA SERVICE  COMMAND          %CPU  %MEM  PS_UPTIME                       |
|                          |  eucalyptus                                                                 |
|                          |                eucalyptus-clou  21.2  33.2  18-10:39:46                     |
|                          |  eucanetd                                                                   |
|                          |                eucanetd         0.4   0.8   18-10:13:05                     |
|                          |  midolman                                                                   |
|                          |                java             9.8   22.4  11-16:53:31                     |
|                          |                wdog             0.0   0.0   11-16:53:31                     |
+--------------------------+-----------------------------------------------------------------------------+
|         HOST:            |   TYPE              NAME                               STATE      CLUSTER   |
| 10.111.5.151             |   node              10.111.5.151                       ENABLED      one     |
|     Ver::4.2.0           |                                                                             |
| Mem:                     | LAST REPORTED NC AVAILABILITY (enabled):                                    |
|  Used:       6246 0.88%  |  CPU:          32/32                                                        |
|  Free:       838  0.12%  |  MEM:      7254/7254                                                        |
|  Swap:       1    0.00%  | DISK:          57/57                                                        |
| CPU:                     |                                                                             |
|  #0:         4.31%       |  EUCA SERVICE   COMMAND  %CPU  %MEM  PS_UPTIME                              |
|  #1:         3.82%       |  eucalyptus-nc                                                              |
|  #2:         4.41%       |                 httpd    0.3   1.5   10:48:44                               |
|  #3:         3.42%       |  midolman                                                                   |
| DISK:                    |                 java     9.2   21.9  11-16:53:23                            |
| md0          244m 15%    |                 wdog     0.0   0.0   11-16:53:23                            |
| vg01-lv_root 196g 4%     |                                                                             |
| tmpfs        3.5g 0%     |                                                                             |
+--------------------------+-----------------------------------------------------------------------------+
|         HOST:            |   TYPE              NAME                               STATE      CLUSTER   |
| 10.111.5.85              |   node              10.111.5.85                        ENABLED      two     |
|      Ver::4.2.0          |                                                                             |
| Mem:                     | INSTANCES                                                                   |
|  Used:       7704 0.98%  | i-44274273(running),     m1.small,    instance-store                        |
|  Free:       155  0.02%  | i-51475876(running),     m1.small,    instance-store                        |
|  Swap:       8    0.00%  | i-3fea5ffe(running),     m1.small,    instance-store                        |
| CPU:                     |                                                                             |
|  #0:         1.4%        | LAST REPORTED NC AVAILABILITY (enabled):                                    |
|  #1:         1.21%       |  CPU:          29/32                                                        |
|  #2:         0.62%       |  MEM:      7280/8048                                                        |
|  #3:         0.61%       | DISK:          42/57                                                        |
| DISK:                    |                                                                             |
| md0          244m 15%    |  EUCA SERVICE   COMMAND  %CPU  %MEM  PS_UPTIME                              |
| vg01-lv_root 196g 4%     |  eucalyptus-nc                                                              |
| tmpfs        3.9g 0%     |                 httpd    0.4   1.8   18-10:22:25                            |
|                          |  midolman                                                                   |
|                          |                 java     16.5  20.0  11-16:53:32                            |
|                          |                 wdog     0.0   0.0   11-16:53:32                            |
+--------------------------+-----------------------------------------------------------------------------+
|         HOST:            |   TYPE              NAME                               STATE      CLUSTER   |
| 10.111.5.180             |   storage           one-sc-1                           ENABLED      one     |
|     Ver::4.2.0           |   cluster           one-cc-1                           ENABLED      one     |
| Mem:                     |                                                                             |
|  Used:       6882 0.97%  |  EUCA SERVICE  COMMAND          %CPU  %MEM  PS_UPTIME                       |
|  Free:       201  0.03%  |  eucalytus-cc                                                               |
|  Swap:       30   0.00%  |                httpd            0.0   1.0   18-10:12:27                     |
| CPU:                     |  eucalyptus                                                                 |
|  #0:         2.41%       |                eucalyptus-clou  10.5  19.2  18-10:24:52                     |
|  #1:         3.05%       |  eucanetd                                                                   |
|  #2:         2.96%       |                eucanetd         0.4   0.9   18-10:25:35                     |
|  #3:         4.1%        |                                                                             |
| DISK:                    |                                                                             |
| md0          244m 15%    |                                                                             |
| vg01-lv_root 196g 4%     |                                                                             |
| tmpfs        3.5g 1%     |                                                                             |
+--------------------------+-----------------------------------------------------------------------------+
|         HOST:            |   TYPE              NAME                               STATE      CLUSTER   |
| 10.111.1.116             |   storage           two-sc-1                           ENABLED      two     |
|     Ver::4.2.0           |   cluster           two-cc-1                           ENABLED      two     |
| Mem:                     |                                                                             |
|  Used:       6864 0.97%  |  EUCA SERVICE  COMMAND          %CPU  %MEM  PS_UPTIME                       |
|  Free:       220  0.03%  |  eucalytus-cc                                                               |
|  Swap:       16   0.00%  |                httpd            0.0   0.8   13-13:37:33                     |
| CPU:                     |  eucalyptus                                                                 |
|  #0:         2.17%       |                eucalyptus-clou  10.6  20.4  18-10:24:46                     |
|  #1:         2.72%       |  eucanetd                                                                   |
|  #2:         1.99%       |                eucanetd         0.4   0.9   18-10:25:29                     |
|  #3:         6.12%       |                                                                             |
| DISK:                    |                                                                             |
| md0          244m 15%    |                                                                             |
| vg01-lv_root 196g 4%     |                                                                             |
| tmpfs        3.5g 1%     |                                                                             |
+--------------------------+-----------------------------------------------------------------------------+
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

#### Host Helpers.

Host object have helper interfaces providing utility methods related to the
eucalytpus services they are hosting.
Node controller host example (continued from above):

```
In [9]: sc.show_nodes()
[2015-05-26 13:52:02,198][INFO][SystemConnection]:
+----+------------+-------+-----------------------------------------------------------+
|ZONE| NODE NAME  | STATE |                         INSTANCES                         |
+----+------------+-------+-----------------------------------------------------------+
|one |10.111.5.151|ENABLED|                                                           |
+----+------------+-------+-----------------------------------------------------------+
|two |10.111.5.85 |ENABLED|  i-44274273(running,       m1.small,    instance-store  ) |
|    |            |       |  i-51475876(running,       m1.small,    instance-store  ) |
|    |            |       |  i-3fea5ffe(running,       m1.small,    instance-store  ) |
+----+------------+-------+-----------------------------------------------------------+


In [10]: nc = sc.get_hosts_for_node_controllers()[1]

In [11]: nc.euc
nc.euca2ools_repo_file              nc.euca_nc_helpers                  nc.euca_service_codes               nc.euca_ws_helpers                  nc.eucalyptus_enterprise_repo_file
nc.euca_cc_helpers                  nc.euca_osg_helpers                 nc.euca_source                      nc.eucalyptus_conf                  nc.eucalyptus_repo_file
nc.euca_clc_helpers                 nc.euca_sc_helpers                  nc.euca_ufs_helpers                 nc.eucalyptus_conf_path

In [11]: nc.euca_nc_helpers.
nc.euca_nc_helpers.debug                                                    nc.euca_nc_helpers.get_instance_xml_dom
nc.euca_nc_helpers.eucalyptus_conf                                          nc.euca_nc_helpers.get_instance_xml_text
nc.euca_nc_helpers.get_hypervisor_from_euca_conf                            nc.euca_nc_helpers.get_local_nc_service_state
nc.euca_nc_helpers.get_instance_block_disk_dev_on_node                      nc.euca_nc_helpers.get_virsh_list
nc.euca_nc_helpers.get_instance_block_disk_source_paths                     nc.euca_nc_helpers.log
nc.euca_nc_helpers.get_instance_block_disk_xml_dom_list                     nc.euca_nc_helpers.machine
nc.euca_nc_helpers.get_instance_console_path                                nc.euca_nc_helpers.node_controller_service
nc.euca_nc_helpers.get_instance_device_xml_dom                              nc.euca_nc_helpers.remote_tail_monitor_cb
nc.euca_nc_helpers.get_instance_multipath_dev_for_instance_block_dev        nc.euca_nc_helpers.services
nc.euca_nc_helpers.get_instance_multipath_dev_for_instance_ebs_volume       nc.euca_nc_helpers.sys
nc.euca_nc_helpers.get_instance_multipath_dev_info_for_instance_block_dev   nc.euca_nc_helpers.tail_instance_console
nc.euca_nc_helpers.get_instance_multipath_dev_info_for_instance_ebs_volume

In [11]: nc.euca_nc_helpers.get_virsh_list()
Out[11]:
[{'id': '14', 'name': 'i-51475876', 'state': 'running'},
 {'id': '15', 'name': 'i-44274273', 'state': 'running'},
 {'id': '23', 'name': 'i-3fea5ffe', 'state': 'running'}]



In [13]: print nc.euca_nc_helpers.get_instance_xml_text('i-44274273')
<domain type='kvm' id='15'>
  <name>i-44274273</name>
  <uuid>ce200234-e30d-3d4b-355d-395dd19d6b04</uuid>
  <description>Eucalyptus instance i-44274273</description>
  <memory unit='KiB'>262144</memory>
  <currentMemory unit='KiB'>262144</currentMemory>
  <vcpu placement='static'>1</vcpu>
  <os>
    <type arch='x86_64' machine='rhel6.6.0'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
  </features>
  <cpu>
    <topology sockets='1' cores='1' threads='1'/>
  </cpu>
  <clock offset='localtime'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/libexec/qemu-kvm</emulator>
    <disk type='block' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source dev='/var/lib/eucalyptus/instances/work/AIDAA6P7VTXQ74ATLJGNG/i-44274273/link-to-vda'/>
      <target dev='vda' bus='virtio'/>
      <serial>euca-bdm-machine-dev-vda</serial>
      <alias name='virtio-disk0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
    </disk>
    <disk type='block' device='disk'>
      <driver name='qemu' type='raw' cache='none'/>
      <source dev='/var/lib/eucalyptus/instances/work/AIDAA6P7VTXQ74ATLJGNG/i-44274273/link-to-vdb'/>
      <target dev='vdb' bus='virtio'/>
      <serial>euca-bdm-ephemeral0-dev-vdb</serial>
      <alias name='virtio-disk1'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </disk>
    <controller type='usb' index='0'>
      <alias name='usb0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x2'/>
    </controller>
    <interface type='bridge'>
      <mac address='d0:0d:dc:dc:10:6c'/>
      <source bridge='br0'/>
      <target dev='vn_i-44274273'/>
      <model type='virtio'/>
      <alias name='net0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
    <serial type='file'>
      <source path='/var/lib/eucalyptus/instances/work/AIDAA6P7VTXQ74ATLJGNG/i-44274273/console.log'/>
      <target port='1'/>
      <alias name='serial0'/>
    </serial>
    <console type='file'>
      <source path='/var/lib/eucalyptus/instances/work/AIDAA6P7VTXQ74ATLJGNG/i-44274273/console.log'/>
      <target type='serial' port='1'/>
      <alias name='serial0'/>
    </console>
    <memballoon model='virtio'>
      <alias name='balloon0'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
    </memballoon>
  </devices>
</domain>
```

### Create Topology manifests...

Using the configblock modules in cloudview, create json, yaml, or graphical representations
of the current cloud. These can later be fed to deployment tools such as Calyptos, Chef, etc.
for re-deploying, diagnostics, etc..


##### First create the systemconnection interface...
```
In [1]: from cloud_admin.systemconnection import SystemConnection

In [2]: sc = SystemConnection('10.111.5.156', password='foobar')

```

##### Using the systemconnection, create config blocks. In this example create the 'eucalyptus' portion
of a configuration manifest.

```

In [3]: from cloud_admin.cloudview.eucalyptusblock import EucalyptusBlock

In [4]: eb = EucalyptusBlock(sc)

```
##### Discover the cloud's topology and current settings to build. Then print the configuration...

```
In [5]: eb.build_active_config(do_props=False)

In [6]: print eb.to
eb.to_json   eb.to_yaml   eb.topology

In [6]: print eb.to_yaml()
cc:
  port: '8774'
  scheduling-policy: ROUNDROBIN
euca2ools-repo: http://packages.release.eucalyptus-systems.com/yum/tags/eucalyptus-4.1/centos/6/x86_64
eucalyptus-enterprise-repo: http://packages.release.eucalyptus-systems.com/yum/tags/eucalyptus-4.1/centos/6/x86_64
eucalyptus-repo: http://packages.release.eucalyptus-systems.com/yum/tags/eucalyptus-4.1/centos/6/x86_64
home-directory: /
nc:
  hypervisor: kvm
  instance-path: /var/lib/eucalyptus/instances
  max-cores: '32'
  port: '8775'
  service-path: axis2/services/EucalyptusNC
network:
  bridge-interface: br0
  config-json:
    InstanceDnsServers:
    - 10.111.5.156
    Mido:
      EucanetdHost: g-12-04.qa1.eucalyptus-systems.com
      GatewayHost: g-12-04.qa1.eucalyptus-systems.com
      GatewayIP: 10.116.133.156
      GatewayInterface: em1.116
      PublicGatewayIP: 10.116.133.173
      PublicNetworkCidr: 10.116.128.0/17
    Mode: VPCMIDO
    PublicIps:
    - 10.116.156.0-10.116.156.254
  dhcp-daemon: /usr/sbin/dhcpd
  disable-tunneling: Y
  metadata-use-private-ip: N
  mode: VPCMIDO
  private-interface: br0
  public-interface: br0
topology:
  clc-1: 10.111.5.156
  clusters:
    one:
      nodes: 10.111.5.151
      one-cc-1: 10.111.5.180
      one-sc-1: 10.111.5.180
    storage-backend: netapp
    two:
      nodes: 10.111.5.85
      two-cc-1: 10.111.1.116
      two-sc-1: 10.111.1.116
  user-facing:
  - 10.111.5.156
  walrus: 10.111.5.156
user: eucalyptus
yum-options: --nogpg


```

### Get Legacy Cloud summary representation
#### (aka older QA/Eutester config file text)...

Older versions of Eutester may have required a cloud summary 'config.file' be provided
in order to run a set of tests. The string can now be produced from a running cloud via the
systemconnection interface. Example:

```
In [1]: from cloud_admin.systemconnection import SystemConnection

In [2]: sc = SystemConnection('10.111.5.156', password='foobar')

In [3]: sc.show_cloud_legacy_summary()
[2015-05-26 14:51:11,978][INFO][SystemConnection]:
 # HOST        DISTRO  VER         ARCH    ZONE  SERVICE CODES
 10.111.5.151  centos  6.6         x86_64  one   [NC]
 10.111.5.180  centos  6.6         x86_64  one   [SC CC]
 10.111.5.85   centos  6.6         x86_64  two   [NC]
 10.111.5.156  centos  6.6         x86_64  euca  [CLC UFS WS]
 10.111.1.116  centos  6.6         x86_64  two   [SC CC]
```
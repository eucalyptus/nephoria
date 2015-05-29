
###### ServiceConnection() is the primary interface for fetching, modifying, and displaying Eucalyptus
###### admin attributes. This includes system; components/hosts, services, and properties.
###### Some examples shown below...







#### First create an admin connection obj...

````
# Reading in a eucarc (local or remote) is quick way to populate the needed creds...
from cloud_utils.file_utils.eucarc import Eucarc
ec = Eucarc(filepath='eucarc-10.111.5.100-eucalyptus-admin/eucarc')

# Now create the ServiceConnection obj...
from cloud_admin.eucaadmin.serviceconnection import ServiceConnection
cloud_admin = ServiceConnection(host='10.111.5.100', aws_access_key_id=ec.aws_access_key,
                        aws_secret_access_key=ec.aws_secret_key)

```

#### ipython shell capture showing some usage examples:
#### Fetch admin info from cloud...
```
In [20]: cloud_admin.get
cloud_admin.get_all_arbitrator_services              cloud_admin.get_arbitrator_service                   cloud_admin.get_property
cloud_admin.get_all_cloud_controller_services        cloud_admin.get_cloud_controller_service             cloud_admin.get_proxy_auth_header
cloud_admin.get_all_cluster_controller_services      cloud_admin.get_cluster_controller_service           cloud_admin.get_proxy_url_with_auth
cloud_admin.get_all_cluster_names                    cloud_admin.get_http_connection                      cloud_admin.get_service_types
cloud_admin.get_all_clusters                         cloud_admin.get_list                                 cloud_admin.get_services
cloud_admin.get_all_components                       cloud_admin.get_machine_inventory                    cloud_admin.get_status
cloud_admin.get_all_node_controller_services         cloud_admin.get_node_controller_service              cloud_admin.get_storage_controller_service
cloud_admin.get_all_object_storage_gateway_services  cloud_admin.get_object                               cloud_admin.get_utf8_value
cloud_admin.get_all_storage_controller_services      cloud_admin.get_object_storage_gateway_service       cloud_admin.get_vmware_broker_service
cloud_admin.get_all_vmware_broker_services           cloud_admin.get_path                                 cloud_admin.get_walrus_backend_service
cloud_admin.get_all_walrus_backend_services          cloud_admin.get_properties
```



### ServiceConnection can provide summarized detail via Tabled output...

```
In [16]: cloud_admin.sho
cloud_admin.show_cloud_controllers       cloud_admin.show_nodes                   cloud_admin.show_properties_narrow       cloud_admin.show_services
cloud_admin.show_cluster_controllers     cloud_admin.show_objectstorage_gateways  cloud_admin.show_service_types           cloud_admin.show_storage_controllers
cloud_admin.show_components_summary      cloud_admin.show_properties              cloud_admin.show_service_types_verbose   cloud_admin.show_walrus_backends
```

### Show all service and their status

```
In [16]: cloud_admin.show_services()
+--------------------+-------------------------------+--------+-------+------------------------------------------------------+
|TYPE                |NAME                           |STATE   |CLUSTER|URI                                                   |
+--------------------+-------------------------------+--------+-------+------------------------------------------------------+
|arbitrator          |NOT REGISTERED?                |MISSING |   --  |SERVICE NOT REGISTERED                                |
|loadbalancingbackend|10.111.5.100                   |NOTREADY|       |http://10.111.5.100:8773/services/LoadBalancingBackend|
|imagingbackend      |10.111.5.100                   |NOTREADY|       |http://10.111.5.100:8773/services/ImagingBackend      |
|walrusbackend       |walrus-1                       |ENABLED |       |http://10.111.5.100:8773/services/WalrusBackend       |
|storage             |two-sc-1                       |ENABLED |  two  |http://10.111.5.147:8773/services/Storage             |
|cluster             |two-cc-1                       |ENABLED |  two  |http://10.111.5.147:8774/axis2/services/EucalyptusCC  |
|storage             |one-sc-1                       |ENABLED |  one  |http://10.111.5.71:8773/services/Storage              |
|cluster             |one-cc-1                       |ENABLED |  one  |http://10.111.5.71:8774/axis2/services/EucalyptusCC   |
|tokens              |API_10.111.5.100.tokens        |ENABLED |       |http://10.111.5.100:8773/services/Tokens              |
|simpleworkflow      |API_10.111.5.100.simpleworkflow|ENABLED |       |http://10.111.5.100:8773/services/SimpleWorkflow      |
|objectstorage       |API_10.111.5.100.objectstorage |ENABLED |       |http://10.111.5.100:8773/services/objectstorage       |
|loadbalancing       |API_10.111.5.100.loadbalancing |ENABLED |       |http://10.111.5.100:8773/services/LoadBalancing       |
|imaging             |API_10.111.5.100.imaging       |ENABLED |       |http://10.111.5.100:8773/services/Imaging             |
|euare               |API_10.111.5.100.euare         |ENABLED |       |http://10.111.5.100:8773/services/Euare               |
|compute             |API_10.111.5.100.compute       |ENABLED |       |http://10.111.5.100:8773/services/compute             |
|cloudwatch          |API_10.111.5.100.cloudwatch    |ENABLED |       |http://10.111.5.100:8773/services/CloudWatch          |
|cloudformation      |API_10.111.5.100.cloudformation|ENABLED |       |http://10.111.5.100:8773/services/CloudFormation      |
|autoscaling         |API_10.111.5.100.autoscaling   |ENABLED |       |http://10.111.5.100:8773/services/AutoScaling         |
|user-api            |API_10.111.5.100               |ENABLED |       |http://10.111.5.100:8773/services/User-API            |
|eucalyptus          |10.111.5.100                   |ENABLED |       |http://10.111.5.100:8773/services/Eucalyptus          |
|bootstrap           |10.111.5.100                   |ENABLED |       |http://10.111.5.100:8773/services/Empyrean            |
|reporting           |10.111.5.100                   |ENABLED |       |http://10.111.5.100:8773/services/Reporting           |
|pollednotifications |10.111.5.100                   |ENABLED |       |http://10.111.5.100:8773/services/PolledNotifications |
|jetty               |10.111.5.100                   |ENABLED |       |http://10.111.5.100:8773/services/Jetty               |
|notifications       |10.111.5.100                   |ENABLED |       |http://10.111.5.100:8773/services/Notifications       |
|dns                 |10.111.5.100                   |ENABLED |       |http://10.111.5.100:8773/services/Dns                 |
|autoscalingbackend  |10.111.5.100                   |ENABLED |       |http://10.111.5.100:8773/services/AutoScalingBackend  |
|cloudwatchbackend   |10.111.5.100                   |ENABLED |       |http://10.111.5.100:8773/services/CloudWatchBackend   |
+--------------------+-------------------------------+--------+-------+------------------------------------------------------+
```

### show all service types possible for this cloud...

```
In [17]: cloud_admin.show_service_types()
+------------------+-------+------------------+------+------------------------------------------------------------+
|NAME              |CLUSTER|      PARENT      |PUBLIC|DESCRIPTION                                                 |
+------------------+-------+------------------+------+------------------------------------------------------------+
|user-api          |   -   |        *         |false |The service group of all user-facing API endpoint services  |
|  loadbalancing   |   -   |     user-api     |true  |ELB API service                                             |
|  autoscaling     |   -   |     user-api     |true  |Auto Scaling API service                                    |
|  objectstorage   |   -   |     user-api     |true  |S3 API service                                              |
|  cloudwatch      |   -   |     user-api     |true  |CloudWatch API service                                      |
|  euare           |   -   |     user-api     |true  |IAM API service                                             |
|  compute         |   -   |     user-api     |true  |the Eucalyptus EC2 API service                              |
|  cloudformation  |   -   |     user-api     |true  |Cloudformation API service                                  |
|  simpleworkflow  |   -   |     user-api     |true  |Simple Workflow API service                                 |
|  tokens          |   -   |     user-api     |true  |STS API service                                             |
|  imaging         |   -   |     user-api     |true  |Eucalyptus imaging service                                  |
|eucalyptus        |   -   |        -         |false |eucalyptus service implementation                           |
|walrusbackend     |   -   |        -         |false |The legacy Walrus Backend service                           |
|storage           |  TRUE |        -         |false |The Storage Controller service                              |
|arbitrator        |  TRUE |        -         |false |The Arbitrator service                                      |
|cluster           |  TRUE |        -         |false |The Cluster Controller service                              |
+------------------+-------+------------------+------+------------------------------------------------------------+
```

### Show node controller services, state and instances

```
In [5]: cloud_admin.show_nodes()

+----+------------+-------+-----------------------------------------------------------+
|ZONE| NODE NAME  | STATE |                         INSTANCES                         |
+----+------------+-------+-----------------------------------------------------------+
|one |10.111.5.120|ENABLED|  i-9d2eff51(running,       m3.xlarge,   ebs             ) |
|    |            |       |  i-22298477(running,       m3.2xlarge,  instance-store  ) |
|    |            |       |  i-30ddd614(running,       m1.small,    instance-store  ) |
+----+------------+-------+-----------------------------------------------------------+

In [18]: cloud_admin.show_nodes()

+----+------------+-------+-----------------------------------------------------------+
|ZONE| NODE NAME  | STATE |                         INSTANCES                         |
+----+------------+-------+-----------------------------------------------------------+
|one |10.111.5.70 |ENABLED|i-dacc93da(running,       m1.small,    instance-store  )   |
+----+------------+-------+-----------------------------------------------------------+
|two |10.111.5.148|ENABLED|                                                           |
+----+------------+-------+-----------------------------------------------------------+
```

### Show component/host service states

```
In [19]: cad.show_components_summary()

+------------+------------------------------+----------------+-------+-------------+
|HOSTNAME    |NAME                          |PARTITION       |STATE  |TYPE         |
+------------+------------------------------+----------------+-------+-------------+
|10.111.5.100|API_10.111.5.100.objectstorage|API_10.111.5.100|ENABLED|objectstorage|
|10.111.5.70 |10.111.5.70                   |one             |ENABLED|node         |
|10.111.5.71 |one-cc-1                      |one             |ENABLED|cluster      |
|10.111.5.71 |one-sc-1                      |one             |ENABLED|storage      |
|10.111.5.147|two-cc-1                      |two             |ENABLED|cluster      |
|10.111.5.147|two-sc-1                      |two             |ENABLED|storage      |
|10.111.5.148|10.111.5.148                  |two             |ENABLED|node         |
|10.111.5.100|walrus-1                      |walrus          |ENABLED|walrusbackend|
+------------+------------------------------+----------------+-------+-------------+

In [4]: cloud_admin.show_clusters(name='two')
[2015-05-20 00:09:01,495] [ServiceConnection] [DEBUG]:
+-------------------------------------------------------------------------------+
| SHOW CLUSTERS                                                                 |
+-------------------------------------------------------------------------------+
| CLUSTER NAME:"two"                                                            |
| +--------------------+------------------------------------------------------+ |
| | MACHINE            | SERVICES                                             | |
| +--------------------+------------------------------------------------------+ |
| |                    |   TYPE       NAME           STATE      CLUSTER       | |
| | 10.111.5.85        |   node       10.111.5.85    ENABLED      two         | |
| |                    |                                                      | |
| |                    | INSTANCES                                            | |
| |                    | i-44274273(running),     m1.small,    instance-store | |
| |                    | i-51475876(running),     m1.small,    instance-store | |
| |                    | i-3fea5ffe(running),     m1.small,    instance-store | |
| |                    |                                                      | |
| +--------------------+------------------------------------------------------+ |
| |                    |   TYPE       NAME           STATE      CLUSTER       | |
| | 10.111.1.116       |   storage    two-sc-1       ENABLED      two         | |
| |                    |   cluster    two-cc-1       ENABLED      two         | |
| |                    |                                                      | |
| +--------------------+------------------------------------------------------+ |
+-------------------------------------------------------------------------------+


In [5]: cloud_admin.show_machines()
[2015-05-20 00:09:47,285] [ServiceConnection] [DEBUG]:
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

### Query and display properties...


##### Retrieve a list of all the cloud properties with get_properties(), or provide a filter
##### to retrieve a subset (for example: filter all properties with the prefix 'www')
```
Filter example:
In [20]: wwwprops = cloud_admin.get_properties('www')

In [21]: cloud_admin.show_prop
cloud_admin.show_properties         cloud_admin.show_properties_narrow

In [21]: cloud_admin.show_properties(wwwprops)

+-------------------+----------------------------------------+---------------------------------+
|PROPERTY NAME      |PROPERTY VALUE                          |DESCRIPTION                      |
+-------------------+----------------------------------------+---------------------------------+
|www.http_port      |8887                                    |Listen to HTTP on this port.     |
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

##### Or provide a filter to the show method directly. Example, only show properties
##### beginning with 'www.https_'

```
In [22]: cloud_admin.show_properties('www.https_')

+-------------------+----------------------------------------+---------------------------------+
|PROPERTY NAME      |PROPERTY VALUE                          |DESCRIPTION                      |
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

### Modify properties...

```
In [5]: prop = cloud_admin.get_property('services.imaging.worker.log_server')

In [6]: prop
Out[6]: EucaProperty:services.imaging.worker.log_server

In [7]: prop.show()

+----------------------------------+---------------+----------------------------------------+
|PROPERTY NAME                     |PROPERTY VALUE |DESCRIPTION                             |
+----------------------------------+---------------+----------------------------------------+
|services.imaging.worker.log_server|169.254.123.123|address/ip of the server that collects  |
|                                  |               |logs from imaging wokrers               |
+----------------------------------+---------------+----------------------------------------+


In [8]: prop.modify_value('169.254.0.100')

+----------------------------------+--------------+
|PROPERTY NAME                     |PROPERTY VALUE|
+----------------------------------+--------------+
|services.imaging.worker.log_server|169.254.0.100 |
+----------------------------------+--------------+

Out[8]: EucaProperty:services.imaging.worker.log_server

In [9]: prop.show()

+----------------------------------+--------------+----------------------------------------+
|PROPERTY NAME                     |PROPERTY VALUE|DESCRIPTION                             |
+----------------------------------+--------------+----------------------------------------+
|services.imaging.worker.log_server|169.254.0.100 |address/ip of the server that collects  |
|                                  |              |logs from imaging wokrers               |
+----------------------------------+--------------+----------------------------------------+
```



### Modify Service States...

```
In [15]: storage_service  = cloud_admin.get_services(service_type='storage', partition='one')[0]

In [16]: storage_service.show()
+-------+--------+-------+-------+----------------------------------------+
|TYPE   |NAME    |STATE  |CLUSTER|URI                                     |
+-------+--------+-------+-------+----------------------------------------+
|storage|one-sc-1|ENABLED|  one  |http://10.111.5.71:8773/services/Storage|
+-------+--------+-------+-------+----------------------------------------+

In [17]: storage_service.modify_service_state('DISABLED')
ModifyService(State="DISABLED", Name="one-sc-1")
+-------+--------+--------+-------+----------------------------------------+
|TYPE   |NAME    |STATE   |CLUSTER|URI                                     |
+-------+--------+--------+-------+----------------------------------------+
|storage|one-sc-1|DISABLED|  one  |http://10.111.5.71:8773/services/Storage|
+-------+--------+--------+-------+----------------------------------------+
Out[17]: EucaService:one-sc-1


In [18]: storage_service.show()
+-------+--------+--------+-------+----------------------------------------+
|TYPE   |NAME    |STATE   |CLUSTER|URI                                     |
+-------+--------+--------+-------+----------------------------------------+
|storage|one-sc-1|DISABLED|  one  |http://10.111.5.71:8773/services/Storage|
+-------+--------+--------+-------+----------------------------------------+

In [19]: storage_service.modify_service_state('ENABLED')
ModifyService(State="ENABLED", Name="one-sc-1")
+-------+--------+-------+-------+----------------------------------------+
|TYPE   |NAME    |STATE  |CLUSTER|URI                                     |
+-------+--------+-------+-------+----------------------------------------+
|storage|one-sc-1|ENABLED|  one  |http://10.111.5.71:8773/services/Storage|
+-------+--------+-------+-------+----------------------------------------+
Out[19]: EucaService:one-sc-1
```



### Can also produce HTML versions of the ascii tables...

##### In [6]: cloud_admin.show_services(do_html=True)


[SAMPLE FULL HTML TABLE ON GH-PAGES](http://bigschwan.github.io/eutester/cloud_admin/services_status_sample.html)


##### ...or github rendering of table html...



<table frame="box" rules="all">
    <tr>
        <th style="padding-left: 0em; padding-right: 0em; text-align: center"><font color="BLUE"><b>TYPE</b></font></th>
        <th style="padding-left: 0em; padding-right: 0em; text-align: center"><font color="BLUE"><b>NAME</b></font></th>
        <th style="padding-left: 0em; padding-right: 0em; text-align: center"><font color="BLUE"><b>STATE</b></font></th>
        <th style="padding-left: 0em; padding-right: 0em; text-align: center"><font color="BLUE"><b>CLUSTER</b></font></th>
        <th style="padding-left: 0em; padding-right: 0em; text-align: center"><font color="BLUE"><b>URI</b></font></th>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED"><b><u>loadbalancingbackend</u></b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED"><b><u>10.111.5.100</u></b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED"><b><u>NOTREADY</u></b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED"><b><u>http://10.111.5.100:8773/services/LoadBalancingBackend</u></b></font></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED"><b><u>imagingbackend</u></b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED"><b><u>10.111.5.100</u></b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED"><b><u>NOTREADY</u></b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED"><b><u>http://10.111.5.100:8773/services/ImagingBackend</u></b></font></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED">arbitrator</font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED">NOT REGISTERED?</font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED">MISSING</font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="RED">--</font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="RED">SERVICE NOT REGISTERED</font></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>walrusbackend</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">walrus-1</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/WalrusBackend</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>storage</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">two-sc-1</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">two</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.147:8773/services/Storage</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>cluster</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">two-cc-1</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">two</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.147:8774/axis2/services/EucalyptusCC</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>storage</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">one-sc-1</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">one</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.71:8773/services/Storage</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>cluster</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">one-cc-1</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">one</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.71:8774/axis2/services/EucalyptusCC</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>tokens</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100.tokens</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/Tokens</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>simpleworkflow</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100.simpleworkflow</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/SimpleWorkflow</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>objectstorage</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100.objectstorage</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/objectstorage</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>loadbalancing</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100.loadbalancing</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/LoadBalancing</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>imaging</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100.imaging</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/Imaging</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>euare</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100.euare</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/Euare</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>compute</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100.compute</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/compute</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>cloudwatch</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100.cloudwatch</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/CloudWatch</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>cloudformation</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100.cloudformation</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/CloudFormation</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>autoscaling</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100.autoscaling</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/AutoScaling</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>user-api</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">API_10.111.5.100</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/User-API</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>eucalyptus</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">10.111.5.100</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="GREEN"><b>ENABLED</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">http://10.111.5.100:8773/services/Eucalyptus</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>bootstrap</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>10.111.5.100</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b><font color="GREEN"><b>ENABLED</b></font></b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>http://10.111.5.100:8773/services/Empyrean</b></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>reporting</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>10.111.5.100</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b><font color="GREEN"><b>ENABLED</b></font></b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>http://10.111.5.100:8773/services/Reporting</b></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>pollednotifications</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>10.111.5.100</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b><font color="GREEN"><b>ENABLED</b></font></b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>http://10.111.5.100:8773/services/PolledNotifications</b></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>jetty</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>10.111.5.100</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b><font color="GREEN"><b>ENABLED</b></font></b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>http://10.111.5.100:8773/services/Jetty</b></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>notifications</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>10.111.5.100</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b><font color="GREEN"><b>ENABLED</b></font></b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>http://10.111.5.100:8773/services/Notifications</b></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>dns</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>10.111.5.100</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b><font color="GREEN"><b>ENABLED</b></font></b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>http://10.111.5.100:8773/services/Dns</b></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>autoscalingbackend</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>10.111.5.100</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b><font color="GREEN"><b>ENABLED</b></font></b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>http://10.111.5.100:8773/services/AutoScalingBackend</b></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>cloudwatchbackend</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>10.111.5.100</b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b><font color="GREEN"><b>ENABLED</b></font></b></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><b>http://10.111.5.100:8773/services/CloudWatchBackend</b></td>
    </tr>
</table>






###### In [5]: cloud_admin.show_service_types(do_html=True)



[SAMPLE FULL HTML TABLE ON GH-PAGES](http://bigschwan.github.io/eutester/cloud_admin/service_types_sample.html)





...or github rendering of table html...


<table frame="box" rules="all">
    <tr>
        <th style="padding-left: 0em; padding-right: 0em; text-align: center"><b>NAME              </b></th>
        <th style="padding-left: 0em; padding-right: 0em; text-align: center"><b>CLUSTER</b></th>
        <th style="padding-left: 0em; padding-right: 0em; text-align: center"><b>      PARENT      </b></th>
        <th style="padding-left: 0em; padding-right: 0em; text-align: center"><b>PUBLIC</b></th>
        <th style="padding-left: 0em; padding-right: 0em; text-align: center"><b>DESCRIPTION                                                 </b></th>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>user-api</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>-</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>        *         </b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>false</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>The service group of all user-facing API endpoint services</b></font></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">  loadbalancing</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">-</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">user-api</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">true</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">ELB API service</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">  autoscaling</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">-</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">user-api</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">true</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">Auto Scaling API service</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">  objectstorage</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">-</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">user-api</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">true</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">S3 API service</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">  cloudwatch</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">-</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">user-api</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">true</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">CloudWatch API service</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">  euare</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">-</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">user-api</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">true</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">IAM API service</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">  compute</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">-</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">user-api</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">true</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">the Eucalyptus EC2 API service</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">  cloudformation</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">-</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">user-api</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">true</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">Cloudformation API service</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">  simpleworkflow</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">-</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">user-api</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">true</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">Simple Workflow API service</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">  tokens</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">-</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">user-api</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">true</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">STS API service</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">  imaging</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">-</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top">user-api</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">true</td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top">Eucalyptus imaging service</td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>eucalyptus</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>-</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>-</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>false</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>eucalyptus service implementation</b></font></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>walrusbackend</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>-</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>-</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>false</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>The legacy Walrus Backend service</b></font></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>storage</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>TRUE</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>-</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>false</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>The Storage Controller service</b></font></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>arbitrator</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>TRUE</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>-</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>false</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>The Arbitrator service</b></font></td>
    </tr>
    <tr>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>cluster</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>TRUE</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: center; vertical-align: top"><font color="BLUE"><b>-</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>false</b></font></td>
        <td style="padding-left: 0em; padding-right: 0em; text-align: left; vertical-align: top"><font color="BLUE"><b>The Cluster Controller service</b></font></td>
    </tr>
</table>



##### More EXAMPLES...




####   Example: How to forward the requests over an ssh encrypted session... #


 - Where '10.111.5.156' is the CLC serving the empyrean requests/service.

```
from cloud_utils.file_utils.eucarc import Eucarc
from cloud_admin.eucaadmin.serviceconnection import ServiceConnection
from cloud_utils.net_utils.sshconnection import SshConnection

# Create an sshconnection to the CLC...
ssh_to_clc = SshConnection(host='10.111.5.156', password='foobar', verbose=True)

# For ease of reading in access and secret keys build a eucarc obj from a local or remote eucarc
# read in a local eucarc:
ec = Eucarc(filepath='eucarc-10.111.5.156-eucalyptus-admin/eucarc')
# or read in a eucarc on a remote system...
ec = Eucarc(filepath='/root/eucarc', sshconnection=ssh_to_clc)

# Create a ServiceConnection interface with the admin's access and secret key, since this is being
# forward from a local port, set the host to localhost...
cad = ServiceConnection(host='127.0.0.1', aws_access_key_id=ec.aws_access_key,
                aws_secret_access_key=ec.aws_secret_key)

# Replace the underlying method of creating an http connection w/ something like this
# returning the connection from the ssh obj's create_http_fwd_connection()
def gethttp(*args, **kwargs):
     http_connection_kwargs = cad.http_connection_kwargs.copy()
     return ssh_to_clc.create_http_fwd_connection(destport=cad.port, localport=9797)

# now swap in the newly created method...
cad._pool.get_http_connection = gethttp

# now fire away requests...
cad.show_storage_controllers()
+------------+--------+---------+-------+-------+
|HOSTNAME    |NAME    |PARTITION|STATE  |TYPE   |
+------------+--------+---------+-------+-------+
|10.111.5.180|one-sc-1|one      |ENABLED|storage|
|10.111.1.116|two-sc-1|two      |ENABLED|storage|
+------------+--------+---------+-------+-------+
```
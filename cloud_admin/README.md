
ipython shell capture showing some usage examples:


First create an admin connection obj...
````
from cloud_utils.file_utils.eucarc import Eucarc
ec = Eucarc(filepath='eucarc-10.111.5.100-eucalyptus-admin/eucarc')
from cloud_admin.eucaadmin import EucaAdmin
cloud_admin = EucaAdmin(host='10.111.5.100', aws_access_key_id=ec.aws_access_key,
                        aws_secret_access_key=ec.aws_secret_key, boto_debug_level=2)

In [12]: from cloud_utils.file_utils.eucarc import Eucarc

In [13]: ec = Eucarc(filepath='eucarc-10.111.5.100-eucalyptus-admin/eucarc')

In [14]: from cloud_admin.eucaadmin import EucaAdmin

In [15]: cloud_admin  = EucaAdmin(host='10.111.5.100', aws_access_key_id=ec.aws_access_key,
                                  aws_secret_access_key=ec.aws_secret_key)
```

Fetch admin info from cloud...
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



EucaAdmin can provide summarized detail via Tabled output...

```
In [16]: cloud_admin.sho
cloud_admin.show_cloud_controllers       cloud_admin.show_nodes                   cloud_admin.show_properties_narrow       cloud_admin.show_services
cloud_admin.show_cluster_controllers     cloud_admin.show_objectstorage_gateways  cloud_admin.show_service_types           cloud_admin.show_storage_controllers
cloud_admin.show_components_summary      cloud_admin.show_properties              cloud_admin.show_service_types_verbose   cloud_admin.show_walrus_backends


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


In [18]: cloud_admin.show_nodes()

+----+------------+-------+-----------------------------------------------------------+
|ZONE| NODE NAME  | STATE |                         INSTANCES                         |
+----+------------+-------+-----------------------------------------------------------+
|one |10.111.5.70 |ENABLED|i-dacc93da(running,       m1.small,    instance-store  )   |
+----+------------+-------+-----------------------------------------------------------+
|two |10.111.5.148|ENABLED|                                                           |
+----+------------+-------+-----------------------------------------------------------+


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
```

Query and display properties...

```
Filter example:
In [20]: wwwprops = cloud_admin.get_properties('www')

In [21]: cloud_admin.sho
cloud_admin.show_cloud_controllers       cloud_admin.show_nodes                   cloud_admin.show_properties_narrow       cloud_admin.show_services
cloud_admin.show_cluster_controllers     cloud_admin.show_objectstorage_gateways  cloud_admin.show_service_types           cloud_admin.show_storage_controllers
cloud_admin.show_components_summary      cloud_admin.show_properties              cloud_admin.show_service_types_verbose   cloud_admin.show_walrus_backends

In [21]: cloud_admin.show_pr
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

Modify properties...

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

Modify Service States...

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

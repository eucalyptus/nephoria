##### Cloud Admin Host Modules

    ### EucaHost
        Eucahost is the primary machine class for a Linux Machine hosting Eucalytpus Services.

    ### Helpers
        The helper classes can accompany a Eucahost machine and provide specific Eucalyptus
        Service utility methods to be run on the Host machine.


#### Example (Build a Euclyptus Node Controller Host):
```
    from cloud_admin.hosts.eucahost import EucaHost
    from cloud_admin.eucaadmin.serviceConnection import ServiceConnection
    from cloud_utils.file_utils.eucarc import Eucarc

    # Build a Eucarc obj to easilly grab our access and secret key strings...
    ec = Eucarc(filepath='eucarc-10.111.5.156-eucalyptus-admin/eucarc')

    # Build the Eucalyptus ServiceConnection obj to request the Node Controller Service...
    cloud_admin = ServiceConnection(host='10.111.5.156', aws_access_key_id=ec.aws_access_key,
                           aws_secret_access_key=ec.aws_secret_key)

    # In this case I know the hostname/ip of the node service I want...
    node_service = cloud_admin.get_node_controller_service('10.111.5.151')

    #Now Create a EucaHost obj...
    node_controller = EucaHost(node_service.hostname, services=[node_service], password='foobar')

    ###########################################################################################
    # Some Sample of methods that might be useful on a node controller host machine...        #
    ###########################################################################################

    # Print the hostname of this machine...
    print node_controller.hostname

    # Get the eucalyptus-nc service process pid...
    node_controller.get_eucalyptus_nc_pid()

    # Check the eucalyptus-nc services uptime on this machine...
    print node_controller.get_eucalyptus_nc_process_uptime()

    # Get an instance's console information
    node_controller.euca_nc_helpers.get_instance_console_path('i-1234abcd')

    # ...or tail a VM's console output. In this case for 20 lines or 5 seconds w/o activity
    # whichever comes first...
    node_controller.euca_nc_helpers.tail_instance_console('i-1234abcd', max_lines=20, idle_timeout=5)

    # Check virsh list to see what VMs the hypervisor says it's running...
    if node_controller.eucalyptus_conf.HYPERVISOR == 'kvm':
        node_controller.euca_nc_helpers.get_virsh_list()

    # Ping the node's CC for a connectivity check...
    nodes_cc = cloud_admin.get_all_cluster_controller_services(partition=node.partition)[0]
    node_controller.ping_check(nodes_cc.hostname)
```

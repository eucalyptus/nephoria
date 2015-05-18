
### Cloud admin modules:

##### backends:
    Cloud backend modules. This may include backend modules for:
        - Block storage modules for the backing HW or SW (ie SAN, DAS, Ceph, etc)
        - Network modules (ie: Network HW, SDN component interfaces, etc. )
        - Hypervisor modules (ie: vmware api, etc)
        - Object Storage modules (ie: Riak, etc)

##### services:
    Eucalyptus specific modules. This may include:
        - Eucalyptus Administrative Services
        - Eucalyptus Administrative Properties
        - Eucalyptus Administrative API

##### hosts:
    Host machine modules. This may include:
       - Eucalyptus Host machine modules and service specific machine helper modules. These will
         be primarily for Linux machines which are hosting the Eucalyptus services.
       - Utlities to manage the host machines.

##### access:
    Utility modules help Administer Cloud Users, Accounts, Credentials Administrative modules
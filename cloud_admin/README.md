
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

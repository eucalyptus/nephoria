
"""
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
"""

from cloud_admin.cloudview import ConfigBlock

class NetworkBuilder(ConfigBlock):
    def __init__(self, builder):
        pass

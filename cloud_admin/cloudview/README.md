
#### Utilities for building cloud manifests. These manifests will be text, and/or graphical
representations of a cloud.
These can be used for cloud configuration mgmt, diagnostics, and related admin tooling.

Utilities should help with:
-Cloud discovery. Discovery an existing cloud, and produce a textual/graphical representation of
 this cloud.
-Diagnostics. Methods to fetch information from a combination of the Eucalyptus Application itself,
 as well as the underlying systems; Machines, Operating systems, Hardware/Backends, etc..


### Some example usage:


First create a systemconnection object and a configuration block obj, type of configurationblock
obj will depend on what you are trying to build...
```

In [1]: from cloud_admin.cloudview.eucalyptusblock import EucalyptusBlock
In [2]: from cloud_admin.systemconnection import SystemConnection

In [3]: sc = SystemConnection('10.111.5.156', password='foobar', credpath='eucarc-10.111.5.156-eucalyptus-admin/eucarc')
In [4]: eb = EucalyptusBlock(sc)
```

Now build/discover the configuration from an active/live cloud...

```
In [7]: eb.build_active_config(do_props=False)
```


In Yaml...

```
In [2]: from cloud_admin.cloudview.eucalyptusblock import EucalyptusBlock
In [3]: from cloud_admin.cloudview.systemconnection import SystemConnection
In [4]: sc = SystemConnection('10.111.5.156', password='foobar')
In [5]: eb = EucalyptusBlock(sc)
In [6]: eb.build_active_config(do_props=False)
In [7]: print eb.to_yaml()
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
    clusters:
      one:
        nodes: 10.111.5.151
        one-cc-1: 10.111.5.180
        one-sc-1: 10.111.5.180
      two:
        nodes: 10.111.5.85
        two-cc-1: 10.111.1.116
        two-sc-1: 10.111.1.116
    storage-backend: netapp
  user-facing:
  - 10.111.5.156
  walrus: 10.111.5.156
user: eucalyptus
yum-options: --nogpg
```

In Json...

```
In [13]: print eb.to_json()
{
    "nc": {
        "max-cores": "32"
    },
    "topology": {
        "clc-1": "10.111.5.156",
        "clusters": {
            "clusters": {
                "one": {
                    "nodes": "10.111.5.151",
                    "one-cc-1": "10.111.5.180",
                    "one-sc-1": "10.111.5.180",
                    "storage-backend": "netapp"
                },
                "two": {
                    "nodes": "10.111.5.85",
                    "storage-backend": "netapp",
                    "two-cc-1": "10.111.1.116",
                    "two-sc-1": "10.111.1.116"
                }
            }
        },
        "user-facing": [
            "10.111.5.156"
        ],
        "walrus": "10.111.5.156"
    }
}

```
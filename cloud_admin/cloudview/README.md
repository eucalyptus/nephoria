
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
In [2]: from cloud_admin.cloudview.systemconnection import SystemConnection

In [3]: sc = SystemConnection('10.111.5.156', password='foobar', credpath='eucarc-10.111.5.156-eucalyptus-admin/eucarc')
In [4]: eb = EucalyptusBlock(sc)
```

Now build/discover the configuration from an active/live cloud...

```
In [7]: eb.build_active_config(do_props=False)
```


In Yaml...

```
In [8]: print eb.to_yaml()
nc:
  max-cores: '32'
topology:
  clc-1: 10.111.5.156
  clusters:
    clusters:
      one:
        nodes: 10.111.5.151
        one-cc-1: 10.111.5.180
        one-sc-1: 10.111.5.180
        storage-backend: netapp
      two:
        nodes: 10.111.5.85
        storage-backend: netapp
        two-cc-1: 10.111.1.116
        two-sc-1: 10.111.1.116
  user-facing:
  - 10.111.5.156
  walrus: 10.111.5.156
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

"""
    eucalyptus-repo: http://packages.release.eucalyptus-systems.com/yum/tags/eucalyptus-devel/centos/6/x86_64/
    enterprise-repo: http://packages.release.eucalyptus-systems.com/yum/tags/enterprise-devel/centos/6/x86_64/
    euca2ools-repo: http://packages.release.eucalyptus-systems.com/yum/tags/euca2ools-devel/centos/6/x86_64/
    yum-options: "--nogpg"
"""

from cloud_admin.topo import BaseBuilder


class RepoBuilder(BaseBuilder):

    def __init__(self, builder):
        pass

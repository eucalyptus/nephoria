
from cloud_admin.hosts.helpers import EucaMachineHelpers


class ClusterControllerHelpers(EucaMachineHelpers):
    """
    Represents a machine hosting the cluster controller service.
    """
    @property
    def cluster_controller_service(self):
        for service in self.services:
            if service.type == 'cluster':
                return service
        return None

    def show_iptables(self):
        self.debug(self.sys('iptables-save', code=0, listformat=False))


from cloud_admin.hosts.helpers import EucaMachineHelpers


class CloudControllerHelpers(EucaMachineHelpers):
    """
    Helper methods for the machine hosting the cluster controller service.
    """
    @property
    def cloud_controller_service(self):
        for service in self.services:
            if service.type == 'eucalyptus':
                return service
        return None

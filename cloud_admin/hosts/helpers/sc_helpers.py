
from cloud_admin.hosts.helpers import EucaMachineHelpers


class StorageControllerHelpers(EucaMachineHelpers):
    """
    Represents a machine hosting the storage controller service.
    """
    @property
    def storage_controller_service(self):
        for service in self.services:
            if service.type == 'storage':
                return service
        return None

    def get_backend_ebs_volumes(self, ids):
        raise NotImplementedError('get_backend_ebs_volumes')

    def get_backend_ebs_snapshots(self, ids):
        raise NotImplementedError('get_backend_ebs_snapshots')

    def delete_ebs_backend_volume(self, id):
        raise NotImplementedError('delete_ebs_backend_volume')

    def create_ebs_backend_volume(self, id):
        raise NotImplementedError('create_ebs_backend_volume')

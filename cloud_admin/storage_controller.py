
from cloud_admin.services import EucaComponentService, SHOW_COMPONENTS
from cloud_admin import EucaMachineHelpers

class EucaStorageControllerService(EucaComponentService):

    def update(self, new_service=None, get_instances=True, silent=True):
        return self._update(get_method_name='get_storage_controller_service',
                            get_method_kwargs=None, new_service=new_service, silent=silent)

    def show(self):
        return SHOW_COMPONENTS(self.connection, self)


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


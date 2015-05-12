
from eutester.euca.cloud_admin.services import EucaComponentService, SHOW_COMPONENTS


class EucaCloudControllerService(EucaComponentService):
    def update(self, new_service=None, get_instances=True, silent=True):
        return self._update(get_method_name='get_cloud_controller_service',
                            get_method_kwargs=None, new_service=new_service, silent=silent)

    def show(self):
        return SHOW_COMPONENTS(self.connection, self)

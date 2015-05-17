
from cloud_admin.services import EucaComponentService, SHOW_COMPONENTS
from cloud_admin import EucaMachineHelpers


class EucaObjectStorageGatewayService(EucaComponentService):


    def update(self, new_service=None, get_instances=True, silent=True):
        return self._update(get_method_name='get_object_storage_gateway_service',
                            get_method_kwargs=None, new_service=new_service, silent=silent)

    def show(self):
        return SHOW_COMPONENTS(self.connection, self)


class ObjectStorageGatewayHelpers(EucaMachineHelpers):
    """
    Place holder for OSG helper methods
    """
    pass

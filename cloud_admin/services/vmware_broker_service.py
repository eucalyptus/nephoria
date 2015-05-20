

from cloud_admin.services.services import EucaComponentService


class EucaVMwareBrokerService(EucaComponentService):

    _service_code = 'VMWARE'

    def update(self, new_service=None, get_instances=True, silent=True):
        return self._update(get_method=self.connection.get_vmware_broker_service,
                            get_method_kwargs=None, new_service=new_service, silent=silent)

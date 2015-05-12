

from eucaadmin.services import EucaComponentService


class EucaVMwareBrokerService(EucaComponentService):

    def update(self, new_service=None, get_instances=True, silent=True):
        return self._update(get_method_name='get_vmware_broker_service',
                            get_method_kwargs=None, new_service=new_service, silent=silent)

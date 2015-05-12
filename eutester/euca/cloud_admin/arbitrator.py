
from eutester.euca.cloud_admin.services import EucaComponentService


class EucaArbitratorService(EucaComponentService):

    def update(self, new_service=None, get_instances=True, silent=True):
        return self._update(get_method_name='get_arbitrator_service',
                            get_method_kwargs=None, new_service=new_service, silent=silent)

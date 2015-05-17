
from cloud_admin.services import EucaComponentService
from cloud_admin import EucaMachineHelpers



class EucaArbitratorService(EucaComponentService):

    def update(self, new_service=None, get_instances=True, silent=True):
        return self._update(get_method_name='get_arbitrator_service',
                            get_method_kwargs=None, new_service=new_service, silent=silent)

class ArbitratorHelpers(EucaMachineHelpers):
    """
    Place holder for arbitrator specific machine helpers
    """
    pass

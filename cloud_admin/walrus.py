

from cloud_admin.services import EucaComponentService, SHOW_COMPONENTS
from cloud_admin import EucaMachineHelpers



class EucaWalrusBackendService(EucaComponentService):


    def update(self, new_service=None, get_instances=True, silent=True):
        return self._update(get_method_name='get_walrus_backend_service',
                            get_method_kwargs=None, new_service=new_service, silent=silent)

    def show(self):
        return SHOW_COMPONENTS(self.connection, self)


class WalrusHelpers(EucaMachineHelpers):
    '''
    Place holder for Walrus specific machine helper methods
    '''
    pass


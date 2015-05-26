
from cloud_admin.services.services import EucaComponentService, SHOW_COMPONENTS


class Ufs(EucaComponentService):
    # Unified Front End Services (UFS), parent service type is 'user-api'
    def __init__(self, connection=None, serviceobj=None):
        if not connection:
            connection = getattr(serviceobj, 'connection', None)
        super(Ufs, self).__init__(connection)
        if serviceobj:
            self.__dict__.update(serviceobj.__dict__)
        if not self.child_services:
            self._get_child_services()

    def update(self, new_service=None, get_instances=True, silent=True):
        self._update(get_method=self.connection.get_unified_frontend_service,
                     get_method_kwargs=None, new_service=new_service, silent=silent)
        self._get_child_services()
        return self

    def show(self):
        return SHOW_COMPONENTS(self.connection, self)

    def _get_child_services(self):
        self.child_services = []
        for serv in self.connection.get_services(partition=self.partition):
            if serv.type != self.type:
                self.child_services.append(serv)
        return self.child_services

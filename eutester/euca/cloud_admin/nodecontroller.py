
from eutester.euca.cloud_admin import EucaBaseObj
from eutester.euca.cloud_admin.services import EucaServiceType


class EucaNodeService(EucaBaseObj):
    def __init__(self, connection=None):
        super(NodeController, self).__init__(connection)
        self.instances=[]

class NodeController(EucaNodeService):
    def __init__(self, connection=None):
        super(NodeController, self).__init__(connection)
        self.instances=[]


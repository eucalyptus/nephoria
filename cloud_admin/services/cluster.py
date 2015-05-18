
from cloud_admin.services import EucaService
from prettytable import PrettyTable


class Cluster(EucaService):
    def __init__(self, connection=None):
        """
        Is intended to represent the sum of services within a given cluster.
        """
        super(Cluster, self).__init__(connection)
        self.connection = connection
        self.cluster_controllers = []
        self.storage_controllers = []
        self.nodes = []
        self.config_properties = {}

    def show_cluster(self, name):
        title = 'CLUSTER: {0}'.format(name)
        main_pt = PrettyTable()

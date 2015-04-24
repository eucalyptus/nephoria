
from eutester.euca.cloud_admin.services import EucaService


class Cluster(EucaService):
    def __init__(self, connection=None):
        super(Cluster, self).__init__(connection)
        self.connection = connection
        self.cluster_controllers = []
        self.storage_controllers = []
        self.nodes = []
        self.config_properties={}

    def update(self, cluster=None):
        params = {}
        params[''] = str(self.partition)
        if not updatedtask:
            updatedtask = self.connection.get_object('DescribeConversionTasks',
                                                     params,
                                                     ConversionTask,
                                                     verb='POST')
        if updatedtask:
            self.__dict__.update(updatedtask.__dict__)
        else:
            print sys.stderr, 'Update. Failed to find task:"{0}"'\
                .format(str(self.conversiontaskid))
            self.notfound = True

    def show_cluster(self, name):

        title = 'CLUSTER: {0}'.format(name)
        main_pt = PrettyTable()

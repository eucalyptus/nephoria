
from prettytable import PrettyTable
from cloud_utils.log_utils import markup

def show_cluster(connection, cluster, print_table=True):
    maintpt = PrettyTable([markup('CLUSTER: {0}'.format(cluster.name))])
    machpt = connection.show_machines(machine_dict=cluster.machines, print_table=False)
    maintpt.add_row([machpt.get_string(sortby=machpt.field_names[1], reversesort=True)])
    proppt = connection.show_properties(cluster.properties, print_table=False)
    maintpt.add_row([proppt.get_string()])
    if print_table:
        connection.debug_method("\n{0}\n".format(maintpt))
    else:
        return maintpt


class Cluster(object):
    def __init__(self, connection, name):
        """
        Is intended to represent the sum of services within a given cluster.
        """
        self.connection = connection
        cluster_names = self.connection.get_all_cluster_names()
        if name not in cluster_names:
            raise ValueError('Cluster Name:{0} was not in system:"{1}"'
                             .format(name, ", ".join(str(x) for x in cluster_names)))
        self.name = name
        self._machines_dict = {}
        self._cluster_controllers = []
        self._storage_controllers = []
        self._nodes = []
        self._properties = []
        self.update()

    def __repr__(self):
        return "{0}:{1}".format(self.__class__.__name__, self.name)

    def show_full(self, print_table=True):
        return show_cluster(connection=self.connection, cluster=self, print_table=print_table)

    def show_summary(self, print_table=True):
        pt = self.show_machines(print_table=False)
        if print_table:
            self.connection.debug_method('\n\t{0}"{1}"\n{2}'.format(markup('\nCLUSTER:'),
                                                                       self.name,
                                                                       str(pt)))
        else:
            return pt

    def show_machines(self, print_table=True):
        pt = self.connection.show_machines(machine_dict=self.machines, print_table=False)
        if print_table:
            self.connection.debug_method("\n{0}\n".format(pt.get_string(sortby=pt.field_names[1],
                                                                        reversesort=True)))
        else:
            return pt

    def show_properties(self, print_table=True):
        return self.connection.show_properties(self.properties, print_table=print_table)

    @property
    def machines(self):
        if not self._machines_dict:
            return self._update_machines()
        return self._machines_dict

    @property
    def cluster_controllers(self):
        if not self._cluster_controllers:
            self._cluster_controllers = []
            for machine, services in self._machines_dict.iteritems():
                for service in services:
                    if service.type == 'cluster':
                        self._cluster_controllers.append({machine: services})
        return self._cluster_controllers

    @cluster_controllers.setter
    def cluster_controllers(self, value):
        value = value or []
        if not isinstance(value, list):
            value = [value]
        self._cluster_controllers = value

    @property
    def storage_controllers(self):
        if not self._storage_controllers:
            self._storage_controllers = []
            for machine, services in self._machines_dict.iteritems():
                for service in services:
                    if service.type == 'storage':
                        self._storage_controllers.append({machine: services})
        return self._storage_controllers

    @storage_controllers.setter
    def storage_controllers(self, value):
        value = value or []
        if not isinstance(value, list):
            value = [value]
        self._storage_controllers = value

    @property
    def node_controllers(self):
        if not self._node_controllers:
            self._node_controllers = []
            for machine, services in self._machines_dict.iteritems():
                for service in services:
                    if service.type == 'node':
                        self._node_controllers.append({machine: services})
        return self._node_controllers

    @node_controllers.setter
    def node_controllers(self, value):
        value = value or []
        if not isinstance(value, list):
            value = [value]
        self._node_controllers = value

    @property
    def properties(self):
        if not self._properties:
            self._properties = self._update_properties()
        return self._properties

    @properties.setter
    def properties(self, value):
        value = value or []
        if not isinstance(value, list):
            value = [value]
        self._properties = value

    def _update_properties(self):
        properties = self.connection.get_properties(self.name + ".")
        if properties:
            self._properties = properties
        return properties

    def _update_machines(self):
        machines = self.connection.get_all_machines(partition=self.name)
        if machines:
            self._machines_dict = machines
        return machines

    def update(self, machines_dict=None, properties=None):
        machines_dict = machines_dict or self._update_machines()
        if machines_dict:
            self._machines_dict = machines_dict
            self._cluster_controllers = []
            self._storage_controllers = []
            self._node_controllers = []
        properties = properties or self._update_properties()
        if properties:
            self._properties = properties
        return self


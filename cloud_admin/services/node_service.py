
from cloud_utils.log_utils import markup
from prettytable import PrettyTable
from cloud_admin.services.services import EucaComponentService


def SHOW_NODES(connection, nodes=None, print_method=None, print_table=True):
    '''
    Prints table summary of nodes.

    :params nodes:  Can be a single, or list of EucaNodeService objects.
                    Can be a single, or list of node names (strings).
    :param print_table: bool, if true will write table to self.debug_method,
                        if false, will return the table object w/o printing it.
    '''
    print_method = print_method or connection._show_method
    if not nodes:
        nodes_list = connection.get_all_node_controller_services()
    else:
        nodes_list = []
        if not isinstance(nodes, list):
            nodes = [nodes]
        for node in nodes:
            if isinstance(node, EucaNodeService):
                nodes_list.append(node)
            elif isinstance(node, basestring):
                nodes_list.append(connection.get_node_controller_service(name=str(node)))
            else:
                raise ValueError('show_nodes: Unknown type for node: "{0}:{1}"'
                                 .format(node, type(node)))
    ins_id_len = 10
    ins_type_len = 13
    ins_dev_len = 16
    ins_st_len = 15
    zone_hdr = (markup('ZONE'), 20)
    name_hdr = (markup('NODE NAME'), 30)
    state_hdr = (markup('STATE'), 20)
    inst_hdr = (markup('INSTANCES'),
                (ins_id_len + ins_dev_len + ins_type_len + ins_st_len) + 5)

    pt = PrettyTable([zone_hdr[0], name_hdr[0], state_hdr[0], inst_hdr[0]])
    pt.max_width[zone_hdr[0]] = zone_hdr[1]
    pt.max_width[inst_hdr[0]] = inst_hdr[1]
    pt.max_width[state_hdr[0]] = state_hdr[1]
    pt.max_width[name_hdr[0]] = name_hdr[1]
    pt.padding_width = 0
    pt.hrules = 1
    for node in nodes_list:
        instances = "".join("{0}({1}{2}{3})"
                            .format(str(x.id).ljust(ins_id_len),
                                    str(x.state + ",").ljust(ins_st_len),
                                    str(x.instance_type + ",").ljust(ins_type_len),
                                    str(x.root_device_type).ljust(ins_dev_len))
                            .ljust(inst_hdr[1])
                            for x in node.instances)
        instances.strip()
        if node.state == 'ENABLED':
            markups = [1, 92]
        else:
            markups = [1, 91]
        pt.add_row([node.partition, markup(node.name),
                    markup(node.state, markups), instances])
    if print_table:
        print_method('\n' + pt.get_string(sortby=zone_hdr[0]) + '\n')
    else:
        return pt

##################################################################################################
#                       Eucalyptus internal service class 'node'                                 #
##################################################################################################


class EucaNodeService(EucaComponentService):
    """
    Represents the Eucalyptus service type 'node' as is represented by the cloud.
    Used to parse the node service type describe, and modify requests/responses.
    """

    def __init__(self, connection=None):
        super(EucaNodeService, self).__init__(connection)
        self.instances = []
        self.localstate = None
        self.name = None
        self.partition = None
        self.fullname = None
        self._hostname = None

    @property
    def state(self):
        return self.localstate

    @state.setter
    def state(self, value):
        self.localstate = value

    @property
    def hostname(self):
        if self._hostname:
            return self._hostname
        else:
            return self.name

    @hostname.setter
    def hostname(self, value):
        self._hostname = value

    @classmethod
    def _from_service(cls, service):
        new_node = cls()
        new_node.__dict__.update(service.__dict__)
        return new_node

    def show(self):
        return SHOW_NODES(self.connection, nodes=self)

    def update(self, new_service=None, get_instances=True, silent=True):
        """
        Updates this service obj
        :params silent: bool, if True will not raise Exceptions found during lookup, will instead
                        write errors to self.connection.err_method()
        :returns : self upon successful update, otherwise returns None
        """
        if not new_service:
            if not self.name and not self.fullname:
                raise ValueError('Must set "name" or "fullname" before using update(). Name:{0}'
                                 .format(self.name))
        return self._update(new_service=new_service,
                            get_method=self.connection.get_node_controller_service,
                            get_method_kwargs={'name': self.name,
                                               'fullname': self.fullname,
                                               'partition': self.partition,
                                               'get_instances': get_instances},
                            silent=silent)

    def modify_service_state(self, state, verbose=True):
        self.connection.modify_service(service=self, state=state, verbose=verbose)
        self.update()
        return self

    def endElement(self, name, value, connection):
        ename = name.replace('euca:', '').lower()
        if ename:
            if ename == 'localstate':
                setattr(self, 'state', value)
                setattr(self, ename, value)
                return
        super(EucaNodeService, self).startElement(name, value, connection)

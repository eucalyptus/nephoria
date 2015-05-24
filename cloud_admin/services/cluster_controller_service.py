
from cloud_admin.services.services import EucaComponentService
from cloud_utils.log_utils import markup
from prettytable import PrettyTable


def SHOW_CLUSTER_CONTROLLER_SERVICES(connection, ccs=None, print_method=None, print_table=True):
    print_method = print_method or connection._show_method
    hostname_hdr = ('HOSTNAME', 24)
    name_hdr = ('NAME', 24)
    cluster_hdr = ('CLUSTER', 24)
    state_hdr = ('STATE', 16)
    pt = PrettyTable([hostname_hdr[0], name_hdr[0], cluster_hdr[0], state_hdr[0]])
    pt.max_width[hostname_hdr[0]] = hostname_hdr[1]
    pt.max_width[name_hdr[0]] = name_hdr[1]
    pt.max_width[cluster_hdr[0]] = cluster_hdr[1]
    pt.max_width[state_hdr[0]] = state_hdr[1]
    pt.align = 'l'
    pt.padding_width = 0
    if ccs is None:
        ccs = connection.get_all_cluster_controller_services()
    if not isinstance(ccs, list):
        ccs = [ccs]
    for cc in ccs:
        if cc.state == 'ENABLED':
            state = markup(cc.state, [1, 92])
        else:
            state = markup(cc.state, [1, 91])
        pt.add_row([markup(cc.hostname, [1, 94]), cc.name, cc.partition, state])
    if print_table:
        print_method('\n' + pt.get_string(sortby=cluster_hdr[0]) + '\n')
    else:
        return pt


class EucaClusterControllerService(EucaComponentService):

    def update(self, new_service=None, get_instances=True, silent=True):
        return self._update(get_method=self.connection.get_cluster_controller_service,
                            get_method_kwargs=None, new_service=new_service, silent=silent)

    def show(self):
        return SHOW_CLUSTER_CONTROLLER_SERVICES(self.connection, self)

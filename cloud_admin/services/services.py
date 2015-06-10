
from boto.resultset import ResultSet
from cloud_admin.services import EucaBaseObj, EucaEmpyreanResponse
from cloud_utils.log_utils import markup, get_traceback
from cloud_utils.net_utils.sshconnection import get_ipv4_lookup
from prettytable import PrettyTable, ALL
from operator import itemgetter
from urlparse import urlparse
import copy
import inspect
import re
import sys
import time


def SHOW_SERVICES(connection, services=None, service_type=None, show_part=False, grid=False,
                  partition=None, print_table=True, print_method=None, do_html=False):
    """
     Displays a table summarizing Eucalyptus services
    :param connection: EucaAdmin() query connection
    :param services: list of EucaService objects
    :param service_type: string, eucalyptus service type (ie: 'user-api')
    :param show_part: bool, if true will show all partitions, if false will only show
                      partitions which are otherwise referred to as  'clusters' or 'zones'
    :param grid: bool, if true will produce grid lines in the table
    :param partition: bool, if true will filter services belonging to this partition
    :param print_table: bool, if True will write the table using connection.debug_method,
                        if False will return the table obj w/o printing it
    :param do_html: If True will produce an html table instead of an ascii table
    :raise ValueError:
    """
    html_open = "###html_open###"
    html_close = "###html_close###"
    print_method = print_method or connection._show_method

    def n_markup(*args, **kwargs):
        kwargs['do_html'] = do_html
        kwargs['html_open'] = html_open
        kwargs['html_close'] = html_close
        return markup(*args, **kwargs)

    h_marks = [1, 94]
    cluster_hdr = n_markup('CLUSTER', h_marks)
    name_hdr = n_markup('NAME', h_marks)
    type_hdr = n_markup('TYPE', h_marks)
    state_hdr = n_markup('STATE', h_marks)
    uri_hdr = n_markup('URI', h_marks)
    part_hdr = n_markup('PARTITION', h_marks)
    pt = PrettyTable([type_hdr, name_hdr, state_hdr, cluster_hdr, uri_hdr, part_hdr])
    pt.max_width[uri_hdr] = 64
    pt.align = 'l'
    pt.align[cluster_hdr] = 'c'
    pt.padding_width = 0
    if grid:
        pt.hrules = ALL
    service_types = []
    all_service_types = []
    if services:
        if not isinstance(services, list):
            services = [services]
    else:
        all_service_types = connection.get_service_types()
    if not service_type and not partition:
        service_types = all_service_types
    else:
        if service_type:
            if isinstance(service_type, EucaServiceType):
                service_types = [service_type]
            elif isinstance(service_type, basestring):
                found_type = None
                for s_type in all_service_types:
                    if s_type.name == service_type:
                        found_type = s_type
                        break
                if found_type:
                    service_types = [found_type]
            if not service_types:
                raise ValueError('show_services, unknown type provided for '
                                 'service_type: "{0}"({1})'
                                 .format(service_type, type(service_type)))
        else:
            service_types = all_service_types
        if partition:
            if partition in connection.get_all_cluster_names():
                new_list = []
                for s_type in service_types:
                    if str(s_type.partitioned).lower().strip() == "true":
                        new_list.append(s_type)
                service_types = new_list
                if not service_types:
                    raise ValueError('No partitioned services found using filter service_type:'
                                     '"{0}"'.format(service_type))
            else:
                # If this is filtering a partition that is not a zone/cluster than
                # dont show unregistered service types. As of 4/30/15 the API does not
                # allow for it.
                service_types = []
    services = services or connection.get_services(service_type=service_type, partition=partition)
    clusters = connection.get_all_cluster_names()
    for service in services:
        markups = []
        partition = ""
        for cluster_name in clusters:
            if service.partition == cluster_name:
                partition = service.partition
        for stype in service_types:
            if stype.name == service.type:
                service_types.remove(stype)
                break
        state = service.localstate
        if (service.partition == 'eucalyptus' and service.type != 'eucalyptus') \
                or service.partition == 'bootstrap':
            markups = [1, 2]
        if state != "ENABLED":
            markups = [1, 4, 31]
        else:
            state = n_markup(state, [1, 92])
        pt.add_row([n_markup(service.type, (markups or [1])), n_markup(service.name, markups),
                    n_markup(state, markups), n_markup(partition, markups),
                    n_markup(service.uri, markups), n_markup(service.partition, markups)])
    for stype in service_types:
        pt.add_row([n_markup(stype.name, [2, 31]), n_markup('NOT REGISTERED?', [2, 31]),
                    n_markup('MISSING', [2, 31]), n_markup('--', [2, 31]),
                    n_markup('SERVICE NOT REGISTERED', [2, 31]), n_markup('--', [2, 31])])
    if show_part:
        fields = pt.field_names
    else:
        fields = pt.field_names[:-1]
    if print_table:
        if do_html:
            html_string = pt.get_html_string(sortby=part_hdr, fields=fields,
                                             sort_key=itemgetter(3, 2), reversesort=True,
                                             format=True, hrules=1)
            html_string = html_string.replace(html_open, "<")
            html_string = html_string.replace(html_close, ">")
            print_method(html_string)
        else:
            print_method("\n" + pt.get_string(sortby=part_hdr,
                                              fields=fields,
                                              sort_key=itemgetter(3, 2),
                                              reversesort=True))
    else:
        return pt


def SHOW_SERVICE_TYPES(connection, service_types=None, verbose=False,
                       printmethod=None, do_html=False, print_table=True):
    """
    Produces a table summarizing the Eucalyptus Service Types
    :param connection: EucaAdmin() connection obj
    :param service_types: a list of service types to query, if None will fetch all service types
    :param verbose: show debug info while producing this table
    :param printmethod: Use this method to print the table, otherwise will
                        use connection.debug_method()
    :param print_table: bool, if True will attempt to print the table, else will return the
                        table obj
    """
    html_open = "###html_open###"
    html_close = "###html_close###"
    printmethod = printmethod or connection._show_method

    def n_markup(*args, **kwargs):
        kwargs['do_html'] = do_html
        kwargs['html_open'] = html_open
        kwargs['html_close'] = html_close
        return markup(*args, **kwargs)

    cluster_len = 7
    parent_len = 18
    name_len = 18
    public_len = 6
    desc_len = 60
    cluster_hdr = n_markup(str('CLUSTER').center(cluster_len))
    parent_hdr = n_markup(str('PARENT').center(parent_len))
    name_hdr = n_markup(str('NAME').ljust(name_len))
    public_hdr = n_markup(str('PUBLIC').ljust(public_len))
    desc_hdr = n_markup(str('DESCRIPTION').ljust(desc_len))
    main_pt = PrettyTable([name_hdr, cluster_hdr, parent_hdr, public_hdr, desc_hdr])
    # main_pt.hrules = ALL
    main_pt.max_width[cluster_hdr] = cluster_len
    main_pt.max_width[public_hdr] = parent_len
    main_pt.max_width[name_hdr] = name_len
    main_pt.max_width[public_hdr] = public_len
    main_pt.max_width[desc_hdr] = desc_len
    main_pt.align = 'l'
    main_pt.align[cluster_hdr] = 'c'
    main_pt.align[parent_hdr] = 'c'
    main_pt.padding_width = 0
    if not service_types:
        service_types = connection.get_service_types()
        if not service_types:
            connection.err_method('{0}\nNo Service types returned'.format(get_traceback()))
            return None
        service_types = _sort_service_types(service_types)
    if not isinstance(service_types, list):
        service_types = [service_types]
    for service in service_types:
        if not isinstance(service, EucaServiceType):
            raise ValueError('Service not of EucaServiceType: {0}:{1}'.format(service,
                                                                              type(service)))
    if verbose:
        return connection.show_service_types_verbose(service_types=service_types,
                                                     printmethod=printmethod,
                                                     print_table=print_table)

    def _get_service_row(service, markup_method=None, markups=None, indent=''):
        if markup_method:
            def mm(x):
                return markup_method(x, markups)
        else:
            mm = str
        partitioned = '-'
        if str(service.partitioned).lower() == str('true'):
            partitioned = 'TRUE'
        cluster = mm(partitioned)
        entry = '-'
        if service.entry is None:
            if service.groupmembers:
                entry = '*'.center(parent_len)
        else:
            entry = service.entry
        parent = mm(entry)
        name = mm(indent + str(service.name))
        public = mm(service.publicapiservice)
        description = mm(service.description)
        row = [name, cluster, parent, public, description]
        return row

    for service in service_types:
        if service.groupmembers:
            # Highlight the parent service type/class
            main_pt.add_row(_get_service_row(service, markup_method=n_markup, markups=[1, 94]))
            # If this list has been sorted, the members have been converted to EucaServiceType
            # and moved here. They should be printed here under the parent, otherwise these
            # are just strings and the member service types will be printed in the main table
            for member in service.groupmembers:
                if isinstance(member, EucaServiceType):
                    main_pt.add_row(_get_service_row(member, indent='  '))
        else:
            main_pt.add_row(_get_service_row(service, markup_method=n_markup, markups=[1, 94]))

    html_string = None
    if do_html:
        html_string = main_pt.get_html_string(format=True, hrules=1)
        html_string = html_string.replace(html_open, "<")
        html_string = html_string.replace(html_close, ">")
    if print_table:
        out = html_string or str(main_pt)
        printmethod("\n{0}\n".format(out))
    else:
        return html_string or main_pt


def _sort_service_types(service_types):
    """
    Convenience Method for sorting lists of servie_types
    :param service_types: list of EucaService Type objs
    :return:
    """
    partitioned = []
    cloud = copy.copy(service_types)
    for service in service_types:
        if service.groupmembers:
            new_member_list = []
            for group_member in service.groupmembers:
                if group_member:
                    for member_service in service_types:
                        if str(member_service.name) == str(group_member.name):
                            # replace the service group member obj with the service obj
                            new_member_list.append(member_service)
                            # now remove the service obj from the main list
                            if member_service in cloud:
                                cloud.remove(member_service)
            service.groupmembers = new_member_list
        if str(service.partitioned).lower() == 'true':
            partitioned.append(service)
            if service in cloud:
                cloud.remove(service)
    return cloud + partitioned


def SHOW_SERVICE_TYPES_VERBOSE(connection, service_types=None, printmethod=None, print_table=True):
    """
    Prints a table summarizing Eucalyptus Service type objs.
    This table shows additional information to SHOW_SERVICE_TYPES(), which shows info most often
    relevant to an administrator. This table is produced without the additional
    formatting and sorting.
    :param connection: EucaAdmin connection
    :param service_types: EucaServiceType objs
    :param printmethod: Method used to print this table, default is connection.default_method()
    :param print_table: bool, if True will print table, if False will return table obj
    :return: see print_table param.
    """
    printmethod = printmethod or connection._show_method
    service_types = service_types or connection.get_service_types()
    if not isinstance(service_types, list):
        service_types = [service_types]
    for service in service_types:
        if not isinstance(service, EucaServiceType):
            raise ValueError('Service not of EucaServiceType: {0}:{1}'.format(service,
                                                                              type(service)))
    parent_hdr = str('PARENT').ljust(16)
    name_hdr = str('NAME').ljust(16)
    main_pt = PrettyTable([name_hdr, parent_hdr, 'CREDS', 'PART', 'PUBLIC', 'REG', 'NAME_REQ',
                           'DESCRIPTION'])
    main_pt.align = 'l'
    main_pt.padding_width = 0
    for service in service_types:
        main_pt.add_row([service.name, service.entry, service.hascredentials,
                         service.partitioned, service.publicapiservice, service.registerable,
                         service.requiresname, service.description])
    if print_table:
        printmethod("\n{0}\n".format(main_pt.get_string(sortby=parent_hdr)))
    else:
        return main_pt


def SHOW_COMPONENTS(connection, components=None, get_method=None, print_method=None,
                    print_table=True):
    """
    Base method for summarizing Eucalyptus components in a table format

    :param connection: EucaAdmin connection
    :param components: EucaServiceComponent objs
    :param get_method: method used to retrieve a list of components to summarize
                      (ie get_all_cluster_controller_services)
    :param print_table: bool, if True will attempt to print the table to connection.debug_method,
                        if False will return the table obj
    """
    print_method = print_method or connection._show_method
    if not components:
        if not get_method:
            raise ValueError('_show_component(). Components or get_method must be populated')
        components = get_method()
    if not isinstance(components, list):
        components = [components]
    hostname_hdr = ('HOSTNAME', 24)
    name_hdr = ('NAME', 50)
    cluster_hdr = ('PARTITION', 24)
    state_hdr = ('STATE', 16)
    type_hdr = ('TYPE', 16)
    pt = PrettyTable([hostname_hdr[0], name_hdr[0], cluster_hdr[0], state_hdr[0], type_hdr[0]])
    pt.max_width[hostname_hdr[0]] = hostname_hdr[1]
    pt.max_width[name_hdr[0]] = name_hdr[1]
    pt.max_width[cluster_hdr[0]] = cluster_hdr[1]
    pt.max_width[state_hdr[0]] = state_hdr[1]
    pt.max_width[type_hdr[0]] = type_hdr[1]
    pt.align = 'l'
    pt.padding_width = 0
    for component in components:
        if component.state == 'ENABLED':
            state = markup(component.state, [1, 92])
        else:
            state = markup(component.state, [1, 91])
        pt.add_row([markup(component.hostname, [1, 94]), component.name,
                    component.partition, state, component.type])
    if print_table:
        print_method('\n' + pt.get_string(sortby=cluster_hdr[0]) + '\n')
    else:
        return pt


class EucaService(EucaBaseObj):
    """
    Base Class for Eucalyptus Service Objects
    """
    def __init__(self, connection=None):
        self._host = None
        self._hostname = None
        self._ip_addr = None
        self._localstate = None
        self._service_code = None
        self._state = None
        self.message = None
        self.name = None
        self.partition = None
        self.type = None
        self.uri = None
        self.uris = []
        self.child_services = []
        super(EucaService, self).__init__(connection)

    @property
    def service_code(self):
        '''
        The classes extending this should replace this method with a known service
        code abbreviation
        '''
        if self._service_code:
            return self._service_code
        else:
            if self.connection.is_user_api_member(self.type):
                scode = 'UFS'
            elif self.type == 'cluster':
                scode = 'CC'
            elif self.type == 'eucalyptus' or self.partition in ['eucalyptus', 'bootstrap']:
                scode = 'CLC'
            elif self.type == 'storage':
                scode = 'SC'
            elif self.type == 'node':
                scode = 'NC'
            elif self.type == 'walrusbackend':
                scode = 'WS'
            else:
                scode = self.type
            return scode

    @property
    def ip_addr(self):
        """
        Not all service types return a hostname in the response,
        and mixed use of FQDN vs IP...
        """
        if not self._ip_addr:
            return self._update_ip_addr()
        return self._ip_addr

    @property
    def state(self):
        return self._state or self._localstate

    @state.setter
    def state(self, value):
        self._state = value

    @property
    def hostname(self):
        if self._hostname:
            return self._hostname
        if self._host:
            return self._host
        if self.uri:
            urlp = urlparse(self.uri)
            hostname = getattr(urlp, 'hostname', None)
            if hostname:
                return hostname
        return None

    @hostname.setter
    def hostname(self, value):
        self._hostname = value
        self._update_ip_addr()

    @property
    def host(self):
        if self._host:
            return self._host
        if self._hostname:
            return self._hostname
        return None

    @host.setter
    def host(self, value):
        self._host = value

    @property
    def localstate(self):
        return self._localstate or self._state

    @localstate.setter
    def localstate(self, value):
        self._localstate = value

    def debug_method(self, *args, **kwargs):
        return self.connection.debug_method(*args, **kwargs)

    def err_method(self, *args, **kwargs):
        return self.connection.err_method(*args, **kwargs)

    def isEnabled(self):
        return 'ENABLED' == self.state

    def disable(self):
        return self.modify_service_state(self, 'DISABLE')

    def enable(self):
        return self.modify_service_state(self, 'ENABLE')

    def get_linux_service_name(self):
        '''
        Return the name of the linux process for this service type
        '''
        if self.type == 'cluster':
            return 'eucalyptus-cc'
        elif self.type == 'node':
            return 'eucalyptus-nc'
        elif self.type == 'eucanetd':
            return 'eucanetd'
        else:
            return 'eucalyptus-cloud'

    def getAllServicePeers(self):
        '''
        Returns all services of this type, in this partition
        for active-active services this could be a list, for non-active-active this
        will likely be a single service obj
        '''
        if not self.type or self.partition:
            raise ValueError('({0}). Can not request active active peers w/o both '
                             'type:("{0}") and partition populated:("{1}")'
                             .format(self.name, self.type, self.partition))
        return self.connection.get_services(service_type=self.type, partition=self.partition)

    def isActiveActive(self):
        '''
        Returns true if there are other registered services of this type in the same
        partition
        '''
        if len(self.getAllServicePeers()) > 1:
            return True
        else:
            return False

    def update(self, new_service=None, silent=True):
        """
        Updates this service obj
        :params silent: bool, if True will not raise Exceptions found during lookup, will instead
                        write errors to self.connection.err_method()
        :returns : self upon successful update, otherwise returns None
        """
        errmsg = ""
        if not new_service:
            if not self.name:
                raise ValueError('Must set "name" before using update(). Name:{0}'
                                 .format(self.name))
            try:
                new_service = self.connection.get_services(service_names=self.name)[0]
            except Exception as LE:
                if silent:
                    errmsg = "{0}\n{1}\n".format(get_traceback(), str(LE))
                    self.connection.err_method('{0}Update failed. Service: {1} not found'
                                               .format(errmsg, self.name))
                    return None
                else:
                    raise
        if not isinstance(new_service, EucaService):
            raise ValueError('"{0}" update error. Non EucaService type for new_prop. Found: '
                             '"{1}/{2}"'.format(self.name, new_service, type(new_service)))
        if new_service:
            self.__dict__.update(new_service.__dict__)
            return self

    def _update_ip_addr(self):
        if self.hostname:
            ips = get_ipv4_lookup(hostname=self.hostname,
                                  port=22,
                                  debug_method=self.debug_method,
                                  verbose=False)
            if ips:
                self._ip_addr = ips[0]
        return self._ip_addr

    def show(self):
        return SHOW_SERVICES(self.connection, services=self)

    def modify_service_state(self, state):
        """
        Modifies service state and updates self with response data
        """
        new_service = self.connection.modify_service(service=self, state=state)
        if new_service:
            self.update(new_service)
        return self

    def startElement(self, name, value, connection):
        ename = name.replace('euca:', '')
        elem = super(EucaService, self).startElement(name, value, connection)
        if elem is not None:
            return elem
        if ename == 'uris':
            self.uris = EucaUris(connection=connection)
            return self.uris

    def endElement(self, name, value, connection):
        ename = name.replace('euca:', '')
        if ename:
            if ename == 'entry':
                self.uris.append(value)
            if ename == '_name':
                if not hasattr(self, 'name') or not self.name:
                    setattr(self, 'name', value)
                setattr(self, ename.lower(), value)
            super(EucaService, self).endElement(name, value, connection)

    def _find_service_class(self, service_name):
        service_name = "euca{0}service".format(str(service_name)).lower()
        for name, service_class in inspect.getmembers(sys.modules[self.__module__],
                                                      inspect.isclass):
            name = name.lower()
            print 'checking service name:{0} against class:{1}'.format(service_name, name)
            if name == service_name:
                print 'got a match!!!'
                return service_class
        return None


class EucaServiceType(EucaBaseObj):
    def __init__(self, connection=None):
        super(EucaServiceType, self).__init__(connection)
        self.groupmembers = []
        self._name = None
        self._componentname = None
        self.description = None
        self.entry = None

    @property
    def name(self):
        if not self._name:
            self._name = getattr(self, 'componentname', None)
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def componentname(self):
        return self._componentname

    @componentname.setter
    def componentname(self, value):
        self._name = value
        self._componentname = value

    def startElement(self, name, value, connection):
        ename = name.replace('euca:', '')
        if ename == 'serviceGroupMembers':
            groupmembers = ResultSet([('item', EucaSeviceGroupMember),
                                      ('euca:item', EucaSeviceGroupMember)])
            self.groupmembers = groupmembers
            return groupmembers
        else:
            return None

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            # print 'service type got ename:{0}'.format(ename)
            if ename == 'componentname':
                self.name = value
            setattr(self, ename.lower(), value)


class EucaSeviceGroupMember(EucaBaseObj):
    '''
    Used for parsing child service types from parent service types
    '''

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            if ename == 'entry':
                self.name = value
            setattr(self, ename.lower(), value)


class EucaServiceGroupMembers(ResultSet):
    '''
    Used to parse and hold a list of child service types under a parent service type
    '''

    def __init__(self, connection=None):
        super(EucaServiceGroupMembers, self).__init__(connection)
        self.markers = [('item', EucaSeviceGroupMember)]

    def __repr__(self):
        return str(self.__class__.__name__) + ":(Count:" + str(len(self)) + ")"

    def startElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename == 'item':
            new_member = EucaSeviceGroupMember(connection=connection)
            self.append(new_member)
            return new_member
        else:
            return None

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            setattr(self, ename.lower(), value)


class EucaServiceRegResponse(EucaEmpyreanResponse):
    """
    Used to handle responses for administrative service requests.
    """

    def __init__(self, connection=None):
        services = []
        super(EucaServiceRegResponse, self).__init__(connection)

    def startElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename == 'registeredservices':
            self.services = EucaServiceList(connection=connection)
            return self.services
        if ename == 'deregisteredservices':
            self.services = EucaServiceList(connection=connection)
            return self.services
        else:
            return super(EucaServiceRegResponse, self).startElement(ename, value, connection)


class EucaServiceList(ResultSet):
    '''
    Result set used to parse a service response into EucaServices
    '''
    def __init__(self, connection=None):
        super(EucaServiceList, self).__init__(connection)
        self.last_updated = time.time()
        self.elems = []

    def __repr__(self):
        return str(self.__class__.__name__) + ":(Count:" + str(len(self)) + ")"

    def startElement(self, name, value, connection):
        self.elems.append(value.copy())
        ename = name.replace('euca:', '')
        if ename == 'item':
            new_service = EucaService(connection=connection)
            self.append(new_service)
            return new_service
        else:
            return None

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            setattr(self, ename.lower(), value)

    def show_list(self, print_method=None):
        for service in self:
            if print_method:
                print_method("{0}:{1}".format(service.type, service.name))
            else:
                print "{0}:{1}".format(service.type, service.name)


class EucaUris(EucaBaseObj):
    """
    Used to parse service URI objects
    """

    def __init__(self, connection=None):
        super(EucaUris, self).__init__(connection)
        self.uris = []

    def startElement(self, name, value, connection):
        elem = super(EucaUris, self).startElement(name, value, connection)
        if elem is not None:
            return elem

    def endElement(self, name, value, connection):
        ename = name.replace('euca:', '')
        if ename:
            if ename == 'entry':
                self.uris.append(value)
            else:
                setattr(self, ename.lower(), value)


class EucaComponentService(EucaService):
    """
    Used to parse Eucalyptus Components per service responses
    (services vs components, confusing? ... yes)
    """

    def _update(self, get_method, get_method_kwargs=None, new_service=None, silent=True):
        """
        Base update method for updating component service objs
        :param get_method_name: method name used to fetch the service for update. This method
                                must be part of self.connection under the admin class
        :param get_method_kwargs: dict of kwargs used when calling the 'get_method_name' to
                                  fetch the updated service obj.
        :params new_service: a service object to be used to update self from.
        :params silent: bool, if True will not raise Exceptions found during lookup, will instead
                        write errors to self.connection.err_method()
        :returns : self upon successful update, otherwise returns None
        """
        errmsg = ""
        if not new_service:
            # If kwargs was left as None, update it with at least self.name...
            if get_method_kwargs is None:
                name = self.name
                if not name:
                    raise ValueError('Must set "name" before using update(). '
                                     'Name:{0}, FullName:{1}'.format(name))
            get_method_kwargs = {'name': self.name}
            try:
                new_service = get_method(**get_method_kwargs)
            except Exception as LE:
                if silent:
                    errmsg = "{0}\n{1}\n".format(get_traceback(), str(LE))
                    self.connection.err_method('{0}Update failed. Node Controller: {1} not found'
                                               .format(errmsg, self.name))
                    return None
                else:
                    raise
        if not isinstance(new_service, self.__class__):
            raise ValueError('"{0}" update error. Non {1} type for new_service. '
                             'Found: "{2}/{3}"'.format(self.name,
                                                       self.__class__.__name__,
                                                       new_service,
                                                       type(new_service)))
        if new_service:
            self.__dict__.update(new_service.__dict__)
            return self

    def show(self, print_table=True):
        """
        Base show method. Will attempt to print a table representing the summary of this
        component.
        :params print_table: bool, if True will attempt to print to connection.debug_method()
                             if False will return the table object w/o printing.
        """
        return SHOW_COMPONENTS(self.connection, components=self, print_table=print_table)

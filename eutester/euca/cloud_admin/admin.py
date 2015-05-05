__author__ = 'clarkmatthew'


import boto
from boto.vpc import VPCConnection
from boto.roboto.awsqueryservice import AWSQueryService
from boto.roboto.awsqueryrequest import AWSQueryRequest
from boto.roboto.param import Param
from boto.resultset import ResultSet
from boto.connection import AWSQueryConnection
from boto.ec2.regioninfo import RegionInfo
from boto.exception import BotoServerError
from eutester.euca.cloud_admin.services import EucaService, EucaServiceType, EucaServiceList,\
    EucaCloudControllerService, EucaObjectStorageGatewayService, EucaClusterControllerService,\
    EucaSeviceGroupMember, EucaStorageControllerService, EucaWalrusBackendService,\
    EucaVMwareBrokerService, EucaArbitratorService
from eutester.euca.cloud_admin.nodecontroller import EucaNodeService
from eutester.euca.cloud_admin.properties import EucaProperty
from eutester.utils.log_utils import markup
from operator import itemgetter
from prettytable import PrettyTable, ALL
from urlparse import urlparse
import copy
import re

class EucaAdmin(AWSQueryConnection):
    APIVersion='eucalyptus'

    def __init__(self,
                 path = '/services/Empyrean',
                 port = 8773,
                 aws_access_key_id=None,
                 aws_secret_access_key=None,
                 is_secure = False,
                 tester=None,
                 host=None,
                 debug_method = None,
                 **kwargs):
        self.tester = tester
        if debug_method:
            self.debug_method = debug_method
        elif self.tester:
            self.debug_method = self.tester.debug
        if not host and tester:
            host = tester.get_ec2_ip()
        self.host = host
        if not aws_access_key_id and tester:
            aws_access_key_id = tester.aws_access_key_id
        aws_access_key_id = aws_access_key_id
        if not aws_secret_access_key and tester:
            aws_secret_access_key = tester.aws_secret_access_key
        aws_secret_access_key = aws_secret_access_key
        if not self.host or not aws_access_key_id or not aws_secret_access_key:
            raise ValueError('Missing required arg. host:"{0}", aws_access_key_id:"{1}", '
                             'aws_secret_access_key:"{2}"'.format(host,
                                                                  aws_access_key_id,
                                                                  aws_secret_access_key))
        self.is_secure = is_secure
        self.port = port
        self.path = path
        super(EucaAdmin, self).__init__(path = self.path,
                                             aws_access_key_id = aws_access_key_id,
                                             aws_secret_access_key = aws_secret_access_key,
                                             port =self.port,
                                             is_secure = self.is_secure,
                                             host = self.host)
        if tester:
            self._ec2_connection = tester.ec2.connection
        else:
            self._ec2_connection = None

    def debug_method(self, msg):
        print msg

    @property
    def ec2_connection(self):
        if not self._ec2_connection:
            self._ec2_connection = self._get_ec2_connection()
        return self._ec2_connection

    def _get_ec2_connection(self, endpoint=None, access_key=None, secret_key=None,
                            port=8773, APIVersion='2012-07-20', path='services/compute',
                            is_secure=False, debug_level=0, **kwargs):
        ec2_region = RegionInfo()
        ec2_region.name = 'eucalyptus'
        host = endpoint or self.host
        ec2_region.endpoint = host
        access_key = access_key or self.aws_access_key_id
        secret_key = secret_key or self. aws_secret_access_key
        connection_args = { 'aws_access_key_id' : access_key,
                            'aws_secret_access_key': secret_key,
                            'is_secure': is_secure,
                            'debug': debug_level,
                            'port' : port,
                            'path' : path,
                            'host' : host}
        if re.search('2.6', boto.__version__):
            connection_args['validate_certs'] = False
        ec2_connection_args = copy.copy(connection_args)
        ec2_connection_args['path'] = path
        ec2_connection_args['api_version'] = APIVersion
        ec2_connection_args['region'] = ec2_region
        for key in kwargs:
            ec2_connection_args[key] = kwargs[key]
        try:
            connection = VPCConnection(**ec2_connection_args)
        except Exception, e:
            buf = ""
            for key, value in connection_args.iteritems():
                buf += "\t{0} = {1}\n".format(key, value)
            print ('Error in ec2 connection attempt while using args:\n{0}'.format(buf))
            raise e
        return connection

    def _get_list_request(self, action='DescribeEucalyptus', service=EucaService, params={},
                          markers=['item', 'euca:item'], verb='GET'):
        params = params
        new_markers=[]
        for marker in markers:
            new_markers.append((marker, service))
        return self.get_list(action, params, new_markers, verb=verb)

    def get_service_types(self, name=None):
        service_types = self._get_list_request('DescribeAvailableServiceTypes', EucaServiceType)
        if name:
            for service_type in service_types:
                if service_type.name == name:
                    new_list = ResultSet()
                    new_list.append(service_type)
                    return new_list
        return service_types

    def show_service_types_verbose(self, service_types=None, printmethod=None, print_table=True):
        service_types = service_types or self.get_service_types()
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
            if printmethod:
                printmethod(main_pt.get_string(sortby=parent_hdr))
            else:
                self.debug_method(main_pt.get_string(sortby=parent_hdr))
        else:
            return main_pt

    def show_service_types(self, service_types=None, verbose=False,
                           printmethod=None, print_table=True):
        cluster_len = 7
        parent_len = 18
        name_len=18
        public_len=6
        desc_len=60
        cluster_hdr = markup(str('CLUSTER').center(cluster_len))
        parent_hdr = markup(str('PARENT').center(parent_len))
        name_hdr = markup(str('NAME').ljust(name_len))
        public_hdr = markup(str('PUBLIC').ljust(public_len))
        desc_hdr = markup(str('DESCRIPTION').ljust(desc_len))
        main_pt = PrettyTable([name_hdr, cluster_hdr,parent_hdr, public_hdr, desc_hdr])
        #main_pt.hrules = ALL
        main_pt.max_width[cluster_hdr] = cluster_len
        main_pt.max_width[public_hdr] = parent_len
        main_pt.max_width[name_hdr] = name_len
        main_pt.max_width[public_hdr] = public_len
        main_pt.max_width[desc_hdr] = desc_len
        main_pt.align = 'l'
        main_pt.align[cluster_hdr] = 'c'
        main_pt.align[parent_hdr] = 'c'
        main_pt.padding_width = 0
        service_types = service_types or self._sort_service_types()
        if not isinstance(service_types, list):
            service_types = [service_types]
        for service in service_types:
            if not isinstance(service, EucaServiceType):
                raise ValueError('Service not of EucaServiceType: {0}:{1}'.format(service,
                                                                                  type(service)))
        if verbose:
            return self.show_service_types_verbose(service_types=service_types,
                                                   printmethod=printmethod,
                                                   print_table=print_table)
        def get_service_row(service, markup_method=None, markups=None, indent=''):
            if markup_method:
                mm = lambda x: markup(x, markups)
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
                main_pt.add_row(get_service_row(service, markup_method=markup, markups=[1,94]))
                # If this list has been sorted, the members have been converted to EucaServiceType
                # and moved here. They should be printed here under the parent, otherwise these
                # are just strings and the member service types will be printed in the main table
                for member in service.groupmembers:
                    if isinstance(member, EucaServiceType):
                        main_pt.add_row(get_service_row(member, indent='  '))
            else:
                main_pt.add_row(get_service_row(service, markup_method=markup, markups=[1,94]))
        if print_table:
            if printmethod:
                printmethod(str(main_pt))
            else:
                self.debug_method(str(main_pt))
        else:
            return main_pt

    def _sort_service_types(self, service_types=None):
        service_types = service_types or self.get_service_types()
        partitioned = []
        cloud = copy.copy(service_types)
        for service in service_types:
            if service.groupmembers:
                new_member_list = []
                for group_member in service.groupmembers:
                    if group_member:
                        for member_service in service_types:
                            if str(member_service.name) == str(group_member.name):
                                #replace the service group member obj with the service obj
                                new_member_list.append(member_service)
                                #now remove the service obj from the main list
                                if member_service in cloud:
                                    cloud.remove(member_service)
                service.groupmembers = new_member_list
            if str(service.partitioned).lower() == 'true':
                partitioned.append(service)
                if service in cloud:
                    cloud.remove(service)
        return cloud + partitioned

    def get_services(self, service_type=None, show_event_stacks=None, show_events=None,
                     list_user_services=None, listall=None, list_internal=None,
                     markers = None, partition=None, service_class=EucaServiceList):
        if markers is None:
            markers = [('euca:serviceStatuses', service_class)]
        params = {}
        if service_type:
            assert isinstance(service_type, basestring)
            params['ByServiceType'] = str(service_type)
        if show_event_stacks:
            assert isinstance(show_event_stacks, bool)
            params['ShowEventStacks'] = str(show_event_stacks).lower()
        if show_events:
            assert isinstance(show_events, bool)
            params['ShowEvents'] = str(show_events).lower()
        if list_user_services:
            assert isinstance(list_user_services, bool)
            params['ListUserServices'] = str(list_user_services).lower()
        if listall:
            assert isinstance(listall, bool)
            params['ListAll'] = str(listall).lower()
        if list_internal:
            assert isinstance(list_internal, bool)
            params['ListInternal'] = str(list_internal).lower()

        service_list = self.get_list('DescribeServices',
                                        params,
                                        markers=markers,
                                        verb='GET')
        if service_list:
            service_list =  service_list[0] or []
            if partition:
                newlist = copy.copy(service_list)
                for service in service_list:
                    if service.partition != partition:
                        newlist.remove(service)
                return newlist
        return service_list


    def show_services(self, services=None, service_type=None, show_part=False, grid=False,
                      partition=None, print_table=True, do_html=False):
        html_open = "[+html_open+]"
        html_close ="[+html_close+]"
        def n_markup(*args, **kwargs):
            kwargs['do_html'] = do_html
            kwargs['html_open'] = html_open
            kwargs['html_close'] = html_close
            return markup(*args, **kwargs)
        h_marks = [1, 94]
        cluster_hdr = n_markup('CLUSTER', h_marks)
        name_hdr =  n_markup('NAME', h_marks)
        type_hdr = n_markup('TYPE', h_marks)
        state_hdr = n_markup('STATE', h_marks)
        uri_hdr = n_markup('URI', h_marks)
        part_hdr = n_markup('PARTITION', h_marks)
        pt = PrettyTable([type_hdr, name_hdr, state_hdr, cluster_hdr, uri_hdr, part_hdr])
        pt.align = 'l'
        pt.align[cluster_hdr] = 'c'
        pt.padding_width = 0
        if grid:
            pt.hrules = ALL
        service_types = []
        all_service_types = self.get_service_types()
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
                if partition in self.get_cluster_names():
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
        services = services or self.get_services(service_type=service_type, partition=partition)
        clusters = self.get_cluster_names()
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
                markups = [1,2]
            if state != "ENABLED":
                markups = [1,4,31]
            else:
                state = n_markup(state, [1,92])
            pt.add_row([n_markup(service.type, (markups or [1])), n_markup(service.name, markups),
                        n_markup(state, markups), n_markup(partition, markups),
                        n_markup(service.uri, markups), n_markup(service.partition, markups)])
        for stype in service_types:
            pt.add_row([n_markup(stype.name, [2,31]), n_markup('NOT REGISTERED?', [2,31]),
                        n_markup('MISSING', [2,31]), n_markup('--', [2,31]),
                        n_markup('SERVICE NOT REGISTERED', [2,31]), n_markup('--', [2,31])])
        if show_part:
            fields = pt.field_names
        else:
            fields = pt.field_names[:-1]
        if print_table:
            if do_html:
                html_string = pt.get_html_string(sortby=part_hdr, fields=fields,
                                                 sort_key=itemgetter(3,2), reversesort=True,
                                                 format=True, hrules=1)
                html_string = html_string.replace(html_open, "<")
                html_string = html_string.replace(html_close, ">")
                self.debug_method(html_string)
            else:
                self.debug_method(pt.get_string(sortby=part_hdr, fields=fields,
                                                sort_key=itemgetter(3,2), reversesort=True))
        else:
            return pt

    def get_cloud_controller_services(self):
        return self._get_list_request('DescribeEucalyptus', EucaCloudControllerService)

    def get_cluster_controller_services(self):
        return self._get_list_request('DescribeClusters', EucaClusterControllerService)

    def get_object_storage_gateways(self):
        return self._get_list_request('DescribeObjectStorageGateways',
                                      EucaObjectStorageGatewayService)

    def get_storage_controllers(self):
        return self._get_list_request('DescribeStorageControllers',EucaStorageControllerService)

    def get_walrus_backends(self):
        return self._get_list_request('DescribeWalrusBackends', EucaWalrusBackendService)

    def get_vmware_broker_services(self):
        return self._get_list_request('DescribeVMwareBrokers', EucaVMwareBrokerService)

    def get_arbitrators(self):
        return self._get_list_request('DescribeArbitrators', EucaArbitratorService)

    def get_cluster_names(self):
        cluster_names = []
        ccs = self.get_cluster_controller_services()
        for cc in ccs:
            cluster_names.append(cc.partition)
        return cluster_names

    def get_nodes(self, get_instances=True, cluster=None, fail_on_instance_fetch=False):
        services = self.get_services(service_type='node', listall=True,
                                     service_class=EucaServiceList)
        nodes = []
        for service in services:
            nodes.append(EucaNodeService._from_service(service))
        remove = []
        if cluster:
            for node in nodes:
                if str(node.partition).lower() != cluster.lower():
                    remove.append(node)
            for node in remove:
                nodes.remove(node)
        if get_instances:
            try:
                for reservation in self.ec2_connection.get_all_instances(
                        filters={'tag-key':'euca:node'}):
                    for vm in reservation.instances:
                        # Should this filter exclude terminated, shutdown, and stopped instances?
                        tag_node_name = vm.tags.get('euca:node')
                        if tag_node_name:
                            for node in nodes:
                                if node.name == tag_node_name:
                                    node.instances.append(vm)
            except Exception, NE:
                self.debug_method('Failed to fetch instances for node:{0}, err:{1}'
                                  .format(node.name, str(NE)))
                if fail_on_instance_fetch:
                    raise NE
        return nodes

    def show_nodes(self, nodes=None, print_table=True):
        nodes = nodes or self.get_nodes()
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
        for node in nodes:
            instances = "".join("{0}({1},{2},{3})"
                                    .format(str(x.id).ljust(ins_id_len),
                                            str(x.state).ljust(ins_st_len),
                                            str(x.instance_type).ljust(ins_type_len),
                                            str(x.root_device_type).ljust(ins_dev_len))
                                    .ljust(inst_hdr[1])
                                 for x in node.instances)
            instances.strip()
            if node.state == 'ENABLED':
                markups = [1,92]
            else:
                markups = [1,91]
            pt.add_row([node.partition, markup(node.name),
                        markup(node.state, markups), instances])
        if print_table:
            self.debug_method('\n' + pt.get_string(sortby=zone_hdr[0]) + '\n')
        else:
            return pt


    def get_properties(self, *prop_names):
        '''
        Gets eucalyptus cloud configuration properties
        examples:
            get_properties()
            get_properties('www', 'objectstorage')
            get_properties('cloud.euca_log_level')
        :param prop_names: list or property names or the prefix to match against properties.
        :returns a list of EucaProperty objs
        '''
        params = {}
        x = 0
        prop_names = prop_names or []
        for prop in prop_names:
            if not prop:
                continue
            x += 1
            params['Property.{0}'.format(x)] = prop
        return self._get_list_request('DescribeProperties', EucaProperty, params=params)

    def show_properties(self, properties=None, description=True, grid=ALL,
                        print_table=True, *prop_names):
        name_hdr = markup('PROPERTY NAME', [1,94])
        value_hdr = markup('PROPERTY VALUE', [1,94])
        desc_hdr = markup('DESCRIPTION', [1,94])
        pt = PrettyTable([name_hdr, value_hdr])
        pt.max_width[name_hdr] = 70
        pt.max_width[value_hdr] = 40
        if description:
            pt.add_column(fieldname=desc_hdr, column=[])
            pt.max_width[desc_hdr]=40
        pt.padding_width = 0
        pt.align = 'l'
        pt.hrules = grid or 0
        properties = properties or self.get_properties(prop_names)
        if not isinstance(properties, list):
            properties = [properties]
        for prop in properties:
            if not isinstance(prop, EucaProperty) and isinstance(prop, basestring):
                props = self.get_properties(prop)
                if not props:
                    continue
            else:
                props = [prop]
            for p in props:
                row = [markup(p.name, [94]), p.value]
                if description:
                    row.append(p.description)
                pt.add_row(row)
        if not pt._rows:
            pt.add_row([markup('NO PROPERTIES RETURNED', [1,91]), ""])
        if print_table:
            self.debug_method('\n' + str(pt) + '\n')
        else:
            return pt

    def show_properties_narrow(self, properties=None, verbose=True, print_table=True, *prop_names):
        if not verbose:
            return self.show_properties(properties=properties, description=False,
                                        print_table=print_table)
        info_len = 60
        desc_len = 40
        markup_size = len(markup('\n'))
        properties = properties or self.get_properties(prop_names)
        pt = PrettyTable(['PROPERTY INFO', 'DESCRIPTION'])
        pt.max_width['PROPERTY INFO'] = info_len
        pt.max_width['DESCRIPTION'] = desc_len
        pt.align = 'l'
        pt.padding_width = 0
        pt.hrules = 1
        if not isinstance(properties, list):
            properties = [properties]
        for prop in properties:
            if not isinstance(prop, EucaProperty) and isinstance(prop, basestring):
                props = self.get_properties(prop)
                if not props:
                    continue
            else:
                props = [prop]
            for p in props:
                info_buf = "NAME: "
                prefix = ""
                line_len = info_len - markup_size - len('NAME: ')
                for i in xrange(0, len(p.name), line_len):
                    if i:
                        prefix = "      "
                    info_buf += (str(prefix +
                                     markup(p.name[i:i+line_len], [1,94])).ljust(info_len-2)
                                 + "\n")
                info_buf += 'VALUE: '
                prefix = ""
                line_len = info_len - markup_size - len('VALUE: ')
                for i in xrange(0, len(p.value), line_len):
                    if i:
                        prefix = "       "
                    info_buf += (prefix + markup(p.value[i:i+line_len]) + "\n")

                desc_buf = markup('DESCRIPTION:').ljust(desc_len) + \
                           str(p.description).ljust(desc_len)
                pt.add_row([info_buf,desc_buf])
        if not pt._rows:
            pt.add_row([markup('NO PROPERTIES RETURNED', [1,91]), ""])
        if print_table:
            self.debug_method("\n" + str(pt) + "\n")
        else:
            return pt


    def get_clusters(self, name=None, get_instances=True, get_storage=True,
                     get_cluster_controllers=True):
        controllers = self.get_cluster_controller_services()
        for cc in controllers:
            assert isinstance(cc, EucaClusterControllerService)
            new_cluster = cc.partition

    def show_cluster_controllers(self, ccs=None, print_table=True):
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
        ccs = ccs or self.get_cluster_controller_services()
        for cc in ccs:
            if cc.state == 'ENABLED':
                state = markup(cc.state, [1,92])
            else:
                state = markup(cc.state, [1,91])
            pt.add_row([markup(cc.hostname, [1,94]), cc.name, cc.partition, state])
        if print_table:
            self.debug_method('\n' + pt.get_string(sortby=cluster_hdr[0]) + '\n')
        else:
            return pt

    def show_storage_controllers(self, scs=None, print_table=True):
        return self._show_components(scs, self.get_storage_controllers, print_table)
    
    def show_objectstorage_gateways(self, osgs=None, print_table=True):
        return self._show_components(osgs, self.get_object_storage_gateways, print_table)

    def show_cloud_controllers(self, clcs=None, print_table=True):
        return self._show_components(clcs, self.get_cloud_controller_services, print_table)

    def show_walrus_backends(self, walruses=None, print_table=True):
        return self._show_components(walruses, self.get_walrus_backends, print_table)

    def _show_components(self, components=None,  get_method=None, print_table=True):
        if not components:
            if not get_method:
                raise ValueError('_show_component(). Components or get_method must be populated')
            components = get_method()
        hostname_hdr = ('HOSTNAME', 24)
        name_hdr = ('NAME', 24)
        cluster_hdr = ('PARTITION', 24)
        state_hdr = ('STATE', 16)
        pt = PrettyTable([hostname_hdr[0], name_hdr[0], cluster_hdr[0], state_hdr[0]])
        pt.max_width[hostname_hdr[0]] = hostname_hdr[1]
        pt.max_width[name_hdr[0]] = name_hdr[1]
        pt.max_width[cluster_hdr[0]] = cluster_hdr[1]
        pt.max_width[state_hdr[0]] = state_hdr[1]
        pt.align = 'l'
        pt.padding_width = 0
        for component in components:
            if component.state == 'ENABLED':
                state = markup(component.state, [1,92])
            else:
                state = markup(component.state, [1,91])
            pt.add_row([markup(component.hostname, [1,94]), component.name,
                        component.partition, state])
        if print_table:
            self.debug_method('\n' + pt.get_string(sortby=cluster_hdr[0]) + '\n')
        else:
            return pt

    def get_all_components(self):
        components = {}
        components['WS'] = self.get_walrus_backends()
        components['SC'] = self.get_storage_controllers()
        components['OSG'] = self.get_object_storage_gateways()
        components['CLC'] = self.get_cloud_controller_services()
        components['CC'] = self.get_cluster_controller_services()
        components['NC'] = self.get_nodes()
        return components

    def get_machine_inventory(self):
        components = self.get_all_components()
        clusters = self.get_cluster_names()
        try:
            components['vmw_list'] = self.get_vmware_broker_services()
        except BotoServerError, VMWE:
            self.debug_method('Failed to fetch vmware brokers, vmware may not be supported on '
                              'this cloud. Err:{0}'.format(VMWE.message))
        machine_list = {}
        for component_type, comp_list in components.iteritems():
            for component in comp_list:
                type_string = component_type
                self.debug_method('Inspecting component type:"{0}"'.format(component_type))
                hostname = getattr(component, 'hostname', component.name)
                if component.partition in clusters:
                    type_string = "{0}({1})".format(component_type, component.partition)
                if hostname not in machine_list:
                    machine_list[hostname]=[type_string]
                else:
                    machine_list[hostname].append(type_string)
        # Add UFS services by parsing the uri of the service,
        # since these services dont present a host attr in the response. This may be incorrect
        # if/when a FQDN is used, or an LB, etc.?
        for ufs in self.get_services(service_type='user-api'):
            if getattr(ufs, 'uri', None):
                url = urlparse(ufs.uri)
                if url.hostname:
                    if url.hostname not in machine_list:
                        machine_list[url.hostname]=['UFS']
                    else:
                        machine_list[url.hostname].append('UFS')
        return machine_list

    def wait_for_service(self, service_type, state = "ENABLED", states=None, attempt_both=True,
                         timeout=600):
        interval = 20
        poll_count = timeout / interval
        while (poll_count > 0):
            matching_services = []
            try:
                matching_services = self.get_services(service_type)
                for service in matching_services:
                    if states:
                        for state in states:
                            if re.search(state, service.state):
                                return service
                    else:
                        if re.search(state, service.state):
                            return service
            except Exception, e:
                self.debug_method('Error while fetching services:"{0}"\nRetrying in "{1}" seconds'
                                  .format(str(e), interval))
            poll_count -= 1
            self.tester.sleep(interval)
        if poll_count is 0:
            states = states or [state]
            state_info = ",".join(str(x) for x in states)
            msg = ("Service: '{0}' did not enter state(s):'{1}'"
                              .format(service.name, state_info))
            raise Exception(msg)







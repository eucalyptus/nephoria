__author__ = 'clarkmatthew'


import boto
from boto.vpc import VPCConnection
from boto.roboto.awsqueryservice import AWSQueryService
from boto.roboto.awsqueryrequest import AWSQueryRequest
from boto.roboto.param import Param
from boto.connection import AWSQueryConnection
from boto.ec2.regioninfo import RegionInfo
from eutester.euca.cloud_admin.services import EucaServiceType, EucaServiceList,\
    EucaCloudControllerService, EucaObjectStorageGatewayService, EucaClusterControllerService,\
    EucaSeviceGroupMember
from eutester.euca.cloud_admin.nodecontroller import EucaNodeService
from eutester.utils.log_utils import markup
from prettytable import PrettyTable, ALL
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

    def get_service_types(self):
        params = {}
        return self.get_list('DescribeAvailableServiceTypes',
                                   params,
                                   [('item', EucaServiceType),
                                    ('euca:item', EucaServiceType)],
                                   verb='GET')

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
        def get_service_row(service, markup_method=None, markups=None):
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
            name = mm(service.name)
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
                        main_pt.add_row(get_service_row(member))
            else:
                main_pt.add_row(get_service_row(service))
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
                     markers = None,
                     service_class=EucaServiceList):
        if markers is None:
            #markers = [('euca:serviceStatuses', service_class)]
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
            return service_list[0]
        else:
            return None

    def show_services(self, services=None, service_type=None, print_table=True):
        services = services or self.get_services(service_type=service_type)
        cluster_hdr = markup('CLUSTER')
        pt = PrettyTable([markup('TYPE'), markup('NAME'), markup('STATE'), cluster_hdr,
                          markup('URI')])
        pt.align = 'l'
        pt.align[cluster_hdr] = 'c'
        pt.padding_width = 0
        service_types = self.get_service_types()
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
            state = service.localState
            if state != "ENABLED":
                markups = [1,4,31]
            pt.add_row([markup(service.type, (markups or [1])), markup(service.name, markups),
                        markup(state, markups), markup(partition, markups),
                        markup(service.uri, markups)])
        for stype in service_types:
            pt.add_row([markup(stype.name, [1,2]), markup('??? NOT REGISTERED ???', [1,2]),
                        markup('MISSING', [1,2]), '',
                        markup('SERVICE NOT REGISTERED', [1,2])])
        if print_table:
            self.debug_method("\n" + str(pt) + "\n")
        else:
            return pt

    def get_cloud_controller_services(self):
        params = {}
        return self.get_list('DescribeEucalyptus',
                                   params,
                                   [('item', EucaCloudControllerService),
                                    ('euca:item', EucaClusterControllerService)],
                                   verb='GET')

    def get_cluster_controller_services(self):
        params = {}
        return self.get_list('DescribeClusters',
                                   params,
                                   [('item', EucaClusterControllerService),
                                    ('euca:item', EucaClusterControllerService)],
                                   verb='GET')

    def get_cluster_names(self):
        cluster_names = []
        ccs = self.get_cluster_controller_services()
        for cc in ccs:
            cluster_names.append(cc.partition)
        return cluster_names

    def get_nodes(self, get_instances=True):
        nodes = self.get_services(service_type='node', listall=True, service_class=EucaNodeService)
        if get_instances:
            for reservation in self.ec2_connection.get_all_instances(
                    filters={'tag-key':'euca:node'}):
                for vm in reservation.instances:
                    # Should this filter exclude terminated, shutdown, and stopped instances?
                    tag_node_name = vm.tags.get('euca:node')
                    if tag_node_name:
                        for node in nodes:
                            if node.name == tag_node_name:
                                node.instances.append(vm)
        return nodes

    def get_object_storage_gateways(self):
        params = {}
        return self.get_list('DescribeClusters',
                                  params,
                                  [('item', EucaObjectStorageGatewayService),
                                   ('euca:item', EucaObjectStorageGatewayService)],
                                  verb='GET')


    def _describe_properties(self):
        class EucaService(AWSQueryService):
            APIVersion='eucalyptus'
        class DescribeProperties(AWSQueryRequest):
            ServiceClass = EucaService
            ServiceName = 'Property'
            Description = "Show the cloud's properties or settings"
            Params = [Param(name='verbose',
                            short_name='v',
                            long_name='verbose',
                            ptype='boolean',
                            default=False,
                            optional=True,
                            doc='Include description information for properties in the '
                                'returned response.'),
                      ]
            Args = [Param(name='properties',
                          long_name='property prefix',
                          ptype='string',
                          cardinality='+',
                          optional=True,
                          doc='[PROPERTY-PREFIX] ...')]

            def __init__(self, **args):
                AWSQueryRequest.__init__(self, **args)
                self.list_markers = ['euca:properties']
                self.item_markers = ['euca:item']
                self.verbose = False

        query = DescribeProperties()
        query.get_connection(path = '/services/Empyrean',
                             aws_access_key_id = self.aws_access_key_id,
                             aws_secret_access_key = self.aws_secret_access_key,
                             port = 8773,
                             is_secure = False,
                             host = self.host)
        return query.send()

    def get_clusters(self, name=None, get_instances=True, get_storage=True,
                     get_cluster_controllers=True):
        controllers = self.get_cluster_controller_services()
        for cc in controllers:
            assert isinstance(cc, EucaClusterControllerService)
            new_cluster = cc.partition
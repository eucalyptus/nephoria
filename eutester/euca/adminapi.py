__author__ = 'clarkmatthew'

from boto.roboto.awsqueryservice import AWSQueryService
from boto.roboto.awsqueryrequest import AWSQueryRequest
from boto.roboto.param import Param
from eutester.aws.ec2.ec2ops import EC2ops
import sys

class EucaAdminQuery(AWSQueryService):
    APIVersion='eucalyptus'

class EucaAdminObj(object):
    # Base Class For Eucalyptus Admin Query Objects
    def __init__(self, connection=None):
        self.connection = connection
        self.name = None

    def __repr__(self):
        return str(self.__class__.__name__) + ":" + str(self.name)

    def startElement(self, name, value, connection):
        pass

    def endElement(self, name, value, connection):
         ename = name.lower().replace('euca:','')
         if ename:
            setattr(self, ename, value)


class EucaServices(object):
    def __init__(self, connection=None):
        self.services = []

    def __repr__(self):
        return str(self.__class__.__name__) + ":" + str(len(self.services))


    def startElement(self, name, value, connection):
        ename = name.replace('euca:','')
        print 'EucaServices got ename:{0}'.format(ename)
        if ename == 'item':
            print 'EucaServices got item, creating new service...'
            new_service = EucaBaseService(connection=connection)
            self.services.append(new_service)
            return new_service
        else:
            return None

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:','')
        if ename:
            setattr(self, ename, value)

class EucaUris(EucaAdminObj):
    # Base Class for Eucalyptus Service Objects
    def __init__(self, connection=None):
        super(EucaUris, self).__init__(connection)
        self.uris=[]

    def startElement(self, name, value, connection):
        ename = name.replace('euca:','')
        elem = super(EucaUris, self).startElement(name, value, connection)
        if elem is not None:
            return elem
    def endElement(self, name, value, connection):
        ename = name.replace('euca:','')
        if ename:
            if ename == 'entry':
                self.uris.append(value)
            else:
                setattr(self, ename, value)


class EucaBaseService(EucaAdminObj):
    # Base Class for Eucalyptus Service Objects
    def __init__(self, connection=None):
        super(EucaBaseService, self).__init__(connection)
        self.name = None
        self.partition = None
        self.uris = []

    def startElement(self, name, value, connection):
        ename = name.replace('euca:','')
        elem = super(EucaBaseService, self).startElement(name,
                                                         value,
                                                         connection)
        if elem is not None:
            return elem
        if ename == 'uris':
            self.uris = EucaUris(connection=connection)
            return self.uris
        elif ename:
            setattr(self, ename, value)



class Cluster(object):
    def __init__(self, cluster_controllers=[], storage_controllers=[], nodes=[],
                 config_property_map=None):
        self.cluster_controllers = cluster_controllers
        self.storage_controllers = storage_controllers
        self.nodes = nodes
        self.config_property_map = config_property_map

class EucaClusterControllerService(EucaBaseService):
    pass

class EucaObjectStorageGatewayService(EucaBaseService):
    pass

class EucaStorageControllerService(EucaBaseService):
    pass

class EucaNode(EucaBaseService):
    def __init__(self, connection=None):
        super(EucaNode, self).__init__(connection)
        self.instances=[]

class EucaProperty(EucaAdminObj):
    # Base Class for Eucalyptus Properties
    def __init__(self, connection=None):
        super(EucaProperty, self).__init__(connection)
        self.value = None
        self.description = None

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:','')
        if ename == 'description':
            self.description = value
        elif ename == 'name':
            self.name = value
        elif ename == 'value':
            self.value = value
        elif ename:
            setattr(self, ename, value)

###################################################################################################

class CloudAdmin():

    def __init__(self, tester=None, host=None, aws_access_key_id=None, aws_secret_access_key=None):
        self.tester = tester
        if not host and tester:
            host = tester.get_ec2_ip()
        self.host = host
        if not aws_access_key_id and tester:
            aws_access_key_id = tester.aws_access_key_id
        self.aws_access_key_id = aws_access_key_id
        if not aws_secret_access_key and tester:
            aws_secret_access_key = tester.aws_secret_access_key
        self.aws_secret_access_key = aws_secret_access_key
        if not self.host or not self.aws_access_key_id or not self.aws_secret_access_key:
            raise ValueError('Missing required arg. host:"{0}", aws_access_key_id:"{1}", '
                             'aws_secret_access_key:"{2}"'.format(host,
                                                                  aws_access_key_id,
                                                                  aws_secret_access_key))
        self.query = EucaAdminQuery(path = '/services/Empyrean',
                                    aws_access_key_id = self.aws_access_key_id,
                                    aws_secret_access_key = self.aws_secret_access_key,
                                    port = 8773,
                                    is_secure = False,
                                    host = self.host)
        if tester:
            self._ec2_connection = tester.ec2.connection
        else:
            self._ec2_connection = None

    @property
    def ec2_connection(self):
        if not self._ec2_connection:
            self._ec2_connection = self._get_ec2_connection()
        return self._ec2_connection

    def _get_ec2_connection(self, endpoint=None, access_key=None, secret_key=None,
                            port=8773, path='services/compute', is_secure=False, **kwargs):
        host = endpoint or self.host
        access_key = access_key or self.aws_access_key_id
        secret_key = secret_key or self. aws_secret_access_key
        connection = EC2ops._setup_ec2_connection(endpoint=host,
                                                  aws_access_key_id=access_key,
                                                  aws_secret_access_key=secret_key,
                                                  port = 8773, path=path, is_secure=is_secure,
                                                  **kwargs)
        return connection

    def get_services(self, service_type=None, show_event_stacks=None, show_events=None,
                     list_user_services=None, listall=None, list_internal=None,
                     markers = None,
                     service_class=EucaBaseService):
        if markers is None:
            #markers = [('euca:serviceStatuses', service_class)]
            markers = [('euca:item', service_class)]
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

        return self.query.get_list('DescribeServices',
                                  params,
                                  markers=markers,
                                  verb='GET')

    def get_clusters(self, get_instances=True, get_storage=True, get_cluster_controllers=True):
        controllers = self.get_cluster_controller_services()
        for cc in controllers:
            assert isinstance(cc, EucaClusterControllerService)
            new_cluster = cc.partition

    def get_cluster_controller_services(self):
        params = {}
        return self.query.get_list('DescribeClusters',
                                   params,
                                   [('item', EucaClusterControllerService),
                                    ('euca:item', EucaClusterControllerService)],
                                   verb='GET')

    def get_nodes(self, get_instances=True):
        nodes = self.get_services(service_type='node', listall=True, service_class=EucaNode)
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
        return self.query.get_list('DescribeClusters',
                                  params,
                                  [('item', EucaObjectStorageGatewayService),
                                   ('euca:item', EucaObjectStorageGatewayService)],
                                  verb='GET')


    def _describe_services(self):
        class EucaService(AWSQueryService):
            APIVersion='eucalyptus'
        class DescribeServices(AWSQueryRequest):
            ServiceClass = EucaService
        query = DescribeServices()
        query.get_connection(path = '/services/Empyrean',
                             aws_access_key_id = self.aws_access_key_id,
                             aws_secret_access_key = self.aws_secret_access_key,
                             port = 8773,
                             is_secure = False,
                             host = self.host)
        return query.send()


    def _describe_object_storage_gateways(self):
        class EucaService(AWSQueryService):
            APIVersion='eucalyptus'
        class DescribeObjectStorageGateways(AWSQueryRequest):
            ServiceClass = EucaService
        query = DescribeObjectStorageGateways()
        query.get_connection(path = '/services/Empyrean',
                             aws_access_key_id = self.aws_access_key_id,
                             aws_secret_access_key = self.aws_secret_access_key,
                             port = 8773,
                             is_secure = False,
                             host = self.host)
        return query.send()



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




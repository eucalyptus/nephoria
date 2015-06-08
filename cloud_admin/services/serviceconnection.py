
"""

###############################################################################################
#                                   Basic example:                                            #
###############################################################################################

from cloud_admin.services import EucaAdmin

# Create a EucaAdmin interface with the admin's access and secret key
cad = EucaAdmin(host='1.2.3.4',
                aws_access_key_id="ABCD123456789",
                aws_secret_access_key="ABCD123456789")

# Then make requests...
prop = cad.get_property('services.imaging.worker.log_server')

prop.show()

+----------------------------------+--------------+----------------------------------------+
|PROPERTY NAME                     |PROPERTY VALUE|DESCRIPTION                             |
+----------------------------------+--------------+----------------------------------------+
|services.imaging.worker.log_server|              |address/ip of the server that collects  |
|                                  |              |logs from imaging wokrers               |
+----------------------------------+--------------+----------------------------------------+

cad.show_nodes()

+----+------------+-------+-----------------------------------------------------------+
|ZONE| NODE NAME  | STATE |                         INSTANCES                         |
+----+------------+-------+-----------------------------------------------------------+
|one |10.111.5.151|ENABLED|                                                           |
+----+------------+-------+-----------------------------------------------------------+
|two |10.111.5.85 |ENABLED|  i-44274273(running,       m1.small,    instance-store  ) |
|    |            |       |  i-51475876(running,       m1.small,    instance-store  ) |
+----+------------+-------+-----------------------------------------------------------+




###############################################################################################
#   SSH tunnel/fwd Example:   How to forward the requests over an ssh encrypted session...    #
###############################################################################################
 - Where '10.111.5.156' is the CLC serving the empyrean requests/service.

from cloud_utils.file_utils.eucarc import Eucarc
from cloud_admin.services import EucaAdmin
from cloud_utils.net_utils.sshconnection import SshConnection

# Create an sshconnection to the CLC...
ssh = SshConnection(host='10.111.5.156', password='foobar', verbose=True)

# For ease of reading in access and secret keys build a eucarc obj from a local or remote eucarc
# local eucarc:
ec = Eucarc(filepath='eucarc-10.111.5.156-eucalyptus-admin/eucarc')
# remote eucarc:
ec = Eucarc(filepath='/root/eucarc', sshconnection=ssh)

# Create a EucaAdmin interface with the admin's access and secret key, since this is being
# forward from a local port, set the host to localhost...
cad = EucaAdmin(host='127.0.0.1', aws_access_key_id=ec.aws_access_key,
                aws_secret_access_key=ec.aws_secret_key)

# Replace the underlying method of creating an http connection w/ something like this
# returning the connection from the ssh obj's create_http_fwd_connection()
def gethttp(*args, **kwargs):
     http_connection_kwargs = cad.http_connection_kwargs.copy()
     return ssh.create_http_fwd_connection(destport=cad.port, localport=9797)

# now swap in the newly created method...
cad._pool.get_http_connection = gethttp

# now fire away requests...
cad.show_storage_controllers()
+------------+--------+---------+-------+-------+
|HOSTNAME    |NAME    |PARTITION|STATE  |TYPE   |
+------------+--------+---------+-------+-------+
|10.111.5.180|one-sc-1|one      |ENABLED|storage|
|10.111.1.116|two-sc-1|two      |ENABLED|storage|
+------------+--------+---------+-------+-------+

"""

import copy
import re
import time
from prettytable import PrettyTable
from urlparse import urlparse

import boto
from boto.vpc import VPCConnection
from boto.resultset import ResultSet
from boto.connection import AWSQueryConnection
from boto.ec2.regioninfo import RegionInfo
from boto.exception import BotoServerError

from cloud_admin.services import EucaResponseException, EucaNotFoundException
from cloud_admin.services.cluster_controller_service import (
    EucaClusterControllerService,
    SHOW_CLUSTER_CONTROLLER_SERVICES
)
from cloud_admin.services.cloud_controller_service import EucaCloudControllerService
from cloud_admin.services.cluster import Cluster, show_cluster
from cloud_admin.services.dns_service import EucaDnsService
from cloud_admin.services.storage_controller_service import EucaStorageControllerService
from cloud_admin.services.osg_service import EucaObjectStorageGatewayService
from cloud_admin.services.node_service import EucaNodeService, SHOW_NODES
from cloud_admin.services.walrus_service import EucaWalrusBackendService
from cloud_admin.services.arbitrator_service import EucaArbitratorService
from cloud_admin.services.ufs import Ufs
from cloud_admin.services.vmware_broker_service import EucaVMwareBrokerService
from cloud_admin.services.services import (
    EucaService,
    EucaServiceList,
    EucaServiceRegResponse,
    EucaServiceType,
    SHOW_COMPONENTS,
    SHOW_SERVICES,
    SHOW_SERVICE_TYPES,
    SHOW_SERVICE_TYPES_VERBOSE
)
from cloud_admin.services.eucaproperty import (
    EucaProperty,
    SHOW_PROPERTIES,
    SHOW_PROPERTIES_NARROW
)
from cloud_utils.log_utils import get_traceback, eulogger, markup

###############################################################################################
#                        Eucalyptus Admin ('Empyrean') Query Interface                        #
###############################################################################################


class ServiceConnection(AWSQueryConnection):
    APIVersion = 'eucalyptus'

    def __init__(self,
                 hostname,
                 aws_access_key,
                 aws_secret_key,
                 path='/services/Empyrean',
                 port=8773,
                 is_secure=False,
                 ec2_connection=None,
                 boto_debug_level=0,
                 err_method=None,
                 logger=None,
                 show_method=None,
                 **kwargs):
        """
        Primary Admin/Empyrean Query interface for a Eucalyptus Cloud

        :param hostname: service endpoint, hostname, ip, etc..
        :param access_key: cloud user access key to auth this connection
        :param secret_key: cloud user secret key to auth this connection
        :param port: remote port to be used for this connection
        :param path: service path for this connection
        :param is_secure: bool
        :param ec2_connection: boto ec2 or vpc connection obj
        :param boto_debug_level: int 0-2
        :param debug_method: method to be used for logging debug information
        :param err_method:  method to be used for logging error information
        :param kwargs: Additional kwargs to be passed to connection init
        :raise ValueError: Upon or invalid params
        """

        # Note: aws_access and secret_key get assigned to self during super().__init__()
        self.host = hostname
        if not isinstance(self.host, basestring) or \
                not isinstance(aws_access_key, basestring) or \
                not isinstance(aws_secret_key, basestring):
            raise ValueError('Missing or invalide type for required arg. host:"{0}", '
                             'aws_access_key_id:"{1}", aws_secret_access_key:"{2}"'
                             .format(self.host,
                                     aws_access_key,
                                     aws_secret_key))
        self.is_secure = is_secure
        self.port = port
        self.path = path
        # debug is an int representation of the debug level. Use log.debug() for
        # logging debug information
        self.debug = boto_debug_level
        if self.debug:
            boto.set_stream_logger('boto')
        if not logger:
            logger = eulogger.Eulogger(identifier=self.__repr__())
        self.log = logger
        self._show_method = self.log.info
        self.debug_method = self.log.debug
        if err_method:
            self.err_method = err_method
        self._ec2_connection = ec2_connection
        super(ServiceConnection, self).__init__(path=self.path,
                                                aws_access_key_id=aws_access_key,
                                                aws_secret_access_key=aws_secret_key,
                                                port=self.port,
                                                is_secure=self.is_secure,
                                                host=self.host,
                                                debug=self.debug,
                                                **kwargs)

    def __repr__(self):
        return "{0}:{1}".format(self.host, self.__class__.__name__)

    def err_method(self, msg):
        '''
        The default error logging method to be used if a 'debug_method' or 'tester' obj
        was not provided at init overwriting this method.
        '''
        self.log.error(msg)

    @property
    def ec2_connection(self):
        '''
        ec2 connection used for querying ec2 info as it relates to services.
        For example: what ec2 instances are located on which node controller host.
        '''
        if not self._ec2_connection:
            self._ec2_connection = self._get_ec2_connection()
        return self._ec2_connection

    def _get_ec2_connection(self, endpoint=None, access_key=None, secret_key=None,
                            port=None, APIVersion='2013-10-15', path=None,
                            is_secure=None, debug_level=None, **kwargs):
        """

        :param endpoint: service endpoint, hostname, etc..
        :param access_key: cloud user access key to auth this connection
        :param secret_key: cloud user secret key to auth this connection
        :param port: remote port to be used for this connection
        :param APIVersion: string, version to be used for this connection/request
        :param path: service path for this connection
        :param is_secure: bool
        :param debug_level: int (0-2)
        :param kwargs: additional kwargs to be passed to boto's vpc connection init
        :return: VPCConnection
        """
        if debug_level is None:
            debug_level = self.debug
        access_key = access_key or self.aws_access_key_id
        secret_key = secret_key or self.aws_secret_access_key
        ec2_region = RegionInfo()
        ec2_region.name = 'eucalyptus'
        host = endpoint
        if not endpoint:
            try:
                services = self.get_services(service_type='compute')
                for service in services:
                    if service.state == 'ENABLED':
                        urlp = urlparse(service.uri)
                        if host is None:
                            host = urlp.hostname
                        if path is None:
                            path = urlp.path
                        if port is None:
                            port = urlp.port
                        if is_secure is None and urlp.scheme == 'https':
                            is_secure = True
                        break
            except:
                self.log.warn('Failed to discover compute service, trying host @ "{0}"'
                              .format(self.host))
                host = self.host
        port = port or 8773
        path = path or 'services/compute'
        is_secure = is_secure or False
        ec2_region.endpoint = host
        connection_args = {'aws_access_key_id': access_key,
                           'aws_secret_access_key': secret_key,
                           'is_secure': is_secure,
                           'debug': debug_level,
                           'port': port,
                           'path': path,
                           'host': host}
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
        except Exception as e:
            buf = ""
            for key, value in connection_args.iteritems():
                buf += "\t{0} = {1}\n".format(key, value)
            self.log.warn('Error in ec2 connection attempt while using args:\n{0}'.format(buf))
            raise e
        return connection

    def _get_list_request(self, action='DescribeEucalyptus', service=EucaService, params={},
                          markers=['item', 'euca:item'], verb='GET'):
        """
        Make list request and parse objects into provided 'service' class using provided 'markers'

        :param action: requested action
        :param service: class used to parse response
        :param params: dict of parameters used in request
        :param markers: list markers for parsing response xml into provided service class
        :param verb: verb used in request, default: 'GET'
        :return: list of obj of type defined by provided 'service' class kwarg
        """
        params = params
        new_markers = []
        for marker in markers:
            new_markers.append((marker, service))
        return self.get_list(action, params, new_markers, verb=verb)

    ###############################################################################################
    #                        Eucalyptus 'Service Type' Methods                                    #
    ###############################################################################################

    def get_service_types(self, name=None):
        """
        Fetches all the available service types which can be registered against this system.
        """
        service_types = self._get_list_request('DescribeAvailableServiceTypes', EucaServiceType)
        if name:
            for service_type in service_types:
                if service_type.name == name:
                    new_list = ResultSet()
                    new_list.append(service_type)
                    return new_list
        return service_types

    def show_service_types_verbose(self, *args, **kwargs):
        """
        Prints a table summarizing Eucalyptus Service type objs.
        This table shows additional information to SHOW_SERVICE_TYPES(), which shows info most
        often relevant to an administrator. This table is produced without the additional
        formatting and sorting.
        :param connection: cloud_admin connection
        :param service_types: EucaServiceType objs
        :param printmethod: Method used to print this table, default is connection.default_method()
        :param print_table: bool, if True will print table, if False will return table obj
        :return: see print_table param.
        """
        return SHOW_SERVICE_TYPES_VERBOSE(self, *args, **kwargs)

    def show_service_types(self, *args, **kwargs):
        """
        Produces a table summarizing the Eucalyptus Service Types
        :param connection: cloud_admin() connection obj
        :param service_types: a list of service types to query, if None will fetch all
                              service types
        :param verbose: show debug info while producing this table
        :param printmethod: Use this method to print the table, otherwise will
                            use connection.debug_method()
        :param print_table: bool, if True will attempt to print the table, else will return the
                            table obj
        """
        return SHOW_SERVICE_TYPES(self, *args, **kwargs)

    def is_user_api_member(self, service_type):
        '''
        Quick lookup of all 'user-api' service and group member types. Returns true if the
        provided service_type is a member.
        :param service_type: string, service type
        :returns bool: True if is a 'user-api' service type member, else False
        '''
        names = ['user-api']
        user_api_service = self.get_service_types('user-api')[0]
        for member in user_api_service.groupmembers:
            names.append(member.name)
        if service_type in names:
            return True
        else:
            return False

    ###############################################################################################
    #                           Eucalyptus 'Service' Methods                                      #
    ###############################################################################################

    def get_services(self, service_type=None, show_event_stacks=None, show_events=True,
                     list_user_services=None, listall=True, list_internal=None,
                     service_names=None, markers=None, partition=None,
                     service_class=EucaServiceList):
        """
        Fetches Eucalyptus Cloud services
        :param service_type: EucaServiceType or string repsenting type
        :param show_event_stacks:
        :param show_events:
        :param list_user_services:
        :param listall:
        :param list_internal:
        :param service_names: Unique names of existing services
        :param markers: Markers used for parsing service objs from response
        :param partition: Existing Eucalyptus partition name
        :param service_class: Class to create from parsed get services response
        :returns: list of EucaService objects
        """
        service_names = service_names or []
        if not isinstance(service_names, list):
            service_names = [service_names]
        if markers is None:
            markers = [('euca:serviceStatuses', service_class)]
        params = {}
        x = 0
        for name in service_names:
            params['ServiceName.{0}'.format(x)] = name
        if service_type:
            assert isinstance(service_type, basestring), \
                "get_services: service_type not type basestring:{0}{1}"\
                .format(service_type, type(service_type))
            params['ByServiceType'] = str(service_type)
        if show_event_stacks:
            assert isinstance(show_event_stacks, bool), \
                "get_services: show_event_stacks not bool:{0}{1}"\
                .format(show_event_stacks, type(show_event_stacks))
            params['ShowEventStacks'] = str(show_event_stacks).lower()
        if show_events:
            assert isinstance(show_events, bool), \
                "get_services: show_events not type bool:{0}{1}"\
                .format(show_events, type(show_events))
            params['ShowEvents'] = str(show_events).lower()
        if list_user_services:
            assert isinstance(list_user_services, bool), \
                "get_services: list_user_services not type bool:{0}{1}"\
                .format(list_user_services, type(list_user_services))
            params['ListUserServices'] = str(list_user_services).lower()
        if listall:
            assert isinstance(listall, bool), \
                'get_services: listall not type bool:{0}{1}'\
                .format(listall, type(listall))
            params['ListAll'] = str(listall).lower()
        if list_internal:
            assert isinstance(list_internal, bool), \
                'get_services: list_internal not type bool:{0}{1}'\
                .format(list_internal, type(list_internal))
            params['ListInternal'] = str(list_internal).lower()
        if partition:
            assert isinstance(partition, basestring), \
                'get_services: partition not string ' \
                'type:{0}{1}'.format(partition, type(partition))
            params['ByPartition'] = str(partition)
        service_list = self.get_list('DescribeServices',
                                     params,
                                     markers=markers,
                                     verb='GET')
        if service_list:
            service_list = service_list[0] or []
            if partition:
                newlist = copy.copy(service_list)
                for service in service_list:
                    if service.partition != partition:
                        newlist.remove(service)
                return newlist
        return service_list

    def modify_service(self, service, state, verbose=True):
        '''
        Modify a eucalyptus service's state.

        :params: service: The unique name of a service, or a service object.
        :params: state: String representing state to transition service to.
                Possible arguments are:
                TRANSITIONS
                    START:DISABLED
                    STOP:STOPPED
                    INITIALIZE:INITIALIZED
                    LOAD:LOADED
                    DESTROY:PRIMORDIAL
                    ENABLE:ENABLED
                    DISABLE:DISABLED
                    CHECK:null
                    RESTART:null STATES
                    BROKEN
                    PRIMORDIAL
                    INITIALIZED
                    LOADED
                    STOPPED
                    NOTREADY
                    DISABLED
                    ENABLED
        verbose: bool, to print debug output to self.debug_method()
        returns: EucaService obj or None if Error
        '''
        modified_service = None
        markers = ['euca:ModifyServiceResponseType', 'ModifyServiceResponseType']
        service_name = None
        if isinstance(service, EucaService):
            service_name = service.name
        else:
            if isinstance(service, basestring):
                service_name = str(service)
        if not service_name:
            raise ValueError('modify_service: invalid service_name:"{0}/{1}"'
                             .format(service, type(service)))
        if not isinstance(state, basestring):
            raise ValueError('modify_service: Unknown type for "state": "{0}/{1}'
                             .format(state, type(state)))
        state = str(state)
        params = {'Name': service_name, 'State': state}
        cmd_string = str(
            'ModifyService({0})'
            .format(", ".join('{0}="{1}"'.format(x, y) for x, y in params.iteritems())))
        if verbose:
            self.debug_method(cmd_string)
        response = self._get_list_request(action='ModifyService', markers=markers, params=params,
                                          service=EucaServiceRegResponse)
        modified_service = self.get_services(service_names=service_name)
        if modified_service:
            modified_service = modified_service[0]
        if verbose:
            self.show_services(modified_service)
        if response:
            response = response[0]
            if response.eucareturn == 'true':
                return modified_service
            else:
                raise EucaResponseException(
                    "ERROR: {0}:\n\tStatusMessages:{1}"
                    .format(cmd_string, response.statusmessages),
                    respobj=response)
        else:
            if verbose:
                self.debug_method('ModifyService: Failed to parse response for: "{0}:{1}"'
                                  .format(service_name, state))
            if not modified_service:
                raise RuntimeError('Failed to fetch service: "{0}" after modify'
                                   .format(service_name))
            if str(modified_service.state).lower() != str(state).lower():
                raise RuntimeError('Modified service:"{0}" did not transition to desired state:'
                                   '"{1}", got:"{2}"'.format(service_name, state, service.state))
        return modified_service

    def register_service(self, unique_name, service_type, service_host, partition, port='8773',
                         verbose=True):
        """
        Registers a service with the cloud

        :param unique_name: Unique name of the service to be registered
        :param service_type: String, service type to be registered
        :param service_host: String, host ip/hostname of the machine hosting the new
                             service to be registered
        :param partition: string, the partition to register the service under.
                          If this is a cluster service, this is the cluster/zone name
        :param port: port this service uses
        :param verbose: show debug for this method
        :return: EucaService obj or None upon error
        :raise EucaResponseException:
        """
        registered_service = None
        messages = ""
        markers = ['RegisterServiceResponseType', 'euca:RegisterServiceResponseType']
        params = {'Type': service_type, 'Host': service_host, 'Partition': partition,
                  'Name': unique_name, 'Port': port}
        cmd_string = str(
            'RegisterService({0})'
            .format(", ".join('{0}="{1}"'.format(x, y) for x, y in params.iteritems())))
        self.debug_method(cmd_string)
        response = self._get_list_request(action='RegisterService', params=params, markers=markers,
                                          service=EucaServiceRegResponse)
        if response:
            response = response[0]
            if response.services:
                registered_service = response.services[0]
                if verbose:
                    self.show_services(services=[registered_service])
            if not registered_service:
                raise EucaResponseException(
                    "ERROR: {0}:\n\tStatusMessages:{1}"
                    .format(cmd_string, response.statusmessages),
                    respobj=response)
        if not registered_service:
            self.log.error('RegisterService: Failed to parse response for:"{0}"'
                           .format(cmd_string))
        return registered_service

    def deregister_service(self, unique_name, service_type=None, verbose=True):
        """
        Deregisters an existing service

        :param unique_name: name of service to be de-registered
        :param service_type: string, service type of the service to be deregistered
        :param verbose: show debug information
        :return: deregistered EucaService obj
        :raise EucaResponseException
        """
        deregistered_service = None
        messages = ""
        markers = ['DeregisterServiceResponseType', 'euca:DeregisterServiceResponseType']
        params = {'Type': service_type, 'Name': unique_name, 'Type': service_type}
        cmd_string = str(
            'DeregisterService({0})'
            .format(", ".join('{0}="{1}"'.format(x, y) for x, y in params.iteritems())))
        self.debug_method(cmd_string)
        response = self._get_list_request(action='DeregisterService', params=params,
                                          markers=markers, service=EucaServiceRegResponse)
        if response:
            response = response[0]
            if response.services:
                deregistered_service = response.services[0]
                if verbose:
                    self.show_services(services=[deregistered_service])
            if not deregistered_service:
                raise EucaResponseException(
                    "ERROR: {0}:\n\tStatusMessages:{1}"
                    .format(cmd_string, response.statusmessages),
                    respobj=response)
        if not deregistered_service:
            self.log.error('DeregisterService: Failed to parse response for:"{0}"'
                           .format(cmd_string))
        return deregistered_service

    def show_services(self, *args, **kwargs):
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
        return SHOW_SERVICES(self, *args, **kwargs)

    ###############################################################################################
    #                Eucalyptus 'Component-Service' Type Methods                                  #
    ###############################################################################################

    def get_all_cloud_controller_services(self):
        """
        Fetch all cloud controller service components

        :return: list of EucaCloudControllerService objs
        """
        return self._get_list_request('DescribeEucalyptus', EucaCloudControllerService)

    def get_cloud_controller_service(self, name):
        """
        Fetch specific cloud controller service from the cloud by it's unique name

        :param name: unique name of service to fetch
        :return: EucaCloudControllerService
        :raise EucaNotFoundException:
        """
        clcs = self.get_all_cloud_controller_services()
        for clc in clcs:
            if name and str(clc.name) == str(name):
                return clc
        raise EucaNotFoundException('get_cloud_controller_service. CLC not found for args:',
                                    notfounddict={'name': name})

    def get_all_cluster_controller_services(self, partition=None):
        """
        Fetch all cluster controller service components

        :return: list of EucaClusterControllerService objs
        """
        retlist = []
        ccs = self._get_list_request('DescribeClusters', EucaClusterControllerService)
        if not partition:
            return ccs
        else:
            for cc in ccs:
                if cc.partition == partition:
                    retlist.append(cc)
            return retlist

    def get_cluster_controller_service(self, name):
        """
        Fetch specific cluster controller service from the cloud by it's unique name

        :param name: unique name of service to fetch
        :return: EucaClusterControllerService
        :raise EucaNotFoundException:
        """
        ccs = self.get_all_cluster_controller_services()
        for cc in ccs:
            if name and str(cc.name) == str(name):
                return cc
        raise EucaNotFoundException('get_cluster_controller_service. CC not found for args:',
                                    notfounddict={'name': name})

    def get_all_cluster_names(self):
        """
        Fetch all cluster controller service components

        :return: list of EucaClusterControllerService objs
        """
        cluster_names = []
        ccs = self.get_all_cluster_controller_services()
        for cc in ccs:
            cluster_names.append(cc.partition)
        return cluster_names

    def get_all_object_storage_gateway_services(self):
        """
        Fetch all object storage gateway service components

        :return: list of EucaObjectStorageGatewayService objs
        """
        return self._get_list_request('DescribeObjectStorageGateways',
                                      EucaObjectStorageGatewayService)

    def get_object_storage_gateway_service(self, name):
        """
        Fetch specific object storage gateway service from the cloud by it's unique name

        :param name: unique name of service to fetch
        :return: EucaObjectStorageGatewayService
        :raise EucaNotFoundException:
        """
        osgs = self.get_all_object_storage_gateway_services()
        for osg in osgs:
            if name and str(osg.name) == str(name):
                return osg
        raise EucaNotFoundException('get_object_storage_gateway_service. OSG not found for args:',
                                    notfounddict={'name': name})

    def get_all_storage_controller_services(self):
        """
        Fetch all storage controller service components

        :return: list of EucaStorageControllerService objs
        """
        return self._get_list_request('DescribeStorageControllers', EucaStorageControllerService)

    def get_storage_controller_service(self, name):
        """
        Fetch specific storage controller service from the cloud by it's unique name

        :param name: unique name of service to fetch
        :return: EucaStorageControllerService
        :raise EucaNotFoundException:
        """
        scs = self.get_all_storage_controller_services()
        for sc in scs:
            if name and str(sc.name) == str(name):
                return sc
        raise EucaNotFoundException('get_storage_controller_service. SC not found for args:',
                                    notfounddict={'name': name})

    def get_all_walrus_backend_services(self):
        """
        Fetch all walrus backend service components

        :return: list of EucaWalrusBackendService objs
        """
        return self._get_list_request('DescribeWalrusBackends', EucaWalrusBackendService)

    def get_walrus_backend_service(self, name):
        """
        Fetch specific walrus backend service from the cloud by it's unique name

        :param name: unique name of service to fetch
        :return: EucaWalrusBackendService
        :raise EucaNotFoundException:
        """
        wals = self.get_all_walrus_backend_services()
        for wal in wals:
            if name and str(wal.name) == str(name):
                return wal
        raise EucaNotFoundException('get_walrus_backend_service. WS not found for args:',
                                    notfounddict={'name': name})

    def get_all_vmware_broker_services(self):
        """
        Fetch all vmware broker service components

        :return: list of EucaVmwareBrokerService objs
        """
        return self._get_list_request('DescribeVMwareBrokers', EucaVMwareBrokerService)

    def get_vmware_broker_service(self, name):
        """
        Fetch specific vmware broker service from the cloud by it's unique name

        :param name: unique name of service to fetch
        :return: EucaVmwareBrokerService
        :raise EucaNotFoundException:
        """
        vmbs = self.get_all_vmware_broker_services()
        for vmb in vmbs:
            if name and str(vmb.name) == str(name):
                return vmb
        raise EucaNotFoundException('get_vmware_broker_service. VMB not found for args:',
                                    notfounddict={'name': name})

    def get_all_arbitrator_services(self):
        """
        Fetch all arbitrator service components

        :return: list of EucaArbitratorService objs
        """
        return self._get_list_request('DescribeArbitrators', EucaArbitratorService)

    def get_arbitrator_service(self, name):
        """
        Fetch specific arbitrator service from the cloud by it's unique name

        :param name: unique name of service to fetch
        :return: EucaArbitratorService
        :raise EucaNotFoundException:
        """
        arbs = self.get_all_arbitrator_services()
        for arb in arbs:
            if name and str(arb.name) == str(name):
                return arb
        raise EucaNotFoundException('get_arbitrator_service. ARB not found for args:',
                                    notfounddict={'name': name})

    def get_all_unified_frontend_services(self, names=None):
        """
        Fetch specific unified front end User-API service (UFS)
        from the cloud by it's unique name

        :param name: unique name of service to fetch
        :return: UfsService
        :raise EucaNotFoundException:
        """
        ret_list = []
        if names and not isinstance(names, list):
            names = [names]
        ufss = self.get_services(service_type='user-api', service_names=names)
        for ufs in ufss:
            ret_list.append(Ufs(serviceobj=ufs))
        return ret_list

    def get_unified_frontend_service(self, name):
        ufss = self.get_all_unified_frontend_services(names=name)
        if ufss:
            ufs = ufss[0]
            if ufs.name == name:
                return ufs
        raise EucaNotFoundException('get_unified_frontend_service. UFS not found for args:',
                                    notfounddict={'name': name})

    def get_all_dns_services(self):
        return self.get_services(service_type='dns', service_class=EucaDnsService)

    def get_dns_service(self, name):
        for serv in self.get_all_dns_services():
            if serv.name == name:
                return serv
        raise EucaNotFoundException('get_dns_service. DNS not found for args:',
                                    notfounddict={'name': name})

    def get_all_node_controller_services(self, get_instances=True,
                                         fail_on_instance_fetch=False, filter_name=None,
                                         filter_fullname=None, partition=None):
        """
        Get multiple node controller service objs from cloud

        :param get_instances: bool, if True will attempt to get ec2 instances from cloud which
                              are being hosted on each node
        :param fail_on_instance_fetch: bool, if True will raise exceptions caught while fetching
                                       ec2 instances
        :param filter_name: string, will attempt to filter the node response by this name
        :param filter_fullname:  string, will attempt to filter the node response by this name
        :param partition:  string, will attempt to filter nodes by this partition/zone
        :return: list of Eucanode objects
\       """

        services = self.get_services(service_type='node', listall=True, partition=partition,
                                     service_class=EucaServiceList)
        nodes = []
        for service in services:
            if filter_name and str(filter_name) != str(getattr(service, 'name', None)):
                continue
            if filter_fullname and str(filter_fullname) != str(getattr(service, 'fullname', None)):
                continue
            nodes.append(EucaNodeService._from_service(service))
        if get_instances:
            try:
                reservations = self.ec2_connection.get_all_instances(
                    instance_ids=['verbose'],
                    filters={'tag-key': 'euca:node'})
            except Exception as RE:
                self.log.debug(get_traceback())
                self.log.warn('Failed to fetch instances for nodes, err:{0}'.format(str(RE)))
                reservations = []
                if fail_on_instance_fetch:
                    raise RE
            for reservation in reservations:
                for vm in reservation.instances:
                    try:
                        # Should this filter exclude terminated, shutdown, and
                        # stopped instances?
                        tag_node_name = vm.tags.get('euca:node', None)
                        if tag_node_name:
                            for node in nodes:
                                if node.name == tag_node_name:
                                    node.instances.append(vm)
                    except Exception as NE:
                        self.log.debug(get_traceback())
                        self.log.warn('Failed to fetch instances for node:{0}, err:{1}'
                                      .format(node.name, str(NE)))
                        if fail_on_instance_fetch:
                            raise NE
        return nodes

    def get_node_controller_service(self, name=None, fullname=None, partition=None,
                                    get_instances=True, fail_on_instance_fetch=False):
        """
        Get a single node controller service obj from cloud

        :param get_instances: bool, if True will attempt to get ec2 instances from cloud which
                              are being hosted on each node
        :param fail_on_instance_fetch: bool, if True will raise exceptions caught while fetching
                                       ec2 instances
        :param filter_name: string, will attempt to filter the node response by this name
        :param filter_fullname:  string, will attempt to filter the node response by this name
        :param partition:  string, will attempt to filter nodes by this partition/zone
        :return: EucaNode obj
        :raise EucaNotFoundException:
        """
        nodes = self.get_all_node_controller_services(
            filter_name=name, filter_fullname=fullname, partition=partition,
            get_instances=get_instances, fail_on_instance_fetch=fail_on_instance_fetch)
        if not nodes:
            raise EucaNotFoundException('get_node_controller_service: Not Found, args:',
                                        notfounddict={'name': name, 'fullname': fullname,
                                                      'partition': partition})
        node_count = len(nodes)
        if node_count != 1:
            try:
                node_string = ", ".join("\t{0}\n".format(x.name) for x in nodes)
                self.err_method('Found the following nodes:\n{0}'.format(node_string))
            except:
                pass
            raise EucaNotFoundException('get_all_node_controller_services: Multiple Matches '
                                        'found for args:',
                                        notfounddict={'name': name,
                                                      'fullname': fullname,
                                                      'partition': partition})
        return nodes[0]

    def show_nodes(self, *args, **kwargs):
        '''
        Prints table summary of nodes.

        :params nodes:  Can be a single, or list of EucaNodeService objects.
                        Can be a single, or list of node names (strings).
        :param print_table: bool, if true will write table to self.debug_method,
                            if false, will return the table object w/o printing it.
        '''
        return SHOW_NODES(self, *args, **kwargs)

    def show_cluster_controllers(self, ccs=None, print_method=None, print_table=True):
        """
        Fetch and summarize all cluster controller components in table format

        :param print_table: bool, if True will print table to connection.debug_method()
                           if False will return table object
        """
        return SHOW_CLUSTER_CONTROLLER_SERVICES(self, ccs=None, print_method=print_method,
                                                print_table=True)

    def show_storage_controllers(self, scs=None, print_method=None, print_table=True):
        """
        Fetch and summarize all storage controller components in table format

        :param print_table: bool, if True will print table to connection.debug_method()
                           if False will return table object
        """
        return SHOW_COMPONENTS(self, scs, self.get_all_storage_controller_services,
                               print_method=print_method, print_table=print_table)

    def show_objectstorage_gateways(self, osgs=None, print_method=None, print_table=True):
        """
        Fetch and summarize all object storage gateway components in table format

        :param print_table: bool, if True will print table to connection.debug_method()
                           if False will return table object
        """
        return SHOW_COMPONENTS(self, osgs, self.get_all_object_storage_gateway_services,
                               print_method=print_method, print_table=print_table)

    def show_cloud_controllers(self, clcs=None, print_method=None, print_table=True):
        """
        Fetch and summarize all cloud controller components in table format

        :param print_table: bool, if True will print table to connection.debug_method()
                           if False will return table object
        """
        return SHOW_COMPONENTS(self, clcs, self.get_all_cloud_controller_services,
                               print_method=print_method, print_table=print_table)

    def show_walrus_backends(self, walruses=None, print_method=None, print_table=True):
        """
        Fetch and summarize all  walrus backend components in table format

        :param print_table: bool, if True will print table to connection.debug_method()
                           if False will return table object
        """
        return SHOW_COMPONENTS(self, walruses, self.get_all_walrus_backend_services,
                               print_method=print_method, print_table=print_table)

    def show_components_summary(self, print_method=None, print_table=True):
        """
        Fetch and summarize all components in table format

        :param print_table: bool, if True will print table to connection.debug_method()
                           if False will return table object
        """
        components = []
        components_dict = self.get_all_components()
        for comp_type, comp_list in components_dict.iteritems():
            components.extend(comp_list or [])
        return SHOW_COMPONENTS(self, components=components, print_method=print_method,
                               print_table=print_table)

    def get_all_components(self, partition=None, service_type=None):
        """
        Attemtps to fetch all the 'components' from a cloud and return in a single list.
        See get_services() for fetching all 'services' from cloud.
        :return: list of EucaComponentService objs
        """
        components = {}
        ret_dict = {}
        if service_type in [None, 'walrus']:
            components['walrus'] = self.get_all_walrus_backend_services()
        if service_type in [None, 'storage']:
            components['storage'] = self.get_all_storage_controller_services()
        if service_type in [None, 'objectstorage']:
            components['objectstorage'] = self.get_all_object_storage_gateway_services()
        if service_type in [None, 'eucalyptus']:
            components['eucalyptus'] = self.get_all_cloud_controller_services()
        if service_type in [None, 'cluster']:
            components['cluster'] = self.get_all_cluster_controller_services()
        if service_type in [None, 'node']:
            components['node'] = self.get_all_node_controller_services()
        if service_type in [None, 'user-api']:
            components['user-api'] = self.get_all_unified_frontend_services()
        components['vmwarebroker'] = []
        if service_type in [None, 'vmwarebroker']:
            try:
                components['vmwarebroker'] = self.get_all_vmware_broker_services()
            except BotoServerError, VMWE:
                self.log.warn('Failed to fetch vmware brokers, vmware may not be supported on '
                              'this cloud. Err:{0}'.format(VMWE.message))
        if not partition:
            return components
        else:
            # Filter on service type
            for ctype, services in components.iteritems():
                ret_dict[ctype] = []
                for service in services:
                    if service.partition == partition:
                        ret_dict[ctype].append(service)
            return ret_dict

    ###############################################################################################
    #                            Eucalyptus 'Property' Methods                                    #
    ###############################################################################################

    def get_property(self, property):
        """
        Gets a single eucalyptus property matching 'property'.
        If the query returns anything other than a single property, a ValueError is thrown.

        :params property: string representing the property name,
                          or EucaProperty obj used to fetch the eucalyptus property
        :returns : A single EucaProperty obj
        """
        property_name = None
        if property:
            if isinstance(property, EucaProperty):
                property_name = property.name
            if isinstance(property, basestring):
                property_name = str(property)
        if not property:
            raise ValueError('Unknown type provided for property lookup: "{0}/{1}"'
                             .format(property, type(property)))
        props = self.get_properties(property_name)
        keep = []
        for prop in props:
            if re.match('^{0}$'.format(property_name), prop.name):
                keep.append(prop)
        prop_count = len(keep)
        if prop_count < 1:
            raise EucaNotFoundException('get_property:Property not Found', {'property': property})
        if prop_count > 1:
            prop_string = ""
            try:
                prop_string = ",".join("\t{0}\n".format(x.name) for x in keep)
            except:
                pass
            raise ValueError('get_property: Multiple matches for property name:{0}, found {1} '
                             'matches:\n{2}'.format(property_name, prop_count, prop_string))
        return keep[0]

    def get_properties(self, search=None, *nameprefix):
        '''
        Gets eucalyptus cloud configuration properties
        examples:
            get_properties()
            get_properties('www', 'objectstorage')
            get_properties('cloud.euca_log_level')
        :param nameprefix: list or property names or the prefix to match against properties.
        :returns a list of EucaProperty objs
        '''
        ret_list = []
        params = {}
        x = 0
        nameprefix = nameprefix or []
        for prop in nameprefix:
            if not prop:
                continue
            x += 1
            params['Property.{0}'.format(x)] = prop
        props = self._get_list_request('DescribeProperties', EucaProperty, params=params)
        if not search:
            return props
        for prop in props:
            if re.search(search, prop.name):
                ret_list.append(prop)
        return ret_list

    def modify_property(self, prop, value, verbose=True):
        """
        Modify a Eucalyptus Property

        :param prop: EucaProperty obj or string name of property
        :param value: value to modify property value to
        :param verbose: show debug information during modify attempt
        :return: Modified EucaProperty object
        :raise ValueError:
        """
        ret_prop = None
        params = {}
        action = 'ModifyPropertyValue'
        value = value or ""
        if not isinstance(prop, EucaProperty):
            props = self.get_properties(prop) or []
            if props:
                prop = props[0]
            else:
                raise ValueError('modify_property err. Property: "{0}" was not found on system?'
                                 .format(prop))
        params['Name'] = prop.name
        params['Value'] = str(value)
        markers = ['euca:ModifyPropertyValueResponseType', 'ModifyPropertyValueResponseType']
        ret_prop_list = self._get_list_request(action=action, service=EucaProperty,
                                               verb='POST', params=params, markers=markers)
        if ret_prop_list:
            ret_prop = ret_prop_list[0]
            if verbose:
                self.show_properties(properties=[ret_prop], description=False)
        else:
            if verbose:
                self.debug_method('Could not parse EucaProperty from ModifyPropertyValue '
                                  'response:"{0}"'.format(prop))
        return ret_prop

    def show_properties(self, *args, **kwargs):
        '''
        Summarize Eucalyptus properties in table format

        :param connection: cloud_admin connection
        :param properties: list of property names, or Eucaproperties to summarize
        :param description: bool, show property descriptions
        :param grid: bool, show table in grid format
        :param print_table: bool, if True will print table using connection.debug_method()
                            if False will return the table object
        :param prop_names: property names used to filter query response
        '''
        return SHOW_PROPERTIES(self, *args, **kwargs)

    def show_properties_narrow(self, *args, **kwargs):
        """
        Narrow formatted table used to summarize Eucalyptus properties

        :param connection: cloud_admin connection
        :param properties: list of EucaProperty objs or string names of properties
        :param verbose: show debug information during table creation
        :param print_table: bool, if True will print table using connection.debug_method()
                            if False will return the table object
        :param prop_names: property names used to filter query response
        """
        return SHOW_PROPERTIES_NARROW(self, *args, **kwargs)

    ###############################################################################################
    #                           Machine/Host Methods                                              #
    ###############################################################################################

    def get_all_machine_mappings(self, partition=None, service_type=None):
        """
        Attempts to derive and return a list of the individual machine/host to service mappings
        in use by a Eucalyptus service
        """
        components = self.get_all_components(partition=partition, service_type=service_type)
        machine_dict = {}
        for component_type, comp_list in components.iteritems():
            for component in comp_list:
                ip_addr = component.ip_addr or component.hostname
                if ip_addr not in machine_dict:
                    machine_dict[ip_addr] = [component]
                else:
                    machine_dict[ip_addr].append(component)
        return machine_dict

    def show_machine_mappings(self, machine_dict=None, partition=None, service_type=None,
                              columns=4, print_method=None, print_table=True):
        print_method = print_method or self._show_method
        ins_id_len = 10
        ins_type_len = 13
        ins_dev_len = 16
        ins_st_len = 15
        ins_total = (ins_id_len + ins_dev_len + ins_type_len + ins_st_len) + 5
        machine_hdr = (markup('MACHINE'), 18)
        service_hdr = (markup('SERVICES'), 100)
        pt = PrettyTable([machine_hdr[0], service_hdr[0]])
        pt.align = 'l'
        pt.hrules = 1
        pt.max_width[machine_hdr[0]] = machine_hdr[1]
        total = []
        machines = machine_dict or self.get_all_machine_mappings(partition=partition,
                                                                 service_type=service_type)
        if not isinstance(machines, dict):
            raise ValueError('show_machine_mappings requires dict example: {"host ip":[services]}, '
                             'got:"{0}/{1}"'.format(machines, type(machines)))
        # To format the tables services, print them all at once and then sort the table
        # rows string into the machines columns
        for machine, services in machines.iteritems():
            for serv in services:
                total.append(serv)
                if serv.child_services:
                    total.extend(serv.child_services)
        # Create a large table showing the service states, grab the first 3 columns
        # for type, name, state, and zone
        servpt = self.show_services(total, print_table=False)
        serv_lines = servpt.get_string(border=0, padding_width=2,
                                       fields=servpt._field_names[0: columns]).splitlines()
        header = serv_lines[0]
        ansi_escape = re.compile(r'\x1b[^m]*m')
        # Now build the machine table...
        for machine, services in machines.iteritems():
            servbuf = header + "\n"
            mservices = []
            # Get the child services (ie for UFS)
            for serv in services:
                mservices.append(serv)
                mservices.extend(serv.child_services)
            for serv in mservices:
                for line in serv_lines:
                    # Remove the ansi markup for parsing purposes, but leave it in the
                    # displayed line
                    clean_line = ansi_escape.sub('', line)
                    splitline = clean_line.split()
                    if len(splitline) < 2:
                        continue
                    line_type = splitline[0]
                    line_name = splitline[1]
                    # Pull matching lines out of the pre-formatted service table...
                    if (splitline and re.match("^{0}$".format(serv.type), line_type) and
                            re.match("^{0}$".format(serv.name), line_name)):
                        # Add this line to the services to be displayed for this machine
                        servbuf += line + "\n"
                if serv.type == 'node' and getattr(serv, 'instances', None):
                    servbuf += "\n" + markup('INSTANCES', [1, 4]) + " \n"
                    for x in serv.instances:
                        servbuf += ("{0}{1}{2}{3}"
                                    .format(str(x.id).ljust(ins_id_len),
                                            str('(' + x.state + '),').ljust(ins_st_len),
                                            str(x.instance_type + ",").ljust(ins_type_len),
                                            str(x.root_device_type).ljust(ins_dev_len))
                                    .ljust(ins_total)).strip() + "\n"
            pt.add_row(["{0}\n{1}".format(str("").rjust(machine_hdr[1]),
                                          markup(machine, [1, 4, 94])),
                        servbuf])
        if print_table:
            print_method("\n{0}\n".format(pt.get_string(sortby=pt.field_names[1])))
        else:
            return pt

    def get_all_clusters(self, cluster_name=None):
        ret_list = []
        cluster_names = self.get_all_cluster_names()
        if cluster_name:
            if cluster_name not in cluster_names:
                raise ValueError('Cluster name:{0} not in cluster names:{1}'
                                 .format(cluster_name, ", ".join(str(x) for x in cluster_names)))
            cluster_names = [cluster_name]
        for cname in cluster_names:
            ret_list.append(Cluster(self, cname))
        return ret_list

    def show_cluster_mappings(self, clusters=None, name=None, print_table=True):
        maintpt = PrettyTable([markup('SHOW CLUSTERS')])
        maintpt.align = 'l'
        if clusters:
            if not isinstance(clusters, list):
                clusters = [clusters]
        else:
            clusters = self.get_all_clusters(cluster_name=name)
        for cluster in clusters:
            maintpt.add_row([markup('CLUSTER NAME:"{0}"'.format(cluster.name), [1, 4, 94])])
            maintpt.add_row([cluster.show_machine_mappings(print_table=False).get_string()])
        if print_table:
            self._show_method("\n{0}\n".format(maintpt))
        else:
            return maintpt

    ###############################################################################################
    #                           Misc Service Methods                                              #
    ###############################################################################################

    def wait_for_service(self, service, states=None, partition=None,
                         attempt_both=True, interval=20, timeout=600):
        """
        Attempts to wait for a specific service to transition to one of the states provided in
        'states' by the given timeout, or raise RunTimeError
        The first service meeting the criteria provided found is returned.

        :param service: Eucaservice obj or name of a service type
        :param states:  The state(s) to match for the given service type
        :param partition: The name of the partition for the service
        :param interval: Interval to wait between querying the services
        :param timeout: Timeout in seconds before giving up
        :raises : RunTimeError() if a service is not found within the timeout period
        :returns a EucaServiceObj matching the provided criteria
        """
        if not states:
            states = ["ENABLED"]
        elif not isinstance(states, list):
            states = [states]
        state_info = ",".join(str(x) for x in states)
        err_msg = ""
        service_type = None
        interval = interval
        matching_services = []
        if service:
            if isinstance(service, EucaService):
                service_type = service.type
            elif isinstance(service, basestring):
                service_types = self.get_service_types(name=str(service))
                if service_types:
                    service_type = service_types[0]
                    service_type = service_type.name
        if not service_type:
            raise ValueError('wait_for_service. Unknown service type for:"{0}:{1}"'
                             .format(service, type(service)))
        self.debug_method('Waiting for service type:{0} to go to States:{1}'
                          .format(service_type, state_info))
        start = time.time()
        elapsed = 0
        while (elapsed < timeout):
            elapsed = int(time.time() - start)
            try:
                matching_services = self.get_services(service_type=service_type,
                                                      partition=partition) or []
                if matching_services:
                    self.show_services(services=matching_services)
                else:
                    err_msg = 'No service registered of type:"{0}", partition:"{1}", ' \
                              'elapsed:{2}/{3}'.format(service_type, partition, elapsed, timeout)
                    self.log.warn(err_msg)
                for service in matching_services:
                    if states:
                        for state in states:
                            if re.search(state, service.state):
                                return service
                    else:
                        if re.search(state, service.state):
                            return service
            except Exception, E:
                err_msg = ('Error while fetching services:"{0}:{1}", elapsed:{2}/{3}'
                           '\nRetrying in "{4}" seconds'.format(type(E), str(E),
                                                                elapsed, timeout, interval))
                err_msg = "{0}\n{1}".format(get_traceback(), err_msg)
                self.log.error(err_msg)
            time.sleep(interval)
        # No services were found matching the information provided...
        if matching_services:
            try:
                self.show_services(services=matching_services)
            except:
                pass
        msg = ("{0}\nERROR: Service_type:'{1}', partition:{2} did not enter state(s):'{3}'"
               .format(err_msg, service_type, partition,  state_info))
        raise RuntimeError(msg)

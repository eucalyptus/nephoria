

from hp3parclient import client, exceptions


class ThreeParBaseObj(object):

    def __init__(self, connection=None, newdict=None):
        if isinstance(newdict, dict):
            for key, value in newdict.iteritems():
                key = str(key).replace('-','_')
                setattr(self, key, value)

class ThreePar(object):

    def __init__(self, systemconnection, defaultpassword=None, zonedict=None, debug=False):

        """

        :param systemconnection: A SystemConnection obj
        :param zonedict: An optional dictionary
        """
        self.connection = systemconnection
        self.zonedict = zonedict


    def create_san_connections(self, zone=None):
        api_url = api_url or self.get_api_url_from_euca_properties(zone=zone)
        username = username or self.get_three_par_username_from_euca_properties(zone=zone)
        super(ThreePar, self).__init__(api_url=api_url, debug=debug)
        self.login(username=username, password=password)


    def get_three_par_username_from_euca_properties(self, zone=None):
        if not zone:
            zones = self.get_three_par_zones()
            if not zones:
                raise ValueError('Could not find a zone configured for '
                                 'blockstoragemanager=threepar')
            zone = zone[0]
        userprop = self.connection.get_property("{0}.storage.sanuser".format(zone))
        userprop = userprop.value
        if not userprop or userprop == '<unset>':
            raise  ValueError('"sanuser" is not configured for threepar zone: "{0}"'.format(zone))
        return userprop

    def get_api_url_from_euca_properties(self, zone=None, port=None):
        if not zone:
            zones = self.get_three_par_zones()
            if not zones:
                raise ValueError('Could not find a zone configured for '
                                 'blockstoragemanager=threepar')
            zone = zone[0]
        shost = self.connection.get_property("{0}.storage.sanhost".format(zone))
        shost = shost.value
        if not shost or shost == '<unset>':
            raise  ValueError('"sanhost" is not configured for threepar zone: "{0}"'.format(zone))
        if port is None:
            portprop =  self.connection.get_property("{0}.storage.threeparwsport"
                                                     .format(zone))
            port = portprop.value or 8008
        return 'http://{0}:{1}/api/v1'.format(shost.value, port)

    def get_three_par_zones(self):
        zones = []
        for cname in  self.connection.get_all_cluster_names():
            prop = self.connection.get_property("{0}.storage.blockstoragemanager"
                                                .format(cname))
            if prop.value == 'threepar':
                zones.append(cname)
        return zones

    def get_volumes(self):
        vlist = self.getVolumes()

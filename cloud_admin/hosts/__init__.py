

class EucaMachineHelpers(object):

    def __init__(self, eucahost):
        self.machine = eucahost
        self.sys = eucahost.sys
        self.log = eucahost.log
        self.debug = self.log.debug
        self.services = getattr(eucahost, 'services', [])
        self.eucalyptus_conf = eucahost.eucalyptus_conf

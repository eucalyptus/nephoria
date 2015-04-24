__author__ = 'clarkmatthew'

from eutester.euca.cloud_admin import EucaBaseObj

class EucaProperty(EucaBaseObj):
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
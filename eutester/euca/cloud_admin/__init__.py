
__author__ = 'clarkmatthew'

class EucaBaseObj(object):
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
            setattr(self, ename.lower(), value)

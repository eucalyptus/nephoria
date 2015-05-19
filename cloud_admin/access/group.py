class IamGroup(object):
    # Base Class For IAM Group Objs
    def __init__(self, connection=None):
        self.connection = connection
        self.name = None
        self.id = None
        self.path = None
        self.arn = None
        self.createdate = None

    def __repr__(self):
        return str(self.__class__.__name__) + ":" + str(self.name)

    def startElement(self, name, value, connection):
        pass

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            if ename == 'groupid':
                self.id = value
            if ename == 'groupname':
                self.name = value
            setattr(self, ename.lower(), value)

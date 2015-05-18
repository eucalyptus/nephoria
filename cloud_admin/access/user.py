
class IamUser(object):
     # Base Class For IAM User Objs
    def __init__(self, connection=None):
        self.connection = connection
        self.name = None
        self.id = None
        self.path = None
        self.arn = None
        self.createdate = None
        self.account = None

    @property
    def account_name(self):
        if self.account:
            return getattr(self.account, 'name', None)

    @property
    def account_id(self):
        if self.account:
            return getattr(self.account, 'id', None)

    def show(self):
        return self.connection.show_all_users(users=self)

    def __repr__(self):
        return str(self.__class__.__name__) + ":" + str(self.name)

    def startElement(self, name, value, connection):
        pass

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            if ename == 'userid':
                self.id = value
            if ename == 'username':
                self.name = value
            setattr(self, ename.lower(), value)
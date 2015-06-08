
import re

class IamUser(object):
    # Base Class For IAM User Objs
    def __init__(self, connection=None):
        self.connection = connection
        self._account_id = None
        self._account_name = None
        self._account = None
        self.name = None
        self.id = None
        self.path = None
        self.arn = None
        self.createdate = None

    @property
    def account_name(self):
        if self.account:
            return getattr(self.account, 'name', None)

    @account_name.setter
    def account_name(self, value):
        self._account_name = value

    @property
    def account_id(self):
        if not self._account_id:
            if self.arn:
                match = re.search(':(\d{12}):', self.arn)
                if match:
                     self._account_id = match.group(1)
            if not self._account_id and self.account:
                self._account_id = getattr(self.account, 'id', None)
        return self._account_id

    @account_id.setter
    def account_id(self, value):
        self._account_id = value

    @property
    def account(self):
        if not self._account:
            if self.account_id:
                try:
                    self._account = self.connection.get_account(self.account_id)
                except Exception as AE:
                    self.log.warn('Could not lookup account for user:"{0}", err:"{1}"'
                                  .format(self.name, str(AE)))
        return self._account

    @account.setter
    def account(self, value):
        self._account = value

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
            elif ename == 'username':
                self.name = value
            else:
                setattr(self, ename.lower(), value)


from boto.resultset import ResultSet
import time
from cloud_utils.log_utils import get_traceback


class IamAccount(object):
    # Base Class For IAM Account Objs
    def __init__(self, connection=None):
        self.connection = connection
        self.name = None
        self.id = None
        self._users = None

    def __repr__(self):
        return str(self.__class__.__name__) + ":" + str(self.name)

    def get_users(self, name=None, id=None, path=None):
        return self.connection.get_users_from_account(user_name=name, user_id=id, path=path,
                                                      delegate_account=(self.id or self.name))

    def show(self):
        return self.connection.show_all_accounts(account=self)

    def show_users(self, name=None, id=None, path=None):
        return self.connection.show_all_users(account_id=self.id, path=path, user_name=name,
                                              user_id=id)

    def update(self, new_account=None, silent=True):
        """
        Base update method for updating component service objs
        :params new_account: optional new_account object to be used to update this account
        :params silent: bool, if True will not raise Exceptions found during lookup, will instead
                        write errors to self.connection.err_method()
        :returns : self upon successful update, otherwise returns None
        """
        errmsg = ""
        if not new_account:
            try:
                if self.id:
                    new_account = self.connection.get_account_by_id(account_id=self.id)
                else:
                    new_account = self.connection.get_account_by_name(account_name=self.name)
            except Exception as LE:
                if silent:
                    errmsg = "{0}\n{1}\n".format(get_traceback(), str(LE))
                    self.connection.log.error('{0}Update failed. IamAccount: {1} not found'
                                              .format(errmsg, self.name))
                    return None
                else:
                    raise
        if not isinstance(new_account, self.__class__):
            raise ValueError('"{0}" update error. Non {1} type for new_account. '
                             'Found: "{2}/{3}"'.format(self.name,
                                                       self.__class__.__name__,
                                                       new_account,
                                                       type(new_account)))
        if new_account:
            self.__dict__.update(new_account.__dict__)
            return self

    def startElement(self, name, value, connection):
        pass

    def endElement(self, name, value, connection):
        ename = name.lower().replace('euca:', '')
        if ename:
            if ename == 'accountid':
                self.id = value
            elif ename == 'accountname':
                self.name = value
            else:
                setattr(self, ename.lower(), value)

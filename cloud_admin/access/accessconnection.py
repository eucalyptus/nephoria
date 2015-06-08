from prettytable import PrettyTable
from boto.iam import IAMConnection
from boto import set_stream_logger
from cloud_utils.file_utils.eucarc import Eucarc
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import markup
from cloud_admin.access.account import IamAccount
from cloud_admin.access.user import IamUser
from cloud_admin.access.group import IamGroup
from urlparse import urlparse
import re


class AccessConnection(IAMConnection):

    def __init__(self, creds=None, host=None, aws_access_key=None, aws_secret_key=None,
                 is_secure=None, port=None, path=None, logger=None, boto_debug=0, **kwargs):

        self.debug = boto_debug
        if self.debug:
            set_stream_logger('boto')
        if creds and not isinstance(creds, Eucarc):
            credsattr = getattr(creds, 'creds', None)
            if not isinstance(credsattr, Eucarc):
                raise ValueError('Unknown type passed for creds arg: "{0}/{1}"'
                                 .format(creds, type(creds)))
            creds = credsattr
        self._eucarc = creds
        self.account_id = None
        self.user_id = None
        if not logger:
            logger = Eulogger(identifier=self.__class__.__name__)
        self.log = logger
        if creds:
            self.user_id = creds.ec2_user_id
            self.account_id = creds.ec2_account_number
            assert isinstance(creds, Eucarc), 'UserAdmin. eucarc not of type Eucarc(), ' \
                                               'got:"{0}/{1}"'.format(creds, type(creds))
            urlp = urlparse(creds.euare_url)
            host = host or getattr(urlp, 'hostname', None)
            port = port or getattr(urlp, 'port', 8773)
            path = path or getattr(urlp, 'path', '/services/Euare')
            if is_secure is None and urlp.scheme == 'https':
                is_secure = True
            aws_secret_key = aws_secret_key or creds.aws_secret_key
            aws_access_key = aws_access_key or creds.aws_access_key
        is_secure = is_secure or False
        ac_kwargs = {'host': host, 'aws_access_key_id': aws_access_key,
                     'aws_secret_access_key': aws_secret_key,
                     'is_secure': is_secure,
                     'port': port, 'path': path}
        ac_kwargs.update(kwargs)
        try:
            super(AccessConnection, self).__init__(**ac_kwargs)
        except:
            self.log.error('Failed to create AccessConnection with kwargs:"{0}"'.format(ac_kwargs))
            raise

    def get_self(self):
        user = self.get_object(action='GetUser', params={}, cls=IamUser, verb='GET')

    def get_all_accounts(self, account_id=None, account_name=None, search=False):
        """
        Request all accounts, return account dicts that match given criteria

        :param account_id: regex string - to use for account_name
        :param account_name: regex - to use for account ID
        :param search: boolean - specify whether to use match or search when filtering the
                       returned list
        :return: list of account names
        """
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        self.log.debug('Attempting to fetch all accounts matching- account_id:{0} account_name:{1}'
                   .format(str(account_id), str(account_name)))
        params = {}
        accounts = self.get_list(action='ListAccounts',
                                 params=params,
                                 markers=[('member', IamAccount)],
                                 verb='GET')
        retlist = []
        # Filter based on criteria provided
        for account in accounts:
            if account_name is not None and re_meth(account_name, account.name):
                continue
            if account_id is not None and not re_meth(account_id, account.id):
                continue
            retlist.append(account)
        return retlist

    def get_account(self, account):
        if not account:
            raise ValueError('get_account got unknown type for account:"{0}/{1}"'
                             .format(account, type(account)))
        if isinstance(account, IamAccount):
            return self.get_all_accounts(account_id=account.id)[0]
        if re.match('^\d{12}$', account):
            return self.get_all_accounts(account_id=account)[0]
        else:
            return self.get_all_accounts(account_name=account)[0]

    def get_users_from_account(self, path=None, user_name=None, user_id=None,
                               delegate_account=None, search=False):
        """
        Returns access that match given criteria. By default will return current account.

        :param path: regex - to match for path
        :param user_name: str name of user
        :param user_id: regex - to match for user_id
        :param delegate_account: str (account name or id) can be used by Cloud admin in
                                 Eucalyptus to choose an account to operate on
        :param search: use regex search (any occurrence) rather than match (exact same
                       strings must occur)
        :return:
        """
        self.log.debug('Attempting to fetch all access matching- user_id:{0} user_name:{1} '
                       'acct_name:{2}'.format(str(user_id), str(user_name), str(delegate_account)))
        retlist = []
        params = {}
        account = None
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        if delegate_account:
            account = self.get_account(delegate_account)
            params['DelegateAccount'] = delegate_account
        users = self.get_list(action='ListUsers', params=params, markers=[('member', IamUser)])
        for user in users:
            if path is not None and not re_meth(path, user.path):
                continue
            if user_name is not None and not re_meth(user_name, user.name):
                continue
            if user_id is not None and not re_meth(user_id, user.id):
                continue
            user.account = account
            retlist.append(user)
        return retlist

    def get_user(self, user_name=None):
        user = super(AccessConnection, self).get_user(user_name=user_name)
        if not user:
            return None
        newuser = IamUser(connection=self)
        userdict = user['get_user_response']['get_user_result']['user']
        newuser.__dict__.update(userdict)
        return newuser

    def get_all_users(self, account_id=None, account_name=None, search=False):
        """
        Request all accounts, return account dicts that match given criteria

        :param account_id: regex string - to use for account_name
        :param account_name: regex - to use for account ID
        :param search: boolean - specify whether to use match or search when filtering the
                       returned list
        :return: list of account names
        """
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        self.log.debug('Attempting to fetch all accounts matching- account_id:{0} account_name:{1}'
                       .format(str(account_id), str(account_name)))
        response = self.connection('ListAccounts', {}, list_marker='Accounts')
        params = {}
        accounts = self.get_list(action='ListAccounts',
                                 params=params,
                                 markers=('member', IamAccount),
                                 verb='GET')
        retlist = []
        for account in accounts:
            if account_name is not None and re_meth(account_name, account.name):
                continue
        # Filter based on criteria provided
        for account in response['list_accounts_response']['list_accounts_result']['accounts']:
            if account_name is not None and not re_meth(account_name, account['account_name']):
                continue
            if account_id is not None and not re_meth(account_id, account.id):
                continue
            retlist.append(account)
        return retlist

    def get_all_users(self, account_name=None,  account_id=None,  path=None,
                      user_name=None,  user_id=None,  search=False):
        """
        Queries all accounts matching given account criteria, returns all access found within
        these accounts which then match the given user criteria.
        Account info is added to the user dicts

        :param account_name: regex - to use for account name
        :param account_id: regex - to use for account id
        :param path: regex - to match for path
        :param user_name: regex - to match for user name
        :param user_id: regex - to match for user id
        :param search: boolean - specify whether to use match or search when filtering the re
                       turned list
        :return: List of access with account name tuples
        """
        userlist = []
        accounts = self.get_all_accounts(account_id=account_id, account_name=account_name,
                                         search=search)
        for account in accounts:
            # if account['account_id'] == self.account_id:
            #    access =self.get_users_from_account()
            # else:
            users = self.get_users_from_account(path=path,
                                                user_name=user_name,
                                                user_id=user_id,
                                                delegate_account=account.name,
                                                search=search)
            for user in users:
                user.account = account
                userlist.append(user)
        return userlist

    def get_all_groups(self, path_prefix='/', delegate_account=None):

        params = {'PathPrefix': path_prefix}
        if delegate_account:
            account = self.get_account(delegate_account)
            params['DelegateAccount'] = account.id
        else:
            account = self.get_account(self.account_id)

    def show_all_accounts(self, account=None, account_name=None, account_id=None, search=False,
                          print_method = None, print_table=True):
        """
        Debug Method to print an account list based on given filter criteria

        :param account_name: regex - to use for account_name
        :param account_id: regex - to use for account_id
        :param search: boolean - specify whether to use match or search when filtering the
                       returned list
        """
        print_method = print_method or self.log.info
        pt = PrettyTable([markup('ACCOUNT_NAME'), markup('ACCOUNT_ID')])
        pt.hrules = 1
        pt.align = 'l'
        if account:
            if isinstance(account, IamAccount):
                alist = [account]
            else:
                alist = [self.get_account(account)]
        else:
            alist = self.get_all_accounts(account_name=account_name,
                                          account_id=account_id,
                                          search=search)
        for account in alist:
            pt.add_row([account.name, account.id])
        if print_table:
            print_method("\n" + str(pt) + "\n")
        else:
            return pt

    def show_all_groups(self, account_name=None,  account_id=None,  path=None, group_name=None,
                        group_id=None,  search=False, print_method=None, print_table=True):
        """
        Print all groups in an account

        :param account_name: regex - to use for account_name
        :param account_id: regex - to use for
        :param path: regex - to match for path
        :param group_name: regex - to match for user_name
        :param group_id: regex - to match for user_id
        :param search:  boolean - specify whether to use match or search when filtering
                        the returned list
        """
        print_method = print_method or self.log.info
        pt = PrettyTable([markup('ACCOUNT:'), markup('GROUPNAME:'), markup('GROUP_ID:')])
        pt.hrules = 1
        pt.align = 'l'
        glist = self.get_all_groups(account_name=account_name, account_id=account_id,
                                    path=path, group_name=group_name, group_id=group_id,
                                    search=search)
        for group in glist:
            pt.add_row([group['account_name'], group['group_name'], group['group_id']])
        if print_table:
            print_method("\n" + str(pt) + "\n")
        else:
            return pt

    def show_all_users(self, users=None, account_name=None, account_id=None,  path=None,
                       user_name=None, user_id=None, search=False, print_method=None,
                       print_table=True):
        """
        Debug Method to print a user list based on given filter criteria

        :param account_name: regex - to use for account_name
        :param account_id: regex - to use for
        :param path: regex - to match for path
        :param user_name: regex - to match for user_name
        :param user_id: regex - to match for user_id
        :param search: boolean - specify whether to use match or search when filtering the
                                 returned list
        """
        print_method = print_method or self.log.info
        pt = PrettyTable([markup('ACCOUNT:'), markup('USERNAME:'), markup('USER_ID'),
                          markup('ACCT_ID')])
        pt.hrules = 1
        pt.align = 'l'
        if users:
            if not isinstance(users, list):
                ulist = [users]
            else:
                ulist = users
            for user in ulist:
                if not isinstance(user, IamUser):
                    raise ValueError('show_all_users got non IAMUser type: "{0}/{1}"'
                                     .format(user, type(user)))
        else:
            ulist = self.get_all_users(account_name=account_name, account_id=account_id, path=path,
                                       user_name=user_name, user_id=user_id, search=search)
        for user in ulist:
            pt.add_row([user.account_name, user.name, user.id, user.account_id])
        if print_table:
            print_method("\n" + str(pt) + "\n")
        else:
            return pt

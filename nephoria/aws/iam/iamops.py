# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2014, Eucalyptus Systems, Inc.
# All rights reserved.
#
# Redistribution and use of this software in source and binary forms, with or
# without modification, are permitted provided that the following conditions
# are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author: vic.iglesias@eucalyptus.com

from boto.iam import IAMConnection
from boto.exception import BotoServerError
import json
import os
import re
import urllib
from prettytable import PrettyTable
from nephoria.baseops.botobaseops import BotoBaseOps


class IAMops(BotoBaseOps):
    EUCARC_URL_NAME = 'iam_url'
    SERVICE_PREFIX = 'iam'
    CONNECTION_CLASS = IAMConnection

    def setup_resource_trackers(self):
        ## add test resource trackers and cleanup methods...
        self.test_resources["iam_accounts"] = self.test_resources.get('iam_accounts', [])
        self.test_resources_clean_methods["iam_accounts"] = None

    def create_account(self, account_name, ignore_existing=True):
        """
        Create an account with the given name

        :param account_name: str name of account to create
        """

        params = {'AccountName': account_name}
        try:
            res = self.get_response_items('CreateAccount', params, item_marker='account')
            self.log.debug("Created account: " + account_name)
        except BotoServerError as BE:
            if not (BE.status == 409 and ignore_existing):
                raise
            res = self.get_account(account_name=account_name)
            self.log.debug("create_account(). Account already exists: " + account_name)
        self.test_resources["iam_accounts"].append(account_name)
        return res
    
    def delete_account(self, account_name, recursive=False):
        """
        Delete an account with the given name

        :param account_name: str name of account to delete
        :param recursive:
        """
        self.log.debug("Deleting account: " + account_name)
        params = {
            'AccountName': account_name,
            'Recursive': recursive
        }
        self.connection.get_response('DeleteAccount', params)

    def get_all_accounts(self, account_id=None, account_name=None, search=False):
        """
        Request all accounts, return account dicts that match given criteria

        :param account_id: regex string - to use for account_name
        :param account_name: regex - to use for account ID
        :param search: boolean - specify whether to use match or search when filtering the returned list
        :return: list of account names
        """
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        if account_id and not re.match("\d{12}", account_id):
            if not account_name:
                account_name = account_id
                account_id = None
        self.log.debug('Attempting to fetch all accounts matching- account_id:' +
                          str(account_id) + ' account_name:' + str(account_name))
        response = self.get_response_items('ListAccounts', {}, item_marker='accounts',
                                            list_marker='Accounts')
        retlist = []
        for account in response:
            if account_name is not None:
                if not search:
                    account_name = "^{0}$".format(account_name.strip())
                if not re_meth(account_name, account['account_name']):
                    continue
            if account_id is not None:
                if not search:
                    account_id = "{0}".format(account_id.strip())
                if not re_meth(account['account_id'], account_id):
                    continue
            retlist.append(account)
        return retlist

    def get_account(self, account_id=None, account_name=None, search=False):
        """
        Request a specific account, returns an account dict that matches the given criteria

        :param account_id: regex string - to use for account_name
        :param account_name: regex - to use for account ID
        :param search: boolean - specify whether to use match or search when filtering the returned list
        :return: account dict
        """
        if not (account_id or account_name):
            aliases = self.get_account_aliases()
            if aliases:
                account_name = aliases[0]
            else:
                raise ValueError('get_account(). Account id, name, or alias not found')
        accounts = self.get_all_accounts(account_id=account_id, account_name=account_name,
                                         search=search)
        if accounts:
            if len(accounts) > 1:
                raise ValueError('get_account matched more than a single account with the '
                                 'provided criteria: account_id="{0}", account_name="{1}". '
                                 'Matched:{2}'
                                 .format(account_id, account_name,
                                         ", ".join(str(x) for x in accounts)))
            else:
                return accounts[0]
        return None


    def create_user(self, user_name, path="/", delegate_account=None, ignore_existing=True):
        """
        Create a user

        :param user_name: str name of user
        :param path: str user path
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an account to operate on
        """
        if not user_name:
            # Assuming this could be part of a test, allow it but warn...
            self.log.warning('create_user(). Passed unsupported user_name:"{0}"'
                                .format(user_name))
        params = {'UserName': user_name,
                  'Path': path }
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        try:
            res = self.get_response_items('CreateUser', params, item_marker='user')
            self.log.debug('Created user:"{0}"'.format(user_name))
        except BotoServerError as BE:
            if not (BE.status == 409 and ignore_existing):
                raise
            res = self.get_user(user_name=user_name, delegate_account=delegate_account)
            self.log.debug("create_user(). User already exists: " + user_name)
        return res


    def get_user(self, user_name=None, delegate_account=None):
        params = {}
        if user_name:
            params['UserName'] = user_name
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        return self.get_response_items('GetUser', params, item_marker='user')

    
    def delete_user(self, user_name, delegate_account=None):
        """
        Delete a user

        :param user_name: str name of user
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an account to operate on
        """
        self.log.debug("Deleting user " + user_name)
        params = {'UserName': user_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.connection.get_response('DeleteUser', params)

    def get_users_from_account(self, path=None, user_name=None, user_id=None,
                               delegate_account=None, search=False):
        """
        Returns access that match given criteria. By default will return current account.

        :param path: regex - to match for path
        :param user_name: str name of user
        :param user_id: regex - to match for user_id
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an account to operate on
        :param search: use regex search (any occurrence) rather than match (exact same strings must occur)
        :return:
        """
        self.log.debug('Attempting to fetch all access matching- user_id:' +
                          str(user_id) + ' user_name:' + str(user_name) + " acct_name:" +
                          str(delegate_account))
        retlist = []
        params = {}
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        if delegate_account:
            params['DelegateAccount'] = delegate_account         
        response = self.get_response_items('ListUsers', params, item_marker='users',
                                               list_marker='Users')
        for user in response:
            if path is not None and not re_meth(path, user['path']):
                continue
            if user_name is not None and not re_meth(user_name, user['user_name']):
                continue
            if user_id is not None and not re_meth(user_id, user['user_id']):
                continue
            retlist.append(user)
        return retlist

    def show_all_accounts(self, account_name=None, account_id=None, search=False,
                          print_table=True):
        """
        Debug Method to print an account list based on given filter criteria

        :param account_name: regex - to use for account_name
        :param account_id: regex - to use for account_id
        :param search: boolean - specify whether to use match or search when filtering the returned list
        """
        pt = PrettyTable(['ACCOUNT_NAME', 'ACCOUNT_ID'])
        pt.hrules = 1
        pt.align = 'l'
        list = self.get_all_accounts(account_name=account_name,
                                     account_id=account_id,
                                     search=search)
        for account in list:
            pt.add_row([account['account_name'], account['account_id']])
        if print_table:
            self.log.info("\n" + str(pt) + "\n")
        else:
            return pt


    def show_all_groups(self, account_name=None,  account_id=None,  path=None,
                        group_name=None,  group_id=None,  search=False, print_table=True):
        """
        Print all groups in an account

        :param account_name: regex - to use for account_name
        :param account_id: regex - to use for
        :param path: regex - to match for path
        :param group_name: regex - to match for user_name
        :param group_id: regex - to match for user_id
        :param search:  boolean - specify whether to use match or search when filtering the returned list
        """
        pt = PrettyTable(['ACCOUNT:', 'GROUPNAME:', 'GROUP_ID:'])
        pt.hrules = 1
        pt.align = 'l'
        list = self.get_all_groups(account_name=account_name, account_id=account_id,
                                   path=path, group_name=group_name, group_id=group_id,
                                   search=search)
        for group in list:
            pt.add_row([group['account_name'], group['group_name'], group['group_id']])
        if print_table:
            self.log.info("\n" + str(pt) + "\n")
        else:
            return pt


    def show_all_users(self, account_name=None, account_id=None,  path=None, user_name=None,
                       user_id=None, search=False, print_table=True ):
        """
        Debug Method to print a user list based on given filter criteria

        :param account_name: regex - to use for account_name
        :param account_id: regex - to use for
        :param path: regex - to match for path
        :param user_name: regex - to match for user_name
        :param user_id: regex - to match for user_id
        :param search: boolean - specify whether to use match or search when filtering the returned list
        """
        pt = PrettyTable(['ACCOUNT:', 'USERNAME:', 'USER_ID', 'ACCT_ID'])
        pt.hrules = 1
        pt.align = 'l'
        list = self.get_all_users(account_name=account_name, account_id=account_id, path=path,
                                  user_name=user_name, user_id=user_id, search=search)
        for user in list:
            pt.add_row([user['account_name'], user['user_name'],
                        user['user_id'], user['account_id']])
        if print_table:
            self.log.info("\n" + str(pt) + "\n")
        else:
            return pt

    def get_account_aliases(self, delegate_account=None):
        params = {}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        resp = self.get_response_items('ListAccountAliases', params,
                                           item_marker='account_aliases',
                                           list_marker='AccountAliases') or []
        return resp


    def get_username_for_active_connection(self):
        """
        Helper method to show the active connections username in the case that the active
        context is not this IAMops class's connection/context.
        """
        user_info = self.get_user_info()
        return  getattr(user_info, 'user_name', None)

    def get_accountname_for_active_connection(self):
        """
        Helper method to show the active connections account name/alias in the case that the active
        context is not this IAMops class's connection/context.
        """
        aliases = self.get_account_aliases()
        if aliases:
            return aliases[0]
        return None

    def get_username_eucarc(self):
        if self.eucarc:
            return self.eucarc.user_name
        return None

    def get_accountname_eucarc(self):
        if self.eucarc:
            return self.eucarc.account_name
        return None
    
    def get_connections_accountname(self):
        """
        Get account name of current user
        """
        account_info = self.get_account()
        return  getattr(account_info, 'account_name', None)

    def get_all_users(self,  account_name=None,  account_id=None,  path=None,
                      user_name=None,  user_id=None,  search=False ):
        """
        Queries all accounts matching given account criteria, returns all access found within
        these accounts which then match the given user criteria.
        Account info is added to the user dicts

        :param account_name: regex - to use for account name
        :param account_id: regex - to use for account id
        :param path: regex - to match for path
        :param user_name: regex - to match for user name
        :param user_id: regex - to match for user id
        :param search: boolean - specify whether to use match or search when filtering the
                      returned list
        :return: List of access with account name tuples
        """
        userlist=[]
        accounts = self.get_all_accounts(account_id=account_id, account_name=account_name,
                                         search=search)
        for account in accounts:
            #if account['account_id'] == self.account_id:
            #    access =self.get_users_from_account()
            #else:
            if account.get('account_id') == self.eucarc.account_id:
                delegate_account = None
            else:
                delegate_account = account['account_name']
            users = self.get_users_from_account(path=path,
                                                user_name=user_name,
                                                user_id=user_id,
                                                delegate_account=delegate_account,
                                                search=search)
            for user in users:
                user['account_name']=account['account_name']
                user['account_id']=account['account_id']
                userlist.append(user)
        return userlist

    def get_user_policy_names(self, user_name, policy_name=None, delegate_account=None,
                              search=False, ignore_admin_err=True):
        """
        Returns list of policy names associated with a given user, and match given criteria.

        :param user_name: string - user to get policies for.
        :param policy_name: regex - to match/filter returned policies
        :param delegate_account: string - used for user lookup
        :param search: specify whether to use match or search when filtering the returned list
        :return: list of policy names
        """
        retlist = []
        params = {}
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        params = {'UserName': user_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        try:
            response = self.connection.get_response('ListUserPolicies', params,
                                                    list_marker='PolicyNames')
            p_names = response['list_user_policies_response']['list_user_policies_result']\
                              ['policy_names']
            for name in p_names:
                if policy_name is not None and not re_meth(policy_name, name):
                    continue
                retlist.append(name)
        except BotoServerError, BE:
            err = 'Error fetching policy for params:\n{0}: '.format(params, BE)
            if BE.status == 403 and ignore_admin_err and str(user_name).strip() == 'admin':
                self.log.debug('IGNORING: '+ err)
            else:
                self.log.critical(err)
                raise
        return retlist

    def get_user_policies(self, user_name, policy_name=None, delegate_account=None, doc=None,
                          search=False, ignore_admin_err=True):
        """
        Returns list of policy dicts associated with a given user, and match given criteria.

        :param user_name: string - user to get policies for.
        :param policy_name: regex - to match/filter returned policies
        :param delegate_account: string - used for user lookup
        :param doc: policy document to use as a filter
        :param search: boolean - specify whether to use match or search when filtering the
                                 returned list
        :param ignore_admin_err: boolean- will ignore 403 responses if the user is 'admin'
        :return:
        """
        retlist = []
        params = {}
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        try:
            names = self.get_user_policy_names(user_name, policy_name=policy_name,
                                               delegate_account=delegate_account, search=search)
            for p_name in names:
                params = {'UserName': user_name,
                          'PolicyName': p_name}
                if delegate_account:
                    params['DelegateAccount'] = delegate_account
                policy = self.connection.get_response(
                            'GetUserPolicy',
                            params,
                            verb='POST')['get_user_policy_response']['get_user_policy_result']
                if doc is not None and not re_meth(doc, policy['policy_document']):
                    continue
                retlist.append(policy)
        except BotoServerError as BE:
            err_msg = 'Error fetching policy using params:\n{0}:"{1}:{2}"'\
                .format(params, BE.status, BE.message)
            if BE.status == 403 and ignore_admin_err and str(user_name).strip() == 'admin':
                self.log.debug('IGNORING:' + str(err_msg))
            else:
                self.log.critical(err_msg)
                raise
        return retlist

    def show_user_policy_summary(self,user_name,policy_name=None,delegate_account=None,
                                 doc=None, search=False, print_table=True):
        """
        Debug method to display policy summary applied to a given user

        :param user_name: string - user to get policies for.
        :param policy_name: regex - to match/filter returned policies
        :param delegate_account: string - used for user lookup
        :param doc: policy document to use as a filter
        :param search: boolean - specify whether to use match or search when filtering the returned list
        """
        title = 'POLICIES FOR USER: {0}'.format(user_name)
        main_pt = PrettyTable([title])
        main_pt.hrules = 1
        main_pt.align = 'l'
        main_pt.max_width[title] = 120
        policies = self.get_user_policies(user_name, policy_name=policy_name,
                                          delegate_account=delegate_account, doc=doc, search=search)
        if not policies:
            main_pt.add_row(['-- No Policies --'])
        else:
            for policy in policies:
                main_pt.add_row(['POLICY NAME: "{0}" :'.format(policy['policy_name'])])
                p_doc = urllib.unquote(policy['policy_document'])
                p_json = json.loads(p_doc)
                pretty_json = (json.dumps(p_json, indent=2) or "") + "\n"
                main_pt.add_row([pretty_json])
        if print_table:
            self.log.info("\n" + str(main_pt) + "\n")
        else:
            return main_pt

    def show_user_summary(self,user_name=None, delegate_account=None, account_id=None,
                          print_table=True):
        """
        Debug method for to display euare/iam info for a specific user.

        :param user_name: string - user to get policies for.
        :param delegate_account: string - used for user lookup
        :param account_id: regex - to use for account id
        """
        if not user_name and self._user_context and self._user_context.user_name:
            user_name = self._user_context.user_name
        else:
            raise ValueError('No user_name provided or found for this connection')
        if delegate_account is None:
            account_id=self.eucarc.account_id
            delegate_account= self.get_all_accounts(account_id=account_id)[0]['account_name']
        self.log.debug('Fetching user summary for: user_name:' + str(user_name) +
                   " account:" + str(delegate_account) + " account_id:" + str(account_id))
        title = 'USER SUMMARY: user:{0}, account:{1}'.format(user_name, delegate_account)
        pt = PrettyTable([title])
        pt.align ='l'
        user_table = str(self.show_all_users(account_name=delegate_account, account_id=account_id,
                                      user_name=user_name, print_table=False)) + "\n"
        pt.add_row([user_table])

        pol_pt = self.show_user_policy_summary(user_name, delegate_account=delegate_account,
                                      print_table=False)
        new_title = str(pol_pt._field_names[0]).center(len(user_table.splitlines()[0])-4)
        new_pt = PrettyTable([new_title])
        new_pt.align[new_title] = 'l'
        new_pt.hrules = 1
        new_pt._rows = pol_pt._rows
        pt.add_row([new_pt])
        if print_table:
            self.log.info("\n" + str(pt) + "\n")
        else:
            return pt

    
    def attach_policy_user(self, user_name, policy_name, policy_json, delegate_account=None):
        """
        Attach a policy string to a user

        :param user_name: string - user to apply policy to
        :param policy_name: Name to upload policy as
        :param policy_json: Policy text
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an account to operate on
        """
        self.log.debug("Attaching the following policy to " + user_name + ":" + policy_json)
        params = {'UserName': user_name,
                  'PolicyName': policy_name,
                  'PolicyDocument': policy_json}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.connection.get_response('PutUserPolicy', params, verb='POST')
    
    def detach_policy_user(self, user_name, policy_name, delegate_account=None):
        """
        Detach a policy from user

        :param user_name: string - user to apply policy to
        :param policy_name: Name to upload policy as
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.log.debug("Detaching the following policy from " + user_name + ":" + policy_name)
        params = {'UserName': user_name,
                  'PolicyName': policy_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.connection.get_response('DeleteUserPolicy', params, verb='POST')

    def get_all_groups(self, account_name=None, account_id=None, path=None, group_name=None,
                       group_id=None, search=False ):
        """
        Queries all accounts matching given account criteria, returns all groups found within
        these accounts which then match the given user criteria.
        Account info is added to the group dicts

        :param account_name: regex - to use for account_name
        :param account_id: regex - to use for
        :param path: regex - to match for path
        :param group_name: regex - to match for group_name
        :param group_id: regex - to match for group_id
        :param search: boolean - specify whether to use match or search when filtering the
                                 returned list
        :return:
        """
        grouplist=[]
        accounts = self.get_all_accounts(account_id=account_id, account_name=account_name,
                                         search=search)
        for account in accounts:
            groups = self.get_groups_from_account(path=path,
                                                  group_name=group_name,
                                                  group_id=group_id,
                                                  delegate_account=account['account_name'],
                                                  search=search)
            for group in groups:
                group['account_name']=account['account_name']
                group['account_id']=account['account_id']
                grouplist.append(group)
        return grouplist

    def get_groups_from_account(self, path=None, group_name=None, group_id=None,
                                delegate_account=None, search=False):
        """
        Returns groups that match given criteria. By default will return groups from
        current account.

        :param path: regex - to match for path
        :param group_name: regex - to match for group_name
        :param group_id: regex - to match for group_id
        :param delegate_account: string - to use for delegating account lookup
        :param search: specify whether to use match or search when filtering the returned list
        :return:
        """
        self.log.debug('Attempting to fetch all groups matching- group_id:' + str(group_id) +
                   ' group_name:' + str(group_name) + " acct_name:" + str(delegate_account))
        retlist = []
        params = {}
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        if delegate_account:
            params['DelegateAccount'] = delegate_account         
        response = self.connection.get_response('ListGroups', params, list_marker='Groups')
        for group in response['list_groups_response']['list_groups_result']['groups']:
            if path is not None and not re_meth(path, group['path']):
                continue
            if group_name is not None and not re_meth(group_name, group['group_name']):
                continue
            if group_id is not None and not re_meth(group_id, group['group_id']):
                continue
            retlist.append(group)
        return retlist

    def get_users_from_group(self, group_name, delegate_account=None):
        """
        :param group_name: name of the group whose access should be returned.
        :param delegate_account: specific account name when method is being called from
                                 eucalyptus admin user.
        :return: list of access of an IAM group.
        """
        ret_list = []
        params = {}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        params['GroupName'] = group_name
        response = self.connection.get_response('GetGroup', params, list_marker='Users')
        for user in response['get_group_response']['get_group_result']['access']:
            ret_list.append(user)
        return ret_list

    def get_group_policy_names(self, group_name, policy_name=None,delegate_account=None,
                               search=False):
        """
        Returns list of policy names associated with a given group, and match given criteria.

        :param group_name: string - group to get policies for.
        :param policy_name: regex - to match/filter returned policies
        :param delegate_account: string - used for group lookup
        :param search: specify whether to use match or search when filtering the returned list
        :return: list of policy names
        """
        retlist = []
        params = {}
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        params = {'GroupName': group_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        response = self.connection.get_response('ListGroupPolicies',
                                                params, list_marker='PolicyNames')
        for name in response['list_group_policies_response']['list_group_policies_result']\
                ['policy_names']:
            if policy_name is not None and not re_meth(policy_name, name):
                continue
            retlist.append(name)
        return retlist

    def get_group_policies(self, group_name, policy_name=None,delegate_account=None, doc=None,
                           search=False):
        """
        Returns list of policy dicts associated with a given group, and match given criteria.

        :param group_name: string - group to get policies for.
        :param policy_name: regex - to match/filter returned policies
        :param delegate_account: string - used for group lookup
        :param doc: policy document to use as a filter
        :param search: boolean - specify whether to use match or search when filtering the
                                 returned list
        :return:
        """
        retlist = []
        params = {}
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        names = self.get_group_policy_names(group_name, policy_name=policy_name,
                                            delegate_account=delegate_account, search=search)

        for p_name in names:
            params = {'GroupName': group_name,
                      'PolicyName': p_name}
            if delegate_account:
                params['DelegateAccount'] = delegate_account
            policy = self.connection.get_response('GetGroupPolicy', params, verb='POST')\
                ['get_group_policy_response']['get_group_policy_result']
            if doc is not None and not re_meth(doc, policy['policy_document']):
                continue
            retlist.append(policy)
        return retlist
    
    def create_group(self, group_name,path="/", delegate_account=None):
        """
        Create group.

        :param
        :param path: path for group
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.log.debug("Attempting to create group: " + group_name)
        params = {'GroupName': group_name,
                  'Path': path}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.connection.get_response('CreateGroup', params)
    
    def delete_group(self, group_name, delegate_account=None):
        """
        Delete group.

        :param group_name: name of group to delete
        :param delegate_account:
        """
        self.log.debug("Deleting group " + group_name)
        params = {'GroupName': group_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.connection.get_response('DeleteGroup', params)
    
    def add_user_to_group(self, group_name, user_name, delegate_account=None):
        """
        Add a user to a group.

        :param group_name: name of group to add user to
        :param user_name: name of user to add to group
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.log.debug("Adding user "  +  user_name + " to group " + group_name)
        params = {'GroupName': group_name,
                  'UserName': user_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.connection.get_response('AddUserToGroup', params)
    
    def remove_user_from_group(self, group_name, user_name, delegate_account=None):
        """
        Remove a user from a group.

        :param group_name: name of group to remove user from
        :param user_name: name of user to remove from group
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.log.debug("Removing user "  +  user_name + " to group " + group_name)
        params = {'GroupName': group_name,
                  'UserName': user_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.connection.get_response('RemoveUserFromGroup', params)
    
    def attach_policy_group(self, group_name, policy_name, policy_json, delegate_account=None):
        """
        Attach a policy to a group.

        :param group_name: name of group to remove user from
        :param policy_name: Name to upload policy as
        :param policy_json: Policy text
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.log.debug("Attaching the following policy to " + group_name + ":" + policy_json)
        params = {'GroupName': group_name,
                  'PolicyName': policy_name,
                  'PolicyDocument': policy_json}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.connection.get_response('PutGroupPolicy', params, verb='POST')
    
    def detach_policy_group(self, group_name, policy_name, delegate_account=None):
        """
        Remove a policy from a group.

        :param group_name: name of group to remove user from
        :param policy_name: Name to upload policy as
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.log.debug("Detaching the following policy from " + group_name + ":" + policy_name)
        params = {'GroupName': group_name,
                  'PolicyName': policy_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.connection.get_response('DeleteGroupPolicy', params, verb='POST')
    
    def create_access_key(self, user_name=None, delegate_account=None):
        """
        Create a new access key for the user.

        :param user_name: Name of user to create access key for to
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        :return: A tuple of access key and and secret key with keys: 'access_key_id' and
                'secret_access_key'
        """
        self.log.debug("Creating access key for " + user_name )
        params = {'UserName': user_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        response = self.connection.get_response('CreateAccessKey', params)
        access_tuple = {}
        access_tuple['access_key_id'] = response['create_access_key_response']\
            ['create_access_key_result']['access_key']['access_key_id']
        access_tuple['secret_access_key'] = response['create_access_key_response']\
            ['create_access_key_result']['access_key']['secret_access_key']
        return access_tuple

    def get_aws_access_key(self, user_name=None, delegate_account=None):
        if not user_name and not delegate_account and self.connection.aws_access_key_id:
            aws_access_key = self.connection.aws_access_key_id or self.eucarc.aws_access_key
            if aws_access_key:
                return  aws_access_key
        params = {}
        if user_name:
            params['UserName'] = user_name
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        response = self.get_response_items('ListAccessKeys', params, item_marker='member')
        #result = response['list_access_keys_response']['list_access_keys_result']
        #return result['access_key_metadata']['member']['access_key_id']
        return response

    def create_signing_cert(self, user_name=None, delegate_account=None):
        params = {}
        if user_name:
            params['UserName'] = user_name
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        response = self.get_response_items('CreateSigningCertificate', params,
                                           item_marker='certificate')

    def delete_signing_cert(self, cert_id, user_name=None, delegate_account=None):
        params = {'CertificateId': cert_id}
        if user_name:
            params['UserName'] = user_name
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        return self.connection.get_response('DeleteSigningCertificate', params)

    def delete_all_signing_certs(self, user_name=None, delegate_account=None, verbose=False):
        for cert in self.get_all_signing_certs(user_name=user_name,
                                               delegate_account=delegate_account):
            certid = cert.get('certificate_id')
            if certid:
                if verbose:
                    self.log.debug('Deleting signing cert: "{0}"'.format(cert))
                self.delete_signing_cert(certid, user_name=user_name,
                                         delegate_account=delegate_account)
            else:
                raise ValueError('certificate_id not found for cert dict:"{0}"'.format(cert))


    def get_all_signing_certs(self, marker=None, max_items=None,
                              user_name=None, delegate_account=None):
        params = {}
        if marker:
            params['Marker'] = marker
        if max_items:
            params['MaxItems'] = max_items
        if user_name:
            params['UserName'] = user_name
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        return self.get_response_items('ListSigningCertificates',
                                       params, item_marker='certificates',
                                       list_marker='Certificates')


    def get_active_id_for_cert(self, certpath, machine):
        '''
        Attempt to get the cloud's active id for a certificate at 'certpath' on
        the 'machine' filesystem. Also see is_ec2_cert_active() for validating the current
        cert in use or the body (string buffer) of a cert.
        :param certpath: string representing the certificate path on the machines filesystem
        :param machine: Machine obj which certpath exists on
        :returns :str() certificate id (if cert is found to be active) else None
        '''
        if not certpath:
            raise ValueError('No ec2 certpath provided or set for eutester obj')
        self.log.debug('Verifying cert: "{0}"...'.format(certpath))
        body = str("\n".join(machine.sys('cat {0}'.format(certpath), verbose=False)) ).strip()
        certs = []
        if body:
            certs = self.get_all_signing_certs()
        for cert in certs:
            if str(cert.get('certificate_body')).strip() == body:
                self.log.debug('verified certificate with id "{0}" is still valid'
                           .format(cert.get('certificate_id')))
                return cert.get('certificate_id')
        self.log.debug('Cert: "{0}" is NOT active'.format(certpath or body))
        return None

    def find_active_cert_and_key_in_dir(self, machine, dir="", recursive=True):
        '''
        Attempts to find an "active" cert and the matching key files in the provided
        directory 'dir' on the provided 'machine' via ssh.
        If recursive is enabled, will attempt a recursive search from the provided directory.
        :param dir: the base dir to search in on the machine provided
        :param machine: a Machine() obj used for ssh search commands
        :param recursive: boolean, if set will attempt to search recursively from the dir provided
        :returns dict w/ values 'certpath' and 'keypath' or {} if not found.
        '''
        ret_dict = {}
        if dir and not dir.endswith("/"):
            dir += "/"
        if recursive:
            rec = "r"
        else:
            rec = ""
        certfiles = machine.sys('grep "{0}" -l{1} {2}*.pem'.format('^-*BEGIN CERTIFICATE', rec, dir))
        for f in certfiles:
            if self.get_active_id_for_cert(f, machine=machine):
                dir = os.path.dirname(f)
                keypath = self.get_key_for_cert(certpath=f, keydir=dir, machine=machine)
                if keypath:
                    self.log.debug('Found existing active cert and key on clc: {0}, {1}'
                                      .format(f, keypath))
                    return {'certpath':f, 'keypath':keypath}
        return ret_dict

    def get_key_for_cert(self, certpath, keydir, machine, recursive=True):
        '''
        Attempts to find a matching key for cert at 'certpath' in the provided directory 'dir'
        on the provided 'machine'.
        If recursive is enabled, will attempt a recursive search from the provided directory.
        :param dir: the base dir to search in on the machine provided
        :param machine: a Machine() obj used for ssh search commands
        :param recursive: boolean, if set will attempt to search recursively from the dir provided
        :returns string representing the path to the key found or None if not found.
        '''
        self.log.debug('Looking for key to go with cert...')
        if keydir and not keydir.endswith("/"):
            keydir += "/"
        if recursive:
            rec = "r"
        else:
            rec = ""
        certmodmd5 = machine.sys('openssl x509 -noout -modulus -in {0}  | md5sum'
                                 .format(certpath))
        if certmodmd5:
            certmodmd5 = str(certmodmd5[0]).strip()
        else:
            return None
        keyfiles = machine.sys('grep "{0}" -lz{1} {2}*.pem'
                               .format("^\-*BEGIN RSA PRIVATE KEY.*\n.*END RSA PRIVATE KEY\-*",
                                       rec, keydir))
        for kf in keyfiles:
            keymodmd5 = machine.sys('openssl rsa -noout -modulus -in {0} | md5sum'.format(kf))
            if keymodmd5:
                keymodmd5 = str(keymodmd5[0]).strip()
            if keymodmd5 == certmodmd5:
                self.log.debug('Found key {0} for cert {1}'.format(kf, certpath))
                return kf
        return None

    def is_ec2_cert_active(self, certbody=None):
        '''
        Attempts to verify if the current self.ec2_cert @ self.ec2_certpath is still active.
        :param certbody
        :returns the cert id if found active, otherwise returns None
        '''
        certbody = certbody or self.ec2_cert
        if not certbody:
            raise ValueError('No ec2 cert body provided or set for eutester to check for active')
        if isinstance(certbody, dict):
            checkbody = certbody.get('certificate_body')
            if not checkbody:
                raise ValueError('Invalid certbody provided, did not have "certificate body" attr')
        for cert in self.get_all_signing_certs():
            body = str(cert.get('certificate_body')).strip()
            if body and body == str(certbody).strip():
                return cert.get('certificate_id')
        return None


    def upload_server_cert(self, cert_name, cert_body, private_key):
        self.log.debug("uploading server certificate: " + cert_name)
        self.upload_server_cert(cert_name=cert_name, cert_body=cert_body,
                                           private_key=private_key)
        if cert_name not in str(self.connection.get_server_certificate(cert_name)):
            raise Exception("certificate " + cert_name + " not uploaded")

    def update_server_cert(self, cert_name, new_cert_name=None, new_path=None):
        self.log.debug("updating server certificate: " + cert_name)
        self.connection.update_server_cert(cert_name=cert_name,
                                                          new_cert_name=new_cert_name,
                                                          new_path=new_path)
        if (new_cert_name and new_path) not in \
                str(self.connection.get_server_certificate(new_cert_name)):
            raise Exception("certificate " + cert_name + " not updated.")

    def get_server_cert(self, cert_name):
        self.log.debug("getting server certificate: " + cert_name)
        cert = self.connection.get_server_certificate(cert_name=cert_name)
        self.log.debug(cert)
        return cert

    def delete_server_cert(self, cert_name):
        self.log.debug("deleting server certificate: " + cert_name)
        self.connection.delete_server_cert(cert_name)
        if (cert_name) in str(self.connection.get_all_server_certs()):
            raise Exception("certificate " + cert_name + " not deleted.")

    def list_server_certs(self, path_prefix='/', marker=None, max_items=None):
        self.log.debug("listing server certificates")
        certs = self.connection.list_server_certs(path_prefix=path_prefix,
                                                      marker=marker, max_items=max_items)
        self.log.debug(certs)
        return certs

    def create_login_profile(self, user_name, password, delegate_account=None):
        self.log.debug("Creating login profile for: " + user_name + " with password: " + password)
        params = {'UserName': user_name,
                  'Password': password}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        return self.connection.get_response('CreateLoginProfile', params, verb='POST')

    @staticmethod
    def _search_dict(dictionary, marker):
        if marker in dictionary.keys():
            return dictionary.get(marker)
        else:
            for value in dictionary.itervalues():
                if isinstance(value, dict):
                    res = IAMops._search_dict(value, marker)
                    if res:
                        return res
        return {}

    def get_response_items(self, action, params, item_marker, path='/', parent=None,
                               verb='POST', list_marker='Set'):
        if list_marker is None:
            list_marker = 'Set'
        resp = self.connection.get_response(action=action, params=params, path=path, parent=parent,
                                 verb=verb, list_marker=list_marker)
        return IAMops._search_dict(resp, item_marker)

    def get_user_info(self, user_name=None, delegate_account=None):
        params = {}
        if user_name:
            params['UserName'] = user_name
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        return self.get_response_items(action='GetUser', params=params,
                                                  item_marker='user', list_marker='user')


class IAMResourceNotFoundException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
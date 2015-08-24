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
import re
import urllib
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.file_utils.eucarc import Eucarc
from urlparse import urlparse
from prettytable import PrettyTable
from nephoria import TestConnection


class IAMops(TestConnection, IAMConnection):
    EUCARC_URL_NAME = 'iam_url'
    def __init__(self, eucarc=None, credpath=None, context_mgr=None,
                 aws_access_key_id=None, aws_secret_access_key=None,
                 is_secure=False, port=None, host=None, region=None, endpoint=None,
                 boto_debug=0, path=None, APIVersion=None, validate_certs=None,
                 test_resources=None, logger=None):

        # Init test connection first to sort out base parameters...
        TestConnection.__init__(self,
                                eucarc=eucarc,
                                credpath=credpath,
                                context_mgr=context_mgr,
                                test_resources=test_resources,
                                logger=logger,
                                aws_access_key_id=aws_access_key_id,
                                aws_secret_access_key=aws_secret_access_key,
                                is_secure=is_secure,
                                port=port,
                                host=host,
                                APIVersion=APIVersion,
                                validate_certs=validate_certs,
                                boto_debug=boto_debug,
                                path=path)
        if self.boto_debug:
            self.show_connection_kwargs()
        # Init IAM connection...
        try:
            IAMConnection.__init__(self, **self._connection_kwargs)
        except:
            self.show_connection_kwargs()
            raise


    def create_account(self, account_name):
        """
        Create an account with the given name

        :param account_name: str name of account to create
        """
        self.logger.debug("Creating account: " + account_name)
        params = {'AccountName': account_name}
        self.test_resource["iam_accounts"].append(account_name)
        self.get_response('CreateAccount', params)
    
    def delete_account(self, account_name, recursive=False):
        """
        Delete an account with the given name

        :param account_name: str name of account to delete
        :param recursive:
        """
        self.logger.debug("Deleting account: " + account_name)
        params = {
            'AccountName': account_name,
            'Recursive': recursive
        }
        self.get_response('DeleteAccount', params)

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
        self.logger.debug('Attempting to fetch all accounts matching- account_id:'+str(account_id)+' account_name:'+str(account_name))
        response = self.get_response('ListAccounts', {}, list_marker='Accounts')
        retlist = []
        for account in response['list_accounts_response']['list_accounts_result']['accounts']:
            if account_name is not None and not re_meth( account_name, account['account_name']):
                continue
            if account_id is not None and not re_meth(account_id, account['account_id']):
                continue
            retlist.append(account)
        return retlist
             
    def create_user(self, user_name, path="/", delegate_account=None):
        """
        Create a user

        :param user_name: str name of user
        :param path: str user path
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an account to operate on
        """
        self.logger.debug("Attempting to create user: " + user_name)
        params = {'UserName': user_name,
                  'Path': path }
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('CreateUser',params)
    
    def delete_user(self, user_name, delegate_account=None):
        """
        Delete a user

        :param user_name: str name of user
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an account to operate on
        """
        self.logger.debug("Deleting user " + user_name)
        params = {'UserName': user_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('DeleteUser', params)

    def get_users_from_account(self, path=None, user_name=None, user_id=None, delegate_account=None, search=False):
        """
        Returns access that match given criteria. By default will return current account.

        :param path: regex - to match for path
        :param user_name: str name of user
        :param user_id: regex - to match for user_id
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an account to operate on
        :param search: use regex search (any occurrence) rather than match (exact same strings must occur)
        :return:
        """
        self.logger.debug('Attempting to fetch all access matching- user_id:'+str(user_id)+' user_name:'+str(user_name)+" acct_name:"+str(delegate_account))
        retlist = []
        params = {}
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        if delegate_account:
            params['DelegateAccount'] = delegate_account         
        response = self.get_response('ListUsers', params, list_marker='Users')
        for user in response['list_users_response']['list_users_result']['access']:
            if path is not None and not re_meth(path, user['path']):
                continue
            if user_name is not None and not re_meth(user_name, user['user_name']):
                continue
            if user_id is not None and not re_meth(user_id, user['user_id']):
                continue
            retlist.append(user)
        return retlist

    def show_all_accounts(self, account_name=None, account_id=None, search=False, print_table=True):
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
            self.logger.debug("\n" + str(pt) + "\n")
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
            self.logger.debug("\n" + str(pt) + "\n")
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
            self.logger.debug("\n" + str(pt) + "\n")
        else:
            return pt

    def get_euare_username(self):
        """
        Get all access in the current access account
        """
        return self.get_all_users(account_id=str(self.get_account_id()))[0]['user_name']
    
    def get_euare_accountname(self):
        """
        Get account name of current user
        """
        return self.get_all_users(account_id=str(self.get_account_id()))[0]['account_name']

    def get_all_users(self,  account_name=None,  account_id=None,  path=None,
                      user_name=None,  user_id=None,  search=False ):
        """
        Queries all accounts matching given account criteria, returns all access found within these accounts which then match the given user criteria.
        Account info is added to the user dicts

        :param account_name: regex - to use for account name
        :param account_id: regex - to use for account id
        :param path: regex - to match for path
        :param user_name: regex - to match for user name
        :param user_id: regex - to match for user id
        :param search: boolean - specify whether to use match or search when filtering the returned list
        :return: List of access with account name tuples
        """
        userlist=[]
        accounts = self.get_all_accounts(account_id=account_id, account_name=account_name,
                                         search=search)
        for account in accounts:
            #if account['account_id'] == self.account_id:
            #    access =self.get_users_from_account()
            #else:
            users = self.get_users_from_account(path=path,
                                                user_name=user_name,
                                                user_id=user_id,
                                                delegate_account=account['account_name'],
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
            response = self.get_response('ListUserPolicies', params,
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
                self.logger.debug('IGNORING: '+ err)
            else:
                self.critical(err)
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
        names = self.get_user_policy_names(user_name, policy_name=policy_name,
                                           delegate_account=delegate_account, search=search)
        for p_name in names:
            params = {'UserName': user_name,
                      'PolicyName': p_name}
            if delegate_account:
                params['DelegateAccount'] = delegate_account
            try:
                policy = self.get_response(
                    'GetUserPolicy',
                    params,
                    verb='POST')['get_user_policy_response']['get_user_policy_result']
            except BotoServerError, BE:
                err_msg = 'Error fetching policy for params:\n{0}: "{1}"'.format(params, BE)
                if BE.status == 403 and ignore_admin_err and str(p_name).strip() == 'admin':
                    self.logger.debug('IGNORING:' + str(err_msg))
                else:
                    self.logger.critical(err_msg)
                    raise
            if doc is not None and not re_meth(doc, policy['policy_document']):
                continue
            retlist.append(policy)
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
            self.logger.debug("\n" + str(main_pt) + "\n")
        else:
            return main_pt

    def show_user_summary(self,user_name, delegate_account=None, account_id=None,
                          print_table=True):
        """
        Debug method for to display euare/iam info for a specific user.

        :param user_name: string - user to get policies for.
        :param delegate_account: string - used for user lookup
        :param account_id: regex - to use for account id
        """
        user_name = user_name
        if delegate_account is None:
            account_id=self.get_account_id()
            delegate_account= self.get_all_accounts(account_id=account_id)[0]['account_name']
        self.logger.debug('Fetching user summary for: user_name:' + str(user_name) +
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
            self.logger.debug("\n" + str(pt) + "\n")
        else:
            return pt


    def show_whoami(self, print_table=True):
        """
        Debug method used to display the who am I info related to iam/euare.
        """

        user= self.get_user()['get_user_response']['get_user_result']['user']

        user_id = user['user_id']
        user_name = user['user_name']
        account_id = self.get_account_id()
        account_name = None
        try:
            account = self.get_all_accounts(account_id=account_id)[0]
            account_name = account['account_name']
        except IndexError:
            self.critical('Failed to lookup account for user:({0}:{1}), account_id:{2}'
                             .format(user_name, user_id, account_id))
        main_pt = PrettyTable(['WHO AM I?  ({0}:{1})'.format(user_name, account_name)])
        main_pt.align = 'l'
        main_pt.add_row([str(self.show_all_users(account_id=account_id, user_id=user_id,
                                                 print_table=False))])
        main_pt.add_row([str(self.show_user_policy_summary(user_name, print_table=False))])
        if print_table:
            self.logger.debug("\n" + str(main_pt) + "\n")
        else:
            return main_pt
        
    
    def attach_policy_user(self, user_name, policy_name, policy_json, delegate_account=None):
        """
        Attach a policy string to a user

        :param user_name: string - user to apply policy to
        :param policy_name: Name to upload policy as
        :param policy_json: Policy text
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an account to operate on
        """
        self.logger.debug("Attaching the following policy to " + user_name + ":" + policy_json)
        params = {'UserName': user_name,
                  'PolicyName': policy_name,
                  'PolicyDocument': policy_json}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('PutUserPolicy', params, verb='POST')
    
    def detach_policy_user(self, user_name, policy_name, delegate_account=None):
        """
        Detach a policy from user

        :param user_name: string - user to apply policy to
        :param policy_name: Name to upload policy as
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.logger.debug("Detaching the following policy from " + user_name + ":" + policy_name)
        params = {'UserName': user_name,
                  'PolicyName': policy_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('DeleteUserPolicy', params, verb='POST')

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
        self.logger.debug('Attempting to fetch all groups matching- group_id:' + str(group_id) +
                   ' group_name:' + str(group_name) + " acct_name:" + str(delegate_account))
        retlist = []
        params = {}
        if search:
            re_meth = re.search
        else:
            re_meth = re.match
        if delegate_account:
            params['DelegateAccount'] = delegate_account         
        response = self.get_response('ListGroups', params, list_marker='Groups')
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
        response = self.get_response('GetGroup', params, list_marker='Users')
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
        response = self.get_response('ListGroupPolicies',
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
            policy = self.get_response('GetGroupPolicy', params, verb='POST')\
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
        self.logger.debug("Attempting to create group: " + group_name)
        params = {'GroupName': group_name,
                  'Path': path}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('CreateGroup', params)
    
    def delete_group(self, group_name, delegate_account=None):
        """
        Delete group.

        :param group_name: name of group to delete
        :param delegate_account:
        """
        self.logger.debug("Deleting group " + group_name)
        params = {'GroupName': group_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('DeleteGroup', params)
    
    def add_user_to_group(self, group_name, user_name, delegate_account=None):
        """
        Add a user to a group.

        :param group_name: name of group to add user to
        :param user_name: name of user to add to group
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.logger.debug("Adding user "  +  user_name + " to group " + group_name)
        params = {'GroupName': group_name,
                  'UserName': user_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('AddUserToGroup', params)
    
    def remove_user_from_group(self, group_name, user_name, delegate_account=None):
        """
        Remove a user from a group.

        :param group_name: name of group to remove user from
        :param user_name: name of user to remove from group
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.logger.debug("Removing user "  +  user_name + " to group " + group_name)
        params = {'GroupName': group_name,
                  'UserName': user_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('RemoveUserFromGroup', params)
    
    def attach_policy_group(self, group_name, policy_name, policy_json, delegate_account=None):
        """
        Attach a policy to a group.

        :param group_name: name of group to remove user from
        :param policy_name: Name to upload policy as
        :param policy_json: Policy text
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.logger.debug("Attaching the following policy to " + group_name + ":" + policy_json)
        params = {'GroupName': group_name,
                  'PolicyName': policy_name,
                  'PolicyDocument': policy_json}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('PutGroupPolicy', params, verb='POST')
    
    def detach_policy_group(self, group_name, policy_name, delegate_account=None):
        """
        Remove a policy from a group.

        :param group_name: name of group to remove user from
        :param policy_name: Name to upload policy as
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        """
        self.logger.debug("Detaching the following policy from " + group_name + ":" + policy_name)
        params = {'GroupName': group_name,
                  'PolicyName': policy_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('DeleteGroupPolicy', params, verb='POST')
    
    def create_access_key(self, user_name=None, delegate_account=None):
        """
        Create a new access key for the user.

        :param user_name: Name of user to create access key for to
        :param delegate_account: str can be used by Cloud admin in Eucalyptus to choose an
                                 account to operate on
        :return: A tuple of access key and and secret key with keys: 'access_key_id' and
                'secret_access_key'
        """
        self.logger.debug("Creating access key for " + user_name )
        params = {'UserName': user_name}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        response = self.get_response('CreateAccessKey', params)
        access_tuple = {}
        access_tuple['access_key_id'] = response['create_access_key_response']\
            ['create_access_key_result']['access_key']['access_key_id']
        access_tuple['secret_access_key'] = response['create_access_key_response']\
            ['create_access_key_result']['access_key']['secret_access_key']
        return access_tuple

    def get_aws_access_key(self, username=None, delegate_account=None):
        if not username and not delegate_account and self.aws_access_key_id:
            aws_access_key = self.aws_access_key_id or self.get_access_key()
            if aws_access_key:
                return  aws_access_key
        params = {}
        if username:
            params['UserName'] = username
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        response = self.get_response('ListAccessKeys', params)
        result = response['list_access_keys_response']['list_access_keys_result']
        return result['access_key_metadata']['member']['access_key_id']


    def upload_server_cert(self, cert_name, cert_body, private_key):
        self.logger.debug("uploading server certificate: " + cert_name)
        self.upload_server_cert(cert_name=cert_name, cert_body=cert_body,
                                           private_key=private_key)
        if cert_name not in str(self.get_server_certificate(cert_name)):
            raise Exception("certificate " + cert_name + " not uploaded")

    def update_server_cert(self, cert_name, new_cert_name=None, new_path=None):
        self.logger.debug("updating server certificate: " + cert_name)
        self.update_server_cert(cert_name=cert_name, new_cert_name=new_cert_name,
                                           new_path=new_path)
        if (new_cert_name and new_path) not in str(self.get_server_certificate(new_cert_name)):
            raise Exception("certificate " + cert_name + " not updated.")

    def get_server_cert(self, cert_name):
        self.logger.debug("getting server certificate: " + cert_name)
        cert = self.get_server_certificate(cert_name=cert_name)
        self.logger.debug(cert)
        return cert

    def delete_server_cert(self, cert_name):
        self.logger.debug("deleting server certificate: " + cert_name)
        self.delete_server_cert(cert_name)
        if (cert_name) in str(self.get_all_server_certs()):
            raise Exception("certificate " + cert_name + " not deleted.")

    def list_server_certs(self, path_prefix='/', marker=None, max_items=None):
        self.logger.debug("listing server certificates")
        certs = self.list_server_certs(path_prefix=path_prefix, marker=marker, max_items=max_items)
        self.logger.debug(certs)
        return certs

    def create_login_profile(self, user_name, password, delegate_account=None):
        self.logger.debug("Creating login profile for: " + user_name + " with password: " + password)
        params = {'UserName': user_name,
                  'Password': password}
        if delegate_account:
            params['DelegateAccount'] = delegate_account
        self.get_response('CreateLoginProfile', params, verb='POST')
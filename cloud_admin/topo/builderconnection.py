import os.path
import yaml
from cloud_admin.access.autocreds import AutoCreds
from cloud_admin.services.adminapi import AdminApi
from cloud_utils.system_utils.machine import Machine


class BuilderConnection(AdminApi):

    def __init__(self,
                 hostname,
                 username='root',
                 password=None,
                 keypath=None,
                 proxy_hostname=None,
                 proxy_username='root',
                 proxy_password=None,
                 proxy_keypath=None,
                 config_yml=None,
                 config_qa=None,
                 credpath=None,
                 aws_access_key=None,
                 aws_secret_key=None,
                 ):
        self.clc_connect_kwargs = {
            'hostname': hostname,
            'username': username,
            'password': password,
            'keypath': keypath,
            'proxy_hostname': proxy_hostname,
            'proxy_username': proxy_username,
            'proxy_password': proxy_password,
            'proxy_keypath': proxy_keypath
        }
        self._clc_machine = None
        self.hostname = hostname
        self.config_qa = config_qa
        self.config_yml = config_yml
        # self._aws_access_key = aws_access_key
        # self._aws_secret_key = aws_secret_key
        self._credpath = credpath
        self._creds = None
        self._creds = AutoCreds(credpath=self._credpath,
                                    aws_access_key=self.aws_access_key,
                                    aws_secret_key=self.aws_secret_key,
                                    **self.clc_connect_kwargs)
        super(BuilderConnection, self).__init__(hostname=hostname,
                                                aws_secret_key=self.creds.aws_secret_key,
                                                aws_access_key=self.creds.aws_access_key)

    @property
    def creds(self):
        if not self._creds:
            self._creds = AutoCreds(credpath=self._credpath,
                                    aws_access_key=self.aws_access_key,
                                    aws_secret_key=self.aws_secret_key,
                                    **self.clc_connect_kwargs)
        return self._creds

    @property
    def clc_machine(self):
        if not self._clc_machine:
            if self.clc_connect_kwargs['hostname']:
                self._clc_machine = Machine(**self.clc_connect_kwargs)
        return self._clc_machine

    @property



    @classmethod
    def build_machine_dict_from_config(cls):
        raise NotImplementedError()

    @classmethod
    def build_machine_dict_from_cloud_services(self):
        raise NotImplementedError()


      """
    @property
    def aws_access_key(self):
        if not self._aws_access_key:
            self._aws_access_key = self.creds.aws_access_key
        return  self._aws_access_key

    @property
    def aws_secret_key(self):
        if not self._aws_secret_key:
            self._aws_secret_key = self.creds.aws_secret_key
        return  self._aws_secret_key
    """

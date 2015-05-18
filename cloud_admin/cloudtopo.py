import os.path
import yaml
from cloud_admin.access.creds import Creds
from cloud_utils.system_utils.machine import Machine

class CloudTopo(object):

    def __init__(self,
                 hostname,
                 username='root',
                 password=None,
                 keypath=None,
                 config_yml=None,
                 config_qa=None,
                 eucarc_path=None,
                 aws_access_key=None,
                 aws_secret_key=None,
                 proxy_hostname=None,
                 proxy_username='root',
                 proxy_password=None,
                 proxy_keypath=None,
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
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self._creds = None

    @property
    def creds(self):
        if not self._creds:
            self._creds = Creds(aws_access_key=self.aws_access_key,
                                aws_secret_key=self.aws_secret_key,
                                **self.clc_connect_kwargs)
        return self._creds

    @property
    def clc_machine(self):
        if not self._clc_machine:
            if self.clc_connect_kwargs['hostname']:
                self._clc_machine = Machine(**self.clc_connect_kwargs)
        return self._clc_machine
    @classmethod
    def build_machine_dict_from_config(cls):
        raise NotImplementedError()

    @classmethod
    def build_machine_dict_from_cloud_services(self):
        raise NotImplementedError()




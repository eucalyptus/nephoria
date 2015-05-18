import os.path
import yaml
from cloud_utils.file_utils.eucarc import Eucarc
from cloud_utils.system_utils.machine import Machine

class CloudTopo(object):

    def __init__(self,
                 clc_ip=None,
                 username='root',
                 password=None,
                 keypath=None,
                 config_yml=None,
                 config_qa=None,
                 eucarc_path=None,
                 aws_access_key=None,
                 aws_secret_key=None,
                 proxy_ip=None,
                 proxy_username='root',
                 proxy_password=None,
                 proxy_keypath=None,
                 ):
        self.clc_connect_kwargs = {
            'hostname': clc_ip,
            'username': username,
            'password': password,
            'keypath': keypath,
            'proxy': proxy_ip,
            'proxy_username': proxy_username,
            'proxy_password': proxy_password,
            'proxy_keypath': proxy_keypath
        }
        self._clc_machine = None
        self.clc_ip = clc_ip
        self.password = None
        self.keypath = None
        self.config_qa = config_qa
        self.config_yml = config_yml
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.eucarc = None
        if clc:
            try:
                self.clc =
        if eucarc_path:
            paths = [eucarc_path]
            if not str(eucarc_path).endswith('eucarc'):
                paths.append(os.path.join(eucarc_path, 'eucarc'))
            for path in paths:
                if os.path.isfile(eucarc_path):
                    self.eucarc = Eucarc(filepath=eucarc_path)

    @property
    def clc_machine(self):
        if not self._clc_machine:
            if self.clc_connect_kwargs['hostname']:
                self._clc_machine = Machine(**self.clc_connect_kwargs)
        return self._clc_machine
    @classmethod
    def build_machine_dict_from_config(cls):


    @classmethod
    def build_machine_dict_from_cloud_services(self):




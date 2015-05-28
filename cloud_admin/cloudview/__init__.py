
import difflib
import json
import os
import yaml
from shutil import copyfile
from cloud_utils.system_utils.machine import Machine


class Namespace(object):
    """
    Convert dict (if provided) into attributes and return a somewhat
    generic object
    """
    def __init__(self, **kwargs):
        if kwargs:
            for key in kwargs:
                value = kwargs[key]
                try:
                    if isinstance(value, dict):
                        setattr(self, key, Namespace(**value))
                    else:
                        setattr(self, key, value)
                except:
                    print '"{0}" ---> "{1}" , type: "{2}"'.format(key,
                                                                  value,
                                                                  type(value))
                    raise

    def __repr__(self):
        return "Namespace:{0}".format(self.__class__.__name__)

    def _get_keys(self):
        return vars(self).keys()

    def _filtered_dict(self):
        return {k: v for (k, v) in self.__dict__.iteritems() if not k.startswith('_')}

    def do_default(self):
        # Removes all values not starting with "_" from dict
        for key in self._filtered_dict():
            if key in self.__dict__:
                if isinstance(self.__dict__[key], Namespace):
                    self.__dict__[key].do_default()
                self.__dict__.pop(key)

    def to_json(self, default=None, sort_keys=True, indent=4, **kwargs):
        if default is None:
            def default(o):
                return o._filtered_dict()
        return json.dumps(self,
                          default=default,
                          sort_keys=True,
                          indent=4,
                          **kwargs)

    def to_yaml(self, json_kwargs=None, yaml_kwargs=None):
        if yaml_kwargs is None:
            yaml_kwargs = {'default_flow_style': False}
        if json_kwargs is None:
            json_kwargs = {}
        jdump = self.to_json(**json_kwargs)
        yload = yaml.load(jdump)
        return yaml.dump(yload, **yaml_kwargs)


class ConfigBlock(Namespace):

    def __init__(self, connection):
        self._connection = connection

    @property
    def blockname(self):
        """
        This must be defined for matching the current config block against a specific section
        in a loaded config (json, yaml). ie to match against this block, self.blockname should
        return the string 'cluster'.
        ie:
        cluster:
          one:
            stuff: 1000
        """
        return self.__class__.__name__.lower().replace('block', '')

    def build_active_config(self):
        raise NotImplementedError("{0} has not implemented this base method"
                                  .format(self.__class__.__name__))

    def read_config_from_file(self, location=None):
        raise NotImplementedError("{0} has not implemented this base method"
                                  .format(self.__class__.__name__))

    def diff_config(self, active=None, configured=None):
        raise NotImplementedError("{0} has not implemented this base method"
                                  .format(self.__class__.__name__))

    def _get_dict_from_file(self, file_path, machine=None, format='json'):
        """
        Attempts to read in json from an existing file, load and return as
        a dict
        :param file_path: string representing a local or remote config file path to read from
        :param machine a cloud utils Machine() obj used for reading a remote filepath.
        :param format: supported values are 'json' and 'yaml'. Defaults to 'json'
        """
        newdict = None
        if machine:
            assert isinstance(machine, Machine)
            if not machine.is_file(file_path):
                raise ValueError('File not found on remote machine:"{0}", path:"{1}"'
                                 .format(machine.hostname, file_path))
            data = machine.sys('cat {0}'.format(file_path), listformat=False, code=0)
        elif os.path.exists(str(file_path)) and os.path.getsize(str(file_path)):
            if not os.path.isfile(file_path):
                raise ValueError('config file exists at path and is not '
                                 'a file:' + str(file_path))
            conf_file = open(file_path, 'rb')
            with conf_file:
                data = conf_file.read()
        if data:

            def searchDictForSelf(self, newdict):
                # Return the section of the loaded dict that pertains to this configblock
                section = newdict.get(self.blockname, None)
                if section and isinstance(section, dict):
                    return section
                # Check for a nested dict that matches...
                for key, value in newdict.iteritems():
                    if isinstance(value, dict):
                        if str(key).lower() == str(self.blockname).lower():
                            return value
                        elif self.blockname in value:
                            return value.get(self.blockname)
                        else:
                            # check the nested dict
                            searchDictForSelf(self, value)
                # No section matching self.blockname was found....
                return {}

            try:
                if format == 'yaml':
                    newdict = yaml.load(data)
                else:
                    newdict = json.loads(data)
                newdict = searchDictForSelf(self, newdict)
            except ValueError as ve:
                ve.args = (['Failed to load json config from: "{0}". '
                            'ERR: "{1}"'.format(file_path, ve.message)])
                raise
        return newdict

    def diff_json(self, file_path, machine=None):
        """
        Method to show current values -vs- those (saved) in a file.
        Will return a formatted string to show the difference

        :param file_path: string, local file path to read config into for diff
        """
        if not file_path:
            raise ValueError('File path must be provided for diff()')
        # Create formatted string representation of dict values
        text1 = self.to_json().splitlines()
        # Create formatted string representation of values in file
        file_dict = self._get_dict_from_file(file_path=file_path,
                                             machine=machine,
                                             format='json') or {}
        text2 = json.dumps(file_dict, sort_keys=True, indent=4).splitlines()
        diff = difflib.unified_diff(text2, text1, lineterm='')
        return str('\n'.join(diff))

    def diff_yaml(self, file_path, machine=None):
        """
        Method to show current values -vs- those (saved) in a file.
        Will return a formatted string to show the difference

        :param file_path: string, local file path to read config into for diff
        """
        if not file_path:
            raise ValueError('File path must be provided for diff()')
        # Create formatted string representation of dict values
        text1 = self.to_yaml().splitlines()
        # Create formatted string representation of values in file
        file_dict = self._get_dict_from_file(file_path=file_path,
                                             machine=machine,
                                             format='yaml') or {}
        text2 = yaml.dump(file_dict, default_flow_style=False).splitlines()
        diff = difflib.unified_diff(text2, text1, lineterm='')
        return str('\n'.join(diff))


    def save(self, path=None):
        """
        Will write the json configuration to a file at path or by default at
        self.write_file_path.

        :param path: string, local file path to save the config to.
        """
        path = path or self.write_file_path
        if not path:
            raise ValueError('Path/write_file_path has not been set '
                             'or provided.')
        backup_path = path + '.bak'
        config_json = self.to_json()
        if os.path.isfile(path):
            copyfile(path, backup_path)
        save_file = file(path, "w")
        with save_file:
            save_file.write(config_json)
            save_file.flush()

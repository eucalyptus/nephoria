
import json
import yaml


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
                        setattr(self, Namespace(value), key)
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
        return {k:v for (k,v) in self.__dict__.iteritems() if not k.startswith('_')}

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

    def build_active_config(self):
        raise NotImplementedError("{0} has not implemented this base method"
                                  .format(self.__class__.__name__))

    def read_config_from_file(self, location=None):
        raise NotImplementedError("{0} has not implemented this base method"
                                  .format(self.__class__.__name__))

    def diff_config(self, active=None, configured=None):
        raise NotImplementedError("{0} has not implemented this base method"
                                  .format(self.__class__.__name__))

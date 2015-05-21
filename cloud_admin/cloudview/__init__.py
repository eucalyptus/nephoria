
import json


class Namespace(object):
    """
    Convert dict (if provided) into attributes and return a somewhat
    generic object
    """
    def __init__(self, newdict=None):
        if newdict:
            for key in newdict:
                value = newdict[key]
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

    def to_json(self):

        return json.dumps(self,
                          #default=lambda o: o.__dict__,
                          default= lambda o: o._filtered_dict(),
                          sort_keys=True,
                          indent=4)


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

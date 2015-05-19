



class BaseBuilder(object):

    def __init__(self, connection):
        self.connection = connection
        self.active_config = None
        self.configured_config = None


    def build_active_config(self):
        raise NotImplementedError("{0} has not implemented this base method"
                                  .format(self.__class__.__name__))

    def read_config_from_file(self, location=None):
        raise NotImplementedError("{0} has not implemented this base method"
                                  .format(self.__class__.__name__))

    def diff_config(self, active=None, configured=None):
        raise NotImplementedError("{0} has not implemented this base method"
                                  .format(self.__class__.__name__))

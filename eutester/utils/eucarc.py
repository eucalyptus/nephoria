
import re
import os
from prettytable import PrettyTable

class Eucarc(object):

    def __init__(self, filepath=None, string=None, sshconnection=None, keydir=None,
                 debug_method=None):

        self._debug_method = debug_method
        if filepath is not None and not sshconnection:
            if not re.search('\S+', filepath):
                filepath = os.path.curdir
            filepath = os.path.realpath(filepath)
        self._filepath = filepath
        if keydir is None:
            keydir = filepath
        self._keydir = keydir
        self._string = string
        self._sshconnection = sshconnection
        self._message = None
        if string:
            self._from_string()
        else:
            if not filepath:
                raise ValueError('Either filepath or string must be provided to Eucarc()')
            self._from_filepath(filepath=filepath, sshconnection=sshconnection)


    def _debug(self, msg):
        if self._debug_method:
            self._debug_method(msg)
        else:
            print(msg)

    def _from_string(self, string=None, keydir=None):
        string = string or self._string
        if keydir is None:
            keydir = self._keydir
        new_dict = {}
        message = ""
        if string:
            if not isinstance(string, basestring):
                raise TypeError('"_from_string" expected string(basestring) type, got:{0}:{1}'
                                .format(string, type(string)))
            string = str(string)
            for line in string.splitlines():
                if line:
                    match = re.search('^\s*export\s+(\w+)=\s*(\S+)$', line)
                    if not match:
                        print 'Got a message:' + str(line)
                        message += line + "\n"
                    else:
                        key = match.group(1)
                        value = match.group(2)
                        value = str(value).strip('"').strip("'")
                        if keydir:
                            value = value.replace('${EUCA_KEY_DIR}', keydir)


                        if not (key and value):
                            raise ValueError('Fix me! Could not find key=value, in this line:"{0}"'
                                             .format(line))
                        for case_key in [key, str(key).lower()]:
                            self.__setattr__(case_key,value)
                            new_dict[case_key] = value
            if message:
                self._message = message
                new_dict['message'] = message
        return new_dict

    def _from_filepath(self, filepath=None, sshconnection=None, keydir=None):
        filepath = filepath or self._filepath
        if keydir is None:
            keydir = self._keydir
        sshconnection = sshconnection or self._sshconnection
        if sshconnection:
            string = sshconnection.sys('cat {0}'.format(filepath), listformat=False, code=0)
        else:
            f = open(filepath)
            with f:
                string = f.read()
        return self._from_string(string, keydir=keydir)


    def _show(self, print_table=True):
        pt = PrettyTable(['KEY', 'VALUE'])
        pt.hrules=1
        pt.align='l'
        pt.header = False
        pt.max_width['VALUE'] = 85
        pt.max_width['KEY'] = 35
        for key in self.__dict__:
            if not str(key).startswith('_'):
                pt.add_row([key, self.__dict__[key]])
        if print_table:
            self._debug(str(pt))
        else:
            return pt













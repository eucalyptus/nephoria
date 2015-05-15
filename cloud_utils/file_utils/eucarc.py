
import re
import os
from prettytable import PrettyTable


class Eucarc(dict):
    _KEY_DIR_STR = '\${EUCA_KEY_DIR}'

    def __init__(self, filepath=None, string=None, sshconnection=None, keydir=None,
                 debug_method=None):
        """
        Will populate a eucarc obj with values from a local file, remote file, or string buffer.
        The parser expect values in the following format:
        export key=value
        For example:
        export S3_URL=http://169.254.123.123:8773/services/objectstorage

        The value 'http://169.254.123.123:8773/services/objectstorage' will be assigned to an
        of the eucarc obj using the lower case version of the key, ie: eucarc.s3
        :param filepath: the local or remote filepath to the eucarc
        :param string: a string buffer containing the eucarc contents to be parsed
        :param sshconnection: an SshConnection() obj to a remote machine to read the eucarc
                              at 'filepath' from.
        :param keydir: A vaule to replace _KEY_DIR_STR (${EUCA_KEY_DIR}) with, by defual this is
                       the filepath, but when parsing from a string buffer filepath is unknown
        :param debug_method: a method to log debug inforation to.
        """
        # init most common eucarc values to None...
        self.ec2_account_number = None
        self.euare_url = None
        self.ec2_user_id = None
        self.token_url = None
        self.ec2_url = None
        self.aws_elb_url = None
        self.aws_cloudformation_url = None
        self.aws_secret_key = None
        self.aws_cloudwatch_url = None
        self.eucalyptus_cert = None
        self.s3_url = None
        self.aws_iam_url = None
        self.aws_simpleworkflow_url = None
        self.aws_access_key = None
        self.ec2_private_key = None
        self.ec2_access_key = None
        self.ec2_secret_key = None
        self.ec2_jvm_args = None
        self.eustore_url = None
        self.aws_credential_file = None
        self.ec2_cert = None
        self.aws_auto_scaling_url = None
        # End of init default eucarc attrs
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
        self._unparsed_lines = None
        if string:
            self._from_string()
        else:
            if not filepath:
                raise ValueError('Either filepath or string must be provided to Eucarc()')
            self._from_filepath(filepath=filepath, sshconnection=sshconnection, keydir=filepath)

    def _debug(self, msg):
        """
        Used to print debug information
        """
        if self._debug_method:
            self._debug_method(msg)
        else:
            print(msg)

    def _from_string(self, string=None, keydir=None):
        """
        Parse the Eucarc attributes from this string buffer. Populates self with attributes.

        :param string: String buffer to parse from. By default self._string is used.
        :param keydir: A vaule to replace _KEY_DIR_STR (${EUCA_KEY_DIR}) with, by defual this is
                       the filepath, but when parsing from a string buffer filepath is unknown
        :returns dict of attributes.
        """
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
                        # This line does not match our expected format, add it to the messages
                        message += line + "\n"
                    else:
                        key = match.group(1)
                        value = match.group(2)
                        value = str(value).strip('"').strip("'")
                        if re.search(self._KEY_DIR_STR, line):
                            if keydir:
                                value = re.sub(self._KEY_DIR_STR, keydir, value)
                            else:
                                # Add this line to the messages since this value will not
                                # resolve without a defined 'keydir'...
                                message += line + "\n"
                                continue
                        if not (key and value):
                            raise ValueError('Fix me! Could not find key=value, in this line:"{0}"'
                                             .format(line))
                        self.__setattr__(key.lower(), value)
                        new_dict[key.lower()] = value
            if message:
                self._unparsed_lines = message
                new_dict['message'] = message
        return new_dict

    def _from_filepath(self, filepath=None, sshconnection=None, keydir=None):
        """
        Read the eucarc from a provided filepath. If an sshconnection obj is provided than
        this will attempt to read from a file path via the sshconnection, otherwise the filepath
        is read from the local filesystem.
        Populated self with attributes read from eucarc.

        :param filepath: The file path to a eucarc
        :param sshconnection: An sshconnection obj, used to read from a remote machine
        :param keydir: A vaule to replace _KEY_DIR_STR (${EUCA_KEY_DIR}) with, by defual this is
                       the filepath, but when parsing from a string buffer filepath is unknown
        :returns dict of attributes
        """
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

    def show(self, print_table=True):
        """
        Show the eucarc key, values in a table format
        :param print_table: bool, if true will print the table to self._debug, else returns the
                            table obj
        """
        pt = PrettyTable(['KEY', 'VALUE'])
        pt.hrules = 1
        pt.align = 'l'
        pt.header = False
        pt.max_width['VALUE'] = 85
        pt.max_width['KEY'] = 35
        for key in self.__dict__:
            if not str(key).startswith('_'):
                pt.add_row([key, self.__dict__[key]])
        pt.add_row(['UNPARSED LINES', self._unparsed_lines])
        if print_table:
            self._debug(str(pt))
        else:
            return pt

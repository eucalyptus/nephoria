#!/usr/bin/python


import testcase_utils
import re
import random
import string

__version__ = '1.4.3.0.1.2'
__DEFAULT_API_VERSION__ = '2015-10-01'


def handle_timeout(self, signum, frame):
    raise testcase_utils.TimeoutFunctionException()

def grep(self, string, list):
    """ Remove the strings from the list that do not match the regex string"""
    expr = re.compile(string)
    return filter(expr.search,list)

def render_file_template(src, dest, **kwargs):
    from cloud_utils import file_utils
    return file_utils.render_file_template(src, dest, **kwargs)

def id_generator(size=6, chars=None):
    """Returns a string of size with random charachters from the chars array.
         size    Size of string to return
         chars   Array of characters to use in generation of the string
    """
    chars = chars or (string.ascii_uppercase + string.ascii_lowercase  + string.digits)
    return ''.join(random.choice(chars) for x in range(size))

class CleanTestResourcesException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

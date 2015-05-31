# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2011, Eucalyptus Systems, Inc.
# All rights reserved.
#
# Redistribution and use of this software in source and binary forms, with or
# without modification, are permitted provided that the following conditions
# are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# author: clarkmatthew
# modified by: Trevor Hodde

'''
    Example:
    import eulogger
    self.logger = eulogger.Eulogger(name='euca')
    self.log = self.logger.log

    self.debug("This is a debug message")
    self.critical("this is a critical message")
'''

import os
import sys
import logging
import time


class Eulogger(logging.Logger):
    # constructor for the Eulogger

    def __init__(self,
                 parent_logger_name='eutester',
                 name=None,
                 identifier=None,
                 stdout_level="debug",
                 stdout_format=None,
                 logfile="",
                 logfile_level="INFO",
                 file_format=None,
                 show_init=False):
        """
        This class basically sets up a child debugger for testing purposes.
        It allows the user to set up a new logger object and pass different logging formats and
        levels so different objects and modules can log with unique identifiers and logging levels.


        :param parent_logger_name: Name of root/parent logger
        :param identifier: identifier used for log formatting and child logger name
        :param stdout_level: log level (see 'logging' class) for std out handler under this
                             child logger
        :param stdout_format: logging format used by this child logger's stdout handler
        :param logfile: file path to use for this child logger's logging file handler
        :param logfile_level: log level (see 'logging' class) for file handler under this
                              child logger
        :param file_format: logging formate used by this child logger's file handler
        :param clear_file: will attempt to remove 'logfile' before creating handler. Will not
                           remove parent's files.
        :param make_log_file_global: boolean, will add this logfile to parent so other child
                                     loggers create afterward will attempt to create a handler
                                      that writes to this file as well.
        :param use_global_log_files: boolean, will query the parent logger for any file handlers
                                     and will attempt to create a handler for this child logger
                                     using the same file
        """
        # Debug for init...
        if show_init:
            print ('-----------------------------------------------\n'
                   'parent_logger_name:{0}\neulogger init:\nidentifier:{1}\nstdout_level:{2}\n'
                   'stdout_format:{3}\nlogfile:{4}\nlogfile_level:{5}\nfile_format:{6}\n'
                   'clear_file:{7}\n-----------------------------------------------'
                   .format(str(parent_logger_name), str(identifier), str(stdout_level),
                           str(stdout_format), str(logfile), str(logfile_level), str(file_format)))
        # Create or fetch existing logger of name 'logger_name
        self.stdout_level = getattr(logging, stdout_level.upper(), logging.DEBUG)
        self.logfile_level = getattr(logging, logfile_level.upper(), logging.DEBUG)
        self.parent_logger_name = parent_logger_name
        # Create a logger
        if not name:
            if identifier:
                name = "{0}".format(identifier)
            else:
                name = 'eulogger'

            name = str(name).replace(".", ":")
            name = "{0}.{1}".format(self.parent_logger_name, name)
        self.identifier = identifier or name

        parent_logger = logging.getLogger(self.parent_logger_name)
        childlogger = parent_logger.getChild(name)
        self.__dict__.update(childlogger.__dict__)
        self.parent = self.parent or parent_logger
        self.logfile = os.path.join(logfile)
        id_string = ""
        if identifier:
            id_string = " [{0}] ".format(identifier)

        self._default_format = stdout_format or logging.Formatter(
            '[%(asctime)s][%(levelname)s]%(message)s')
        self.file_format = file_format or self._default_format

        # Add handler for stdout...
        stdout_handler = None
        for handler in self.parent.handlers:
            if isinstance(handler, logging.StreamHandler):
                if 'stdout' in handler.stream.name:
                    stdout_handler = handler
        if not stdout_handler:
            stdout_handler = logging.StreamHandler(sys.stdout)
            stdout_handler.setFormatter(self._default_format)
            stdout_handler.setLevel(self.stdout_level)
            self.parent.addHandler(stdout_handler)
            self.parent.setLevel(self.stdout_level)
        self.stdout_handler = stdout_handler

        # Now add the file handlers...
        file_info_list = self.getparent_files()
        if self.logfile:
            self.logfile = os.path.abspath(self.logfile)
            if self.logfile not in file_info_list:
                file_hdlr = logging.FileHandler(self.logfile)
                file_hdlr.setFormatter(self._default_format)
                file_hdlr.setLevel(logfile_level)
                self.parent.addHandler(file_hdlr)
        self.manager.loggerDict[self.name] = self

    def _log(self, level, msg, args, exc_info=None, extra=None):
        msg = "[{0}]: {1}".format(self.identifier, msg)
        return super(Eulogger, self)._log(level, msg, args, exc_info=exc_info, extra=extra)

    def getparent_files(self):
        files = []
        for h in self.parent.handlers:
            if isinstance(h, logging.FileHandler):
                files.append(h.stream.name)
        return files

    def set_parentloglevel(self, level):
        if self.parent:
            if not isinstance(level, int) and isinstance(level, basestring):
                level = getattr(logging, level.upper())
            self.parent.setLevel(level)


class AllowLoggerByName(logging.Filter):
    """
    Only messages from this logger are allow through to prevent duplicates from other
    loggers of same level, etc..
    """
    def __init__(self, name=""):
        logging.Filter.__init__(self, name)

    def filter(self, record):
        return record.name == self.name


class MuteFilter(logging.Filter):
    def filter(self, record):
        return False

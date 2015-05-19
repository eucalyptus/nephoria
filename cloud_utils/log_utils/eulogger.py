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
                 identifier="eulogger",
                 stdout_level="debug",
                 stdout_format=None,
                 logfile="",
                 logfile_level="debug",
                 make_log_file_global=True,
                 use_global_log_files=True,
                 file_format=None,
                 show_init=False,
                 clear_file=False):
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
                           str(stdout_format), str(logfile), str(logfile_level), str(file_format),
                           str(clear_file)))

        self.logfile = os.path.join(logfile)
        self.clear_file = clear_file

        # Create of fetch existing logger of name 'logger_name
        self.parent_logger_name = parent_logger_name
        self.identifier = identifier
        self.name = identifier + str(time.time())
        self.parent_logger = logging.getLogger(self.parent_logger_name)
        logger = self.getChild(self.parent_logger, self.name)
        self.__dict__.update(logger.__dict__)
        self.file_info_list = []

        # map string for log level to 'logging' class type or default to logging.DEBUG
        # if string isn't found
        self.stdout_level = logging.__dict__.get(stdout_level.upper(), logging.DEBUG)
        self.logfile_level = logging.__dict__.get(logfile_level.upper(), logging.DEBUG)

        # set the parent and child logger levels to the lowest of the two handler levels
        if self.stdout_level < self.logfile_level:
            self.logger_level = self.stdout_level
        else:
            self.logger_level = self.logfile_level
        if self.level > self.logger_level or self.level == 0:
            self.setLevel(self.logfile_level)
        if self.parent_logger > self.logger_level or self.level == 0:
            self.parent_logger.setLevel(self.logfile_level)

        # set some default and canned formatters for logging output
        self.default_format = stdout_format or logging.Formatter(
            '[%(asctime)s] [' + self.identifier + '] [%(levelname)s]: %(message)s')
        self.file_format = file_format or self.default_format

        # Add a few canned formatters for reference/convenience
        self.formatter2 = logging.Formatter('[%(asctime)s] [{0}] [%(levelname)s] '
                                            '[%(filename)s:%(funcName)s():%(lineno)d]: %(message)s'
                                            .format(self.identifier))
        self.formatter3 = logging.Formatter(
            self.identifier + ':%(funcName)s():%(lineno)d: %(message)s')
        self.formatter4 = logging.Formatter('%(message)s')

        self.stdout_handler = logging.StreamHandler(sys.stdout)
        self.stdout_handler.setFormatter(self.default_format)
        self.stdout_handler.setLevel(self.stdout_level)
        # Add filter so only log records from this child logger are handled
        self.stdout_handler.addFilter(AllowLoggerByName(self.name))
        if self.stdout_handler not in self.handlers:
            self.addHandler(self.stdout_handler)
        else:
            print "Not adding stdout handler for this eulogger:" + str(self.identifier)

        # Now add the file handlers...
        if use_global_log_files:
            self.file_info_list = self.get_parent_logger_files()
        if (self.logfile):
            self.file_info_list.append(FileHandlerInfo(self.logfile, self.logfile_level))
            # If the clear flag is set remove the file first...
            if (self.clear_file):
                try:
                    os.remove(self.logfile)
                except Exception, e:
                    print "Error while attempting to remove log file \'{0}\', err:{1}"\
                        .format(self.logfile, str(e))
            if make_log_file_global:
                self.add_muted_file_handler_to_parent_logger(self.logfile, self.logfile_level)
        for fileinfo in self.file_info_list:
            file_hdlr = logging.FileHandler(fileinfo.filepath)
            file_hdlr.setFormatter(self.file_format)
            file_hdlr.setLevel(fileinfo.level)
            # Add filter so only log records from this child logger are handled
            file_hdlr.addFilter(AllowLoggerByName(self.name))
            # Make sure this is not a duplicate handler or this file is a dup of another handler
            if file_hdlr not in self.handlers:
                add = True
                for h in self.handlers:
                    if h.stream.name == file_hdlr.stream.name:
                        add = False
                        self.debug('File already has log handler:' + str(logfile.filepath))
                        break
                if add:
                    self.addHandler(file_hdlr)
            else:
                print "Not adding logfile handler for this eulogger:" + str(self.identifier)

    def add_muted_file_handler_to_parent_logger(self, filepath, level):
        file_handler = logging.FileHandler(filepath)
        file_handler.setLevel(level)
        file_handler.addFilter(MuteFilter())

    def get_parent_logger_files(self):
        files = []
        for h in self.parent_logger.handlers:
            if isinstance(h, logging.FileHandler):
                files.append(FileHandlerInfo(h.stream.name, h.level))
        return files

    def getChild(self, logger, suffix):
        """
        Add this for 2.6 support, this was implemented in 2.7...###
        """
        if hasattr(logger, 'getChild'):
            return logger.getChild(suffix)
        else:
            if logger.root is not logger:
                suffix = '.'.join((logger.name, suffix))
            return logger.manager.getLogger(suffix)


class FileHandlerInfo():
    def __init__(self, filepath, level):
        if not filepath or not level:
            raise Exception("File_Handler_Info None option not allowed, filepath:" + str(
                filepath) + ",level:" + str(level))
        self.filepath = filepath
        self.level = level


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

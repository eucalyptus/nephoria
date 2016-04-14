#!/usr/bin/env python
from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
import copy
import time

"""
This is intended to demonstrate some basic ways to write a test suite.

To run this test from the command line:

## First see what CLI args are provided. Not the --sample-arg added in the test vs the default
## arguments provided by the CliTestRunner Class
prompt# python sample_test_suite.py -h

## Run the tests
prompt# python sample_test_suite.py --sample-arg 'my sample arg'

## Run a subset of the tests
prompt# python sample_test_suite.py --sample-arg 'woot' --test-list 'test1, test12_skip_me'


To run this test from a python shell:
prompt# ipython
In [1]: from nephoria.testcase_utils.sample_test_suite import SampleTestSuite1
In [2]: test = SampleTestSuite1(sample_arg='another way to provide args', test_list='test12_skip_me')
In [3]: test.run()

# Or call the method directly...
In [4]: test.test1()
[03-10 11:07:29][INFO][SampleTestSuite1]: This is the default

"""

##################################################################################################
# Extend the CliTestRunner Class to create a new test suite
# - The '_DEFAULT_CLI_ARGS' attribute defines the cli arguments available to the user at run time.
#   See the CliTestRunner base class for all the default cli arguments
#   The following example shows how to add CLI arguments to this class.
#   From a command prompt/shell the default CLI arguments can also be seen by typing:
#   Command Line Example:
#       'python CliTestRunner.py --help'
# - Any argument defined in '_DEFAULT_CLI_ARGS' can also be defined during CliTestRunner.__init__()
#   if objects of type CliTestRunner are to be used within other python modules/scripts.
#   Embedded Python Example:
#       from nephoria.testcase_utils.cli_test_runner import CliTestRunner
#       mytestcaseobject = CliTestRunner(clc='1.2.3.4', password='mypass', log_level='debug')
##################################################################################################

class SampleTestSuite1(CliTestRunner):
    _DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)
    _DEFAULT_CLI_ARGS['sample_arg'] = {'args': ['--sample-arg'],
                                       'kwargs': {'help': 'This sample arg is mandatory',
                                                  'default': None,
                                                  'required': True}}

    ###############################################################################################
    # A 'test' method can be named anything, but if not prefixed with the word 'test' the testcase
    # author will need to feed the methods into the runner explicitly.
    # By default the CliTestRunner.run() method will execute all local methods prefixed with the
    # word 'test' in sorted order of the name (ie test1_blah, test2_yada, testa_blah,...)
    # Any 'test' method should be capable of running autonomously. If the test has dependencies,
    # it should be able to re-use or create the artifacts it needs, or fail with an error explaining
    # that it can or will not do so, and what the user needs to do prior to running this test.
    ###############################################################################################

    def test1(self, string_to_print='This is the default'):
        self.log.info(string_to_print)

    def test2_ditto(self):
        self.test1(string_to_print='This is test2 now')

    # Tests can raise the 'SkipTestException' to skip a test w/o failure. If a test detects the
    # it is not intended for the test environment it should raise this to skip itself.
    def test12_skip_me(self):
        raise SkipTestException('I was too lazy to run')

    def test_33_failure_test(self, a=1, b=2, c=3):
        time.sleep(1)
        if a == 1:
            raise ValueError('a == 1, so I am failing')

    # Test can reference the command line arguments using the 'args' attribute.
    def test3_arg_usage(self):
        print "Heres all the command line arguments in self._DEFAULT_CLI_ARGS..."
        self.show_args()
        if not self.args.sample_arg:
            raise ValueError('The sample arg was empty:"{0}", I thought we said to set this'
                             .format(self.args.sample_arg))
        else:
            self.log.info('You set the sample arg to: "{0}"'.format(self.args.sample_arg))

    ###############################################################################################
    # At the end of each full testcase run, the clean_method() is called unless 'no_clean' arg
    # is set to True. Each test case will need to implement this method to enforce tests do not
    # leave test artifacts behind on a system, resource leaks, etc.. Tests that do not leave
    # the system in the state it found it should be clear about the test's intention and any
    # resulting artifacts intended to remain after the test has ran.
    ###############################################################################################

    def clean_method(self):
        print 'Cleaning...'

##################################################################################################
# Define main() for when this module is invoked from the command line
# here the module creates an object of itself, invokes run() and exits with the proper return
# code
# During run():
# - function/methods intended to be run as 'tests' are converted to
#   cli_test_runner.TestUnit() type objects. These test unit object carry their results, metrics,
#   loggers, run time arguments/attributes, etc..
# - While the test units are being executed information about the test is logged to stdout and/or
#   a defined log file. (see the CliTestRunner default args for logger settings).
# - When a testunit is first started, an introduction header is logged. The information in this
#   header is contained in the  TestUnit.test_unit_description, and defaults to a method/function's
#   doc-string if not provided.
# - At the end of each TestUnit the result of the testunit is logged as well as a brief summary
#   of all the testunit results. When the entire suite has completed (at the end of run()),
#   a summary of all the tests run, their results, time to complete, as well as brief descriptions
#   of any errors/failures is logged in table format.
# - It is up to the testcase author to exit with the proper return code. (see below)
##################################################################################################

if __name__ == "__main__":

    test = SampleTestSuite1()
    result = test.run()
    exit(result)


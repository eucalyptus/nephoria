#!/usr/bin/env python
from nephoria.testcase_utils.cli_test_runner import CliTestRunner, SkipTestException
import time


class SampleTestSuite1(CliTestRunner):
    _DEFAULT_CLI_ARGS = CliTestRunner._DEFAULT_CLI_ARGS
    _DEFAULT_CLI_ARGS['sample_arg'] = {'args': ['--sample-arg'],
                                       'kwargs': {'help': 'This sample arg is mandatory',
                                                  'default': None,
                                                  'required': True}}



    def test1(self, string_to_print='This is the default'):
        self.log.info(string_to_print)

    def test2_ditto(self):
        self.test1(string_to_print='This is test2 now')

    def test12_skip_me(self):
        raise SkipTestException('I was too lazy to run')

    def test_33_failure_test(self, a=1, b=2, c=3):
        time.sleep(1)
        if a == 1:
            raise ValueError('a == 1, so I am failing')

    def test3_arg_usage(self):
        print "Heres all the command line arguments in self._DEFAULT_CLI_ARGS..."
        self.show_args()
        if not self.args.sample_arg:
            raise ValueError('The sample arg was empty:"{0}", I thought we said to set this'
                             .format(self.args.sample_arg))
        else:
            self.log.info('You set the sample arg to: "{0}"'.format(self.args.sample_arg))

    def clean_method(self):
        print 'Cleaning...'

if __name__ == "__main__":

    test = SampleTestSuite1()
    test.run_test_case_list()


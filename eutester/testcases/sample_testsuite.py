from eutester.testcase_utils.eutestcase import EutesterTestCase, SkipTestException
from cloud_utils.net_utils.sshconnection import SshConnection

##################################################################################################
# Create the testcase object                                                                     #
##################################################################################################
testcase = EutesterTestCase()

##################################################################################################
# See 'setup_parser' for all the default cli arguments. These can be negated by setting          #
# these to 'false' as shown here...                                                              #
##################################################################################################
testcase.setup_parser(testname='My first test',
                      description='Sample testcase',
                      emi=False, # exclude the emi cli option from this test
                      testlist=False # Exclude the 'testlist' cli option for this test
                      )

##################################################################################################
# Add an additional CLI argument to this test                                                    #
##################################################################################################
testcase.parser.add_argument('--test_ip',
                             help='IP address used to create SSH connection sample test',
                             default=None)

##################################################################################################
# Gather CLI arguments, this will also parse any arguments in any config files                   #
# that are provided. The cli args and config file args will be merged into testcase.args         #
##################################################################################################
testcase.get_args()

##################################################################################################
# Add a test method, Name is not important to running, but does help organize the suite.         #
# Methods will later be used/created when converted to testunit class objs shown later(at bottom)#
##################################################################################################
def my_first_test_method(ip=None, username=None, password=None):
    """
    Description: This description will be displayed in the test run output and should
    explain this test's objectives, progression, any artifacts it creates/removes, dependencies,
    etc..
    This test attempts to ssh into a remote device (in practice this might be a VM/instance)
     and verify the end host is alive by executing 2 commands; 'hostname' and 'uptime', verifies
     the return code of the commands to be '0', and prints the output out at debug level.
    """
    ip = ip or  testcase.args.test_ip # this is the arg we added above
    password = password or testcase.args.instance_password # instance_password provided
    username = username or testcase.args.instance_user or 'root' # so is instance_user
    if not ip or not password:
        raise ValueError('Need ip and password to run this ssh test! ip={0}, password={1}'
                         .format(ip, password))
    # Create an ssh connection using the ip. Using a short timeout and no retry since this
    # is an example, otherwise defaults are usually good.
    ssh = SshConnection(host=ip, username=username, password=password, timeout=10, retry=0,
                        verbose=True)

    # SshConnection.sys() will execute a cmd on the remote system, 'code' will check the return
    # code of the command and throw an exception if it does not match the value provided.
    # By default the returned output is a list of lines, but can also be returned as a single
    # string buffer using 'listformat=False')
    # The command is monitored and the session will be torn down and a timeout exception will be
    # thrown if it does not return by 'timeout' seconds.
    output = ssh.sys('hostname && uptime', listformat=False, code=0, timeout=20)


    # default logger writes to stdout and it's debug level method can be used such as...
    testcase.debug('my_first_test_method passed yay!!')
    testcase.debug('Heres the output of our two commands:\n{0}'.format(output))


##################################################################################################
# Now add a method that is intended to fail...                                                   #
##################################################################################################
def sample_test_fail_method():
    return my_first_test_method(ip=None, username='noone', password='badpassword')

testcase.uh_oh_fail = sample_test_fail_method
testcase.uh_oh_fail.__doc__ = "Description: This test should demonstrate a failure...\n"


##################################################################################################
# Add a test which demonstrates how to skip a test from within the test method                   #
##################################################################################################
def too_lazy_to_run():
    """
    This shows how to throw a 'SkipTestException' in the case a test detects it should not be
    run. Reasons for not running a test might be; the environment is not for this test, another
    test has failed and this test depends on an artifact created by that test as a dependency,
    the code base is not of the correct version (ie the feature this tests is not present), etc..
    """
    raise SkipTestException('Im too lazy to run right now')


##################################################################################################
# Add a test which will later demonstrate how the eof (end on failure) flag works                #
##################################################################################################
def hope_i_get_to_run():
    '''
    'This test should show a failure of a test which never gets to run'
                   'due to EOF(End On Failure) set for a failed testcase'
    '''
    testcase.debug('This test should show a failure of a test which never gets to run'
                   'due to EOF(End On Failure) set for a failed testcase')

##################################################################################################
# Create our test list of test units...                                                          #
# this can be done by using a method or the name of a method within the testcase class...        #
# by passing a method.                                                                           #
#                                                                                                #
#                                                                                                #
# First test is a vanilla passing testcase, created by adding a 'method' from above              #
# This first test case is using autoarg=True, this will populate the test method using           #
# any args/kwargs from  testcase.args which match the methods(*args, **kwargs).                  #
##################################################################################################
test0 = testcase.create_testunit_from_method(my_first_test_method)

##################################################################################################
# Next run the same method disabling autoarg. Set end of failure flag to false to continue       #
# Running the test suite upon failure                                                            #
##################################################################################################
test1 = testcase.create_testunit_from_method(my_first_test_method, autoarg=False, eof=False)

# Add Another test by method
test2 = testcase.create_testunit_from_method(too_lazy_to_run)

##################################################################################################
# Create this testunit obj by passing a name of a method local to the testcase object.           #
# Setting eof to True here will abort any remaining tests if this unit fails. This can also be   #
# set globally for all test units                                                                #
# during run_test_case_list()                                                                    #
##################################################################################################
test3 = testcase.create_testunit_by_name('uh_oh_fail', eof=True)

# Add one more test unit by method, this test should not be attempted since eof is set on a
# test intended to fail prior to this test
test4 = testcase.create_testunit_from_method(hope_i_get_to_run)


##################################################################################################
# Finally run the test list                                                                      #
##################################################################################################
result = testcase.run_test_case_list(list = [test0, test1, test2, test3, test4],
                                     eof=False,
                                     clean_on_exit=False,
                                     printresults=True)

##################################################################################################
# Dont forget to exit with the proper code                                                       #
##################################################################################################
exit(result)

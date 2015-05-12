## Sample test 'sample_testsuite.py' and it's output.



File: sample_testsuite.py
```
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


```






## TEST Output explanation from sample_testsuite.py...



Test case starts by building the arguments from the CLI and any configuration files provided...

```
### python sample_testsuite.py --test_ip=10.111.5.100 --password foobar
setuptestname:None
setup_debugmethod:
testcasename:None
log_level:None
logfile:None
logfile_level:debug
Starting setup_debugmethod, name:eutestcase
After populating... setup_debugmethod: testcasename:Nonelog_level:debuglogfile:Nonelogfile_level:debug
[2015-05-12 13:32:15,414] [eutestcase] [DEBUG]: (setuptestcase:339): <pre>
[2015-05-12 13:32:15,415] [eutestcase] [DEBUG]: (show_self:1312):
-------------------------------------------------------------------------
TESTCASE INFO:
----------
NAME:                     --->:  eutestcase
TEST LIST:                --->:  []
CONFIG FILES:             --->:  []
-------------------------------------------------------------------------
[2015-05-12 13:32:15,416] [eutestcase] [DEBUG]: (show_args:1333):
-------------------------------------------------------------------------
TEST ARGS:                       VALUE:
----------                      ------
debug_method              --->:  <bound method EutesterTestCase.debug of <eutester.eutestcase.EutesterTestCase testMethod=eutestcase>>
logger                    --->:  <eutester.eulogger.Eulogger object at 0x10ed267d0>
-------------------------------------------------------------------------
setup_debugmethod:
testcasename:None
log_level:None
logfile:None
logfile_level:None
Starting setup_debugmethod, name:eutestcase
After populating... setup_debugmethod: testcasename:Nonelog_level:debuglogfile:Nonelogfile_level:debug
[2015-05-12 13:32:15,418] [eutestcase] [DEBUG]: (show_self:1312):
-------------------------------------------------------------------------
TESTCASE INFO:
----------
NAME:                     --->:  eutestcase
TEST LIST:                --->:  []
CONFIG FILES:             --->:  []

```
The table below shows all the args in 'testcase.args' and their values. All but 'test_ip' which
was added in the test are defaults. These arguments available to the tests.
Example to retrieve an arg from a testcase obj called 'testcase': testcase.args.test_ip
```

-------------------------------------------------------------------------
[2015-05-12 13:32:15,420] [eutestcase] [DEBUG]: (show_args:1333):
-------------------------------------------------------------------------
TEST ARGS:                       VALUE:
----------                      ------
args                      --->:  Namespace(config=None, config_file=None, configblocks=[], configfile=None, configsections=['MEMO', 'globals', 'eutestcase'], cred_path=None, credpath=None, html_anchors=False, ignoreblocks=[], instance_password=None, instance_user='root', keypair=None, log_level='debug', logfile=None, logfile_level='debug', password='foobar', region=None, test_ip='10.111.5.100', use_color=False, user_data=None, vmtype='c1.medium', zone=None)
config                    --->:  None
config_file               --->:  None
configblocks              --->:  []
configfile                --->:  None
configsections            --->:  ['MEMO', 'globals', 'eutestcase']
cred_path                 --->:  None
credpath                  --->:  None
debug_method              --->:  <bound method EutesterTestCase.debug of <eutester.eutestcase.EutesterTestCase testMethod=eutestcase>>
html_anchors              --->:  False
ignoreblocks              --->:  []
instance_password         --->:  None
instance_user             --->:  root
keypair                   --->:  None
log_level                 --->:  debug
logfile                   --->:  None
logfile_level             --->:  debug
logger                    --->:  <eutester.eulogger.Eulogger object at 0x10ed31190>
password                  --->:  foobar
region                    --->:  None
test_ip                   --->:  10.111.5.100
use_color                 --->:  False
user_data                 --->:  None
vmtype                    --->:  c1.medium
zone                      --->:  None
-------------------------------------------------------------------------

```
Next the testunits are built. Notice The first test is populated with testcase.args which
match the test method's args/kwargs.
The second test is the same method but has autoarg=False disabling this autopopulation of args.
```

Creating testunit:my_first_test_method, args:
[2015-05-12 13:32:15,421] [eutestcase] [DEBUG]: (populate_testunit_with_args:1351): Attempting to populate testunit:my_first_test_method, with testcase.args...
[2015-05-12 13:32:15,422] [eutestcase] [DEBUG]: (populate_testunit_with_args:1359): Testunit keyword args:{}
[2015-05-12 13:32:15,423] [eutestcase] [DEBUG]: (populate_testunit_with_args:1364): Got method args:('ip', 'username', 'password')
[2015-05-12 13:32:15,424] [eutestcase] [DEBUG]: (populate_testunit_with_args:1372): test unit total args:{}
[2015-05-12 13:32:15,425] [eutestcase] [DEBUG]: (populate_testunit_with_args:1378): Found matching arg for:password
Creating testunit:my_first_test_method, args:
Creating testunit:too_lazy_to_run, args:
[2015-05-12 13:32:15,426] [eutestcase] [DEBUG]: (populate_testunit_with_args:1351): Attempting to populate testunit:too_lazy_to_run, with testcase.args...
[2015-05-12 13:32:15,427] [eutestcase] [DEBUG]: (populate_testunit_with_args:1359): Testunit keyword args:{}
[2015-05-12 13:32:15,428] [eutestcase] [DEBUG]: (populate_testunit_with_args:1364): Got method args:()
[2015-05-12 13:32:15,429] [eutestcase] [DEBUG]: (populate_testunit_with_args:1372): test unit total args:{}
Creating testunit:sample_test_fail_method, args:
[2015-05-12 13:32:15,430] [eutestcase] [DEBUG]: (populate_testunit_with_args:1351): Attempting to populate testunit:sample_test_fail_method, with testcase.args...
[2015-05-12 13:32:15,431] [eutestcase] [DEBUG]: (populate_testunit_with_args:1359): Testunit keyword args:{}
[2015-05-12 13:32:15,432] [eutestcase] [DEBUG]: (populate_testunit_with_args:1364): Got method args:()
[2015-05-12 13:32:15,433] [eutestcase] [DEBUG]: (populate_testunit_with_args:1372): test unit total args:{}
Creating testunit:hope_i_get_to_run, args:
[2015-05-12 13:32:15,434] [eutestcase] [DEBUG]: (populate_testunit_with_args:1351): Attempting to populate testunit:hope_i_get_to_run, with testcase.args...
[2015-05-12 13:32:15,435] [eutestcase] [DEBUG]: (populate_testunit_with_args:1359): Testunit keyword args:{}
[2015-05-12 13:32:15,436] [eutestcase] [DEBUG]: (populate_testunit_with_args:1364): Got method args:()
[2015-05-12 13:32:15,437] [eutestcase] [DEBUG]: (populate_testunit_with_args:1372): test unit total args:{}

```
And the tests are run, each test prints the test method's
docstring and the arguments is is being run with.
This test unit should show a passing test unit...
```

[2015-05-12 13:32:15,439] [eutestcase] [DEBUG]: (print_test_unit_startmsg:870):
-------------------------------------------------------------------------
STARTING TESTUNIT: my_first_test_method
METHOD:my_first_test_method, TEST DESCRIPTION:
Description: This description will be displayed in the test run output and should
explain this test's objectives, progression, any artifacts it creates/removes, dependencies,
etc..
This test attempts to ssh into a remote device (in practice this might be a VM/instance)
and verify the end host is alive by executing 2 commands; 'hostname' and 'uptime', verifies
the return code of the commands to be '0', and prints the output out at debug level.
End on Failure:False
Passing ARGS:
---------------------
password : foobar
---------------------
Running list method: "my_first_test_method(username:None,ip:None,password:foobar)"
-------------------------------------------------------------------------
KWARG:password = foobar
SSH connection has hostname:10.111.5.100 user:root password:f****r
SSH connection attempt(1 of 1), host:'root@10.111.5.100', using ipv4:10.111.5.100, thru proxy:'None'
SSH - Connected to 10.111.5.100
[2015-05-12 13:32:15,825] [eutestcase] [DEBUG]: (my_first_test_method:67): my_first_test_method passed yay!!
[2015-05-12 13:32:15,827] [eutestcase] [DEBUG]: (my_first_test_method:68): Heres the output of our two commands:
[2015-05-12 13:32:15,827] [eutestcase] [DEBUG]: (my_first_test_method:68): c-39.qa1.eucalyptus-systems.com
[2015-05-12 13:32:15,827] [eutestcase] [DEBUG]: (my_first_test_method:68): 13:32:14 up 101 days, 22:41,  1 user,  load average: 0.00, 0.00, 0.00
[2015-05-12 13:32:15,827] [eutestcase] [DEBUG]: (my_first_test_method:68):
[2015-05-12 13:32:15,828] [eutestcase] [DEBUG]: (endtestunit:702):
-------------------------------------------------------------------------
- UNIT ENDED - my_first_test_method
-------------------------------------------------------------------------

```
Test summary is printed at the end of each unit
This next test shows an example of a test failure
```

[2015-05-12 13:32:15,830] [eutestcase] [DEBUG]: (run_test_case_list:809): RESULTS SUMMARY FOR 'eutestcase':
[2015-05-12 13:32:15,830] [eutestcase] [DEBUG]: (run_test_case_list:809):
[2015-05-12 13:32:15,830] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 13:32:15,830] [eutestcase] [DEBUG]: (run_test_case_list:809): | TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
[2015-05-12 13:32:15,830] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 13:32:15,830] [eutestcase] [DEBUG]: (run_test_case_list:809): | 5       | 0       | 1       | 4       | 0
[2015-05-12 13:32:15,830] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 13:32:15,830] [eutestcase] [DEBUG]: (run_test_case_list:809):

```
The next test unit is the same method as the previous test but is not using autoargs.
This test will fail because the unit was not passed password directly, and is expecting
the 'instance_password' arg to be set instead of the 'password' arg which is currently set.
This test has eof (end on failure) set to False which will allow the sequence to continue
despite this test failing.
```

[2015-05-12 13:32:15,831] [eutestcase] [DEBUG]: (print_test_unit_startmsg:870):
-------------------------------------------------------------------------
STARTING TESTUNIT: my_first_test_method
METHOD:my_first_test_method, TEST DESCRIPTION:
Description: This description will be displayed in the test run output and should
explain this test's objectives, progression, any artifacts it creates/removes, dependencies,
etc..
This test attempts to ssh into a remote device (in practice this might be a VM/instance)
and verify the end host is alive by executing 2 commands; 'hostname' and 'uptime', verifies
the return code of the commands to be '0', and prints the output out at debug level.
End on Failure:False
Passing ARGS:""
Running list method: "my_first_test_method(username:None,ip:None,password:None)"
-------------------------------------------------------------------------

TESTUNIT FAILED: my_first_test_methodTraceback (most recent call last):
  File "/Users/clarkmatthew/Documents/python_workspace/eutester_qa/eutester/eutester/eutestcase.py", line 279, in run
    ret = self.method()
  File "test.py", line 51, in my_first_test_method
    .format(ip, password))
ValueError: Need ip and password to run this ssh test! ip=10.111.5.100, password=None

[2015-05-12 13:32:15,833] [eutestcase] [DEBUG]: (endtestunit:702):
-------------------------------------------------------------------------
- UNIT ENDED - my_first_test_method
-------------------------------------------------------------------------

[2015-05-12 13:32:15,834] [eutestcase] [DEBUG]: (run_test_case_list:809): RESULTS SUMMARY FOR 'eutestcase':
[2015-05-12 13:32:15,834] [eutestcase] [DEBUG]: (run_test_case_list:809):
[2015-05-12 13:32:15,834] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 13:32:15,834] [eutestcase] [DEBUG]: (run_test_case_list:809): | TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
[2015-05-12 13:32:15,834] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 13:32:15,834] [eutestcase] [DEBUG]: (run_test_case_list:809): | 5       | 1       | 1       | 3       | 0
[2015-05-12 13:32:15,834] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 13:32:15,834] [eutestcase] [DEBUG]: (run_test_case_list:809):

```
Next test shows an example of how to skip a test from within the test unit
```

[2015-05-12 13:32:15,836] [eutestcase] [DEBUG]: (print_test_unit_startmsg:870):
-------------------------------------------------------------------------
STARTING TESTUNIT: too_lazy_to_run
METHOD:too_lazy_to_run, TEST DESCRIPTION:

End on Failure:False
Passing ARGS:""
Running list method: "too_lazy_to_run()"
-------------------------------------------------------------------------
TESTUNIT SKIPPED:too_lazy_to_run
'Im too lazy to run right now'
[2015-05-12 13:32:15,837] [eutestcase] [DEBUG]: (endtestunit:702):
-------------------------------------------------------------------------
- UNIT ENDED - too_lazy_to_run
-------------------------------------------------------------------------

[2015-05-12 13:32:15,838] [eutestcase] [DEBUG]: (run_test_case_list:809): RESULTS SUMMARY FOR 'eutestcase':
[2015-05-12 13:32:15,838] [eutestcase] [DEBUG]: (run_test_case_list:809):
[2015-05-12 13:32:15,838] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 13:32:15,838] [eutestcase] [DEBUG]: (run_test_case_list:809): | TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
[2015-05-12 13:32:15,838] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 13:32:15,838] [eutestcase] [DEBUG]: (run_test_case_list:809): | 5       | 1       | 1       | 3       | 0
[2015-05-12 13:32:15,838] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 13:32:15,838] [eutestcase] [DEBUG]: (run_test_case_list:809):

```
This test shows an example of a test case which fails. This test is also using
the eof (end of failure) flag which will abort the sequence and not run any remaining test
units.
```

[2015-05-12 13:32:15,839] [eutestcase] [DEBUG]: (print_test_unit_startmsg:870):
-------------------------------------------------------------------------
STARTING TESTUNIT: sample_test_fail_method
METHOD:sample_test_fail_method, TEST DESCRIPTION:
Description: This test should demonstrate a failure...
End on Failure:True
Passing ARGS:""
Running list method: "sample_test_fail_method()"
-------------------------------------------------------------------------
SSH connection has hostname:10.111.5.100 user:noone password:b*********d
SSH connection attempt(1 of 1), host:'noone@10.111.5.100', using ipv4:10.111.5.100, thru proxy:'None'
Failed to connect to 10.111.5.100, retry in 10 seconds. Err:Authentication failed.

TESTUNIT FAILED: sample_test_fail_methodTraceback (most recent call last):
  File "/Users/clarkmatthew/Documents/python_workspace/eutester_qa/eutester/eutester/eutestcase.py", line 279, in run
    ret = self.method()
  File "test.py", line 75, in sample_test_fail_method
    return my_first_test_method(ip=None, username='noone', password='badpassword')
  File "test.py", line 55, in my_first_test_method
    verbose=True)
  File "/Users/clarkmatthew/Documents/python_workspace/eutester_qa/eutester/eutester/sshconnection.py", line 267, in __init__
    verbose=self.debug_connect)
  File "/Users/clarkmatthew/Documents/python_workspace/eutester_qa/eutester/eutester/sshconnection.py", line 764, in get_ssh_connection
    ". IPs tried:" + ",".join(iplist))
Exception: Failed to connect to "10.111.5.100", attempts:1. IPs tried:10.111.5.100

[2015-05-12 13:32:28,086] [eutestcase] [DEBUG]: (run_test_case_list:801): Testcase:sample_test_fail_method error:Failed to connect to "10.111.5.100", attempts:1. IPs tried:10.111.5.100
[2015-05-12 13:32:28,087] [eutestcase] [DEBUG]: (endfailure:710):
-------------------------------------------------------------------------
- FAILED - sample_test_fail_method
-------------------------------------------------------------------------


```
After all the test have run the summary is printed below. Notice the last test method was not
run due to test3 failing. Test3 had the eof (end on failure) flag set to True which aborts
the sequence.
```

[2015-05-12 13:32:28,089] [eutestcase] [DEBUG]: (run_test_case_list:819): Printing pre-cleanup results:
[2015-05-12 13:32:28,091] [eutestcase] [DEBUG]: (<lambda>:966): Test list results for testcase:eutestcase
[2015-05-12 13:32:28,092] [eutestcase] [DEBUG]: (run_test_case_list:821):
-------------------------------------------------------------------------
RUN TEST CASE LIST DONE:
Ran 4/5 tests in 12 seconds

TESTUNIT LIST SUMMARY FOR eutestcase

--------------------------------------------------------------------------------
                    | RESULT: passed
                    | TEST NAME: my_first_test_method
                    | TIME : 0
                    | ARGS: my_first_test_method(username:None,ip:None,password:foobar)
--------------------------------------------------------------------------------
                    | RESULT: failed
                    | TEST NAME: my_first_test_method
                    | TIME : 0
                    | ARGS: my_first_test_method(username:None,ip:None,password:None)
ERROR:(my_first_test_method): Need ip and password to run this ssh test! ip=10.111.5.100, password=None

--------------------------------------------------------------------------------
                    | RESULT: not_run
                    | TEST NAME: too_lazy_to_run
                    | TIME : 0
                    | ARGS: too_lazy_to_run()
NOT_RUN:(too_lazy_to_run): 'Im too lazy to run right now'

--------------------------------------------------------------------------------
                    | RESULT: failed
                    | TEST NAME: sample_test_fail_method
                    | TIME : 12
                    | ARGS: sample_test_fail_method()
ERROR:(sample_test_fail_method): Failed to connect to "10.111.5.100", attempts:1. IPs tried:10.111.5.100

--------------------------------------------------------------------------------
                    | RESULT: not_run
                    | TEST NAME: hope_i_get_to_run
                    | TIME : 0
                    | ARGS: hope_i_get_to_run()
NOT_RUN:(hope_i_get_to_run):

--------------------------------------------------------------------------------
RESULTS SUMMARY FOR 'eutestcase':

------------------------------------------------------
| TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
------------------------------------------------------
| 5       | 2       | 1       | 2       | 12
------------------------------------------------------


-------------------------------------------------------------------------
passed:1 failed:2 not_run:2 total:5

```
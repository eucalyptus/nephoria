## Sample test 'sample_testsuite.py' and it's output.



File: sample_testsuite.py
```
#!/usr/bin/python
from eutester.testcase_utils.eutestcase import EutesterTestCase
from cloud_utils.net_utils.sshconnection import SshConnection

# Create the testcase object
testcase = EutesterTestCase()


# See 'setup_parser' for all the default cli arguments. These can be negated by setting
# these to 'false' as shown here...
testcase.setup_parser(testname='My first test',
                      description='Sample testcase',
                      emi=False, # exclude the emi cli option from this test
                      testlist=False # Exclude the 'testlist' cli option for this test
                      )


# Add an additional CLI argument to this test
testcase.parser.add_argument('--test_ip',
                             help='IP address used to create SSH connection sample test',
                             default=None)


# Gather CLI arguments, this will also parse any arguments in any config files
# that are provided. The cli args and config file args will be merged into testcase.args
testcase.get_args()


# Add a test method, Name is not important to running, but does help organize the suite.
# Methods will later be used/created when converted to testunit class objs shown later(at bottom)
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

    # SshConnection.sys() will execute a cmd on the remote system, 'code' will check the return code of the
    # command and throw an exception if it does not match the value provided.
    # By default the returned output is a list of lines, but can also be returned as a single
    # string buffer using 'listformat=False')
    # The command is monitored and the session will be torn down and a timeout exception will be
    # thrown if it does not return by 'timeout' seconds.
    output = ssh.sys('hostname && uptime', listformat=False, code=0, timeout=20)


    # default logger writes to stdout and it's debug level method can be used such as...
    testcase.debug('my_first_test_method passed yay!!')
    testcase.debug('Heres the output of our two commands:\n{0}'.format(output))


# Now add a method that is intended to fail...
testcase.sample_test_fail_method = lambda: my_first_test_method(ip=None,
                                                                username='root',
                                                                password='badpassword')

# Create our test list of test units...
# this can be done by using a method or the name of a method within the testcase class...
# by passing a method
test1 = testcase.create_testunit_from_method(my_first_test_method)

# By passing a name of a method local to the testcase object
test2 = testcase.create_testunit_by_name('sample_test_fail_method')

result = testcase.run_test_case_list(list = [test1, test2],
                                     eof=False,
                                     clean_on_exit=False,
                                     printresults=True)

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
[2015-05-12 12:54:27,255] [eutestcase] [DEBUG]: (setuptestcase:339): <pre>
[2015-05-12 12:54:27,256] [eutestcase] [DEBUG]: (show_self:1312):
-------------------------------------------------------------------------
TESTCASE INFO:
----------
NAME:                     --->:  eutestcase
TEST LIST:                --->:  []
CONFIG FILES:             --->:  []
-------------------------------------------------------------------------
[2015-05-12 12:54:27,257] [eutestcase] [DEBUG]: (show_args:1333):
-------------------------------------------------------------------------
TEST ARGS:                       VALUE:
----------                      ------
debug_method              --->:  <bound method EutesterTestCase.debug of <eutester.eutestcase.EutesterTestCase testMethod=eutestcase>>
logger                    --->:  <eutester.eulogger.Eulogger object at 0x10db2c810>
-------------------------------------------------------------------------
setup_debugmethod:
testcasename:None
log_level:None
logfile:None
logfile_level:None
Starting setup_debugmethod, name:eutestcase
After populating... setup_debugmethod: testcasename:Nonelog_level:debuglogfile:Nonelogfile_level:debug
[2015-05-12 12:54:27,259] [eutestcase] [DEBUG]: (show_self:1312):
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
[2015-05-12 12:54:27,261] [eutestcase] [DEBUG]: (show_args:1333):
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
logger                    --->:  <eutester.eulogger.Eulogger object at 0x10db351d0>
password                  --->:  foobar
region                    --->:  None
test_ip                   --->:  10.111.5.100
use_color                 --->:  False
user_data                 --->:  None
vmtype                    --->:  c1.medium
zone                      --->:  None
-------------------------------------------------------------------------

```
Next the testunits are built...
```

Creating testunit:my_first_test_method, args:
[2015-05-12 12:54:27,262] [eutestcase] [DEBUG]: (populate_testunit_with_args:1351): Attempting to populate testunit:my_first_test_method, with testcase.args...
[2015-05-12 12:54:27,263] [eutestcase] [DEBUG]: (populate_testunit_with_args:1359): Testunit keyword args:{}
[2015-05-12 12:54:27,264] [eutestcase] [DEBUG]: (populate_testunit_with_args:1364): Got method args:('ip', 'username', 'password')
[2015-05-12 12:54:27,265] [eutestcase] [DEBUG]: (populate_testunit_with_args:1372): test unit total args:{}
[2015-05-12 12:54:27,266] [eutestcase] [DEBUG]: (populate_testunit_with_args:1378): Found matching arg for:password
Creating testunit:too_lazy_to_run, args:
[2015-05-12 12:54:27,267] [eutestcase] [DEBUG]: (populate_testunit_with_args:1351): Attempting to populate testunit:too_lazy_to_run, with testcase.args...
[2015-05-12 12:54:27,268] [eutestcase] [DEBUG]: (populate_testunit_with_args:1359): Testunit keyword args:{}
[2015-05-12 12:54:27,269] [eutestcase] [DEBUG]: (populate_testunit_with_args:1364): Got method args:()
[2015-05-12 12:54:27,270] [eutestcase] [DEBUG]: (populate_testunit_with_args:1372): test unit total args:{}
Creating testunit:sample_test_fail_method, args:
[2015-05-12 12:54:27,271] [eutestcase] [DEBUG]: (populate_testunit_with_args:1351): Attempting to populate testunit:sample_test_fail_method, with testcase.args...
[2015-05-12 12:54:27,272] [eutestcase] [DEBUG]: (populate_testunit_with_args:1359): Testunit keyword args:{}
[2015-05-12 12:54:27,273] [eutestcase] [DEBUG]: (populate_testunit_with_args:1364): Got method args:()
[2015-05-12 12:54:27,274] [eutestcase] [DEBUG]: (populate_testunit_with_args:1372): test unit total args:{}
Creating testunit:hope_i_get_to_run, args:
[2015-05-12 12:54:27,275] [eutestcase] [DEBUG]: (populate_testunit_with_args:1351): Attempting to populate testunit:hope_i_get_to_run, with testcase.args...
[2015-05-12 12:54:27,276] [eutestcase] [DEBUG]: (populate_testunit_with_args:1359): Testunit keyword args:{}
[2015-05-12 12:54:27,277] [eutestcase] [DEBUG]: (populate_testunit_with_args:1364): Got method args:()
[2015-05-12 12:54:27,278] [eutestcase] [DEBUG]: (populate_testunit_with_args:1372): test unit total args:{}

```
And the tests are run, each test prints the test method's
docstring and the arguments is is being run with.
This test unit should show a passing test unit...
```


[2015-05-12 12:54:27,279] [eutestcase] [DEBUG]: (print_test_unit_startmsg:870):
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
[2015-05-12 12:54:27,666] [eutestcase] [DEBUG]: (my_first_test_method:60): my_first_test_method passed yay!!
[2015-05-12 12:54:27,668] [eutestcase] [DEBUG]: (my_first_test_method:61): Heres the output of our two commands:
[2015-05-12 12:54:27,668] [eutestcase] [DEBUG]: (my_first_test_method:61): c-39.qa1.eucalyptus-systems.com
[2015-05-12 12:54:27,668] [eutestcase] [DEBUG]: (my_first_test_method:61): 12:54:26 up 101 days, 22:04,  1 user,  load average: 0.00, 0.00, 0.00
[2015-05-12 12:54:27,668] [eutestcase] [DEBUG]: (my_first_test_method:61):
[2015-05-12 12:54:27,670] [eutestcase] [DEBUG]: (endtestunit:702):
-------------------------------------------------------------------------
- UNIT ENDED - my_first_test_method
-------------------------------------------------------------------------

```
Test summary is printed at the end of each unit
This next test shows an example of a test failure
```

[2015-05-12 12:54:27,671] [eutestcase] [DEBUG]: (run_test_case_list:809): RESULTS SUMMARY FOR 'eutestcase':
[2015-05-12 12:54:27,671] [eutestcase] [DEBUG]: (run_test_case_list:809):
[2015-05-12 12:54:27,672] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 12:54:27,672] [eutestcase] [DEBUG]: (run_test_case_list:809): | TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
[2015-05-12 12:54:27,672] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 12:54:27,672] [eutestcase] [DEBUG]: (run_test_case_list:809): | 4       | 0       | 1       | 3       | 0
[2015-05-12 12:54:27,672] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 12:54:27,672] [eutestcase] [DEBUG]: (run_test_case_list:809):

```
Next test shows an example of how to skip a test from within the test unit
```
[2015-05-12 12:54:27,673] [eutestcase] [DEBUG]: (print_test_unit_startmsg:870):
-------------------------------------------------------------------------
STARTING TESTUNIT: too_lazy_to_run
METHOD:too_lazy_to_run, TEST DESCRIPTION:

End on Failure:False
Passing ARGS:""
Running list method: "too_lazy_to_run()"
-------------------------------------------------------------------------
TESTUNIT SKIPPED:too_lazy_to_run
'Im too lazy to run right now'
[2015-05-12 12:54:27,675] [eutestcase] [DEBUG]: (endtestunit:702):
-------------------------------------------------------------------------
- UNIT ENDED - too_lazy_to_run
-------------------------------------------------------------------------

[2015-05-12 12:54:27,676] [eutestcase] [DEBUG]: (run_test_case_list:809): RESULTS SUMMARY FOR 'eutestcase':
[2015-05-12 12:54:27,676] [eutestcase] [DEBUG]: (run_test_case_list:809):
[2015-05-12 12:54:27,676] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 12:54:27,676] [eutestcase] [DEBUG]: (run_test_case_list:809): | TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
[2015-05-12 12:54:27,676] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 12:54:27,676] [eutestcase] [DEBUG]: (run_test_case_list:809): | 4       | 0       | 1       | 3       | 0
[2015-05-12 12:54:27,676] [eutestcase] [DEBUG]: (run_test_case_list:809): ------------------------------------------------------
[2015-05-12 12:54:27,676] [eutestcase] [DEBUG]: (run_test_case_list:809):

```
This test shows an example of a test case which fails...
```

[2015-05-12 12:54:27,677] [eutestcase] [DEBUG]: (print_test_unit_startmsg:870):
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
  File "test.py", line 66, in sample_test_fail_method
    return my_first_test_method(ip=None, username='noone', password='badpassword')
  File "test.py", line 48, in my_first_test_method
    verbose=True)
  File "/Users/clarkmatthew/Documents/python_workspace/eutester_qa/eutester/eutester/sshconnection.py", line 267, in __init__
    verbose=self.debug_connect)
  File "/Users/clarkmatthew/Documents/python_workspace/eutester_qa/eutester/eutester/sshconnection.py", line 764, in get_ssh_connection
    ". IPs tried:" + ",".join(iplist))
Exception: Failed to connect to "10.111.5.100", attempts:1. IPs tried:10.111.5.100

[2015-05-12 12:54:39,789] [eutestcase] [DEBUG]: (run_test_case_list:801): Testcase:sample_test_fail_method error:Failed to connect to "10.111.5.100", attempts:1. IPs tried:10.111.5.100
[2015-05-12 12:54:39,791] [eutestcase] [DEBUG]: (endfailure:710):
-------------------------------------------------------------------------
- FAILED - sample_test_fail_method
-------------------------------------------------------------------------

[2015-05-12 12:54:39,793] [eutestcase] [DEBUG]: (run_test_case_list:819): Printing pre-cleanup results:
[2015-05-12 12:54:39,795] [eutestcase] [DEBUG]: (<lambda>:966): Test list results for testcase:eutestcase
[2015-05-12 12:54:39,796] [eutestcase] [DEBUG]: (run_test_case_list:821):

```
After all the test have run the summary is printed below. Notice the last test method was not
run due to test3 failing. Test3 had the eof (end on failure) flag set to True which aborts
the sequence.
```

-------------------------------------------------------------------------
RUN TEST CASE LIST DONE:
Ran 3/4 tests in 12 seconds

TESTUNIT LIST SUMMARY FOR eutestcase

--------------------------------------------------------------------------------
                    | RESULT: passed
                    | TEST NAME: my_first_test_method
                    | TIME : 0
                    | ARGS: my_first_test_method(username:None,ip:None,password:foobar)
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
| 4       | 1       | 1       | 2       | 12
------------------------------------------------------


-------------------------------------------------------------------------
```
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






## TEST Output from sample_testsuite.py...




```
### python sample_testsuite.py --test_ip 10.111.5.100 --instance-password foobar --use_color
setuptestname:None
setup_debugmethod:
testcasename:None
log_level:None
logfile:None
logfile_level:debug
Starting setup_debugmethod, name:eutestcase
After populating... setup_debugmethod: testcasename:Nonelog_level:debuglogfile:Nonelogfile_level:debug
[2015-05-12 12:13:16,418] [eutestcase] [DEBUG]: (setuptestcase:438): <pre>
[2015-05-12 12:13:16,419] [eutestcase] [DEBUG]: (show_self:1406):
-------------------------------------------------------------------------
TESTCASE INFO:
----------
NAME:                     --->:  eutestcase
TEST LIST:                --->:  []
CONFIG FILES:             --->:  []
-------------------------------------------------------------------------
[2015-05-12 12:13:16,419] [eutestcase] [DEBUG]: (show_args:1427):
-------------------------------------------------------------------------
TEST ARGS:                       VALUE:
----------                      ------
debug_method              --->:  <bound method EutesterTestCase.debug of <eutester.testcase_utils.eutestcase.EutesterTestCase testMethod=eutestcase>>
logger                    --->:  <cloud_utils.log_utils.eulogger.Eulogger object at 0x10b0f0410>
-------------------------------------------------------------------------
setup_debugmethod:
testcasename:None
log_level:None
logfile:None
logfile_level:None
Starting setup_debugmethod, name:eutestcase
After populating... setup_debugmethod: testcasename:Nonelog_level:debuglogfile:Nonelogfile_level:debug
[2015-05-12 12:13:16,422] [eutestcase] [DEBUG]: (show_self:1406):
-------------------------------------------------------------------------
TESTCASE INFO:
----------
NAME:                     --->:  eutestcase
TEST LIST:                --->:  []
CONFIG FILES:             --->:  []
-------------------------------------------------------------------------
[2015-05-12 12:13:16,422] [eutestcase] [DEBUG]: (show_self:1406):
-------------------------------------------------------------------------
TESTCASE INFO:
----------
NAME:                     --->:  eutestcase
TEST LIST:                --->:  []
CONFIG FILES:             --->:  []
-------------------------------------------------------------------------
[2015-05-12 12:13:16,423] [eutestcase] [DEBUG]: (show_args:1427):
-------------------------------------------------------------------------
TEST ARGS:                       VALUE:
----------                      ------
args                      --->:  Namespace(config=None, config_file=None, configblocks=[], configfile=None, configsections=['MEMO', 'globals', 'eutestcase'], cred_path=None, credpath=None, html_anchors=False, ignoreblocks=[], instance_password='foobar', instance_user='root', keypair=None, log_level='debug', logfile=None, logfile_level='debug', password=None, region=None, test_ip='10.111.5.100', use_color=True, user_data=None, vmtype='c1.medium', zone=None)
config                    --->:  None
config_file               --->:  None
configblocks              --->:  []
configfile                --->:  None
configsections            --->:  ['MEMO', 'globals', 'eutestcase']
cred_path                 --->:  None
credpath                  --->:  None
debug_method              --->:  <bound method EutesterTestCase.debug of <eutester.testcase_utils.eutestcase.EutesterTestCase testMethod=eutestcase>>
html_anchors              --->:  False
ignoreblocks              --->:  []
instance_password         --->:  foobar
instance_user             --->:  root
keypair                   --->:  None
log_level                 --->:  debug
logfile                   --->:  None
logfile_level             --->:  debug
logger                    --->:  <cloud_utils.log_utils.eulogger.Eulogger object at 0x10b0f0d90>
password                  --->:  None
region                    --->:  None
test_ip                   --->:  10.111.5.100
use_color                 --->:  True
user_data                 --->:  None
vmtype                    --->:  c1.medium
zone                      --->:  None
-------------------------------------------------------------------------
[2015-05-12 12:13:16,423] [eutestcase] [DEBUG]: (show_args:1427):
-------------------------------------------------------------------------
TEST ARGS:                       VALUE:
----------                      ------
args                      --->:  Namespace(config=None, config_file=None, configblocks=[], configfile=None, configsections=['MEMO', 'globals', 'eutestcase'], cred_path=None, credpath=None, html_anchors=False, ignoreblocks=[], instance_password='foobar', instance_user='root', keypair=None, log_level='debug', logfile=None, logfile_level='debug', password=None, region=None, test_ip='10.111.5.100', use_color=True, user_data=None, vmtype='c1.medium', zone=None)
config                    --->:  None
config_file               --->:  None
configblocks              --->:  []
configfile                --->:  None
configsections            --->:  ['MEMO', 'globals', 'eutestcase']
cred_path                 --->:  None
credpath                  --->:  None
debug_method              --->:  <bound method EutesterTestCase.debug of <eutester.testcase_utils.eutestcase.EutesterTestCase testMethod=eutestcase>>
html_anchors              --->:  False
ignoreblocks              --->:  []
instance_password         --->:  foobar
instance_user             --->:  root
keypair                   --->:  None
log_level                 --->:  debug
logfile                   --->:  None
logfile_level             --->:  debug
logger                    --->:  <cloud_utils.log_utils.eulogger.Eulogger object at 0x10b0f0d90>
password                  --->:  None
region                    --->:  None
test_ip                   --->:  10.111.5.100
use_color                 --->:  True
user_data                 --->:  None
vmtype                    --->:  c1.medium
zone                      --->:  None
-------------------------------------------------------------------------
Creating testunit:my_first_test_method, args:
[2015-05-12 12:13:16,424] [eutestcase] [DEBUG]: (populate_testunit_with_args:1445): Attempting to populate testunit:my_first_test_method, with testcase.args...
[2015-05-12 12:13:16,424] [eutestcase] [DEBUG]: (populate_testunit_with_args:1445): Attempting to populate testunit:my_first_test_method, with testcase.args...
[2015-05-12 12:13:16,425] [eutestcase] [DEBUG]: (populate_testunit_with_args:1453): Testunit keyword args:{}
[2015-05-12 12:13:16,425] [eutestcase] [DEBUG]: (populate_testunit_with_args:1453): Testunit keyword args:{}
[2015-05-12 12:13:16,426] [eutestcase] [DEBUG]: (populate_testunit_with_args:1458): Got method args:('ip', 'username', 'password')
[2015-05-12 12:13:16,426] [eutestcase] [DEBUG]: (populate_testunit_with_args:1458): Got method args:('ip', 'username', 'password')
[2015-05-12 12:13:16,427] [eutestcase] [DEBUG]: (populate_testunit_with_args:1466): test unit total args:{}
[2015-05-12 12:13:16,427] [eutestcase] [DEBUG]: (populate_testunit_with_args:1466): test unit total args:{}
[2015-05-12 12:13:16,428] [eutestcase] [DEBUG]: (populate_testunit_with_args:1472): Found matching arg for:password
[2015-05-12 12:13:16,428] [eutestcase] [DEBUG]: (populate_testunit_with_args:1472): Found matching arg for:password
Creating testunit:<lambda>, args:
[2015-05-12 12:13:16,429] [eutestcase] [DEBUG]: (populate_testunit_with_args:1445): Attempting to populate testunit:<lambda>, with testcase.args...
[2015-05-12 12:13:16,429] [eutestcase] [DEBUG]: (populate_testunit_with_args:1445): Attempting to populate testunit:<lambda>, with testcase.args...
[2015-05-12 12:13:16,430] [eutestcase] [DEBUG]: (populate_testunit_with_args:1453): Testunit keyword args:{}
[2015-05-12 12:13:16,430] [eutestcase] [DEBUG]: (populate_testunit_with_args:1453): Testunit keyword args:{}
[2015-05-12 12:13:16,431] [eutestcase] [DEBUG]: (populate_testunit_with_args:1458): Got method args:()
[2015-05-12 12:13:16,431] [eutestcase] [DEBUG]: (populate_testunit_with_args:1458): Got method args:()
[2015-05-12 12:13:16,432] [eutestcase] [DEBUG]: (populate_testunit_with_args:1466): test unit total args:{}
[2015-05-12 12:13:16,432] [eutestcase] [DEBUG]: (populate_testunit_with_args:1466): test unit total args:{}
[2015-05-12 12:13:16,433] [eutestcase] [DEBUG]: (print_test_unit_startmsg:962):
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
password : None
---------------------
Running list method: "my_first_test_method(username:None,ip:None,password:None)"
-------------------------------------------------------------------------
[2015-05-12 12:13:16,433] [eutestcase] [DEBUG]: (print_test_unit_startmsg:962):
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
password : None
---------------------
Running list method: "my_first_test_method(username:None,ip:None,password:None)"
-------------------------------------------------------------------------
KWARG:password = None
SSH connection has hostname:10.111.5.100 user:root password:f****r
SSH connection attempt(1 of 1), host:'root@10.111.5.100', using ipv4:10.111.5.100, thru proxy:'None'
SSH - Connected to 10.111.5.100
[2015-05-12 12:13:17,090] [eutestcase] [DEBUG]: (my_first_test_method:60): my_first_test_method passed yay!!
[2015-05-12 12:13:17,090] [eutestcase] [DEBUG]: (my_first_test_method:60): my_first_test_method passed yay!!
[2015-05-12 12:13:17,092] [eutestcase] [DEBUG]: (my_first_test_method:61): Heres the output of our two commands:
[2015-05-12 12:13:17,092] [eutestcase] [DEBUG]: (my_first_test_method:61): Heres the output of our two commands:
[2015-05-12 12:13:17,092] [eutestcase] [DEBUG]: (my_first_test_method:61): c-39.qa1.eucalyptus-systems.com
[2015-05-12 12:13:17,092] [eutestcase] [DEBUG]: (my_first_test_method:61): c-39.qa1.eucalyptus-systems.com
[2015-05-12 12:13:17,092] [eutestcase] [DEBUG]: (my_first_test_method:61): 12:13:16 up 101 days, 21:22,  1 user,  load average: 0.00, 0.00, 0.00
[2015-05-12 12:13:17,092] [eutestcase] [DEBUG]: (my_first_test_method:61): 12:13:16 up 101 days, 21:22,  1 user,  load average: 0.00, 0.00, 0.00
[2015-05-12 12:13:17,092] [eutestcase] [DEBUG]: (my_first_test_method:61):
[2015-05-12 12:13:17,092] [eutestcase] [DEBUG]: (my_first_test_method:61):
[2015-05-12 12:13:17,094] [eutestcase] [DEBUG]: (endsuccess:799):
-------------------------------------------------------------------------
- UNIT ENDED - my_first_test_method
-------------------------------------------------------------------------

[2015-05-12 12:13:17,094] [eutestcase] [DEBUG]: (endsuccess:799):
-------------------------------------------------------------------------
- UNIT ENDED - my_first_test_method
-------------------------------------------------------------------------

[2015-05-12 12:13:17,095] [eutestcase] [DEBUG]: (run_test_case_list:903): RESULTS SUMMARY FOR 'eutestcase':
[2015-05-12 12:13:17,095] [eutestcase] [DEBUG]: (run_test_case_list:903): RESULTS SUMMARY FOR 'eutestcase':
[2015-05-12 12:13:17,095] [eutestcase] [DEBUG]: (run_test_case_list:903):
[2015-05-12 12:13:17,095] [eutestcase] [DEBUG]: (run_test_case_list:903):
[2015-05-12 12:13:17,095] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:17,095] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:17,096] [eutestcase] [DEBUG]: (run_test_case_list:903): | TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
[2015-05-12 12:13:17,096] [eutestcase] [DEBUG]: (run_test_case_list:903): | TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
[2015-05-12 12:13:17,096] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:17,096] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:17,096] [eutestcase] [DEBUG]: (run_test_case_list:903): | 2       | 0       | 1       | 1       | 0
[2015-05-12 12:13:17,096] [eutestcase] [DEBUG]: (run_test_case_list:903): | 2       | 0       | 1       | 1       | 0
[2015-05-12 12:13:17,096] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:17,096] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:17,096] [eutestcase] [DEBUG]: (run_test_case_list:903):
[2015-05-12 12:13:17,096] [eutestcase] [DEBUG]: (run_test_case_list:903):
[2015-05-12 12:13:17,097] [eutestcase] [DEBUG]: (print_test_unit_startmsg:962):
-------------------------------------------------------------------------
STARTING TESTUNIT: <lambda>
METHOD:<lambda>, TEST DESCRIPTION:

End on Failure:False
Passing ARGS:""
Running list method: "<lambda>()"
-------------------------------------------------------------------------
[2015-05-12 12:13:17,097] [eutestcase] [DEBUG]: (print_test_unit_startmsg:962):
-------------------------------------------------------------------------
STARTING TESTUNIT: <lambda>
METHOD:<lambda>, TEST DESCRIPTION:

End on Failure:False
Passing ARGS:""
Running list method: "<lambda>()"
-------------------------------------------------------------------------
SSH connection has hostname:10.111.5.100 user:root password:b*********d
SSH connection attempt(1 of 1), host:'root@10.111.5.100', using ipv4:10.111.5.100, thru proxy:'None'
Failed to connect to 10.111.5.100, retry in 10 seconds. Err:Authentication failed.

TESTUNIT FAILED: <lambda>Traceback (most recent call last):
  File "/Library/Python/2.7/site-packages/eutester-0.0.10-py2.7.egg/eutester/testcase_utils/eutestcase.py", line 378, in run
    ret = self.method()
  File "sample_testsuite.py", line 67, in <lambda>
    password='badpassword')
  File "sample_testsuite.py", line 48, in my_first_test_method
    verbose=True)
  File "/Library/Python/2.7/site-packages/eutester-0.0.10-py2.7.egg/cloud_utils/net_utils/sshconnection.py", line 268, in __init__
    verbose=self.debug_connect)
  File "/Library/Python/2.7/site-packages/eutester-0.0.10-py2.7.egg/cloud_utils/net_utils/sshconnection.py", line 764, in get_ssh_connection
    ". IPs tried:" + ",".join(iplist))
Exception: Failed to connect to "10.111.5.100", attempts:1. IPs tried:10.111.5.100

[2015-05-12 12:13:29,161] [eutestcase] [DEBUG]: (endsuccess:799):
-------------------------------------------------------------------------
- UNIT ENDED - <lambda>
-------------------------------------------------------------------------

[2015-05-12 12:13:29,161] [eutestcase] [DEBUG]: (endsuccess:799):
-------------------------------------------------------------------------
- UNIT ENDED - <lambda>
-------------------------------------------------------------------------

[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): RESULTS SUMMARY FOR 'eutestcase':
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): RESULTS SUMMARY FOR 'eutestcase':
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903):
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903):
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): | TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): | TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): | 2       | 1       | 1       | 0       | 12
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): | 2       | 1       | 1       | 0       | 12
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:29,163] [eutestcase] [DEBUG]: (run_test_case_list:903): ------------------------------------------------------
[2015-05-12 12:13:29,164] [eutestcase] [DEBUG]: (run_test_case_list:903):
[2015-05-12 12:13:29,164] [eutestcase] [DEBUG]: (run_test_case_list:903):
[2015-05-12 12:13:29,165] [eutestcase] [DEBUG]: (run_test_case_list:911): Printing pre-cleanup results:
[2015-05-12 12:13:29,165] [eutestcase] [DEBUG]: (run_test_case_list:911): Printing pre-cleanup results:
[2015-05-12 12:13:29,166] [eutestcase] [DEBUG]: (<lambda>:1058): Test list results for testcase:eutestcase
[2015-05-12 12:13:29,166] [eutestcase] [DEBUG]: (<lambda>:1058): Test list results for testcase:eutestcase
[2015-05-12 12:13:29,168] [eutestcase] [DEBUG]: (run_test_case_list:913):
-------------------------------------------------------------------------
RUN TEST CASE LIST DONE:
Ran 2/2 tests in 12 seconds

TESTUNIT LIST SUMMARY FOR eutestcase

--------------------------------------------------------------------------------
                    | RESULT: passed
                    | TEST NAME: my_first_test_method
                    | TIME : 0
                    | ARGS: my_first_test_method(username:None,ip:None,password:None)
--------------------------------------------------------------------------------
                    | RESULT: failed
                    | TEST NAME: <lambda>
                    | TIME : 12
                    | ARGS: <lambda>()
ERROR:(<lambda>): Failed to connect to "10.111.5.100", attempts:1. IPs tried:10.111.5.100

--------------------------------------------------------------------------------
RESULTS SUMMARY FOR 'eutestcase':

------------------------------------------------------
| TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
------------------------------------------------------
| 2       | 1       | 1       | 0       | 12
------------------------------------------------------


-------------------------------------------------------------------------
[2015-05-12 12:13:29,168] [eutestcase] [DEBUG]: (run_test_case_list:913):
-------------------------------------------------------------------------
RUN TEST CASE LIST DONE:
Ran 2/2 tests in 12 seconds

TESTUNIT LIST SUMMARY FOR eutestcase

--------------------------------------------------------------------------------
                    | RESULT: passed
                    | TEST NAME: my_first_test_method
                    | TIME : 0
                    | ARGS: my_first_test_method(username:None,ip:None,password:None)
--------------------------------------------------------------------------------
                    | RESULT: failed
                    | TEST NAME: <lambda>
                    | TIME : 12
                    | ARGS: <lambda>()
ERROR:(<lambda>): Failed to connect to "10.111.5.100", attempts:1. IPs tried:10.111.5.100

--------------------------------------------------------------------------------
RESULTS SUMMARY FOR 'eutestcase':

------------------------------------------------------
| TOTAL   | FAILED  | PASSED  | NOT_RUN | TIME_ELAPSED
------------------------------------------------------
| 2       | 1       | 1       | 0       | 12
------------------------------------------------------


-------------------------------------------------------------------------
passed:1 failed:1 not_run:0 total:2

```

from prettytable import PrettyTable
from nephoria.testcontroller import TestController
from cloud_admin.backends.network.midget import Midget
from cloud_utils.log_utils import get_traceback, markup
from cloud_utils.net_utils.sshconnection import CommandExitCodeException
from os import remove
from sys import exit
import threading
import time
import copy
from optparse import OptionParser, OptionValueError


parser = OptionParser('Instance Stress Test')

parser.add_option("-c", "--clc-ip", dest="clc_ip", default=None,
                  help="CLC IP")
parser.add_option("-p", "--password", dest="password", default='foobar',
                  help="clc ssh password")
parser.add_option("-u", "--user-count", dest="user_count", type="int", default=1,
                  help="Number of users")
parser.add_option("-v", "--vm-count", dest="vm_count", type="int", default=1,
                  help="Number of vms to run per user")
parser.add_option("-l", "--log-level", dest="log_level", default='DEBUG',
                  help="LOGLEVEL")
parser.add_option("--instance-timeout", dest="instance_timeout", type='int', default=180,
                  help="Seconds used as timeout in run-image/instance request")
parser.add_option("--prefix", dest="prefix", default='stressaccount',
                  help="Account name prefix")
parser.add_option("--account-start", dest="account_start", type='int', default=0,
                  help="Account name prefix + account-start value = accountname")
parser.add_option("--artifact-timeout", dest="artifact_timeout", type='int', default=300,
                  help="Seconds used as timeout waiting for vpc related artifacts on CLC")
parser.add_option("--freeze", dest="freeze", action='store_true', default=False,
                  help="Boolean to freeze test without cleaning up at end of test")

options, args = parser.parse_args()

count = options.user_count
vm_count = options.vm_count
log_level = str(options.log_level).upper()
clc_ip = options.clc_ip
instance_timeout = int(options.instance_timeout)
password = options.password
account_prefix = options.prefix
account_start = options.account_start
freeze_test = options.freeze
artifact_timeout = int(options.artifact_timeout)
users = []
userlock = threading.Lock()
errors = []
clc_times = {}
mido_md_times = {}
tc = TestController(clc_ip, password=password, log_level=log_level)
md = Midget(clc_ip, systemconnection=tc.sysadmin)
# Spread the love over all zones in the cloud...
max_zone_name = 0
zones = {}
zone_names = tc.sysadmin.get_all_cluster_names()
netprop = tc.sysadmin.get_property('{0}.cluster.networkmode'.format(zone_names[0]))
networkmode = netprop.value
for zone in zone_names:
    # Store the max name len for printing later
    if len(zone) > max_zone_name:
        max_zone_name = len(zone)
    # Init the zone with a 0 vm count
    zones[zone] = 0
i = 0
while i < vm_count:
    for zname in zones.iterkeys():
        if i >= vm_count:
            break
        zones[zname] += 1
        i += 1

print 'RUNNING TEST WITH ZONE VM COUNTS:'
for name, value in zones.iteritems():
    print "ZONE:{0} COUNT:{1}".format(name, value)
time.sleep(3)


def add_user(id):
    new_user = tc.create_user_using_cloudadmin(aws_user_name='admin',
                                               aws_account_name=account_prefix + str(x),
                                               service_connection=tc,
                                               log_level=log_level)
    print 'Add user found or created    :"{0}"'.format(new_user)
    new_user.ec2.log.set_stdout_loglevel(log_level)
    new_user.iam.log.set_stdout_loglevel(log_level)
    return new_user

def cleanup(user):
    try:
        user.ec2.terminate_instances()
        for key in user.ec2.test_resources['keypairs']:
            user.ec2.delete_keypair(key)
            remove(key.name + ".pem")
    except Exception as E:
        my_error = {'user':str(user), 'error':'{0}\nError:{1}'.format(get_traceback(), E)}
        with userlock:
            errors.append(my_error)

def get_clc_artifacts_for_vpc(user, vpc_ids, subnet_ids, addtime=0, interval=2,
                              timeout=artifact_timeout):
    start = time.time()
    elapsed = 0
    vpc_wait = copy.copy(vpc_ids)
    subnet_wait = copy.copy(subnet_ids)
    ret_dict = {}
    while elapsed < timeout and (vpc_wait or subnet_wait):
        user.log.info('Waiting for clc artifacts, elapsed:{0}/{1}, vpcs:{2}, subnets:{3}'
                          .format(int(elapsed + addtime), timeout, vpc_wait, subnet_wait))
        if vpc_wait:
            for vpc_id in vpc_ids:
                if vpc_id in vpc_wait:
                    for retry in xrange(0, 2):
                        try:
                            tc.sysadmin.clc_machine.sys('ps aux  | grep {0}'.format(str(vpc_id).lstrip('vpc-')), code=0)
                            if vpc_id in vpc_wait:
                                vpc_wait.remove(vpc_id)
                            ret_dict[vpc_id] = int(time.time() - start) + addtime
                            break
                        except Exception as E:
                            if isinstance(E, CommandExitCodeException):
                                pass
                            else:
                                tc.log.error("Error trying to fetch nginx ps for vpc:{0}".format(E))
                                time.sleep(1)
        if subnet_wait:
            for subnet_id in subnet_ids:
                if subnet_id in subnet_wait:
                    for retry in xrange(0, 2):
                        try:
                            tc.sysadmin.clc_machine.sys('ifconfig | grep {0}'.format(str(subnet_id).lstrip('subnet-')), code=0)
                            subnet_wait.remove(subnet_id)
                            ret_dict[subnet_id] = int(time.time() - start) + addtime
                            break
                        except Exception as E:
                            if isinstance(E, CommandExitCodeException):
                                pass
                            else:
                                tc.log.error("Error trying to fetch subnet veth:{0}".format(E))
                                time.sleep(1)

        elapsed = time.time() - start
        if elapsed < timeout and (vpc_wait or subnet_wait):
            time.sleep(interval)
        else:
            break
    for id in vpc_wait + subnet_wait:
        ret_dict[id] = 'Timedout:' + str(timeout + addtime)
    return ret_dict



def wait_for_mido_metadata_nat_rule(instances, addtime=0, interval=2, timeout=300):
    if networkmode != 'VPCMIDO':
        return {}
    start = time.time()
    elapsed = 0
    ret_dict = {}
    errbuff = ""
    waiting = copy.copy(instances)
    while waiting and elapsed < timeout:
        errbuff = ""
        for instance in instances:
            if instance in waiting:
                instance.update()
                rule = None
                try:
                    rule =  md.get_instance_bridge_port_metadata_nat_rule(instance.id)
                except Exception as E:
                    errbuff += ("{0}\nERROR fetching meta nat rule, elapsed:{1}, instance_state:{"
                                "2}, Error:{3}".format(get_traceback(),elapsed, instance.state, E))
                    if not int(elapsed) % 10:
                        md.log.error("ERROR fetching meta nat rule, elapsed:{0}, "
                                        "instance_state: {1}, Error:{2}"
                                        .format(elapsed, instance.state, E))
                if rule:
                    tc.log.info('Got MD rule for instance:{0} after elapsed{1}'
                                   .format(instance.id, elapsed))
                    try:
                        md.show_rules(rule)
                    except:
                        pass
                    elapsed = time.time() - start
                    ret_dict[instance.id] = elapsed + addtime
                    waiting.remove(instance)
                else:
                    if instance.state == 'terminated':
                        waiting.remove(instance)
                        elapsed = time.time() - start
                        ret_dict[instance.id] = "instance terminated after:{0}".format(elapsed)
        elapsed = time.time() - start
        if elapsed < timeout and waiting:
            time.sleep(interval)
    if errbuff:
        tc.log.error(errbuff)
    for instance in waiting:
        ret_dict[instance.id] = "Timed out waiting for MD after: {0}".format(int(elapsed))
    return ret_dict




def run_instance_with_user(user):
    my_error = {}
    err_string = ""
    instance_str = ""
    setattr(user, 'results', {})
    instances = []
    vpc_ids = []
    subnet_ids = []
    my_md_times = {}
    my_clc_times = None
    try:
        emi = user.ec2.get_emi(root_device_type='instance-store',
                               filters={'virtualization-type': 'hvm'},
                               basic_image=True)
        key = user.ec2.create_keypair_and_localcert('key_{0}_{1}_{2}'
                                                    .format(user.account_name, user.user_name,
                                                            int(time.time())))
        if not key:
            raise RuntimeError('Could not find or create key for account/user:{0}/{1}'
                               .format(user.account_name, user.user_name))
        group = user.ec2.add_group('group_{0}_{1}'.format(user.account_name, user.user_name))
        user.ec2.authorize_group(group=group, port=22, protocol='tcp')
        user.ec2.authorize_group(group=group, port=-1, protocol='icmp')
        start = time.time()
        for zone, count in zones.iteritems():
            instances += user.ec2.run_image(image=emi, keypair = key, group=group, min=count,
                                            max=count, zone=zone, timeout=instance_timeout,
                                            monitor_to_running=False, clean_on_fail=False,
                                            auto_connect=True)
        for i in instances:
            if not i.vpc_id in vpc_ids:
                vpc_ids.append(i.vpc_id)
            if not i.subnet_id in subnet_ids:
                subnet_ids.append(i.subnet_id)
        elapsed = int(time.time() - start)
        my_clc_times = get_clc_artifacts_for_vpc(user, vpc_ids, subnet_ids, addtime=elapsed)
        elapsed = int(time.time() - start)
        my_md_times = wait_for_mido_metadata_nat_rule(instances, addtime=elapsed)
        user.ec2.monitor_euinstances_to_running(instances, timeout=instance_timeout)
        instance_str = "\n".join("{0}:{1}".format(x.id, x.placement) for x in instances)
        my_results = {'user':str(user), 'result':'PASSED', 'instances':instance_str}
    except Exception as E:
        user.log.debug('{0}\nError:{1}'.format(get_traceback(), E))
        err_string += '{0}\nError:{1}'.format(get_traceback(), E)
        my_results = {'user':str(user), 'result': markup('FAILED', [1, 91]),
                      'instances':instance_str}
        try:
            for vpc_id in vpc_ids:
                cmd = 'ps aux  | grep {0}'.format(vpc_id)
                err_string += '\nCLC CMD#: {0}\n'.format(cmd)
                err_string += tc.sysadmin.clc_machine.sys(cmd, listformat=False)
        except Exception as E:
             tc.log.error('Failed to get vpc process info from clc:' + str(E))
        finally:
            err_string += "(CMD DONE)\n"
        try:
            for vpc_id in vpc_ids:
                cmd = 'ifconfig | grep {0}'.format(str(vpc_id).lstrip('vpc-'))
                err_string += '\nCLC CMD#: {0}\n'.format(cmd)
                err_string += tc.sysadmin.clc_machine.sys(cmd, listformat=False)
        except Exception as E:
             tc.log.error('Failed to get vpc ifconfig info from clc:' + str(E))
        finally:
            err_string += "(CMD DONE)\n"
        try:
            for subnet_id in subnet_ids:
                cmd = 'ifconfig | grep {0}'.format(str(subnet_id).lstrip('subnet-'))
                err_string += '\nCLC CMD#: {0}\n'.format(cmd)
                err_string += tc.sysadmin.clc_machine.sys(cmd, listformat=False)
        except Exception as E:
             tc.log.error('Failed to get subnet ifconfig info from clc:' + str(E))
        finally:
            err_string += "(CMD DONE)\n"
        for i in instances:
            try:
                cmd = "grep {0} /var/run/eucalyptus/eucanetd_vpc_instance_ip_map".format(i.id)
                err_string += '\nCLC CMD#: {0}\n'.format(cmd)
                err_string += tc.sysadmin.clc_machine.sys(cmd, listformat=False)
            except Exception as E:
                tc.log.error('Failed to get vpc nginx map info from clc:' + str(E))
            finally:
                err_string += "(CMD DONE)\n"
            err_string += i.get_cloud_init_info_from_console() + "\n"

    finally:
        try:
            for ins in instances:
                if ins and ins.ssh:
                    ins.ssh.close()
                ins = None
            instances = None
        except Exception as E:
            err_string += '{0}\nError:{1}'.format(get_traceback(), E)
            user.log.warn('')
        user.results = my_results
        with userlock:
            if err_string:
                my_error = {'user':str(user), 'error':err_string}
                errors.append(my_error)
            if my_clc_times:
                for key, value in my_clc_times.iteritems():
                    clc_times[key] = value
            if my_md_times:
                for key, value in my_md_times.iteritems():
                    mido_md_times[key] = value


for x in xrange(account_start, count + account_start):
    users.append(add_user(x))
tc.log.info('Done Creating Users')
upt = PrettyTable(['ACCOUNT', 'NAME', 'ACCT_ID'])
for user in users:
    upt.add_row([user.account_name, user.user_name, user.account_id])
upt.sortby='ACCOUNT'

print "\n{0}\n".format(upt)
time.sleep(5)

def print_results():
    errpt = PrettyTable(['USER', 'ERROR'])
    errpt.max_width['USER'] = 20
    errpt.max_width['ERROR'] = 100
    errpt.hrules = 1
    errpt.align = 'l'
    for err in errors:
        errpt.add_row([err.get('user'), err.get('error')])
    print "\n{0}\n".format(errpt)
    tc.log.info('User - Thread Completed! Current Results....')
    pt = PrettyTable(['ACCOUNT', 'USER', 'RESULT', 'INSTANCES'])
    pt.align = 'l'
    pt.max_width['INSTANCES'] = 11 + max_zone_name + 1
    pt.sortby = 'ACCOUNT'
    for user in users:
        if user.results:
            res = user.results
            pt.add_row([user.account_name, user.user_name, res.get('result'), res.get('instances')])
    print "\n{0}\n".format(pt)
    tt = PrettyTable(['CLC VETH', 'CREATE TIME'])
    tt.align = 'l'
    tt.hrules = 1
    for key, value in clc_times.iteritems():
        tt.add_row([key, value])
    print "\n{0}\n".format(tt)
    mdt = PrettyTable(['INSTANCE', 'MIDO MD RULE TIME'])
    mdt.align = 'l'
    mdt.hrules = 1
    for key, value in mido_md_times.iteritems():
        mdt.add_row([key, value])
    print "\n{0}\n".format(mdt)


threads = []
for user in users:
    t = threading.Thread(target=run_instance_with_user, args=(user, ))
    t.start()
    threads.append(t)
for t in threads:
    t.join()
    print_results()

if not freeze_test:
    threads = []
    for user in users:
        t = threading.Thread(target=cleanup, args=(user, ))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

print_results()
tc.log.info('User - All threads have completed')

if errors:
    exit(1)
else:
    exit(0)

from nephoria.testcontroller import TestController
from cloud_utils.log_utils import get_traceback, eulogger, red
from prettytable import PrettyTable
import time
from optparse import OptionParser
import resource
import signal
import sys





import __builtin__
openfiles = set()
oldfile = __builtin__.file

def printOpenFiles():
    print red("\n\n### %d OPEN FILES: [%s]\n\n" % (len(openfiles), ", ".join(f.x for f in openfiles)))

class newfile(oldfile):
    def __init__(self, *args):
        self.x = args[0]
        print red("### OPENING %s ###" % str(self.x))
        oldfile.__init__(self, *args)
        openfiles.add(self)
        printOpenFiles()

    def close(self):
        print red("### CLOSING %s ###" % str(self.x))
        oldfile.close(self)
        openfiles.remove(self)
        printOpenFiles()

oldopen = __builtin__.open
def newopen(*args):
    return newfile(*args)
__builtin__.file = newfile
__builtin__.open = newopen




class InstanceBatchTest():
    def __init__(self):
        self.name = 'InstanceBatchTest'
        parser = OptionParser('InstanceBatchTest')

        parser.add_option("-c", "--clc-ip", dest="clc", default=None,
                          help="CLC IP")
        parser.add_option("-p", "--password", dest="password", default='foobar',
                          help="clc ssh password")
        parser.add_option("-l", "--log-level", dest="log_level", default='DEBUG',
                          help="LOGLEVEL")
        parser.add_option("--instance-timeout", dest="instance_timeout", type='int', default=1200,
                          help="Seconds used as timeout in run-image/instance request")
        parser.add_option('--emi', type=str, default=None,
                                 help='Image id used to run VMs')
        parser.add_option('--keypair', type=str, default=None,
                                 help='EC2 Keypair name to use for VM connections, '
                                      'default:"InstanceBatchTestKey_<timestamp>"')
        parser.add_option('--zone', type=str, default=None,
                                 help='Name of availability zone to run VMs in')
        parser.add_option('--vmtype', type=str, default='t1.micro',
                                 help='Instance Vmtype to use')
        parser.add_option('--results-file', type=str, default=None,
                                 help='File to save results to')
        parser.add_option('--vm-count', type=int, default=10,
                                 help='Number of VMs to run per request')
        parser.add_option('--vm-max', type=int, default=500,
                                 help='Max or total number of VMs to run in this test')
        parser.add_option('--no-clean', default=False, action='store_true',
                          help="Do not terminate VMs during test")
        parser.add_option('--user', type=str, default='admin',
                                 help='Cloud username, default: "admin"')
        parser.add_option('--account', type=str, default='nephotest',
                                 help='Cloud account name, default:"nephotest"')


        self.args, pos = parser.parse_args()
        if not self.args.clc:
            raise ValueError('CLC must be provided. See --clc argument')
        self.log = eulogger.Eulogger('InstanceBatchTest', stdout_level=self.args.log_level)
        self.tc = TestController(self.args.clc,
                                 password=self.args.password,
                                 clouduser_account=self.args.account,
                                 clouduser_name=self.args.user,
                                 log_level=self.args.log_level)
        self.emi = self.tc.user.ec2.get_emi(emi=self.args.emi)
        self.vmtype = self.args.vmtype
        self.keyname = self.args.keypair or "InstanceBatchTestKey_{0}".format(int(time.time()))
        self.key = self.tc.user.ec2.get_keypair(key_name=self.keyname)
        self.group = self.tc.user.ec2.add_group('InstanceBatchTestGroup')
        self.tc.user.ec2.authorize_group(self.group, port=22, protocol='tcp')
        self.tc.user.ec2.authorize_group(self.group,  protocol='icmp', port=-1)
        self.tc.user.ec2.show_security_group(self.group)
        if not self.key:
            raise RuntimeError('Was not able to find or create key:"{0}". '
                               'If the key exists, it may not be in the local dir?')
        self.results = {}
        self.pt = PrettyTable(['RUN', 'START', 'TOTAL', 'NEW', 'ELAPSED'])
        self.last_kill_sig = 0
        self.kill = False


    def add_result(self, start_date, run_number, total, added, elapsed):
        self.results[run_number] = {'start_date': start_date,
                                    'total': total,
                                    'added': added,
                                    'elapsed': elapsed}
        self.pt.add_row([run_number, start_date, total, added, elapsed])
        self.log.info('')

    def run_batch_loop(self):
        error = ""
        error_count = 0
        self.log.info('Test start. Terminating all instances for user:{0}/{1}'
                      .format(self.tc.user.account_name, self.tc.user.user_name))
        if not self.args.no_clean:
            self.tc.user.ec2.connection.terminate_instances()
            #Monitor to terminated state
            self.tc.user.ec2.terminate_instances()

        existing_instances = self.tc.admin.ec2.get_instances(state='running')
        start_count = len(existing_instances)
        elapsed = 0
        run_number = 0

        added = 0
        ins_ids = []
        start_date = time.strftime("%Y-%m-%d %H:%M")
        self.add_result(start_date=start_date, run_number=run_number, total=start_count,
                        added=added, elapsed=elapsed)
        while (len(ins_ids) < self.args.vm_max) and not self.kill:
            try:
                printOpenFiles()
                run_number += 1
                start_date = time.strftime("%Y-%m-%d %H:%M")
                start_time = time.time()
                ins = self.tc.user.ec2.run_image(image=self.emi, keypair=self.key,
                                                 min=self.args.vm_count, max=self.args.vm_count,
                                                 zone=self.args.zone, type=self.vmtype,
                                                 group=self.group,
                                                 timeout=self.args.instance_timeout,
                                                 )
                elapsed = time.time() - start_time
                added = len(ins)
                total = len(self.tc.admin.ec2.get_instances(state='running'))
                for i in ins:
                    ins_ids.append(i.id)
                    try:
                        i.log.close()
                        if i.ssh:
                            i.ssh.connection.close()
                            i.ssh.close()
                    except Exception as IE:
                        printOpenFiles()
                        self.log.warning('Error closing instances fds:"{0}"'.format(IE))
                    i = None
                ins = None
                self.add_result(start_date=start_date, run_number=run_number, total=total,
                                added=added, elapsed=elapsed)
                self.log.info('\n\nDone with iteration:"{0}", ran: "{1}". Now added:{2}/{3}\n\n'
                              .format(run_number, added, len(ins_ids), self.args.vm_max))
                time.sleep(1)
            except Exception as E:
                error_count += 1
                error = "{0}\n{1}".format(get_traceback(), E)
                self.log.error(error)
                if error_count > 1:
                    raise
            self.show_results()
        self.log.info('Done with test, ran: {0} instances'.format(len(ins_ids)))
        return error

    def show_results(self):
        self.log.info('\n{0}\n'.format(self.pt))
        if self.args.results_file:
            with open(self.args.results_file, 'w') as resfile:
                resfile.write('\n{0}\n'.format(self.pt))
                resfile.flush()

    def clean_method(self):
        if not self.args.no_clean:
            self.log.info('Terminating all instances for user:{0}/{1}'
                          .format(self.tc.user.account_name, self.tc.user.user_name))
            self.tc.user.ec2.terminate_instances()

if __name__ == "__main__":

    errors =[]
    test = InstanceBatchTest()
    try:
        # In the case we want to keep each instance connection open?...
        resource.setrlimit(resource.RLIMIT_NOFILE, (10 * test.args.vm_max ,-1))
    except Exception as RE:
        test.log.warning(red('Unable to set resource limit to:"{0}", err:"{1}"'
                             .format(10 * test.args.vm_max, RE)))

    def signal_handler(signal, frame):
        kill_it = False
        now = time.time()
        if now - test.last_kill_sig < 2:
            kill_it = True
        test.last_kill_sig = now
        sys.stderr.write(red('\n\nReceived SIGINT, dumping results. (Press ctrl+c twice quickly to end test now)\n\n'))
        sys.stderr.flush()
        test.show_results()
        if kill_it:
            sys.stderr.write(red('\n\nReceived SIGINT twice within 2 seconds killing test...!\n\n'))
            sys.stderr.flush()
            sys.exit(0)
        signal.signal(signal.SIGINT, signal_handler)

    for meth in [test.run_batch_loop, test.clean_method]:
        try:
           ret = meth()
           if ret:
               test.log.error(ret)
        except Exception as E:
            test.tc.log.error('{0}\nError in test:"{1}"'.format(get_traceback(), E))
            errors.append(E)
    test.show_results()
    printOpenFiles()
    exit(len(errors) and 1)


from eutester.sshconnection import SshConnection
from eutester.eulogger import Eulogger
import re
import subprocess
keypath = '/root/.ssh/id_rsa.pub'

p = subprocess.Popen('cat {0}'.format(keypath), shell=True,
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
pub_key = p.stdout.read()
result = p.wait()
if result:
    raise RuntimeError('Error reading in key at: "{0}", errcode:{1}'.format(keypath, result))

with open('config_data') as config_data:
    lines = config_data.readlines()

ipset = set([])
ip_regex = re.compile("(^\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

for line in lines:
    match = ip_regex.match(line)
    if match:
        ipset.add(match.groups()[0])

logger = Eulogger()

for ip in ipset:
    logger = Eulogger(identifier=ip)
    ssh = SshConnection(host=ip, password='foobar', debugmethod=logger.log.debug)
    ssh.sys("echo " + pub_key + " >> ~/.ssh/authorized_keys", code=0, verbose=True)



import os.path
from cloud_utils.file_utils.eucarc import Eucarc
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.system_utils.machine import Machine
from cloud_admin.servicemgmt.adminapi import AdminApi
from cloud_utils.net_utils.sshconnection import CommandExitCodeException

eucarc_to_service_map = {
    "euare_url": 'euare',
    "ec2_url": 'compute',
    "token_url": 'tokens',
    "aws_elb_url": 'loadbalancing',
    "aws_cloudformation_url": 'cloudformation',
    "aws_cloudwatch_url": 'cloudwatch',
    "s3_url": 'objectstorage',
    "aws_iam_url": 'euare',
    "aws_simpleworkflow_url": 'simpleworkflow',
    "aws_auto_scaling_url": 'autoscaling'}

class Creds(Eucarc):
    def __init__(self,
                 aws_access_key=None,
                 aws_secret_key=None,
                 clc_ip=None,
                 username='root',
                 password=None,
                 keypath=None,
                 credpath=None,
                 proxy_ip=None,
                 proxy_username='root',
                 proxy_password=None,
                 proxy_keypath=None,
                 logger = None
                 ):
        self._adminapi = None
        self._clc_ip = clc_ip
        self.aws_secret_key = aws_secret_key
        self.aws_access_key = aws_access_key
        if not logger:
            logger = Eulogger(identifier=str(self.__class__.__name__))
        self.log = logger
        self.debug = self.log.debug
        self.clc_machine = None
        self.clc_connect_kwargs = {
            'hostname': clc_ip,
            'username': username,
            'password': password,
            'keypath': keypath,
            'proxy': proxy_ip,
            'proxy_username': proxy_username,
            'proxy_password': proxy_password,
            'proxy_keypath': proxy_keypath
        }


    @property
    def adminapi(self):
        if not self._adminapi:
            if self.aws_secret_key and self.aws_access_key and self._clc_ip:
                self._adminapi = AdminApi(host=self._clc_ip,
                                          aws_access_key_id=self.aws_access_key,
                                          aws_secret_key=self.aws_secret_key,
                                          debug_method=self.debug)
        return self._adminapi

    def update_attrs_from_cloud_services(self):
        if not self._adminapi:
            raise RuntimeError('Can not fetch service paths from cloud without an AdminApi '
                               'connection\n This requires: clc_ip, aws_access_key, '
                               'aws_secret_key')
        path_dict = self._get_service_paths_from_adminapi(self.adminapi)
        self.__dict__.update(path_dict)
        return path_dict

    @classmethod
    def _get_service_paths_from_adminapi(cls, adminapi):
        assert isinstance(adminapi, AdminApi)
        services = adminapi.get_services()
        ret_dict = {}
        for service in services:
            for key, serv_value in eucarc_to_service_map:
                if service.name == serv_value:
                    ret_dict[key] = str(service.uri)
        return ret_dict

    def get_local_eucarc(self, credpath):
        paths = [credpath]
        if not str(credpath).endswith('eucarc'):
            paths.append(os.path.join(credpath, 'eucarc'))
        for path in paths:
            if os.path.isfile(path):
                self._from_filepath(path)
        return None

    def get_remote_eucarc(self, sshconnection, credpath):
        paths = [credpath]
        if not str(credpath).endswith('eucarc'):
            paths.append(os.path.join(credpath, 'eucarc'))
        for path in paths:
            try:
                self._from_filepath(filepath=credpath, sshconnection=sshconnection)
            except:
                pass
        return None

    def connect_to_clc(self):
        self.clc = Machine(**self.clc_connect_kwargs)














    def get_credentials(self, account="eucalyptus", user="admin", force=False):
        """
        Login to the CLC and download credentials programatically for the user and account
        passed in. Defaults to admin@eucalyptus
        """
        self.debug("Starting the process of getting credentials")

        ### GET the CLCs from the config file
        clcs = self.get_component_machines("clc")
        if len(clcs) < 1:
            raise Exception("Could not find a CLC in the config file when trying to"
                            " get credentials")
        admin_cred_dir = "eucarc-" + clcs[0].hostname + "-" + account + "-" + user
        cred_file_name = "creds.zip"
        full_cred_path = admin_cred_dir + "/" + cred_file_name

        ### IF I dont already have credentials, download and sync them
        if force or self.credpath is None or not self.is_ec2_cert_active():
            ### SETUP directory remotely
            self.setup_remote_creds_dir(admin_cred_dir)

            ### Create credential from Active CLC
            # Store the zipfile info to check for active certs when iam/euare connection is
            # established later...
            self.cred_zipfile = self.create_credentials(admin_cred_dir, account, user,
                                                        zipfile=cred_file_name)
            if hasattr(self, 'euare') and self.euare:
                self.get_active_cert_for_creds(credzippath=self.cred_zipfile, account=account,
                                               user=user)
            self.debug('self.cred_zipfile: ' + str(self.cred_zipfile))
            ### SETUP directory locally
            self.setup_local_creds_dir(admin_cred_dir)

            ### DOWNLOAD creds from clc
            self.download_creds_from_clc(admin_cred_dir=os.path.dirname((self.cred_zipfile)),
                                         zipfile=os.path.basename(self.cred_zipfile))

            ### SET CREDPATH ONCE WE HAVE DOWNLOADED IT LOCALLY
            self.credpath = admin_cred_dir
            ### IF there are 2 clcs make sure to sync credentials across them
        ### sync the credentials  to all CLCs
        for clc in clcs:
            self.send_creds_to_machine(admin_cred_dir, clc)

        return admin_cred_dir

    def create_credentials(self, admin_cred_dir, account, user, zipfile='creds.zip'):
        zipfilepath = os.path.join(admin_cred_dir, zipfile)

        output = self.credential_exist_on_remote_machine(zipfilepath)
        if output['status'] == 0:
            self.debug("Found creds file, skipping euca_conf --get-credentials.")
        else:
            cmd_download_creds = str("{0}/usr/sbin/euca_conf --get-credentials {1}/creds.zip "
                                     "--cred-user {2} --cred-account {3}"
                                     .format(self.eucapath, admin_cred_dir, user, account))
            if self.clc.found(cmd_download_creds, "The MySQL server is not responding"):
                raise IOError("Error downloading credentials, looks like CLC was not running")
            if self.clc.found("unzip -o {0}/creds.zip -d {1}"
                                      .format(admin_cred_dir, admin_cred_dir),
                              "cannot find zipfile directory"):
                raise IOError("Empty ZIP file returned by CLC")
        return zipfilepath

    def get_active_cert_for_creds(self, credzippath=None, account=None, user=None, update=True):
            if credzippath is None:
                if hasattr(self, 'cred_zipfile') and self.cred_zipfile:
                    credzippath = self.cred_zipfile
                elif self.credpath:
                    credzippath = self.credpath
                else:
                    raise ValueError('cred zip file not provided or set for eutester object')
            account = account or self.account_name
            user = user or self.aws_username
            admin_cred_dir = os.path.dirname(credzippath)
            clc_eucarc = os.path.join(admin_cred_dir, 'eucarc')
            # backward compatibility
            certpath_in_eucarc = self.clc.sys(". {0} &>/dev/null && "
                                              "echo $EC2_CERT".format(clc_eucarc))
            if certpath_in_eucarc:
                certpath_in_eucarc = certpath_in_eucarc[0]
            self.debug('Current EC2_CERT path for {0}: {1}'.format(clc_eucarc, certpath_in_eucarc))
            if certpath_in_eucarc and self.get_active_id_for_cert(certpath_in_eucarc):
                self.debug("Cert/pk already exist and is active in '" +
                           admin_cred_dir + "/eucarc' file.")
            else:
                # Try to find existing active cert/key on clc first. Check admin_cred_dir then
                # do a recursive search from ssh user's home dir (likely root/)
                self.debug('Attempting to find an active cert for this account on the CLC...')
                certpaths = self.find_active_cert_and_key_in_dir(dir=admin_cred_dir) or \
                            self.find_active_cert_and_key_in_dir()
                self.debug('Found Active cert and key paths')
                if not certpaths:
                    # No existing and active certs found, create new ones...
                    self.debug('Could not find any existing active certs on clc, '
                               'trying to create new ones...')
                    certpaths = self.create_new_user_certs(admin_cred_dir, account, user)
                # Copy cert and key into admin_cred_dir
                certpath = certpaths.get('certpath')
                keypath = certpaths.get('keypath')
                newcertpath = os.path.join(admin_cred_dir, os.path.basename(certpath))
                newkeypath = os.path.join(admin_cred_dir, os.path.basename(keypath))
                self.debug('Using certpath:{0} and keypath:{1} on clc'
                           .format(newcertpath, newkeypath))
                self.clc.sys('cp {0} {1}'.format(certpath, newcertpath))
                self.clc.sys('cp {0} {1}'.format(keypath, newkeypath))
                # Update the existing eucarc with new cert and key path info...
                self.debug("Setting cert/pk in '" + admin_cred_dir + "/eucarc'")
                self.sys("echo 'export EC2_CERT=${EUCA_KEY_DIR}/" + "{0}' >> {1}"
                         .format(os.path.basename(newcertpath), clc_eucarc))
                self.sys("echo 'export EC2_PRIVATE_KEY=${EUCA_KEY_DIR}/" + "{0}' >> {1}"
                         .format(os.path.basename(newkeypath), clc_eucarc))
                self.debug('updating zip file with new cert, key and eucarc: {0}'
                           .format(credzippath))
                for updatefile in [os.path.basename(newcertpath), os.path.basename(newkeypath),
                             os.path.basename(clc_eucarc)]:
                    self.clc.sys('cd {0} && zip -g {1} {2}'
                                 .format(os.path.dirname(credzippath),
                                         os.path.basename(credzippath),
                                         updatefile), code=0)
                return credzippath

    def create_new_user_certs(self, admin_cred_dir, account, user,
                              newcertpath=None, newkeypath=None):
        eucarcpath = os.path.join(admin_cred_dir, 'eucarc')
        newcertpath = newcertpath or os.path.join(admin_cred_dir, "euca2-cert.pem")
        newkeypath = newkeypath or os.path.join(admin_cred_dir, "/euca2-pk.pem")
        #admin_certs = self.clc.sys("source {0} && /usr/bin/euare-userlistcerts | grep -v Active"
        #                           .format(eucarcpath))
        admin_certs = []
        for cert in self.get_active_certs():
            admin_certs.append(cert.get('certificate_id'))
        if len(admin_certs) > 1:
            if self.force_cert_create:
                self.debug("Found more than one certs, deleting last cert")
                self.clc.sys(". {0} &>/dev/null && "
                             "/usr/bin/euare-userdelcert -c {1} --user-name {2}"
                             .format(eucarcpath,
                                     admin_certs[admin_certs.pop()],
                                     user),
                             code=0)
            else:
                raise RuntimeWarning('No active certs were found on the clc, and there are 2'
                                     'certs outstanding. Either delete an existing '
                                     'cert or move and active cert into clc root dir.'
                                     'The option "force_cert_create" will "delete" an existing'
                                     'cert automatically and replace it.'
                                     'Warning: deleting existing certs may leave signed'
                                     'objects in cloud unrecoverable.')
        self.debug("Creating a new signing certificate for user '{0}' in account '{1}'."
                   .format(user, account))
        self.debug('New cert name:{0}, keyname:{1}'.format(os.path.basename(newcertpath),
                                                           os.path.basename(newkeypath)))

        self.clc.sys(". {0} &>/dev/null && "
                     "/usr/bin/euare-usercreatecert --user-name {1} --out {2} --keyout {3}"
                     .format(eucarcpath,
                             user,
                             newcertpath,
                             newkeypath),
                    code=0)
        return {"certpath":newcertpath, "keypath":newkeypath}

    def get_active_certs(self):
        '''
        Query system for active certs list
        :returns :list of active cert dicts
        '''
        if not hasattr(self, 'euare') or not self.euare:
            self.critical(self.markup('Cant update certs until euare interface '
                                      'is initialized', 91))
            return []
        certs = []
        resp = self.euare.get_all_signing_certs()
        if resp:
            cresp= resp.get('list_signing_certificates_response')
            if cresp:
                lscr = cresp.get('list_signing_certificates_result')
                if lscr:
                    certs = lscr.get('certificates', [])
        return certs

    def get_active_id_for_cert(self, certpath, machine=None):
        '''
        Attempt to get the cloud's active id for a certificate at 'certpath' on
        the 'machine' filesystem. Also see is_ec2_cert_active() for validating the current
        cert in use or the body (string buffer) of a cert.
        :param certpath: string representing the certificate path on the machines filesystem
        :param machine: Machine obj which certpath exists on
        :returns :str() certificate id (if cert is found to be active) else None
        '''
        if not certpath:
            raise ValueError('No ec2 certpath provided or set for eutester obj')
        machine = machine or self.clc
        self.debug('Verifying cert: "{0}"...'.format(certpath))
        body = str("\n".join(machine.sys('cat {0}'.format(certpath), verbose=False)) ).strip()
        certs = []
        if body:
            certs = self.get_active_certs()
        for cert in certs:
            if str(cert.get('certificate_body')).strip() == body:
                self.debug('verified certificate with id "{0}" is still valid'
                           .format(cert.get('certificate_id')))
                return cert.get('certificate_id')
        self.debug('Cert: "{0}" is NOT active'.format(certpath or body))
        return None

    def find_active_cert_and_key_in_dir(self, dir="", machine=None, recursive=True):
        '''
        Attempts to find an "active" cert and the matching key files in the provided
        directory 'dir' on the provided 'machine' via ssh.
        If recursive is enabled, will attempt a recursive search from the provided directory.
        :param dir: the base dir to search in on the machine provided
        :param machine: a Machine() obj used for ssh search commands
        :param recursive: boolean, if set will attempt to search recursively from the dir provided
        :returns dict w/ values 'certpath' and 'keypath' or {} if not found.
        '''
        machine = machine or self.clc
        ret_dict = {}
        if dir and not dir.endswith("/"):
            dir += "/"
        if recursive:
            rec = "r"
        else:
            rec = ""
        certfiles = machine.sys('grep "{0}" -l{1} {2}*.pem'.format('^-*BEGIN CERTIFICATE', rec, dir))
        for f in certfiles:
            if self.get_active_id_for_cert(f, machine=machine):
                dir = os.path.dirname(f)
                keypath = self.get_key_for_cert(certpath=f, keydir=dir, machine=machine)
                if keypath:
                    self.debug('Found existing active cert and key on clc: {0}, {1}'
                               .format(f, keypath))
                    return {'certpath':f, 'keypath':keypath}
        return ret_dict

    def get_key_for_cert(self, certpath, keydir, machine=None, recursive=True):
        '''
        Attempts to find a matching key for cert at 'certpath' in the provided directory 'dir'
        on the provided 'machine'.
        If recursive is enabled, will attempt a recursive search from the provided directory.
        :param dir: the base dir to search in on the machine provided
        :param machine: a Machine() obj used for ssh search commands
        :param recursive: boolean, if set will attempt to search recursively from the dir provided
        :returns string representing the path to the key found or None if not found.
        '''
        machine = machine or self.clc
        self.debug('Looking for key to go with cert...')
        if keydir and not keydir.endswith("/"):
            keydir += "/"
        if recursive:
            rec = "r"
        else:
            rec = ""
        certmodmd5 = machine.sys('openssl x509 -noout -modulus -in {0}  | md5sum'
                                  .format(certpath))
        if certmodmd5:
            certmodmd5 = str(certmodmd5[0]).strip()
        else:
            return None
        keyfiles = machine.sys('grep "{0}" -lz{1} {2}*.pem'
                               .format("^\-*BEGIN RSA PRIVATE KEY.*\n.*END RSA PRIVATE KEY\-*",
                                       rec, keydir))
        for kf in keyfiles:
            keymodmd5 = machine.sys('openssl rsa -noout -modulus -in {0} | md5sum'.format(kf))
            if keymodmd5:
                keymodmd5 = str(keymodmd5[0]).strip()
            if keymodmd5 == certmodmd5:
                self.debug('Found key {0} for cert {1}'.format(kf, certpath))
                return kf
        return None

    def is_ec2_cert_active(self, certbody=None):
        '''
        Attempts to verify if the current self.ec2_cert @ self.ec2_certpath is still active.
        :param certbody
        :returns the cert id if found active, otherwise returns None
        '''
        certbody = certbody or self.ec2_cert
        if not certbody:
            raise ValueError('No ec2 cert body provided or set for eutester to check for active')
        if isinstance(certbody, dict):
            checkbody = certbody.get('certificate_body')
            if not checkbody:
                raise ValueError('Invalid certbody provided, did not have "certificate body" attr')
        for cert in self.get_active_certs():
            body = str(cert.get('certificate_body')).strip()
            if body and body == str(certbody).strip():
                return cert.get('certificate_id')
        return None

    def credential_exist_on_remote_machine(self, cred_path, machine=None):
        machine = machine or self.clc
        return machine.ssh.cmd("test -e " + cred_path)

    def download_creds_from_clc(self, admin_cred_dir, zipfile="creds.zip"):

        zipfilepath = os.path.join(admin_cred_dir, zipfile)
        self.debug("Downloading credentials from " + self.clc.hostname + ", path:" + zipfilepath +
                   " to local file: " + str(zipfile))
        self.sftp.get(zipfilepath, zipfilepath)
        unzip_cmd = "unzip -o {0} -d {1}".format(zipfilepath, admin_cred_dir)
        self.debug('Trying unzip cmd: ' + str(unzip_cmd))
        self.local(unzip_cmd)
        # backward compatibility
        cert_exists_in_eucarc = self.found("cat " + admin_cred_dir + "/eucarc", "export EC2_CERT")
        if cert_exists_in_eucarc:
            self.debug("Cert/pk already exist in '" + admin_cred_dir + "/eucarc' file.")
        else:
            self.download_certs_from_clc(admin_cred_dir=admin_cred_dir, update_eucarc=True)

    def download_certs_from_clc(self, admin_cred_dir=None, update_eucarc=True):
        admin_cred_dir = admin_cred_dir or self.credpath
        self.debug("Downloading certs from " + self.clc.hostname + ", path:" +
                   admin_cred_dir + "/")
        clc_eucarc = os.path.join(admin_cred_dir, 'eucarc')
        local_eucarc = os.path.join(admin_cred_dir,  'eucarc')
        remotecertpath = self.clc.sys(". {0} &>/dev/null && "
                                      "echo $EC2_CERT".format(clc_eucarc))
        if remotecertpath:
            remotecertpath = remotecertpath[0]
        remotekeypath = self.clc.sys(". {0} &>/dev/null && "
                                     "echo $EC2_PRIVATE_KEY".format(clc_eucarc))
        if remotekeypath:
            remotekeypath = remotekeypath[0]
        if not remotecertpath or not remotekeypath:
            self.critical('CERT and KEY paths not provided in {0}'.format(clc_eucarc))
            return {}
        localcertpath = os.path.join(admin_cred_dir, os.path.basename(remotecertpath))
        localkeypath = os.path.join(admin_cred_dir, os.path.basename(remotekeypath))
        self.sftp.get(remotecertpath,localcertpath )
        self.sftp.get(remotekeypath, localkeypath)
        if update_eucarc:
            self.debug("Setting cert/pk in '{0}".format(local_eucarc))
            self.local("echo 'export EC2_CERT=${EUCA_KEY_DIR}/" +
                       str(os.path.basename(localcertpath)) + "' >> " + local_eucarc)
            self.local("echo 'export EC2_PRIVATE_KEY=${EUCA_KEY_DIR}/" +
                       str(os.path.basename(localkeypath)) + "' >> " +local_eucarc)
        return {'certpath':localcertpath, 'keypath':localkeypath}

    def send_creds_to_machine(self, admin_cred_dir, machine, filename='creds.zip'):
        filepath = os.path.join(admin_cred_dir, filename)
        self.debug("Sending credentials to " + machine.hostname)
        localmd5 = None
        remotemd5 = None
        try:
            machine.sys('ls ' + filepath, code=0)
            remotemd5 = self.get_md5_for_file(filepath, machine=machine)
            localmd5 = self.get_md5_for_file(filepath)
        except CommandExitCodeException:
            pass
        if not remotemd5 or (remotemd5 != localmd5):
            machine.sys("mkdir " + admin_cred_dir)
            machine.sftp.put( admin_cred_dir + "/creds.zip" , admin_cred_dir + "/creds.zip")
            machine.sys("unzip -o " + admin_cred_dir + "/creds.zip -d " + admin_cred_dir )
        else:
            self.debug("Machine " + machine.hostname + " already has credentials in place not "
                                                       " sending")

    def setup_local_creds_dir(self, admin_cred_dir):
        if not os.path.exists(admin_cred_dir):
            os.mkdir(admin_cred_dir)

    def setup_remote_creds_dir(self, admin_cred_dir):
        self.sys("mkdir " + admin_cred_dir)

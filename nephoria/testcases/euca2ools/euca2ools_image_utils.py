# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2011, Eucalyptus Systems, Inc.
# All rights reserved.
#
# Redistribution and use of this software in source and binary forms, with or
# without modification, are permitted provided that the following conditions
# are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author: matt.clark@eucalyptus.com

import re
import time
import httplib
from xml.etree import ElementTree
import sys
from cloud_utils.net_utils.sshconnection import SshCbReturn
from cloud_utils.system_utils.machine import Machine
from cloud_utils.log_utils.eulogger import Eulogger
from cloud_utils.log_utils import TextStyle, ForegroundColor, BackGroundColor, markup, \
    get_traceback
from nephoria.aws.ec2.conversiontask import ConversionTask
from nephoria.usercontext import UserContext


class Euca2oolsImageUtils(object):
    #Define the bytes per gig
    gig = 1073741824
    mb = 1048576
    kb = 1024
    def __init__(self,
                 access_key=None,
                 secret_key=None,
                 account_id=None,
                 region_domain=None,
                 s3_url=None,
                 ec2_url=None,
                 bootstrap_url=None,
                 ec2_cert_path=None,
                 worker_hostname=None,
                 worker_keypath=None,
                 worker_username='root',
                 worker_password=None,
                 worker_machine=None,
                 user_context=None,
                 test_controller=None,
                 log_level='debug',
                 destpath=None,
                 time_per_gig=300,
                 eof=True):
        
        self.access_key = access_key
        self.secret_key = secret_key
        self.account_id = account_id
        self.region_domain = region_domain
        self.bootstrap_url = bootstrap_url
        self.s3_url = s3_url
        self.ec2_url = ec2_url
        self.ec2_cert_path = ec2_cert_path

        self.log = Eulogger('Euca2oolsImageUtils', stdout_level=log_level)
        # Setup the work machine, this is the machine which will be used for
        # performing the 'work' (download, bundle, etc)
        self.worker_hostname = worker_hostname
        self.worker_keypath = worker_keypath
        self.worker_username = worker_username
        self.worker_password = worker_password
        self._worker_machine = None
        self._user_context = None
        self.user_context = user_context
        if worker_machine:
            self._worker_machine = worker_machine
        
        self.time_per_gig = time_per_gig
        self.eof = eof
        
        if destpath is not None:
            self.destpath = str(destpath)
        else:
            self.destpath = "/disk1/storage"

        self.time_per_gig = time_per_gig
        
    def status_log(self, msg):
        return self.log.info(markup(msg, 
                                    markups=[ForegroundColor.WHITE, 
                                             BackGroundColor.BG_GREEN, 
                                             TextStyle.BOLD]))
        
        
    @property
    def worker_machine(self):
        '''
        Attempts to verify the worker passed is a Machine() class else assume
        it's a host name of the machine work should be performed on and
        attempt to return a Machine() created from the hostname

        param: worker Machine() or 'hostname' to be used to perform image utils
        work on.
        returns Machine obj
        '''
        if not self._worker_machine:     
            if self.worker_hostname:
                self.log.debug('Attempting to connect to machine: "{0}" for image utility work...'
                               .format(self.worker_hostname))
                self._worker_machine = Machine(hostname=self.worker_hostname,
                                               username=self.worker_username,
                                               password=self.worker_password,
                                               keypath=self.worker_keypath)
        return self._worker_machine
    
    @worker_machine.setter
    def worker_machine(self, machine):
        if isinstance(machine, Machine):
                self._worker_machine = machine
        else:
            raise ValueError('worker_machine must be of type Machine, got:"{0}/{1}"'
                             .format(machine, type(machine)))

    def create_user_context(self, access_key, secret_key, account_id=None,
                            region_domain=None, ec2_url=None, s3_url=None, bootstrap_url=None):
        if not (region_domain or s3_url or ec2_url):
            raise ValueError('Can not derive service endpoints for user. '
                             'Must supply either region_domain:"{0}", or ec2_url:"{1}" '
                             's3_url:"{2}"'.format(region_domain, ec2_url, s3_url))
        access_key = access_key or self.access_key
        secret_key = secret_key or self.secret_key
        region_domain = region_domain or self.region_domain
        if (not access_key and secret_key and region_domain):
            raise ValueError('Must supply access_key, secret_key and region domain to '
                             'create user context')
        user = UserContext(aws_access_key=access_key, aws_secret_key=secret_key,
                           region=region_domain)
        if ec2_url:
            user.ec2_url = ec2_url
        if s3_url:
            user.s3_url = s3_url
        if bootstrap_url:
            user.bootstrap_url = bootstrap_url
        if account_id:
            user.account_id = account_id
        return user

    @property
    def user_context(self):
        if not self._user_context:
            try:
                self.user_context = self.create_user_context(access_key=self.access_key,
                                                             secret_key=self.secret_key,
                                                             region_domain=self.region_domain,
                                                             ec2_url=self.ec2_url,
                                                             s3_url=self.s3_url,
                                                             bootstrap_url=self.bootstrap_url,
                                                             account_id=self.account_id)
            except ValueError as VE:
                self.log.warning('Could not create user context, err:"{0}"'.format(VE))
        return self._user_context

    @user_context.setter
    def user_context(self, user_context):
        if user_context is None or isinstance(user_context, UserContext):
            if user_context:
                self._user_context = user_context
                self.access_key = user_context.access_key
                self.secret_key = user_context.secret_key
                self.ec2_url = user_context.ec2_url
                self.s3_url = user_context.s3_url
                self.bootstrap_url = user_context.bootstrap_url
                self.account_id = user_context.account_id
        else:
            raise ValueError('Usercontext must be of type UserContext. Got:"{0}/{1}"'
                             .format(user_context, type(user_context)))



    def getHttpRemoteImageSize(self, url, unit=None, maxredirect=5):
        return Euca2oolsImageUtils._getHttpRemoteImageSize(url, unit=unit, maxredirect=maxredirect)

    @staticmethod
    def _getHttpRemoteImageSize(url, unit=None, maxredirect=5, debug=None):
        '''
        Get the remote file size from the http header of the url given
        Returns size in GB unless unit is given.
        '''
        unit = unit or 1073741824
        if debug is None:
            def printdebug(msg):
                print msg
            debug = printdebug

        def get_location(url, depth, maxdepth):
            if depth > maxdepth:
                raise ValueError('Max redirects limit has been reached:{0}/{1}'
                                 .format(depth, maxdepth))
            conn = None
            try:
                url = url.replace('http://', '')
                host = url.split('/')[0]
                path = url.replace(host, '')
                res = None
                err = None
                retries = 5
                for retry in xrange(0, retries):
                    try:
                        debug('HTTP HEAD request for: {0}, attempt:{1}/{2}'
                              .format(url, retry, retries))
                        conn = httplib.HTTPConnection(host)
                        conn.request("HEAD", path)
                        res = conn.getresponse()
                        break
                    except Exception as HE:
                        err = '{0}\nError attempting to fetch url:{1}, attempt:{2}/{3}, ' \
                              'error:{4}'.format(get_traceback(), url, retry, retries, HE)
                        debug(err)
                        time.sleep(retry)
                if not res:
                    err = err or "Error retrieving url:{0}".format(url)
                    raise RuntimeError(err)
                location = res.getheader('location')
                if location and location != url:
                    depth += 1
                    debug('Redirecting: depth:{0}, url:{1}'.format(depth, location))
                    return get_location(location, depth=depth,maxdepth=maxdepth)
                else:
                    content_length = res.getheader('content-length')
                    if content_length is None:
                        raise ValueError('No content-length header found for url:{0}'
                                         .format(url))
                    fbytes = int(content_length)
                    return fbytes
            except Exception as HE:
                debug('Failed to fetch content-length header from url:{0}'.format(url))
                raise HE
            finally:
                if conn:
                    conn.close()
        try:
            fbytes = get_location(url, depth=0, maxdepth=maxredirect)
            debug("content-length:" + str(fbytes))
            if fbytes == 0:
                rfsize = 0
            else:
                rfsize = (((fbytes/unit) + 1) or 1)
            debug("Remote file size: " + str(rfsize) + "g")
        except Exception, e:
            debug("Failed to get remote file size...")
            raise e
        return rfsize

    def wget_image(self,
                   image_url,
                   destpath=None,
                   dest_file_name=None,
                   machine=None,
                   user=None,
                   password=None,
                   retryconn=True,
                   time_per_gig=300):
        '''
        Attempts to wget a url to a remote (worker) machine.
        :param image_url: url to wget/download
        :param destpath:path/dir to download to
        :param dest_file_name: filename to download image to
        :param machine: remote (worker) machine to wget on
        :param user: wget user name
        :param password: wget password
        :param retryconn: boolean to retry connection
        :param time_per_gig: int time to allow per gig of image wget'd
        :returns int size of image
        '''
        machine = machine or self.worker_machine
        if destpath is None and self.destpath is not None:
            destpath = self.destpath
        size = self.getHttpRemoteImageSize(image_url)
        if (size <  machine.get_available(destpath, unit=self.__class__.gig)):
            raise Exception("Not enough available space at: " +
                            str(destpath) + ", for image: " + str(image_url))
        timeout = size * time_per_gig
        self.log.debug('wget_image: ' + str(image_url) + ' to destpath' +
                       str(destpath) + ' on machine:' + str(machine.hostname))
        saved_location = machine.wget_remote_image(image_url,
                                                   path=destpath,
                                                   dest_file_name=dest_file_name,
                                                   user=user,
                                                   password=password,
                                                   retryconn=retryconn,
                                                   timeout=timeout)
        return (size, saved_location)


    def get_manifest_obj(self, path, machine=None, local=False, timeout=30):
        '''
        Read in a local or remote manifest xml file and convert to an
        xml ElementTree object.
        :param path: local or remote path to manifest file
        :param machine: the remote machine to read manifest file from
        :param local: boolean to determine if file is local
        :param timeout: timeout in second for reading in file
        :returns xml ElementTree obj
        '''
        cmd = 'cat ' + str(path)
        if not local:
            machine = machine or self.worker_machine
            out = machine.cmd(cmd, timeout=timeout, verbose=False)
            if out['status'] != 0:
                raise Exception('get_manifest_part_count failed, cmd status:'
                                + str(out['status']))
            output = out['output']
        else:
            with open(path) as m_file:
                output = m_file.read()
        xml = ElementTree.fromstring(output)
        return xml

    def get_manifest_part_count(self,
                                path,
                                machine=None,
                                local=False,
                                timeout=30):
        '''
        Attempt retrieve the part count value from a manifest file
        :param path: local or remote path to manifest file
        :param machine: the remote machine to read manifest file from
        :param local: boolean to determine if file is local
        :param timeout: timeout in second for reading in file
        :returns int count
        '''
        manifest_xml = self.get_manifest_obj(path=path,
                                             machine=machine,
                                             local=local,
                                             timeout=timeout)
        image = manifest_xml.find('image')
        parts = image.find('parts')
        part_count = parts.get('count')
        self.log.debug('get_manifest_part_count:' + str(path) +
                   ', count:' + str(part_count))
        return int(part_count)

    def get_manifest_image_name(self,
                                path,
                                machine=None,
                                local=False,
                                timeout=30):
        '''
        Attempts to read the image name from a manifest file
        :param path: local or remote path to manifest file
        :param machine: the remote machine to read manifest file from
        :param local: boolean to determine if file is local
        :param timeout: timeout in second for reading in file
        :returns string image name
        '''
        manifest_xml = self.get_manifest_obj(path=path,
                                             machine=machine,
                                             local=local,
                                             timeout=timeout)
        image = manifest_xml.find('image')
        name_elem = image.find('name')
        return name_elem.text

    def euca2ools_bundle_image(self,
                     path,
                     machine=None,
                     machine_credpath=None,
                     prefix=None,
                     kernel=None,
                     ramdisk=None,
                     access_key=None,
                     secret_key=None,
                     account_id=None,
                     ec2cert=None,
                     bootstrap_url=None,
                     block_device_mapping=None,
                     destination='/disk1/storage',
                     arch='x86_64',
                     debug=False,
                     interbundle_timeout=120,
                     time_per_gig=None):
        '''
        Bundle an image on a 'machine'.
        where credpath to creds on machine
        '''
        self.status_log('Starting euca2ools_bundle_image at path:"{0}"'.format(path))
        time_per_gig = time_per_gig or self.time_per_gig
        machine = machine or self.worker_machine
        image_size = machine.get_file_size(path)/self.gig or 1
        timeout = time_per_gig * image_size
        cbargs = [timeout, interbundle_timeout, time.time(), 0, True]
        if destination is None:
            destination = machine.sys('pwd')[0]
        freesize = machine.get_available(str(destination), (self.gig/self.kb))
        if (freesize < image_size):
            raise Exception("Not enough free space at:" + str(destination))
        ec2cert = ec2cert or self.ec2_cert_path
        bootstrap_url = bootstrap_url or self.bootstrap_url
        access_key = access_key or self.access_key
        secret_key = secret_key or self.secret_key
        account_id = account_id or self.account_id

        #build our tools bundle-image command...
        cmdargs = ""
        if prefix:
            cmdargs = cmdargs + " --prefix " +str(prefix)
        if kernel:
            cmdargs = cmdargs + " --kernel "  +str(kernel)
        if ramdisk:
            cmdargs = cmdargs + " --ramdisk " +str(ramdisk)
        if block_device_mapping:
            cmdargs = cmdargs + " --block-device-mapping " + \
                      str(block_device_mapping)
        if destination:
            cmdargs = cmdargs + " --destination " + str(destination)
        if arch:
            cmdargs = cmdargs + " --arch " + str(arch)
        if account_id:
            cmdargs += " --user " + str(account_id)
        if bootstrap_url:
            cmdargs += " --bootstrap-url " + str(bootstrap_url)
        if ec2cert:
            cmdargs += " --ec2cert " + str(ec2cert)
        if debug:
            cmdargs = cmdargs + " --debug "

        cmdargs = cmdargs + " -i " + str(path)

        cmd = 'euca-bundle-image -I {0} -S {1} --user {2} {3}'\
            .format(access_key, secret_key, account_id, cmdargs)
        #execute the command
        out = machine.cmd(cmd, timeout=timeout, listformat=True,
                          cb = self._bundle_status_cb, cbargs=cbargs)
        if out['status'] != 0:
            raise Exception('bundle_image "' + str(path) +
                            '" failed. Errcode:' + str(out['status']))
        manifest = None
        for line in out['output']:
            line = str(line)
            if re.search("(Generating|Wrote) manifest",line):
                manifest = line.split()[2]
                break
        if manifest is None:
            raise Exception('Failed to find manifest from bundle_image:' +
                            str(path))
        self.log.debug('bundle_image:'+str(path)+'. manifest:'+str(manifest))
        return manifest

    def euca2ools_upload_bundle(self,
                      manifest,
                      access_key=None,
                      secret_key=None,
                      s3_url=None,
                      user_context=None,
                      machine=None,
                      bucketname=None,
                      debug=False,
                      interbundle_timeout=120,
                      timeout=0,
                      image_check_timeout=300,
                      uniquebucket=True):
        '''
        Bundle an image on a 'machine'.
        where credpath to creds on machine
        '''
        self.status_log('Starting euca2ools_upload_bundle for manifest:"{0}"'.format(manifest))
        machine = machine or self.worker_machine
        access_key = access_key or self.access_key
        secret_key = secret_key or self.secret_key
        s3_url = s3_url or self.s3_url
        if not access_key:
            raise ValueError('Could not determine access key for euca2ools_upload_bundle')
        if not secret_key:
            raise ValueError('Could not determine secret key for euca2ools_upload_bundle')
        cbargs = [timeout, interbundle_timeout, time.time(), 0, True]
        bname = ''
        cmdargs = ""
        manifest = str(manifest)
        upmanifest = None
        part_count = -1
        try:
            part_count = self.get_manifest_part_count(manifest, machine=machine)
        except:
            pass
        self.log.debug('Attempting to upload_bundle:' + str(manifest) +
                   ", bucketname:" + str(bucketname) + ", part_count:" +
                   str(part_count))
        if bucketname:
            bname = bucketname
            if uniquebucket:
                bname = self._get_unique_bucket_name(bname)
        else:
            #Use the image name found in the manifest as bucketname
            bname = self._generate_unique_bucket_name_from_manifest(
                manifest, unique=uniquebucket)
        self.log.debug('Using upload_bundle bucket name: '+str(bname))
        cmdargs = cmdargs + " -b " + str(bname)
        if s3_url:
            cmdargs += " --url " + str(s3_url)
        if debug:
            cmdargs = cmdargs + " --debug "
        cmdargs = cmdargs + " -b " + str(bname) + " -m " +str(manifest)

        cmd = 'euca-upload-bundle -I ' + str(access_key) + ' -S ' + str(secret_key) + str(cmdargs)
        #execute upload-bundle command...
        out = machine.cmd(cmd, timeout=image_check_timeout, listformat=True,
                          cb=self._bundle_status_cb, cbargs=cbargs)
        if out['status'] != 0:
            raise RuntimeError('upload_bundle "' + str(manifest) +
                            '" failed. Errcode:' + str(out['status']))
        for line in out['output']:
            line = str(line)
            if re.search('Uploaded', line) and re.search('manifest', line):
                upmanifest = line.split().pop()
                break
        if upmanifest is None:
            raise RuntimeError('Failed to find upload manifest from '
                               'upload_bundle command')
        self.log.debug('upload_image:'+str(manifest)+'. manifest:'+str(upmanifest))
        return upmanifest

    def euca2ools_bundle_and_upload(self,
                                    file,
                                    arch,
                                    bucket,
                                    access_key=None,
                                    secret_key=None,
                                    s3_url=None,
                                    prefix=None,
                                    directory=None,
                                    kernel=None,
                                    ramdisk=None,
                                    block_device_map=[],
                                    product_codes=None,
                                    acl=None,
                                    location=None,
                                    ):
        raise NotImplemented('euca2ools_bundle_and_upload wrapper '
                             'not implemented yet')

    def euca2ools_register(self,
                           manifest,
                           name,
                           description=None,
                           access_key=None,
                           secret_key=None,
                           ec2_url=None,
                           arch=None,
                           kernel=None,
                           ramdisk=None,
                           root_device_name=None,
                           snapshot_id=None,
                           block_dev_map=[],
                           virtualization_type=None,
                           platform=None,
                           machine=None,
                           machine_credpath=None):
        self.status_log('Starting euca2ools_register for manifest:"{0}", kernel:"{1}", ramdisk:"{2}"'
                    .format(manifest, kernel,ramdisk))

        machine = machine or self.worker_machine
        access_key = access_key or self.access_key
        secret_key = secret_key or self.secret_key
        ec2_url = ec2_url or self.ec2_url
        if not access_key:
            self.log.warning('Could not determine access key for euca2ools_register')
        if not secret_key:
            self.log.warning('Could not determine secret key for euca2ools_register')
        if not manifest:
            self.log.warning('No manifest provided to register command! ')
        cmdargs = str(manifest) + " -n " + str(name)
        emi = None
        if description:
            cmdargs += ' -d ' + str(description)
        if arch:
            cmdargs += ' -a ' + str(arch)
        if kernel:
            cmdargs += ' --kernel ' + str(kernel)
        if ramdisk:
            cmdargs += ' --ramdisk ' + str(ramdisk)
        if root_device_name:
            cmdargs += ' --root-device-name ' + str(root_device_name)
        if snapshot_id:
            cmdargs += ' -s ' + str(snapshot_id)
        for dev in block_dev_map:
            cmdargs += ' -b ' + str(dev)
        if virtualization_type:
            cmdargs += ' --virtualization-type ' + str(virtualization_type)
        if platform:
            cmdargs += ' --platform ' + str(platform)
        if ec2_url:
            cmdargs += ' --url ' + str(ec2_url)


        cmd = 'euca-register {0} -I {1} -S {2}'.format(cmdargs, access_key, secret_key)
        out = machine.sys(cmd=cmd, code=0)
        for line in out:
            if re.search('IMAGE',line):
                emi = line.split().pop().strip()
        assert emi, 'Invalid emi value: "{0}"'.format(emi)
        return emi

    def euca2ools_download_bundle(self,
                                  bucket,
                                  manifest=None,
                                  prefix=None,
                                  directory=None,
                                  image_name=None,
                                  machine=None,
                                  access_key=None,
                                  secret_key=None,
                                  s3_url=None,
                                  ):
        machine = machine or self.worker_machine
        access_key = access_key or self.access_key
        secret_key = secret_key or self.secret_key
        s3_url = s3_url or self.s3_url
        if not access_key:
            self.log.warning('Could not determine access key for euca2ools_download_bundle')
        if not secret_key:
            self.log.warning('Could not determine secret key for euca2ools_download_bundle')
        cmdargs = " -b " + str(bucket)
        if manifest:
            cmdargs += " -m " + str(manifest)
        if prefix:
            cmdargs += " -p " + str(prefix)
        if directory:
            cmdargs += " -d " + str(directory)
        if s3_url:
            cmdargs += " --url " + str(s3_url)


        cmd = ('euca-download-bundle -I ' + access_key + ' -S ' + secret_key + str(cmdargs))
        out = machine.sys(cmd=cmd, code=0)
        # Complete this wrapper...
        raise NotImplemented('euca2ools_download_bundle wrapper '
                             'not implemented yet')

    def euca2ools_download_and_unbundle(self,
                                        bucket,
                                        manifest=None,
                                        prefix=None,
                                        directory=None,
                                        maxbytes=None,
                                        access_key=None,
                                        secret_key=None,
                                        s3_url=None,
                                        ):
        raise NotImplemented('euca2ools_download_and_unbundle wrapper'
                             ' not implemented yet')


    def euca2ools_import_volume(self,
                                import_file,
                                bucket,
                                zone,
                                format,
                                size=None,
                                presigned_manifest_url=None,
                                prefix=None,
                                days=None,
                                no_upload=None,
                                description=None,
                                s3_url=None,
                                ec2_url=None,
                                security_token=None,
                                machine=None,
                                access_key=None,
                                secret_key=None,
                                user_context=None,
                                region_domain=None,
                                misc=None):
        '''
        Note: Under normal conditions this will create a volume that may
        not be available to the returned task object immediately. The volume
        id will be available later by using task.update() on the returned
        task object. For this reason the volume is not being added to
        the tester's resources list here.
        '''
        machine = machine or self.worker_machine
        access_key = access_key or self.access_key
        secret_key = secret_key or self.secret_key
        user = user_context
        if not user:
            try:
                user = self.create_user_context(access_key=access_key, secret_key=secret_key,
                                                region_domain=region_domain, s3_url=s3_url,
                                                ec2_url=ec2_url)
            except Exception as UE:
                self.log.warning('Could not create user context for euca2ools_import_volume, '
                                 'proceeding in case this is a "negative test". Err:"{0}"'
                                 .format(UE))
        if user:
            ec2_url = ec2_url or user.ec2_url
            s3_url = s3_url or user.s3_url
            access_key = access_key or user.access_key
            secret_key = secret_key or user.secret_key

        if not access_key:
            self.log.warning('Could not determine access key for euca2ools_import_volume')
        if not secret_key:
            self.log.warning('Could not determine secret key for euca2ools_import_volume')
        cmdargs = str(import_file) + " -b " + str(bucket) + \
                  " -z " + str(zone) + " -f " + str(format) + \
                  " --show-empty-fields "
        emi = None
        if description:
            cmdargs += ' -d ' + str(description)
        if size:
            cmdargs += ' -s ' + str(size)
        if presigned_manifest_url:
            cmdargs += ' --manifest-url ' + str(presigned_manifest_url)
        if prefix:
            cmdargs += " --prefix " + str(prefix)
        if days:
            cmdargs += " -x " + str(days)
        if no_upload:
            cmdargs += " --no-upload "
        if s3_url:
            cmdargs += " --s3-url " + str(s3_url)
        if ec2_url:
            cmdargs += " -U " + str(ec2_url)
        if access_key:
            cmdargs += " -w " + access_key
        if secret_key:
            cmdargs += " -o " + secret_key
        if security_token:
            cmdargs += " --security-token " + str(security_token)
        if misc:
            cmdargs += misc

        cmd = 'euca-upload-import-volume ' + str(cmdargs)
        out = machine.sys(cmd=cmd, code=0)
        for line in out:
            lre = re.search('import-vol-\w{8}', line)
            if lre:
                taskid = lre.group()
        self.log.info('Import taskid:' + str(taskid))
        #check on system using describe...
        task = self.tc.user.ec2.get_conversion_task(taskid=taskid)
        assert task, 'Task not found in describe conversion tasks. "{0}"'\
            .format(str(taskid))
        return task


    def euca2ools_import_instance(self,
                                import_file,
                                bucket,
                                zone,
                                format,
                                instance_type,
                                arch,
                                platform,
                                size=None,
                                keypair=None,
                                presigned_manifest_url=None,
                                prefix=None,
                                days=None,
                                no_upload=None,
                                description=None,
                                group=None,
                                s3_url=None,
                                ec2_url=None,
                                image_size=None,
                                user_data=None,
                                user_data_file=None,
                                private_addr=None,
                                shutdown_behavior=None,
                                access_key=None,
                                secret_key=None,
                                region_domain=None,
                                user_context=None,
                                security_token=None,
                                machine=None,
                                machine_credpath=None,
                                misc=None,
                                time_per_gig=90):
        machine = machine or self.worker_machine
        access_key = access_key or self.access_key
        secret_key = secret_key or self.secret_key
        user = user_context
        if not user:
            try:
                user = self.create_user_context(access_key=access_key, secret_key=secret_key,
                                                region_domain=region_domain, s3_url=s3_url,
                                                ec2_url=ec2_url)
            except Exception as UE:
                self.log.warning('Could not create user context for euca2ools_import_instance, '
                                 'proceeding in case this is a "negative test". Err:"{0}"'
                                 .format(UE))
        if user:
            ec2_url = ec2_url or user.ec2_url
            s3_url = s3_url or user.s3_url
            access_key = access_key or user.access_key
            secret_key = secret_key or user.secret_key
        if not access_key:
            self.log.warning('Could not determine access key for euca2ools_import_instance')
        if not secret_key:
            self.log.warning('Could not determine secret key for euca2ools_import_instance')
        try:
            file_size = machine.get_file_size(import_file)
            gb = file_size/self.gig or 1
            timeout = gb * time_per_gig
        except:
            timeout = 300
        cmdargs = str(import_file) + " -b " + str(bucket) + \
                  " -z " + str(zone) + " -f " + str(format) + \
                  " -t " + str(instance_type) + " -a " + str(arch) + \
                  " -p " + str(platform) + \
                  " --show-empty-fields "
        emi = None
        if description:
            cmdargs += ' -d ' + str(description)
        if group:
            cmdargs += ' -g ' + str(group)
        if keypair:
            cmdargs += ' --key ' + str(keypair)
        if size:
            cmdargs += ' -s ' + str(size)
        if presigned_manifest_url:
            cmdargs += ' --manifest-url ' + str(presigned_manifest_url)
        if prefix:
            cmdargs += " --prefix " + str(prefix)
        if days:
            cmdargs += " -x " + str(days)
        if no_upload:
            cmdargs += " --no-upload "
        if s3_url:
            cmdargs += " --s3-url " + str(s3_url)
        if ec2_url:
            cmdargs += " -U " + str(ec2_url)
        if image_size:
            cmdargs += " --image-size " + str(image_size)
        if user_data:
            cmdargs += ' --user-data "' + str(user_data) +'"'
        if user_data_file:
            cmdargs += " --user-data-file " + str(user_data_file)
        if private_addr:
            cmdargs += " --private-ip-address"
        if shutdown_behavior:
            cmdargs += " --instance-initiated-shutdown-behavior " + \
                        str(shutdown_behavior)
        if access_key:
            cmdargs += " -w " + str(access_key)
        if secret_key:
            cmdargs += " -o " + str(secret_key)
        if security_token:
            cmdargs += " --security-token " + str(security_token)
        if misc:
            cmdargs += misc

        cmd = 'euca-upload-import-volume ' + str(cmdargs)

        out = machine.sys(cmd=cmd, timeout=timeout, code=0)
        taskid = None
        for line in out:
            lre = re.search('import-i-\w{8}', line)
            if lre:
                taskid = lre.group()
        if not taskid:
            raise RuntimeError('Could not find a task id in output from cmd:'
                               + str(cmd))
        self.log.debug('Import taskid:' + str(taskid))
        #check on system using describe...
        if user:
            task = user.ec2.get_conversion_task(taskid=taskid)
            assert task, 'Task not found in describe conversion tasks. "{0}"'\
                .format(str(taskid))
        return taskid

    def _parse_euca2ools_conversion_task_output(self, output):
        splitlist = []
        retlist = []
        for line in output:
            splitlist.extend(line.split('\t'))
        if len(splitlist) % 2:
            raise ValueError("Conversion task output:\n" + str(output) +
                             '\nParsed euca2ools conversion task output does '
                             'not have an even number of fields to parse')
        #Build out a dict based upon the key value-ish format of the output
        task = ConversionTask()
        for i in xrange(0, len(splitlist)):
            if i % 2:
                task.endElement(name=lastkey, value=splitlist[i])
            else:
                lastkey = str(splitlist[i]).lower()
                if lastkey == 'tasktype':
                    if task:
                        retlist.append(task)
                    task = ConversionTask
        return retlist

    def _generate_unique_bucket_name_from_manifest(self, manifest, unique=True):
        mlist = str(manifest.replace('.manifest.xml', '')).split('/')
        basename = mlist[len(mlist)-1].replace('_', '').replace('.', '')
        if unique:
            return self._get_unique_bucket_name(basename)
        return basename

    def _get_unique_bucket_name(self, basename, id='test', start=0, user=None):
        bx=start
        bname = basename
        user = user or self.user_context
        while user.s3.get_bucket_by_name(bname) is not None:
            bx += 1
            bname = basename+str(id)+str(bx)
        return bname


    def create_working_dir_on_worker_machine(self, path, overwrite=False):
        path = str(path)
        if self.worker_machine.is_file(path):
            if not overwrite:
                raise Exception('Dir found on:' +
                                str(self.worker_machine.hostname) +
                                ',"' + path + '".\n' +
                                'Either remove conflicting files, '
                                'use "filepath" option or "overwrite"')
        else:
            self.worker_machine.sys('mkdir -p ' + path, code=0)


    def _bundle_status_cb(self, buf, cmdtimeout, parttimeout, starttime,
                         lasttime, check_image_stage):
        ret = SshCbReturn(stop=False)
        #if the over timeout or the callback interval has expired,
        # then return stop=true
        #interval timeout should not be hit due to the setting of the
        # timer value, but check here anyways

        if (cmdtimeout != 0) and ( int(time.time()-starttime) > cmdtimeout):
            self.log.debug('bundle_status_cb command timed out after ' +
                       str(cmdtimeout)+' seconds')
            ret.statuscode=-100
            ret.stop = True
            return ret
        if not check_image_stage:
            ret.settimer = parttimeout
            if (parttimeout != 0 and lasttime != 0) and \
                    (int(time.time()-lasttime) > parttimeout):
                self.log.debug('bundle_status_cb inter-part time out after ' +
                           str(parttimeout) + ' seconds')
                ret.statuscode=-100
                ret.stop = True
                return ret

        if re.search('[P|p]art:',buf):
            sys.stdout.write("\r\x1b[K"+str(buf).strip())
            sys.stdout.flush()
            check_image_stage=False
        else:
            #Print command output and write to ssh.cmd['output'] buffer
            ret.buf = buf
            self.log.debug(str(buf))
        #Command is still going, reset timer thread to intervaltimeout,
        # provide arguments for  next time this is called from ssh cmd.
        ret.stop = False
        ret.nextargs =[cmdtimeout, parttimeout, starttime,
                       time.time(), check_image_stage]
        return ret

    def create_emi(self,
                   image_url,
                   machine=None,
                   access_key=None,
                   secret_key=None,
                   ec2_url=None,
                   s3_url=None,
                   bucketname=None,
                   machine_credpath=None,
                   debug=False,
                   prefix=None,
                   kernel=None,
                   ramdisk=None,
                   architecture=None,
                   block_device_mapping=[],
                   destpath=None,
                   root_device_name=None,
                   description=None,
                   virtualization_type=None,
                   platform=None,
                   name=None,
                   interbundle_timeout=120,
                   upload_timeout=0,
                   uniquebucket=True,
                   wget_user=None,
                   wget_password=None,
                   wget_retryconn=True,
                   filepath=None,
                   bundle_manifest=None,
                   uploaded_manifest=None,
                   time_per_gig=300,
                   tagname=None,
                   overwrite=False,
                   user_context=None,
                   region_domain=None,
                   ):
        start = time.time()
        user = user_context
        if not user:
            try:
                user = self.create_user_context(access_key=access_key, secret_key=secret_key,
                                                region_domain=region_domain, s3_url=s3_url,
                                                ec2_url=ec2_url)
            except Exception as UE:
                self.log.error('Could not create user context for create_emi. Err:"{0}"'
                               .format(UE))
                raise UE
        if user:
            ec2_url = ec2_url or user.ec2_url
            s3_url = s3_url or user.s3_url
            access_key = access_key or user.access_key
            secret_key = secret_key or user.secret_key
        filesize = None
        destpath = destpath or self.destpath
        destpath = str(destpath)
        self.log.debug('create_emi_from_url:' + str(image_url) + ", starting...")

        if not destpath.endswith('/'):
            destpath += '/'
        if image_url:
            filename = str(image_url).split('/')[-1]
            destpath = destpath + str(filename.replace('.','_'))
            if filepath is None and bundle_manifest is None and uploaded_manifest is None:
                filepath = destpath + "/" + str(filename)
                self.create_working_dir_on_worker_machine(path=destpath,
                                                          overwrite=overwrite)

                self.log.debug('Downloading image to ' + str(machine) + ':' +
                               str(filepath) + ', image_url:' + str(image_url))
                filesize = self.wget_image(image_url,
                                           destpath=destpath,
                                           machine=machine,
                                           user=wget_user,
                                           password=wget_password,
                                           retryconn=wget_retryconn,
                                           time_per_gig=time_per_gig)

        self.status_log('create_emi_from_url: Image downloaded to machine, '
                    'now bundling image...')
        if bundle_manifest is None and uploaded_manifest is None:
            bundle_manifest = self.euca2ools_bundle_image(
                filepath,
                machine=machine,
                machine_credpath=machine_credpath,
                access_key=access_key,
                secret_key=secret_key,
                prefix=prefix,
                kernel=kernel,
                ramdisk=ramdisk,
                block_device_mapping=block_device_mapping,
                destination=destpath,
                debug=debug,
                interbundle_timeout=interbundle_timeout,
                time_per_gig=time_per_gig)

        self.status_log('create_emi_from_url: Image bundled, now uploading...')
        if uploaded_manifest is None:
            uploaded_manifest = self.euca2ools_upload_bundle(
                bundle_manifest,
                machine=machine,
                access_key=access_key,
                secret_key=secret_key,
                bucketname=bucketname,
                s3_url=s3_url,
                debug=debug,
                interbundle_timeout=interbundle_timeout,
                timeout=upload_timeout,
                uniquebucket=uniquebucket)

        self.status_log('create_emi_from_url: Now registering...')
        if name is None:
            name = uploaded_manifest.split('/').pop().rstrip('manifest.xml')
            name = "".join(re.findall(r"\w", name))
            name += '-' + str(int(time.time()))
        try:
            if user:
                user.ec2.get_emi(name='name')
        except:
            name += 'X'
        emi = self.euca2ools_register(
            manifest=uploaded_manifest,
            name=name,
            description=description,
            access_key=access_key,
            secret_key=secret_key,
            ec2_url=ec2_url,
            arch=architecture,
            kernel=kernel,
            ramdisk=ramdisk,
            root_device_name=root_device_name,
            block_dev_map=block_device_mapping,
            virtualization_type=virtualization_type,
            platform=platform)
        self.log.debug('euca2ools_register returned:"' + str(emi) +
                       '", now verify it exists on the cloud...')

        #Verify emi exists on the system, and convert to boto obj...
        emi = user.ec2.get_emi(emi)

        #Add tags that might have test use meaning...
        try:
            if filesize is not None:
                emi.add_tag('size', value= str(filesize))
            if image_url:
                emi.add_tag('source', value=(str(image_url)))
            emi.add_tag(tagname or 'eutester-created')
        except Exception, te:
            self.log.debug('Could not add tags to image:' + str(emi.id) +
                       ", err:" + str(te))
        elapsed= int(time.time()-start)
        self.status_log('create_emi_from_url: Done, image registered as:' +
                    str(emi.id) + ", after " + str(elapsed) + " seconds")
        return emi


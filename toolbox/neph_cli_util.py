#!/usr/bin/env python

import argparse
import os
from nephoria.testcontroller import TestController
import logging
parser = argparse.ArgumentParser(description='Euca Runtime Config Generator')
parser.add_argument('--get-credentials', dest='get_credentials', action='store_true',
                    default=False,
                    help='Operation to get credentials, boolean.(not used)')

parser.add_argument('--cred-user', dest='cred_user',
                    default='admin',
                    help='Username to use for building runtime config, default:"admin"')

parser.add_argument('--cred-account', dest='cred_account',
                    default='eucalyptus',
                    help='Account name to use for building runtime config, default:"eucalyptus"')
parser.add_argument('--clc-ip', dest='clc_ip',
                    default="127.0.0.1",
                    help='CLC host ip, default:"127.0.0.1"')
parser.add_argument('--clc-password', dest='clc_password',
                    default=None,
                    help='Optional CLC root password')
parser.add_argument('filepath',
                    default=None,
                    help='Optional zip filename/path. Default is ./<cred_user>.zip')

parser.add_argument('--log-level', dest='log_level',
                    default="ERROR",
                    help='Log level')

parser.add_argument('--unpack', dest='unpack', action='store_true',
                    default=False,
                    help='Create files in addition to zip archive')




args = parser.parse_args()
zip_path = args.filepath
if zip_path:
    zip_dest_dir = os.path.dirname(zip_path)
    zip_file_name = os.path.basename(zip_path)
else:
    zip_dest_dir = None
    zip_file_name = "{0}_{1}.zip".format(args.cred_account, args.cred_user)
zip_only = True
if args.unpack:
    zip_only = False
logger = logging.getLogger('eulogger')
if isinstance(args.log_level, basestring):
    log_level = getattr(logging, args.log_level.upper(), logging.DEBUG)
logger.setLevel(log_level)
tc = TestController(args.clc_ip, log_level=args.log_level, password=args.clc_password)
user = tc.get_user_by_name(aws_account_name=args.cred_account, aws_user_name=args.cred_user)
files = user.create_local_creds(local_destdir=zip_dest_dir, zipfilename=zip_file_name,
                                ziponly=zip_only) or []
print 'Created artifacts:"{0}"'.format(", ".join(files))

